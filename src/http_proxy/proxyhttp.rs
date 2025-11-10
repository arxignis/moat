use crate::utils::structs::{AppConfig, Extraparams, Headers, InnerMap, UpstreamsDashMap, UpstreamsIdMap};
use crate::http_proxy::gethosts::GetHost;
use crate::waf::wirefilter::{evaluate_waf_for_pingora_request, WafAction};
use crate::waf::actions::captcha::{validate_captcha_token, apply_captcha_challenge_with_token, generate_captcha_token};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::body::Bytes;
use dashmap::DashMap;
use log::{debug, error, info, warn};
use once_cell::sync::Lazy;
use pingora_http::{RequestHeader, ResponseHeader, StatusCode};
use pingora_core::prelude::*;
use pingora_core::ErrorSource::Upstream;
use pingora_core::{Error, ErrorType::HTTPStatus, RetryType, ImmutStr};
use pingora_core::listeners::ALPN;
use pingora_core::prelude::HttpPeer;
use pingora_limits::rate::Rate;
use pingora_proxy::{ProxyHttp, Session};
use serde_json;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use tokio::time::Instant;

static RATE_LIMITER: Lazy<Rate> = Lazy::new(|| Rate::new(Duration::from_secs(1)));

#[derive(Clone)]
pub struct LB {
    pub ump_upst: Arc<UpstreamsDashMap>,
    pub ump_full: Arc<UpstreamsDashMap>,
    pub ump_byid: Arc<UpstreamsIdMap>,
    pub arxignis_paths: Arc<DashMap<String, (Vec<InnerMap>, AtomicUsize)>>,
    pub headers: Arc<Headers>,
    pub config: Arc<AppConfig>,
    pub extraparams: Arc<ArcSwap<Extraparams>>,
}

pub struct Context {
    backend_id: String,
    https_proxy_enabled: bool,
    redirect_to: String,
    start_time: Instant,
    hostname: Option<String>,
    upstream_peer: Option<InnerMap>,
    extraparams: arc_swap::Guard<Arc<Extraparams>>,
    tls_fingerprint: Option<Arc<crate::utils::tls_fingerprint::Fingerprint>>,
    request_body: Vec<u8>,
    malware_detected: bool,
    malware_response_sent: bool,
}

#[async_trait]
impl ProxyHttp for LB {
    type CTX = Context;
    fn new_ctx(&self) -> Self::CTX {
        Context {
            backend_id: String::new(),
            https_proxy_enabled: false,
            redirect_to: String::new(),
            start_time: Instant::now(),
            hostname: None,
            upstream_peer: None,
            extraparams: self.extraparams.load(),
            tls_fingerprint: None,
            request_body: Vec::new(),
            malware_detected: false,
            malware_response_sent: false,
        }
    }
    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let ep = _ctx.extraparams.clone();

        // Try to get TLS fingerprint if available
        if _ctx.tls_fingerprint.is_none() {
            if let Some(peer_addr) = session.client_addr().and_then(|addr| addr.as_inet()) {
                if let Some(fingerprint) = crate::utils::tls_client_hello::get_fingerprint(&peer_addr) {
                    _ctx.tls_fingerprint = Some(fingerprint.clone());
                    debug!(
                        "TLS Fingerprint retrieved for session - Peer: {}, JA4: {}, SNI: {:?}, ALPN: {:?}",
                        peer_addr,
                        fingerprint.ja4,
                        fingerprint.sni,
                        fingerprint.alpn
                    );
                }
            }
        }

        // Evaluate WAF rules
        if let Some(peer_addr) = session.client_addr().and_then(|addr| addr.as_inet()) {
            let socket_addr = std::net::SocketAddr::new(peer_addr.ip(), peer_addr.port());
            match evaluate_waf_for_pingora_request(session.req_header(), b"", socket_addr).await {
                Ok(Some(waf_result)) => {
                    debug!("WAF rule matched: rule={}, id={}, action={:?}", waf_result.rule_name, waf_result.rule_id, waf_result.action);
                    match waf_result.action {
                        WafAction::Block => {
                            info!("WAF blocked request: rule={}, id={}, uri={}", waf_result.rule_name, waf_result.rule_id, session.req_header().uri);
                            let mut header = ResponseHeader::build(403, None).unwrap();
                            header.insert_header("X-WAF-Rule", waf_result.rule_name).ok();
                            header.insert_header("X-WAF-Rule-ID", waf_result.rule_id).ok();
                            session.set_keepalive(None);
                            session.write_response_header(Box::new(header), true).await?;
                            return Ok(true);
                        }
                        WafAction::Challenge => {
                            info!("WAF challenge required: rule={}, id={}, uri={}", waf_result.rule_name, waf_result.rule_id, session.req_header().uri);

                            // Check for captcha token in cookies or headers
                            let mut captcha_token: Option<String> = None;

                            // Check cookies for captcha_token
                            if let Some(cookies) = session.req_header().headers.get("cookie") {
                                if let Ok(cookie_str) = cookies.to_str() {
                                    for cookie in cookie_str.split(';') {
                                        let trimmed = cookie.trim();
                                        if let Some(value) = trimmed.strip_prefix("captcha_token=") {
                                            captcha_token = Some(value.to_string());
                                            break;
                                        }
                                    }
                                }
                            }

                            // Check X-Captcha-Token header if not found in cookies
                            if captcha_token.is_none() {
                                if let Some(token_header) = session.req_header().headers.get("x-captcha-token") {
                                    if let Ok(token_str) = token_header.to_str() {
                                        captcha_token = Some(token_str.to_string());
                                    }
                                }
                            }

                            // Validate token if present
                            let token_valid = if let Some(token) = &captcha_token {
                                let user_agent = session.req_header().headers
                                    .get("user-agent")
                                    .and_then(|h| h.to_str().ok())
                                    .unwrap_or("")
                                    .to_string();

                                match validate_captcha_token(token, &peer_addr.ip().to_string(), &user_agent).await {
                                    Ok(valid) => {
                                        if valid {
                                            debug!("Captcha token validated successfully");
                                        } else {
                                            debug!("Captcha token validation failed");
                                        }
                                        valid
                                    }
                                    Err(e) => {
                                        error!("Captcha token validation error: {}", e);
                                        false
                                    }
                                }
                            } else {
                                false
                            };

                            if !token_valid {
                                // Generate a new token (don't reuse invalid token)
                                let jwt_token = {
                                    let user_agent = session.req_header().headers
                                        .get("user-agent")
                                        .and_then(|h| h.to_str().ok())
                                        .unwrap_or("")
                                        .to_string();

                                    match generate_captcha_token(
                                        peer_addr.ip().to_string(),
                                        user_agent,
                                        None, // JA4 fingerprint not available here
                                    ).await {
                                        Ok(token) => token.token,
                                        Err(e) => {
                                            error!("Failed to generate captcha token: {}", e);
                                            // Fallback to challenge without token
                                            match apply_captcha_challenge_with_token("") {
                                                Ok(html) => {
                                                    let mut header = ResponseHeader::build(403, None).unwrap();
                                                    header.insert_header("Content-Type", "text/html; charset=utf-8").ok();
                                                    session.set_keepalive(None);
                                                    session.write_response_header(Box::new(header), false).await?;
                                                    session.write_response_body(Some(Bytes::from(html)), true).await?;
                                                    return Ok(true);
                                                }
                                                Err(e) => {
                                                    error!("Failed to apply captcha challenge: {}", e);
                                                    // Block the request if captcha fails
                                                    let mut header = ResponseHeader::build(403, None).unwrap();
                                                    header.insert_header("X-WAF-Rule", waf_result.rule_name).ok();
                                                    header.insert_header("X-WAF-Rule-ID", waf_result.rule_id).ok();
                                                    session.set_keepalive(None);
                                                    session.write_response_header(Box::new(header), true).await?;
                                                    return Ok(true);
                                                }
                                            }
                                        }
                                    }
                                };

                                // Return captcha challenge page
                                match apply_captcha_challenge_with_token(&jwt_token) {
                                    Ok(html) => {
                                        let mut header = ResponseHeader::build(403, None).unwrap();
                                        header.insert_header("Content-Type", "text/html; charset=utf-8").ok();
                                        header.insert_header("Set-Cookie", format!("captcha_token={}; Path=/; HttpOnly; SameSite=Lax", jwt_token)).ok();
                                        header.insert_header("X-WAF-Rule", waf_result.rule_name).ok();
                                        header.insert_header("X-WAF-Rule-ID", waf_result.rule_id).ok();
                                        session.set_keepalive(None);
                                        session.write_response_header(Box::new(header), false).await?;
                                        session.write_response_body(Some(Bytes::from(html)), true).await?;
                                        return Ok(true);
                                    }
                                    Err(e) => {
                                        error!("Failed to apply captcha challenge: {}", e);
                                        // Block the request if captcha fails
                                        let mut header = ResponseHeader::build(403, None).unwrap();
                                        header.insert_header("X-WAF-Rule", waf_result.rule_name).ok();
                                        header.insert_header("X-WAF-Rule-ID", waf_result.rule_id).ok();
                                        session.set_keepalive(None);
                                        session.write_response_header(Box::new(header), true).await?;
                                        return Ok(true);
                                    }
                                }
                            } else {
                                // Token is valid, allow request to continue
                                debug!("Captcha token validated, allowing request");
                            }
                        }
                        WafAction::Allow => {
                            debug!("WAF allowed request: rule={}, id={}", waf_result.rule_name, waf_result.rule_id);
                            // Allow the request to continue
                        }
                    }
                }
                Ok(None) => {
                    // No WAF rules matched, allow request to continue
                    debug!("WAF: No rules matched for uri={}", session.req_header().uri);
                }
                Err(e) => {
                    error!("WAF evaluation error: {}", e);
                    // On error, allow request to continue (fail open)
                }
            }
        } else {
            debug!("WAF: No peer address available for request");
        }

        let hostname = return_header_host(&session);
        _ctx.hostname = hostname;

        let mut backend_id = None;

        if ep.sticky_sessions {
            if let Some(cookies) = session.req_header().headers.get("cookie") {
                if let Ok(cookie_str) = cookies.to_str() {
                    for cookie in cookie_str.split(';') {
                        let trimmed = cookie.trim();
                        if let Some(value) = trimmed.strip_prefix("backend_id=") {
                            backend_id = Some(value);
                            break;
                        }
                    }
                }
            }
        }

        match _ctx.hostname.as_ref() {
            None => return Ok(false),
            Some(host) => {
                // let optioninnermap = self.get_host(host.as_str(), host.as_str(), backend_id);
                let optioninnermap = self.get_host(host.as_str(), session.req_header().uri.path(), backend_id);
                match optioninnermap {
                    None => return Ok(false),
                    Some(ref innermap) => {
                        if let Some(rate) = innermap.rate_limit.or(ep.rate_limit) {
                            // let rate_key = session.client_addr().and_then(|addr| addr.as_inet()).map(|inet| inet.ip().to_string()).unwrap_or_else(|| host.to_string());
                            let rate_key = session.client_addr().and_then(|addr| addr.as_inet()).map(|inet| inet.ip());
                            let curr_window_requests = RATE_LIMITER.observe(&rate_key, 1);
                            if curr_window_requests > rate {
                                let mut header = ResponseHeader::build(429, None).unwrap();
                                header.insert_header("X-Rate-Limit-Limit", rate.to_string()).unwrap();
                                header.insert_header("X-Rate-Limit-Remaining", "0").unwrap();
                                header.insert_header("X-Rate-Limit-Reset", "1").unwrap();
                                session.set_keepalive(None);
                                session.write_response_header(Box::new(header), true).await?;
                                debug!("Rate limited: {:?}, {}", rate_key, rate);
                                return Ok(true);
                            }
                        }
                    }
                }
                _ctx.upstream_peer = optioninnermap;
            }
        }
        Ok(false)
    }
    async fn upstream_peer(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<Box<HttpPeer>> {
        // Check if malware was detected, send JSON response and prevent forwarding
        if ctx.malware_detected && !ctx.malware_response_sent {
            // Check if response has already been written
            if session.response_written().is_some() {
                warn!("Response already written, cannot block malware request in upstream_peer");
                ctx.malware_response_sent = true;
                return Err(Box::new(Error {
                    etype: HTTPStatus(403),
                    esource: Upstream,
                    retry: RetryType::Decided(false),
                    cause: None,
                    context: Option::from(ImmutStr::Static("Malware detected")),
                }));
            }

            info!("Blocking request due to malware detection");

            // Build JSON response
            let json_response = serde_json::json!({
                "success": false,
                "error": "Request blocked",
                "reason": "malware_detected",
                "message": "Malware detected in request"
            });
            let json_body = Bytes::from(json_response.to_string());

            // Build response header
            let mut header = ResponseHeader::build(403, None).unwrap();
            header.insert_header("Content-Type", "application/json").ok();
            header.insert_header("X-Content-Scan-Result", "malware_detected").ok();

            session.set_keepalive(None);

            // Try to write response, handle error if response already sent
            match session.write_response_header(Box::new(header), false).await {
                Ok(_) => {
                    match session.write_response_body(Some(json_body), true).await {
                        Ok(_) => {
                            ctx.malware_response_sent = true;
                        }
                        Err(e) => {
                            warn!("Failed to write response body for malware block in upstream_peer: {}", e);
                            ctx.malware_response_sent = true;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to write response header for malware block in upstream_peer: {}", e);
                    ctx.malware_response_sent = true;
                }
            }

            return Err(Box::new(Error {
                etype: HTTPStatus(403),
                esource: Upstream,
                retry: RetryType::Decided(false),
                cause: None,
                context: Option::from(ImmutStr::Static("Malware detected")),
            }));
        }

        // let host_name = return_header_host(&session);
        match ctx.hostname.as_ref() {
            Some(hostname) => {
                match ctx.upstream_peer.as_ref() {
                    // Some((address, port, ssl, is_h2, https_proxy_enabled)) => {
                    Some(innermap) => {
                        let mut peer = Box::new(HttpPeer::new((innermap.address.clone(), innermap.port.clone()), innermap.ssl_enabled, String::new()));
                        // if session.is_http2() {
                        if innermap.http2_enabled {
                            peer.options.alpn = ALPN::H2;
                        }
                        if innermap.ssl_enabled {
                            peer.sni = hostname.clone();
                            peer.options.verify_cert = false;
                            peer.options.verify_hostname = false;
                        }
                        if ctx.https_proxy_enabled || innermap.https_proxy_enabled {
                            if let Some(stream) = session.stream() {
                                if stream.get_ssl().is_none() {
                                    if let Some(addr) = session.server_addr() {
                                        if let Some((host, _)) = addr.to_string().split_once(':') {
                                            let uri = session.req_header().uri.path_and_query().map_or("/", |pq| pq.as_str());
                                            let port = self.config.proxy_port_tls.unwrap_or(403);
                                            ctx.https_proxy_enabled = true;
                                            ctx.redirect_to = format!("https://{}:{}{}", host, port, uri);
                                        }
                                    }
                                }
                            }
                        }

                        ctx.backend_id = format!("{}:{}:{}", innermap.address.clone(), innermap.port.clone(), innermap.ssl_enabled);
                        Ok(peer)
                    }
                    None => {
                        if let Err(e) = session.respond_error_with_body(502, Bytes::from("502 Bad Gateway\n")).await {
                            error!("Failed to send error response: {:?}", e);
                        }
                        Err(Box::new(Error {
                            etype: HTTPStatus(502),
                            esource: Upstream,
                            retry: RetryType::Decided(false),
                            cause: None,
                            context: Option::from(ImmutStr::Static("Upstream not found")),
                        }))
                    }
                }
            }
            None => {
                // session.respond_error_with_body(502, Bytes::from("502 Bad Gateway\n")).await.expect("Failed to send error");
                if let Err(e) = session.respond_error_with_body(502, Bytes::from("502 Bad Gateway\n")).await {
                    error!("Failed to send error response: {:?}", e);
                }
                Err(Box::new(Error {
                    etype: HTTPStatus(502),
                    esource: Upstream,
                    retry: RetryType::Decided(false),
                    cause: None,
                    context: None,
                }))
            }
        }
    }

    async fn upstream_request_filter(&self, _session: &mut Session, upstream_request: &mut RequestHeader, ctx: &mut Self::CTX) -> Result<()> {
        if let Some(hostname) = ctx.hostname.as_ref() {
            upstream_request.insert_header("Host", hostname)?;
        }
        if let Some(peer) = ctx.upstream_peer.as_ref() {
            upstream_request.insert_header("X-Forwarded-For", peer.address.as_str())?;
        }
        Ok(())
    }


    async fn request_body_filter(&self, _session: &mut Session, body: &mut Option<Bytes>, end_of_stream: bool, ctx: &mut Self::CTX) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        // Accumulate request body for content scanning
        if let Some(body_bytes) = body {
            ctx.request_body.extend_from_slice(body_bytes);
        }

        // When stream ends, perform content scanning if enabled
        if end_of_stream && !ctx.request_body.is_empty() {
            if let Some(scanner) = crate::content_scanning::get_global_content_scanner() {
                // Get peer address for scanning
                let peer_addr = if let Some(addr) = _session.client_addr().and_then(|a| a.as_inet()) {
                    std::net::SocketAddr::new(addr.ip(), addr.port())
                } else {
                    return Ok(()); // Can't scan without peer address
                };

                // Convert request header to Parts for should_scan check
                let req_header = _session.req_header();
                let method = req_header.method.as_str();
                let uri = req_header.uri.to_string();
                let mut req_builder = hyper::http::Request::builder()
                    .method(method)
                    .uri(&uri);

                // Copy essential headers for content scanning (content-type, content-length)
                if let Some(content_type) = req_header.headers.get("content-type") {
                    if let Ok(ct_str) = content_type.to_str() {
                        req_builder = req_builder.header("content-type", ct_str);
                    }
                }
                if let Some(content_length) = req_header.headers.get("content-length") {
                    if let Ok(cl_str) = content_length.to_str() {
                        req_builder = req_builder.header("content-length", cl_str);
                    }
                }

                let req = match req_builder.body(()) {
                    Ok(req) => req,
                    Err(_) => {
                        warn!("Failed to build request for content scanning, skipping scan");
                        return Ok(());
                    }
                };
                let (req_parts, _) = req.into_parts();

                // Check if we should scan this request
                if scanner.should_scan(&req_parts, &ctx.request_body, peer_addr) {
                    debug!("Content scanner: scanning request body (size: {} bytes)", ctx.request_body.len());

                    // Check if content-type is multipart and scan accordingly
                    let content_type = req_parts.headers
                        .get("content-type")
                        .and_then(|h| h.to_str().ok());

                    let scan_result = if let Some(ct) = content_type {
                        if let Some(boundary) = crate::content_scanning::extract_multipart_boundary(ct) {
                            debug!("Detected multipart content, scanning parts individually");
                            scanner.scan_multipart_content(&ctx.request_body, &boundary).await
                        } else {
                            scanner.scan_content(&ctx.request_body).await
                        }
                    } else {
                        scanner.scan_content(&ctx.request_body).await
                    };

                    match scan_result {
                        Ok(scan_result) => {
                            if scan_result.malware_detected {
                                info!("Malware detected in request from {}: {} {} - signature: {:?}",
                                    peer_addr, method, uri, scan_result.signature);

                                // Mark malware detected in context - upstream_peer will handle blocking
                                ctx.malware_detected = true;

                                // Don't send response here - let upstream_peer handle it before forwarding
                                return Ok(());
                            } else {
                                debug!("Content scan completed: no malware detected");
                            }
                        }
                        Err(e) => {
                            warn!("Content scanning failed: {}", e);
                            // On scanning error, allow the request to proceed (fail open)
                        }
                    }
                } else {
                    debug!("Content scanner: skipping scan (should_scan returned false)");
                }
            }
        }

        Ok(())
    }
    async fn response_filter(&self, session: &mut Session, _upstream_response: &mut ResponseHeader, ctx: &mut Self::CTX) -> Result<()> {
        // _upstream_response.insert_header("X-Proxied-From", "Fooooooooooooooo").unwrap();
        if ctx.extraparams.sticky_sessions {
            let backend_id = ctx.backend_id.clone();
            if let Some(bid) = self.ump_byid.get(&backend_id) {
                let _ = _upstream_response.insert_header("set-cookie", format!("backend_id={}; Path=/; Max-Age=600; HttpOnly; SameSite=Lax", bid.address));
            }
        }
        if ctx.https_proxy_enabled {
            let mut redirect_response = ResponseHeader::build(StatusCode::MOVED_PERMANENTLY, None)?;
            redirect_response.insert_header("Location", ctx.redirect_to.clone())?;
            redirect_response.insert_header("Content-Length", "0")?;
            session.write_response_header(Box::new(redirect_response), false).await?;
        }
        match ctx.hostname.as_ref() {
            Some(host) => {
                let path = session.req_header().uri.path();
                let host_header = host;
                let split_header = host_header.split_once(':');

                match split_header {
                    Some(sh) => {
                        let yoyo = self.get_header(sh.0, path);
                        for k in yoyo.iter() {
                            for t in k.iter() {
                                _upstream_response.insert_header(t.0.clone(), t.1.clone()).unwrap();
                            }
                        }
                    }
                    None => {
                        let yoyo = self.get_header(host_header, path);
                        for k in yoyo.iter() {
                            for t in k.iter() {
                                _upstream_response.insert_header(t.0.clone(), t.1.clone()).unwrap();
                            }
                        }
                    }
                }
            }
            None => {}
        }
        session.set_keepalive(Some(300));
        Ok(())
    }

    async fn logging(&self, session: &mut Session, _e: Option<&pingora_core::Error>, ctx: &mut Self::CTX) {
        let response_code = session.response_written().map_or(0, |resp| resp.status.as_u16());
        debug!("{}, response code: {response_code}", self.request_summary(session, ctx));

        // Log TLS fingerprint if available
        if let Some(ref fingerprint) = ctx.tls_fingerprint {
            debug!(
                "Request completed - JA4: {}, JA4_Raw: {}, TLS_Version: {}, Cipher: {:?}, SNI: {:?}, ALPN: {:?}, Response: {}",
                fingerprint.ja4,
                fingerprint.ja4_raw,
                fingerprint.tls_version,
                fingerprint.cipher_suite,
                fingerprint.sni,
                fingerprint.alpn,
                response_code
            );
        }

        let m = &crate::utils::metrics::MetricTypes {
            method: session.req_header().method.to_string(),
            code: session.response_written().map(|resp| resp.status.as_str().to_owned()).unwrap_or("0".to_string()),
            latency: ctx.start_time.elapsed(),
            version: session.req_header().version,
        };
        crate::utils::metrics::calc_metrics(m);

        // Clean up fingerprint from storage after logging
        if let Some(peer_addr) = session.client_addr().and_then(|addr| addr.as_inet()) {
            crate::utils::tls_client_hello::remove_fingerprint(&peer_addr);
        }
    }
}

impl LB {}

fn return_header_host(session: &Session) -> Option<String> {
    if session.is_http2() {
        match session.req_header().uri.host() {
            Some(host) => Option::from(host.to_string()),
            None => None,
        }
    } else {
        match session.req_header().headers.get("host") {
            Some(host) => {
                let header_host = host.to_str().unwrap().splitn(2, ':').collect::<Vec<&str>>();
                Option::from(header_host[0].to_string())
            }
            None => None,
        }
    }
}
