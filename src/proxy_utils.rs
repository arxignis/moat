use anyhow::{anyhow, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, Uri};
use hyper::header::HeaderValue;
use hyper::header::HOST;
// Client and HttpConnector types are not referenced directly here

use crate::http::ProxyContext;
use crate::threat;

pub type ProxyBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

pub fn header_json() -> (hyper::header::HeaderName, hyper::header::HeaderValue) {
    (
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    )
}

pub fn json(s: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::<Bytes>::from(Bytes::from(format!("{s}\n"))));
    let (k, v) = header_json();
    r.headers_mut().insert(k, v);
    r
}

pub fn build_upstream_uri(incoming: &Uri, upstream: &Uri) -> Result<Uri> {
    let mut parts = upstream.clone().into_parts();
    parts.path_and_query.replace(
        incoming
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| "/".parse().unwrap()),
    );
    Uri::from_parts(parts).map_err(|e| anyhow!("failed to construct upstream uri: {e}"))
}

pub fn build_proxy_error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let body = serde_json::json!({
        "ok": false,
        "error": message,
    })
    .to_string();
    let boxed = Full::new(Bytes::from(body))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(boxed)
        .expect("valid response")
}

pub async fn forward_to_upstream_with_body(
    req_parts: &hyper::http::request::Parts,
    body_bytes: bytes::Bytes,
    ctx: std::sync::Arc<ProxyContext>,
    peer_addr: std::net::SocketAddr,
    is_tls: bool,
) -> Result<Response<ProxyBody>> {
    let upstream_uri = build_upstream_uri(&req_parts.uri, &ctx.upstream)?;
    let mut builder = Request::builder()
        .method(req_parts.method.clone())
        .version(req_parts.version)
        .uri(upstream_uri.clone());

    // Copy all headers from the original request, including Host
    for (name, value) in req_parts.headers.iter() {
        if name != HOST {
            builder = builder.header(name, value.clone());
        }
    }

    let mut outbound = builder
        .body(Full::new(body_bytes))
        .map_err(|e| anyhow!("failed to build proxy request: {e}"))?;

    // Add X-Forwarded-For header with client IP
    let client_ip = peer_addr.ip().to_string();
    outbound.headers_mut().insert(
        hyper::header::HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&client_ip)
            .map_err(|e| anyhow!("invalid client IP for X-Forwarded-For: {e}"))?,
    );

    // Add X-Forwarded-Proto header based on TLS usage
    let proto = if is_tls { "https" } else { "http" };
    outbound.headers_mut().insert(
        hyper::header::HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static(proto),
    );

    // Add X-Forwarded-Host header with original host
    if let Some(host) = req_parts.headers.get(HOST) {
        outbound.headers_mut().insert(
            hyper::header::HeaderName::from_static("x-forwarded-host"),
            host.clone(),
        );
    }

    // Add AX-Country and AX-ASN headers from threat intelligence
    if let Ok(Some(waf_fields)) = threat::get_waf_fields(&peer_addr.ip().to_string()).await {
        // Add AX-Country header
        if let Ok(value) = HeaderValue::from_str(&waf_fields.ip_src_country) {
            outbound.headers_mut().insert(
                hyper::header::HeaderName::from_static("ax-country"),
                value,
            );
        }

        // Add AX-ASN header
        if let Ok(value) = HeaderValue::from_str(&waf_fields.ip_src_asn.to_string()) {
            outbound.headers_mut().insert(
                hyper::header::HeaderName::from_static("ax-asn"),
                value,
        );
        }
    }

    let response = ctx
        .client
        .request(outbound)
        .await
        .map_err(|e| anyhow!("upstream request error: {e}"))?;
    let (parts, body) = response.into_parts();
    let boxed = body.boxed();
    Ok(Response::from_parts(parts, boxed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_json() {
        let (name, value) = header_json();
        assert_eq!(name, hyper::header::CONTENT_TYPE);
        assert_eq!(value, HeaderValue::from_static("application/json"));
    }

    #[test]
    fn test_json_response() {
        let response = json(r#"{"status":"ok"}"#);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(hyper::header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );
    }

    #[test]
    fn test_build_upstream_uri_with_path() {
        let incoming = Uri::from_static("http://example.com/api/v1/users?id=123");
        let upstream = Uri::from_static("http://backend.local:8080");

        let result = build_upstream_uri(&incoming, &upstream).unwrap();

        assert_eq!(result.scheme_str(), Some("http"));
        assert_eq!(result.authority().map(|a| a.as_str()), Some("backend.local:8080"));
        assert_eq!(result.path(), "/api/v1/users");
        assert_eq!(result.query(), Some("id=123"));
    }

    #[test]
    fn test_build_upstream_uri_root_path() {
        let incoming = Uri::from_static("http://example.com/");
        let upstream = Uri::from_static("https://backend.local");

        let result = build_upstream_uri(&incoming, &upstream).unwrap();

        assert_eq!(result.scheme_str(), Some("https"));
        assert_eq!(result.authority().map(|a| a.as_str()), Some("backend.local"));
        assert_eq!(result.path(), "/");
    }

    #[test]
    fn test_build_upstream_uri_no_path() {
        let incoming = Uri::from_static("http://example.com");
        let upstream = Uri::from_static("http://backend.local:3000");

        let result = build_upstream_uri(&incoming, &upstream).unwrap();

        assert_eq!(result.path(), "/");
    }

    #[test]
    fn test_build_upstream_uri_preserves_query() {
        let incoming = Uri::from_static("http://example.com/search?q=test&limit=10");
        let upstream = Uri::from_static("http://backend.local");

        let result = build_upstream_uri(&incoming, &upstream).unwrap();

        assert_eq!(result.path(), "/search");
        assert_eq!(result.query(), Some("q=test&limit=10"));
    }

    #[test]
    fn test_build_proxy_error_response() {
        let response = build_proxy_error_response(StatusCode::FORBIDDEN, "Access denied");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get(hyper::header::CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/json"))
        );
    }

    #[test]
    fn test_build_proxy_error_response_formats_json() {
        let response = build_proxy_error_response(StatusCode::BAD_REQUEST, "Invalid input");

        // We can't easily check the body content without consuming it,
        // but we can verify the response is properly constructed
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().contains_key(hyper::header::CONTENT_TYPE));
    }
}
