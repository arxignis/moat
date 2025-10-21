use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use hyper::{HeaderMap, StatusCode};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::form_urlencoded;
use http_body_util::BodyExt;

#[derive(Clone, Debug)]
pub enum ArxignisMode {
    Monitor,
    Block,
}

impl ArxignisMode {
    pub fn from_str(s: &str) -> ArxignisMode {
        match s.to_ascii_lowercase().as_str() {
            "block" => ArxignisMode::Block,
            _ => ArxignisMode::Monitor,
        }
    }
}

#[derive(Clone, Debug)]
pub enum CaptchaProvider {
    Turnstile,
    Recaptcha,
    Hcaptcha,
}

impl CaptchaProvider {
    pub fn from_str(s: &str) -> Option<CaptchaProvider> {
        match s.to_ascii_lowercase().as_str() {
            "turnstile" => Some(CaptchaProvider::Turnstile),
            "recaptcha" => Some(CaptchaProvider::Recaptcha),
            "hcaptcha" => Some(CaptchaProvider::Hcaptcha),
            _ => None,
        }
    }

    pub fn backend_url(&self) -> &'static str {
        match self {
            CaptchaProvider::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            CaptchaProvider::Recaptcha => "https://www.recaptcha.net/recaptcha/api/siteverify",
            CaptchaProvider::Hcaptcha => "https://hcaptcha.com/siteverify",
        }
    }

    pub fn frontend_js(&self) -> &'static str {
        match self {
            CaptchaProvider::Turnstile => "https://challenges.cloudflare.com/turnstile/v0/api.js",
            CaptchaProvider::Recaptcha => "https://www.recaptcha.net/recaptcha/api.js",
            CaptchaProvider::Hcaptcha => "https://js.hcaptcha.com/1/api.js",
        }
    }

    pub fn response_key(&self) -> &'static str {
        match self {
            CaptchaProvider::Turnstile => "cf-turnstile-response",
            CaptchaProvider::Recaptcha => "g-recaptcha-response",
            CaptchaProvider::Hcaptcha => "h-captcha-response",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CaptchaConfig {
    pub provider: Option<CaptchaProvider>,
    pub site_key: Option<String>,
    pub secret_key: Option<String>,
    pub template_path: Option<PathBuf>,
    pub http_status_code: u16,
}

#[derive(Clone)]
pub struct ArxignisClient {
    base_url: String,
    api_key: String,
    http: Client,
    pub mode: ArxignisMode,
    pub captcha: CaptchaConfig,
}

impl ArxignisClient {
    pub fn new(base_url: String, api_key: String, mode: ArxignisMode, captcha: CaptchaConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(30000))
            .connect_timeout(Duration::from_millis(10000))
            .user_agent("Moat/1.0")
            .build()?;
        Ok(Self { base_url, api_key, http, mode, captcha })
    }

    pub async fn get_threat(&self, ip: &str) -> Result<ThreatResponse> {
        let url = format!("{}/threat?ip={}", self.base_url.trim_end_matches('/'), ip);
        let mut req = self.http.get(&url);
        if !self.api_key.is_empty() {
            req = req.bearer_auth(&self.api_key);
        }
        let res = req.send().await.context("threat request failed")?;
        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(anyhow!("threat API error {}: {}", status, body));
        }
        let parsed = res.json::<ThreatResponse>().await.context("parse threat json")?;
        Ok(parsed)
    }

    pub async fn send_filter(&self, event: &FilterEvent, idempotency_key: &str) -> Result<FilterDecision> {
        let base = self.base_url.trim_end_matches('/');
        let url = format!("{}/filter", base);
        
        let mut req = self.http.post(url).query(&[("idempotency-key", idempotency_key), ("originalEvent", "false")]).json(event);
        if !self.api_key.is_empty() {
            req = req.bearer_auth(&self.api_key);
        }
        let res = req.send().await.context("filter request failed")?;
        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            return Err(anyhow!("filter API error {}: {}", status, body));
        }
        let parsed = res.json::<FilterDecision>().await.context("parse filter json")?;
        Ok(parsed)
    }

    pub async fn send_scan(&self, scan: &ScanRequest) -> Result<ScanDecision> {
        let base = self.base_url.trim_end_matches('/');
        let url = format!("{}/scan", base);
        let mut req = self.http.post(url).json(scan);
        if !self.api_key.is_empty() {
            req = req.bearer_auth(&self.api_key);
        }
        let res = req.send().await.context("scan request failed")?;
        if !res.status().is_success() {
            return Err(anyhow!("scan non-200: {}", res.status()));
        }
        let parsed = res.json::<ScanDecision>().await.context("parse scan json")?;
        Ok(parsed)
    }

    pub async fn validate_captcha(&self, response: &str, remote_ip: &str) -> Result<bool> {
        let provider = match self.captcha.provider {
            Some(ref p) => p,
            None => return Ok(false),
        };
        let secret = match self.captcha.secret_key.as_ref() {
            Some(s) if !s.is_empty() => s,
            _ => return Ok(false),
        };
        let url = provider.backend_url();
        let params = [
            ("secret", secret.as_str()),
            ("response", response),
            ("remoteip", remote_ip),
        ];
        let res = self
            .http
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(serde_urlencoded::to_string(&params).unwrap_or_default())
            .timeout(Duration::from_millis(2000))
            .send()
            .await
            .context("captcha http error")?;
        if !res.status().is_success() {
            return Ok(false);
        }
        let v: serde_json::Value = res.json().await.unwrap_or(serde_json::json!({"success": false}));
        Ok(v.get("success").and_then(|s| s.as_bool()).unwrap_or(false))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatResponse {
    pub advice: Option<String>,
    pub intel: Option<serde_json::Value>,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilterEvent {
    pub event_type: String,
    pub schema_version: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")] pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub tenant_id: Option<String>,
    pub http: HttpSection,
    #[serde(skip_serializing_if = "Option::is_none")] pub ip: Option<IpSection>,
    #[serde(skip_serializing_if = "Option::is_none")] pub threat: Option<ThreatSection>,
    #[serde(skip_serializing_if = "Option::is_none")] pub additional: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpSection {
    pub src: IpSrcSection,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpSrcSection {
    #[serde(skip_serializing_if = "Option::is_none")] pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")] pub asn_org: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub asn_country: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatSection {
    #[serde(skip_serializing_if = "Option::is_none")] pub score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")] pub advice: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HttpSection {
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")] pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub scheme: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")] pub remote_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub content_type: Option<String>,
    pub headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub body_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] pub content_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")] pub query_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilterDecision {
    pub action: Option<String>,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanRequest {
    pub content_type: String,
    pub body: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScanDecision {
    #[serde(default)]
    pub virus_detected: Option<bool>,
    #[serde(default)]
    pub files_infected: Option<u64>,
    #[serde(default)]
    pub virus_name: Option<String>,
}

pub fn build_event_from_request(
    headers: &HeaderMap,
    method: &str,
    uri: &hyper::Uri,
    body: &Bytes,
    remote_ip: &str,
    threat_response: Option<&ThreatResponse>,
    is_https: bool,
) -> FilterEvent {
    let host = uri.host().or_else(|| headers.get("host").and_then(|h| h.to_str().ok())).map(|s| s.to_string());
    let query = uri.query().map(|s| s.to_string());
    // Use scheme from URI, or default based on is_https flag
    let scheme = uri.scheme().map(|s| s.to_string()).or_else(|| Some(if is_https { "https" } else { "http" }.to_string()));
    // Use port from URI, or default to 443 for HTTPS, 80 for HTTP
    let port = uri.port_u16().or_else(|| Some(if is_https { 443 } else { 80 }));

    let mut headers_map = HashMap::new();
    let mut user_agent = None::<String>;
    let mut content_type = None::<String>;
    for (name, value) in headers.iter() {
        let key = name.as_str().to_string();
        let val = value.to_str().unwrap_or("").to_string();
        if key.eq_ignore_ascii_case("user-agent") { user_agent = Some(val.clone()); }
        if key.eq_ignore_ascii_case("content-type") { content_type = Some(val.clone()); }
        headers_map.insert(key, val);
    }

    let path = Some(uri.path().to_string());
    let content_length = Some(body.len());
    let body_str = String::from_utf8_lossy(body).to_string();
    let body_sha256 = format!("{:x}", Sha256::digest(body));
    let query_hash = query.as_ref().map(|q| format!("{:x}", Sha256::digest(q.as_bytes())));

    let http = HttpSection {
        method: method.to_string(),
        path,
        query,
        host,
        scheme,
        port,
        remote_ip: Some(remote_ip.to_string()),
        user_agent,
        content_type,
        headers: headers_map,
        body: if body.is_empty() { None } else { Some(body_str) },
        body_sha256: if body.is_empty() { None } else { Some(body_sha256) },
        content_length,
        query_hash,
    };

    // Extract threat intelligence data
    let (ip_section, threat_section) = if let Some(threat) = threat_response {
        let intel = threat.intel.as_ref();
        
        let ip_src = IpSrcSection {
            country: intel.and_then(|i| i.get("geo").and_then(|g| g.get("country").and_then(|c| c.as_str().map(String::from)))),
            asn: intel.and_then(|i| i.get("asn").and_then(|a| a.as_u64().map(|v| v as u32))),
            asn_org: intel.and_then(|i| i.get("org").and_then(|o| o.as_str().map(String::from))),
            asn_country: intel.and_then(|i| i.get("geo").and_then(|g| g.get("iso_code").and_then(|c| c.as_str().map(String::from)))),
        };
        
        let threat_sec = ThreatSection {
            score: intel.and_then(|i| i.get("score").and_then(|s| s.as_f64())),
            advice: threat.advice.clone(),
        };
        
        (Some(IpSection { src: ip_src }), Some(threat_sec))
    } else {
        (None, None)
    };

    // Generate a unique request ID
    let request_id = format!("req_{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));

    FilterEvent {
        event_type: "filter".to_string(),
        schema_version: "1.0".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        request_id: Some(request_id),
        tenant_id: threat_response.and_then(|t| t.tenant_id.clone()),
        http,
        ip: ip_section,
        threat: threat_section,
        additional: None,
    }
}

pub fn extract_captcha_response(provider: &Option<CaptchaProvider>, _headers: &HeaderMap, body: &Bytes) -> Option<String> {
    if !body.is_empty() {
        if let Ok(body_str) = std::str::from_utf8(body) {
            let pairs = form_urlencoded::parse(body_str.as_bytes());
            if let Some(p) = provider.as_ref() {
                let key = p.response_key();
                for (k, v) in pairs {
                    if k.as_ref() == key { return Some(v.into_owned()); }
                }
            } else {
                for (k, v) in pairs {
                    if k.as_ref().ends_with("captcha-response") { return Some(v.into_owned()); }
                }
            }
        }
    }
    None
}

pub fn build_block_response(html: String, status: u16) -> hyper::Response<http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>> {
    let body = http_body_util::Full::new(bytes::Bytes::from(html))
        .map_err(|never| match never {})
        .boxed();
    let res = hyper::Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN))
        .header("Content-Type", "text/html")
        .header("Cache-Control", "no-cache, no-store, must-revalidate")
        .header("Pragma", "no-cache")
        .header("Expires", "0")
        .body(body)
        .expect("build response");
    res
}

pub fn render_captcha_page(template: &str, provider: &CaptchaProvider, site_key: &str) -> String {
    // Very small template substitution compatible with our templates
    template
        .replace("{{captcha_site_key}}", site_key)
        .replace("{{captcha_frontend_js}}", provider.frontend_js())
        .replace("{{captcha_frontend_key}}", provider.response_key())
}

pub fn generate_captcha_token(ip: &str, user_agent: &str, ja4: Option<&str>) -> String {
    use rand::{distributions::Alphanumeric, thread_rng, Rng};
    let random: String = thread_rng().sample_iter(&Alphanumeric).take(16).map(char::from).collect();
    let ts = chrono::Utc::now().timestamp();
    let ip_hash = format!("{:x}", md5::compute(ip)).chars().take(8).collect::<String>();
    let ua_hash = format!("{:x}", md5::compute(user_agent)).chars().take(8).collect::<String>();
    let salt_sig = format!("{:x}", md5::compute(format!("{}{}{}", ip, user_agent, "SECRET_SALT")));
    let sig = salt_sig.chars().take(16).collect::<String>();
    let ja4_hash = ja4.filter(|s| !s.is_empty() && *s != "no_ssl" && *s != "unknown").map(|j| {
        format!("_{:8}", format!("{:x}", md5::compute(j)).chars().take(8).collect::<String>())
    }).unwrap_or_default();
    format!("captcha_{}_{}_{}_{}_{}{}", ts, ip_hash, ua_hash, random, sig, ja4_hash)
}

pub fn verify_captcha_token(token: &str, ip: &str, user_agent: &str, ja4: Option<&str>) -> bool {
    let parts: Vec<&str> = token.split('_').collect();
    if parts.len() < 6 || parts[0] != "captcha" { return false; }
    let ts = parts[1].parse::<i64>().ok();
    if ts.is_none() { return false; }
    if chrono::Utc::now().timestamp() - ts.unwrap() >= 7200 { return false; }
    let expected_ip_hash = format!("{:x}", md5::compute(ip)).chars().take(8).collect::<String>();
    if parts[2] != expected_ip_hash { return false; }
    let expected_ua_hash = format!("{:x}", md5::compute(user_agent)).chars().take(8).collect::<String>();
    if parts[3] != expected_ua_hash { return false; }
    let expected_sig = format!("{:x}", md5::compute(format!("{}{}{}", ip, user_agent, "SECRET_SALT")));
    let expected_sig = expected_sig.chars().take(16).collect::<String>();
    if parts[5] != expected_sig { return false; }
    if parts.len() >= 7 {
        if let Some(j) = ja4 {
            if !j.is_empty() && j != "no_ssl" && j != "unknown" {
                let expected_ja4_hash = format!("{:x}", md5::compute(j)).chars().take(8).collect::<String>();
                if parts[6] != expected_ja4_hash { return false; }
            }
        }
    }
    true
}


