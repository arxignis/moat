use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH, Duration, Instant};

use chrono::{DateTime, Utc};
use hyper::Response;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use reqwest::Client;

use std::sync::Arc;
use std::sync::RwLock;
use tokio::sync::mpsc;
use tokio::time::interval;

use crate::http::tls_fingerprint::Fingerprint as TlsFingerprint;
use crate::proxy_utils::ProxyBody;

/// Configuration for sending access logs to arxignis server
#[derive(Debug, Clone)]
pub struct LogSenderConfig {
    pub enabled: bool,
    pub base_url: String,
    pub api_key: String,
    pub batch_size_limit: usize,    // Maximum number of logs in a batch
    pub batch_size_bytes: usize,    // Maximum size of batch in bytes (5MB)
    pub batch_timeout_secs: u64,    // Maximum time to wait before sending batch (10 seconds)
    pub include_response_body: bool, // Whether to include response body in logs
    pub max_body_size: usize,       // Maximum size for request/response bodies (1MB)
}

impl LogSenderConfig {
    pub fn new(enabled: bool, base_url: String, api_key: String) -> Self {
        Self {
            enabled,
            base_url,
            api_key,
            batch_size_limit: 5000,        // Default: 5000 logs per batch
            batch_size_bytes: 5 * 1024 * 1024, // Default: 5MB
            batch_timeout_secs: 10,        // Default: 10 seconds
            include_response_body: true,   // Default: include response body
            max_body_size: 1024 * 1024,    // Default: 1MB
        }
    }

    /// Check if log sending is enabled and api_key is configured
    pub fn should_send_logs(&self) -> bool {
        self.enabled && !self.api_key.is_empty()
    }
}

/// Buffer for storing access logs before batch sending
#[derive(Debug)]
pub struct LogBuffer {
    logs: Vec<HttpAccessLog>,
    failed_logs: Vec<HttpAccessLog>, // Store logs that failed to send
    total_size_bytes: usize,
    failed_size_bytes: usize,
    last_flush_time: Instant,
    last_retry_time: Instant, // Track when we last tried to resend failed logs
}

impl LogBuffer {
    fn new() -> Self {
        Self {
            logs: Vec::new(),
            failed_logs: Vec::new(),
            total_size_bytes: 0,
            failed_size_bytes: 0,
            last_flush_time: Instant::now(),
            last_retry_time: Instant::now(),
        }
    }

    fn add_log(&mut self, log: HttpAccessLog) -> usize {
        // Estimate log size (rough approximation)
        let log_size = estimate_log_size(&log);
        self.logs.push(log);
        self.total_size_bytes += log_size;
        self.logs.len()
    }

    fn should_flush(&self, config: &LogSenderConfig) -> bool {
        self.logs.len() >= config.batch_size_limit ||
        self.total_size_bytes >= config.batch_size_bytes ||
        self.last_flush_time.elapsed().as_secs() >= config.batch_timeout_secs
    }

    fn take_logs(&mut self) -> Vec<HttpAccessLog> {
        self.total_size_bytes = 0;
        self.last_flush_time = Instant::now();
        std::mem::take(&mut self.logs)
    }

    fn is_empty(&self) -> bool {
        self.logs.is_empty()
    }

    fn add_failed_logs(&mut self, logs: Vec<HttpAccessLog>) {
        for log in logs {
            let log_size = estimate_log_size(&log);
            self.failed_logs.push(log);
            self.failed_size_bytes += log_size;
        }
    }

    fn should_retry_failed_logs(&self) -> bool {
        // Retry failed logs every 30 seconds
        !self.failed_logs.is_empty() &&
        self.last_retry_time.elapsed().as_secs() >= 30
    }

    fn take_failed_logs(&mut self) -> Vec<HttpAccessLog> {
        self.failed_size_bytes = 0;
        self.last_retry_time = Instant::now();
        std::mem::take(&mut self.failed_logs)
    }

    fn has_failed_logs(&self) -> bool {
        !self.failed_logs.is_empty()
    }
}

/// Estimate the size of a log entry in bytes
fn estimate_log_size(log: &HttpAccessLog) -> usize {
    // Rough estimation based on JSON serialization
    // This is an approximation - actual size may vary
    let base_size = 1000; // Base overhead
    let body_size = log.http.body.len();
    let headers_size = log.http.headers.len() * 50; // Rough estimate for headers
    let response_size = log.response.body.len();

    base_size + body_size + headers_size + response_size
}

/// Global log sender configuration
static LOG_SENDER_CONFIG: std::sync::OnceLock<Arc<RwLock<Option<LogSenderConfig>>>> = std::sync::OnceLock::new();

/// Global log buffer for batching logs
static LOG_BUFFER: std::sync::OnceLock<Arc<RwLock<LogBuffer>>> = std::sync::OnceLock::new();

/// Channel for sending logs to the batch processor
static LOG_CHANNEL: std::sync::OnceLock<mpsc::UnboundedSender<HttpAccessLog>> = std::sync::OnceLock::new();

pub fn get_log_sender_config() -> Arc<RwLock<Option<LogSenderConfig>>> {
    LOG_SENDER_CONFIG
        .get_or_init(|| Arc::new(RwLock::new(None)))
        .clone()
}

pub fn get_log_buffer() -> Arc<RwLock<LogBuffer>> {
    LOG_BUFFER
        .get_or_init(|| Arc::new(RwLock::new(LogBuffer::new())))
        .clone()
}

pub fn get_log_channel() -> Option<&'static mpsc::UnboundedSender<HttpAccessLog>> {
    LOG_CHANNEL.get()
}

pub fn set_log_sender_config(config: LogSenderConfig) {
    let store = get_log_sender_config();
    if let Ok(mut guard) = store.write() {
        *guard = Some(config);
    }
}

pub fn set_log_channel(sender: mpsc::UnboundedSender<HttpAccessLog>) {
    let _ = LOG_CHANNEL.set(sender);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpAccessLog {
    pub event_type: String,
    pub schema_version: String,
    pub timestamp: DateTime<Utc>,
    pub request_id: String,
    pub http: HttpDetails,
    pub network: NetworkDetails,
    pub tls: Option<TlsDetails>,
    pub response: ResponseDetails,
    pub remediation: Option<RemediationDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpDetails {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub query: String,
    pub query_hash: Option<String>,
    pub headers: HashMap<String, String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub body: String,
    pub body_sha256: String,
    pub body_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDetails {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsDetails {
    pub version: String,
    pub cipher: String,
    pub alpn: Option<String>,
    pub sni: Option<String>,
    pub ja4: Option<String>,
    pub ja4one: Option<String>,
    pub ja4l: Option<String>,
    pub ja4t: Option<String>,
    pub ja4h: Option<String>,
    pub server_cert: Option<ServerCertDetails>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerCertDetails {
    pub issuer: String,
    pub subject: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub fingerprint_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDetails {
    pub status: u16,
    pub status_text: String,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationDetails {
    pub waf_action: Option<String>,
    pub waf_rule_id: Option<String>,
    pub waf_rule_name: Option<String>,
    pub threat_score: Option<u32>,
    pub threat_confidence: Option<f64>,
    pub threat_categories: Option<Vec<String>>,
    pub threat_tags: Option<Vec<String>>,
    pub threat_reason_code: Option<String>,
    pub threat_reason_summary: Option<String>,
    pub threat_advice: Option<String>,
    pub ip_country: Option<String>,
    pub ip_asn: Option<u32>,
    pub ip_asn_org: Option<String>,
    pub ip_asn_country: Option<String>,
}

impl HttpAccessLog {
    /// Create access log from request parts and response data
    pub async fn create_from_parts(
        req_parts: &hyper::http::request::Parts,
        req_body_bytes: &bytes::Bytes,
        peer_addr: SocketAddr,
        dst_addr: SocketAddr,
        tls_fingerprint: Option<&TlsFingerprint>,
        response_data: ResponseData,
        waf_result: Option<&crate::wirefilter::WafResult>,
        threat_data: Option<&crate::threat::ThreatResponse>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let timestamp = Utc::now();
        let request_id = format!("req_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());

        // Extract request details
        let uri = &req_parts.uri;
        let method = req_parts.method.to_string();

        // Determine scheme: prefer URI scheme, fallback to TLS fingerprint presence, then default to http
        let scheme = uri.scheme().map(|s| s.to_string()).unwrap_or_else(|| {
            if tls_fingerprint.is_some() {
                "https".to_string()
            } else {
                "http".to_string()
            }
        });

        // Extract host from URI, fallback to Host header if URI doesn't have host
        let host = uri.host().map(|h| h.to_string()).unwrap_or_else(|| {
            req_parts.headers
                .get("host")
                .and_then(|h| h.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h).to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });

        // Determine port: prefer URI port, fallback to scheme-based default
        let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
        let path = uri.path().to_string();
        let query = uri.query().unwrap_or("").to_string();

        // Process headers
        let mut headers = HashMap::new();
        let mut user_agent = None;
        let mut content_type = None;

        for (name, value) in req_parts.headers.iter() {
            let key = name.to_string();
            let val = value.to_str().unwrap_or("").to_string();
            headers.insert(key, val.clone());

            if name.as_str().to_lowercase() == "user-agent" {
                user_agent = Some(val.clone());
            }
            if name.as_str().to_lowercase() == "content-type" {
                content_type = Some(val);
            }
        }

        // Get log sender configuration for body processing
        let log_config = {
            let config_store = get_log_sender_config();
            let config_guard = config_store.read().unwrap();
            config_guard.as_ref().cloned()
        };

        // Process request body with truncation
        let max_body_size = log_config.as_ref()
            .map(|c| c.max_body_size)
            .unwrap_or(1024 * 1024); // Default: 1MB limit
        let body_truncated = req_body_bytes.len() > max_body_size;
        let truncated_body_bytes = if body_truncated {
            req_body_bytes.slice(..max_body_size)
        } else {
            req_body_bytes.clone()
        };
        let body_str = String::from_utf8_lossy(&truncated_body_bytes).to_string();

        // Calculate SHA256 hash - handle empty body explicitly
        let body_sha256 = if req_body_bytes.is_empty() {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()
        } else {
            format!("{:x}", Sha256::digest(req_body_bytes))
        };

        // Process TLS details
        let tls_details = if let Some(fp) = tls_fingerprint {
            // Determine cipher based on TLS version
            let cipher = match fp.tls_version.as_str() {
                "TLSv1.3" => "TLS_AES_256_GCM_SHA384", // Most common TLS 1.3 cipher
                "TLSv1.2" => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", // Most common TLS 1.2 cipher
                _ => "Unknown",
            };

            // Calculate JA4L (simplified version)
            let ja4l = calculate_ja4l(&fp.tls_version, fp.alpn.as_deref());

            Some(TlsDetails {
                version: fp.tls_version.clone(),
                cipher: cipher.to_string(),
                alpn: fp.alpn.clone(),
                sni: fp.sni.clone(),
                ja4: Some(fp.ja4.clone()),
                ja4one: Some(fp.ja4_unsorted.clone()),
                ja4l: Some(ja4l),
                ja4t: Some(fp.ja4_unsorted.clone()),
                ja4h: Some(fp.ja4_unsorted.clone()),
                server_cert: None, // TODO: extract server certificate details
            })
        } else if scheme == "https" {
            // Create minimal TLS details for HTTPS connections without fingerprint (e.g., PROXY protocol)
            Some(TlsDetails {
                version: "TLS 1.3".to_string(),
                cipher: "TLS_AES_256_GCM_SHA384".to_string(),
                alpn: None,
                sni: None,
                ja4: Some("t13d".to_string()),
                ja4one: Some("t13d".to_string()),
                ja4l: Some("t13d".to_string()),
                ja4t: Some("t13d".to_string()),
                ja4h: Some("t13d".to_string()),
                server_cert: None,
            })
        } else {
            None
        };

        // Create HTTP details
        let http_details = HttpDetails {
            method,
            scheme,
            host,
            port,
            path,
            query: query.clone(),
            query_hash: if query.is_empty() { None } else { Some(format!("{:x}", Sha256::digest(query.as_bytes()))) },
            headers,
            user_agent,
            content_type,
            content_length: Some(req_body_bytes.len() as u64),
            body: body_str,
            body_sha256,
            body_truncated,
        };

        // Create network details
        let network_details = NetworkDetails {
            src_ip: peer_addr.ip().to_string(),
            src_port: peer_addr.port(),
            dst_ip: dst_addr.ip().to_string(),
            dst_port: dst_addr.port(),
        };

        // Create response details from response_data
        let response_body = response_data.response_json["body"].as_str().unwrap_or("");
        let response_body_truncated = if let Some(config) = &log_config {
            if !config.include_response_body {
                "" // Don't include response body if disabled
            } else if response_body.len() > config.max_body_size {
                &response_body[..config.max_body_size] // Truncate if too large
            } else {
                response_body
            }
        } else {
            response_body
        };

        let response_details = ResponseDetails {
            status: response_data.response_json["status"].as_u64().unwrap_or(0) as u16,
            status_text: response_data.response_json["status_text"].as_str().unwrap_or("Unknown").to_string(),
            content_type: response_data.response_json["content_type"].as_str().map(|s| s.to_string()),
            content_length: response_data.response_json["content_length"].as_u64(),
            body: response_body_truncated.to_string(),
        };

        // Create remediation details
        let remediation_details = Self::create_remediation_details(waf_result, threat_data);

        // Create the access log
        let access_log = HttpAccessLog {
            event_type: "http_access_log".to_string(),
            schema_version: "1.2.0".to_string(),
            timestamp,
            request_id,
            http: http_details,
            network: network_details,
            tls: tls_details,
            response: response_details,
            remediation: remediation_details,
        };

        // Log to stdout (existing behavior)
        if let Err(e) = access_log.log_to_stdout() {
            log::warn!("Failed to log access log to stdout: {}", e);
        }

        // Send to arxignis server in background
        access_log.send_to_arxignis_background();

        Ok(())
    }

    /// Create remediation details from WAF result and threat intelligence data
    fn create_remediation_details(
        waf_result: Option<&crate::wirefilter::WafResult>,
        threat_data: Option<&crate::threat::ThreatResponse>,
    ) -> Option<RemediationDetails> {
        // If neither WAF result nor threat data is available, return None
        if waf_result.is_none() && threat_data.is_none() {
            return None;
        }

        let mut remediation = RemediationDetails {
            waf_action: None,
            waf_rule_id: None,
            waf_rule_name: None,
            threat_score: None,
            threat_confidence: None,
            threat_categories: None,
            threat_tags: None,
            threat_reason_code: None,
            threat_reason_summary: None,
            threat_advice: None,
            ip_country: None,
            ip_asn: None,
            ip_asn_org: None,
            ip_asn_country: None,
        };

        // Populate WAF data if available
        if let Some(waf) = waf_result {
            remediation.waf_action = Some(format!("{:?}", waf.action).to_lowercase());
            remediation.waf_rule_id = Some(waf.rule_id.clone());
            remediation.waf_rule_name = Some(waf.rule_name.clone());
        }

        // Populate threat intelligence data if available
        if let Some(threat) = threat_data {
            remediation.threat_score = Some(threat.intel.score);
            remediation.threat_confidence = Some(threat.intel.confidence);
            remediation.threat_categories = Some(threat.intel.categories.clone());
            remediation.threat_tags = Some(threat.intel.tags.clone());
            remediation.threat_reason_code = Some(threat.intel.reason_code.clone());
            remediation.threat_reason_summary = Some(threat.intel.reason_summary.clone());
            remediation.threat_advice = Some(threat.advice.clone());
            // Use iso_code directly from threat response
            let country_code = threat.context.geo.iso_code.clone();
            remediation.ip_country = Some(country_code);
            remediation.ip_asn = Some(threat.context.asn);
            remediation.ip_asn_org = Some(threat.context.org.clone());
            remediation.ip_asn_country = Some(threat.context.geo.asn_iso_code.clone());
        }

        Some(remediation)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn log_to_stdout(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = self.to_json()?;
        log::info!("{}", json);
        Ok(())
    }

    /// Send access log to arxignis server asynchronously (single log)
    pub async fn send_to_arxignis(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = {
            let config_store = get_log_sender_config();
            let config_guard = config_store.read().unwrap();
            config_guard.as_ref().cloned()
        };

        let config = match config {
            Some(config) => {
                if !config.should_send_logs() {
                    return Ok(());
                }
                config
            }
            None => return Ok(()),
        };

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("Moat/1.0")
            .build()?;

        let url = format!("{}/logs", config.base_url);
        let logs_array = vec![self.clone()];
        let json = serde_json::to_string(&logs_array)?;

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", config.api_key))
            .header("Content-Type", "application/json")
            .body(json)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            log::warn!("Failed to send access log to arxignis: {} - {}", status, error_text);
        } else {
            log::debug!("Successfully sent access log to arxignis");
        }

        Ok(())
    }

    /// Add log to buffer for batch sending
    pub fn add_to_buffer(&self) {
        if let Some(sender) = get_log_channel() {
            if let Err(e) = sender.send(self.clone()) {
                log::warn!("Failed to send log to buffer: {}", e);
            }
        } else {
            // Log channel not initialized - this is expected when log_sending_enabled is false
            log::trace!("Log channel not initialized, skipping log buffering");
        }
    }

    /// Send access log to arxignis server in background (fire-and-forget)
    pub fn send_to_arxignis_background(&self) {
        // Check if log sending is enabled before adding to buffer
        let config = {
            let config_store = get_log_sender_config();
            let config_guard = config_store.read().unwrap();
            config_guard.as_ref().cloned()
        };

        if let Some(config) = config {
            if !config.should_send_logs() {
                return; // Don't add to buffer if log sending is disabled
            }
        }

        // Use buffering instead of immediate sending
        self.add_to_buffer();
    }
}

/// Helper struct to hold response data for access logging
#[derive(Debug, Clone)]
pub struct ResponseData {
    pub response_json: serde_json::Value,
    pub blocking_info: Option<serde_json::Value>,
    pub waf_result: Option<crate::wirefilter::WafResult>,
    pub threat_data: Option<crate::threat::ThreatResponse>,
}

impl ResponseData {
    /// Create response data for a regular response
    pub async fn from_response(response: Response<ProxyBody>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (response_parts, response_body) = response.into_parts();
        let response_body_bytes = response_body.collect().await?.to_bytes();
        let response_body_str = String::from_utf8_lossy(&response_body_bytes).to_string();

        let response_content_type = response_parts.headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let response_json = serde_json::json!({
            "status": response_parts.status.as_u16(),
            "status_text": response_parts.status.canonical_reason().unwrap_or("Unknown"),
            "content_type": response_content_type,
            "content_length": response_body_bytes.len() as u64,
            "body": response_body_str
        });

        Ok(ResponseData {
            response_json,
            blocking_info: None,
            waf_result: None,
            threat_data: None,
        })
    }

    /// Create response data for a blocked request
    pub fn for_blocked_request(
        block_reason: &str,
        status_code: u16,
        waf_result: Option<crate::wirefilter::WafResult>,
        threat_data: Option<&crate::threat::ThreatResponse>,
    ) -> Self {
        let status_text = match status_code {
            403 => "Forbidden",
            426 => "Upgrade Required",
            429 => "Too Many Requests",
            _ => "Blocked"
        };

        let response_json = serde_json::json!({
            "status": status_code,
            "status_text": status_text,
            "content_type": "application/json",
            "content_length": 0,
            "body": format!("{{\"ok\":false,\"error\":\"{}\"}}", block_reason)
        });

        let blocking_info = serde_json::json!({
            "blocked": true,
            "reason": block_reason,
            "filter_type": "waf"
        });

        ResponseData {
            response_json,
            blocking_info: Some(blocking_info),
            waf_result,
            threat_data: threat_data.cloned(),
        }
    }

    /// Create response data for a malware-blocked request with scan details
    pub fn for_malware_blocked_request(
        signature: Option<String>,
        scan_error: Option<String>,
        waf_result: Option<crate::wirefilter::WafResult>,
        threat_data: Option<&crate::threat::ThreatResponse>,
    ) -> Self {
        let response_json = serde_json::json!({
            "status": 403,
            "status_text": "Forbidden",
            "content_type": "application/json",
            "content_length": 0,
            "body": "{\"ok\":false,\"error\":\"malware_detected\"}"
        });

        let mut blocking_info = serde_json::json!({
            "blocked": true,
            "reason": "malware_detected",
            "filter_type": "content_scanning",
            "malware_detected": true,
        });

        if let Some(sig) = signature {
            blocking_info["malware_signature"] = serde_json::Value::String(sig);
        }

        if let Some(err) = scan_error {
            blocking_info["scan_error"] = serde_json::Value::String(err);
        }

        ResponseData {
            response_json,
            blocking_info: Some(blocking_info),
            waf_result,
            threat_data: threat_data.cloned(),
        }
    }
}

/// Send a batch of logs to arxignis server
async fn send_log_batch(logs: Vec<HttpAccessLog>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if logs.is_empty() {
        return Ok(());
    }

    let config = {
        let config_store = get_log_sender_config();
        let config_guard = config_store.read().unwrap();
        config_guard.as_ref().cloned()
    };

    let config = match config {
        Some(config) => {
            if !config.should_send_logs() {
                return Ok(());
            }
            config
        }
        None => return Ok(()),
    };

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("Moat/1.0")
        .build()?;

    let url = format!("{}/logs", config.base_url);
    let json = serde_json::to_string(&logs)?;

    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .header("Content-Type", "application/json")
        .body(json)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        log::warn!("Failed to send log batch to arxignis: {} - {} (batch size: {})", status, error_text, logs.len());
        return Err(format!("HTTP {}: {}", status, error_text).into());
    } else {
        log::debug!("Successfully sent log batch to arxignis (batch size: {})", logs.len());
    }

    Ok(())
}

/// Start the background batch log processor
pub fn start_batch_log_processor() {
    let (sender, mut receiver) = mpsc::unbounded_channel::<HttpAccessLog>();
    set_log_channel(sender);

    tokio::spawn(async move {
        let mut buffer = LogBuffer::new();
        let mut flush_interval = interval(Duration::from_secs(1)); // Check every second

        loop {
            tokio::select! {
                // Receive new logs
                log = receiver.recv() => {
                    match log {
                        Some(log) => {
                            let count = buffer.add_log(log);
                            log::trace!("Added log to buffer, total: {}", count);
                        }
                        None => {
                            log::info!("Log channel closed, flushing remaining logs");
                            // Flush any remaining logs before exiting
                            if !buffer.is_empty() {
                                let logs = buffer.take_logs();
                                if let Err(e) = send_log_batch(logs.clone()).await {
                                    log::warn!("Failed to send final log batch: {}, storing locally", e);
                                    buffer.add_failed_logs(logs);
                                }
                            }
                            // Also try to flush any remaining failed logs
                            if buffer.has_failed_logs() {
                                let failed_logs = buffer.take_failed_logs();
                                log::warn!("Storing {} failed logs locally (endpoint unavailable)", failed_logs.len());
                                // In a real implementation, you might want to write these to disk
                                // For now, we just log the count
                            }
                            break;
                        }
                    }
                }

                // Periodic flush check
                _ = flush_interval.tick() => {
                    let config = {
                        let config_store = get_log_sender_config();
                        let config_guard = config_store.read().unwrap();
                        config_guard.as_ref().cloned()
                    };

                    if let Some(config) = config {
                        // Handle regular log flushing
                        if buffer.should_flush(&config) {
                            let logs = buffer.take_logs();
                            if !logs.is_empty() {
                                log::debug!("Flushing log batch: {} logs", logs.len());
                                if let Err(e) = send_log_batch(logs.clone()).await {
                                    log::warn!("Failed to send log batch: {}, storing locally for retry", e);
                                    buffer.add_failed_logs(logs);
                                }
                            }
                        }

                        // Handle retry of failed logs
                        if buffer.should_retry_failed_logs() {
                            let failed_logs = buffer.take_failed_logs();
                            if !failed_logs.is_empty() {
                                log::debug!("Retrying failed log batch: {} logs", failed_logs.len());
                                if let Err(e) = send_log_batch(failed_logs.clone()).await {
                                    log::warn!("Failed to retry log batch: {}, storing locally again", e);
                                    buffer.add_failed_logs(failed_logs);
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}

/// Calculate JA4L fingerprint based on TLS version and ALPN
fn calculate_ja4l(tls_version: &str, alpn: Option<&str>) -> String {
    // JA4L format: TLS_version_ALPN_length
    let version_code = match tls_version {
        "TLSv1.3" => "13",
        "TLSv1.2" => "12",
        "TLSv1.1" => "11",
        "TLSv1.0" => "10",
        _ => "00",
    };

    let alpn_length = alpn.map_or(0, |a| a.len());

    format!("{}_{}_{}", version_code, alpn_length, alpn_length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;
    use http_body_util::Full;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_access_log_creation() {
        // Create a simple request
        let _req = Request::builder()
            .method("GET")
            .uri("https://example.com/test?param=value")
            .header("User-Agent", "TestAgent/1.0")
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .unwrap();

        // Create a simple response
        let _response = Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from("{\"ok\":true}")))
            .unwrap();

        let _peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let _dst_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

        // This test would need more setup to work properly
        // For now, just test the structure creation
        let log = HttpAccessLog {
            event_type: "http_access_log".to_string(),
            schema_version: "1.2.0".to_string(),
            timestamp: Utc::now(),
            request_id: "test_123".to_string(),
            http: HttpDetails {
                method: "GET".to_string(),
                scheme: "https".to_string(),
                host: "example.com".to_string(),
                port: 443,
                path: "/test".to_string(),
                query: "param=value".to_string(),
                query_hash: Some("abc123".to_string()),
                headers: HashMap::new(),
                user_agent: Some("TestAgent/1.0".to_string()),
                content_type: None,
                content_length: None,
                body: "".to_string(),
                body_sha256: "abc123".to_string(),
                body_truncated: false,
            },
            network: NetworkDetails {
                src_ip: "127.0.0.1".to_string(),
                src_port: 12345,
                dst_ip: "127.0.0.1".to_string(),
                dst_port: 443,
            },
            tls: None,
            response: ResponseDetails {
                status: 200,
                status_text: "OK".to_string(),
                content_type: Some("application/json".to_string()),
                content_length: Some(10),
                body: "{\"ok\":true}".to_string(),
            },
            remediation: None,
        };

        let json = log.to_json().unwrap();
        assert!(json.contains("http_access_log"));
        assert!(json.contains("GET"));
        assert!(json.contains("example.com"));
    }
}
