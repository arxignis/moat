use hyper::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use flate2::read::GzDecoder;
use std::sync::{Arc, OnceLock, RwLock};

pub type Details = serde_json::Value;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfigApiResponse {
    pub success: bool,
    pub config: Config,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub access_rules: AccessRule,
    pub waf_rules: WafRules,
    pub created_at: String,
    pub updated_at: String,
    pub last_modified: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccessRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub allow: RuleSet,
    pub block: RuleSet,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WafRules {
    pub rules: Vec<WafRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WafRule {
    pub id: String,
    pub name: String,
    pub org_id: String,
    pub description: String,
    pub action: String,
    pub expression: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleSet {
    pub asn: Vec<HashMap<String, Vec<String>>>,
    pub country: Vec<HashMap<String, Vec<String>>>,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub details: Details,
    pub error: String,
    pub success: bool,
}

// Global configuration store accessible across services
static GLOBAL_CONFIG: OnceLock<Arc<RwLock<Option<Config>>>> = OnceLock::new();

pub fn global_config() -> Arc<RwLock<Option<Config>>> {
    GLOBAL_CONFIG
        .get_or_init(|| Arc::new(RwLock::new(None)))
        .clone()
}

pub fn set_global_config(cfg: Config) {
    let store = global_config();
    if let Ok(mut guard) = store.write() {
        *guard = Some(cfg);
    }
}

pub async fn fetch_config(
    base_url: String,
    api_key: String,
) -> Result<ConfigApiResponse, Box<dyn std::error::Error>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(false)
        .user_agent("Moat/1.0")
        .build()?;
    let url = format!("{}/config", base_url);

    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Accept-Encoding", "gzip")
        .send()
        .await?;

    match response.status() {
        StatusCode::OK => {
            // Check if response is gzipped by looking at Content-Encoding header first
            let content_encoding = response.headers()
                .get("content-encoding")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_string(); // Convert to owned String to avoid borrow issues

            let bytes = response.bytes().await?;

            let json_text = if content_encoding.contains("gzip") ||
                (bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b) {
                // Response is gzipped, decompress it
                let mut decoder = GzDecoder::new(&bytes[..]);
                let mut decompressed_bytes = Vec::new();
                decoder.read_to_end(&mut decompressed_bytes)
                    .map_err(|e| format!("Failed to decompress gzipped response: {}", e))?;

                // Check if the decompressed content is also gzipped (double compression)
                let final_bytes = if decompressed_bytes.len() >= 2 && decompressed_bytes[0] == 0x1f && decompressed_bytes[1] == 0x8b {
                    let mut second_decoder = GzDecoder::new(&decompressed_bytes[..]);
                    let mut final_bytes = Vec::new();
                    second_decoder.read_to_end(&mut final_bytes)
                        .map_err(|e| format!("Failed to decompress second gzip layer: {}", e))?;
                    final_bytes
                } else {
                    decompressed_bytes
                };

                // Try to convert to UTF-8 string
                match String::from_utf8(final_bytes) {
                    Ok(text) => text,
                    Err(e) => {
                        return Err(format!("Final decompressed response contains invalid UTF-8: {}", e).into());
                    }
                }
            } else {
                // Response is not gzipped, use as-is
                String::from_utf8(bytes.to_vec())
                    .map_err(|e| format!("Response contains invalid UTF-8: {}", e))?
            };

            let body: ConfigApiResponse = serde_json::from_str(&json_text)
                .map_err(|e| format!("Failed to parse JSON response: {}", e))?;
            // Update global config snapshot
            set_global_config(body.config.clone());
            Ok(body)
        }
        StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND | StatusCode::INTERNAL_SERVER_ERROR => {
            let body: ErrorResponse = serde_json::from_str(&response.text().await?)?;
            Err(format!("API Error: {}", body.error).into())
        }

        status => Err(format!(
            "Unexpected API status code: {} - {}",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Unknown")
        )
        .into()),

    }
}

/// Fetch config and run a user-provided callback to apply it.
/// The callback can update WAF rules, BPF maps, caches, etc.
pub async fn fetch_and_apply<F>(
    base_url: String,
    api_key: String,
    mut on_config: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(&ConfigApiResponse) -> Result<(), Box<dyn std::error::Error>>,
{
    let resp = fetch_config(base_url, api_key).await?;
    on_config(&resp)?;
    Ok(())
}
