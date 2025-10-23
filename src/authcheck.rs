use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCheckResponse {
    pub success: bool,
    pub message: Option<String>,
}

/// Validates the API key by calling the /authcheck endpoint
pub async fn validate_api_key(base_url: &str, api_key: &str) -> Result<()> {
    if base_url.is_empty() || api_key.is_empty() {
        return Err(anyhow::anyhow!("Base URL and API key must be provided"));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .danger_accept_invalid_certs(false)
        .user_agent("Moat/1.0")
        .build()
        .context("Failed to create HTTP client")?;

    let url = format!("{}/authcheck", base_url);

    log::info!("Validating API key with endpoint: {}", url);

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .send()
        .await
        .context("Failed to send authcheck request")?;

    match response.status() {
        reqwest::StatusCode::OK => {
            let auth_response: AuthCheckResponse = response
                .json()
                .await
                .context("Failed to parse authcheck response")?;

            if auth_response.success {
                log::info!("API key validation successful");
                Ok(())
            } else {
                let error_msg = auth_response.message.unwrap_or_else(|| "Unknown error".to_string());
                Err(anyhow::anyhow!("API key validation failed: {}", error_msg))
            }
        }
        reqwest::StatusCode::UNAUTHORIZED => {
            Err(anyhow::anyhow!("API key validation failed: Unauthorized (401)"))
        }
        reqwest::StatusCode::FORBIDDEN => {
            Err(anyhow::anyhow!("API key validation failed: Forbidden (403)"))
        }
        status => {
            Err(anyhow::anyhow!(
                "API key validation failed with status: {} - {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            ))
        }
    }
}
