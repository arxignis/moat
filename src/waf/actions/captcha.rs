use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::Utc;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, OnceCell};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use uuid::Uuid;

use crate::redis::RedisManager;
use crate::http_client::get_global_reqwest_client;

/// Captcha provider types supported by Gen0Sec
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, clap::ValueEnum, Default)]
pub enum CaptchaProvider {
    #[serde(rename = "hcaptcha")]
    #[default]
    HCaptcha,
    #[serde(rename = "recaptcha")]
    ReCaptcha,
    #[serde(rename = "turnstile")]
    Turnstile,
}


impl std::str::FromStr for CaptchaProvider {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hcaptcha" => Ok(CaptchaProvider::HCaptcha),
            "recaptcha" => Ok(CaptchaProvider::ReCaptcha),
            "turnstile" => Ok(CaptchaProvider::Turnstile),
            _ => Err(anyhow::anyhow!("Invalid captcha provider: {}", s)),
        }
    }
}

/// Captcha validation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaValidationRequest {
    pub response_token: String,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub site_key: String,
    pub secret_key: String,
    pub provider: CaptchaProvider,
}

/// Captcha validation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaValidationResponse {
    pub success: bool,
    pub error_codes: Option<Vec<String>>,
    pub challenge_ts: Option<String>,
    pub hostname: Option<String>,
    pub score: Option<f64>,
    pub action: Option<String>,
}

/// JWT Claims for captcha tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaClaims {
    /// Standard JWT claims
    pub sub: String,        // Subject (user identifier)
    pub iss: String,        // Issuer
    pub aud: String,        // Audience
    pub exp: i64,           // Expiration time
    pub iat: i64,           // Issued at
    pub jti: String,        // JWT ID (unique identifier)

    /// Custom captcha claims
    pub ip_address: String,
    pub user_agent: String,
    pub ja4_fingerprint: Option<String>,
    pub captcha_provider: String,
    pub captcha_validated: bool,
}

/// Captcha token with JWT-based security
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaToken {
    pub token: String,
    pub claims: CaptchaClaims,
}

/// Cached captcha validation result
#[derive(Debug, Clone)]
pub struct CachedCaptchaResult {
    pub is_valid: bool,
    pub expires_at: Instant,
}

/// Captcha action configuration
#[derive(Debug, Clone)]
pub struct CaptchaConfig {
    pub site_key: String,
    pub secret_key: String,
    pub jwt_secret: String,
    pub provider: CaptchaProvider,
    pub token_ttl_seconds: u64,
    pub validation_cache_ttl_seconds: u64,
}

/// Captcha client for validation and token management
pub struct CaptchaClient {
    config: CaptchaConfig,
    validation_cache: Arc<RwLock<HashMap<String, CachedCaptchaResult>>>,
    validated_tokens: Arc<RwLock<HashMap<String, Instant>>>, // JTI -> expiration time
}

impl CaptchaClient {
    pub fn new(
        config: CaptchaConfig,
    ) -> Self {
        Self {
            config,
            validation_cache: Arc::new(RwLock::new(HashMap::new())),
            validated_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Validate a captcha response token
    pub async fn validate_captcha(&self, request: CaptchaValidationRequest) -> Result<bool> {
        log::info!("Starting captcha validation for IP: {}, provider: {:?}",
                   request.ip_address, self.config.provider);

        // Check if captcha response is provided
        if request.response_token.is_empty() {
            log::warn!("No captcha response provided for IP: {}", request.ip_address);
            return Ok(false);
        }

        log::debug!("Captcha response token length: {}", request.response_token.len());

        // Check validation cache first
        let cache_key = format!("{}:{}", request.response_token, request.ip_address);
        if let Some(cached) = self.get_validation_cache(&cache_key).await {
            if cached.expires_at > Instant::now() {
                log::debug!("Captcha validation for {} found in cache", request.ip_address);
                return Ok(cached.is_valid);
            } else {
                self.remove_validation_cache(&cache_key).await;
            }
        }

        // Validate with provider API
        let is_valid = match self.config.provider {
            CaptchaProvider::HCaptcha => self.validate_hcaptcha(&request).await?,
            CaptchaProvider::ReCaptcha => self.validate_recaptcha(&request).await?,
            CaptchaProvider::Turnstile => self.validate_turnstile(&request).await?,
        };

        log::info!("Captcha validation result for IP {}: {}", request.ip_address, is_valid);

        // Cache the result
        self.set_validation_cache(&cache_key, is_valid).await;

        Ok(is_valid)
    }

    /// Generate a secure JWT captcha token
    pub async fn generate_token(
        &self,
        ip_address: String,
        user_agent: String,
        ja4_fingerprint: Option<String>,
    ) -> Result<CaptchaToken> {
        let now = Utc::now();
        let exp = now + chrono::Duration::seconds(self.config.token_ttl_seconds as i64);
        let jti = Uuid::new_v4().to_string();

        let claims = CaptchaClaims {
            sub: format!("captcha:{}", ip_address),
            iss: "arxignis-synapse".to_string(),
            aud: "captcha-validation".to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            jti: jti.clone(),
            ip_address: ip_address.clone(),
            user_agent: user_agent.clone(),
            ja4_fingerprint,
            captcha_provider: format!("{:?}", self.config.provider),
            captcha_validated: false,
        };

        let header = Header::new(Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(self.config.jwt_secret.as_bytes());

        let token = encode(&header, &claims, &encoding_key)
            .context("Failed to encode JWT token")?;

        let captcha_token = CaptchaToken {
            token: token.clone(),
            claims: claims.clone(),
        };

        // Store token in Redis for validation (optional, JWT is self-contained)
        if let Ok(redis_manager) = RedisManager::get() {
            let key = format!("{}:captcha_jwt:{}", redis_manager.create_namespace("captcha"), jti);
            let mut redis = redis_manager.get_connection();
            let token_data = serde_json::to_string(&captcha_token)
                .context("Failed to serialize captcha token")?;

            let _: () = redis
                .set_ex(&key, token_data, self.config.token_ttl_seconds)
                .await
                .context("Failed to store captcha token in Redis")?;
        }

        Ok(captcha_token)
    }

    /// Validate a JWT captcha token
    pub async fn validate_token(&self, token: &str, ip_address: &str, user_agent: &str) -> Result<bool> {
        let decoding_key = DecodingKey::from_secret(self.config.jwt_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["captcha-validation"]);

        match decode::<CaptchaClaims>(token, &decoding_key, &validation) {
            Ok(token_data) => {
                let claims = token_data.claims;

                // Check if token is expired (JWT handles this automatically, but double-check)
                let now = Utc::now().timestamp();
                if claims.exp < now {
                    log::debug!("JWT token expired");
                    return Ok(false);
                }

                // Verify IP and User-Agent binding
                if claims.ip_address != ip_address || claims.user_agent != user_agent {
                    log::warn!("JWT token validation failed: IP or User-Agent mismatch");
                    return Ok(false);
                }

                // Check Redis first for updated token state
                let mut captcha_validated = claims.captcha_validated;
                log::debug!("Initial JWT token captcha_validated: {}", captcha_validated);

                // Check in-memory cache first (faster)
                {
                    let validated_tokens = self.validated_tokens.read().await;
                    if let Some(expiration) = validated_tokens.get(&claims.jti) {
                        if *expiration > Instant::now() {
                            captcha_validated = true;
                            log::debug!("Found validated token JTI {} in memory cache", claims.jti);
                        } else {
                            log::debug!("Token JTI {} expired in memory cache", claims.jti);
                        }
                    }
                }

                // If not found in memory cache, check Redis
                if !captcha_validated {
                    if let Ok(redis_manager) = RedisManager::get() {
                        let key = format!("{}:captcha_jwt:{}", redis_manager.create_namespace("captcha"), claims.jti);
                        log::debug!("Looking up token in Redis with key: {}", key);

                        let mut redis = redis_manager.get_connection();
                        match redis.get::<_, String>(&key).await {
                            Ok(token_data_str) => {
                                log::debug!("Found token data in Redis: {}", token_data_str);
                                if let Ok(updated_token) = serde_json::from_str::<CaptchaToken>(&token_data_str) {
                                    captcha_validated = updated_token.claims.captcha_validated;
                                    log::debug!("Updated captcha_validated from Redis: {}", captcha_validated);

                                    // Update memory cache if found in Redis
                                    if captcha_validated {
                                        let expiration = Instant::now() + Duration::from_secs(self.config.token_ttl_seconds);
                                        let mut validated_tokens = self.validated_tokens.write().await;
                                        validated_tokens.insert(claims.jti.clone(), expiration);
                                    }
                                } else {
                                    log::warn!("Failed to parse token data from Redis");
                                }
                            }
                            Err(e) => {
                                log::debug!("Redis token lookup failed for JTI {}: {}", claims.jti, e);
                            }
                        }
                    } else {
                        log::debug!("Redis manager not available");
                    }
                }

                // Check if captcha was validated (either from JWT or Redis)
                if !captcha_validated {
                    log::debug!("JWT token not validated for captcha");
                    return Ok(false);
                }

                // Optional: Check Redis blacklist for revoked tokens
                if let Ok(redis_manager) = RedisManager::get() {
                    let blacklist_key = format!("{}:captcha_blacklist:{}", redis_manager.create_namespace("captcha"), claims.jti);
                    let mut redis = redis_manager.get_connection();
                    match redis.exists::<_, bool>(&blacklist_key).await {
                        Ok(true) => {
                            log::debug!("JWT token {} is blacklisted", claims.jti);
                            return Ok(false);
                        }
                        Ok(false) => {
                            // Token not blacklisted, continue validation
                        }
                        Err(e) => {
                            log::warn!("Redis blacklist check error for JWT {}: {}", claims.jti, e);
                            // Continue validation despite Redis error
                        }
                    }
                }

                Ok(true)
            }
            Err(e) => {
                log::warn!("JWT token validation failed: {}", e);
                Ok(false)
            }
        }
    }

    /// Mark a JWT token as validated after successful captcha completion
    pub async fn mark_token_validated(&self, token: &str) -> Result<()> {
        let decoding_key = DecodingKey::from_secret(self.config.jwt_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["captcha-validation"]);

        match decode::<CaptchaClaims>(token, &decoding_key, &validation) {
            Ok(token_data) => {
                let claims = token_data.claims;

                // Store the JTI as validated in memory cache
                let expiration = Instant::now() + Duration::from_secs(self.config.token_ttl_seconds);
                {
                    let mut validated_tokens = self.validated_tokens.write().await;
                    validated_tokens.insert(claims.jti.clone(), expiration);
                    log::debug!("Marked token JTI {} as validated, expires at {:?}", claims.jti, expiration);
                }

                // Also update Redis cache if available (for persistence across restarts)
                if let Ok(redis_manager) = RedisManager::get() {
                    let key = format!("{}:captcha_jwt:{}", redis_manager.create_namespace("captcha"), claims.jti);
                    log::debug!("Storing updated token in Redis with key: {}", key);

                    let mut redis = redis_manager.get_connection();
                    let mut updated_claims = claims.clone();
                    updated_claims.captcha_validated = true;

                    let updated_captcha_token = CaptchaToken {
                        token: token.to_string(),
                        claims: updated_claims,
                    };
                    let token_data = serde_json::to_string(&updated_captcha_token)
                        .context("Failed to serialize updated captcha token")?;

                    log::debug!("Token data to store: {}", token_data);

                    let _: () = redis
                        .set_ex(&key, token_data, self.config.token_ttl_seconds)
                        .await
                        .context("Failed to update captcha token in Redis")?;

                    log::debug!("Successfully stored updated token in Redis");
                } else {
                    log::debug!("Redis manager not available for token storage");
                }

                Ok(())
            }
            Err(e) => {
                log::warn!("Failed to decode JWT token for validation marking: {}", e);
                Err(anyhow::anyhow!("Invalid JWT token: {}", e))
            }
        }
    }

    /// Revoke a JWT token by adding it to blacklist
    pub async fn revoke_token(&self, token: &str) -> Result<()> {
        let decoding_key = DecodingKey::from_secret(self.config.jwt_secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["captcha-validation"]);

        match decode::<CaptchaClaims>(token, &decoding_key, &validation) {
            Ok(token_data) => {
                let claims = token_data.claims;

                // Add to Redis blacklist
                if let Ok(redis_manager) = RedisManager::get() {
                    let blacklist_key = format!("{}:captcha_blacklist:{}", redis_manager.create_namespace("captcha"), claims.jti);
                    let mut redis = redis_manager.get_connection();
                    let _: () = redis
                        .set_ex(&blacklist_key, "revoked", self.config.token_ttl_seconds)
                        .await
                        .context("Failed to add token to blacklist")?;
                }

                Ok(())
            }
            Err(e) => {
                log::warn!("Failed to decode JWT token for revocation: {}", e);
                Err(anyhow::anyhow!("Invalid JWT token: {}", e))
            }
        }
    }

    /// Apply captcha challenge (return HTML form)
    pub fn apply_captcha_challenge(&self, site_key: &str) -> String {
        self.render_captcha_template(site_key, None)
    }

    /// Apply captcha challenge with JWT token (return HTML form)
    pub fn apply_captcha_challenge_with_token(&self, site_key: &str, jwt_token: &str) -> String {
        self.render_captcha_template(site_key, Some(jwt_token))
    }

    /// Render captcha template based on provider
    fn render_captcha_template(&self, site_key: &str, jwt_token: Option<&str>) -> String {
        let (frontend_js, frontend_key, callback_attr) = match self.config.provider {
            CaptchaProvider::HCaptcha => (
                "https://js.hcaptcha.com/1/api.js",
                "h-captcha",
                "data-callback=\"captchaCallback\""
            ),
            CaptchaProvider::ReCaptcha => (
                "https://www.recaptcha.net/recaptcha/api.js",
                "g-recaptcha",
                "data-callback=\"captchaCallback\""
            ),
            CaptchaProvider::Turnstile => (
                "https://challenges.cloudflare.com/turnstile/v0/api.js",
                "cf-turnstile",
                "data-callback=\"onTurnstileSuccess\" data-error-callback=\"onTurnstileError\""
            ),
        };

        let jwt_token_input = if let Some(token) = jwt_token {
            format!(r#"<input type="hidden" name="jwt_token" value="{}">"#, token)
        } else {
            r#"<input type="hidden" name="jwt_token" id="jwt_token" value="">"#.to_string()
        };

        let html_template = format!(
            r#"<!doctype html>
<html lang="en">
  <head>
    <title>Gen0Sec Captcha</title>
    <meta content="text/html; charset=utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <script src="{}" async defer></script>
    <style>
      body {{
        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, Noto Sans, sans-serif;
        line-height: 1.5;
        margin: 0;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
      }}
      .container {{
        background: white;
        border-radius: 12px;
        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        padding: 2rem;
        max-width: 400px;
        width: 100%;
        margin: 1rem;
      }}
      .header {{
        text-align: center;
        margin-bottom: 2rem;
      }}
      .title {{
        font-size: 1.875rem;
        font-weight: 700;
        color: #1f2937;
        margin-bottom: 0.5rem;
      }}
      .subtitle {{
        color: #6b7280;
        font-size: 0.875rem;
      }}
      .captcha-container {{
        margin: 1.5rem 0;
        display: flex;
        justify-content: center;
      }}
      .footer {{
        margin-top: 2rem;
        text-align: center;
        font-size: 0.75rem;
        color: #9ca3af;
      }}
      .footer a {{
        color: #3b82f6;
        text-decoration: none;
      }}
      .footer a:hover {{
        text-decoration: underline;
      }}
      .error {{
        color: #dc2626;
        font-size: 0.875rem;
        margin-top: 1rem;
        text-align: center;
      }}
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h1 class="title">Gen0Sec Captcha</h1>
        <p class="subtitle">Please complete the security verification below to continue.</p>
      </div>

      <form
        method="POST"
        action="/cgi-bin/captcha/verify"
        id="captcha-form"
      >
        <div class="captcha-container">
          <div
            id="captcha"
            class="{}"
            data-sitekey="{}"
            {}
          ></div>
        </div>
        <input type="hidden" name="captcha_response" id="captcha_response" value="">
        {}
      </form>

      <div class="footer">
        <p>Secured by</p>
        <a href="https://gen0sec.com/" target="_blank" rel="noopener">
          Gen0Sec Security
        </a>
      </div>
    </div>

    <script>
        // Function to get JWT token from secure sources (removed URL parameters for security)
        function getJwtToken() {{
          // First check if token is already in the form
          const jwtInput = document.getElementById('jwt_token');
          if (jwtInput && jwtInput.value) {{
            return jwtInput.value;
          }}

          // Check localStorage
          const localToken = localStorage.getItem('captcha_token');
          if (localToken) {{
            return localToken;
          }}

          // Check cookies
          const cookies = document.cookie.split(';');
          for (let cookie of cookies) {{
            const [name, value] = cookie.trim().split('=');
            if (name === 'captcha_token') {{
              return value;
            }}
          }}

          return null;
        }}

      function captchaCallback(token) {{
        // Set the captcha response in the hidden field
        document.getElementById('captcha_response').value = token;

        // Get JWT token and set it in the form
        const jwtToken = getJwtToken();
        if (jwtToken) {{
          const jwtInput = document.getElementById('jwt_token');
          if (jwtInput) {{
            jwtInput.value = jwtToken;
          }}
        }}

        // Auto-submit the form after a short delay
        setTimeout(() => {{
          document.getElementById('captcha-form').submit();
        }}, 500);
      }}

      // For Turnstile, we need a different approach
      function onTurnstileSuccess(token) {{
        captchaCallback(token);
      }}

      function onTurnstileError(error) {{
        console.error('Turnstile error:', error);
        alert('Captcha verification failed. Please try again.');
      }}

      // Initialize JWT token on page load
      document.addEventListener('DOMContentLoaded', function() {{
        const jwtToken = getJwtToken();
        if (jwtToken) {{
          const jwtInput = document.getElementById('jwt_token');
          if (jwtInput) {{
            jwtInput.value = jwtToken;
          }}
        }}
      }});
    </script>
  </body>
</html>"#,
            frontend_js,
            frontend_key,
            site_key,
            callback_attr,
            jwt_token_input
        );
        html_template
    }

    /// Validate with hCaptcha API
    async fn validate_hcaptcha(&self, request: &CaptchaValidationRequest) -> Result<bool> {
        // Use shared HTTP client with keepalive instead of creating new client
        let client = get_global_reqwest_client()
            .context("Failed to get global HTTP client")?;

        let mut params = HashMap::new();
        params.insert("response", &request.response_token);
        params.insert("secret", &request.secret_key);
        params.insert("sitekey", &request.site_key);
        params.insert("remoteip", &request.ip_address);

        log::info!("hCaptcha validation request - response_length: {}, remote_ip: {}",
                   request.response_token.len(), request.ip_address);

        let response = client
            .post("https://hcaptcha.com/siteverify")
            .form(&params)
            .send()
            .await
            .context("Failed to send hCaptcha validation request")?;

        log::info!("hCaptcha validation HTTP response - status: {}", response.status());

        if !response.status().is_success() {
            log::error!("hCaptcha service returned non-success status: {}", response.status());
            return Ok(false);
        }

        let validation_response: CaptchaValidationResponse = response
            .json()
            .await
            .context("Failed to parse hCaptcha response")?;

        if !validation_response.success {
            if let Some(error_codes) = &validation_response.error_codes {
                for error_code in error_codes {
                    match error_code.as_str() {
                        "invalid-input-secret" => {
                            log::error!("hCaptcha secret key is invalid");
                            return Ok(false);
                        }
                        "invalid-input-response" => {
                            log::info!("Invalid hCaptcha response from user");
                            return Ok(false);
                        }
                        "timeout-or-duplicate" => {
                            log::info!("hCaptcha response expired or duplicate");
                            return Ok(false);
                        }
                        _ => {
                            log::warn!("hCaptcha validation failed with error code: {}", error_code);
                        }
                    }
                }
            }
            log::info!("hCaptcha validation failed without specific error code");
            return Ok(false);
        }

        Ok(true)
    }

    /// Validate with reCAPTCHA API
    async fn validate_recaptcha(&self, request: &CaptchaValidationRequest) -> Result<bool> {
        // Use shared HTTP client with keepalive instead of creating new client
        let client = get_global_reqwest_client()
            .context("Failed to get global HTTP client")?;

        let mut params = HashMap::new();
        params.insert("response", &request.response_token);
        params.insert("secret", &request.secret_key);
        params.insert("remoteip", &request.ip_address);

        log::info!("reCAPTCHA validation request - response_length: {}, remote_ip: {}",
                   request.response_token.len(), request.ip_address);

        let response = client
            .post("https://www.recaptcha.net/recaptcha/api/siteverify")
            .form(&params)
            .send()
            .await
            .context("Failed to send reCAPTCHA validation request")?;

        log::info!("reCAPTCHA validation HTTP response - status: {}", response.status());

        if !response.status().is_success() {
            log::error!("reCAPTCHA service returned non-success status: {}", response.status());
            return Ok(false);
        }

        let validation_response: CaptchaValidationResponse = response
            .json()
            .await
            .context("Failed to parse reCAPTCHA response")?;

        if !validation_response.success {
            if let Some(error_codes) = &validation_response.error_codes {
                for error_code in error_codes {
                    match error_code.as_str() {
                        "invalid-input-secret" => {
                            log::error!("reCAPTCHA secret key is invalid");
                            return Ok(false);
                        }
                        "invalid-input-response" => {
                            log::info!("Invalid reCAPTCHA response from user");
                            return Ok(false);
                        }
                        "timeout-or-duplicate" => {
                            log::info!("reCAPTCHA response expired or duplicate");
                            return Ok(false);
                        }
                        _ => {
                            log::warn!("reCAPTCHA validation failed with error code: {}", error_code);
                        }
                    }
                }
            }
            log::info!("reCAPTCHA validation failed without specific error code");
            return Ok(false);
        }

        Ok(true)
    }

    /// Validate with Cloudflare Turnstile API
    async fn validate_turnstile(&self, request: &CaptchaValidationRequest) -> Result<bool> {
        // Use shared HTTP client with keepalive instead of creating new client
        let client = get_global_reqwest_client()
            .context("Failed to get global HTTP client")?;

        let mut params = HashMap::new();
        params.insert("response", &request.response_token);
        params.insert("secret", &request.secret_key);
        params.insert("remoteip", &request.ip_address);

        log::info!("Turnstile validation request - response_length: {}, remote_ip: {}",
                   request.response_token.len(), request.ip_address);

        let response = client
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .form(&params)
            .send()
            .await
            .context("Failed to send Turnstile validation request")?;

        log::info!("Turnstile validation HTTP response - status: {}", response.status());

        if !response.status().is_success() {
            log::error!("Turnstile service returned non-success status: {}", response.status());
            return Ok(false);
        }

        let validation_response: CaptchaValidationResponse = response
            .json()
            .await
            .context("Failed to parse Turnstile response")?;

        if !validation_response.success {
            if let Some(error_codes) = &validation_response.error_codes {
                for error_code in error_codes {
                    match error_code.as_str() {
                        "invalid-input-secret" => {
                            log::error!("Turnstile secret key is invalid");
                            return Ok(false);
                        }
                        "invalid-input-response" => {
                            log::info!("Invalid Turnstile response from user");
                            return Ok(false);
                        }
                        "timeout-or-duplicate" => {
                            log::info!("Turnstile response expired or duplicate");
                            return Ok(false);
                        }
                        _ => {
                            log::warn!("Turnstile validation failed with error code: {}", error_code);
                        }
                    }
                }
            }
            log::info!("Turnstile validation failed without specific error code");
            return Ok(false);
        }

        Ok(true)
    }

    /// Get the captcha backend response key name for the current provider
    pub fn get_captcha_backend_key(&self) -> &'static str {
        match self.config.provider {
            CaptchaProvider::HCaptcha => "h-captcha-response",
            CaptchaProvider::ReCaptcha => "g-recaptcha-response",
            CaptchaProvider::Turnstile => "cf-turnstile-response",
        }
    }

    /// Get validation result from cache
    async fn get_validation_cache(&self, key: &str) -> Option<CachedCaptchaResult> {
        let cache = self.validation_cache.read().await;
        cache.get(key).cloned()
    }

    /// Set validation result in cache
    async fn set_validation_cache(&self, key: &str, is_valid: bool) {
        let mut cache = self.validation_cache.write().await;
        cache.insert(
            key.to_string(),
            CachedCaptchaResult {
                is_valid,
                expires_at: Instant::now() + Duration::from_secs(self.config.validation_cache_ttl_seconds),
            },
        );
    }

    /// Remove validation result from cache
    async fn remove_validation_cache(&self, key: &str) {
        let mut cache = self.validation_cache.write().await;
        cache.remove(key);
    }

    /// Clean up expired cache entries
    pub async fn cleanup_cache(&self) {
        let mut cache = self.validation_cache.write().await;
        let now = Instant::now();
        cache.retain(|_, cached| cached.expires_at > now);

        // Also clean up expired validated tokens
        let mut validated_tokens = self.validated_tokens.write().await;
        validated_tokens.retain(|_, expiration| *expiration > now);
    }
}

/// Global captcha client instance
static CAPTCHA_CLIENT: OnceCell<Arc<CaptchaClient>> = OnceCell::const_new();

/// Initialize the global captcha client
pub async fn init_captcha_client(
    config: CaptchaConfig,
) -> Result<()> {
    let client = Arc::new(CaptchaClient::new(config));

    CAPTCHA_CLIENT.set(client)
        .map_err(|_| anyhow::anyhow!("Failed to initialize captcha client"))?;

    Ok(())
}

/// Validate captcha response
pub async fn validate_captcha_response(
    response_token: String,
    ip_address: String,
    user_agent: Option<String>,
) -> Result<bool> {
    let client = CAPTCHA_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Captcha client not initialized"))?;

    let request = CaptchaValidationRequest {
        response_token,
        ip_address,
        user_agent,
        site_key: client.config.site_key.clone(),
        secret_key: client.config.secret_key.clone(),
        provider: client.config.provider.clone(),
    };

    client.validate_captcha(request).await
}

/// Generate captcha token
pub async fn generate_captcha_token(
    ip_address: String,
    user_agent: String,
    ja4_fingerprint: Option<String>,
) -> Result<CaptchaToken> {
    let client = CAPTCHA_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Captcha client not initialized"))?;

    client.generate_token(ip_address, user_agent, ja4_fingerprint).await
}

/// Validate captcha token
pub async fn validate_captcha_token(
    token: &str,
    ip_address: &str,
    user_agent: &str,
) -> Result<bool> {
    let client = CAPTCHA_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Captcha client not initialized"))?;

    client.validate_token(token, ip_address, user_agent).await
}

/// Apply captcha challenge
pub fn apply_captcha_challenge() -> Result<String> {
    let client = CAPTCHA_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Captcha client not initialized"))?;

    Ok(client.apply_captcha_challenge(&client.config.site_key))
}

/// Apply captcha challenge with JWT token
pub fn apply_captcha_challenge_with_token(jwt_token: &str) -> Result<String> {
    let client = CAPTCHA_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Captcha client not initialized"))?;

    Ok(client.apply_captcha_challenge_with_token(&client.config.site_key, jwt_token))
}

/// Get the captcha backend response key name
pub fn get_captcha_backend_key() -> Result<&'static str> {
    let client = CAPTCHA_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Captcha client not initialized"))?;

    Ok(client.get_captcha_backend_key())
}

/// Mark a JWT token as validated after successful captcha completion
pub async fn mark_captcha_token_validated(token: &str) -> Result<()> {
    let client = CAPTCHA_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Captcha client not initialized"))?;

    client.mark_token_validated(token).await
}

/// Revoke a JWT token
pub async fn revoke_captcha_token(token: &str) -> Result<()> {
    let client = CAPTCHA_CLIENT
        .get()
        .ok_or_else(|| anyhow::anyhow!("Captcha client not initialized"))?;

    client.revoke_token(token).await
}

/// Validate captcha response and mark token as validated
pub async fn validate_and_mark_captcha(
    response_token: String,
    jwt_token: String,
    ip_address: String,
    user_agent: Option<String>,
) -> Result<bool> {
    log::info!("validate_and_mark_captcha called for IP: {}, response_token length: {}, jwt_token length: {}",
               ip_address, response_token.len(), jwt_token.len());

    // First validate the captcha response
    let is_valid = validate_captcha_response(response_token, ip_address.clone(), user_agent.clone()).await?;

    log::info!("Captcha validation result: {}", is_valid);

    if is_valid {
        // Only try to mark JWT token as validated if it's not empty
        if !jwt_token.is_empty() {
        if let Err(e) = mark_captcha_token_validated(&jwt_token).await {
            log::warn!("Failed to mark JWT token as validated: {}", e);
                // Don't return false here - captcha validation succeeded
            } else {
        log::info!("Captcha validated and JWT token marked as validated for IP: {}", ip_address);
            }
        } else {
            log::info!("Captcha validated successfully for IP: {} (no JWT token to mark)", ip_address);
        }
    } else {
        log::warn!("Captcha validation failed for IP: {}", ip_address);
    }

    Ok(is_valid)
}

/// Start periodic cache cleanup task
pub async fn start_cache_cleanup_task() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            if let Some(client) = CAPTCHA_CLIENT.get() {
                client.cleanup_cache().await;
            }
        }
    });
}
