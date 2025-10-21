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

/// Captcha provider types supported by Arxignis
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, clap::ValueEnum)]
pub enum CaptchaProvider {
    #[serde(rename = "hcaptcha")]
    HCaptcha,
    #[serde(rename = "recaptcha")]
    ReCaptcha,
    #[serde(rename = "turnstile")]
    Turnstile,
}

impl Default for CaptchaProvider {
    fn default() -> Self {
        CaptchaProvider::HCaptcha
    }
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
}

impl CaptchaClient {
    pub fn new(
        config: CaptchaConfig,
    ) -> Self {
        Self {
            config,
            validation_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Validate a captcha response token
    pub async fn validate_captcha(&self, request: CaptchaValidationRequest) -> Result<bool> {
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
            iss: "arxignis-moat".to_string(),
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
        let validation = Validation::new(Algorithm::HS256);

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

                // Check if captcha was validated
                if !claims.captcha_validated {
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
        let validation = Validation::new(Algorithm::HS256);

        match decode::<CaptchaClaims>(token, &decoding_key, &validation) {
            Ok(token_data) => {
                let mut claims = token_data.claims;
                claims.captcha_validated = true;

                // Re-encode the token with updated claims
                let header = Header::new(Algorithm::HS256);
                let encoding_key = EncodingKey::from_secret(self.config.jwt_secret.as_bytes());
                let updated_token = encode(&header, &claims, &encoding_key)
                    .context("Failed to re-encode JWT token")?;

                // Update Redis cache if available
                if let Ok(redis_manager) = RedisManager::get() {
                    let key = format!("{}:captcha_jwt:{}", redis_manager.create_namespace("captcha"), claims.jti);
                    let mut redis = redis_manager.get_connection();
                    let updated_captcha_token = CaptchaToken {
                        token: updated_token,
                        claims: claims.clone(),
                    };
                    let token_data = serde_json::to_string(&updated_captcha_token)
                        .context("Failed to serialize updated captcha token")?;

                    let _: () = redis
                        .set_ex(&key, token_data, self.config.token_ttl_seconds)
                        .await
                        .context("Failed to update captcha token in Redis")?;
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
        let validation = Validation::new(Algorithm::HS256);

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
        match self.config.provider {
            CaptchaProvider::HCaptcha => self.render_hcaptcha_form(site_key),
            CaptchaProvider::ReCaptcha => self.render_recaptcha_form(site_key),
            CaptchaProvider::Turnstile => self.render_turnstile_form(site_key),
        }
    }

    /// Apply captcha challenge with JWT token (return HTML form)
    pub fn apply_captcha_challenge_with_token(&self, site_key: &str, jwt_token: &str) -> String {
        match self.config.provider {
            CaptchaProvider::HCaptcha => self.render_hcaptcha_form_with_token(site_key, jwt_token),
            CaptchaProvider::ReCaptcha => self.render_recaptcha_form_with_token(site_key, jwt_token),
            CaptchaProvider::Turnstile => self.render_turnstile_form_with_token(site_key, jwt_token),
        }
    }

    /// Validate with hCaptcha API
    async fn validate_hcaptcha(&self, request: &CaptchaValidationRequest) -> Result<bool> {
        let client = reqwest::Client::new();
        let mut params = HashMap::new();
        params.insert("response", &request.response_token);
        params.insert("secret", &request.secret_key);
        params.insert("sitekey", &request.site_key);
        params.insert("remoteip", &request.ip_address);

        let response = client
            .post("https://hcaptcha.com/siteverify")
            .form(&params)
            .send()
            .await
            .context("Failed to send hCaptcha validation request")?;

        let validation_response: CaptchaValidationResponse = response
            .json()
            .await
            .context("Failed to parse hCaptcha response")?;

        if !validation_response.success {
            log::warn!("hCaptcha validation failed: {:?}", validation_response.error_codes);
        }

        Ok(validation_response.success)
    }

    /// Validate with reCAPTCHA API
    async fn validate_recaptcha(&self, request: &CaptchaValidationRequest) -> Result<bool> {
        let client = reqwest::Client::new();
        let mut params = HashMap::new();
        params.insert("response", &request.response_token);
        params.insert("secret", &request.secret_key);
        params.insert("remoteip", &request.ip_address);

        let response = client
            .post("https://www.google.com/recaptcha/api/siteverify")
            .form(&params)
            .send()
            .await
            .context("Failed to send reCAPTCHA validation request")?;

        let validation_response: CaptchaValidationResponse = response
            .json()
            .await
            .context("Failed to parse reCAPTCHA response")?;

        if !validation_response.success {
            log::warn!("reCAPTCHA validation failed: {:?}", validation_response.error_codes);
        }

        Ok(validation_response.success)
    }

    /// Validate with Cloudflare Turnstile API
    async fn validate_turnstile(&self, request: &CaptchaValidationRequest) -> Result<bool> {
        let client = reqwest::Client::new();
        let mut params = HashMap::new();
        params.insert("response", &request.response_token);
        params.insert("secret", &request.secret_key);
        params.insert("remoteip", &request.ip_address);

        let response = client
            .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
            .form(&params)
            .send()
            .await
            .context("Failed to send Turnstile validation request")?;

        let validation_response: CaptchaValidationResponse = response
            .json()
            .await
            .context("Failed to parse Turnstile response")?;

        if !validation_response.success {
            log::warn!("Turnstile validation failed: {:?}", validation_response.error_codes);
        }

        Ok(validation_response.success)
    }

    /// Render hCaptcha form HTML with JWT token
    fn render_hcaptcha_form(&self, site_key: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Security Verification Required</title>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }}
        .captcha-container {{ margin: 20px auto; }}
        .error {{ color: red; margin: 10px 0; }}
        .token-info {{ font-size: 12px; color: #666; margin: 10px 0; }}
    </style>
</head>
<body>
    <h2>Security Verification Required</h2>
    <p>Please complete the security verification below to continue.</p>
    <div class="captcha-container">
        <div class="h-captcha" data-sitekey="{}"></div>
    </div>
    <form method="POST" action="/cgi-bin/captcha/verify">
        <input type="hidden" name="captcha_response" id="captcha_response">
        <input type="hidden" name="jwt_token" id="jwt_token">
        <button type="submit" onclick="return submitCaptcha()">Verify</button>
    </form>
    <div class="token-info">
        <p>Your session token will be validated after completing the captcha.</p>
    </div>
    <script>
        function submitCaptcha() {{
            const response = hcaptcha.getResponse();
            if (!response) {{
                alert('Please complete the captcha');
                return false;
            }}
            document.getElementById('captcha_response').value = response;

            // Get JWT token from URL parameter or localStorage
            const urlParams = new URLSearchParams(window.location.search);
            const jwtToken = urlParams.get('token') || localStorage.getItem('captcha_token');
            if (jwtToken) {{
                document.getElementById('jwt_token').value = jwtToken;
            }}

            return true;
        }}
    </script>
</body>
</html>"#,
            site_key
        )
    }

    /// Render reCAPTCHA form HTML with JWT token
    fn render_recaptcha_form(&self, site_key: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Security Verification Required</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }}
        .captcha-container {{ margin: 20px auto; }}
        .error {{ color: red; margin: 10px 0; }}
        .token-info {{ font-size: 12px; color: #666; margin: 10px 0; }}
    </style>
</head>
<body>
    <h2>Security Verification Required</h2>
    <p>Please complete the security verification below to continue.</p>
    <div class="captcha-container">
        <div class="g-recaptcha" data-sitekey="{}"></div>
    </div>
    <form method="POST" action="/cgi-bin/captcha/verify">
        <input type="hidden" name="captcha_response" id="captcha_response">
        <input type="hidden" name="jwt_token" id="jwt_token">
        <button type="submit" onclick="return submitCaptcha()">Verify</button>
    </form>
    <div class="token-info">
        <p>Your session token will be validated after completing the captcha.</p>
    </div>
    <script>
        function submitCaptcha() {{
            const response = grecaptcha.getResponse();
            if (!response) {{
                alert('Please complete the captcha');
                return false;
            }}
            document.getElementById('captcha_response').value = response;

            // Get JWT token from URL parameter or localStorage
            const urlParams = new URLSearchParams(window.location.search);
            const jwtToken = urlParams.get('token') || localStorage.getItem('captcha_token');
            if (jwtToken) {{
                document.getElementById('jwt_token').value = jwtToken;
            }}

            return true;
        }}
    </script>
</body>
</html>"#,
            site_key
        )
    }

    /// Render Turnstile form HTML with JWT token
    fn render_turnstile_form(&self, site_key: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Security Verification Required</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }}
        .captcha-container {{ margin: 20px auto; }}
        .error {{ color: red; margin: 10px 0; }}
        .token-info {{ font-size: 12px; color: #666; margin: 10px 0; }}
    </style>
</head>
<body>
    <h2>Security Verification Required</h2>
    <p>Please complete the security verification below to continue.</p>
    <div class="captcha-container">
        <div class="cf-turnstile" data-sitekey="{}"></div>
    </div>
    <form method="POST" action="/cgi-bin/captcha/verify">
        <input type="hidden" name="captcha_response" id="captcha_response">
        <input type="hidden" name="jwt_token" id="jwt_token">
        <button type="submit" onclick="return submitCaptcha()">Verify</button>
    </form>
    <div class="token-info">
        <p>Your session token will be validated after completing the captcha.</p>
    </div>
    <script>
        function submitCaptcha() {{
            const response = document.querySelector('[name="cf-turnstile-response"]').value;
            if (!response) {{
                alert('Please complete the captcha');
                return false;
            }}
            document.getElementById('captcha_response').value = response;

            // Get JWT token from URL parameter or localStorage
            const urlParams = new URLSearchParams(window.location.search);
            const jwtToken = urlParams.get('token') || localStorage.getItem('captcha_token');
            if (jwtToken) {{
                document.getElementById('jwt_token').value = jwtToken;
            }}

            return true;
        }}
    </script>
</body>
</html>"#,
            site_key
        )
    }

    /// Render hCaptcha form HTML with explicit JWT token
    fn render_hcaptcha_form_with_token(&self, site_key: &str, jwt_token: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Security Verification Required</title>
    <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }}
        .captcha-container {{ margin: 20px auto; }}
        .error {{ color: red; margin: 10px 0; }}
        .token-info {{ font-size: 12px; color: #666; margin: 10px 0; }}
    </style>
</head>
<body>
    <h2>Security Verification Required</h2>
    <p>Please complete the security verification below to continue.</p>
    <div class="captcha-container">
        <div class="h-captcha" data-sitekey="{}"></div>
    </div>
    <form method="POST" action="/cgi-bin/captcha/verify">
        <input type="hidden" name="captcha_response" id="captcha_response">
        <input type="hidden" name="jwt_token" id="jwt_token" value="{}">
        <button type="submit" onclick="return submitCaptcha()">Verify</button>
    </form>
    <div class="token-info">
        <p>Your session token will be validated after completing the captcha.</p>
    </div>
    <script>
        function submitCaptcha() {{
            const response = hcaptcha.getResponse();
            if (!response) {{
                alert('Please complete the captcha');
                return false;
            }}
            document.getElementById('captcha_response').value = response;
            return true;
        }}
    </script>
</body>
</html>"#,
            site_key, jwt_token
        )
    }

    /// Render reCAPTCHA form HTML with explicit JWT token
    fn render_recaptcha_form_with_token(&self, site_key: &str, jwt_token: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Security Verification Required</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }}
        .captcha-container {{ margin: 20px auto; }}
        .error {{ color: red; margin: 10px 0; }}
        .token-info {{ font-size: 12px; color: #666; margin: 10px 0; }}
    </style>
</head>
<body>
    <h2>Security Verification Required</h2>
    <p>Please complete the security verification below to continue.</p>
    <div class="captcha-container">
        <div class="g-recaptcha" data-sitekey="{}"></div>
    </div>
    <form method="POST" action="/cgi-bin/captcha/verify">
        <input type="hidden" name="captcha_response" id="captcha_response">
        <input type="hidden" name="jwt_token" id="jwt_token" value="{}">
        <button type="submit" onclick="return submitCaptcha()">Verify</button>
    </form>
    <div class="token-info">
        <p>Your session token will be validated after completing the captcha.</p>
    </div>
    <script>
        function submitCaptcha() {{
            const response = grecaptcha.getResponse();
            if (!response) {{
                alert('Please complete the captcha');
                return false;
            }}
            document.getElementById('captcha_response').value = response;
            return true;
        }}
    </script>
</body>
</html>"#,
            site_key, jwt_token
        )
    }

    /// Render Turnstile form HTML with explicit JWT token
    fn render_turnstile_form_with_token(&self, site_key: &str, jwt_token: &str) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Security Verification Required</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }}
        .captcha-container {{ margin: 20px auto; }}
        .error {{ color: red; margin: 10px 0; }}
        .token-info {{ font-size: 12px; color: #666; margin: 10px 0; }}
    </style>
</head>
<body>
    <h2>Security Verification Required</h2>
    <p>Please complete the security verification below to continue.</p>
    <div class="captcha-container">
        <div class="cf-turnstile" data-sitekey="{}"></div>
    </div>
    <form method="POST" action="/cgi-bin/captcha/verify">
        <input type="hidden" name="captcha_response" id="captcha_response">
        <input type="hidden" name="jwt_token" id="jwt_token" value="{}">
        <button type="submit" onclick="return submitCaptcha()">Verify</button>
    </form>
    <div class="token-info">
        <p>Your session token will be validated after completing the captcha.</p>
    </div>
    <script>
        function submitCaptcha() {{
            const response = document.querySelector('[name="cf-turnstile-response"]').value;
            if (!response) {{
                alert('Please complete the captcha');
                return false;
            }}
            document.getElementById('captcha_response').value = response;
            return true;
        }}
    </script>
</body>
</html>"#,
            site_key, jwt_token
        )
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
        user_agent: user_agent,
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
    // First validate the captcha response
    let is_valid = validate_captcha_response(response_token, ip_address.clone(), user_agent.clone()).await?;

    if is_valid {
        // Mark the JWT token as validated
        if let Err(e) = mark_captcha_token_validated(&jwt_token).await {
            log::warn!("Failed to mark JWT token as validated: {}", e);
            return Ok(false);
        }
        log::info!("Captcha validated and JWT token marked as validated for IP: {}", ip_address);
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
