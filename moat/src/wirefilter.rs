use std::net::SocketAddr;
use std::sync::{Arc, RwLock, OnceLock};

use anyhow::Result;
use sha2::{Digest, Sha256};
use wirefilter::{ExecutionContext, Scheme, TypedArray, TypedMap};
use crate::config::{Config, fetch_config};
use anyhow::anyhow;

/// Wirefilter-based HTTP request filtering engine
pub struct HttpFilter {
    scheme: Arc<Scheme>,
    filter: Arc<RwLock<wirefilter::Filter>>,
    rules_hash: Arc<RwLock<Option<String>>>,
}

impl HttpFilter {
    /// Create the wirefilter scheme with HTTP request fields
    fn create_scheme() -> Scheme {
        let mut builder = Scheme! {
            http.request.method: Bytes,
            http.request.scheme: Bytes,
            http.request.host: Bytes,
            http.request.port: Int,
            http.request.path: Bytes,
            http.request.uri: Bytes,
            http.request.query: Bytes,
            http.request.user_agent: Bytes,
            http.request.content_type: Bytes,
            http.request.content_length: Int,
            http.request.body: Bytes,
            http.request.body_sha256: Bytes,
            http.request.headers: Map(Array(Bytes)),
            ip.src: Ip,
        };

        // Register functions used in Cloudflare-style expressions
        builder.add_function("any", wirefilter::AnyFunction::default()).unwrap();
        builder.add_function("all", wirefilter::AllFunction::default()).unwrap();

        builder.build()
    }

    /// Create a new HTTP filter with the given filter expression (static version)
    pub fn new(filter_expr: &'static str) -> Result<Self> {
        // Create the scheme with HTTP request fields
        let scheme = Arc::new(Self::create_scheme());

        // Parse the filter expression
        let ast = scheme.parse(filter_expr)?;

        // Compile the filter
        let filter = ast.compile();

        Ok(Self {
            scheme,
            filter: Arc::new(RwLock::new(filter)),
            rules_hash: Arc::new(RwLock::new(None)),
        })
    }

    /// Create a new HTTP filter with an owned string by converting to static
    fn new_from_string(filter_expr: String) -> Result<Self> {
        // Convert to static by leaking the string
        let leaked = Box::leak(filter_expr.into_boxed_str());
        Self::new(leaked)
    }


    /// Create a new HTTP filter from config WAF rules
    pub fn new_from_config(config: &Config) -> Result<Self> {
        if config.waf_rules.rules.is_empty() {
            // If no WAF rules, create a default filter that allows all
            return Self::new("false");
        }

        // Validate and combine all WAF rule expressions with OR logic
        let mut valid_expressions = Vec::new();
        for rule in &config.waf_rules.rules {
            // Basic validation - check if expression is not empty
            if rule.expression.trim().is_empty() {
                log::warn!("Skipping empty WAF rule expression for rule '{}'", rule.name);
                continue;
            }

            // Try to parse the expression to validate it
            let scheme = Self::create_scheme();
            if let Err(error) = scheme.parse(&rule.expression) {
                log::warn!("Invalid WAF rule expression for rule '{}': {}: {}", rule.name, rule.expression, error);
                continue;
            }

            valid_expressions.push(format!("({})", rule.expression));
        }

        if valid_expressions.is_empty() {
            log::warn!("No valid WAF rules found, using default filter that allows all");
            return Self::new("false");
        }

        let combined_expr = valid_expressions.join(" or ");
        let filter = Self::new_from_string(combined_expr.clone())?;
        let hash = Self::compute_rules_hash(&combined_expr);
        *filter.rules_hash.write().unwrap() = Some(hash);
        Ok(filter)
    }

    /// Update the filter with new WAF rules from config
    pub fn update_from_config(&self, config: &Config) -> Result<()> {
        if config.waf_rules.rules.is_empty() {
            // If no WAF rules, create a filter that allows all
            let ast = self.scheme.parse("false")?;
            let new_filter = ast.compile();
            *self.filter.write().unwrap() = new_filter;
            *self.rules_hash.write().unwrap() = Some(Self::compute_rules_hash("false"));
            return Ok(());
        }

        // Validate and combine all WAF rule expressions with OR logic
        let mut valid_expressions = Vec::new();
        for rule in &config.waf_rules.rules {
            // Basic validation - check if expression is not empty
            if rule.expression.trim().is_empty() {
                log::warn!("Skipping empty WAF rule expression for rule '{}'", rule.name);
                continue;
            }

            // Try to parse the expression to validate it
            if let Err(error) = self.scheme.parse(&rule.expression) {
                log::warn!("Invalid WAF rule expression for rule '{}': {}: {}", rule.name, rule.expression, error);
                continue;
            }

            valid_expressions.push(format!("({})", rule.expression));
        }

        let combined_expr = if valid_expressions.is_empty() {
            log::warn!("No valid WAF rules found, using default filter that allows all");
            "false".to_string()
        } else {
            valid_expressions.join(" or ")
        };

        // Compute hash and skip update if unchanged
        let new_hash = Self::compute_rules_hash(&combined_expr);
        if let Some(prev) = self.rules_hash.read().unwrap().as_ref() {
            if prev == &new_hash {
                log::debug!("HTTP filter WAF rules unchanged; skipping update");
                return Ok(());
            }
        }

        // Convert to static by leaking the string
        let leaked = Box::leak(combined_expr.into_boxed_str());
        let ast = self.scheme.parse(leaked)?;
        let new_filter = ast.compile();
        *self.filter.write().unwrap() = new_filter;
        *self.rules_hash.write().unwrap() = Some(new_hash);

        Ok(())
    }

    fn compute_rules_hash(expr: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(expr.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Get the current filter expression (for debugging)
    pub fn get_current_expression(&self) -> String {
        // This is a simplified version - in practice you might want to store the original expression
        "dynamic_filter_from_config".to_string()
    }

    /// Check if the given HTTP request should be blocked using request parts and body bytes
    pub fn should_block_request_from_parts(
        &self,
        req_parts: &hyper::http::request::Parts,
        body_bytes: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<bool> {
        // Create execution context
        let mut ctx = ExecutionContext::new(&self.scheme);

        // Extract request information
        let method = req_parts.method.as_str();
        let uri = &req_parts.uri;
        let scheme = uri.scheme().map(|s| s.as_str()).unwrap_or("http");
        let host = uri.host().unwrap_or("").to_string();
        let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
        let path = uri.path().to_string();
        let full_uri = uri.to_string();
        let query = uri.query().unwrap_or("").to_string();

        // Extract headers
        let user_agent = req_parts
            .headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        let content_type = req_parts
            .headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Get content length
        let content_length = req_parts
            .headers
            .get("content-length")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(body_bytes.len() as i64);

        // Process request body
        let body_text = String::from_utf8_lossy(body_bytes).to_string();

        // Calculate body SHA256
        let mut hasher = Sha256::new();
        hasher.update(body_bytes);
        let body_sha256_hex = hex::encode(hasher.finalize());

        // Set field values in execution context
        ctx.set_field_value(
            self.scheme.get_field("http.request.method").unwrap(),
            method,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.scheme").unwrap(),
            scheme,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.host").unwrap(),
            host,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.port").unwrap(),
            port as i64,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.path").unwrap(),
            path,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.uri").unwrap(),
            full_uri,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.query").unwrap(),
            query,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.user_agent").unwrap(),
            user_agent,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.content_type").unwrap(),
            content_type,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.headers").unwrap(),
            {
                let mut headers_map: TypedMap<'_, TypedArray<'_, &[u8]>> = TypedMap::new();
                for (name, value) in req_parts.headers.iter() {
                    let key = name.as_str().to_ascii_lowercase().into_bytes().into_boxed_slice();
                    let entry = headers_map.get_or_insert(key, TypedArray::new());
                    match value.to_str() {
                        Ok(s) => entry.push(s.as_bytes()),
                        Err(_) => entry.push(value.as_bytes()),
                    }
                }
                headers_map
            },
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.content_length").unwrap(),
            content_length,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.body").unwrap(),
            body_text,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("http.request.body_sha256").unwrap(),
            body_sha256_hex,
        )?;
        ctx.set_field_value(
            self.scheme.get_field("ip.src").unwrap(),
            peer_addr.ip(),
        )?;

        // Execute the filter
        let filter_guard = self.filter.read().unwrap();
        let result = filter_guard.execute(&ctx)?;
        Ok(result)
    }
}

// Global wirefilter instance for HTTP request filtering
static HTTP_FILTER: OnceLock<HttpFilter> = OnceLock::new();

pub fn get_global_http_filter() -> Option<&'static HttpFilter> {
    HTTP_FILTER.get()
}

pub fn set_global_http_filter(filter: HttpFilter) -> anyhow::Result<()> {
    HTTP_FILTER
        .set(filter)
        .map_err(|_| anyhow!("Failed to initialize HTTP filter"))
}


/// Initialize the global config + HTTP filter from API with retry logic
pub async fn init_config(base_url: String, api_key: String) -> anyhow::Result<()> {
    let mut retry_count = 0;
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_MS: u64 = 1000;

    loop {
        match fetch_config(base_url.clone(), api_key.clone()).await {
            Ok(config_response) => {
                let filter = HttpFilter::new_from_config(&config_response.config)?;
                set_global_http_filter(filter)?;
                log::info!("HTTP filter initialized with {} WAF rules from config", config_response.config.waf_rules.rules.len());
                return Ok(());
            }
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("503") && retry_count < MAX_RETRIES {
                    retry_count += 1;
                    log::warn!("Failed to fetch config for HTTP filter (attempt {}): {}. Retrying in {}ms...", retry_count, error_msg, RETRY_DELAY_MS);
                    tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                    continue;
                } else {
                    log::error!("Failed to fetch config for HTTP filter after {} attempts: {}", retry_count + 1, error_msg);
                    return Err(anyhow!("Failed to initialize HTTP filter: {}", error_msg));
                }
            }
        }
    }
}

/// Update the global HTTP filter with new config with retry logic
pub async fn update_with_config(base_url: String, api_key: String) -> anyhow::Result<()> {
    let mut retry_count = 0;
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_MS: u64 = 1000;

    loop {
        match fetch_config(base_url.clone(), api_key.clone()).await {
            Ok(config_response) => {
                if let Some(filter) = HTTP_FILTER.get() {
                    // Capture previous hash to decide logging level
                    let prev_hash = filter.rules_hash.read().unwrap().clone();
                    filter.update_from_config(&config_response.config)?;
                    let new_hash = filter.rules_hash.read().unwrap().clone();
                    if new_hash.is_some() && new_hash == prev_hash {
                        log::debug!("HTTP filter WAF rules unchanged; skipping update log");
                    } else {
                        log::info!(
                            "HTTP filter updated with {} WAF rules from config",
                            config_response.config.waf_rules.rules.len()
                        );
                    }
                } else {
                    log::warn!("HTTP filter not initialized, cannot update");
                }
                return Ok(());
            }
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("503") && retry_count < MAX_RETRIES {
                    retry_count += 1;
                    log::warn!("Failed to fetch config for HTTP filter update (attempt {}): {}. Retrying in {}ms...", retry_count, error_msg, RETRY_DELAY_MS);
                    tokio::time::sleep(tokio::time::Duration::from_millis(RETRY_DELAY_MS)).await;
                    continue;
                } else {
                    log::error!("Failed to fetch config for HTTP filter update after {} attempts: {}", retry_count + 1, error_msg);
                    return Err(anyhow!("Failed to fetch config: {}", error_msg));
                }
            }
        }
    }
}

/// Update the global HTTP filter using an already-fetched Config value
pub fn update_http_filter_from_config_value(config: &Config) -> anyhow::Result<()> {
    if let Some(filter) = HTTP_FILTER.get() {
        // Capture previous hash to decide logging level
        let prev_hash = filter.rules_hash.read().unwrap().clone();
        filter.update_from_config(config)?;
        let new_hash = filter.rules_hash.read().unwrap().clone();
        if new_hash.is_some() && new_hash == prev_hash {
            log::debug!("HTTP filter WAF rules unchanged; skipping update log");
        } else {
            log::info!(
                "HTTP filter updated with {} WAF rules from config",
                config.waf_rules.rules.len()
            );
        }
        Ok(())
    } else {
        log::warn!("HTTP filter not initialized, cannot update");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::request::Builder;
    use std::net::Ipv4Addr;


    #[test]
    fn test_custom_filter() -> Result<()> {
        // Test a custom filter that blocks requests to specific host
        let filter = HttpFilter::new("http.request.host == \"blocked.example.com\"")?;

        let req = Builder::new()
            .method("GET")
            .uri("http://blocked.example.com/test")
            .body(())?;
        let (req_parts, _) = req.into_parts();

        let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);
        let should_block = filter.should_block_request_from_parts(&req_parts, b"", peer_addr)?;
        assert!(should_block, "Request to blocked host should be blocked");

        Ok(())
    }
}
