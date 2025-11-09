use std::net::SocketAddr;
use std::sync::{Arc, RwLock, OnceLock};

use anyhow::Result;
use sha2::{Digest, Sha256};
use wirefilter::{ExecutionContext, Scheme, TypedArray, TypedMap};
use crate::config::{Config, fetch_config};
use crate::threat;
use anyhow::anyhow;

/// WAF action types
#[derive(Debug, Clone, PartialEq)]
pub enum WafAction {
    Block,
    Challenge,
    Allow,
}

impl WafAction {
    pub fn from_str(action: &str) -> Self {
        match action.to_lowercase().as_str() {
            "block" => WafAction::Block,
            "challenge" => WafAction::Challenge,
            _ => WafAction::Allow,
        }
    }
}

/// WAF rule evaluation result
#[derive(Debug, Clone)]
pub struct WafResult {
    pub action: WafAction,
    pub rule_name: String,
    pub rule_id: String,
}

/// Wirefilter-based HTTP request filtering engine
pub struct HttpFilter {
    scheme: Arc<Scheme>,
    rules: Arc<RwLock<Vec<(wirefilter::Filter, WafAction, String, String)>>>, // (filter, action, name, id)
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
            ip.src.country: Bytes,
            ip.src.asn: Int,
            ip.src.asn_org: Bytes,
            ip.src.asn_country: Bytes,
            threat.score: Int,
            threat.advice: Bytes,
        };

        // Register functions used in Cloudflare-style expressions
        builder.add_function("any", wirefilter::AnyFunction::default()).unwrap();
        builder.add_function("all", wirefilter::AllFunction::default()).unwrap();

        builder.add_function("cidr", wirefilter::CIDRFunction::default()).unwrap();
        builder.add_function("concat", wirefilter::ConcatFunction::default()).unwrap();
        builder.add_function("decode_base64", wirefilter::DecodeBase64Function::default()).unwrap();
        builder.add_function("ends_with", wirefilter::EndsWithFunction::default()).unwrap();
        builder.add_function("json_lookup_integer", wirefilter::JsonLookupIntegerFunction::default()).unwrap();
        builder.add_function("json_lookup_string", wirefilter::JsonLookupStringFunction::default()).unwrap();
        builder.add_function("len", wirefilter::LenFunction::default()).unwrap();
        builder.add_function("lower", wirefilter::LowerFunction::default()).unwrap();
        builder.add_function("remove_bytes", wirefilter::RemoveBytesFunction::default()).unwrap();
        builder.add_function("remove_query_args", wirefilter::RemoveQueryArgsFunction::default()).unwrap();
        builder.add_function("starts_with", wirefilter::StartsWithFunction::default()).unwrap();
        builder.add_function("substring", wirefilter::SubstringFunction::default()).unwrap();
        builder.add_function("to_string", wirefilter::ToStringFunction::default()).unwrap();
        builder.add_function("upper", wirefilter::UpperFunction::default()).unwrap();
        builder.add_function("url_decode", wirefilter::UrlDecodeFunction::default()).unwrap();
        builder.add_function("uuid4", wirefilter::UUID4Function::default()).unwrap();
        builder.add_function("wildcard_replace", wirefilter::WildcardReplaceFunction::default()).unwrap();


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
            rules: Arc::new(RwLock::new(vec![
                (filter, WafAction::Block, "default".to_string(), "default".to_string())
            ])),
            rules_hash: Arc::new(RwLock::new(None)),
        })
    }

    /// Create a new HTTP filter from config WAF rules
    pub fn new_from_config(config: &Config) -> Result<Self> {
        // Create the scheme with HTTP request fields
        let scheme = Arc::new(Self::create_scheme());

        if config.waf_rules.rules.is_empty() {
            // If no WAF rules, create a default filter that allows all
            return Ok(Self {
                scheme,
                rules: Arc::new(RwLock::new(vec![])),
                rules_hash: Arc::new(RwLock::new(Some(Self::compute_rules_hash("")))),
            });
        }

        // Validate and compile individual WAF rules
        let mut compiled_rules = Vec::new();
        let mut rules_hash_input = String::new();

        for rule in &config.waf_rules.rules {
            // Basic validation - check if expression is not empty
            if rule.expression.trim().is_empty() {
                log::warn!("Skipping empty WAF rule expression for rule '{}'", rule.name);
                continue;
            }

            // Try to parse the expression to validate it
            if let Err(error) = scheme.parse(&rule.expression) {
                log::warn!("Invalid WAF rule expression for rule '{}': {}: {}", rule.name, rule.expression, error);
                continue;
            }

            // Compile the rule
            let expression = Box::leak(rule.expression.clone().into_boxed_str());
            let ast = scheme.parse(expression)?;
            let filter = ast.compile();
            let action = WafAction::from_str(&rule.action);

            compiled_rules.push((filter, action, rule.name.clone(), rule.id.clone()));
            rules_hash_input.push_str(&format!("{}:{}:{};", rule.id, rule.action, rule.expression));
        }

        if compiled_rules.is_empty() {
            log::warn!("No valid WAF rules found, using default filter that allows all");
            return Ok(Self {
                scheme,
                rules: Arc::new(RwLock::new(vec![])),
                rules_hash: Arc::new(RwLock::new(Some(Self::compute_rules_hash("")))),
            });
        }

        let hash = Self::compute_rules_hash(&rules_hash_input);
        Ok(Self {
            scheme,
            rules: Arc::new(RwLock::new(compiled_rules)),
            rules_hash: Arc::new(RwLock::new(Some(hash))),
        })
    }

    /// Update the filter with new WAF rules from config
    pub fn update_from_config(&self, config: &Config) -> Result<()> {
        // Validate and compile individual WAF rules
        let mut compiled_rules = Vec::new();
        let mut rules_hash_input = String::new();

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

            // Compile the rule
            let expression = Box::leak(rule.expression.clone().into_boxed_str());
            let ast = self.scheme.parse(expression)?;
            let filter = ast.compile();
            let action = WafAction::from_str(&rule.action);

            compiled_rules.push((filter, action, rule.name.clone(), rule.id.clone()));
            rules_hash_input.push_str(&format!("{}:{}:{};", rule.id, rule.action, rule.expression));
        }

        // Compute hash and skip update if unchanged
        let new_hash = Self::compute_rules_hash(&rules_hash_input);
        if let Some(prev) = self.rules_hash.read().unwrap().as_ref() {
            if prev == &new_hash {
                log::debug!("HTTP filter WAF rules unchanged; skipping update");
                return Ok(());
            }
        }

        let rules_count = compiled_rules.len();
        *self.rules.write().unwrap() = compiled_rules;
        *self.rules_hash.write().unwrap() = Some(new_hash);

        log::info!("HTTP filter updated with {} WAF rules from config", rules_count);

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
    pub async fn should_block_request_from_parts(
        &self,
        req_parts: &hyper::http::request::Parts,
        body_bytes: &[u8],
        peer_addr: SocketAddr,
    ) -> Result<Option<WafResult>> {
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

        // Fetch threat intelligence data for the source IP
        let _threat_fields = match threat::get_waf_fields(&peer_addr.ip().to_string()).await {
            Ok(Some(waf_fields)) => {
                // Set threat intelligence fields
                ctx.set_field_value(
                    self.scheme.get_field("ip.src.country").unwrap(),
                    waf_fields.ip_src_country.clone(),
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("ip.src.asn").unwrap(),
                    waf_fields.ip_src_asn as i64,
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("ip.src.asn_org").unwrap(),
                    waf_fields.ip_src_asn_org.clone(),
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("ip.src.asn_country").unwrap(),
                    waf_fields.ip_src_asn_country.clone(),
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("threat.score").unwrap(),
                    waf_fields.threat_score as i64,
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("threat.advice").unwrap(),
                    waf_fields.threat_advice.clone(),
                )?;
                Some(waf_fields)
            }
            Ok(None) => {
                // No threat data found, set default values
                ctx.set_field_value(
                    self.scheme.get_field("ip.src.country").unwrap(),
                    "",
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("ip.src.asn").unwrap(),
                    0i64,
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("ip.src.asn_org").unwrap(),
                    "",
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("ip.src.asn_country").unwrap(),
                    "",
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("threat.score").unwrap(),
                    0i64,
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("threat.advice").unwrap(),
                    "",
                )?;
                None
            }
            Err(e) => {
                log::warn!("Failed to fetch threat intelligence for {}: {}", peer_addr.ip(), e);
                // Set default values on error
                ctx.set_field_value(
                    self.scheme.get_field("ip.src.country").unwrap(),
                    "",
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("ip.src.asn").unwrap(),
                    0i64,
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("ip.src.asn_org").unwrap(),
                    "",
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("ip.src.asn_country").unwrap(),
                    "",
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("threat.score").unwrap(),
                    0i64,
                )?;
                ctx.set_field_value(
                    self.scheme.get_field("threat.advice").unwrap(),
                    "",
                )?;
                None
            }
        };

        // Execute each rule individually and return the first match
        let rules_guard = self.rules.read().unwrap();
        for (filter, action, rule_name, rule_id) in rules_guard.iter() {
            let rule_result = filter.execute(&ctx)?;
            if rule_result {
                return Ok(Some(WafResult {
                    action: action.clone(),
                    rule_name: rule_name.clone(),
                    rule_id: rule_id.clone(),
                }));
            }
        }

        Ok(None)
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
                    filter.update_from_config(&config_response.config)?;
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
        filter.update_from_config(config)?;
        Ok(())
    } else {
        log::warn!("HTTP filter not initialized, cannot update");
        Ok(())
    }
}

/// Evaluate WAF rules for a Pingora request
/// This is a convenience function that converts Pingora's RequestHeader to hyper's Parts
pub async fn evaluate_waf_for_pingora_request(
    req_header: &pingora_http::RequestHeader,
    body_bytes: &[u8],
    peer_addr: SocketAddr,
) -> Result<Option<WafResult>> {
    let filter = match get_global_http_filter() {
        Some(f) => {
            // Check if filter has any rules
            let rules_count = f.rules.read().unwrap().len();
            if rules_count == 0 {
                log::debug!("WAF filter initialized but has no rules loaded");
            } else {
                log::debug!("WAF filter has {} rules loaded", rules_count);
            }
            f
        }
        None => {
            log::debug!("WAF filter not initialized, skipping evaluation");
            return Ok(None);
        }
    };

    // Convert Pingora RequestHeader to hyper::http::request::Parts
    // Pingora URIs might be relative, so we need to construct a full URI
    let uri_str = if req_header.uri.scheme().is_some() {
        // Already an absolute URI
        req_header.uri.to_string()
    } else {
        // Construct absolute URI from relative path
        // Use http://localhost as base since we only need the path/query for WAF evaluation
        format!("http://localhost{}", req_header.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"))
    };

    let uri = match uri_str.parse::<hyper::http::Uri>() {
        Ok(u) => u,
        Err(e) => {
            log::error!("WAF: Failed to parse URI '{}': {}", uri_str, e);
            return Err(anyhow!("Failed to parse URI: {}", e));
        }
    };

    let mut builder = hyper::http::request::Builder::new()
        .method(req_header.method.as_str())
        .uri(uri);

    // Copy headers
    for (name, value) in req_header.headers.iter() {
        if let Ok(name_str) = name.as_str().parse::<hyper::http::HeaderName>() {
            if let Ok(value_str) = value.to_str() {
                builder = builder.header(name_str, value_str);
            } else {
                builder = builder.header(name_str, value.as_bytes());
            }
        } else {
            log::debug!("WAF: Failed to parse header name: {}", name.as_str());
        }
    }

    let req = match builder.body(()) {
        Ok(r) => r,
        Err(e) => {
            log::error!("WAF: Failed to build hyper request: {}", e);
            return Err(anyhow!("Failed to build hyper request: {}", e));
        }
    };
    let (req_parts, _) = req.into_parts();

    log::debug!("WAF: Evaluating request - method={}, uri={}, peer={}",
                req_header.method.as_str(), uri_str, peer_addr);

    match filter.should_block_request_from_parts(&req_parts, body_bytes, peer_addr).await {
        Ok(result) => {
            if result.is_some() {
                log::debug!("WAF: Rule matched - {:?}", result);
            }
            Ok(result)
        }
        Err(e) => {
            log::error!("WAF: Evaluation error: {}", e);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::request::Builder;
    use std::net::Ipv4Addr;


    #[tokio::test]
    async fn test_custom_filter() -> Result<()> {
        // Test a custom filter that blocks requests to specific host
        let filter = HttpFilter::new("http.request.host == \"blocked.example.com\"")?;

        let req = Builder::new()
            .method("GET")
            .uri("http://blocked.example.com/test")
            .body(())?;
        let (req_parts, _) = req.into_parts();

        let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);
        let result = filter.should_block_request_from_parts(&req_parts, b"", peer_addr).await?;
        assert!(result.is_some(), "Request to blocked host should be blocked");
        assert_eq!(result.unwrap().action, WafAction::Block);

        Ok(())
    }

    #[tokio::test]
    async fn test_content_scanning_integration() -> Result<()> {
        // Test content scanning integration with wirefilter
        let filter = HttpFilter::new("http.request.host == \"example.com\"")?;

        let req = Builder::new()
            .method("POST")
            .uri("http://example.com/test")
            .header("content-type", "text/html")
            .body(())
            .unwrap();
        let (req_parts, _) = req.into_parts();

        let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);

        // Test with clean content (should not be blocked by content scanning)
        let clean_content = b"<html><body>Clean content</body></html>";
        let result = filter.should_block_request_from_parts(&req_parts, clean_content, peer_addr).await?;

        // Should be blocked by host rule, not content scanning
        assert!(result.is_some(), "Request to example.com should be blocked by host rule");
        assert_eq!(result.unwrap().rule_name, "default");

        Ok(())
    }
}
