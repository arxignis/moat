use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use anyhow::Result;
use sha2::{Digest, Sha256};
use wirefilter::{ExecutionContext, Scheme, TypedArray, TypedMap};
use crate::config::Config;

/// Wirefilter-based HTTP request filtering engine
pub struct HttpFilter {
    scheme: Arc<Scheme>,
    filter: Arc<RwLock<wirefilter::Filter>>,
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
            filter: Arc::new(RwLock::new(filter))
        })
    }

    /// Create a new HTTP filter with an owned string by converting to static
    fn new_from_string(filter_expr: String) -> Result<Self> {
        // Convert to static by leaking the string
        let leaked = Box::leak(filter_expr.into_boxed_str());
        Self::new(leaked)
    }

    /// Create a default filter that blocks POST requests (for testing)
    pub fn new_test_filter() -> Result<Self> {
        Self::new("http.request.method == \"POST\"")
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
                eprintln!("Warning: Skipping empty WAF rule expression for rule '{}'", rule.name);
                continue;
            }

            // Try to parse the expression to validate it
            let scheme = Self::create_scheme();
            if let Err(error) = scheme.parse(&rule.expression) {
                eprintln!("Warning: Invalid WAF rule expression for rule '{}': {}: {}", rule.name, rule.expression, error);
                continue;
            }

            valid_expressions.push(format!("({})", rule.expression));
        }

        if valid_expressions.is_empty() {
            eprintln!("Warning: No valid WAF rules found, using default filter that allows all");
            return Self::new("false");
        }

        let combined_expr = valid_expressions.join(" or ");
        Self::new_from_string(combined_expr)
    }

    /// Update the filter with new WAF rules from config
    pub fn update_from_config(&self, config: &Config) -> Result<()> {
        if config.waf_rules.rules.is_empty() {
            // If no WAF rules, create a filter that allows all
            let ast = self.scheme.parse("false")?;
            let new_filter = ast.compile();
            *self.filter.write().unwrap() = new_filter;
            return Ok(());
        }

        // Validate and combine all WAF rule expressions with OR logic
        let mut valid_expressions = Vec::new();
        for rule in &config.waf_rules.rules {
            // Basic validation - check if expression is not empty
            if rule.expression.trim().is_empty() {
                eprintln!("Warning: Skipping empty WAF rule expression for rule '{}'", rule.name);
                continue;
            }

            // Try to parse the expression to validate it
            if let Err(error) = self.scheme.parse(&rule.expression) {
                eprintln!("Warning: Invalid WAF rule expression for rule '{}': {}: {}", rule.name, rule.expression, error);
                continue;
            }

            valid_expressions.push(format!("({})", rule.expression));
        }

        let combined_expr = if valid_expressions.is_empty() {
            eprintln!("Warning: No valid WAF rules found, using default filter that allows all");
            "false".to_string()
        } else {
            valid_expressions.join(" or ")
        };

        // Convert to static by leaking the string
        let leaked = Box::leak(combined_expr.into_boxed_str());
        let ast = self.scheme.parse(leaked)?;
        let new_filter = ast.compile();
        *self.filter.write().unwrap() = new_filter;

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::request::Builder;
    use std::net::Ipv4Addr;

    #[test]
    fn test_post_blocking() -> Result<()> {
        let filter = HttpFilter::new_test_filter()?;

        // Test POST request (should be blocked)
        let post_req = Builder::new()
            .method("POST")
            .uri("http://example.com/test")
            .body(())?;
        let (post_parts, _) = post_req.into_parts();

        let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);
        let should_block = filter.should_block_request_from_parts(&post_parts, b"", peer_addr)?;
        assert!(should_block, "POST request should be blocked");

        // Test GET request (should not be blocked)
        let get_req = Builder::new()
            .method("GET")
            .uri("http://example.com/test")
            .body(())?;
        let (get_parts, _) = get_req.into_parts();

        let should_block = filter.should_block_request_from_parts(&get_parts, b"", peer_addr)?;
        assert!(!should_block, "GET request should not be blocked");

        Ok(())
    }

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
