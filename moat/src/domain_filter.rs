use std::sync::Arc;
use std::collections::HashSet;

/// Domain filter that supports exact matches and wildcard patterns
#[derive(Debug, Clone)]
pub struct DomainFilter {
    /// Exact domain matches (e.g., "example.com", "api.example.com")
    whitelist: Arc<Vec<String>>,
    /// Wildcard patterns (e.g., "*.example.com", "api.*.example.com")
    wildcards: Arc<Vec<WildcardPattern>>,
    /// If true, filtering is enabled
    enabled: bool,
}

#[derive(Debug, Clone)]
struct WildcardPattern {
    _original: String,
    parts: Vec<PatternPart>,
}

#[derive(Debug, Clone, PartialEq)]
enum PatternPart {
    Literal(String),
    Wildcard,
}

impl DomainFilter {
    pub fn new(whitelist: Vec<String>, wildcard_patterns: Vec<String>) -> Self {
        let enabled = !whitelist.is_empty() || !wildcard_patterns.is_empty();
        let wildcards = wildcard_patterns
            .into_iter()
            .map(|pattern| WildcardPattern::parse(&pattern))
            .collect();

        // Normalize whitelist domains
        let normalized_whitelist: Vec<String> = whitelist
            .into_iter()
            .map(|domain| normalize_domain(&domain))
            .collect();

        Self {
            whitelist: Arc::new(normalized_whitelist),
            wildcards: Arc::new(wildcards),
            enabled,
        }
    }

    /// Expand wildcard domains into specific domains
    /// This generates common subdomains for wildcard patterns like *.example.com
    pub fn expand_wildcard_domains(domains: &[String]) -> Vec<String> {
        let mut expanded = HashSet::new();

        for domain in domains {
            let normalized = normalize_domain(domain);

            if normalized.contains('*') {
                // Generate common subdomains for wildcard patterns
                let subdomains = generate_common_subdomains(&normalized);
                for subdomain in subdomains {
                    expanded.insert(subdomain);
                }
            } else {
                // Add exact domain as-is
                expanded.insert(normalized);
            }
        }

        expanded.into_iter().collect()
    }

    /// Check if a domain is allowed
    pub fn is_allowed(&self, domain: &str) -> bool {
        // If no filters configured, allow all
        if !self.enabled {
            return true;
        }

        // Normalize domain (lowercase, remove port if present)
        let normalized = normalize_domain(domain);

        // Check exact whitelist
        if self.whitelist.iter().any(|d| d == &normalized) {
            return true;
        }

        // Check wildcard patterns
        if self
            .wildcards
            .iter()
            .any(|pattern| pattern.matches(&normalized))
        {
            return true;
        }

        false
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl WildcardPattern {
    fn parse(pattern: &str) -> Self {
        let normalized = normalize_domain(pattern);
        let mut parts = Vec::new();
        let mut current = String::new();

        for ch in normalized.chars() {
            if ch == '*' {
                if !current.is_empty() {
                    parts.push(PatternPart::Literal(current.clone()));
                    current.clear();
                }
                parts.push(PatternPart::Wildcard);
            } else {
                current.push(ch);
            }
        }

        if !current.is_empty() {
            parts.push(PatternPart::Literal(current));
        }

        Self {
            _original: pattern.to_string(),
            parts,
        }
    }

    fn matches(&self, domain: &str) -> bool {
        let mut domain_pos = 0;
        let domain_bytes = domain.as_bytes();

        for (i, part) in self.parts.iter().enumerate() {
            match part {
                PatternPart::Literal(literal) => {
                    let literal_bytes = literal.as_bytes();

                    // Check if there's enough space left in domain
                    if domain_pos + literal_bytes.len() > domain_bytes.len() {
                        return false;
                    }

                    // For the first part or parts after wildcards, try to find the literal
                    if i > 0 && matches!(self.parts.get(i - 1), Some(PatternPart::Wildcard)) {
                        // After wildcard: search for the literal substring
                        if let Some(pos) = find_substring(&domain_bytes[domain_pos..], literal_bytes) {
                            domain_pos += pos + literal_bytes.len();
                        } else {
                            return false;
                        }
                    } else {
                        // Exact match at current position
                        if &domain_bytes[domain_pos..domain_pos + literal_bytes.len()] != literal_bytes {
                            return false;
                        }
                        domain_pos += literal_bytes.len();
                    }
                }
                PatternPart::Wildcard => {
                    // Look ahead to see what comes next
                    if i + 1 >= self.parts.len() {
                        // Wildcard at the end matches anything
                        return true;
                    }
                    // Wildcard in the middle is handled by the next literal
                }
            }
        }

        // Check if we consumed the entire domain
        domain_pos == domain_bytes.len()
    }
}

fn normalize_domain(domain: &str) -> String {
    // Remove port if present (e.g., "example.com:443" -> "example.com")
    let without_port = domain.split(':').next().unwrap_or(domain);
    // Convert to lowercase
    without_port.to_lowercase()
}

fn find_substring(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if haystack.len() < needle.len() {
        return None;
    }

    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

/// Generate common subdomains for wildcard patterns
fn generate_common_subdomains(wildcard_pattern: &str) -> Vec<String> {
    let mut domains = Vec::new();

    // Common subdomains to generate
    let common_subdomains = vec![
        "www", "api", "app", "admin", "mail", "ftp", "blog", "shop", "store",
        "support", "help", "docs", "dev", "test", "staging", "prod", "production",
        "cdn", "static", "assets", "img", "images", "js", "css", "media",
        "v1", "v2", "v3", "api-v1", "api-v2", "mobile", "m", "wap",
        "secure", "ssl", "tls", "login", "auth", "oauth", "sso",
        "dashboard", "panel", "console", "control", "manage", "monitor",
        "status", "health", "ping", "metrics", "stats", "analytics",
        "logs", "log", "audit", "backup", "backups", "archive", "archives",
        "download", "downloads", "upload", "uploads", "files", "file",
        "cache", "caching", "proxy", "gateway", "router", "loadbalancer",
        "db", "database", "mysql", "postgres", "redis", "memcached",
        "search", "elastic", "solr", "lucene", "index", "indices",
        "queue", "worker", "job", "jobs", "task", "tasks", "cron",
        "webhook", "webhooks", "callback", "callbacks", "notify",
        "notification", "notifications", "alert", "alerts", "warning",
        "warnings", "error", "errors", "exception", "exceptions",
        "debug", "trace", "profiler", "profile", "profiling",
        "beta", "alpha", "rc", "release", "preview", "demo",
        "sandbox", "playground", "experiment", "experimental",
        "internal", "private", "public", "external", "partner",
        "partners", "vendor", "vendors", "supplier", "suppliers",
        "customer", "customers", "client", "clients", "user", "users",
        "member", "members", "guest", "guests", "visitor", "visitors",
        "subdomain", "subdomains", "wildcard", "wildcards", "catch-all"
    ];

    // Replace * with each common subdomain
    for subdomain in common_subdomains {
        let expanded = wildcard_pattern.replace('*', subdomain);
        domains.push(expanded);
    }

    // Also add the base domain (without subdomain) if it's a *.domain.com pattern
    if wildcard_pattern.starts_with("*.") {
        let base_domain = wildcard_pattern.strip_prefix("*.").unwrap_or(wildcard_pattern);
        domains.push(base_domain.to_string());
    }

    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_whitelist() {
        let filter = DomainFilter::new(
            vec!["example.com".to_string(), "api.example.com".to_string()],
            vec![],
        );

        assert!(filter.is_allowed("example.com"));
        assert!(filter.is_allowed("api.example.com"));
        assert!(!filter.is_allowed("other.com"));
        assert!(!filter.is_allowed("subdomain.example.com"));
    }

    #[test]
    fn test_wildcard_subdomain() {
        let filter = DomainFilter::new(vec![], vec!["*.example.com".to_string()]);

        assert!(filter.is_allowed("api.example.com"));
        assert!(filter.is_allowed("www.example.com"));
        assert!(filter.is_allowed("anything.example.com"));
        assert!(!filter.is_allowed("example.com"));
        assert!(!filter.is_allowed("other.com"));
    }

    #[test]
    fn test_wildcard_middle() {
        let filter = DomainFilter::new(vec![], vec!["api.*.example.com".to_string()]);

        assert!(filter.is_allowed("api.v1.example.com"));
        assert!(filter.is_allowed("api.v2.example.com"));
        assert!(filter.is_allowed("api.prod.example.com"));
        assert!(!filter.is_allowed("api.example.com"));
        assert!(!filter.is_allowed("web.v1.example.com"));
    }

    #[test]
    fn test_combined_whitelist_and_wildcard() {
        let filter = DomainFilter::new(
            vec!["example.com".to_string()],
            vec!["*.example.org".to_string()],
        );

        assert!(filter.is_allowed("example.com"));
        assert!(filter.is_allowed("api.example.org"));
        assert!(filter.is_allowed("www.example.org"));
        assert!(!filter.is_allowed("example.org"));
        assert!(!filter.is_allowed("other.com"));
    }

    #[test]
    fn test_port_normalization() {
        let filter = DomainFilter::new(vec!["example.com".to_string()], vec![]);

        assert!(filter.is_allowed("example.com:443"));
        assert!(filter.is_allowed("example.com:8080"));
        assert!(filter.is_allowed("example.com"));
    }

    #[test]
    fn test_case_insensitive() {
        let filter = DomainFilter::new(vec!["Example.Com".to_string()], vec![]);

        assert!(filter.is_allowed("example.com"));
        assert!(filter.is_allowed("EXAMPLE.COM"));
        assert!(filter.is_allowed("Example.Com"));
    }

    #[test]
    fn test_no_filter_allows_all() {
        let filter = DomainFilter::new(vec![], vec![]);

        assert!(filter.is_allowed("anything.com"));
        assert!(filter.is_allowed("example.org"));
        assert!(!filter.is_enabled());
    }

    #[test]
    fn test_expand_wildcard_domains() {
        let domains = vec![
            "*.example.com".to_string(),
            "api.example.org".to_string(),
            "*.test.net".to_string(),
        ];

        let expanded = DomainFilter::expand_wildcard_domains(&domains);

        // Should contain the exact domain
        assert!(expanded.contains(&"api.example.org".to_string()));

        // Should contain base domains
        assert!(expanded.contains(&"example.com".to_string()));
        assert!(expanded.contains(&"test.net".to_string()));

        // Should contain common subdomains
        assert!(expanded.contains(&"www.example.com".to_string()));
        assert!(expanded.contains(&"api.example.com".to_string()));
        assert!(expanded.contains(&"www.test.net".to_string()));

        // Should not contain duplicates and have reasonable count
        let unique_count = expanded.len();

        // Should have at least the exact domain + base domains + many subdomains
        assert!(unique_count >= 200); // Should have many subdomains from 2 wildcards
        assert!(unique_count <= 500); // But not too many
    }
}


