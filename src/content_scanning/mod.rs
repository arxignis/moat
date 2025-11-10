use anyhow::{Result, anyhow};
use clamav_tcp::scan;
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use std::sync::{Arc, RwLock, OnceLock};
use std::collections::HashMap;
use std::net::SocketAddr;
use hyper::http::request::Parts;
use wirefilter::{ExecutionContext, Scheme, Filter};
use bytes::Bytes;
use multer::Multipart;

/// Content scanning configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContentScanningConfig {
    /// Enable or disable content scanning
    pub enabled: bool,
    /// ClamAV server address (e.g., "localhost:3310")
    pub clamav_server: String,
    /// Maximum file size to scan in bytes (default: 10MB)
    pub max_file_size: usize,
    /// Content types to scan (empty means scan all)
    pub scan_content_types: Vec<String>,
    /// Skip scanning for specific file extensions
    pub skip_extensions: Vec<String>,
    /// Wirefilter expression to determine when to scan
    #[serde(default = "default_scan_expression")]
    pub scan_expression: String,
}

fn default_scan_expression() -> String {
    "http.request.method eq \"POST\" or http.request.method eq \"PUT\"".to_string()
}

impl Default for ContentScanningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            clamav_server: "localhost:3310".to_string(),
            max_file_size: 10 * 1024 * 1024, // 10MB
            scan_content_types: vec![
                "text/html".to_string(),
                "application/x-www-form-urlencoded".to_string(),
                "multipart/form-data".to_string(),
                "application/json".to_string(),
                "text/plain".to_string(),
            ],
            skip_extensions: vec![],
            scan_expression: default_scan_expression(),
        }
    }
}

/// Content scanning result
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Whether malware was detected
    pub malware_detected: bool,
    /// Malware signature name if detected
    pub signature: Option<String>,
    /// Error message if scanning failed
    pub error: Option<String>,
}

/// Content scanner implementation
pub struct ContentScanner {
    config: Arc<RwLock<ContentScanningConfig>>,
    scheme: Arc<Scheme>,
    filter: Arc<RwLock<Option<Filter>>>,
}

/// Extract boundary from Content-Type header for multipart content
pub fn extract_multipart_boundary(content_type: &str) -> Option<String> {
    // Content-Type format: multipart/form-data; boundary=----WebKitFormBoundary...
    if !content_type.to_lowercase().contains("multipart/") {
        return None;
    }

    for part in content_type.split(';') {
        let trimmed = part.trim();
        let lower = trimmed.to_lowercase();
        if lower.starts_with("boundary=") {
            // Find the actual position of "boundary=" in the original string (case-insensitive)
            if let Some(eq_pos) = trimmed.to_lowercase().find("boundary=") {
                let boundary = trimmed[eq_pos + 9..].trim();
                // Remove quotes if present
                let boundary = boundary.trim_matches('"').trim_matches('\'');
                return Some(boundary.to_string());
            }
        }
    }

    None
}

impl ContentScanner {
    /// Create a new content scanner
    pub fn new(config: ContentScanningConfig) -> Self {
        let scheme = Self::create_scheme();
        let filter = Self::compile_filter(&scheme, &config.scan_expression);

        Self {
            config: Arc::new(RwLock::new(config)),
            scheme: Arc::new(scheme),
            filter: Arc::new(RwLock::new(filter)),
        }
    }

    /// Create the wirefilter scheme for content scanning
    fn create_scheme() -> Scheme {
        let builder = wirefilter::Scheme! {
            http.request.method: Bytes,
            http.request.path: Bytes,
            http.request.content_type: Bytes,
            http.request.content_length: Int,
        };
        builder.build()
    }

    /// Compile the scan expression filter
    fn compile_filter(scheme: &Scheme, expression: &str) -> Option<Filter> {
        if expression.is_empty() {
            return None;
        }

        match scheme.parse(expression) {
            Ok(ast) => Some(ast.compile()),
            Err(e) => {
                log::error!("Failed to compile content scanning expression '{}': {}", expression, e);
                None
            }
        }
    }

    /// Update scanner configuration
    pub fn update_config(&self, config: ContentScanningConfig) {
        let new_filter = Self::compile_filter(&self.scheme, &config.scan_expression);

        if let Ok(mut guard) = self.config.write() {
            *guard = config;
        }
        if let Ok(mut guard) = self.filter.write() {
            *guard = new_filter;
        }
    }

    /// Check if content scanning should be performed for this request
    pub fn should_scan(&self, req_parts: &Parts, body_bytes: &[u8], _peer_addr: SocketAddr) -> bool {
        let config = match self.config.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return false,
        };

        if !config.enabled {
            log::debug!("Content scanning disabled");
            return false;
        }

        log::debug!("Checking if should scan request: method={}, path={}, body_size={}",
            req_parts.method, req_parts.uri.path(), body_bytes.len());

        // Check wirefilter expression first
        let filter_guard = match self.filter.read() {
            Ok(guard) => guard,
            Err(_) => return false,
        };

        if let Some(ref filter) = *filter_guard {
            let mut ctx = ExecutionContext::new(&self.scheme);

            // Set request fields
            let method = req_parts.method.as_str();
            let path = req_parts.uri.path();
            let content_type = req_parts.headers
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            let content_length = body_bytes.len() as i64;

            if ctx.set_field_value(self.scheme.get_field("http.request.method").unwrap(), method).is_err() {
                return false;
            }
            if ctx.set_field_value(self.scheme.get_field("http.request.path").unwrap(), path).is_err() {
                return false;
            }
            if ctx.set_field_value(self.scheme.get_field("http.request.content_type").unwrap(), content_type).is_err() {
                return false;
            }
            if ctx.set_field_value(self.scheme.get_field("http.request.content_length").unwrap(), content_length).is_err() {
                return false;
            }

            // Execute filter
            match filter.execute(&ctx) {
                Ok(result) => {
                    if !result {
                        log::debug!("Skipping content scan: expression does not match");
                        return false;
                    } else {
                        log::debug!("Expression matched, proceeding with content scan checks");
                        log::debug!("Expression result: {:?}", result);
                    }
                }
                Err(e) => {
                    log::error!("Failed to execute content scanning expression: {}", e);
                    return false;
                }
            }
        } else {
            log::debug!("No scan expression configured, allowing scan");
        }

        // Check if body is too large
        if body_bytes.len() > config.max_file_size {
            log::debug!("Skipping content scan: body too large ({} bytes)", body_bytes.len());
            return false;
        }

        // Check content type
        if let Some(content_type) = req_parts.headers.get("content-type") {
            if let Ok(content_type_str) = content_type.to_str() {
                let content_type_lower = content_type_str.to_lowercase();

                // If specific content types are configured, only scan those
                if !config.scan_content_types.is_empty() {
                    let should_scan = config.scan_content_types.iter()
                        .any(|ct| content_type_lower.contains(ct));
                    if !should_scan {
                        log::debug!("Skipping content scan: content type '{}' not in scan list: {:?}",
                            content_type_str, config.scan_content_types);
                        return false;
                    } else {
                        log::debug!("Content type '{}' matches scan list", content_type_str);
                    }
                }

                // Skip certain content types
                if content_type_lower.contains("image/") ||
                   content_type_lower.contains("video/") ||
                   content_type_lower.contains("audio/") {
                    log::debug!("Skipping content scan: binary content type {}", content_type_str);
                    return false;
                }
            }
        }

        // Check file extension from URL path
        if let Some(path) = req_parts.uri.path().split('/').last() {
            if let Some(extension) = std::path::Path::new(path).extension() {
                if let Some(ext_str) = extension.to_str() {
                    let ext_lower = format!(".{}", ext_str.to_lowercase());
                    if config.skip_extensions.contains(&ext_lower) {
                        log::debug!("Skipping content scan: file extension {} in skip list", ext_lower);
                        return false;
                    }
                }
            }
        }

        log::debug!("All checks passed, will scan content");
        true
    }

    /// Scan content for malware
    pub async fn scan_content(&self, body_bytes: &[u8]) -> Result<ScanResult> {
        let config = match self.config.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return Err(anyhow!("Failed to read scanner config")),
        };

        if !config.enabled {
            return Ok(ScanResult {
                malware_detected: false,
                signature: None,
                error: None,
            });
        }

        self.scan_bytes(&config.clamav_server, body_bytes).await
    }

    /// Internal method to scan bytes with ClamAV
    async fn scan_bytes(&self, clamav_server: &str, data: &[u8]) -> Result<ScanResult> {
        // Create a cursor over the body bytes for scanning
        let mut cursor = Cursor::new(data);

        // Perform the scan
        match scan(clamav_server, &mut cursor, None) {
            Ok(result) => {
                // Check if malware was detected using the new API
                if !result.is_infected {
                    Ok(ScanResult {
                        malware_detected: false,
                        signature: None,
                        error: None,
                    })
                } else {
                    // Extract signature name from detected_infections
                    let signature = if !result.detected_infections.is_empty() {
                        Some(result.detected_infections.join(", "))
                    } else {
                        None
                    };

                    Ok(ScanResult {
                        malware_detected: true,
                        signature,
                        error: None,
                    })
                }
            }
            Err(e) => {
                log::error!("ClamAV scan failed: {}", e);
                Ok(ScanResult {
                    malware_detected: false,
                    signature: None,
                    error: Some(format!("Scan failed: {}", e)),
                })
            }
        }
    }

    /// Scan multipart content for malware by parsing parts and scanning each individually
    pub async fn scan_multipart_content(&self, body_bytes: &[u8], boundary: &str) -> Result<ScanResult> {
        let config = match self.config.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return Err(anyhow!("Failed to read scanner config")),
        };

        if !config.enabled {
            return Ok(ScanResult {
                malware_detected: false,
                signature: None,
                error: None,
            });
        }

        log::debug!("Parsing multipart body with boundary: {}", boundary);

        // Create a multipart parser
        let stream = futures::stream::once(async move {
            Result::<Bytes, std::io::Error>::Ok(Bytes::copy_from_slice(body_bytes))
        });

        let mut multipart = Multipart::new(stream, boundary);

        let mut parts_scanned = 0;
        let mut parts_failed = 0;

        // Iterate over each part in the multipart body
        while let Some(field) = multipart.next_field().await.map_err(|e| anyhow!("Failed to read multipart field: {}", e))? {
            let field_name = field.name().unwrap_or("<unnamed>").to_string();
            let field_filename = field.file_name().map(|s| s.to_string());
            let field_content_type = field.content_type().map(|m| m.to_string());

            log::debug!("Scanning multipart field: name={}, filename={:?}, content_type={:?}",
                field_name, field_filename, field_content_type);

            // Read the entire field into bytes
            let field_bytes = field.bytes().await.map_err(|e| anyhow!("Failed to read field bytes: {}", e))?;

            // Skip empty fields
            if field_bytes.is_empty() {
                log::debug!("Skipping empty multipart field: {}", field_name);
                continue;
            }

            // Check if field size exceeds max_file_size
            if field_bytes.len() > config.max_file_size {
                log::debug!("Skipping multipart field '{}': size {} exceeds max_file_size {}",
                    field_name, field_bytes.len(), config.max_file_size);
                continue;
            }

            parts_scanned += 1;

            // Scan this part
            match self.scan_bytes(&config.clamav_server, &field_bytes).await {
                Ok(result) => {
                    if result.malware_detected {
                        log::info!("Malware detected in multipart field '{}' (filename: {:?}): signature {:?}",
                            field_name, field_filename, result.signature);

                        // Return immediately on first malware detection
                        return Ok(ScanResult {
                            malware_detected: true,
                            signature: result.signature.map(|s| format!("{}:{}", field_name, s)),
                            error: None,
                        });
                    }
                }
                Err(e) => {
                    log::warn!("Failed to scan multipart field '{}': {}", field_name, e);
                    parts_failed += 1;
                }
            }
        }

        log::debug!("Multipart scan complete: {} parts scanned, {} failed", parts_scanned, parts_failed);

        // If all parts failed to scan, return an error
        if parts_scanned > 0 && parts_failed == parts_scanned {
            return Ok(ScanResult {
                malware_detected: false,
                signature: None,
                error: Some(format!("All {} multipart parts failed to scan", parts_failed)),
            });
        }

        // No malware detected
        Ok(ScanResult {
            malware_detected: false,
            signature: None,
            error: None,
        })
    }

    /// Scan HTML form data for malware
    pub async fn scan_form_data(&self, form_data: &HashMap<String, String>) -> Result<ScanResult> {
        let config = match self.config.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return Err(anyhow!("Failed to read scanner config")),
        };

        if !config.enabled {
            return Ok(ScanResult {
                malware_detected: false,
                signature: None,
                error: None,
            });
        }

        // Combine all form values into a single string for scanning
        let combined_data = form_data.values()
            .map(|v| v.as_str())
            .collect::<Vec<&str>>()
            .join("\n");

        let mut cursor = Cursor::new(combined_data.as_bytes());

        // Perform the scan
        match scan(&config.clamav_server, &mut cursor, None) {
            Ok(result) => {
                // Check if malware was detected using the new API
                if !result.is_infected {
                    Ok(ScanResult {
                        malware_detected: false,
                        signature: None,
                        error: None,
                    })
                } else {
                    // Extract signature name from detected_infections
                    let signature = if !result.detected_infections.is_empty() {
                        Some(result.detected_infections.join(", "))
                    } else {
                        None
                    };

                    Ok(ScanResult {
                        malware_detected: true,
                        signature,
                        error: None,
                    })
                }
            }
            Err(e) => {
                log::error!("ClamAV form data scan failed: {}", e);
                Ok(ScanResult {
                    malware_detected: false,
                    signature: None,
                    error: Some(format!("Form data scan failed: {}", e)),
                })
            }
        }
    }
}

// Global content scanner instance
static CONTENT_SCANNER: OnceLock<ContentScanner> = OnceLock::new();

/// Get the global content scanner instance
pub fn get_global_content_scanner() -> Option<&'static ContentScanner> {
    CONTENT_SCANNER.get()
}

/// Set the global content scanner instance
pub fn set_global_content_scanner(scanner: ContentScanner) -> Result<()> {
    CONTENT_SCANNER
        .set(scanner)
        .map_err(|_| anyhow!("Failed to initialize content scanner"))
}

/// Initialize the global content scanner with default configuration
pub fn init_content_scanner(config: ContentScanningConfig) -> Result<()> {
    let scanner = ContentScanner::new(config);
    set_global_content_scanner(scanner)?;
    log::info!("Content scanner initialized");
    Ok(())
}

/// Update the global content scanner configuration
pub fn update_content_scanner_config(config: ContentScanningConfig) -> Result<()> {
    if let Some(scanner) = get_global_content_scanner() {
        scanner.update_config(config);
        log::info!("Content scanner configuration updated");
        Ok(())
    } else {
        Err(anyhow!("Content scanner not initialized"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::http::request::Builder;

    #[test]
    fn test_content_scanner_config_default() {
        let config = ContentScanningConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.clamav_server, "localhost:3310");
        assert_eq!(config.max_file_size, 10 * 1024 * 1024);
        assert!(!config.scan_content_types.is_empty());
        assert!(config.skip_extensions.is_empty());
    }

    #[test]
    fn test_should_scan_disabled() {
        use std::net::{Ipv4Addr, SocketAddr};

        let config = ContentScanningConfig {
            enabled: false,
            ..Default::default()
        };
        let scanner = ContentScanner::new(config);

        let req = Builder::new()
            .method("POST")
            .uri("http://example.com/test")
            .body(())
            .unwrap();
        let (req_parts, _) = req.into_parts();
        let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);

        assert!(!scanner.should_scan(&req_parts, b"test content", peer_addr));
    }

    #[test]
    fn test_should_scan_content_type_filter() {
        use std::net::{Ipv4Addr, SocketAddr};

        let config = ContentScanningConfig {
            enabled: true,
            scan_content_types: vec!["text/html".to_string()],
            ..Default::default()
        };
        let scanner = ContentScanner::new(config);

        let req = Builder::new()
            .method("POST")
            .uri("http://example.com/test")
            .header("content-type", "text/html")
            .body(())
            .unwrap();
        let (req_parts, _) = req.into_parts();
        let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);

        assert!(scanner.should_scan(&req_parts, b"<html>test</html>", peer_addr));

        let req2 = Builder::new()
            .method("POST")
            .uri("http://example.com/test")
            .header("content-type", "application/json")
            .body(())
            .unwrap();
        let (req_parts2, _) = req2.into_parts();

        assert!(!scanner.should_scan(&req_parts2, b"{\"test\": \"data\"}", peer_addr));
    }

    #[test]
    fn test_should_scan_file_size_limit() {
        use std::net::{Ipv4Addr, SocketAddr};

        let config = ContentScanningConfig {
            enabled: true,
            max_file_size: 100,
            ..Default::default()
        };
        let scanner = ContentScanner::new(config);

        let req = Builder::new()
            .method("POST")
            .uri("http://example.com/test")
            .body(())
            .unwrap();
        let (req_parts, _) = req.into_parts();
        let peer_addr = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080);

        let small_content = b"small";
        let large_content = b"x".repeat(200);

        assert!(scanner.should_scan(&req_parts, small_content, peer_addr));
        assert!(!scanner.should_scan(&req_parts, &large_content, peer_addr));
    }

    #[test]
    fn test_extract_multipart_boundary() {
        // Test with standard format
        let ct1 = "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW";
        assert_eq!(
            extract_multipart_boundary(ct1),
            Some("----WebKitFormBoundary7MA4YWxkTrZu0gW".to_string())
        );

        // Test with quoted boundary
        let ct2 = "multipart/form-data; boundary=\"----WebKitFormBoundary7MA4YWxkTrZu0gW\"";
        assert_eq!(
            extract_multipart_boundary(ct2),
            Some("----WebKitFormBoundary7MA4YWxkTrZu0gW".to_string())
        );

        // Test with spaces
        let ct3 = "multipart/form-data;   boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW  ";
        assert_eq!(
            extract_multipart_boundary(ct3),
            Some("----WebKitFormBoundary7MA4YWxkTrZu0gW".to_string())
        );

        // Test with charset and boundary
        let ct4 = "multipart/form-data; charset=utf-8; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW";
        assert_eq!(
            extract_multipart_boundary(ct4),
            Some("----WebKitFormBoundary7MA4YWxkTrZu0gW".to_string())
        );

        // Test non-multipart content type
        let ct5 = "application/json";
        assert_eq!(extract_multipart_boundary(ct5), None);

        // Test missing boundary
        let ct6 = "multipart/form-data";
        assert_eq!(extract_multipart_boundary(ct6), None);

        // Test mixed case
        let ct7 = "Multipart/Form-Data; Boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW";
        assert_eq!(
            extract_multipart_boundary(ct7),
            Some("----WebKitFormBoundary7MA4YWxkTrZu0gW".to_string())
        );
    }
}
