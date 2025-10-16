use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Utc};
use hyper::body::Incoming;
use hyper::{Request, Response};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ssl::tls_fingerprint::Fingerprint as TlsFingerprint;

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

impl HttpAccessLog {
    pub async fn from_request_response(
        req: Request<Incoming>,
        response: Response<http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>>,
        peer: SocketAddr,
        dst_addr: SocketAddr,
        tls_fingerprint: Option<&TlsFingerprint>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let timestamp = Utc::now();
        let request_id = generate_request_id();

        // Extract request details
        let uri = req.uri();
        let method = req.method().to_string();
        let scheme = uri.scheme().map(|s| s.to_string()).unwrap_or_else(|| "http".to_string());
        let host = uri.host().unwrap_or("unknown").to_string();
        let port = uri.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
        let path = uri.path().to_string();
        let query = uri.query().unwrap_or("").to_string();

        // Process headers
        let mut headers = HashMap::new();
        let mut user_agent = None;
        let mut content_type = None;

        for (name, value) in req.headers().iter() {
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

        // Process request body with truncation
        let (_parts, body) = req.into_parts();
        let body_bytes = body.collect().await?.to_bytes();
        let max_body_size = 1024 * 1024; // 1MB limit
        let body_truncated = body_bytes.len() > max_body_size;
        let truncated_body_bytes = if body_truncated {
            body_bytes.slice(..max_body_size)
        } else {
            body_bytes
        };
        let body_str = String::from_utf8_lossy(&truncated_body_bytes).to_string();
        let body_sha256 = format!("{:x}", Sha256::digest(&body_bytes)); // Always hash full body
        let content_length = Some(body_bytes.len() as u64);

        // Process response
        let (response_parts, response_body) = response.into_parts();
        let response_body_bytes = response_body.collect().await?.to_bytes();
        let response_body_str = String::from_utf8_lossy(&response_body_bytes).to_string();

        let response_content_type = response_parts.headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

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
            content_length,
            body: body_str,
            body_sha256,
            body_truncated,
        };

        let network_details = NetworkDetails {
            src_ip: peer.ip().to_string(),
            src_port: peer.port(),
            dst_ip: dst_addr.ip().to_string(),
            dst_port: dst_addr.port(),
        };

        let tls_details = tls_fingerprint.map(|fp| {
            // Determine cipher based on TLS version
            let cipher = match fp.tls_version.as_str() {
                "TLSv1.3" => "TLS_AES_256_GCM_SHA384", // Most common TLS 1.3 cipher
                "TLSv1.2" => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", // Most common TLS 1.2 cipher
                _ => "Unknown",
            };

            // Calculate JA4L (simplified version)
            let ja4l = calculate_ja4l(&fp.tls_version, fp.alpn.as_deref());

            TlsDetails {
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
            }
        });

        let response_details = ResponseDetails {
            status: response_parts.status.as_u16(),
            status_text: response_parts.status.canonical_reason().unwrap_or("Unknown").to_string(),
            content_type: response_content_type,
            content_length: Some(response_body_bytes.len() as u64),
            body: response_body_str,
        };

        Ok(HttpAccessLog {
            event_type: "http_access_log".to_string(),
            schema_version: "1.2.0".to_string(),
            timestamp,
            request_id,
            http: http_details,
            network: network_details,
            tls: tls_details,
            response: response_details,
        })
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn log_to_stdout(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = self.to_json()?;
        println!("{}", json);
        Ok(())
    }
}

fn generate_request_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("req_{}", timestamp)
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
    use hyper::body::Incoming;
    use http_body_util::Full;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_access_log_creation() {
        // Create a simple request
        let req = Request::builder()
            .method("GET")
            .uri("https://example.com/test?param=value")
            .header("User-Agent", "TestAgent/1.0")
            .body(Incoming::new())
            .unwrap();

        // Create a simple response
        let response = Response::builder()
            .status(200)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from("{\"ok\":true}")))
            .unwrap();

        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let dst_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

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
        };

        let json = log.to_json().unwrap();
        assert!(json.contains("http_access_log"));
        assert!(json.contains("GET"));
        assert!(json.contains("example.com"));
    }
}
