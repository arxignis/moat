use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use anyhow::{anyhow, Result};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use hyper::body::Bytes;
use ipnet::IpNet;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::cli::HealthCheckConfig;

/// Health check server that runs on a separate port with CIDR filtering
#[derive(Debug)]
pub struct HealthCheckServer {
    config: HealthCheckConfig,
    allowed_cidrs: Vec<IpNet>,
}

impl HealthCheckServer {
    pub fn new(config: HealthCheckConfig) -> Result<Self> {
        let allowed_cidrs = if config.allowed_cidrs.is_empty() {
            // If no CIDRs specified, allow all (0.0.0.0/0 and ::/0)
            vec![
                IpNet::from_str("0.0.0.0/0")?,
                IpNet::from_str("::/0")?,
            ]
        } else {
            config.allowed_cidrs
                .iter()
                .map(|cidr| IpNet::from_str(cidr))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("Invalid CIDR in health check config: {}", e))?
        };

        Ok(Self {
            config,
            allowed_cidrs,
        })
    }

    /// Check if the client IP is allowed based on CIDR restrictions
    fn is_ip_allowed(&self, client_ip: IpAddr) -> bool {
        self.allowed_cidrs.iter().any(|cidr| cidr.contains(&client_ip))
    }

    /// Handle health check requests (for testing with Full<Bytes> body)
    #[cfg(test)]
    async fn handle_request_test(
        &self,
        req: Request<Full<Bytes>>,
        client_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>> {
        // Check if client IP is allowed
        if !self.is_ip_allowed(client_addr.ip()) {
            log::warn!("Health check request from disallowed IP: {}", client_addr.ip());
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from("Forbidden")))
                .unwrap());
        }

        // Check if the path matches the configured endpoint
        if req.uri().path() != self.config.endpoint {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not Found")))
                .unwrap());
        }

        // Check if the method is allowed
        let method_allowed = self.config.methods
            .iter()
            .any(|m| m.as_str() == req.method().as_str());

        if !method_allowed {
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::from("Method Not Allowed")))
                .unwrap());
        }

        // For HEAD requests, return empty body
        if req.method() == Method::HEAD {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }

        // Return health status
        let health_status = serde_json::json!({
            "status": "healthy",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "service": "moat"
        });

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(serde_json::to_string(&health_status)?)))
            .unwrap())
    }

    /// Handle health check requests
    async fn handle_request(
        &self,
        req: Request<Incoming>,
        client_addr: SocketAddr,
    ) -> Result<Response<Full<Bytes>>> {
        // Check if client IP is allowed
        if !self.is_ip_allowed(client_addr.ip()) {
            log::warn!("Health check request from disallowed IP: {}", client_addr.ip());
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::from("Forbidden")))
                .unwrap());
        }

        // Check if the path matches the configured endpoint
        if req.uri().path() != self.config.endpoint {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not Found")))
                .unwrap());
        }

        // Check if the method is allowed
        let method_allowed = self.config.methods
            .iter()
            .any(|m| m.as_str() == req.method().as_str());

        if !method_allowed {
            return Ok(Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Full::new(Bytes::from("Method Not Allowed")))
                .unwrap());
        }

        // For HEAD requests, return empty body
        if req.method() == Method::HEAD {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::new()))
                .unwrap());
        }

        // Return health status
        let health_status = serde_json::json!({
            "status": "healthy",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "service": "moat"
        });

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(serde_json::to_string(&health_status)?)))
            .unwrap())
    }

    /// Start the health check server
    pub async fn start(&self, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
        let addr = self.config.port.parse::<SocketAddr>()
            .map_err(|e| anyhow!("Invalid health check port '{}': {}", self.config.port, e))?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| anyhow!("Failed to bind health check server to {}: {}", addr, e))?;

        log::info!("Health check server listening on http://{}", addr);
        log::info!("Health check endpoint: {}", self.config.endpoint);
        log::info!("Allowed methods: {:?}", self.config.methods);
        log::info!("Allowed CIDRs: {:?}", self.config.allowed_cidrs);

        let server = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, client_addr)) => {
                                let server = server.clone();
                                tokio::spawn(async move {
                                    let io = TokioIo::new(stream);
                                    let service = service_fn(move |req| {
                                        let server = server.clone();
                                        let client_addr = client_addr;
                                        async move {
                                            server.handle_request(req, client_addr).await
                                        }
                                    });

                                    if let Err(err) = http1::Builder::new()
                                        .serve_connection(io, service)
                                        .await
                                    {
                                        log::error!("Health check connection error: {}", err);
                                    }
                                });
                            }
                            Err(err) => {
                                log::error!("Health check accept error: {}", err);
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            log::info!("Health check server shutting down");
                            break;
                        }
                    }
                }
            }
        });

        Ok(())
    }
}

impl Clone for HealthCheckServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            allowed_cidrs: self.allowed_cidrs.clone(),
        }
    }
}

/// Start the health check server if enabled
pub async fn start_health_check_server(
    config: HealthCheckConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    if !config.enabled {
        log::info!("Health check server disabled");
        return Ok(());
    }

    let server = HealthCheckServer::new(config)?;
    server.start(shutdown_rx).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use tokio::sync::watch;
    use http_body_util::BodyExt;

    fn create_test_config() -> HealthCheckConfig {
        HealthCheckConfig {
            enabled: true,
            endpoint: "/health".to_string(),
            port: "127.0.0.1:0".to_string(), // Use port 0 for dynamic port allocation in tests
            methods: vec!["GET".to_string(), "HEAD".to_string()],
            allowed_cidrs: vec![],
        }
    }

    fn create_restricted_config() -> HealthCheckConfig {
        HealthCheckConfig {
            enabled: true,
            endpoint: "/health".to_string(),
            port: "127.0.0.1:0".to_string(),
            methods: vec!["GET".to_string()],
            allowed_cidrs: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
        }
    }

    #[test]
    fn test_health_check_server_new() {
        let config = create_test_config();
        let server = HealthCheckServer::new(config).unwrap();
        assert_eq!(server.config.endpoint, "/health");
        assert_eq!(server.config.methods, vec!["GET", "HEAD"]);
    }

    #[test]
    fn test_health_check_server_new_with_cidrs() {
        let config = create_restricted_config();
        let server = HealthCheckServer::new(config).unwrap();
        assert_eq!(server.allowed_cidrs.len(), 2);
    }

    #[test]
    fn test_health_check_server_new_invalid_cidr() {
        let mut config = create_test_config();
        config.allowed_cidrs = vec!["invalid-cidr".to_string()];

        let result = HealthCheckServer::new(config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid CIDR"));
    }

    #[test]
    fn test_is_ip_allowed_all_ips() {
        let config = create_test_config();
        let server = HealthCheckServer::new(config).unwrap();

        // Should allow all IPs when no CIDRs specified
        assert!(server.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(server.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(server.is_ip_allowed(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_is_ip_allowed_restricted() {
        let config = create_restricted_config();
        let server = HealthCheckServer::new(config).unwrap();

        // Should allow localhost IPs
        assert!(server.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(server.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 255))));
        assert!(server.is_ip_allowed(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))));

        // Should deny other IPs
        assert!(!server.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!server.is_ip_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[tokio::test]
    async fn test_handle_request_allowed_ip() {
        let config = create_test_config();
        let server = HealthCheckServer::new(config).unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/health")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let response = server.handle_request_test(req, client_addr).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("Content-Type").unwrap(), "application/json");
    }

    #[tokio::test]
    async fn test_handle_request_disallowed_ip() {
        let config = create_restricted_config();
        let server = HealthCheckServer::new(config).unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/health")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let response = server.handle_request_test(req, client_addr).await.unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_handle_request_wrong_endpoint() {
        let config = create_test_config();
        let server = HealthCheckServer::new(config).unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/wrong-endpoint")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let response = server.handle_request_test(req, client_addr).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_handle_request_wrong_method() {
        let config = create_test_config();
        let server = HealthCheckServer::new(config).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/health")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let response = server.handle_request_test(req, client_addr).await.unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn test_handle_request_head_method() {
        let config = create_test_config();
        let server = HealthCheckServer::new(config).unwrap();

        let req = Request::builder()
            .method("HEAD")
            .uri("/health")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let response = server.handle_request_test(req, client_addr).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        // HEAD requests should have empty body
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body_bytes.len(), 0);
    }

    #[tokio::test]
    async fn test_handle_request_get_method_response() {
        let config = create_test_config();
        let server = HealthCheckServer::new(config).unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/health")
            .body(Full::new(Bytes::new()))
            .unwrap();

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let response = server.handle_request_test(req, client_addr).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("Content-Type").unwrap(), "application/json");

        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        let health_status: serde_json::Value = serde_json::from_str(&body_str).unwrap();

        assert_eq!(health_status["status"], "healthy");
        assert_eq!(health_status["service"], "moat");
        assert!(health_status["timestamp"].is_string());
    }

    #[tokio::test]
    async fn test_start_health_check_server_disabled() {
        let mut config = create_test_config();
        config.enabled = false;

        let (_tx, rx) = watch::channel(false);
        let result = start_health_check_server(config, rx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_health_check_server_invalid_port() {
        let mut config = create_test_config();
        config.port = "invalid-port".to_string();

        let (_tx, rx) = watch::channel(false);
        let result = start_health_check_server(config, rx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid health check port"));
    }

    #[test]
    fn test_cidr_parsing() {
        let cidrs = vec![
            "192.168.1.0/24".to_string(),
            "10.0.0.0/8".to_string(),
            "::1/128".to_string(),
        ];

        let parsed: Result<Vec<IpNet>, _> = cidrs
            .iter()
            .map(|cidr| IpNet::from_str(cidr))
            .collect();

        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.len(), 3);
    }

    #[test]
    fn test_default_config_values() {
        let config = HealthCheckConfig {
            enabled: true,
            endpoint: "/health".to_string(),
            port: "0.0.0.0:8080".to_string(),
            methods: vec!["GET".to_string(), "HEAD".to_string()],
            allowed_cidrs: vec![],
        };

        assert!(config.enabled);
        assert_eq!(config.endpoint, "/health");
        assert_eq!(config.port, "0.0.0.0:8080");
        assert_eq!(config.methods, vec!["GET", "HEAD"]);
        assert!(config.allowed_cidrs.is_empty());
    }
}
