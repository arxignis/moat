//! Embedded ACME server that integrates with the main synapse application
//! Reads domains from upstreams.yaml and manages certificates

use crate::acme::domain_reader::{DomainConfig, DomainReader};
use crate::acme::{request_cert, should_renew_certs_check, StorageFactory};
use crate::acme::upstreams_reader::UpstreamsDomainReader;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use actix_web::{App, HttpServer, HttpResponse, web, Responder};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EmbeddedAcmeConfig {
    /// Port for ACME server (e.g., 9180)
    pub port: u16,
    /// IP address to bind (default: 127.0.0.1)
    #[serde(default = "default_bind_ip")]
    pub bind_ip: String,
    /// Path to upstreams.yaml file
    pub upstreams_path: PathBuf,
    /// Email for ACME account
    pub email: String,
    /// Storage path for certificates
    pub storage_path: PathBuf,
    /// Storage type: "file" or "redis" (optional, defaults based on redis_url)
    pub storage_type: Option<String>,
    /// Use development/staging ACME server
    #[serde(default)]
    pub development: bool,
    /// Redis URL for storage (optional)
    pub redis_url: Option<String>,
    /// Redis SSL config (optional)
    pub redis_ssl: Option<crate::acme::config::RedisSslConfig>,
}

pub struct EmbeddedAcmeServer {
    config: EmbeddedAcmeConfig,
    domain_reader: Arc<RwLock<Option<Arc<dyn DomainReader + Send + Sync>>>>,
}

impl EmbeddedAcmeServer {
    pub fn new(config: EmbeddedAcmeConfig) -> Self {
        Self {
            config,
            domain_reader: Arc::new(RwLock::new(None)),
        }
    }

    /// Initialize the domain reader from upstreams
    pub async fn init_domain_reader(&self) -> Result<()> {
        let reader: Arc<dyn DomainReader + Send + Sync> = Arc::new(
            UpstreamsDomainReader::new(
                self.config.upstreams_path.clone(),
                Some(self.config.email.clone()),
            )
        );

        let mut domain_reader = self.domain_reader.write().await;
        *domain_reader = Some(reader);

        Ok(())
    }

    /// Start the embedded ACME HTTP server
    pub async fn start_server(&self) -> Result<()> {
        let address = format!("{}:{}", self.config.bind_ip, self.config.port);
        info!("Starting embedded ACME server at {}", address);

        // Ensure challenge directory exists
        let mut challenge_path = self.config.storage_path.clone();
        challenge_path.push("well-known");
        challenge_path.push("acme-challenge");
        tokio::fs::create_dir_all(&challenge_path).await
            .with_context(|| format!("Failed to create challenge directory: {:?}", challenge_path))?;

        let challenge_path_clone = challenge_path.clone();
        let domain_reader_clone = Arc::clone(&self.domain_reader);
        let config_clone = self.config.clone();

        let server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(config_clone.clone()))
                .app_data(web::Data::new(domain_reader_clone.clone()))
                .service(
                    // Serve ACME challenges
                    actix_files::Files::new("/.well-known/acme-challenge", challenge_path_clone.clone())
                        .prefer_utf8(true),
                )
                .route(
                    "/cert/expiration",
                    web::get().to(check_all_certs_expiration_handler),
                )
                .route(
                    "/cert/expiration/{domain}",
                    web::get().to(check_cert_expiration_handler),
                )
                .route(
                    "/cert/renew/{domain}",
                    web::post().to(renew_cert_handler),
                )
                .default_service(web::route().to(|| async {
                    HttpResponse::NotFound().body("Not Found")
                }))
        })
        .bind(&address)
        .with_context(|| format!("Failed to bind ACME server to {}", address))?;

        info!("Embedded ACME server started at {}", address);
        server.run().await
            .with_context(|| "ACME server error")?;

        Ok(())
    }

    /// Process certificates for all domains
    pub async fn process_certificates(&self) -> Result<()> {
        let domain_reader = self.domain_reader.read().await;
        let reader = domain_reader.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Domain reader not initialized"))?;

        let domains = reader.read_domains().await
            .context("Failed to read domains")?;

        info!("Processing {} domain(s) for certificate management", domains.len());

        for domain_config in domains {
            let domain_cfg = self.create_domain_config(&domain_config)?;

            // Check if certificate needs renewal
            if should_renew_certs_check(&domain_cfg).await? {
                info!("Requesting new certificate for {}...", domain_config.domain);
                if let Err(e) = request_cert(&domain_cfg).await {
                    warn!("Failed to request certificate for {}: {}", domain_config.domain, e);
                } else {
                    info!("Certificate obtained successfully for {}!", domain_config.domain);
                }
            } else {
                info!("Certificate is still valid for {}", domain_config.domain);
            }
        }

        Ok(())
    }

    fn create_domain_config(&self, domain: &DomainConfig) -> Result<crate::acme::Config> {
        let mut domain_https_path = self.config.storage_path.clone();
        domain_https_path.push(&domain.domain);

        let mut cert_path = domain_https_path.clone();
        cert_path.push("cert.pem");
        let mut key_path = domain_https_path.clone();
        key_path.push("key.pem");
        let static_path = domain_https_path.clone();

        // Format domain for ACME order
        // If wildcard is true, ensure domain has *. prefix for ACME order
        let acme_domain = if domain.wildcard && !domain.domain.starts_with("*.") {
            // Extract base domain (domain + TLD, e.g., arxignis.dev from david-proxytest2.arxignis.dev)
            // Split by '.' and take the last two parts
            let parts: Vec<&str> = domain.domain.split('.').collect();
            if parts.len() >= 2 {
                let base = parts[parts.len() - 2..].join(".");
                format!("*.{}", base)
            } else {
                // Fallback: just add *. prefix
                format!("*.{}", domain.domain)
            }
        } else {
            domain.domain.clone()
        };

        Ok(crate::acme::Config {
            https_path: domain_https_path,
            cert_path,
            key_path,
            static_path,
            opts: crate::acme::ConfigOpts {
                ip: self.config.bind_ip.clone(),
                port: self.config.port,
                domain: acme_domain,
                email: Some(domain.email.clone().unwrap_or_else(|| self.config.email.clone())),
                https_dns: domain.dns,
                development: self.config.development,
                dns_lookup_max_attempts: Some(100),
                dns_lookup_delay_seconds: Some(10),
            storage_type: {
                // Always use Redis (storage_type option is kept for compatibility but always uses Redis)
                let storage_type = Some("redis".to_string());
                tracing::info!("Domain {}: Using storage type: 'redis'", domain.domain);
                storage_type
            },
                redis_url: self.config.redis_url.clone(),
                lock_ttl_seconds: Some(900),
                redis_ssl: self.config.redis_ssl.clone(),
                challenge_max_ttl_seconds: Some(3600),
            },
        })
    }
}

/// HTTP handler for checking expiration of all domains
async fn check_all_certs_expiration_handler(
    config: web::Data<EmbeddedAcmeConfig>,
    domain_reader: web::Data<Arc<RwLock<Option<Arc<dyn DomainReader + Send + Sync>>>>>,
) -> impl Responder {
    let reader = domain_reader.read().await;
    let reader_ref = match reader.as_ref() {
        Some(r) => r,
        None => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Domain reader not initialized"
            }));
        }
    };

    let domains = match reader_ref.read_domains().await {
        Ok(d) => d,
        Err(e) => {
            warn!("Error reading domains: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to read domains: {}", e)
            }));
        }
    };

    let mut results = Vec::new();
    for domain_config in domains {
        let domain_cfg = match create_domain_config_for_handler(&config, &domain_config) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("Error creating domain config for {}: {}", domain_config.domain, e);
                continue;
            }
        };

        let storage = match StorageFactory::create_default(&domain_cfg) {
            Ok(s) => s,
            Err(e) => {
                warn!("Error creating storage for {}: {}", domain_config.domain, e);
                continue;
            }
        };

        let exists = storage.cert_exists().await;
        results.push(serde_json::json!({
            "domain": domain_config.domain,
            "exists": exists,
        }));
    }

    HttpResponse::Ok().json(results)
}

/// HTTP handler for checking expiration of a specific domain
async fn check_cert_expiration_handler(
    config: web::Data<EmbeddedAcmeConfig>,
    domain_reader: web::Data<Arc<RwLock<Option<Arc<dyn DomainReader + Send + Sync>>>>>,
    path: web::Path<String>,
) -> impl Responder {
    let domain = path.into_inner();

    let reader = domain_reader.read().await;
    let reader_ref = match reader.as_ref() {
        Some(r) => r,
        None => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Domain reader not initialized"
            }));
        }
    };

    let domains = match reader_ref.read_domains().await {
        Ok(d) => d,
        Err(e) => {
            warn!("Error reading domains: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to read domains: {}", e)
            }));
        }
    };

    let domain_config = match domains.iter().find(|d| d.domain == domain) {
        Some(d) => d.clone(),
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("Domain {} not found", domain)
            }));
        }
    };

    let domain_cfg = match create_domain_config_for_handler(&config, &domain_config) {
        Ok(cfg) => cfg,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create domain config: {}", e)
            }));
        }
    };

    let storage = match StorageFactory::create_default(&domain_cfg) {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create storage: {}", e)
            }));
        }
    };

    let exists = storage.cert_exists().await;
    HttpResponse::Ok().json(serde_json::json!({
        "domain": domain,
        "exists": exists,
    }))
}

/// HTTP handler for renewing a certificate
async fn renew_cert_handler(
    config: web::Data<EmbeddedAcmeConfig>,
    domain_reader: web::Data<Arc<RwLock<Option<Arc<dyn DomainReader + Send + Sync>>>>>,
    path: web::Path<String>,
) -> impl Responder {
    let domain = path.into_inner();

    let reader = domain_reader.read().await;
    let reader_ref = match reader.as_ref() {
        Some(r) => r,
        None => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Domain reader not initialized"
            }));
        }
    };

    let domains = match reader_ref.read_domains().await {
        Ok(d) => d,
        Err(e) => {
            warn!("Error reading domains: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to read domains: {}", e)
            }));
        }
    };

    let domain_config = match domains.iter().find(|d| d.domain == domain) {
        Some(d) => d.clone(),
        None => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": format!("Domain {} not found", domain)
            }));
        }
    };

    let domain_cfg = match create_domain_config_for_handler(&config, &domain_config) {
        Ok(cfg) => cfg,
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create domain config: {}", e)
            }));
        }
    };

    // Spawn renewal in background
    let domain_config_clone = domain_config.clone();
    tokio::spawn(async move {
        if let Err(e) = request_cert(&domain_cfg).await {
            warn!("Error renewing certificate for {}: {}", domain_config_clone.domain, e);
        } else {
            info!("Certificate renewed successfully for {}!", domain_config_clone.domain);
        }
    });

    HttpResponse::Ok().json(serde_json::json!({
        "message": format!("Certificate renewal started for {}", domain),
    }))
}

fn create_domain_config_for_handler(
    config: &EmbeddedAcmeConfig,
    domain: &DomainConfig,
) -> Result<crate::acme::Config> {
    let mut domain_https_path = config.storage_path.clone();
    domain_https_path.push(&domain.domain);

    let mut cert_path = domain_https_path.clone();
    cert_path.push("cert.pem");
    let mut key_path = domain_https_path.clone();
    key_path.push("key.pem");
    let static_path = domain_https_path.clone();

    Ok(crate::acme::Config {
        https_path: domain_https_path,
        cert_path,
        key_path,
        static_path,
        opts: crate::acme::ConfigOpts {
            ip: config.bind_ip.clone(),
            port: config.port,
            domain: domain.domain.clone(),
            email: Some(domain.email.clone().unwrap_or_else(|| config.email.clone())),
            https_dns: domain.dns,
            development: config.development,
            dns_lookup_max_attempts: Some(100),
            dns_lookup_delay_seconds: Some(10),
            storage_type: {
                // Always use Redis (storage_type option is kept for compatibility but always uses Redis)
                Some("redis".to_string())
            },
            redis_url: config.redis_url.clone(),
            lock_ttl_seconds: Some(900),
            redis_ssl: config.redis_ssl.clone(),
            challenge_max_ttl_seconds: Some(3600),
        },
    })
}

