use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::{interval, Duration};

use crate::redis::RedisManager;
use crate::utils::tls::{CertificateConfig, Certificates};
use crate::worker::Worker;

/// Normalize PEM certificate chain to ensure proper format
/// - Ensures newline between certificates (END CERTIFICATE and BEGIN CERTIFICATE)
/// - Ensures file ends with newline
fn normalize_pem_chain(chain: &str) -> String {
    let mut normalized = chain.to_string();

    // Ensure newline between END CERTIFICATE and BEGIN CERTIFICATE
    // Replace "-----END CERTIFICATE----------BEGIN CERTIFICATE-----" with proper newline
    normalized = normalized.replace("-----END CERTIFICATE----------BEGIN CERTIFICATE-----",
                                    "-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----");

    // Ensure newline between END CERTIFICATE and BEGIN PRIVATE KEY (for key files)
    normalized = normalized.replace("-----END CERTIFICATE----------BEGIN PRIVATE KEY-----",
                                    "-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----");

    // Ensure file ends with newline
    if !normalized.ends_with('\n') {
        normalized.push('\n');
    }

    normalized
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DomainConfig {
    domain: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    dns: bool,
    #[serde(default)]
    wildcard: bool,
}

/// Global certificate store for Redis-loaded certificates
static CERTIFICATE_STORE: once_cell::sync::OnceCell<Arc<tokio::sync::RwLock<Option<Arc<Certificates>>>>> = once_cell::sync::OnceCell::new();

/// Get the global certificate store
pub fn get_certificate_store() -> Arc<tokio::sync::RwLock<Option<Arc<Certificates>>>> {
    CERTIFICATE_STORE.get_or_init(|| Arc::new(tokio::sync::RwLock::new(None))).clone()
}

/// Certificate worker that fetches SSL certificates from Redis
pub struct CertificateWorker {
    certificate_path: String,
    refresh_interval_secs: u64,
}

impl CertificateWorker {
    pub fn new(certificate_path: String, refresh_interval_secs: u64) -> Self {
        Self {
            certificate_path,
            refresh_interval_secs,
        }
    }
}

impl Worker for CertificateWorker {
    fn name(&self) -> &str {
        "certificate"
    }

    fn run(&self, mut shutdown: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
        let certificate_path = self.certificate_path.clone();
        let refresh_interval_secs = self.refresh_interval_secs;
        let worker_name = self.name().to_string();

        tokio::spawn(async move {
            // Initial fetch on startup - download all certificates immediately
            log::info!("[{}] Starting certificate download from Redis on service startup...", worker_name);
            match fetch_certificates_from_redis(&certificate_path).await {
                Ok(_) => {
                    log::info!("[{}] Successfully downloaded all certificates from Redis on startup", worker_name);
                }
                Err(e) => {
                    log::warn!("[{}] Failed to fetch certificates from Redis on startup: {}", worker_name, e);
                    log::warn!("[{}] Will retry on next scheduled interval", worker_name);
                }
            }

            // Set up periodic refresh interval
            let mut interval = interval(Duration::from_secs(refresh_interval_secs));
            // Skip the first tick since we already fetched on startup
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        log::debug!("[{}] Periodic certificate refresh triggered", worker_name);
                        if let Err(e) = fetch_certificates_from_redis(&certificate_path).await {
                            log::warn!("[{}] Failed to fetch certificates from Redis: {}", worker_name, e);
                        }
                    }
                }
            }

            log::info!("[{}] Certificate fetcher task stopped", worker_name);
        })
    }
}

/// Start a background task that periodically fetches SSL certificates from Redis
/// This is kept for backward compatibility
pub fn start_certificate_fetcher(
    certificate_path: String,
    refresh_interval_secs: u64,
    shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let worker = CertificateWorker::new(certificate_path, refresh_interval_secs);
    worker.run(shutdown)
}

/// Fetch domains from ssl-storage:domains key in Redis
async fn fetch_domains_from_redis() -> Result<Vec<String>> {
    let redis_manager = RedisManager::get()
        .context("Redis manager not initialized")?;

    let mut connection = redis_manager.get_connection();

    // Fetch domains list from ssl-storage:domains key
    let domains_key = "ssl-storage:domains";
    log::debug!("Fetching domains from Redis key: {}", domains_key);

    let domains_json: Option<String> = redis::cmd("GET")
        .arg(domains_key)
        .query_async(&mut connection)
        .await
        .context("Failed to get domains from Redis")?;

    let domains = match domains_json {
        Some(json_str) => {
            log::debug!("Received domains JSON from Redis: {}", json_str);
            let domain_configs: Vec<DomainConfig> = serde_json::from_str(&json_str)
                .context(format!("Failed to parse domains JSON from Redis. JSON: {}", json_str))?;

            let domain_names: Vec<String> = domain_configs
                .into_iter()
                .map(|config| config.domain)
                .collect();

            log::info!("Found {} domains in ssl-storage:domains: {:?}", domain_names.len(), domain_names);
            domain_names
        }
        None => {
            log::warn!("No domains found in ssl-storage:domains key (key does not exist or is empty)");
            Vec::new()
        }
    };

    Ok(domains)
}

/// Fetch SSL certificates from Redis for domains listed in ssl-storage:domains
async fn fetch_certificates_from_redis(certificate_path: &str) -> Result<()> {
    let redis_manager = RedisManager::get()
        .context("Redis manager not initialized")?;

    // First, get the list of domains from ssl-storage:domains
    let domains = fetch_domains_from_redis().await?;

    if domains.is_empty() {
        log::warn!("No domains found in ssl-storage:domains key, skipping certificate fetch");
        return Ok(());
    }

    log::info!("Downloading certificates for {} domains from Redis", domains.len());

    let mut connection = redis_manager.get_connection();
    let mut certificate_configs = Vec::new();
    let cert_dir = std::path::Path::new(certificate_path);

    // Create certificate directory if it doesn't exist
    if !cert_dir.exists() {
        log::info!("Creating certificate directory: {}", certificate_path);
        std::fs::create_dir_all(cert_dir)
            .context(format!("Failed to create certificate directory: {}", certificate_path))?;
        log::info!("Certificate directory created: {}", certificate_path);
    } else {
        log::debug!("Certificate directory already exists: {}", certificate_path);
    }

    for domain in &domains {
        // Normalize domain (remove wildcard prefix if present)
        let normalized_domain = domain.strip_prefix("*.").unwrap_or(domain);

        // Fetch fullchain and private key from Redis
        // ssl-storage stores certificates with keys:
        // - ssl-storage:{domain}:live:fullchain
        // - ssl-storage:{domain}:live:privkey
        let fullchain_key = format!("ssl-storage:{}:live:fullchain", normalized_domain);
        let privkey_key = format!("ssl-storage:{}:live:privkey", normalized_domain);

        log::debug!("Fetching certificate for domain: {} (normalized: {})", domain, normalized_domain);
        log::debug!("Fullchain key: {}, Privkey key: {}", fullchain_key, privkey_key);

        let fullchain: Option<Vec<u8>> = redis::cmd("GET")
            .arg(&fullchain_key)
            .query_async(&mut connection)
            .await
            .context(format!("Failed to get fullchain for domain: {}", domain))?;

        let privkey: Option<Vec<u8>> = redis::cmd("GET")
            .arg(&privkey_key)
            .query_async(&mut connection)
            .await
            .context(format!("Failed to get private key for domain: {}", domain))?;

        match (fullchain, privkey) {
            (Some(fullchain_bytes), Some(privkey_bytes)) => {
                // Validate PEM format
                let fullchain_str = match String::from_utf8(fullchain_bytes.clone()) {
                    Ok(s) => s,
                    Err(_) => {
                        log::warn!("Fullchain for domain {} is not valid UTF-8", domain);
                        continue;
                    }
                };

                let privkey_str = match String::from_utf8(privkey_bytes.clone()) {
                    Ok(s) => s,
                    Err(_) => {
                        log::warn!("Private key for domain {} is not valid UTF-8", domain);
                        continue;
                    }
                };

                if !fullchain_str.contains("-----BEGIN CERTIFICATE-----") {
                    log::warn!("Fullchain for domain {} does not appear to be in PEM format", domain);
                    continue;
                }
                if !privkey_str.contains("-----BEGIN") {
                    log::warn!("Private key for domain {} does not appear to be in PEM format", domain);
                    continue;
                }

                // Write certificates to certificate directory
                // Use sanitized original domain name for file names (not normalized)
                // This ensures wildcard domains get unique filenames
                let sanitized_domain = domain.replace('.', "_").replace('*', "_");
                let cert_path = cert_dir.join(format!("{}.crt", sanitized_domain));
                let key_path = cert_dir.join(format!("{}.key", sanitized_domain));

                log::debug!("Writing certificate to: {} and key to: {}", cert_path.display(), key_path.display());

                // Write fullchain to file
                // Normalize the fullchain to ensure proper PEM format:
                // - Ensure newline between certificates (END CERTIFICATE and BEGIN CERTIFICATE)
                // - Ensure file ends with newline
                let normalized_fullchain = normalize_pem_chain(&fullchain_str);
                let mut cert_file = std::fs::File::create(&cert_path)
                    .context(format!("Failed to create certificate file for domain: {} at path: {}", domain, cert_path.display()))?;
                cert_file.write_all(normalized_fullchain.as_bytes())
                    .context(format!("Failed to write certificate file for domain: {} to path: {}", domain, cert_path.display()))?;
                cert_file.sync_all()
                    .context(format!("Failed to sync certificate file for domain: {} at path: {}", domain, cert_path.display()))?;

                // Write private key to file
                // Normalize the key to ensure proper PEM format
                let normalized_key = normalize_pem_chain(&privkey_str);
                let mut key_file = std::fs::File::create(&key_path)
                    .context(format!("Failed to create key file for domain: {} at path: {}", domain, key_path.display()))?;
                key_file.write_all(normalized_key.as_bytes())
                    .context(format!("Failed to write key file for domain: {} to path: {}", domain, key_path.display()))?;
                key_file.sync_all()
                    .context(format!("Failed to sync key file for domain: {} at path: {}", domain, key_path.display()))?;

                log::info!("Successfully downloaded and saved certificate for domain: {} to {}", domain, cert_path.display());

                // Verify files were written correctly
                if !cert_path.exists() {
                    log::warn!("Certificate file does not exist after write: {}", cert_path.display());
                    continue;
                }
                if !key_path.exists() {
                    log::warn!("Key file does not exist after write: {}", key_path.display());
                    continue;
                }

                // Create certificate config entry
                certificate_configs.push(CertificateConfig {
                    cert_path: cert_path.to_string_lossy().to_string(),
                    key_path: key_path.to_string_lossy().to_string(),
                });
                log::debug!("Added certificate config for domain: {} -> cert: {}, key: {}",
                    domain, cert_path.display(), key_path.display());
            }
            _ => {
                log::warn!("Certificate not found in Redis for domain: {}", domain);
            }
        }
    }

    if !certificate_configs.is_empty() {
        log::info!("Successfully fetched {} certificates from Redis", certificate_configs.len());
        log::debug!("Certificate configs to load: {:?}",
            certificate_configs.iter().map(|c| format!("cert: {}, key: {}", c.cert_path, c.key_path)).collect::<Vec<_>>());

        // Update the certificate store
        // Use "medium" as default TLS grade (can be made configurable)
        match Certificates::new(&certificate_configs, "medium") {
            Some(certificates) => {
                let store = get_certificate_store();
                let mut guard = store.write().await;
                *guard = Some(Arc::new(certificates));
                log::info!("Updated certificate store with {} certificates", certificate_configs.len());
            }
            None => {
                log::error!("Failed to create Certificates object from fetched configs. This usually means one or more certificate files are invalid or cannot be loaded.");
                log::error!("Attempted to load {} certificate configs", certificate_configs.len());
                for config in &certificate_configs {
                    log::error!("  - cert: {}, key: {}", config.cert_path, config.key_path);
                }
            }
        }
    } else {
        log::warn!("No certificates were successfully downloaded. Check if certificates exist in Redis for the domains listed in ssl-storage:domains");
    }

    Ok(())
}

