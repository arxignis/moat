use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::time::{interval, Duration};

use crate::redis::RedisManager;
use crate::utils::tls::{CertificateConfig, Certificates};
use crate::worker::Worker;

/// Calculate SHA256 hash of certificate files (fullchain + key)
fn calculate_local_hash(cert_path: &std::path::Path, key_path: &std::path::Path) -> Result<String> {
    use sha2::{Sha256, Digest};
    use std::io::Read;

    let mut hasher = Sha256::new();

    // Read and hash certificate file
    let mut cert_file = std::fs::File::open(cert_path)
        .context(format!("Failed to open certificate file: {}", cert_path.display()))?;
    let mut cert_data = Vec::new();
    cert_file.read_to_end(&mut cert_data)
        .context(format!("Failed to read certificate file: {}", cert_path.display()))?;
    hasher.update(&cert_data);

    // Read and hash key file
    let mut key_file = std::fs::File::open(key_path)
        .context(format!("Failed to open key file: {}", key_path.display()))?;
    let mut key_data = Vec::new();
    key_file.read_to_end(&mut key_data)
        .context(format!("Failed to read key file: {}", key_path.display()))?;
    hasher.update(&key_data);

    Ok(format!("{:x}", hasher.finalize()))
}

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

/// Global in-memory cache for certificate hashes (domain -> SHA256 hash)
/// Using Arc<Mutex<HashMap>> instead of MemoryCache to avoid lifetime issues
static CERTIFICATE_HASH_CACHE: once_cell::sync::OnceCell<Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>>> = once_cell::sync::OnceCell::new();

/// Get the global certificate store
pub fn get_certificate_store() -> Arc<tokio::sync::RwLock<Option<Arc<Certificates>>>> {
    CERTIFICATE_STORE.get_or_init(|| Arc::new(tokio::sync::RwLock::new(None))).clone()
}

/// Get the global certificate hash cache
/// Cache size: 1000 entries (should be enough for most deployments)
fn get_certificate_hash_cache() -> Arc<tokio::sync::RwLock<std::collections::HashMap<String, String>>> {
    CERTIFICATE_HASH_CACHE.get_or_init(|| {
        Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()))
    }).clone()
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

            log::info!("Found {} unique domain(s) in ssl-storage:domains: {:?}", domain_names.len(), domain_names);
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

    log::info!("Checking certificates for {} domain(s) from Redis (will skip download if hashes match)", domains.len());

    let mut connection = redis_manager.get_connection();
    let mut certificate_configs = Vec::new();
    let mut skipped_count = 0;
    let mut downloaded_count = 0;
    let mut missing_count = 0;
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

        // Check certificate hash from Redis before downloading
        let hash_key = format!("ssl-storage:{}:metadata:certificate_hash", normalized_domain);
        let remote_hash: Option<String> = redis::cmd("GET")
            .arg(&hash_key)
            .query_async(&mut connection)
            .await
            .context(format!("Failed to get certificate hash for domain: {}", domain))?;

        // Check in-memory cache first for local hash
        let hash_cache = get_certificate_hash_cache();
        let local_hash = {
            let cache = hash_cache.read().await;
            cache.get(domain).cloned()
        };

        // If not in cache, calculate from files if they exist
        let sanitized_domain = domain.replace('.', "_").replace('*', "_");
        let cert_path = cert_dir.join(format!("{}.crt", sanitized_domain));
        let key_path = cert_dir.join(format!("{}.key", sanitized_domain));

        let local_hash = if let Some(cached_hash) = local_hash {
            Some(cached_hash)
        } else if cert_path.exists() && key_path.exists() {
            // Calculate hash from files and store in cache
            if let Ok(hash) = calculate_local_hash(&cert_path, &key_path) {
                let mut cache = hash_cache.write().await;
                cache.insert(domain.clone(), hash.clone());
                Some(hash)
            } else {
                None
            }
        } else {
            None
        };

        // Skip download if hashes match, but still add existing certificates to config
        if let (Some(remote), Some(local)) = (&remote_hash, &local_hash) {
            if remote == local {
                log::info!("Certificate hash matches for domain: {} (hash: {}), skipping download", domain, remote);

                // Verify local certificate files exist and are valid
                if cert_path.exists() && key_path.exists() {
                    // Add existing certificate to config without re-downloading
                    certificate_configs.push(CertificateConfig {
                        cert_path: cert_path.to_string_lossy().to_string(),
                        key_path: key_path.to_string_lossy().to_string(),
                    });
                    skipped_count += 1;
                    log::debug!("Added existing certificate config for domain: {} -> cert: {}, key: {}",
                        domain, cert_path.display(), key_path.display());
                    continue; // Skip download, files already exist and are valid
                } else {
                    log::warn!("Hash matches but certificate files missing for domain: {}, will download", domain);
                    // Fall through to download
                }
            } else {
                log::info!("Certificate hash changed for domain: {} (remote: {}, local: {}), downloading new certificate", domain, remote, local);
            }
        } else if remote_hash.is_none() {
            log::debug!("No certificate hash found in Redis for domain: {}, will check if certificate exists", domain);
        } else if local_hash.is_none() {
            log::info!("No local certificate found for domain: {}, downloading from Redis", domain);
        }

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

                downloaded_count += 1;
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

                // Store local hash in memory cache after successful download
                if let Some(hash) = &remote_hash {
                    let domain_key = domain.clone();
                    let hash_value = hash.clone();
                    let hash_cache = get_certificate_hash_cache();
                    let mut cache = hash_cache.write().await;
                    cache.insert(domain_key, hash_value);
                    log::debug!("Stored local hash in memory cache for domain: {} -> {}", domain, hash);
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
                missing_count += 1;
                log::warn!("Certificate not found in Redis for domain: {}", domain);
            }
        }
    }

    // Log summary
    if skipped_count > 0 {
        log::info!("Skipped {} certificate(s) due to hash matches (using existing files)", skipped_count);
    }
    if downloaded_count > 0 {
        log::info!("Downloaded {} new/updated certificate(s) from Redis", downloaded_count);
    }
    if missing_count > 0 {
        log::warn!("{} certificate(s) not found in Redis", missing_count);
    }

    if !certificate_configs.is_empty() {
        log::info!("Successfully processed {} certificate(s) ({} downloaded, {} skipped)",
            certificate_configs.len(), downloaded_count, skipped_count);
        log::debug!("Certificate configs to load: {:?}",
            certificate_configs.iter().map(|c| format!("cert: {}, key: {}", c.cert_path, c.key_path)).collect::<Vec<_>>());

        // Update the certificate store
        // Use "medium" as default TLS grade (can be made configurable)
        // Default certificate is None for worker (can be made configurable later)
        match Certificates::new(&certificate_configs, "medium", None) {
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
        log::warn!("No certificates were processed. Check if certificates exist in Redis for the domains listed in ssl-storage:domains, or if all certificates were skipped due to hash matches but files are missing");
    }

    Ok(())
}

