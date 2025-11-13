use anyhow::{Context, Result};
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
/// Uses upstreams.yaml as the source of truth for domains
pub struct CertificateWorker {
    certificate_path: String,
    upstreams_path: String,
    refresh_interval_secs: u64,
}

impl CertificateWorker {
    pub fn new(certificate_path: String, upstreams_path: String, refresh_interval_secs: u64) -> Self {
        Self {
            certificate_path,
            upstreams_path,
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
        let upstreams_path = self.upstreams_path.clone();
        let refresh_interval_secs = self.refresh_interval_secs;
        let worker_name = self.name().to_string();

        tokio::spawn(async move {
            // Store upstreams_path globally for ACME requests
            set_upstreams_path(upstreams_path.clone());

            // Initial fetch on startup - download all certificates immediately
            log::info!("[{}] Starting certificate download from Redis on service startup...", worker_name);
            match fetch_certificates_from_redis(&certificate_path, &upstreams_path).await {
                Ok(_) => {
                    log::info!("[{}] Successfully downloaded all certificates from Redis on startup", worker_name);
                }
                Err(e) => {
                    log::warn!("[{}] Failed to fetch certificates from Redis on startup: {}", worker_name, e);
                    log::warn!("[{}] Will retry on next scheduled interval", worker_name);
                }
            }

            // Set up periodic refresh interval
            let mut refresh_interval = interval(Duration::from_secs(refresh_interval_secs));
            // Skip the first tick since we already fetched on startup
            refresh_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            // Set up periodic expiration check (every 6 hours)
            let mut expiration_check_interval = interval(Duration::from_secs(6 * 60 * 60)); // 6 hours
            expiration_check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // Skip the first tick - we'll check after the first certificate fetch
            let mut first_expiration_check = true;

            loop {
                tokio::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            break;
                        }
                    }
                    _ = refresh_interval.tick() => {
                        log::debug!("[{}] Periodic certificate refresh triggered", worker_name);
                        // Update upstreams_path in case it changed
                        set_upstreams_path(upstreams_path.clone());
                        if let Err(e) = fetch_certificates_from_redis(&certificate_path, &upstreams_path).await {
                            log::warn!("[{}] Failed to fetch certificates from Redis: {}", worker_name, e);
                        }
                    }
                    _ = expiration_check_interval.tick() => {
                        if first_expiration_check {
                            first_expiration_check = false;
                            continue; // Skip first check, wait for next interval
                        }
                        log::info!("[{}] Periodic certificate expiration check triggered", worker_name);
                        // Update upstreams_path in case it changed
                        set_upstreams_path(upstreams_path.clone());
                        if let Err(e) = check_and_renew_expiring_certificates(&upstreams_path).await {
                            log::warn!("[{}] Failed to check certificate expiration: {}", worker_name, e);
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
    upstreams_path: String,
    refresh_interval_secs: u64,
    shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    let worker = CertificateWorker::new(certificate_path, upstreams_path, refresh_interval_secs);
    worker.run(shutdown)
}

/// Fetch domains from upstreams.yaml file (source of truth)
async fn fetch_domains_from_upstreams(upstreams_path: &str) -> Result<Vec<String>> {
    use serde_yaml;
    use std::path::PathBuf;

    let path = PathBuf::from(upstreams_path);

    // Read and parse upstreams.yaml
    let yaml_content = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("Failed to read upstreams file: {:?}", path))?;

    let parsed: crate::utils::structs::Config = serde_yaml::from_str(&yaml_content)
        .with_context(|| format!("Failed to parse upstreams YAML: {:?}", path))?;

    let mut domains = Vec::new();

    if let Some(upstreams) = &parsed.upstreams {
        for (hostname, _host_config) in upstreams {
            domains.push(hostname.clone());
        }
    }

    log::info!("Found {} domain(s) in upstreams.yaml: {:?}", domains.len(), domains);
    Ok(domains)
}

/// Fetch SSL certificates from Redis for domains listed in upstreams.yaml
async fn fetch_certificates_from_redis(certificate_path: &str, upstreams_path: &str) -> Result<()> {
    let redis_manager = RedisManager::get()
        .context("Redis manager not initialized")?;

    // Parse upstreams.yaml to get domains and their certificate mappings
    use serde_yaml;
    use std::path::PathBuf;
    let path = PathBuf::from(upstreams_path);
    let yaml_content = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("Failed to read upstreams file: {:?}", path))?;
    let parsed: crate::utils::structs::Config = serde_yaml::from_str(&yaml_content)
        .with_context(|| format!("Failed to parse upstreams YAML: {:?}", path))?;

    // Build mapping of domain -> certificate_name (or None if not specified)
    let mut domain_cert_map: Vec<(String, Option<String>)> = Vec::new();
    if let Some(upstreams) = &parsed.upstreams {
        for (hostname, host_config) in upstreams {
            let cert_name = host_config.certificate.clone();
            domain_cert_map.push((hostname.clone(), cert_name));
        }
    }

    if domain_cert_map.is_empty() {
        log::warn!("No domains found in upstreams.yaml, skipping certificate fetch");
        return Ok(());
    }

    log::info!("Checking certificates for {} domain(s) from Redis (will skip download if hashes match)", domain_cert_map.len());

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

    for (domain, cert_name_opt) in &domain_cert_map {
        // Use certificate name if specified, otherwise use domain name
        let cert_name = cert_name_opt.as_ref().unwrap_or(domain);
        // Normalize certificate name (remove wildcard prefix if present)
        let normalized_cert_name = cert_name.strip_prefix("*.").unwrap_or(cert_name);

        // Check certificate hash from Redis before downloading
        // Get prefix from RedisManager
        let prefix = RedisManager::get()
            .map(|rm| rm.get_prefix().to_string())
            .unwrap_or_else(|_| "ssl-storage".to_string());
        let hash_key = format!("{}:{}:metadata:certificate_hash", prefix, normalized_cert_name);
        let remote_hash: Option<String> = redis::cmd("GET")
            .arg(&hash_key)
            .query_async(&mut connection)
            .await
            .context(format!("Failed to get certificate hash for domain: {}", domain))?;

        // Check in-memory cache first for local hash
        let hash_cache = get_certificate_hash_cache();

        // Get file paths first - use certificate name for file naming
        let sanitized_cert_name = cert_name.replace('.', "_").replace('*', "_");
        let cert_path = cert_dir.join(format!("{}.crt", sanitized_cert_name));
        let key_path = cert_dir.join(format!("{}.key", sanitized_cert_name));

        // Determine local hash for comparison
        // IMPORTANT: We use the Redis hash (remote_hash) as the source of truth when available
        // because Redis calculates hash from raw bytes, while files are normalized (whitespace changes)
        // If we have a Redis hash, we trust it. If not, we check cache or recalculate from files.
        let local_hash = if remote_hash.is_some() {
            // We have a Redis hash - check if we have it cached locally
            let cached_hash = {
                let cache = hash_cache.read().await;
                cache.get(cert_name).cloned()
            };

            if let Some(cached_hash) = cached_hash {
                // We have a cached hash - verify files exist
                if cert_path.exists() && key_path.exists() {
                    // Files exist and we have cached hash - use cached hash (which should match Redis)
            Some(cached_hash)
                } else {
                    // Files don't exist - clear cache
                let mut cache = hash_cache.write().await;
                    cache.remove(cert_name);
                    None
                }
            } else {
                // No cached hash - if files exist, we'll download and cache the hash
                // For now, return None to trigger download (hash will be cached after download)
                None
            }
        } else {
            // No Redis hash - check files and calculate hash if needed
            if cert_path.exists() && key_path.exists() {
                let cached_hash = {
                    let cache = hash_cache.read().await;
                    cache.get(domain).cloned()
                };

                if let Some(cached_hash) = cached_hash {
                    Some(cached_hash)
                } else if let Ok(calculated_hash) = calculate_local_hash(&cert_path, &key_path) {
                    // Calculate from files and cache it
                    let mut cache = hash_cache.write().await;
                    cache.insert(domain.clone(), calculated_hash.clone());
                    Some(calculated_hash)
                } else {
                    None
                }
            } else {
                // Files don't exist - clear cache
                let mut cache = hash_cache.write().await;
                cache.remove(domain);
                None
            }
        };

        // Determine if we need to download
        let should_download = if let (Some(remote), Some(local)) = (&remote_hash, &local_hash) {
            if remote == local {
                // Hashes match - check if files actually exist
                if cert_path.exists() && key_path.exists() {
                    log::debug!("Certificate hash matches for domain: {} (hash: {}), files exist, skipping download", domain, remote);
                    // Add existing certificate to config without re-downloading
                    certificate_configs.push(CertificateConfig {
                        cert_path: cert_path.to_string_lossy().to_string(),
                        key_path: key_path.to_string_lossy().to_string(),
                    });
                    skipped_count += 1;
                    log::debug!("Added existing certificate config for domain: {} -> cert: {}, key: {}",
                        domain, cert_path.display(), key_path.display());
                    false // Don't download
                } else {
                    log::warn!("Hash matches but certificate files missing for domain: {} (cert: {}, key: {}), will download",
                        domain, cert_path.display(), key_path.display());
                    true // Download - files are missing
                }
            } else {
                log::debug!("Certificate hash mismatch for domain: {} (remote: {}, local: {}), downloading new certificate", domain, remote, local);
                true // Download - hash changed
            }
        } else if remote_hash.is_none() {
            log::debug!("No certificate hash found in Redis for domain: {}, will check if certificate exists in Redis", domain);
            true // Download - check if certificate exists
        } else if local_hash.is_none() {
            log::debug!("No local certificate found for domain: {} (files don't exist or hash not calculated), downloading from Redis", domain);
            true // Download - no local certificate
        } else {
            log::debug!("Unexpected state for domain: {} (remote_hash: {:?}, local_hash: {:?}), defaulting to download", domain, remote_hash, local_hash);
            true // Default to downloading
        };

        // Skip download if not needed
        if !should_download {
            continue;
        }

        // Fetch fullchain and private key from Redis
        // Get prefix from RedisManager
        let prefix = RedisManager::get()
            .map(|rm| rm.get_prefix().to_string())
            .unwrap_or_else(|_| "ssl-storage".to_string());
        // Redis stores certificates with keys:
        // - {prefix}:{cert_name}:live:fullchain
        // - {prefix}:{cert_name}:live:privkey
        let fullchain_key = format!("{}:{}:live:fullchain", prefix, normalized_cert_name);
        let privkey_key = format!("{}:{}:live:privkey", prefix, normalized_cert_name);

        log::info!("Fetching certificate for domain: {} (using cert: {}, normalized: {}, prefix: {})", domain, cert_name, normalized_cert_name, prefix);
        log::info!("Fullchain key: '{}', Privkey key: '{}'", fullchain_key, privkey_key);

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

        log::info!("Redis GET results for domain {}: fullchain={}, privkey={}",
            domain,
            if fullchain.is_some() { "Some" } else { "None" },
            if privkey.is_some() { "Some" } else { "None" }
        );

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
                // Use sanitized certificate name for file names (already set above)
                // cert_path and key_path are already set using cert_name

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

                // Calculate hash from raw bytes (before normalization) to match Redis hash calculation
                // Redis calculates hash from: fullchain (raw bytes) + key (raw bytes)
                // We need to match this exactly, not from normalized files
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&fullchain_bytes);
                hasher.update(&privkey_bytes);
                let calculated_hash = format!("{:x}", hasher.finalize());

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
                // Use the hash calculated from raw bytes (matching Redis calculation)
                    let cert_key = cert_name.to_string();
                    let hash_cache = get_certificate_hash_cache();
                    let mut cache = hash_cache.write().await;
                cache.insert(cert_key, calculated_hash.clone());
                log::debug!("Stored local hash in memory cache for domain: {} -> {} (calculated from raw bytes, matching Redis)", domain, calculated_hash);

                // Verify hash matches Redis hash
                if let Some(remote_hash) = &remote_hash {
                    if calculated_hash != *remote_hash {
                        log::warn!("Hash mismatch after download for domain {}: calculated={}, redis={}. This should not happen!",
                            domain, calculated_hash, remote_hash);
                    } else {
                        log::debug!("Hash verified: calculated hash matches Redis hash for domain: {}", domain);
                    }
                }

                // Create certificate config entry
                certificate_configs.push(CertificateConfig {
                    cert_path: cert_path.to_string_lossy().to_string(),
                    key_path: key_path.to_string_lossy().to_string(),
                });
                log::debug!("Added certificate config for domain: {} -> cert: {}, key: {}",
                    domain, cert_path.display(), key_path.display());
            }
            (Some(_), None) => {
                missing_count += 1;
                log::warn!("Certificate fullchain found but private key missing in Redis for domain: {} (cert: {}, key: {})", domain, cert_name, privkey_key);
                // Only request certificate if no certificate name is specified (i.e., use domain name)
                if cert_name_opt.is_none() {
                    if let Err(e) = request_certificate_from_acme(domain, normalized_cert_name, &certificate_path).await {
                        log::warn!("Failed to request certificate from ACME for domain {}: {}", domain, e);
                    } else {
                        log::debug!("Successfully requested certificate from ACME for domain: {}", domain);
                    }
                } else {
                    log::debug!("Certificate name '{}' is specified for domain '{}', not requesting new certificate (certificate may be shared)", cert_name, domain);
                }
            }
            (None, Some(_)) => {
                missing_count += 1;
                log::warn!("Certificate private key found but fullchain missing in Redis for domain: {} (cert: {}, key: {})", domain, cert_name, fullchain_key);
                // Only request certificate if no certificate name is specified (i.e., use domain name)
                if cert_name_opt.is_none() {
                    if let Err(e) = request_certificate_from_acme(domain, normalized_cert_name, &certificate_path).await {
                        log::warn!("Failed to request certificate from ACME for domain {}: {}", domain, e);
                    } else {
                        log::debug!("Successfully requested certificate from ACME for domain: {}", domain);
                    }
                } else {
                    log::debug!("Certificate name '{}' is specified for domain '{}', not requesting new certificate (certificate may be shared)", cert_name, domain);
                }
            }
            (None, None) => {
                missing_count += 1;
                log::warn!("Certificate not found in Redis for domain: {} (cert: {}, checked keys: fullchain='{}', privkey='{}')",
                    domain, cert_name, fullchain_key, privkey_key);

                // Only request certificate if no certificate name is specified (i.e., use domain name)
                // If a certificate name is specified, it means we should use an existing shared certificate
                if cert_name_opt.is_none() {
                    // Try to list matching keys to help debug
                    let pattern = format!("{}:{}:*", prefix, normalized_cert_name);
                let keys_result: Result<Vec<String>, _> = redis::cmd("KEYS")
                    .arg(&pattern)
                    .query_async(&mut connection)
                    .await;
                match keys_result {
                    Ok(keys) => {
                        if !keys.is_empty() {
                            log::debug!("Found {} matching keys for pattern '{}': {:?}", keys.len(), pattern, keys);
                        } else {
                            log::warn!("No keys found matching pattern '{}'", pattern);
                        }
                    }
                    Err(e) => {
                        log::debug!("Failed to list keys with pattern '{}': {}", pattern, e);
                    }
                }

                    // Request certificate from ACME server if enabled
                    if let Err(e) = request_certificate_from_acme(domain, normalized_cert_name, &certificate_path).await {
                        log::warn!("Failed to request certificate from ACME for domain {}: {}", domain, e);
                    } else {
                        log::debug!("Successfully requested certificate from ACME for domain: {}", domain);
                    }
                } else {
                    log::debug!("Certificate name '{}' is specified for domain '{}', not requesting new certificate (certificate may be shared)", cert_name, domain);
                }
            }
        }
    }

    // Log summary
    if skipped_count > 0 {
        log::debug!("Skipped {} certificate(s) due to hash matches (using existing files)", skipped_count);
    }
    if downloaded_count > 0 {
        log::info!("Downloaded {} new/updated certificate(s) from Redis", downloaded_count);
    }
    if missing_count > 0 {
        log::warn!("{} certificate(s) not found in Redis", missing_count);
    }

    if !certificate_configs.is_empty() {
        log::debug!("Successfully processed {} certificate(s) ({} downloaded, {} skipped)",
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
                log::debug!("Updated certificate store with {} certificates", certificate_configs.len());
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
        log::warn!("No certificates were processed. Check if certificates exist in Redis for the domains listed in upstreams.yaml, or if all certificates were skipped due to hash matches but files are missing");
    }

    Ok(())
}

/// Global ACME config store
static ACME_CONFIG: once_cell::sync::OnceCell<Arc<std::sync::RwLock<Option<crate::cli::AcmeConfig>>>> = once_cell::sync::OnceCell::new();

/// Global upstreams path store
static UPSTREAMS_PATH: once_cell::sync::OnceCell<Arc<std::sync::RwLock<Option<String>>>> = once_cell::sync::OnceCell::new();

/// Set the global ACME config (called from main.rs)
pub fn set_acme_config(config: crate::cli::AcmeConfig) {
    let store = ACME_CONFIG.get_or_init(|| Arc::new(std::sync::RwLock::new(None)));
    let mut guard = store.write().unwrap();
    *guard = Some(config);
}

/// Set the global upstreams path (called from certificate worker)
fn set_upstreams_path(path: String) {
    let store = UPSTREAMS_PATH.get_or_init(|| Arc::new(std::sync::RwLock::new(None)));
    let mut guard = store.write().unwrap();
    *guard = Some(path);
}

/// Get the global ACME config
pub async fn get_acme_config() -> Option<crate::cli::AcmeConfig> {
    let store = ACME_CONFIG.get()?;
    let guard = tokio::task::spawn_blocking({
        let store = Arc::clone(store);
        move || store.read().unwrap().clone()
    }).await.ok()?;
    guard
}

/// Get the global upstreams path
async fn get_upstreams_path() -> Option<String> {
    let store = UPSTREAMS_PATH.get()?;
    let guard = tokio::task::spawn_blocking({
        let store = Arc::clone(store);
        move || store.read().unwrap().clone()
    }).await.ok()?;
    guard
}

/// Request a certificate from ACME server for a domain
pub async fn request_certificate_from_acme(
    domain: &str,
    normalized_domain: &str,
    _certificate_path: &str,
) -> Result<()> {
    use crate::acme::{Config, ConfigOpts, request_cert};
    use std::path::PathBuf;

    // Check if ACME is enabled
    let acme_config = match get_acme_config().await {
        Some(config) if config.enabled => config,
        Some(_) => {
            log::debug!("ACME is disabled, skipping certificate request for domain: {}", domain);
            return Ok(());
        }
        None => {
            log::debug!("ACME config not available, skipping certificate request for domain: {}", domain);
            return Ok(());
        }
    };

    // Get email - use from config or default
    let email = acme_config.email
        .unwrap_or_else(|| "admin@example.com".to_string());

    // Get Redis URL from RedisManager if available
    let redis_url = crate::redis::RedisManager::get()
        .ok()
        .and_then(|_| {
            // Use ACME config Redis URL, or try to get from RedisManager
            acme_config.redis_url.clone()
                .or_else(|| std::env::var("REDIS_URL").ok())
        });

    // Read challenge type from upstreams.yaml
    // Get upstreams path from global store (set by certificate worker) or use default
    let upstreams_path = get_upstreams_path().await
        .unwrap_or_else(|| "/root/moat/upstreams.yaml".to_string());

    let (use_dns, domain_email) = {

        // Try to read challenge type from upstreams.yaml
        if let Ok(yaml_content) = tokio::fs::read_to_string(&upstreams_path).await {
            if let Ok(parsed) = serde_yaml::from_str::<crate::utils::structs::Config>(&yaml_content) {
                if let Some(upstreams) = &parsed.upstreams {
                    if let Some(host_config) = upstreams.get(domain) {
                        // Get challenge type from ACME config in upstreams
                        let challenge_type = if let Some(acme_cfg) = &host_config.acme {
                            acme_cfg.challenge_type.clone()
                        } else {
                            // Auto-detect: DNS-01 for wildcard, HTTP-01 otherwise
                            if domain.starts_with("*.") {
                                "dns-01".to_string()
                            } else {
                                "http-01".to_string()
                            }
                        };

                        let use_dns = challenge_type == "dns-01";
                        let domain_email = host_config.acme.as_ref()
                            .and_then(|a| a.email.clone())
                            .or_else(|| Some(email.clone()));

                        log::debug!("Using challenge type '{}' for domain {} (from upstreams.yaml)", challenge_type, domain);
                        (use_dns, domain_email)
                    } else {
                        // Domain not found in upstreams, auto-detect
                        let is_wildcard = domain.starts_with("*.");
                        log::info!("Domain {} not found in upstreams.yaml, auto-detecting challenge type (wildcard: {})", domain, is_wildcard);
                        (is_wildcard, Some(email.clone()))
                    }
                } else {
                    // No upstreams, auto-detect
                    let is_wildcard = domain.starts_with("*.");
                    (is_wildcard, Some(email.clone()))
                }
            } else {
                // Failed to parse, auto-detect
                let is_wildcard = domain.starts_with("*.");
                (is_wildcard, Some(email.clone()))
            }
        } else {
            // Failed to read, auto-detect
            let is_wildcard = domain.starts_with("*.");
            (is_wildcard, Some(email.clone()))
        }
    };

    // Create domain config for ACME
    let mut domain_storage_path = PathBuf::from(&acme_config.storage_path);
    domain_storage_path.push(normalized_domain);

    let mut cert_path = domain_storage_path.clone();
    cert_path.push("cert.pem");
    let mut key_path = domain_storage_path.clone();
    key_path.push("key.pem");
    let static_path = domain_storage_path.clone();

    // Determine if this is a wildcard domain
    let is_wildcard = domain.starts_with("*.");

    // Get Redis SSL config if available
    let redis_ssl = crate::redis::RedisManager::get()
        .ok()
        .and_then(|_| {
            // Try to get SSL config from global config if available
            // For now, we'll use None and let it use defaults
            None
        });

    let acme_config_internal = Config {
        https_path: domain_storage_path,
        cert_path,
        key_path,
        static_path,
        opts: ConfigOpts {
            ip: "127.0.0.1".to_string(),
            port: acme_config.port,
            domain: domain.to_string(),
            email: domain_email,
            https_dns: use_dns,
            development: acme_config.development,
            dns_lookup_max_attempts: Some(100),
            dns_lookup_delay_seconds: Some(10),
                storage_type: {
                    // Always use Redis (storage_type option is kept for compatibility but always uses Redis)
                    Some("redis".to_string())
                },
            redis_url,
            lock_ttl_seconds: Some(900),
            redis_ssl,
            challenge_max_ttl_seconds: Some(3600),
        },
    };

    // Request certificate from ACME
    log::debug!("Requesting certificate from ACME for domain: {} (wildcard: {}, dns: {})",
        domain, is_wildcard, use_dns);

    request_cert(&acme_config_internal).await
        .context(format!("Failed to request certificate from ACME for domain: {}", domain))?;

    log::debug!("Certificate requested successfully from ACME for domain: {}. It will be available in Redis after processing.", domain);

    // After requesting, the certificate should be in Redis (if using Redis storage)
    // The next refresh cycle will pick it up automatically

    Ok(())
}

/// Check certificates for expiration and renew if expiring within 60 days
async fn check_and_renew_expiring_certificates(upstreams_path: &str) -> Result<()> {
    use x509_parser::prelude::*;
    use x509_parser::nom::Err as NomErr;
    use rustls_pemfile::read_one;
    use std::io::BufReader;

    // Get the list of domains from upstreams.yaml
    let domains = fetch_domains_from_upstreams(upstreams_path).await?;

    if domains.is_empty() {
        log::debug!("No domains found in upstreams.yaml, skipping expiration check");
        return Ok(());
    }

    log::info!("Checking certificate expiration for {} domain(s)", domains.len());

    let redis_manager = RedisManager::get()
        .context("Redis manager not initialized")?;

    let mut connection = redis_manager.get_connection();
    let mut renewed_count = 0;
    let mut checked_count = 0;

    for domain in &domains {
        let normalized_domain = domain.strip_prefix("*.").unwrap_or(domain);

        // Check if certificate exists in Redis
        // Get prefix from RedisManager
        let prefix = RedisManager::get()
            .map(|rm| rm.get_prefix().to_string())
            .unwrap_or_else(|_| "ssl-storage".to_string());
        let fullchain_key = format!("{}:{}:live:fullchain", prefix, normalized_domain);
        let fullchain: Option<Vec<u8>> = redis::cmd("GET")
            .arg(&fullchain_key)
            .query_async(&mut connection)
            .await
            .context(format!("Failed to get fullchain for domain: {}", domain))?;

        let fullchain_bytes = match fullchain {
            Some(bytes) => bytes,
            None => {
                log::debug!("Certificate not found in Redis for domain: {}, skipping expiration check", domain);
                continue;
            }
        };

        // Parse the certificate to get expiration date
        let fullchain_str = match String::from_utf8(fullchain_bytes.clone()) {
            Ok(s) => s,
            Err(_) => {
                log::warn!("Fullchain for domain {} is not valid UTF-8, skipping expiration check", domain);
                continue;
            }
        };

        // Parse PEM to get the first certificate (domain cert)
        let mut reader = BufReader::new(fullchain_str.as_bytes());
        let cert_der = match read_one(&mut reader) {
            Ok(Some(rustls_pemfile::Item::X509Certificate(cert))) => cert,
            Ok(_) => {
                log::warn!("No X509 certificate found in fullchain for domain: {}", domain);
                continue;
            }
            Err(e) => {
                log::warn!("Failed to parse certificate for domain {}: {:?}", domain, e);
                continue;
            }
        };

        // Parse the DER certificate
        let (_, x509_cert) = match X509Certificate::from_der(&cert_der) {
            Ok(cert) => cert,
            Err(NomErr::Error(e)) | Err(NomErr::Failure(e)) => {
                log::warn!("Failed to parse X509 certificate for domain {}: {:?}", domain, e);
                continue;
            }
            Err(_) => {
                log::warn!("Unknown error parsing X509 certificate for domain: {}", domain);
                continue;
            }
        };

        // Get expiration date
        let validity = x509_cert.validity();
        let not_after_offset = validity.not_after.to_datetime();
        let now = chrono::Utc::now();

        // Convert OffsetDateTime to chrono::DateTime<Utc>
        let not_after = chrono::DateTime::<chrono::Utc>::from_timestamp(
            not_after_offset.unix_timestamp(),
            0
        ).unwrap_or_else(|| {
            log::warn!("Failed to convert certificate expiration date for domain: {}", domain);
            now + chrono::Duration::days(90) // Fallback to 90 days from now
        });

        // Calculate days until expiration
        let expires_in = not_after - now;
        let days_until_expiration = expires_in.num_days();

        checked_count += 1;

        log::debug!("Certificate for domain {} expires in {} days (expires at: {})",
            domain, days_until_expiration, not_after);

        // Check if certificate expires in less than 60 days
        if days_until_expiration < 60 {
            log::info!("Certificate for domain {} expires in {} days (< 60 days), starting renewal process",
                domain, days_until_expiration);

            // Request renewal from ACME
            let certificate_path = "/tmp/moat-certs"; // Placeholder, will be stored in Redis
            if let Err(e) = request_certificate_from_acme(domain, normalized_domain, certificate_path).await {
                log::warn!("Failed to renew certificate for domain {}: {}", domain, e);
            } else {
                log::info!("Successfully initiated certificate renewal for domain: {}", domain);
                renewed_count += 1;
            }
        } else {
            log::debug!("Certificate for domain {} is still valid (expires in {} days)",
                domain, days_until_expiration);
        }
    }

    log::info!("Certificate expiration check completed: {} checked, {} renewed", checked_count, renewed_count);

    Ok(())
}

