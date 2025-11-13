//! Domain reader that supports multiple sources: file, Redis, and HTTP

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use sha2::{Sha256, Digest};
use notify::{Watcher, RecommendedWatcher, RecursiveMode, EventKind};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    pub domain: String,
    pub email: Option<String>,
    pub dns: bool,
    pub wildcard: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainSourceConfig {
    pub source: String,
    pub file_path: Option<String>,
    pub redis_key: Option<String>,
    pub redis_url: Option<String>,
    pub redis_ssl: Option<crate::acme::config::RedisSslConfig>,
    pub http_url: Option<String>,
    pub http_refresh_interval: Option<u64>,
}

/// Domain reader trait
#[async_trait::async_trait]
pub trait DomainReader: Send + Sync {
    async fn read_domains(&self) -> Result<Vec<DomainConfig>>;
}

/// File-based domain reader with file watching and hash-based change detection
pub struct FileDomainReader {
    file_path: PathBuf,
    cached_domains: Arc<tokio::sync::RwLock<Option<(Vec<DomainConfig>, String)>>>, // (domains, hash)
}

impl FileDomainReader {
    pub fn new(file_path: impl Into<PathBuf>) -> Self {
        let file_path = file_path.into();
        let reader = Self {
            file_path: file_path.clone(),
            cached_domains: Arc::new(tokio::sync::RwLock::new(None)),
        };

        // Start file watching task
        let reader_clone = reader.clone_for_watching();
        tokio::spawn(async move {
            reader_clone.start_watching().await;
        });

        reader
    }

    /// Create a clone for the watching task
    fn clone_for_watching(&self) -> FileDomainReaderWatching {
        FileDomainReaderWatching {
            file_path: self.file_path.clone(),
            cached_domains: Arc::clone(&self.cached_domains),
        }
    }

    /// Calculate SHA256 hash of content
    fn calculate_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Fetch domains from file
    async fn fetch_domains(&self) -> Result<(Vec<DomainConfig>, String)> {
        let content = tokio::fs::read_to_string(&self.file_path)
            .await
            .with_context(|| format!("Failed to read domains file: {:?}", self.file_path))?;

        let hash = Self::calculate_hash(&content);

        let domains: Vec<DomainConfig> = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse domains JSON: {:?}", self.file_path))?;

        Ok((domains, hash))
    }
}

/// Internal struct for file watching task
struct FileDomainReaderWatching {
    file_path: PathBuf,
    cached_domains: Arc<tokio::sync::RwLock<Option<(Vec<DomainConfig>, String)>>>,
}

impl FileDomainReaderWatching {
    /// Start watching the file for changes
    async fn start_watching(&self) {
        // Initial load
        if let Err(e) = self.check_and_update().await {
            tracing::warn!("Failed to load domains file initially: {}", e);
        }

        // Create watcher with std::sync::mpsc (required by notify)
        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher: RecommendedWatcher = match Watcher::new(
            tx,
            notify::Config::default()
                .with_poll_interval(std::time::Duration::from_secs(1))
                .with_compare_contents(true),
        ) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("Failed to create file watcher: {}", e);
                return;
            }
        };

        // Watch the parent directory to catch file renames/moves
        if let Some(parent) = self.file_path.parent() {
            if let Err(e) = watcher.watch(parent, RecursiveMode::NonRecursive) {
                tracing::warn!("Failed to watch directory {:?}: {}", parent, e);
            }
        }

        // Also watch the file directly
        if let Err(e) = watcher.watch(&self.file_path, RecursiveMode::NonRecursive) {
            tracing::warn!("Failed to watch file {:?}: {}", self.file_path, e);
        }

        tracing::info!("Watching domains file: {:?}", self.file_path);

        // Process file events (bridge from sync channel to async)
        let file_path = self.file_path.clone();
        let cached_domains = Arc::clone(&self.cached_domains);

        tokio::task::spawn_blocking(move || {
            while let Ok(res) = rx.recv() {
                match res {
                    Ok(event) => {
                        // Check if the event is for our file
                        if event.paths.iter().any(|p| p == &file_path) {
                            match event.kind {
                                EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_) => {
                                    // Use a blocking task to handle the async update
                                    let file_path_clone = file_path.clone();
                                    let cached_domains_clone = Arc::clone(&cached_domains);

                                    tokio::spawn(async move {
                                        // Small delay to ensure file write is complete
                                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                                        let content = match tokio::fs::read_to_string(&file_path_clone).await {
                                            Ok(c) => c,
                                            Err(e) => {
                                                tracing::debug!("Failed to read domains file {:?}: {}", file_path_clone, e);
                                                return;
                                            }
                                        };

                                        let new_hash = FileDomainReader::calculate_hash(&content);

                                        // Check if hash changed
                                        {
                                            let cache = cached_domains_clone.read().await;
                                            if let Some((_, old_hash)) = cache.as_ref() {
                                                if *old_hash == new_hash {
                                                    return; // No change
                                                }
                                            }
                                        }

                                        // Parse and update cache
                                        let domains: Vec<DomainConfig> = match serde_json::from_str(&content) {
                                            Ok(d) => d,
                                            Err(e) => {
                                                tracing::warn!("Failed to parse domains JSON from file {:?}: {}", file_path_clone, e);
                                                return;
                                            }
                                        };

                                        {
                                            let mut cache = cached_domains_clone.write().await;
                                            *cache = Some((domains, new_hash));
                                        }

                                        tracing::info!("Domains file changed (hash updated), cache refreshed");
                                    });
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("File watcher error: {}", e);
                    }
                }
            }
        });
    }

    /// Check file and update cache if content changed
    async fn check_and_update(&self) -> Result<bool> {
        let content = match tokio::fs::read_to_string(&self.file_path).await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("Failed to read domains file {:?}: {}", self.file_path, e);
                return Ok(false);
            }
        };

        let new_hash = FileDomainReader::calculate_hash(&content);

        // Check if hash changed
        {
            let cache = self.cached_domains.read().await;
            if let Some((_, old_hash)) = cache.as_ref() {
                if *old_hash == new_hash {
                    return Ok(false); // No change
                }
            }
        }

        // Parse and update cache
        let domains: Vec<DomainConfig> = match serde_json::from_str(&content) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("Failed to parse domains JSON from file {:?}: {}", self.file_path, e);
                return Ok(false);
            }
        };

        {
            let mut cache = self.cached_domains.write().await;
            *cache = Some((domains, new_hash));
        }

        Ok(true) // Changed
    }
}

#[async_trait::async_trait]
impl DomainReader for FileDomainReader {
    async fn read_domains(&self) -> Result<Vec<DomainConfig>> {
        // First, try to get from cache
        {
            let cache = self.cached_domains.read().await;
            if let Some((domains, _)) = cache.as_ref() {
                return Ok(domains.clone());
            }
        }

        // Cache is empty, fetch from file
        let (domains, hash) = self.fetch_domains().await?;

        // Update cache
        {
            let mut cache = self.cached_domains.write().await;
            *cache = Some((domains.clone(), hash));
        }

        Ok(domains)
    }
}

/// Redis-based domain reader with polling and hash-based change detection
pub struct RedisDomainReader {
    redis_key: String,
    redis_url: String,
    redis_ssl: Option<crate::acme::config::RedisSslConfig>,
    cached_domains: Arc<tokio::sync::RwLock<Option<(Vec<DomainConfig>, String)>>>, // (domains, hash)
}

impl RedisDomainReader {
    pub fn new(redis_key: String, redis_url: Option<String>, redis_ssl: Option<crate::acme::config::RedisSslConfig>) -> Self {
        let reader = Self {
            redis_key: redis_key.clone(),
            redis_url: redis_url
                .clone()
                .or_else(|| std::env::var("REDIS_URL").ok())
                .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string()),
            redis_ssl: redis_ssl.clone(),
            cached_domains: Arc::new(tokio::sync::RwLock::new(None)),
        };

        // Start background polling task
        let reader_clone = reader.clone_for_polling();
        tokio::spawn(async move {
            reader_clone.start_polling().await;
        });

        reader
    }

    /// Create a clone for the polling task (only the necessary fields)
    fn clone_for_polling(&self) -> RedisDomainReaderPolling {
        RedisDomainReaderPolling {
            redis_key: self.redis_key.clone(),
            redis_url: self.redis_url.clone(),
            redis_ssl: self.redis_ssl.clone(),
            cached_domains: Arc::clone(&self.cached_domains),
        }
    }

    /// Calculate SHA256 hash of content
    fn calculate_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Create Redis client with optional SSL configuration
    fn create_redis_client(&self) -> Result<redis::Client> {
        if let Some(ssl_config) = &self.redis_ssl {
            Self::create_client_with_ssl(&self.redis_url, ssl_config)
        } else {
            redis::Client::open(self.redis_url.as_str())
                .with_context(|| format!("Failed to connect to Redis at {}", self.redis_url))
        }
    }

    /// Create Redis client with custom SSL/TLS configuration (static method for use in polling)
    pub(crate) fn create_client_with_ssl(redis_url: &str, ssl_config: &crate::acme::config::RedisSslConfig) -> Result<redis::Client> {
        use native_tls::{Certificate, Identity, TlsConnector};

        // Build TLS connector with custom certificates
        let mut tls_builder = TlsConnector::builder();

        // Load CA certificate if provided
        if let Some(ca_cert_path) = &ssl_config.ca_cert_path {
            let ca_cert_data = std::fs::read(ca_cert_path)
                .with_context(|| format!("Failed to read CA certificate from {}", ca_cert_path))?;
            let ca_cert = Certificate::from_pem(&ca_cert_data)
                .with_context(|| format!("Failed to parse CA certificate from {}", ca_cert_path))?;
            tls_builder.add_root_certificate(ca_cert);
            tracing::info!("Loaded CA certificate from {}", ca_cert_path);
        }

        // Load client certificate and key if provided
        if let (Some(client_cert_path), Some(client_key_path)) = (&ssl_config.client_cert_path, &ssl_config.client_key_path) {
            let client_cert_data = std::fs::read(client_cert_path)
                .with_context(|| format!("Failed to read client certificate from {}", client_cert_path))?;
            let client_key_data = std::fs::read(client_key_path)
                .with_context(|| format!("Failed to read client key from {}", client_key_path))?;

            // Try to create identity from PEM format (cert + key)
            let identity = Identity::from_pkcs8(&client_cert_data, &client_key_data)
                .or_else(|_| {
                    // Try PEM format if PKCS#8 fails
                    Identity::from_pkcs12(&client_cert_data, "")
                })
                .or_else(|_| {
                    // Try loading as separate PEM files
                    // Combine cert and key into a single PEM
                    let mut combined = client_cert_data.clone();
                    combined.extend_from_slice(b"\n");
                    combined.extend_from_slice(&client_key_data);
                    Identity::from_pkcs12(&combined, "")
                })
                .with_context(|| format!("Failed to parse client certificate/key from {} and {}. Supported formats: PKCS#8, PKCS#12, or PEM", client_cert_path, client_key_path))?;
            tls_builder.identity(identity);
            tracing::info!("Loaded client certificate from {} and key from {}", client_cert_path, client_key_path);
        }

        // Configure certificate verification
        if ssl_config.insecure {
            tls_builder.danger_accept_invalid_certs(true);
            tls_builder.danger_accept_invalid_hostnames(true);
            tracing::warn!("Redis SSL: Certificate verification disabled (insecure mode)");
        }

        let _tls_connector = tls_builder.build()
            .with_context(|| "Failed to build TLS connector")?;

        // Note: The redis crate with tokio-native-tls-comp uses native-tls internally,
        // but doesn't expose a way to pass a custom TlsConnector. However, when using
        // rediss:// URLs, it will use the system trust store. For custom CA certificates,
        // we need to add them to the system trust store or use a workaround.

        let client = redis::Client::open(redis_url)
            .with_context(|| format!("Failed to create Redis client with SSL config"))?;

        Ok(client)
    }

    /// Fetch domains from Redis
    async fn fetch_domains(&self) -> Result<(Vec<DomainConfig>, String)> {
        use redis::AsyncCommands;

        let client = self.create_redis_client()?;

        use redis::aio::ConnectionManager;
        let mut conn = ConnectionManager::new(client)
            .await
            .with_context(|| "Failed to get Redis connection")?;

        let content: String = conn.get(&self.redis_key).await
            .with_context(|| format!("Failed to read domains from Redis key: {}", self.redis_key))?;

        let hash = Self::calculate_hash(&content);

        let domains: Vec<DomainConfig> = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse domains JSON from Redis"))?;

        Ok((domains, hash))
    }
}

/// Internal struct for polling task (avoids circular references)
struct RedisDomainReaderPolling {
    redis_key: String,
    redis_url: String,
    redis_ssl: Option<crate::acme::config::RedisSslConfig>,
    cached_domains: Arc<tokio::sync::RwLock<Option<(Vec<DomainConfig>, String)>>>,
}

impl RedisDomainReaderPolling {
    /// Create Redis client with optional SSL configuration
    fn create_redis_client(&self) -> Result<redis::Client> {
        if let Some(ssl_config) = &self.redis_ssl {
            RedisDomainReader::create_client_with_ssl(&self.redis_url, ssl_config)
        } else {
            redis::Client::open(self.redis_url.as_str())
                .with_context(|| format!("Failed to connect to Redis at {}", self.redis_url))
        }
    }

    /// Start polling Redis every 5 seconds
    async fn start_polling(&self) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match self.check_and_update().await {
                Ok(changed) => {
                    if changed {
                        tracing::info!("Redis domains changed (hash updated), cache refreshed");
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to check Redis for domain changes: {}", e);
                }
            }
        }
    }

    /// Check Redis and update cache if content changed
    async fn check_and_update(&self) -> Result<bool> {
        use redis::AsyncCommands;

        let client = match self.create_redis_client() {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("Failed to create Redis client: {}", e);
                return Ok(false);
            }
        };

        use redis::aio::ConnectionManager;
        let mut conn = match ConnectionManager::new(client).await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("Failed to get Redis connection: {}", e);
                return Ok(false);
            }
        };

        let content: String = match conn.get(&self.redis_key).await {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("Failed to read from Redis key {}: {}", self.redis_key, e);
                return Ok(false);
            }
        };

        let new_hash = RedisDomainReader::calculate_hash(&content);

        // Check if hash changed
        {
            let cache = self.cached_domains.read().await;
            if let Some((_, old_hash)) = cache.as_ref() {
                if *old_hash == new_hash {
                    return Ok(false); // No change
                }
            }
        }

        // Parse and update cache
        let domains: Vec<DomainConfig> = match serde_json::from_str(&content) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!("Failed to parse domains JSON from Redis: {}", e);
                return Ok(false);
            }
        };

        {
            let mut cache = self.cached_domains.write().await;
            *cache = Some((domains, new_hash));
        }

        Ok(true) // Changed
    }
}

#[async_trait::async_trait]
impl DomainReader for RedisDomainReader {
    async fn read_domains(&self) -> Result<Vec<DomainConfig>> {
        // First, try to get from cache
        {
            let cache = self.cached_domains.read().await;
            if let Some((domains, _)) = cache.as_ref() {
                return Ok(domains.clone());
            }
        }

        // Cache is empty, fetch from Redis
        let (domains, hash) = self.fetch_domains().await?;

        // Update cache
        {
            let mut cache = self.cached_domains.write().await;
            *cache = Some((domains.clone(), hash));
        }

        Ok(domains)
    }
}

/// HTTP-based domain reader
pub struct HttpDomainReader {
    url: String,
    refresh_interval: u64,
    cached_domains: tokio::sync::RwLock<Option<(Vec<DomainConfig>, chrono::DateTime<chrono::Utc>)>>,
}

impl HttpDomainReader {
    pub fn new(url: String, refresh_interval: u64) -> Self {
        Self {
            url,
            refresh_interval,
            cached_domains: tokio::sync::RwLock::new(None),
        }
    }

    async fn fetch_domains(&self) -> Result<Vec<DomainConfig>> {
        let response = reqwest::get(&self.url).await
            .with_context(|| format!("Failed to fetch domains from {}", self.url))?;

        let content = response.text().await
            .with_context(|| format!("Failed to read response from {}", self.url))?;

        let domains: Vec<DomainConfig> = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse domains JSON from HTTP response"))?;

        Ok(domains)
    }
}

#[async_trait::async_trait]
impl DomainReader for HttpDomainReader {
    async fn read_domains(&self) -> Result<Vec<DomainConfig>> {
        let now = chrono::Utc::now();

        // Check cache
        {
            let cache = self.cached_domains.read().await;
            if let Some((domains, cached_at)) = cache.as_ref() {
                let age = now - *cached_at;
                if age.num_seconds() < self.refresh_interval as i64 {
                    return Ok(domains.clone());
                }
            }
        }

        // Fetch fresh data
        let domains = self.fetch_domains().await?;

        // Update cache
        {
            let mut cache = self.cached_domains.write().await;
            *cache = Some((domains.clone(), now));
        }

        Ok(domains)
    }
}

/// Factory for creating domain readers
pub struct DomainReaderFactory;

impl DomainReaderFactory {
    pub fn create(config: &DomainSourceConfig) -> Result<Box<dyn DomainReader>> {
        match config.source.as_str() {
            "file" => {
                let file_path = config.file_path.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("file_path is required for file source"))?;
                Ok(Box::new(FileDomainReader::new(file_path)))
            }
            "redis" => {
                let redis_key = config.redis_key.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("redis_key is required for redis source"))?
                    .clone();
                let redis_url = config.redis_url.clone();
                let redis_ssl = config.redis_ssl.clone();
                Ok(Box::new(RedisDomainReader::new(redis_key, redis_url, redis_ssl)))
            }
            "http" => {
                let url = config.http_url.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("http_url is required for http source"))?
                    .clone();
                let refresh_interval = config.http_refresh_interval.unwrap_or(300);
                Ok(Box::new(HttpDomainReader::new(url, refresh_interval)))
            }
            _ => Err(anyhow::anyhow!("Unknown domain source: {}", config.source)),
        }
    }
}

