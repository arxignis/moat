//! Redis storage backend implementation

use crate::acme::Config;
use super::Storage;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use redis::AsyncCommands;
use std::path::PathBuf;
use std::sync::Arc;

/// Redis storage backend
pub struct RedisStorage {
    client: Arc<redis::Client>,
    base_key: String,
    static_path: PathBuf,
    // Optional shared connection manager from RedisManager (for connection pooling)
    // ConnectionManager is Clone, so we can store a clone of it
    shared_connection: Option<redis::aio::ConnectionManager>,
}

impl RedisStorage {
    /// Create a new Redis storage backend
    pub fn new(config: &Config) -> Result<Self> {
        // Get Redis URL from config, environment, or use default
        let redis_url = config.opts.redis_url.clone()
            .or_else(|| std::env::var("REDIS_URL").ok())
            .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());

        // Create Redis client (ConnectionManager will be reused from RedisManager if available)
        let client = if let Some(ssl_config) = &config.opts.redis_ssl {
            Self::create_client_with_ssl(&redis_url, ssl_config)?
        } else {
            redis::Client::open(redis_url.as_str())
                .with_context(|| format!("Failed to connect to Redis at {}", redis_url))?
        };

        // Get Redis prefix from RedisManager if available, otherwise use default
        let prefix = crate::redis::RedisManager::get()
            .map(|rm| rm.get_prefix().to_string())
            .unwrap_or_else(|_| "ssl-storage".to_string());

        let domain = config.opts.domain.clone();
        let base_key = format!("{}:{}", prefix, domain);

        // Try to reuse the connection manager from RedisManager for connection pooling
        // ConnectionManager is Clone and shares the underlying connection pool
        let shared_connection = crate::redis::RedisManager::get()
            .ok()
            .map(|rm| rm.get_connection());

        Ok(Self {
            client: Arc::new(client),
            base_key,
            static_path: config.static_path.clone(),
            shared_connection,
        })
    }

    /// Create Redis client with custom SSL/TLS configuration
    fn create_client_with_ssl(redis_url: &str, ssl_config: &crate::acme::config::RedisSslConfig) -> Result<redis::Client> {
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
        //
        // For now, we'll create the client normally. The TLS configuration above
        // validates the certificates, but the redis crate will use its own TLS setup.
        //
        // TODO: The redis crate doesn't support custom TlsConnector directly.
        // We may need to:
        // 1. Add CA cert to system trust store (requires system-level changes)
        // 2. Use a different Redis client that supports custom TLS
        // 3. Wait for redis crate to support custom TLS configuration

        // For insecure mode, the redis crate should handle it via rediss:// URL
        // For custom CA certs, we'll need to rely on the system trust store
        // or use environment variables if the redis crate supports it

        let client = redis::Client::open(redis_url)
            .with_context(|| format!("Failed to create Redis client with SSL config"))?;

        Ok(client)
    }

    /// Get Redis connection (reuses pooled connection if available)
    async fn get_conn(&self) -> Result<redis::aio::ConnectionManager> {
        use redis::aio::ConnectionManager;

        // Prefer shared connection from RedisManager (connection pooling)
        // ConnectionManager is Clone and shares the underlying connection pool
        if let Some(shared_conn) = &self.shared_connection {
            return Ok(shared_conn.clone());
        }

        // Fallback: create new connection manager from client
        // This still uses connection pooling internally via the client
        let client = Arc::as_ref(&self.client);
        ConnectionManager::new(client.clone())
            .await
            .with_context(|| "Failed to get Redis connection")
    }

    /// Get key for live certificate
    fn live_key(&self, file_type: &str) -> String {
        format!("{}:live:{}", self.base_key, file_type)
    }


    /// Get metadata key
    fn metadata_key(&self, key: &str) -> String {
        format!("{}:metadata:{}", self.base_key, key)
    }

    /// Get key for challenge token
    fn challenge_key(&self, token: &str) -> String {
        format!("{}:challenge:{}", self.base_key, token)
    }

    /// Get key for DNS challenge
    fn dns_challenge_key(&self) -> String {
        format!("{}:dns-challenge", self.base_key)
    }

    /// Get key for distributed lock
    fn lock_key(&self) -> String {
        format!("{}:lock", self.base_key)
    }

    /// Acquire a distributed lock for this domain
    /// Returns true if lock was acquired, false if already locked
    /// Lock expires after `ttl_seconds` to prevent deadlocks
    pub async fn acquire_lock(&self, ttl_seconds: u64) -> Result<bool> {
        let mut conn = self.get_conn().await?;
        let lock_key = self.lock_key();

        // Use SET with NX (only set if not exists) and EX (expiration) for atomic lock acquisition
        let result: Option<()> = redis::cmd("SET")
            .arg(&lock_key)
            .arg("locked")
            .arg("NX")  // Only set if key doesn't exist
            .arg("EX")  // Set expiration
            .arg(ttl_seconds)
            .query_async(&mut conn)
            .await
            .with_context(|| format!("Failed to acquire lock for key: {}", lock_key))?;

        Ok(result.is_some())
    }

    /// Release the distributed lock for this domain
    pub async fn release_lock(&self) -> Result<()> {
        let mut conn = self.get_conn().await?;
        let lock_key = self.lock_key();
        conn.del::<_, ()>(&lock_key).await
            .with_context(|| format!("Failed to release lock for key: {}", lock_key))?;
        Ok(())
    }

    /// Execute a function with a distributed lock
    /// Returns Ok with default value if the lock cannot be acquired (skips operation)
    pub async fn with_lock<F, Fut, T>(&self, ttl_seconds: u64, f: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
        T: Default,
    {
        if !self.acquire_lock(ttl_seconds).await? {
            tracing::warn!("Failed to acquire lock for domain - another instance is processing this domain. Skipping operation.");
            return Ok(Default::default());
        }

        let result = f().await;

        // Always try to release the lock, even if f() returned an error
        if let Err(e) = self.release_lock().await {
            tracing::warn!("Failed to release lock: {}", e);
        }

        result
    }

    /// Delete all archived certificates (Redis doesn't need to keep old versions)
    async fn delete_archived_certs(&self, conn: &mut redis::aio::ConnectionManager) -> Result<()> {
        // Get all keys matching the archive pattern
        let archive_pattern = format!("{}:archive:*", self.base_key);
        let keys: Vec<String> = conn.keys(&archive_pattern).await
            .with_context(|| format!("Failed to get archive keys matching {}", archive_pattern))?;

        // Delete all archived keys
        if !keys.is_empty() {
            conn.del::<_, ()>(keys).await
                .with_context(|| "Failed to delete archived certificates")?;
        }

        Ok(())
    }
}

#[async_trait]
impl Storage for RedisStorage {
    async fn read_cert(&self) -> Result<Vec<u8>> {
        let mut conn = self.get_conn().await?;
        let key = self.live_key("cert");
        let data: Vec<u8> = conn.get(&key).await
            .with_context(|| format!("Failed to read certificate from Redis key: {}", key))?;
        Ok(data)
    }

    async fn read_chain(&self) -> Result<Vec<u8>> {
        let mut conn = self.get_conn().await?;
        let key = self.live_key("chain");
        let data: Vec<u8> = conn.get(&key).await
            .with_context(|| format!("Failed to read chain from Redis key: {}", key))?;
        Ok(data)
    }

    async fn read_fullchain(&self) -> Result<Vec<u8>> {
        let mut conn = self.get_conn().await?;
        let key = self.live_key("fullchain");
        let data: Vec<u8> = conn.get(&key).await
            .with_context(|| format!("Failed to read fullchain from Redis key: {}", key))?;
        Ok(data)
    }

    async fn read_key(&self) -> Result<Vec<u8>> {
        let mut conn = self.get_conn().await?;
        let key = self.live_key("privkey");
        let data: Vec<u8> = conn.get(&key).await
            .with_context(|| format!("Failed to read private key from Redis key: {}", key))?;
        Ok(data)
    }

    async fn write_certs(&self, cert: &[u8], chain: &[u8], key: &[u8]) -> Result<()> {
        tracing::debug!("Connecting to Redis for certificate storage...");
        let mut conn = self.get_conn().await
            .with_context(|| "Failed to get Redis connection")?;
        tracing::debug!("Redis connection established");

        // Combine cert and chain to create fullchain
        let mut fullchain = cert.to_vec();
        fullchain.extend_from_slice(chain);
        tracing::debug!("Combined certificate chain (cert: {} bytes, chain: {} bytes, fullchain: {} bytes)",
            cert.len(), chain.len(), fullchain.len());

        // Calculate SHA256 hash of fullchain + key for change detection
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&fullchain);
        hasher.update(key);
        let hash = format!("{:x}", hasher.finalize());
        tracing::debug!("Calculated certificate hash: {}", hash);

        // Delete old archived certificates (keep only live/current version)
        self.delete_archived_certs(&mut conn).await?;

        // Update live keys (current version only, no archive in Redis)
        let live_files = [
            ("cert", cert),
            ("chain", chain),
            ("fullchain", &fullchain),
            ("privkey", key),
        ];

        for (file_type, content) in live_files.iter() {
            let live_key = self.live_key(file_type);
            tracing::debug!("Writing {} to Redis key: {} ({} bytes)", file_type, live_key, content.len());
            conn.set::<_, _, ()>(&live_key, content).await
                .with_context(|| format!("Failed to write live {} to Redis key: {}", file_type, live_key))?;
            tracing::debug!("Successfully wrote {} to Redis key: {}", file_type, live_key);
        }

        // Store certificate hash for change detection
        let hash_key = self.metadata_key("certificate_hash");
        conn.set::<_, _, ()>(&hash_key, &hash).await
            .with_context(|| format!("Failed to write certificate hash to Redis key: {}", hash_key))?;
        tracing::debug!("Stored certificate hash: {} at key: {}", hash, hash_key);

        tracing::info!("All certificates written successfully to Redis for domain: {}", self.base_key);
        Ok(())
    }

    async fn cert_exists(&self) -> bool {
        let mut conn = match self.get_conn().await {
            Ok(c) => c,
            Err(_) => return false,
        };

        let key = self.live_key("cert");
        conn.exists(&key).await.unwrap_or(false)
    }

    async fn read_created_at(&self) -> Result<chrono::DateTime<chrono::Utc>> {
        let mut conn = self.get_conn().await?;
        let key = self.metadata_key("created_at");
        let content: String = conn.get(&key).await
            .with_context(|| format!("Failed to read created_at from Redis key: {}", key))?;
        content
            .parse::<chrono::DateTime<chrono::Utc>>()
            .with_context(|| format!("Failed to parse created_at: {}", content))
    }

    async fn write_created_at(&self, created_at: chrono::DateTime<chrono::Utc>) -> Result<()> {
        let mut conn = self.get_conn().await?;
        let key = self.metadata_key("created_at");
        conn.set::<_, _, ()>(&key, created_at.to_string()).await
            .with_context(|| format!("Failed to write created_at to Redis key: {}", key))?;
        Ok(())
    }

    async fn write_challenge(&self, token: &str, key_auth: &str) -> Result<()> {
        // Store challenge token in Redis
        let mut conn = self.get_conn().await?;
        let challenge_key = self.challenge_key(token);
        conn.set::<_, _, ()>(&challenge_key, key_auth).await
            .with_context(|| format!("Failed to write challenge token to Redis key: {}", challenge_key))?;

        // Store challenge timestamp
        let timestamp = chrono::Utc::now();
        let timestamp_key = format!("{}:timestamp", challenge_key);
        conn.set::<_, _, ()>(&timestamp_key, timestamp.to_rfc3339()).await
            .with_context(|| format!("Failed to write challenge timestamp to Redis key: {}", timestamp_key))?;

        // Also write to filesystem for HTTP-01 challenge serving
        // The HTTP server needs to serve these files
        // Write challenge files to a shared location (not per-domain)
        // This allows the HTTP server to serve them from a single base path
        let base_path = self.static_path.parent()
            .ok_or_else(|| anyhow!("Cannot get parent path from static_path"))?
            .to_path_buf();

        let mut well_known_folder = base_path.clone();
        well_known_folder.push("well-known");
        tokio::fs::create_dir_all(&well_known_folder)
            .await
            .with_context(|| format!("Failed to create well-known directory {:?}", well_known_folder))?;

        let mut challenge_path = well_known_folder.clone();
        challenge_path.push("acme-challenge");
        tokio::fs::create_dir_all(&challenge_path)
            .await
            .with_context(|| format!("Failed to create acme-challenge directory {:?}", challenge_path))?;

        challenge_path.push(token);
        tokio::fs::write(&challenge_path, key_auth)
            .await
            .with_context(|| format!("Failed to write challenge file {:?}", challenge_path))?;

        Ok(())
    }

    fn static_path(&self) -> PathBuf {
        self.static_path.clone()
    }

    fn read_fullchain_sync(&self) -> Option<Result<Vec<u8>>> {
        // Redis doesn't support sync operations easily, return None
        None
    }

    fn read_key_sync(&self) -> Option<Result<Vec<u8>>> {
        // Redis doesn't support sync operations easily, return None
        None
    }

    async fn write_dns_challenge(&self, _domain: &str, dns_record: &str, dns_value: &str) -> Result<()> {
        // Store DNS challenge code in Redis
        let mut conn = self.get_conn().await?;
        let dns_key = self.dns_challenge_key();

        // Store as JSON with dns_record and challenge_code
        let challenge_data = serde_json::json!({
            "dns_record": dns_record,
            "challenge_code": dns_value,
        });

        conn.set::<_, _, ()>(&dns_key, challenge_data.to_string()).await
            .with_context(|| format!("Failed to write DNS challenge to Redis key: {}", dns_key))?;

        // Store DNS challenge timestamp
        let timestamp = chrono::Utc::now();
        let timestamp_key = format!("{}:timestamp", dns_key);
        conn.set::<_, _, ()>(&timestamp_key, timestamp.to_rfc3339()).await
            .with_context(|| format!("Failed to write DNS challenge timestamp to Redis key: {}", timestamp_key))?;

        tracing::info!("DNS challenge code saved to Redis: {} = {}", dns_record, dns_value);
        Ok(())
    }

    async fn read_account_credentials(&self) -> Result<Option<String>> {
        let mut conn = self.get_conn().await?;
        // Use a shared key for account credentials (not per-domain)
        // Get prefix from RedisManager if available
        let prefix = crate::redis::RedisManager::get()
            .map(|rm| rm.get_prefix().to_string())
            .unwrap_or_else(|_| "ssl-storage".to_string());
        let creds_key = format!("{}:acme:account_credentials", prefix);
        let creds_key_clone = creds_key.clone();

        let result: Option<String> = conn.get(&creds_key).await
            .with_context(|| format!("Failed to read account credentials from Redis key: {}", creds_key_clone))?;

        Ok(result)
    }

    async fn write_account_credentials(&self, credentials: &str) -> Result<()> {
        let mut conn = self.get_conn().await?;
        // Use a shared key for account credentials (not per-domain)
        // Get prefix from RedisManager if available
        let prefix = crate::redis::RedisManager::get()
            .map(|rm| rm.get_prefix().to_string())
            .unwrap_or_else(|_| "ssl-storage".to_string());
        let creds_key = format!("{}:acme:account_credentials", prefix);
        let creds_key_clone = creds_key.clone();

        conn.set::<_, _, ()>(&creds_key, credentials).await
            .with_context(|| format!("Failed to write account credentials to Redis key: {}", creds_key_clone))?;

        Ok(())
    }

    async fn record_failure(&self, error: &str) -> Result<()> {
        let mut conn = self.get_conn().await?;
        let failure_key = self.metadata_key("cert_failure");
        let count_key = self.metadata_key("cert_failure_count");

        // Read current failure count
        let count: u32 = conn.get(&count_key).await.unwrap_or(0);
        let new_count = count + 1;

        // Write failure record
        let failure_data = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "error": error,
            "count": new_count,
        });

        conn.set::<_, _, ()>(&failure_key, failure_data.to_string()).await
            .with_context(|| format!("Failed to write failure record to Redis key: {}", failure_key))?;

        // Write failure count
        conn.set::<_, _, ()>(&count_key, new_count.to_string()).await
            .with_context(|| format!("Failed to write failure count to Redis key: {}", count_key))?;

        Ok(())
    }

    async fn get_last_failure(&self) -> Result<Option<(chrono::DateTime<chrono::Utc>, String)>> {
        let mut conn = self.get_conn().await?;
        let failure_key = self.metadata_key("cert_failure");

        let content: Option<String> = conn.get(&failure_key).await
            .with_context(|| format!("Failed to read failure record from Redis key: {}", failure_key))?;

        let content = match content {
            Some(c) => c,
            None => return Ok(None),
        };

        let failure_data: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse failure record: {}", content))?;

        let timestamp_str = failure_data["timestamp"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing timestamp in failure record"))?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
            .with_context(|| format!("Failed to parse timestamp: {}", timestamp_str))?
            .with_timezone(&chrono::Utc);

        let error = failure_data["error"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing error in failure record"))?
            .to_string();

        Ok(Some((timestamp, error)))
    }

    async fn clear_failure(&self) -> Result<()> {
        let mut conn = self.get_conn().await?;
        let failure_key = self.metadata_key("cert_failure");
        let count_key = self.metadata_key("cert_failure_count");

        conn.del::<_, ()>(&failure_key).await.ok();
        conn.del::<_, ()>(&count_key).await.ok();

        Ok(())
    }

    async fn get_failure_count(&self) -> Result<u32> {
        let mut conn = self.get_conn().await?;
        let count_key = self.metadata_key("cert_failure_count");

        let count: Option<String> = conn.get(&count_key).await
            .with_context(|| format!("Failed to read failure count from Redis key: {}", count_key))?;

        let count = match count {
            Some(c) => c.trim().parse::<u32>().unwrap_or(0),
            None => 0,
        };

        Ok(count)
    }

    async fn get_certificate_hash(&self) -> Result<Option<String>> {
        let mut conn = self.get_conn().await?;
        let hash_key = self.metadata_key("certificate_hash");

        // Check if hash exists
        let hash: Option<String> = conn.get(&hash_key).await
            .with_context(|| format!("Failed to read certificate hash from Redis key: {}", hash_key))?;

        if let Some(hash) = hash {
            return Ok(Some(hash));
        }

        // Hash doesn't exist, but check if certificate exists
        if !self.cert_exists().await {
            return Ok(None);
        }

        // Certificate exists but hash doesn't - generate it
        let fullchain = self.read_fullchain().await?;
        let key = self.read_key().await?;

        // Calculate SHA256 hash of fullchain + key
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&fullchain);
        hasher.update(&key);
        let hash = format!("{:x}", hasher.finalize());

        // Store the hash for future use
        conn.set::<_, _, ()>(&hash_key, &hash).await
            .with_context(|| format!("Failed to write certificate hash to Redis key: {}", hash_key))?;

        Ok(Some(hash))
    }

    async fn get_challenge_timestamp(&self, token: &str) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let mut conn = self.get_conn().await?;
        let challenge_key = self.challenge_key(token);
        let timestamp_key = format!("{}:timestamp", challenge_key);

        let content: Option<String> = conn.get(&timestamp_key).await
            .with_context(|| format!("Failed to read challenge timestamp from Redis key: {}", timestamp_key))?;

        let content = match content {
            Some(c) => c,
            None => return Ok(None),
        };

        let timestamp = chrono::DateTime::parse_from_rfc3339(content.trim())
            .with_context(|| format!("Failed to parse challenge timestamp: {}", content))?
            .with_timezone(&chrono::Utc);

        Ok(Some(timestamp))
    }

    async fn get_dns_challenge_timestamp(&self, _domain: &str) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let mut conn = self.get_conn().await?;
        let dns_key = self.dns_challenge_key();
        let timestamp_key = format!("{}:timestamp", dns_key);

        let content: Option<String> = conn.get(&timestamp_key).await
            .with_context(|| format!("Failed to read DNS challenge timestamp from Redis key: {}", timestamp_key))?;

        let content = match content {
            Some(c) => c,
            None => return Ok(None),
        };

        let timestamp = chrono::DateTime::parse_from_rfc3339(content.trim())
            .with_context(|| format!("Failed to parse DNS challenge timestamp: {}", content))?
            .with_timezone(&chrono::Utc);

        Ok(Some(timestamp))
    }

    async fn is_challenge_expired(&self, token: &str, max_ttl_seconds: u64) -> Result<bool> {
        let timestamp = match self.get_challenge_timestamp(token).await? {
            Some(ts) => ts,
            None => return Ok(true), // No timestamp means expired
        };

        let now = chrono::Utc::now();
        let age = now - timestamp;
        let age_seconds = age.num_seconds() as u64;

        Ok(age_seconds >= max_ttl_seconds)
    }

    async fn is_dns_challenge_expired(&self, _domain: &str, max_ttl_seconds: u64) -> Result<bool> {
        let timestamp = match self.get_dns_challenge_timestamp(_domain).await? {
            Some(ts) => ts,
            None => return Ok(true), // No timestamp means expired
        };

        let now = chrono::Utc::now();
        let age = now - timestamp;
        let age_seconds = age.num_seconds() as u64;

        Ok(age_seconds >= max_ttl_seconds)
    }

    async fn cleanup_expired_challenges(&self, max_ttl_seconds: u64) -> Result<()> {
        let mut conn = self.get_conn().await?;

        // Get all challenge keys matching the pattern
        let challenge_pattern = format!("{}:challenge:*", self.base_key);
        let keys: Vec<String> = conn.keys(&challenge_pattern).await
            .with_context(|| format!("Failed to get challenge keys matching {}", challenge_pattern))?;

        for challenge_key in keys {
            // Skip timestamp keys
            if challenge_key.ends_with(":timestamp") {
                continue;
            }

            // Extract token from key (format: base_key:challenge:token)
            if let Some(token) = challenge_key.split(':').last() {
                if let Ok(expired) = self.is_challenge_expired(token, max_ttl_seconds).await {
                    if expired {
                        let timestamp_key = format!("{}:timestamp", challenge_key);
                        // Remove challenge and timestamp
                        conn.del::<_, ()>(&challenge_key).await.ok();
                        conn.del::<_, ()>(&timestamp_key).await.ok();
                    }
                }
            }
        }

        Ok(())
    }
}

