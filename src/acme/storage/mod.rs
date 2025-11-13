//! Storage backend abstraction for certificate storage.
//! Uses Redis as the only storage backend.

mod redis;

use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

pub use redis::RedisStorage;

/// Storage backend type (Redis only)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageType {
    /// Redis storage
    Redis,
}

/// Trait for certificate storage backends
#[async_trait]
pub trait Storage: Send + Sync {
    /// Read certificate from storage (from live directory)
    async fn read_cert(&self) -> Result<Vec<u8>>;

    /// Read certificate chain from storage (from live directory)
    async fn read_chain(&self) -> Result<Vec<u8>>;

    /// Read fullchain (cert + chain) from storage (from live directory)
    async fn read_fullchain(&self) -> Result<Vec<u8>>;

    /// Read private key from storage (from live directory)
    async fn read_key(&self) -> Result<Vec<u8>>;

    /// Write certificate, chain, and fullchain to storage (certbot-style)
    /// cert: The domain certificate
    /// chain: The intermediate certificate chain
    /// key: The private key
    async fn write_certs(&self, cert: &[u8], chain: &[u8], key: &[u8]) -> Result<()>;

    /// Get the SHA256 hash of the certificate (fullchain + key combined)
    /// Returns None if certificate doesn't exist
    async fn get_certificate_hash(&self) -> Result<Option<String>>;

    /// Check if certificate exists
    async fn cert_exists(&self) -> bool;

    /// Read certificate creation timestamp
    async fn read_created_at(&self) -> Result<chrono::DateTime<chrono::Utc>>;

    /// Write certificate creation timestamp
    async fn write_created_at(&self, created_at: chrono::DateTime<chrono::Utc>) -> Result<()>;

    /// Write challenge file for ACME HTTP-01 challenge
    async fn write_challenge(&self, token: &str, key_auth: &str) -> Result<()>;

    /// Write DNS challenge code for ACME DNS-01 challenge
    async fn write_dns_challenge(&self, domain: &str, dns_record: &str, dns_value: &str) -> Result<()>;

    /// Get the timestamp when a challenge was created
    /// Returns None if challenge doesn't exist or has no timestamp
    async fn get_challenge_timestamp(&self, token: &str) -> Result<Option<chrono::DateTime<chrono::Utc>>>;

    /// Get the timestamp when a DNS challenge was created
    /// Returns None if challenge doesn't exist or has no timestamp
    async fn get_dns_challenge_timestamp(&self, domain: &str) -> Result<Option<chrono::DateTime<chrono::Utc>>>;

    /// Check if a challenge is expired based on TTL
    async fn is_challenge_expired(&self, token: &str, max_ttl_seconds: u64) -> Result<bool>;

    /// Check if a DNS challenge is expired based on TTL
    async fn is_dns_challenge_expired(&self, domain: &str, max_ttl_seconds: u64) -> Result<bool>;

    /// Clean up expired challenges
    async fn cleanup_expired_challenges(&self, max_ttl_seconds: u64) -> Result<()>;

    /// Get the path for static files (well-known directory)
    fn static_path(&self) -> PathBuf;

    /// Read fullchain synchronously (for compatibility with sync APIs like rustls)
    /// Returns None if the storage backend doesn't support sync operations
    fn read_fullchain_sync(&self) -> Option<Result<Vec<u8>>> {
        None
    }

    /// Read private key synchronously (for compatibility with sync APIs like rustls)
    /// Returns None if the storage backend doesn't support sync operations
    fn read_key_sync(&self) -> Option<Result<Vec<u8>>> {
        None
    }

    /// Read ACME account credentials from storage
    /// Returns None if credentials don't exist
    async fn read_account_credentials(&self) -> Result<Option<String>>;

    /// Write ACME account credentials to storage
    async fn write_account_credentials(&self, credentials: &str) -> Result<()>;

    /// Record a certificate generation failure
    async fn record_failure(&self, error: &str) -> Result<()>;

    /// Get the last failure timestamp and error message
    /// Returns None if no failure was recorded
    async fn get_last_failure(&self) -> Result<Option<(chrono::DateTime<chrono::Utc>, String)>>;

    /// Clear failure record (called when certificate is successfully generated)
    async fn clear_failure(&self) -> Result<()>;

    /// Get the number of consecutive failures
    async fn get_failure_count(&self) -> Result<u32>;
}

/// Factory for creating storage backends
pub struct StorageFactory;

impl StorageFactory {
    /// Create a storage backend (Redis only)
    pub fn create(storage_type: StorageType, config: &crate::acme::Config) -> Result<Box<dyn Storage>> {
        match storage_type {
            StorageType::Redis => {
                Ok(Box::new(RedisStorage::new(config)?))
            }
        }
    }

    /// Create storage from AppConfig storage settings (Redis only)
    pub fn create_from_app_config(_app_config: &crate::acme::AppConfig, domain_config: &crate::acme::Config) -> Result<Box<dyn Storage>> {
        Self::create(StorageType::Redis, domain_config)
    }

    /// Create storage based on config settings (Redis only)
    pub fn create_default(config: &crate::acme::Config) -> Result<Box<dyn Storage>> {
        tracing::debug!("Creating Redis storage backend for domain: {}", config.opts.domain);
        Self::create(StorageType::Redis, config)
    }
}

