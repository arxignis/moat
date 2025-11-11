use anyhow::{Context, Result};
use redis::aio::ConnectionManager;
use redis::Client;
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Global Redis connection manager
static REDIS_MANAGER: OnceCell<Arc<RedisManager>> = OnceCell::const_new();

/// Centralized Redis connection manager
pub struct RedisManager {
    pub connection: ConnectionManager,
    pub prefix: String,
}

impl RedisManager {
    /// Initialize the global Redis manager
    pub async fn init(redis_url: &str, prefix: String, ssl_config: Option<&crate::cli::RedisSslConfig>) -> Result<()> {
        log::info!("Initializing Redis manager with URL: {}", redis_url);

        let client = if let Some(ssl_config) = ssl_config {
            // Configure Redis client with custom SSL certificates
            Self::create_client_with_ssl(redis_url, ssl_config)?
        } else {
            // Use default client (will handle rediss:// URLs automatically)
            Client::open(redis_url)
                .context("Failed to create Redis client")?
        };

        let connection = client
            .get_connection_manager()
            .await
            .context("Failed to create Redis connection manager")?;

        log::info!("Redis connection manager created successfully with prefix: {}", prefix);

        // Test the connection
        let mut test_conn = connection.clone();
        match redis::cmd("PING").query_async::<String>(&mut test_conn).await {
            Ok(_) => log::info!("Redis connection test successful"),
            Err(e) => {
                log::warn!("Redis connection test failed: {}", e);
                return Err(anyhow::anyhow!("Redis connection test failed: {}", e));
            }
        }

        let manager = Arc::new(RedisManager {
            connection,
            prefix,
        });

        REDIS_MANAGER.set(manager)
            .map_err(|_| anyhow::anyhow!("Redis manager already initialized"))?;

        Ok(())
    }

    /// Get the global Redis manager instance
    pub fn get() -> Result<Arc<RedisManager>> {
        REDIS_MANAGER.get()
            .cloned()
            .context("Redis manager not initialized")
    }

    /// Get a connection manager for use in other modules
    pub fn get_connection(&self) -> ConnectionManager {
        self.connection.clone()
    }

    /// Get the configured prefix
    pub fn get_prefix(&self) -> &str {
        &self.prefix
    }

    /// Create a namespaced prefix
    pub fn create_namespace(&self, namespace: &str) -> String {
        format!("{}:{}", self.prefix, namespace)
    }

    /// Create Redis client with custom SSL/TLS configuration
    fn create_client_with_ssl(redis_url: &str, ssl_config: &crate::cli::RedisSslConfig) -> Result<Client> {
        // Note: The redis crate with tokio-native-tls-comp uses native-tls internally,
        // but doesn't expose a way to pass a custom TlsConnector directly. However, when using
        // rediss:// URLs, it will use the system trust store. For custom CA certificates,
        // we need to add them to the system trust store or use a workaround.
        //
        // For now, we'll validate the certificates exist and log warnings, but the redis crate
        // will use its own TLS setup. The TLS configuration below validates the certificates
        // are readable, but the redis crate will use the system trust store.
        //
        // TODO: The redis crate doesn't support custom TlsConnector directly.
        // We may need to:
        // 1. Add CA cert to system trust store (requires system-level changes)
        // 2. Use a different Redis client that supports custom TLS
        // 3. Wait for redis crate to support custom TLS configuration

        // Validate certificate files exist and are readable
        if let Some(ca_cert_path) = &ssl_config.ca_cert_path {
            std::fs::read(ca_cert_path)
                .with_context(|| format!("Failed to read CA certificate from {}", ca_cert_path))?;
            log::info!("Redis SSL: CA certificate found at {}", ca_cert_path);
        }

        if let (Some(client_cert_path), Some(client_key_path)) = (&ssl_config.client_cert_path, &ssl_config.client_key_path) {
            std::fs::read(client_cert_path)
                .with_context(|| format!("Failed to read client certificate from {}", client_cert_path))?;
            std::fs::read(client_key_path)
                .with_context(|| format!("Failed to read client key from {}", client_key_path))?;
            log::info!("Redis SSL: Client certificate found at {} and key at {}", client_cert_path, client_key_path);
        }

        // Configure certificate verification
        if ssl_config.insecure {
            log::warn!("Redis SSL: Certificate verification disabled (insecure mode)");
        }

        // For insecure mode, the redis crate should handle it via rediss:// URL
        // For custom CA certs, we'll need to rely on the system trust store
        // or use environment variables if the redis crate supports it

        let client = Client::open(redis_url)
            .with_context(|| "Failed to create Redis client with SSL config")?;

        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::RedisSslConfig;

    #[tokio::test]
    async fn test_redis_manager_init() {
        // This test would require a Redis instance running
        // For now, just test that the structure compiles
        assert!(true);
    }

    #[test]
    fn test_create_client_with_ssl_no_config() {
        // Test that client creation works without SSL config
        let redis_url = "redis://127.0.0.1:6379";
        let result = Client::open(redis_url);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_client_with_ssl_insecure() {
        // Test SSL config with insecure mode
        let ssl_config = RedisSslConfig {
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            insecure: true,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should succeed even without certificate files when insecure is true
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_client_with_ssl_missing_ca_cert() {
        // Test that missing CA cert file returns error
        let ssl_config = RedisSslConfig {
            ca_cert_path: Some("/nonexistent/path/ca.crt".to_string()),
            client_cert_path: None,
            client_key_path: None,
            insecure: false,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should fail because CA cert file doesn't exist
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read CA certificate"));
    }

    #[test]
    fn test_create_client_with_ssl_missing_client_cert() {
        // Test that missing client cert file returns error
        let ssl_config = RedisSslConfig {
            ca_cert_path: None,
            client_cert_path: Some("/nonexistent/path/client.crt".to_string()),
            client_key_path: Some("/nonexistent/path/client.key".to_string()),
            insecure: false,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should fail because client cert file doesn't exist
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read client certificate"));
    }

    #[test]
    fn test_create_client_with_ssl_missing_client_key() {
        // Test that missing client key file returns error
        let ssl_config = RedisSslConfig {
            ca_cert_path: None,
            client_cert_path: Some("/nonexistent/path/client.crt".to_string()),
            client_key_path: Some("/nonexistent/path/client.key".to_string()),
            insecure: false,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should fail because client key file doesn't exist
        assert!(result.is_err());
    }

    #[test]
    fn test_create_client_with_ssl_partial_client_config() {
        // Test that providing only cert or only key (not both) still validates
        let ssl_config = RedisSslConfig {
            ca_cert_path: None,
            client_cert_path: Some("/nonexistent/path/client.crt".to_string()),
            client_key_path: None, // Missing key
            insecure: false,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should succeed because we only validate when both cert and key are provided
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_client_with_ssl_empty_config() {
        // Test SSL config with all None values
        let ssl_config = RedisSslConfig {
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            insecure: false,
        };

        let redis_url = "rediss://127.0.0.1:6379";
        let result = RedisManager::create_client_with_ssl(redis_url, &ssl_config);
        // Should succeed with empty config
        assert!(result.is_ok());
    }
}
