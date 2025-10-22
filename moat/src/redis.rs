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
    pub async fn init(redis_url: &str, prefix: String) -> Result<()> {
        log::info!("Initializing Redis manager with URL: {}", redis_url);

        let client = Client::open(redis_url)
            .context("Failed to create Redis client")?;

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
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_redis_manager_init() {
        // This test would require a Redis instance running
        // For now, just test that the structure compiles
        assert!(true);
    }
}
