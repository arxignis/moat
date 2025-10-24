use std::sync::Arc;
use std::time::Duration;
use reqwest::Client;
use anyhow::{Context, Result};

/// Shared HTTP client configuration with keepalive settings
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub keepalive_timeout: Duration,
    pub max_idle_per_host: usize,
    pub user_agent: String,
    pub danger_accept_invalid_certs: bool,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            keepalive_timeout: Duration::from_secs(60), // Keep connections alive for 60 seconds
            max_idle_per_host: 10, // Allow up to 10 idle connections per host
            user_agent: format!("Moat/{}", env!("CARGO_PKG_VERSION")),
            danger_accept_invalid_certs: false,
        }
    }
}

/// Shared HTTP client with keepalive configuration
pub struct SharedHttpClient {
    client: Arc<Client>,
    config: HttpClientConfig,
}

impl SharedHttpClient {
    /// Create a new shared HTTP client with the given configuration
    pub fn new(config: HttpClientConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .tcp_keepalive(config.keepalive_timeout)
            .pool_max_idle_per_host(config.max_idle_per_host)
            .user_agent(&config.user_agent)
            .danger_accept_invalid_certs(config.danger_accept_invalid_certs)
            .build()
            .context("Failed to create HTTP client with keepalive configuration")?;

        Ok(Self {
            client: Arc::new(client),
            config,
        })
    }

    /// Create a new shared HTTP client with default configuration
    pub fn with_defaults() -> Result<Self> {
        Self::new(HttpClientConfig::default())
    }

    /// Get a reference to the underlying HTTP client
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Get a clone of the client Arc for sharing across threads
    pub fn client_arc(&self) -> Arc<Client> {
        self.client.clone()
    }

    /// Get the current configuration
    pub fn config(&self) -> &HttpClientConfig {
        &self.config
    }

    /// Update the configuration and recreate the client
    pub fn update_config(&mut self, config: HttpClientConfig) -> Result<()> {
        let client = Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .tcp_keepalive(config.keepalive_timeout)
            .pool_max_idle_per_host(config.max_idle_per_host)
            .user_agent(&config.user_agent)
            .danger_accept_invalid_certs(config.danger_accept_invalid_certs)
            .build()
            .context("Failed to recreate HTTP client with new configuration")?;

        self.client = Arc::new(client);
        self.config = config;
        Ok(())
    }
}

/// Global shared HTTP client instance
static GLOBAL_HTTP_CLIENT: std::sync::OnceLock<Arc<SharedHttpClient>> = std::sync::OnceLock::new();

/// Initialize the global HTTP client with default configuration
pub fn init_global_client() -> Result<()> {
    let client = SharedHttpClient::with_defaults()?;
    GLOBAL_HTTP_CLIENT
        .set(Arc::new(client))
        .map_err(|_| anyhow::anyhow!("Global HTTP client already initialized"))?;
    Ok(())
}

/// Initialize the global HTTP client with custom configuration
pub fn init_global_client_with_config(config: HttpClientConfig) -> Result<()> {
    let client = SharedHttpClient::new(config)?;
    GLOBAL_HTTP_CLIENT
        .set(Arc::new(client))
        .map_err(|_| anyhow::anyhow!("Global HTTP client already initialized"))?;
    Ok(())
}

/// Get a reference to the global HTTP client
pub fn get_global_client() -> Result<Arc<SharedHttpClient>> {
    GLOBAL_HTTP_CLIENT
        .get()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Global HTTP client not initialized"))
}

/// Get a reference to the underlying reqwest Client from the global client
pub fn get_global_reqwest_client() -> Result<Arc<Client>> {
    let shared_client = get_global_client()?;
    Ok(shared_client.client_arc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_client_config_default() {
        let config = HttpClientConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert_eq!(config.keepalive_timeout, Duration::from_secs(60));
        assert_eq!(config.max_idle_per_host, 10);
        assert_eq!(config.user_agent, format!("Moat/{}", env!("CARGO_PKG_VERSION")));
        assert!(!config.danger_accept_invalid_certs);
    }

    #[test]
    fn test_shared_http_client_creation() {
        let config = HttpClientConfig::default();
        let client = SharedHttpClient::new(config).unwrap();
        assert_eq!(client.config().user_agent, format!("Moat/{}", env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn test_shared_http_client_with_defaults() {
        let client = SharedHttpClient::with_defaults().unwrap();
        assert_eq!(client.config().user_agent, format!("Moat/{}", env!("CARGO_PKG_VERSION")));
    }
}
