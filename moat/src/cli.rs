use std::{net::SocketAddr, path::PathBuf, env};

use anyhow::Result;
use clap::Parser;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::http::TlsMode;
use crate::actions::captcha::CaptchaProvider;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub acme: AcmeConfig,
    pub redis: RedisConfig,
    pub network: NetworkConfig,
    pub arxignis: ArxignisConfig,
    pub domains: DomainConfig,
    pub content_scanning: ContentScanningCliConfig,
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub http_addr: String,
    pub http_bind: Vec<String>,
    pub tls_addr: String,
    pub tls_bind: Vec<String>,
    pub upstream: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub mode: String,
    pub only: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    pub wildcards: Vec<String>,
    pub contacts: Vec<String>,
    pub use_prod: bool,
    pub directory: Option<String>,
    pub accept_tos: bool,
    pub ca_root: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub iface: String,
    pub ifaces: Vec<String>,
    pub disable_xdp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArxignisConfig {
    pub api_key: String,
    #[serde(default = "default_base_url")]
    pub base_url: String,
    pub captcha: CaptchaConfig,
}

fn default_base_url() -> String {
    "https://api.arxignis.com/v1".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    pub whitelist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentScanningCliConfig {
    #[serde(default = "default_scanning_enabled")]
    pub enabled: bool,
    #[serde(default = "default_clamav_server")]
    pub clamav_server: String,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize,
    #[serde(default)]
    pub scan_content_types: Vec<String>,
    #[serde(default)]
    pub skip_extensions: Vec<String>,
    #[serde(default = "default_scan_expression")]
    pub scan_expression: String,
}

fn default_scanning_enabled() -> bool { false }
fn default_clamav_server() -> String { "localhost:3310".to_string() }
fn default_max_file_size() -> usize { 10 * 1024 * 1024 }
fn default_scan_expression() -> String { "http.request.method eq \"POST\" or http.request.method eq \"PUT\"".to_string() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptchaConfig {
    pub site_key: Option<String>,
    pub secret_key: Option<String>,
    pub jwt_secret: Option<String>,
    pub provider: String,
    pub token_ttl: u64,
    pub cache_ttl: u64,
}

impl Config {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn default() -> Self {
        Self {
            server: ServerConfig {
                http_addr: "0.0.0.0:80".to_string(),
                http_bind: vec![],
                tls_addr: "0.0.0.0:443".to_string(),
                tls_bind: vec![],
                upstream: "http://localhost:8080".to_string(),
            },
            tls: TlsConfig {
                mode: "disabled".to_string(),
                only: false,
                cert_path: None,
                key_path: None,
            },
            acme: AcmeConfig {
                domains: vec![],
                wildcards: vec![],
                contacts: vec![],
                use_prod: false,
                directory: None,
                accept_tos: false,
                ca_root: None,
            },
            redis: RedisConfig {
                url: "redis://127.0.0.1/0".to_string(),
                prefix: "ax:moat".to_string(),
            },
            network: NetworkConfig {
                iface: "eth0".to_string(),
                ifaces: vec![],
                disable_xdp: false,
            },
            arxignis: ArxignisConfig {
                api_key: "".to_string(),
                base_url: "https://api.arxignis.com/v1".to_string(),
                captcha: CaptchaConfig {
                    site_key: None,
                    secret_key: None,
                    jwt_secret: None,
                    provider: "hcaptcha".to_string(),
                    token_ttl: 7200,
                    cache_ttl: 300,
                },
            },
            domains: DomainConfig {
                whitelist: vec![],
            },
            content_scanning: ContentScanningCliConfig {
                enabled: false,
                clamav_server: "localhost:3310".to_string(),
                max_file_size: 10 * 1024 * 1024,
                scan_content_types: vec![
                    "text/html".to_string(),
                    "application/x-www-form-urlencoded".to_string(),
                    "multipart/form-data".to_string(),
                    "application/json".to_string(),
                    "text/plain".to_string(),
                ],
                skip_extensions: vec![],
                scan_expression: default_scan_expression(),
            },
            logging: LoggingConfig {
                level: "info".to_string(),
            },
        }
    }

    pub fn merge_with_args(&mut self, args: &Args) {
        // Override config values with command line arguments if provided
        if !args.http_bind.is_empty() {
            self.server.http_bind = args.http_bind.iter().map(|addr| addr.to_string()).collect();
        }
        if !args.tls_bind.is_empty() {
            self.server.tls_bind = args.tls_bind.iter().map(|addr| addr.to_string()).collect();
        }
        if !args.acme_domains.is_empty() {
            self.acme.domains = args.acme_domains.clone();
        }
        if !args.domain_wildcards.is_empty() {
            self.acme.wildcards = args.domain_wildcards.clone();
        }
        if !args.domain_whitelist.is_empty() {
            self.domains.whitelist = args.domain_whitelist.clone();
        }
        if !args.ifaces.is_empty() {
            self.network.ifaces = args.ifaces.clone();
        }
        if let Some(api_key) = &args.arxignis_api_key {
            self.arxignis.api_key = api_key.clone();
        }
        if let Some(upstream) = &args.upstream {
            self.server.upstream = upstream.clone();
        }
        if let Some(base_url) = &args.arxignis_base_url {
            self.arxignis.base_url = base_url.clone();
        }
        if args.captcha_site_key.is_some() {
            self.arxignis.captcha.site_key = args.captcha_site_key.clone();
        }
        if args.captcha_secret_key.is_some() {
            self.arxignis.captcha.secret_key = args.captcha_secret_key.clone();
        }
        if args.captcha_jwt_secret.is_some() {
            self.arxignis.captcha.jwt_secret = args.captcha_jwt_secret.clone();
        }
        if let Some(provider) = &args.captcha_provider {
            self.arxignis.captcha.provider = format!("{:?}", provider).to_lowercase();
        }

        // Redis configuration overrides
        if !args.redis_url.is_empty() && args.redis_url != "redis://127.0.0.1/0" {
            self.redis.url = args.redis_url.clone();
        }
        if !args.redis_prefix.is_empty() && args.redis_prefix != "ax:moat" {
            self.redis.prefix = args.redis_prefix.clone();
        }
    }

    pub fn validate_required_fields(&mut self, args: &Args) -> Result<()> {
        // Check if upstream is provided either via CLI args or config file
        if args.upstream.is_none() && self.server.upstream.is_empty() {
            return Err(anyhow::anyhow!("Upstream URL is required. Provide it via --upstream argument or in config file"));
        }

        // Check if arxignis API key is provided either via CLI args or config file
        if args.arxignis_api_key.is_none() && self.arxignis.api_key.is_empty() {
            return Err(anyhow::anyhow!("Arxignis API key is required. Provide it via --arxignis-api-key argument or in config file"));
        }

        Ok(())
    }

    pub fn load_from_args(args: &Args) -> Result<Self> {
        let mut config = if let Some(config_path) = &args.config {
            Self::load_from_file(config_path)?
        } else {
            Self::default()
        };

        config.merge_with_args(args);
        config.apply_env_overrides();
        config.validate_required_fields(args)?;
        Ok(config)
    }

    pub fn apply_env_overrides(&mut self) {
        // Server configuration overrides
        if let Ok(val) = env::var("AX_SERVER_HTTP_ADDR") {
            self.server.http_addr = val;
        }
        if let Ok(val) = env::var("AX_SERVER_TLS_ADDR") {
            self.server.tls_addr = val;
        }
        if let Ok(val) = env::var("AX_SERVER_UPSTREAM") {
            self.server.upstream = val;
        }
        if let Ok(val) = env::var("AX_SERVER_HTTP_BIND") {
            self.server.http_bind = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = env::var("AX_SERVER_TLS_BIND") {
            self.server.tls_bind = val.split(',').map(|s| s.trim().to_string()).collect();
        }

        // TLS configuration overrides
        if let Ok(val) = env::var("AX_TLS_MODE") {
            self.tls.mode = val;
        }
        if let Ok(val) = env::var("AX_TLS_ONLY") {
            self.tls.only = val.parse().unwrap_or(false);
        }
        if let Ok(val) = env::var("AX_TLS_CERT_PATH") {
            self.tls.cert_path = Some(val);
        }
        if let Ok(val) = env::var("AX_TLS_KEY_PATH") {
            self.tls.key_path = Some(val);
        }

        // ACME configuration overrides
        if let Ok(val) = env::var("AX_ACME_DOMAINS") {
            self.acme.domains = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = env::var("AX_ACME_WILDCARDS") {
            self.acme.wildcards = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = env::var("AX_ACME_CONTACTS") {
            self.acme.contacts = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = env::var("AX_ACME_USE_PROD") {
            self.acme.use_prod = val.parse().unwrap_or(false);
        }
        if let Ok(val) = env::var("AX_ACME_DIRECTORY") {
            self.acme.directory = Some(val);
        }
        if let Ok(val) = env::var("AX_ACME_ACCEPT_TOS") {
            self.acme.accept_tos = val.parse().unwrap_or(false);
        }
        if let Ok(val) = env::var("AX_ACME_CA_ROOT") {
            self.acme.ca_root = Some(val);
        }

        // Redis configuration overrides
        if let Ok(val) = env::var("AX_REDIS_URL") {
            self.redis.url = val;
        }
        if let Ok(val) = env::var("AX_REDIS_PREFIX") {
            self.redis.prefix = val;
        }

        // Network configuration overrides
        if let Ok(val) = env::var("AX_NETWORK_IFACE") {
            self.network.iface = val;
        }
        if let Ok(val) = env::var("AX_NETWORK_IFACES") {
            self.network.ifaces = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = env::var("AX_NETWORK_DISABLE_XDP") {
            self.network.disable_xdp = val.parse().unwrap_or(false);
        }

        // Arx Ignis configuration overrides
        if let Ok(val) = env::var("AX_ARXIGNIS_API_KEY") {
            self.arxignis.api_key = val;
        }
        if let Ok(val) = env::var("AX_ARXIGNIS_BASE_URL") {
            self.arxignis.base_url = val;
        }

        // Domain configuration overrides
        if let Ok(val) = env::var("AX_DOMAINS_WHITELIST") {
            self.domains.whitelist = val.split(',').map(|s| s.trim().to_string()).collect();
        }

        // Logging configuration overrides
        if let Ok(val) = env::var("AX_LOGGING_LEVEL") {
            self.logging.level = val;
        }

        // Content scanning overrides
        if let Ok(val) = env::var("AX_CONTENT_SCANNING_ENABLED") {
            self.content_scanning.enabled = val.parse().unwrap_or(false);
        }
        if let Ok(val) = env::var("AX_CLAMAV_SERVER") {
            self.content_scanning.clamav_server = val;
        }
        if let Ok(val) = env::var("AX_CONTENT_MAX_FILE_SIZE") {
            self.content_scanning.max_file_size = val.parse().unwrap_or(10 * 1024 * 1024);
        }
        if let Ok(val) = env::var("AX_CONTENT_SCAN_CONTENT_TYPES") {
            self.content_scanning.scan_content_types = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = env::var("AX_CONTENT_SKIP_EXTENSIONS") {
            self.content_scanning.skip_extensions = val.split(',').map(|s| s.trim().to_string()).collect();
        }
        if let Ok(val) = env::var("AX_CONTENT_SCAN_EXPRESSION") {
            self.content_scanning.scan_expression = val;
        }

        // Captcha configuration overrides
        if let Ok(val) = env::var("AX_CAPTCHA_SITE_KEY") {
            self.arxignis.captcha.site_key = Some(val);
        }
        if let Ok(val) = env::var("AX_CAPTCHA_SECRET_KEY") {
            self.arxignis.captcha.secret_key = Some(val);
        }
        if let Ok(val) = env::var("AX_CAPTCHA_JWT_SECRET") {
            self.arxignis.captcha.jwt_secret = Some(val);
        }
        if let Ok(val) = env::var("AX_CAPTCHA_PROVIDER") {
            self.arxignis.captcha.provider = val;
        }
        if let Ok(val) = env::var("AX_CAPTCHA_TOKEN_TTL") {
            self.arxignis.captcha.token_ttl = val.parse().unwrap_or(7200);
        }
        if let Ok(val) = env::var("AX_CAPTCHA_CACHE_TTL") {
            self.arxignis.captcha.cache_ttl = val.parse().unwrap_or(300);
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Path to configuration file (YAML format)
    #[arg(long, short = 'c')]
    pub config: Option<PathBuf>,

    /// HTTP server bind address (for ACME HTTP-01 challenges and regular HTTP traffic).
    #[arg(long, default_value = "0.0.0.0:80")]
    pub http_addr: SocketAddr,

    /// Additional HTTP bind addresses (comma-separated). If set, overrides http_addr.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub http_bind: Vec<SocketAddr>,

    /// HTTPS reverse-proxy bind address.
    #[arg(long, default_value = "0.0.0.0:443")]
    pub tls_addr: SocketAddr,

    /// Additional HTTPS bind addresses (comma-separated). If set, overrides tls_addr.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub tls_bind: Vec<SocketAddr>,

    /// TLS operating mode.
    #[arg(long, value_enum, default_value_t = TlsMode::Disabled)]
    pub tls_mode: TlsMode,

    /// Require TLS for application traffic (HTTP used only for ACME).
    /// If enabled, plain HTTP requests (except ACME) will be rejected with 426.
    #[arg(long, default_value_t = false)]
    pub tls_only: bool,

    /// Upstream origin URL (required unless TLS is disabled or config file provided).
    #[arg(long)]
    pub upstream: Option<String>,

    /// Path to custom certificate (PEM) when using custom TLS mode.
    #[arg(long)]
    pub tls_cert_path: Option<PathBuf>,

    /// Path to custom private key (PEM) when using custom TLS mode.
    #[arg(long)]
    pub tls_key_path: Option<PathBuf>,

    /// Domains for ACME certificate issuance and domain whitelist (comma separated or repeated).
    /// These domains will be used for SSL certificate generation and domain filtering.
    /// Only requests to these domains (or matching wildcards) will be allowed.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub acme_domains: Vec<String>,

    /// Domain wildcard patterns for filtering (comma separated or repeated).
    /// Supports wildcards: *.example.com, api.*.example.com
    /// These are checked along with acme_domains (OR logic).
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub domain_wildcards: Vec<String>,

    /// ACME contact addresses (mailto: optional, comma separated or repeated).
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub acme_contacts: Vec<String>,

    /// Use Let's Encrypt production directory instead of staging.
    #[arg(long)]
    pub acme_use_prod: bool,

    /// Override ACME directory URL (useful for Pebble or other test CAs).
    #[arg(long)]
    pub acme_directory: Option<String>,

    /// Explicitly accept the ACME Terms of Service.
    #[arg(long, default_value_t = false)]
    pub acme_accept_tos: bool,

    /// Custom CA bundle for the ACME directory (PEM file).
    #[arg(long)]
    pub acme_ca_root: Option<PathBuf>,

    /// Redis connection URL for ACME cache storage.
    #[arg(long, default_value = "redis://127.0.0.1/0")]
    pub redis_url: String,

    /// Namespace prefix for Redis ACME cache entries.
    #[arg(long, default_value = "ax:moat")]
    pub redis_prefix: String,

    /// The network interface to attach the XDP program to.
    #[arg(short, long, default_value = "eth0")]
    pub iface: String,

    /// Additional network interfaces for XDP attach (comma-separated). If set, overrides --iface.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub ifaces: Vec<String>,

    #[arg(long)]
    pub arxignis_api_key: Option<String>,

    /// Base URL for Arx Ignis API.
    #[arg(long, default_value = "https://api.arxignis.com/v1")]
    pub arxignis_base_url: Option<String>,

    /// Domain whitelist (exact matches, comma separated or repeated).
    /// If specified, only requests to these domains will be allowed.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub domain_whitelist: Vec<String>,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Disable XDP packet filtering (run without BPF/XDP)
    #[arg(long, default_value_t = false)]
    pub disable_xdp: bool,

    /// Captcha site key for security verification
    #[arg(long)]
    pub captcha_site_key: Option<String>,

    /// Captcha secret key for security verification
    #[arg(long)]
    pub captcha_secret_key: Option<String>,

    /// JWT secret key for captcha token signing
    #[arg(long)]
    pub captcha_jwt_secret: Option<String>,

    /// Captcha provider (hcaptcha, recaptcha, turnstile)
    #[arg(long, value_enum)]
    pub captcha_provider: Option<CaptchaProvider>,


    /// Captcha token TTL in seconds
    #[arg(long, default_value = "7200")]
    pub captcha_token_ttl: u64,

    /// Captcha validation cache TTL in seconds
    #[arg(long, default_value = "300")]
    pub captcha_cache_ttl: u64,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn to_level_filter(self) -> log::LevelFilter {
        match self {
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Trace => log::LevelFilter::Trace,
        }
    }
}
