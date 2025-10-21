use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use clap::ValueEnum;

use crate::ssl::TlsMode;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// HTTP control-plane bind address.
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub control_addr: SocketAddr,

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

    /// Upstream origin URL (required unless TLS is disabled).
    #[arg(long)]
    pub upstream: String,

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
    #[arg(long, default_value = "arxignis:acme")]
    pub redis_prefix: String,

    /// The network interface to attach the XDP program to.
    #[arg(short, long, default_value = "eth0")]
    pub iface: String,

    /// Additional network interfaces for XDP attach (comma-separated). If set, overrides --iface.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub ifaces: Vec<String>,

    #[arg(long)]
    pub arxignis_api_key: String,

    /// Base URL for Arx Ignis API.
    #[arg(long, default_value = "https://api.arxignis.com/v1")]
    pub arxignis_base_url: String,

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
