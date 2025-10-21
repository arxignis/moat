use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, ValueEnum};

use crate::ssl::TlsMode;

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// HTTP control-plane bind address.
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub control_addr: SocketAddr,

    /// HTTP server bind address (for ACME HTTP-01 challenges and regular HTTP traffic).
    #[arg(long, default_value = "0.0.0.0:80")]
    pub http_addr: SocketAddr,

    /// HTTPS reverse-proxy bind address.
    #[arg(long, default_value = "0.0.0.0:443")]
    pub tls_addr: SocketAddr,

    /// TLS operating mode.
    #[arg(long, value_enum, default_value_t = TlsMode::Disabled)]
    pub tls_mode: TlsMode,

    /// Require TLS for application traffic (HTTP used only for ACME).
    /// If enabled, plain HTTP requests (except ACME) will be rejected with 426.
    #[arg(long, default_value_t = false)]
    pub tls_only: bool,

    /// Upstream origin URL (required unless TLS is disabled).
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
    #[arg(long, default_value = "bpf-firewall:acme")]
    pub redis_prefix: String,

    /// The network interface to attach the XDP program to.
    #[arg(short, long, default_value = "eth0")]
    pub iface: String,

    #[arg(long)]
    pub arxignis_api_key: String,

    /// Base URL for Arx Ignis API.
    #[arg(long, default_value = "https://api.arxignis.com/v1")]
    pub arxignis_base_url: String,

    // TODO: make it be able to add a list of ids
    #[arg(long)]
    pub arxignis_rule_id: String,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Disable XDP packet filtering (run without BPF/XDP)
    #[arg(long, default_value_t = false)]
    pub disable_xdp: bool,

    /// Mode for Arxignis decisions: monitor or block
    #[arg(long, default_value = "monitor")]
    pub arxignis_mode: String,

    /// Optional CAPTCHA provider: turnstile|recaptcha|hcaptcha
    #[arg(long)]
    pub captcha_provider: Option<String>,

    /// CAPTCHA site key
    #[arg(long)]
    pub captcha_site_key: Option<String>,

    /// CAPTCHA secret key
    #[arg(long)]
    pub captcha_secret_key: Option<String>,

    /// Path to CAPTCHA HTML template
    #[arg(long)]
    pub captcha_template_path: Option<PathBuf>,

    /// HTTP status code for CAPTCHA page (default 200)
    #[arg(long, default_value_t = 200)]
    pub captcha_http_status_code: u16,
}
