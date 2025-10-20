use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;

use crate::ssl::TlsMode;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// HTTP control-plane bind address.
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub control_addr: SocketAddr,

    /// HTTPS reverse-proxy bind address.
    #[arg(long, default_value = "0.0.0.0:8443")]
    pub tls_addr: SocketAddr,

    /// TLS operating mode.
    #[arg(long, value_enum, default_value_t = TlsMode::Disabled)]
    pub tls_mode: TlsMode,

    /// Upstream origin URL (required unless TLS is disabled).
    #[arg(long)]
    pub upstream: Option<String>,

    /// Path to custom certificate (PEM) when using custom TLS mode.
    #[arg(long)]
    pub tls_cert_path: Option<PathBuf>,

    /// Path to custom private key (PEM) when using custom TLS mode.
    #[arg(long)]
    pub tls_key_path: Option<PathBuf>,

    /// Domains for ACME certificate issuance (comma separated or repeated).
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    pub acme_domains: Vec<String>,

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
}
