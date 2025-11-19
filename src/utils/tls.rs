use dashmap::DashMap;
use log::{error, info, warn};
use pingora_core::tls::ssl::{select_next_proto, AlpnError, NameType, SniError, SslAlert, SslContext, SslFiletype, SslMethod, SslRef, SslVersion};
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::listeners::TlsAccept;
use rustls_pemfile::{read_one, Item};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use once_cell::sync::OnceCell;
use async_trait::async_trait;
use x509_parser::extensions::GeneralName;
use x509_parser::nom::Err as NomErr;
use x509_parser::prelude::*;

// Global certificate store for SNI callback
static GLOBAL_CERTIFICATES: OnceCell<Arc<Certificates>> = OnceCell::new();

/// Set the global certificates for SNI callback
pub fn set_global_certificates(certificates: Arc<Certificates>) {
    let _ = GLOBAL_CERTIFICATES.set(certificates);
}

/// Get the global certificates for SNI callback
fn get_global_certificates() -> Option<Arc<Certificates>> {
    GLOBAL_CERTIFICATES.get().cloned()
}

#[derive(Clone, Deserialize, Debug)]
pub struct CertificateConfig {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Clone, Debug)]
struct CertificateInfo {
    common_names: Vec<String>,
    alt_names: Vec<String>,
    ssl_context: SslContext,
    #[allow(dead_code)]
    cert_path: String, // Only used for logging
    #[allow(dead_code)]
    key_path: String, // Only used for logging
}

#[derive(Clone, Debug)]
pub struct Certificates {
    configs: Vec<CertificateInfo>,
    name_map: DashMap<String, SslContext>,
    // Map from certificate name (e.g., "arxignis.dev") to SSL context
    cert_name_map: DashMap<String, SslContext>,
    // Map from hostname (e.g., "david-playground3.arxignis.dev") to certificate name (e.g., "arxignis.dev")
    upstreams_cert_map: DashMap<String, String>,
    pub default_cert_path: String,
    pub default_key_path: String,
}

// Implement TlsAccept trait for dynamic certificate selection based on SNI
#[async_trait]
impl TlsAccept for Certificates {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        if let Some(server_name) = ssl.servername(NameType::HOST_NAME) {
            let name_str = server_name.to_string();
            log::info!("TlsAccept::certificate_callback invoked for hostname: {}", name_str);
            log::debug!("TlsAccept: upstreams_cert_map has {} entries", self.upstreams_cert_map.len());
            log::debug!("TlsAccept: cert_name_map has {} entries", self.cert_name_map.len());

            // Find the matching SSL context for this hostname
            if let Some(ctx) = self.find_ssl_context(&name_str) {
                // Log which certificate was found (will be logged in find_ssl_context)
                log::info!("TlsAccept: Found matching certificate for hostname: {} (see details above)", name_str);

                // Get the certificate and key from the SSL context
                // We need to extract them from the context to use with ssl_use_certificate
                // However, SslContext doesn't expose the certificate/key directly
                // So we'll use set_ssl_context instead, which should work
                match ssl.set_ssl_context(&ctx) {
                    Ok(_) => {
                        log::info!("TlsAccept: Successfully set SSL context for hostname: {}", name_str);
                        return;
                    }
                    Err(e) => {
                        log::error!("TlsAccept: Failed to set SSL context for hostname {}: {:?}", name_str, e);
                        // Fall through to use default certificate
                    }
                }
            } else {
                log::warn!("TlsAccept: No matching certificate found for hostname: {}, using default", name_str);
            }
        } else {
            log::debug!("TlsAccept: No SNI provided, using default certificate");
        }

        // Use default certificate - get it by name from default_cert_path
        let default_cert_name = std::path::Path::new(&self.default_cert_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("default");

        if let Some(default_ctx) = self.cert_name_map.get(default_cert_name) {
            let ctx = default_ctx.value();
            log::info!("TlsAccept: Using configured default certificate: {}", default_cert_name);
            if let Err(e) = ssl.set_ssl_context(ctx) {
                log::error!("TlsAccept: Failed to set default SSL context: {:?}", e);
            } else {
                log::debug!("TlsAccept: Successfully set default certificate");
            }
        } else {
            // Fallback to first available certificate if default not found
            log::warn!("TlsAccept: Default certificate '{}' not found in cert_name_map, using first available", default_cert_name);
            if let Some(default_ctx) = self.cert_name_map.iter().next() {
                let ctx = default_ctx.value();
                if let Err(e) = ssl.set_ssl_context(ctx) {
                    log::error!("TlsAccept: Failed to set fallback SSL context: {:?}", e);
                } else {
                    log::debug!("TlsAccept: Using fallback certificate");
            }
        } else {
            log::error!("TlsAccept: No certificates available!");
            }
        }
    }
}

impl Certificates {
    pub fn new(configs: &Vec<CertificateConfig>, _grade: &str, default_certificate: Option<&String>) -> Option<Self> {
        Self::new_with_sni_callback(configs, _grade, default_certificate, None)
    }

    pub fn new_with_sni_callback(
        configs: &Vec<CertificateConfig>,
        _grade: &str,
        default_certificate: Option<&String>,
        _certificates_for_callback: Option<Arc<Certificates>>,
    ) -> Option<Self> {
        if configs.is_empty() {
            warn!("No TLS certificates found, TLS will be disabled until certificates are added");
            return None;
        }

        // First, create a temporary Certificates struct to get access to it in the callback
        // We'll recreate it properly after loading all certificates
        let mut cert_infos = Vec::new();
        let name_map: DashMap<String, SslContext> = DashMap::new();
        let mut valid_configs = Vec::new();

        for config in configs {
            let cert_info = load_cert_info(&config.cert_path, &config.key_path, _grade);
            match cert_info {
                Some(cert) => {
                    for name in &cert.common_names {
                        name_map.insert(name.clone(), cert.ssl_context.clone());
                    }
                    for name in &cert.alt_names {
                        name_map.insert(name.clone(), cert.ssl_context.clone());
                    }

                    cert_infos.push(cert);
                    valid_configs.push(config.clone());
                }
                None => {
                    warn!("Skipping invalid certificate: cert={}, key={}", &config.cert_path, &config.key_path);
                    // Continue with other certificates instead of failing
                }
            }
        }

        if cert_infos.is_empty() {
            error!("No valid certificates could be loaded from {} certificate configs", configs.len());
            return None;
        }

        // Find default certificate: use configured default_certificate if specified, otherwise use first valid certificate
        let default_cert = if let Some(default_cert_name) = default_certificate {
            // Try to find certificate by name (file stem without extension)
            let found = valid_configs.iter().find(|config| {
                if let Some(file_name) = std::path::Path::new(&config.cert_path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                {
                    file_name == default_cert_name.as_str()
                } else {
                    false
                }
            });
            match found {
                Some(cert) => {
                    log::info!("Using configured default certificate: {}", default_cert_name);
                    cert
                }
                None => {
                    log::warn!("Configured default certificate '{}' not found, using first valid certificate", default_cert_name);
                    &valid_configs[0]
                }
            }
        } else {
            // Use first valid certificate as default
            &valid_configs[0]
        };

        // Build cert_name_map: map from certificate file name (without extension) to SSL context
        let cert_name_map: DashMap<String, SslContext> = DashMap::new();
        for (idx, config) in valid_configs.iter().enumerate() {
            // Extract certificate name from path (e.g., "/path/to/arxignis.dev.crt" -> "arxignis.dev")
            // Use file_stem() to get the filename without extension
            if let Some(file_name) = std::path::Path::new(&config.cert_path)
                .file_stem()
                .and_then(|s| s.to_str())
            {
                if let Some(cert_info) = cert_infos.get(idx) {
                    let cert_name = file_name.to_string();
                    cert_name_map.insert(cert_name.clone(), cert_info.ssl_context.clone());
                    log::debug!("Mapped certificate name '{}' to SSL context (from path: {})", cert_name, config.cert_path);
                }
            } else {
                log::warn!("Failed to extract certificate name from path: {}", config.cert_path);
            }
        }

        log::debug!("Built cert_name_map with {} entries", cert_name_map.len());

        Some(Self {
            name_map,
            cert_name_map,
            upstreams_cert_map: DashMap::new(),
            configs: cert_infos,
            default_cert_path: default_cert.cert_path.clone(),
            default_key_path: default_cert.key_path.clone(),
        })
    }

    /// Set upstreams certificate mappings (hostname -> certificate_name)
    pub fn set_upstreams_cert_map(&self, mappings: DashMap<String, String>) {
        self.upstreams_cert_map.clear();
        for entry in mappings.iter() {
            let hostname = entry.key().clone();
            let cert_name = entry.value().clone();
            self.upstreams_cert_map.insert(hostname.clone(), cert_name.clone());
            log::info!("Mapped hostname '{}' to certificate '{}'", hostname, cert_name);
        }
        log::info!("Set upstreams certificate mappings: {} entries", self.upstreams_cert_map.len());
    }

    fn find_ssl_context(&self, server_name: &str) -> Option<SslContext> {
        log::debug!("Finding SSL context for server_name: {}", server_name);

        // First, check if there's an upstreams mapping for this hostname
        if let Some(cert_name) = self.upstreams_cert_map.get(server_name) {
            let cert_name_str = cert_name.value();
            log::info!("Found upstreams mapping: {} -> {}", server_name, cert_name_str);
            if let Some(ctx) = self.cert_name_map.get(cert_name_str) {
                log::info!("Using certificate '{}' for hostname '{}' via upstreams mapping", cert_name_str, server_name);
                return Some(ctx.clone());
            } else {
                // Certificate specified in upstreams.yaml but doesn't exist - use default instead of searching further
                log::warn!("Certificate '{}' specified in upstreams config for hostname '{}' not found in cert_name_map. Will use default certificate (NOT searching for wildcards).", cert_name_str, server_name);
                return None; // Return None to use default certificate - DO NOT continue searching
            }
        } else {
            log::debug!("No upstreams mapping found for hostname: {}, will search for exact/wildcard matches", server_name);
        }

        // Then, try exact match in name_map (from certificate CN/SAN)
        if let Some(ctx) = self.name_map.get(server_name) {
            log::info!("Found certificate via CN/SAN exact match for: {}", server_name);
            return Some(ctx.clone());
        }

        // Check if default certificate is configured - if so, prefer it over wildcards
        let default_cert_name = std::path::Path::new(&self.default_cert_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("default");

        // If default certificate exists and is configured, use it instead of wildcards
        if self.cert_name_map.contains_key(default_cert_name) {
            log::info!("Default certificate '{}' is configured. Skipping wildcard matching for '{}' to use default instead.", default_cert_name, server_name);
            return None; // Return None to use default certificate instead of wildcard
        }

        // Try wildcard match from certificate CN/SAN (only if no default is configured)
        for config in &self.configs {
            for name in &config.common_names {
                if name.starts_with("*.") && server_name.ends_with(&name[1..]) {
                    log::info!("Found certificate via CN wildcard match: {} matches {}", server_name, name);
                    return Some(config.ssl_context.clone());
                }
            }
            for name in &config.alt_names {
                if name.starts_with("*.") && server_name.ends_with(&name[1..]) {
                    log::info!("Found certificate via SAN wildcard match: {} matches {}", server_name, name);
                    return Some(config.ssl_context.clone());
                }
            }
        }

        log::warn!("No matching certificate found for hostname: {}, will use default certificate", server_name);
        None
    }

    pub fn server_name_callback(&self, ssl_ref: &mut SslRef, _ssl_alert: &mut SslAlert) -> Result<(), SniError> {
        let server_name_opt = ssl_ref.servername(NameType::HOST_NAME);
        log::info!("TLS server_name_callback invoked: server_name = {:?}", server_name_opt);
        if let Some(name) = server_name_opt {
            let name_str = name.to_string();
            log::info!("SNI callback: Looking up certificate for hostname: {}", name_str);
            log::debug!("SNI callback: upstreams_cert_map has {} entries", self.upstreams_cert_map.len());
            log::debug!("SNI callback: cert_name_map has {} entries", self.cert_name_map.len());

            match self.find_ssl_context(&name_str) {
                Some(ctx) => {
                    log::info!("SNI callback: Found matching certificate for hostname: {}", name_str);
                    log::info!("SNI callback: Setting SSL context for hostname: {}", name_str);
                    ssl_ref.set_ssl_context(&ctx).map_err(|e| {
                        log::error!("SNI callback: Failed to set SSL context for hostname {}: {:?}", name_str, e);
                        SniError::ALERT_FATAL
                    })?;
                    log::info!("SNI callback: Successfully set SSL context for hostname: {}", name_str);
                }
                None => {
                    log::warn!("SNI callback: No matching certificate found for hostname: {}, using default certificate", name_str);
                    log::debug!("SNI callback: Available upstreams mappings: {:?}",
                        self.upstreams_cert_map.iter().map(|e| (e.key().clone(), e.value().clone())).collect::<Vec<_>>());
                    log::debug!("SNI callback: Available certificate names: {:?}",
                        self.cert_name_map.iter().map(|e| e.key().clone()).collect::<Vec<_>>());
                    // Don't set a context - let it use the default
                }
            }
        } else {
            log::debug!("SNI callback: No server name (SNI) provided in TLS handshake");
        }
        Ok(())
    }

    /// Get certificate path for a given hostname
    pub fn get_cert_path_for_hostname(&self, hostname: &str) -> Option<String> {
        // First try exact match
        if self.name_map.contains_key(hostname) {
            // Find the certificate info that matches this hostname
            for config in &self.configs {
                if config.common_names.contains(&hostname.to_string()) || config.alt_names.contains(&hostname.to_string()) {
                    return Some(config.cert_path.clone());
                }
            }
        }

        // Try wildcard match
        for config in &self.configs {
            for name in &config.common_names {
                if name.starts_with("*.") && hostname.ends_with(&name[1..]) {
                    return Some(config.cert_path.clone());
                }
            }
            for name in &config.alt_names {
                if name.starts_with("*.") && hostname.ends_with(&name[1..]) {
                    return Some(config.cert_path.clone());
                }
            }
        }

        // Return default certificate path if no match found
        Some(self.default_cert_path.clone())
    }
}

fn load_cert_info(cert_path: &str, key_path: &str, _grade: &str) -> Option<CertificateInfo> {
    let mut common_names = HashSet::new();
    let mut alt_names = HashSet::new();

    let file = File::open(cert_path);
    match file {
        Err(e) => {
            log::error!("Failed to open certificate file: {:?}", e);
            return None;
        }
        Ok(file) => {
            let mut reader = BufReader::new(file);
            match read_one(&mut reader) {
                Err(e) => {
                    log::error!("Failed to decode PEM from certificate file: {:?}", e);
                    return None;
                }
                Ok(leaf) => match leaf {
                    Some(Item::X509Certificate(cert)) => match X509Certificate::from_der(&cert) {
                        Err(NomErr::Error(e)) | Err(NomErr::Failure(e)) => {
                            log::error!("Failed to parse certificate: {:?}", e);
                            return None;
                        }
                        Err(_) => {
                            log::error!("Unknown error while parsing certificate");
                            return None;
                        }
                        Ok((_, x509)) => {
                            let subject = x509.subject();
                            for attr in subject.iter_common_name() {
                                if let Ok(cn) = attr.as_str() {
                                    common_names.insert(cn.to_string());
                                }
                            }

                            if let Ok(Some(san)) = x509.subject_alternative_name() {
                                for name in san.value.general_names.iter() {
                                    if let GeneralName::DNSName(dns) = name {
                                        let dns_string = dns.to_string();
                                        if !common_names.contains(&dns_string) {
                                            alt_names.insert(dns_string);
                                        }
                                    }
                                }
                            }
                        }
                    },
                    _ => {
                        log::error!("Failed to read certificate");
                        return None;
                    }
                },
            }
        }
    }

    match create_ssl_context(cert_path, key_path) {
        Ok(ssl_context) => {
            Some(CertificateInfo {
                cert_path: cert_path.to_string(),
                key_path: key_path.to_string(),
                common_names: common_names.into_iter().collect(),
                alt_names: alt_names.into_iter().collect(),
                ssl_context,
            })
        }
        Err(e) => {
            log::error!("Failed to create SSL context from cert paths '{}' and '{}': {}", cert_path, key_path, e);
            None
        }
    }
}

fn create_ssl_context(cert_path: &str, key_path: &str) -> Result<SslContext, Box<dyn std::error::Error>> {
    // Always try to use global certificates for SNI callback
    // This ensures that even contexts created without explicit certificates
    // will have the SNI callback set if global certificates are available
    create_ssl_context_with_sni_callback(cert_path, key_path, None)
}

fn create_ssl_context_with_sni_callback(
    cert_path: &str,
    key_path: &str,
    certificates: Option<Arc<Certificates>>,
) -> Result<SslContext, Box<dyn std::error::Error>> {
    let mut ctx = SslContext::builder(SslMethod::tls())
        .map_err(|e| format!("Failed to create SSL context builder: {}", e))?;

    ctx.set_certificate_chain_file(cert_path)
        .map_err(|e| format!("Failed to set certificate chain file '{}': {}", cert_path, e))?;

    ctx.set_private_key_file(key_path, SslFiletype::PEM)
        .map_err(|e| format!("Failed to set private key file '{}': {}", key_path, e))?;

    ctx.set_alpn_select_callback(prefer_h2);

    // Set SNI callback - use provided certificates or global certificates
    let certs_for_callback = certificates.or_else(get_global_certificates);
    if let Some(certs) = certs_for_callback {
        let certs_clone = certs.clone();
        ctx.set_servername_callback(move |ssl_ref: &mut SslRef, _ssl_alert: &mut SslAlert| -> Result<(), SniError> {
            certs_clone.server_name_callback(ssl_ref, _ssl_alert)
        });
        log::debug!("Set SNI callback on SSL context for certificate selection");
    } else {
        // Certificates may not be loaded yet (e.g., during startup before Redis certificates are fetched)
        // This is expected during initialization, so use debug level instead of warn
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| {
            log::debug!("No certificates available for SNI callback yet - certificates will be loaded asynchronously. Certificate selection by hostname will work once certificates are loaded.");
        });
    }

    let built = ctx.build();

    Ok(built)
}

#[derive(Debug)]
pub struct CipherSuite {
    pub high: &'static str,
    pub medium: &'static str,
    pub legacy: &'static str,
}
const CIPHERS: CipherSuite = CipherSuite {
    high: "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
    medium: "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:AES128-GCM-SHA256",
    legacy: "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH",
};

#[derive(Debug)]
pub enum TlsGrade {
    HIGH,
    MEDIUM,
    LEGACY,
}

impl TlsGrade {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "high" => Some(TlsGrade::HIGH),
            "medium" => Some(TlsGrade::MEDIUM),
            "unsafe" => Some(TlsGrade::LEGACY),
            _ => None,
        }
    }
}
pub fn prefer_h2<'a>(_ssl: &mut SslRef, alpn_in: &'a [u8]) -> Result<&'a [u8], AlpnError> {
    match select_next_proto("\x02h2\x08http/1.1".as_bytes(), alpn_in) {
        Some(p) => Ok(p),
        _ => Err(AlpnError::NOACK),
    }
}

// Helper to set ALPN on TlsSettings
pub fn set_alpn_prefer_h2(tls_settings: &mut pingora_core::listeners::tls::TlsSettings) {
    use pingora_core::listeners::ALPN;
    tls_settings.set_alpn(ALPN::H2H1);
}

// Helper to create TlsSettings with SNI callback for certificate selection
// This uses TlsSettings::with_callbacks() which allows us to provide a TlsAccept implementation
// that handles dynamic certificate selection based on SNI (Server Name Indication)
pub fn create_tls_settings_with_sni(
    cert_path: &str,
    key_path: &str,
    grade: &str,
    certificates: Option<Arc<Certificates>>,
) -> Result<TlsSettings, Box<dyn std::error::Error>> {
    // Get the certificates - use provided or fall back to global
    let certs = certificates
        .or_else(get_global_certificates)
        .ok_or_else(|| "No certificates available for TLS configuration".to_string())?;

    log::info!("Creating TlsSettings with callbacks for dynamic certificate selection");
    log::info!("Default certificate: {} / {}", cert_path, key_path);
    log::info!("Certificate mappings: {} upstreams, {} certificates",
        certs.upstreams_cert_map.len(), certs.cert_name_map.len());

    // Use TlsSettings::with_callbacks() instead of TlsSettings::intermediate()
    // This allows us to provide our Certificates struct which implements TlsAccept
    // The certificate_callback method will be called during TLS handshake to select
    // the appropriate certificate based on the SNI hostname
    //
    // Note: with_callbacks expects a Box<dyn TlsAccept + Send + Sync>
    // We clone the Certificates struct to create a new instance for the callback
    let tls_accept: Box<dyn TlsAccept + Send + Sync> = Box::new((*certs).clone());
    let mut tls_settings = TlsSettings::with_callbacks(tls_accept)
        .map_err(|e| format!("Failed to create TlsSettings with callbacks: {}", e))?;

    // Configure TLS grade and ALPN
    set_tsl_grade(&mut tls_settings, grade);
    set_alpn_prefer_h2(&mut tls_settings);

    log::info!("Successfully created TlsSettings with SNI-based certificate selection");
    log::info!("Certificate selection will work based on hostname from SNI");

    Ok(tls_settings)
}

pub fn set_tsl_grade(tls_settings: &mut TlsSettings, grade: &str) {
    let config_grade = TlsGrade::from_str(grade);
    match config_grade {
        Some(TlsGrade::HIGH) => {
            let _ = tls_settings.set_min_proto_version(Some(SslVersion::TLS1_2));
            // let _ = tls_settings.set_max_proto_version(Some(SslVersion::TLS1_3));
            let _ = tls_settings.set_cipher_list(CIPHERS.high);
            let _ = tls_settings.set_ciphersuites(CIPHERS.high);
            info!("TLS grade: => HIGH");
        }
        Some(TlsGrade::MEDIUM) => {
            let _ = tls_settings.set_min_proto_version(Some(SslVersion::TLS1));
            let _ = tls_settings.set_cipher_list(CIPHERS.medium);
            let _ = tls_settings.set_ciphersuites(CIPHERS.medium);
            info!("TLS grade: => MEDIUM");
        }
        Some(TlsGrade::LEGACY) => {
            let _ = tls_settings.set_min_proto_version(Some(SslVersion::SSL3));
            let _ = tls_settings.set_cipher_list(CIPHERS.legacy);
            let _ = tls_settings.set_ciphersuites(CIPHERS.legacy);
            warn!("TLS grade: => UNSAFE");
        }
        None => {
            // Defaults to MEDIUM
            let _ = tls_settings.set_min_proto_version(Some(SslVersion::TLS1));
            let _ = tls_settings.set_cipher_list(CIPHERS.medium);
            let _ = tls_settings.set_ciphersuites(CIPHERS.medium);
            warn!("TLS grade is not detected defaulting top MEDIUM");
        }
    }
}

/// Extract server certificate information for access logging
pub fn extract_cert_info(cert_path: &str) -> Option<crate::access_log::ServerCertInfo> {
    use sha2::{Digest, Sha256};

    let file = File::open(cert_path).ok()?;
    let mut reader = BufReader::new(file);

    // Read the first certificate from the PEM file
    let item = read_one(&mut reader).ok()??;

    let cert_der = match item {
        Item::X509Certificate(der) => der,
        _ => return None,
    };

    // Parse the X.509 certificate
    let (_, cert) = X509Certificate::from_der(&cert_der).ok()?;

    // Extract issuer
    let issuer = cert.issuer().to_string();

    // Extract subject
    let subject = cert.subject().to_string();

    // Extract validity dates (as ISO 8601 format)
    let not_before = cert.validity().not_before.to_datetime().to_string();
    let not_after = cert.validity().not_after.to_datetime().to_string();

    // Calculate SHA256 fingerprint
    let mut hasher = Sha256::new();
    hasher.update(&cert_der);
    let fingerprint_sha256 = format!("{:x}", hasher.finalize());

    Some(crate::access_log::ServerCertInfo {
        issuer,
        subject,
        not_before,
        not_after,
        fingerprint_sha256,
    })
}

