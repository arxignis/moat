use std::convert::Infallible;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context as TaskContext, Poll};

use crate::domain_filter::DomainFilter;
use crate::wirefilter::get_global_http_filter;
use crate::actions::captcha::{validate_captcha_token, generate_captcha_token, apply_captcha_challenge, apply_captcha_challenge_with_token};
use crate::threat;
use crate::redis::RedisManager;
use crate::access_rules::is_ip_allowed_by_access_rules;
use crate::{bpf, utils::bpf_utils};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use clap::ValueEnum;
use futures_rustls::rustls::{ClientConfig as AcmeClientConfig, RootCertStore};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use libbpf_rs::{MapCore, MapFlags};
use redis::{AsyncCommands, RedisError};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls_acme::{AccountCache, CertCache};
use rustls_pemfile::{certs, private_key};
use serde::ser::Serializer;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, RwLock};
use tokio_rustls::LazyConfigAcceptor;
use tokio_stream::wrappers::TcpListenerStream;
use url::form_urlencoded;

use crate::proxy_utils::{build_proxy_error_response, forward_to_upstream_with_body, ProxyBody};
use crate::access_log::{HttpAccessLog, ResponseData};

use self::tls_fingerprint::{fingerprint_client_hello, Fingerprint as TlsFingerprint};

#[derive(Clone, Debug)]
pub struct ServerCertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub fingerprint_sha256: String,
}

#[derive(Clone)]
pub struct ServerConfigWithCert {
    pub config: Arc<ServerConfig>,
    pub cert_info: Option<ServerCertInfo>,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum TlsMode {
    Disabled,
    Custom,
    Acme,
}

impl TlsMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            TlsMode::Disabled => "disabled",
            TlsMode::Custom => "custom",
            TlsMode::Acme => "acme",
        }
    }
}

impl std::str::FromStr for TlsMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "disabled" => Ok(TlsMode::Disabled),
            "custom" => Ok(TlsMode::Custom),
            "acme" => Ok(TlsMode::Acme),
            _ => Err(anyhow::anyhow!("Invalid TLS mode: {}", s)),
        }
    }
}

impl fmt::Display for TlsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for TlsMode {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[derive(Clone, Serialize)]
pub struct TlsStatusSnapshot {
    mode: TlsMode,
    enabled: bool,
    detail: String,
    domains: Vec<String>,
    custom_cert: Option<String>,
}

#[derive(Clone)]
pub struct SharedTlsState {
    inner: Arc<RwLock<TlsStatusSnapshot>>,
}

impl SharedTlsState {
    pub fn new(mode: TlsMode, domains: Vec<String>, custom_cert: Option<String>) -> Self {
        let enabled = mode != TlsMode::Disabled;
        let detail = if enabled {
            "initializing TLS subsystem".to_string()
        } else {
            "disabled by configuration".to_string()
        };
        let snapshot = TlsStatusSnapshot {
            mode,
            enabled,
            detail,
            domains,
            custom_cert,
        };
        Self {
            inner: Arc::new(RwLock::new(snapshot)),
        }
    }

    pub async fn set_running_detail(&self, detail: impl Into<String>) {
        let mut guard = self.inner.write().await;
        guard.enabled = true;
        guard.detail = detail.into();
    }

    pub async fn set_error_detail(&self, detail: impl Into<String>) {
        let mut guard = self.inner.write().await;
        guard.enabled = false;
        guard.detail = detail.into();
    }

    pub async fn snapshot(&self) -> TlsStatusSnapshot {
        self.inner.read().await.clone()
    }
}

pub mod tls_fingerprint;
pub mod health_checks;

#[derive(Debug)]
pub struct FingerprintTcpStream {
    inner: TcpStream,
    peer_addr: SocketAddr,
    fingerprint: Option<TlsFingerprint>,
}

impl FingerprintTcpStream {
    pub async fn new(stream: TcpStream) -> io::Result<Self> {
        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(err) => {
                // Handle connection disconnection gracefully - this is not a critical error
                log::debug!("Connection disconnected before TLS handshake: {}", err);
                return Err(err);
            }
        };
        let fingerprint = Self::capture_fingerprint(&stream).await;
        Ok(Self {
            inner: stream,
            peer_addr,
            fingerprint,
        })
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn fingerprint(&self) -> Option<&TlsFingerprint> {
        self.fingerprint.as_ref()
    }

    pub async fn capture_fingerprint(stream: &TcpStream) -> Option<TlsFingerprint> {
        let mut buf = vec![0u8; 16 * 1024];
        match stream.peek(&mut buf).await {
            Ok(n) if n > 0 => fingerprint_client_hello(&buf[..n]),
            _ => None,
        }
    }
}

impl AsyncRead for FingerprintTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for FingerprintTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsRef<TcpStream> for FingerprintTcpStream {
    fn as_ref(&self) -> &TcpStream {
        &self.inner
    }
}

// Custom stream wrapper that implements Unpin for use with rustls-acme
pub struct FingerprintingTcpListener {
    inner: TcpListenerStream,
    _skel: Option<Arc<bpf::FilterSkel<'static>>>,
    pending: Option<
        Pin<
            Box<
                dyn futures::Future<
                        Output = Result<(TcpStream, Option<TlsFingerprint>, SocketAddr), io::Error>,
                    > + Send,
            >,
        >,
    >,
}

impl FingerprintingTcpListener {
    pub fn new(inner: TcpListenerStream, skel: Option<Arc<bpf::FilterSkel<'static>>>) -> Self {
        Self {
            inner,
            _skel: skel,
            pending: None,
        }
    }
}

impl futures::Stream for FingerprintingTcpListener {
    type Item = Result<TcpStream, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        // If we have a pending fingerprinting task, poll it
        if let Some(mut fut) = self.pending.take() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok((stream, _fp, _peer))) => {
                    return Poll::Ready(Some(Ok(stream)));
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Pending => {
                    self.pending = Some(fut);
                    return Poll::Pending;
                }
            }
        }

        // Poll for new connection
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(stream))) => {
                // Create a future to do the fingerprinting
                let fut = Box::pin(async move {
                    let peer = stream.peer_addr()?;
                    let mut buf = vec![0u8; 16 * 1024];
                    let fp = match stream.peek(&mut buf).await {
                        Ok(n) if n > 0 => fingerprint_client_hello(&buf[..n]),
                        _ => None,
                    };
                    Ok((stream, fp, peer))
                });
                self.pending = Some(fut);
                // Immediately poll the future we just created
                self.poll_next(cx)
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Implement Unpin so it works with rustls-acme
impl Unpin for FingerprintingTcpListener {}

pub fn ipv4_to_u32_be(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn is_ipv4_banned(peer: SocketAddr, skels: &Vec<Arc<bpf::FilterSkel<'static>>>) -> bool {
    if skels.is_empty() {
        return false;
    }
    match peer.ip() {
        std::net::IpAddr::V4(ip) => {
            let key_bytes = bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, 32);
            for skel in skels {
                match skel
                    .maps
                    .recently_banned_ips
                    .lookup(&key_bytes, MapFlags::ANY)
                {
                    Ok(Some(flag)) if flag == vec![1u8] => return true,
                    Ok(_) => continue,
                    Err(e) => {
                        log::error!("bpf recently_banned_ips lookup error for {peer}: {e}");
                        continue;
                    }
                }
            }
            false
        }
        _ => false,
    }
}

fn is_ipv6_banned(peer: SocketAddr, skels: &Vec<Arc<bpf::FilterSkel<'static>>>) -> bool {
    if skels.is_empty() {
        return false;
    }
    match peer.ip() {
        std::net::IpAddr::V6(ip) => {
            let key_bytes = bpf_utils::convert_ipv6_into_bpf_map_key_bytes(ip, 128);
            for skel in skels {
                match skel
                    .maps
                    .recently_banned_ips_v6
                    .lookup(&key_bytes, MapFlags::ANY)
                {
                    Ok(Some(flag)) if flag == vec![1u8] => return true,
                    Ok(_) => continue,
                    Err(e) => {
                        log::error!("bpf recently_banned_ips_v6 lookup error for {peer}: {e}");
                        continue;
                    }
                }
            }
            false
        }
        _ => false,
    }
}

const BANNED_MESSAGE: &str = "blocked: your ip is temporarily banned\n";

// header_json moved to proxy_utils

pub fn install_ring_crypto_provider() -> Result<()> {
    static INSTALL: OnceLock<Result<()>> = OnceLock::new();
    match INSTALL.get_or_init(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .map_err(|err| anyhow!("failed to install ring crypto provider: {err:?}"))
    }) {
        Ok(()) => Ok(()),
        Err(err) => Err(anyhow!("ring crypto provider previously failed: {err:?}")),
    }
}

pub fn load_acme_client_config(path: Option<&Path>) -> Result<Arc<AcmeClientConfig>> {
    let mut roots = RootCertStore::empty();

    if let Some(path) = path {
        // Load custom CA bundle
        let file = File::open(path)
            .with_context(|| format!("failed to open ACME CA root bundle {:?}", path))?;
        let mut reader = BufReader::new(file);
        let certs = rustls_pemfile::certs(&mut reader)
            .collect::<std::io::Result<Vec<_>>>()
            .with_context(|| format!("failed to parse ACME CA root bundle {:?}", path))?;
        if certs.is_empty() {
            return Err(anyhow!(
                "no certificates found in ACME CA root bundle {:?}",
                path
            ));
        }

        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| anyhow!("failed to add ACME CA root certificate: {e}"))?;
        }
    } else {
        // Use webpki roots for Let's Encrypt
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let provider = rustls::crypto::ring::default_provider();
    let client_config = AcmeClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("failed to set ACME TLS protocol versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(Arc::new(client_config))
}
// ProxyBody moved to proxy_utils

pub fn parse_ip_param(req: &Request<Incoming>) -> Result<Ipv4Addr, String> {
    let uri = req.uri();
    let query = uri.query().unwrap_or("");
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == "ip"
        {
            return v
                .parse::<Ipv4Addr>()
                .map_err(|_| "invalid ip parameter".to_string());
        }
    }
    Err("missing ip parameter".to_string())
}

// json moved to proxy_utils

#[derive(Clone)]
pub struct ProxyContext {
    pub client: Client<HttpConnector, Full<Bytes>>,
    pub upstream: Uri,
    pub domain_filter: DomainFilter,
    pub tls_only: bool,
    pub proxy_protocol_enabled: bool,
    pub proxy_protocol_timeout_ms: u64,
}

#[derive(Clone)]
pub struct RedisAcmeCache {
    pub prefix: String,
}

impl RedisAcmeCache {
    pub async fn new(prefix: String) -> Result<Self> {
        log::info!("Initializing Redis ACME cache with prefix: {}", prefix);

        // Test Redis connection
        let redis_manager = RedisManager::get()
            .context("Redis manager not initialized")?;

        let mut test_conn = redis_manager.get_connection();
        match redis::cmd("PING").query_async::<String>(&mut test_conn).await {
            Ok(_) => log::info!("Redis connection test successful"),
            Err(e) => {
                log::warn!("Redis connection test failed: {}", e);
                return Err(anyhow!("Redis connection test failed: {}", e));
            }
        }

        Ok(Self { prefix })
    }

    pub fn key(
        &self,
        kind: &str,
        domains: &[String],
        directory_url: &str,
        extra: &[String],
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(kind.as_bytes());
        hasher.update(directory_url.as_bytes());
        for domain in domains {
            hasher.update(domain.as_bytes());
        }
        for item in extra {
            hasher.update(item.as_bytes());
        }
        let digest = hasher.finalize();
        format!("{}:{}:{}", self.prefix, kind, hex::encode(digest))
    }
}

#[async_trait]
impl CertCache for RedisAcmeCache {
    type EC = RedisError;

    async fn load_cert(
        &self,
        domains: &[String],
        directory_url: &str,
    ) -> std::result::Result<Option<Vec<u8>>, Self::EC> {
        let key = self.key("cert", domains, directory_url, &[]);
        log::debug!("Loading certificate with key: {}", key);

        let redis_manager = RedisManager::get()
            .map_err(|e| RedisError::from((redis::ErrorKind::IoError, "Redis manager not initialized", e.to_string())))?;
        let mut conn = redis_manager.get_connection();

        let value: Option<Vec<u8>> = conn.get(key).await?;
        if value.is_some() {
            log::debug!("Certificate found in cache");
        } else {
            log::debug!("No certificate found in cache");
        }
        Ok(value)
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> std::result::Result<(), Self::EC> {
        let key = self.key("cert", domains, directory_url, &[]);
        log::debug!("Storing certificate with key: {}", key);

        let redis_manager = RedisManager::get()
            .map_err(|e| RedisError::from((redis::ErrorKind::IoError, "Redis manager not initialized", e.to_string())))?;
        let mut conn = redis_manager.get_connection();

        // Set certificate to expire in 60 days (5184000 seconds)
        conn.set_ex::<_, _, ()>(key, cert, 5184000).await?;
        log::debug!("Certificate stored successfully with 60-day expiration");
        Ok(())
    }
}

#[async_trait]
impl AccountCache for RedisAcmeCache {
    type EA = RedisError;

    async fn load_account(
        &self,
        contact: &[String],
        directory_url: &str,
    ) -> std::result::Result<Option<Vec<u8>>, Self::EA> {
        let key = self.key("account", &[], directory_url, contact);
        let redis_manager = RedisManager::get()
            .map_err(|_e| RedisError::from((redis::ErrorKind::IoError, "Redis manager not initialized")))?;
        let mut conn = redis_manager.get_connection();
        let value: Option<Vec<u8>> = conn.get(key).await?;
        Ok(value)
    }

    async fn store_account(
        &self,
        contact: &[String],
        directory_url: &str,
        account: &[u8],
    ) -> std::result::Result<(), Self::EA> {
        let key = self.key("account", &[], directory_url, contact);
        let redis_manager = RedisManager::get()
            .map_err(|_e| RedisError::from((redis::ErrorKind::IoError, "Redis manager not initialized")))?;
        let mut conn = redis_manager.get_connection();
        // Set account to expire in 1 year (31536000 seconds)
        conn.set_ex::<_, _, ()>(key, account, 31536000).await?;
        Ok(())
    }
}

pub fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).with_context(|| format!("failed to open certificate file {:?}", path))?;
    let mut reader = BufReader::new(file);
    let certs = certs(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("failed to parse certificates in {:?}", path))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {:?}", path));
    }
    Ok(certs)
}

pub fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).with_context(|| format!("failed to open private key file {:?}", path))?;
    let mut reader = BufReader::new(file);
    let key = private_key(&mut reader)
        .with_context(|| format!("failed to parse private key in {:?}", path))?
        .ok_or_else(|| anyhow!("no private key found in {:?}", path))?;
    Ok(key)
}

// Type alias for challenge storage
type ChallengeStore = Arc<RwLock<std::collections::HashMap<String, String>>>;

// Helper function to load or create instant-acme account
// Note: AccountCredentials::private_key() getter is already available in instant-acme 0.8+
// Supported key types: ECDSA P-256 (as per instant-acme documentation)
async fn load_or_create_account(
    cache: &RedisAcmeCache,
    directory_url: &str,
    contacts: &[String],
) -> Result<Account> {
    let account_key = cache.key("account", &[], directory_url, contacts);
    let redis_manager = RedisManager::get()
        .context("Redis manager not initialized")?;
    let mut conn = redis_manager.get_connection();

    // Try to load existing account
    if let Ok(Some(account_data)) = conn.get::<_, Option<Vec<u8>>>(&account_key).await {
        // Deserialize account credentials
        if let Ok(credentials) = serde_json::from_slice::<AccountCredentials>(&account_data) {
            if let Ok(account) = Account::builder()?.from_credentials(credentials).await {
                log::info!("Loaded existing ACME account from cache");
                return Ok(account);
            }
        }
    }

    // Create new account
    log::info!("Creating new ACME account");
    let url = if directory_url.contains("staging") || directory_url.contains("pebble") {
        instant_acme::LetsEncrypt::Staging.url()
    } else {
        instant_acme::LetsEncrypt::Production.url()
    };

    let contacts: Vec<&str> = contacts.iter().map(|s| s.as_str()).collect();
    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            url.to_string(),
            None,
        )
        .await?;

    // Store account credentials with 1 year expiration
    let credentials_json = serde_json::to_vec(&credentials)?;
    let _: () = conn.set_ex(&account_key, &credentials_json, 31536000).await?;

    Ok(account)
}

// Helper to load private key from Redis
async fn load_private_key_from_redis(
    cache: &RedisAcmeCache,
    domains: &[String],
    directory_url: &str,
) -> Result<Option<PrivateKeyDer<'static>>> {
    let key = cache.key("privkey", domains, directory_url, &[]);
    let redis_manager = RedisManager::get()
        .context("Redis manager not initialized")?;
    let mut conn = redis_manager.get_connection();

    if let Some(der_bytes) = conn.get::<_, Option<Vec<u8>>>(&key).await? {
        Ok(Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            der_bytes,
        ))))
    } else {
        Ok(None)
    }
}

// Helper to store private key in Redis
async fn store_private_key_in_redis(
    cache: &RedisAcmeCache,
    domains: &[String],
    directory_url: &str,
    private_key_der: &[u8],
) -> Result<()> {
    let key = cache.key("privkey", domains, directory_url, &[]);
    log::debug!("Storing private key with key: {}", key);
    let redis_manager = RedisManager::get()
        .context("Redis manager not initialized")?;
    let mut conn = redis_manager.get_connection();
    // Set private key to expire in 60 days (5184000 seconds)
    conn.set_ex::<_, _, ()>(key, private_key_der, 5184000).await?;
    log::debug!("Private key stored successfully with 60-day expiration");
    Ok(())
}

// Parse PEM certificate chain
fn parse_cert_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    Ok(certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|cert| cert.into_owned())
        .collect())
}

// Extract certificate info from DER-encoded certificate using x509-parser
fn extract_cert_info_from_der(cert_der: &CertificateDer<'static>) -> Option<ServerCertInfo> {
    use x509_parser::parse_x509_certificate;

    match parse_x509_certificate(cert_der.as_ref()) {
        Ok((_, cert)) => {
            // Extract subject
            let subject = cert.subject().to_string();

            // Extract issuer
            let issuer = cert.issuer().to_string();

            // Extract serial number
            let serial_number = cert.serial.to_string();

            // Extract validity dates
            let validity = cert.validity();
            let not_before = format!("{}", validity.not_before.to_datetime());
            let not_after = format!("{}", validity.not_after.to_datetime());

            // Calculate SHA256 fingerprint
            let fingerprint_sha256 = format!("{:x}", sha2::Sha256::digest(cert_der.as_ref()));

            Some(ServerCertInfo {
                subject,
                issuer,
                serial_number,
                not_before,
                not_after,
                fingerprint_sha256,
            })
        }
        Err(e) => {
            log::warn!("Failed to parse X.509 certificate: {}", e);
            // Fallback to fingerprint-only info
            Some(ServerCertInfo {
                subject: "parse_error".to_string(),
                issuer: "parse_error".to_string(),
                serial_number: "parse_error".to_string(),
                not_before: Utc::now().to_rfc3339(),
                not_after: Utc::now().to_rfc3339(),
                fingerprint_sha256: format!("{:x}", sha2::Sha256::digest(cert_der.as_ref())),
            })
        }
    }
}

// Retry configuration for ACME operations
#[derive(Debug, Clone)]
struct AcmeRetryConfig {
    max_retries: u32,
    base_delay_ms: u64,
    max_delay_ms: u64,
    backoff_multiplier: f64,
    jitter_range: f64,
}

impl Default for AcmeRetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            base_delay_ms: 1000,      // 1 second
            max_delay_ms: 300000,     // 5 minutes
            backoff_multiplier: 2.0,
            jitter_range: 0.1,       // 10% jitter
        }
    }
}

impl AcmeRetryConfig {
    fn calculate_delay(&self, attempt: u32) -> u64 {
        let exponential_delay = self.base_delay_ms as f64 * self.backoff_multiplier.powi(attempt as i32);
        let capped_delay = exponential_delay.min(self.max_delay_ms as f64);

        // Add jitter to prevent thundering herd
        let jitter = capped_delay * self.jitter_range * (rand::random::<f64>() - 0.5) * 2.0;
        let final_delay = capped_delay + jitter;

        final_delay.max(100.0) as u64 // Minimum 100ms delay
    }
}

// Check if an error is retryable
fn is_retryable_error(error: &anyhow::Error) -> bool {
    let error_str = error.to_string().to_lowercase();

    // DNS issues are not retryable (expected when DNS isn't ready)
    if error_str.contains("nxdomain") ||
       error_str.contains("dns problem") ||
       error_str.contains("no dns record") {
        return false;
    }

    // Retryable errors
    error_str.contains("rate limited") ||
    error_str.contains("too many requests") ||
    error_str.contains("connection") ||
    error_str.contains("timeout") ||
    error_str.contains("network") ||
    error_str.contains("temporary") ||
    error_str.contains("server error") ||
    error_str.contains("service unavailable") ||
    error_str.contains("bad gateway") ||
    error_str.contains("gateway timeout") ||
    error_str.contains("no such authorization") ||
    error_str.contains("malformed") ||
    error_str.contains("authorization") ||
    error_str.contains("order") ||
    error_str.contains("challenge")
}

// Extract retry-after information from rate limit errors
fn extract_retry_after(error: &anyhow::Error) -> Option<u64> {
    let error_str = error.to_string();

    // Look for "retry after" patterns in the error message
    if let Some(captures) = regex::Regex::new(r"retry after (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
        .ok()
        .and_then(|re| re.captures(&error_str))
    {
        if let Some(time_str) = captures.get(1) {
            if let Ok(parsed_time) = chrono::DateTime::parse_from_rfc3339(&format!("{}Z", time_str.as_str())) {
                let now = chrono::Utc::now();
                let duration = parsed_time.signed_duration_since(now);
                if duration.num_seconds() > 0 {
                    return Some(duration.num_seconds() as u64);
                }
            }
        }
    }

    None
}

// Manage ACME certificate lifecycle with progressive retry logic
async fn manage_acme_certificate_with_retry(
    domains: Vec<String>,
    directory_url: String,
    contacts: Vec<String>,
    cache: RedisAcmeCache,
    cert_config: Arc<RwLock<Option<ServerConfigWithCert>>>,
    challenge_store: ChallengeStore,
    tls_state: SharedTlsState,
) -> Result<()> {
    let retry_config = AcmeRetryConfig::default();
    let mut attempt = 0;

    loop {
        attempt += 1;

        log::info!("ACME certificate management attempt {}/{} for domains: {:?}",
                  attempt, retry_config.max_retries + 1, domains);

        match manage_acme_certificate(
            domains.clone(),
            directory_url.clone(),
            contacts.clone(),
            cache.clone(),
            cert_config.clone(),
            challenge_store.clone(),
        ).await {
            Ok(()) => {
                log::info!("ACME certificate management succeeded on attempt {}", attempt);
                tls_state.set_running_detail("ACME certificate active").await;
                return Ok(());
            }
            Err(error) => {
                // Check if this is the last attempt
                if attempt > retry_config.max_retries {
                    log::error!("ACME certificate management failed after {} attempts, giving up: {}", attempt, error);
                    tls_state.set_error_detail(format!("ACME failed after {} attempts: {}", attempt, error)).await;
                    return Err(error);
                }

                // Check if the error is retryable
                if !is_retryable_error(&error) {
                    let error_str = error.to_string().to_lowercase();
                    if error_str.contains("nxdomain") || error_str.contains("dns problem") {
                        log::warn!("ACME certificate management skipped due to DNS issue (domain not ready): {}", error);
                        tls_state.set_error_detail(format!("ACME DNS issue: {}", error)).await;
                    } else {
                        log::warn!("ACME certificate management failed with non-retryable error: {}", error);
                        tls_state.set_error_detail(format!("ACME non-retryable error: {}", error)).await;
                    }
                    return Err(error);
                }

                log::warn!("ACME certificate management failed on attempt {} (retryable), retrying: {}", attempt, error);

                // Calculate delay for next retry
                let mut delay_ms = retry_config.calculate_delay(attempt - 1);

                // Check for specific retry-after information (e.g., from rate limits)
                if let Some(retry_after_seconds) = extract_retry_after(&error) {
                    delay_ms = retry_after_seconds * 1000; // Convert to milliseconds
                    log::info!("Using retry-after delay: {} seconds", retry_after_seconds);
                }

                log::info!("Retrying ACME certificate management in {}ms (attempt {}/{})",
                          delay_ms, attempt + 1, retry_config.max_retries + 1);

                tls_state.set_running_detail(format!(
                    "ACME retry in {}s (attempt {}/{})",
                    delay_ms / 1000,
                    attempt + 1,
                    retry_config.max_retries + 1
                )).await;

                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
            }
        }
    }
}

// Manage ACME certificate lifecycle with instant-acme
async fn manage_acme_certificate(
    domains: Vec<String>,
    directory_url: String,
    contacts: Vec<String>,
    cache: RedisAcmeCache,
    cert_config: Arc<RwLock<Option<ServerConfigWithCert>>>,
    challenge_store: ChallengeStore,
) -> Result<()> {
    // Try to load existing certificate
    if let Ok(Some(cert_pem_bytes)) = cache.load_cert(&domains, &directory_url).await {
        if let Ok(cert_pem) = String::from_utf8(cert_pem_bytes) {
            if let Ok(certs) = parse_cert_chain(&cert_pem) {
                if let Some(private_key) = load_private_key_from_redis(&cache, &domains, &directory_url).await? {
                    log::info!("Loaded existing certificate from cache");
                    match ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs.clone(), private_key)
                    {
                        Ok(config) => {
                            let cert_info = extract_cert_info_from_der(&certs[0]);
                            *cert_config.write().await = Some(ServerConfigWithCert { config: Arc::new(config), cert_info });
                            return Ok(());
                        }
                        Err(e) => {
                            log::warn!("KeyMismatch detected when loading cached certificate: {}", e);
                            log::info!("Clearing cached certificate and private key to force regeneration");

                            // Clear the cached certificate and private key
                            let cert_key = cache.key("cert", &domains, &directory_url, &[]);
                            let privkey_key = cache.key("privkey", &domains, &directory_url, &[]);
                            let redis_manager = RedisManager::get()
                                .context("Redis manager not initialized")?;
                            let mut conn = redis_manager.get_connection();
                            let _: () = conn.del(cert_key).await.unwrap_or(());
                            let _: () = conn.del(privkey_key).await.unwrap_or(());

                            log::info!("Cached certificate and private key cleared, proceeding with new certificate generation");
                        }
                    }
                }
            }
        }
    }

    // Need to obtain new certificate
    log::info!("Obtaining new ACME certificate for {:?}", domains);

    let account = load_or_create_account(&cache, &directory_url, &contacts).await?;

    // Create order
    let identifiers: Vec<Identifier> =
        domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await?;

    // Process authorizations
    let mut authorizations = order.authorizations();
    let mut challenges_set = Vec::new();
    let mut failed_domains = Vec::new();

    while let Some(result) = authorizations.next().await {
        let mut authz = result?;
        let domain = authz.identifier().to_string();

        // Find HTTP-01 challenge
        let mut challenge = match authz.challenge(ChallengeType::Http01) {
            Some(c) => c,
            None => {
                log::warn!("Domain '{}': No HTTP-01 challenge found, skipping", domain);
                failed_domains.push((domain.clone(), "No HTTP-01 challenge available".to_string()));
                continue;
            }
        };

        // Get key authorization
        let key_auth = challenge.key_authorization().as_str().to_string();

        // Store challenge response
        {
            let mut store = challenge_store.write().await;
            store.insert(challenge.token.to_string(), key_auth.clone());
        }

        log::info!("Set HTTP-01 challenge for token: {}", challenge.token);

        // Notify ACME server to validate
        match challenge.set_ready().await {
            Ok(_) => {
                challenges_set.push(domain.clone());
            }
            Err(e) => {
                log::warn!("Domain '{}': Failed to notify ACME server: {}", domain, e);
                failed_domains.push((domain.clone(), format!("Challenge notification failed: {}", e)));
                continue;
            }
        }
    }

    if challenges_set.is_empty() {
        return Err(anyhow!(
            "All domains failed challenge setup. Failed domains: {:?}",
            failed_domains
        ));
    }

    if !failed_domains.is_empty() {
        log::warn!("Some domains failed: {:?}", failed_domains);
        log::warn!("Continuing with successful domains: {:?}", challenges_set);
    }

    // Wait for order to be ready with progressive retry logic
    let mut tries = 0;
    let mut consecutive_errors = 0;
    let state = loop {
        // Progressive delay: start with 1 second, increase on consecutive errors
        let delay_secs = if consecutive_errors > 0 {
            (1 << consecutive_errors.min(5)).min(60) // Cap at 60 seconds
        } else {
            1
        };

        tokio::time::sleep(tokio::time::Duration::from_secs(delay_secs)).await;

        let state = match order.refresh().await {
            Ok(state) => {
                consecutive_errors = 0; // Reset error counter on success
                state
            }
            Err(e) => {
                consecutive_errors += 1;
                log::warn!("Order refresh failed (consecutive errors: {}): {}", consecutive_errors, e);

                // If we have too many consecutive errors, fail
                if consecutive_errors >= 5 {
                    return Err(anyhow!("Order refresh failed after {} consecutive errors: {}", consecutive_errors, e));
                }

                // Continue with the loop to retry
                continue;
            }
        };

        match state.status {
            OrderStatus::Ready => {
                log::info!("Order status: Ready");
                break state;
            }
            OrderStatus::Invalid => {
                let mut auth_results = order.authorizations();
                let mut validation_errors = Vec::new();

                while let Some(result) = auth_results.next().await {
                    let authz = result?;
                    let domain = authz.identifier().to_string();

                    match authz.status {
                        AuthorizationStatus::Valid => {
                            log::info!("Domain '{}': Validated successfully", domain);
                        }
                        AuthorizationStatus::Invalid => {
                            // Check for challenge errors
                            let mut error_msg = format!("Domain '{}': Validation failed", domain);
                            for challenge in &authz.challenges {
                                if let Some(err) = &challenge.error {
                                    error_msg = format!(
                                        "Domain '{}': {} (Type: {:?})",
                                        domain,
                                        err.detail.as_deref().unwrap_or("Unknown error"),
                                        err.r#type
                                    );
                                }
                            }
                            log::error!("{}", error_msg);
                            validation_errors.push(error_msg);
                        }
                        AuthorizationStatus::Pending => {
                                log::warn!("Domain '{}': Still pending", domain);
                        }
                        _ => {
                            log::warn!("Domain '{}': Status {:?}", domain, authz.status);
                        }
                    }
                }

                return Err(anyhow!(
                    "Order invalid. Validation errors: {:?}",
                    validation_errors
                ));
            }
            OrderStatus::Processing => {
                if tries % 3 == 0 {
                    log::info!("Order status: Processing... (attempt {}/10)", tries + 1);
                }
            }
            _ => {
                if tries % 3 == 0 {
                    log::info!("Order status: {:?} (attempt {}/10)", state.status, tries + 1);
                }
            }
        }

        tries += 1;
        if tries >= 10 {
            return Err(anyhow!(
                "Order status: {:?}, gave up after {} tries. \
                Try checking if your DNS points to this server and port 80 is accessible.",
                state.status,
                tries
            ));
        }
    };

    if state.status == OrderStatus::Invalid {
        log::warn!("Order became invalid after {} tries and status: {:?}", tries, state.status);
        return Err(anyhow!("Order became invalid after {} tries and status: {:?}", tries, state.status));
    }

    log::info!("Order status: Ready");

    // Finalize order with CSR and get the private key used for CSR generation
    let private_key_pem = order.finalize().await?;

    // Download certificate with retry logic
    let cert_chain_pem = loop {
        match order.certificate().await {
            Ok(Some(cert)) => break cert,
            Ok(None) => {
                log::debug!("Certificate not ready yet, waiting...");
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
            Err(e) => {
                log::warn!("Certificate download failed, retrying: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    };

    log::info!("Successfully obtained ACME certificate!");

    // Store certificate in Redis
    log::info!("Storing certificate in Redis for domains: {:?}", domains);
    cache
        .store_cert(&domains, &directory_url, cert_chain_pem.as_bytes())
        .await?;
    log::info!("Certificate successfully stored in Redis");

    // Convert PEM private key to DER format for storage
    let private_key_der = match rustls_pemfile::private_key(&mut private_key_pem.as_bytes())
        .with_context(|| "failed to parse private key PEM")?
        .ok_or_else(|| anyhow!("no private key found in PEM"))?
    {
        PrivateKeyDer::Pkcs8(pkcs8_key) => pkcs8_key.secret_pkcs8_der().to_vec(),
        _ => return Err(anyhow!("unsupported private key format - only PKCS8 is supported")),
    };

    // Store the actual private key used for CSR generation
    log::info!("Storing private key in Redis for domains: {:?}", domains);
    store_private_key_in_redis(
        &cache,
        &domains,
        &directory_url,
        &private_key_der,
    )
    .await?;
    log::info!("Private key successfully stored in Redis");

    // Parse and configure
    let certs = parse_cert_chain(&cert_chain_pem)?;
    let private_key_rustls = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der));

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), private_key_rustls)?;
    let cert_info = extract_cert_info_from_der(&certs[0]);
    *cert_config.write().await = Some(ServerConfigWithCert { config: Arc::new(config), cert_info });

    Ok(())
}

pub fn load_custom_server_config(cert: &Path, key: &Path) -> Result<ServerConfigWithCert> {
    let certs = load_certificates(cert)?;
    let key = load_private_key(key)?;

    // Extract certificate info from the first certificate
    let _cert_info = extract_cert_info_from_der(&certs[0]);

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .map_err(|e| anyhow!("unable to build rustls server config: {e}"))?;
    let mut config = Arc::new(config);
    Arc::get_mut(&mut config)
        .expect("arc get mutable")
        .alpn_protocols = vec![b"http/1.1".to_vec()];
    let cert_info = extract_cert_info_from_der(&certs[0]);
    Ok(ServerConfigWithCert { config, cert_info })
}

pub fn ensure_mailto(contact: &str) -> String {
    if contact.starts_with("mailto:") {
        contact.to_string()
    } else {
        format!("mailto:{contact}")
    }
}

pub fn extract_server_cert_info(_config: &ServerConfig) -> Option<ServerCertInfo> {
    // For now, we'll create a basic certificate info with a placeholder fingerprint
    // The actual certificate parsing would require additional dependencies
    // In a production system, you'd want to parse the X.509 certificate properly

    // Create a placeholder certificate info
    // TODO: Parse actual X.509 certificate to extract real subject, issuer, etc.
    Some(ServerCertInfo {
        subject: "CN=placeholder".to_string(),
        issuer: "CN=placeholder-issuer".to_string(),
        serial_number: "0000000000000000000000000000000000000000".to_string(),
        not_before: "2024-01-01T00:00:00Z".to_string(),
        not_after: "2025-01-01T00:00:00Z".to_string(),
        fingerprint_sha256: "placeholder_fingerprint".to_string(),
    })
}

// build_upstream_uri moved to proxy_utils

/// Parse upstream address from URI, handling cases where port might be missing
fn parse_upstream_addr(upstream: &Uri) -> SocketAddr {
    if let Some(authority) = upstream.authority() {
        let host = authority.host();
        let port = authority.port_u16().unwrap_or_else(|| {
            match upstream.scheme().map(|s| s.as_str()) {
                Some("https") => 443,
                Some("http") => 80,
                _ => 80,
            }
        });

        // Try to parse as SocketAddr first
        if let Ok(addr) = format!("{}:{}", host, port).parse::<SocketAddr>() {
            return addr;
        }

        // If that fails, try to resolve the hostname (simplified - just use localhost for now)
        if let Ok(addr) = format!("127.0.0.1:{}", port).parse::<SocketAddr>() {
            return addr;
        }
    }

    // Fallback to localhost:80
    "127.0.0.1:80".parse().unwrap()
}

/// Handle captcha verification endpoint
async fn handle_captcha_verification(
    req_parts: hyper::http::request::Parts,
    req_body_bytes: Bytes,
    peer_addr: SocketAddr,
    _tls_fingerprint: Option<crate::http::tls_fingerprint::Fingerprint>,
) -> Result<Response<ProxyBody>, Infallible> {
    use crate::actions::captcha::{validate_and_mark_captcha, apply_captcha_challenge};
    use std::collections::HashMap;

    // Parse form data from request body
    let form_data = match String::from_utf8(req_body_bytes.to_vec()) {
        Ok(body) => {
            log::debug!("Captcha verification request body: {}", body);
            let parsed = form_urlencoded::parse(body.as_bytes())
                .into_owned()
                .collect::<HashMap<String, String>>();
            log::debug!("Parsed form data: {:?}", parsed);
            parsed
        }
        Err(e) => {
            log::warn!("Failed to parse captcha verification request body: {}", e);
            return Ok(build_proxy_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_body",
            ));
        }
    };

    // Extract captcha response and JWT token from form data
    let captcha_response = match form_data.get("captcha_response") {
        Some(response) => response.clone(),
        None => {
            log::warn!("Missing captcha_response in verification request from {}", peer_addr.ip());
            return Ok(build_proxy_error_response(
                StatusCode::BAD_REQUEST,
                "missing_captcha_response",
            ));
        }
    };

    let jwt_token = match form_data.get("jwt_token") {
        Some(token) => token.clone(),
        None => {
            log::warn!("Missing jwt_token in verification request from {}", peer_addr.ip());
            return Ok(build_proxy_error_response(
                StatusCode::BAD_REQUEST,
                "missing_jwt_token",
            ));
        }
    };

    // Get user agent for validation
    let user_agent = req_parts
        .headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Validate captcha and mark token as validated
    match validate_and_mark_captcha(
        captcha_response,
        jwt_token.clone(),
        peer_addr.ip().to_string(),
        Some(user_agent.clone()),
    ).await {
        Ok(true) => {
            log::info!("Captcha verification successful for IP: {}", peer_addr.ip());

            // Use the original token that was already marked as validated
            let validated_token = jwt_token.clone();

            // Generate success page with redirect
            let success_html = format!(
                r#"<!DOCTYPE html>
<html>
<head>
    <title>Verification Successful</title>
    <meta http-equiv="refresh" content="3;url=/">
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }}
        .success {{ color: green; margin: 20px 0; }}
        .redirect {{ color: #666; margin: 10px 0; }}
    </style>
</head>
<body>
    <h2>Verification Successful</h2>
    <div class="success">
        <p>Your request has been verified successfully.</p>
        <p>You will be redirected automatically in 3 seconds.</p>
    </div>
    <div class="redirect">
        <p><a href="/">Click here if you are not redirected automatically</a></p>
    </div>
    <script>
        // Set captcha token in localStorage for future requests
        const token = '{}';
        if (token) {{
            localStorage.setItem('captcha_token', token);
        }}

        // Also set a cookie for server-side access
        document.cookie = "captcha_token=" + token + "; path=/; max-age=3600; SameSite=Lax";
    </script>
</body>
</html>"#,
                validated_token
            );

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Cache-Control", "no-cache, no-store, must-revalidate")
                .header("Pragma", "no-cache")
                .header("Expires", "0")
                .body(Full::new(Bytes::from(success_html)).map_err(|e| match e {}).boxed())
                .unwrap())
        }
        Ok(false) => {
            log::warn!("Captcha verification failed for IP: {}", peer_addr.ip());

            // Generate failure page with retry option
            let failure_html = match apply_captcha_challenge() {
                Ok(html) => html,
                Err(e) => {
                    log::error!("Failed to generate captcha challenge HTML for retry: {}", e);
                    format!(
                        r#"<!DOCTYPE html>
<html>
<head>
    <title>Verification Failed</title>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }}
        .error {{ color: red; margin: 20px 0; }}
    </style>
</head>
<body>
    <h2>Verification Failed</h2>
    <div class="error">
        <p>Captcha verification failed. Please try again.</p>
        <p><a href="/">Return to main page</a></p>
    </div>
</body>
</html>"#
                    )
                }
            };

            Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Cache-Control", "no-cache, no-store, must-revalidate")
                .header("Pragma", "no-cache")
                .header("Expires", "0")
                .body(Full::new(Bytes::from(failure_html)).map_err(|e| match e {}).boxed())
                .unwrap())
        }
        Err(e) => {
            log::error!("Captcha verification error for IP {}: {}", peer_addr.ip(), e);
            Ok(build_proxy_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "captcha_verification_error",
            ))
        }
    }
}

pub async fn proxy_http_service(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext>,
    peer: Option<SocketAddr>,
    tls_fingerprint: Option<&TlsFingerprint>,
    server_cert_info: Option<ServerCertInfo>,
) -> Result<Response<ProxyBody>, Infallible> {
    let peer_addr = peer.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

    log::info!("Processing request from {}: {} {}", peer_addr, req.method(), req.uri());

    // Extract request details for logging before consuming the request
    let (req_parts, req_body) = req.into_parts();
    let req_body_bytes = match req_body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            log::warn!("Failed to read request body: {}", e);
            // For GET requests, try to continue with empty body
            if req_parts.method == Method::GET {
                log::info!("Continuing with empty body for GET request");
                Bytes::new()
            } else {
                return Ok(build_proxy_error_response(
                    StatusCode::BAD_REQUEST,
                    "body_read_error",
                ));
            }
        }
    };

    log::info!("Request body read successfully, size: {} bytes", req_body_bytes.len());

    // Handle captcha verification endpoint
    if req_parts.uri.path() == "/cgi-bin/captcha/verify" {
        return handle_captcha_verification(req_parts, req_body_bytes, peer_addr, tls_fingerprint.cloned()).await;
    }

    // Enforce TLS-only mode (except ACME challenges and captcha verification)
    if ctx.tls_only {
        let is_acme_challenge = req_parts
            .uri
            .path()
            .starts_with("/.well-known/acme-challenge/");
        let is_captcha_verify = req_parts.uri.path() == "/cgi-bin/captcha/verify";
        if !is_acme_challenge && !is_captcha_verify && tls_fingerprint.is_none() {
            // Generate access log for TLS required block
            let dst_addr = parse_upstream_addr(&ctx.upstream);
            if let Err(e) = HttpAccessLog::create_from_parts(
                &req_parts,
                &req_body_bytes,
                peer_addr,
                dst_addr,
                tls_fingerprint,
                ResponseData::for_blocked_request("tls_required", 426, None, None),
                None,
                None,
                server_cert_info.as_ref(),
            )
            .await
            {
                log::warn!("Failed to log TLS required block: {}", e);
            }

            return Ok(build_proxy_error_response(
                StatusCode::UPGRADE_REQUIRED,
                "tls_required",
            ));
        }
    }

    // Check if IP is allowed by access rules - if so, skip threat intelligence and WAF but still do content scanning
    let is_allowed_by_access_rules = is_ip_allowed_by_access_rules(peer_addr.ip());
    if is_allowed_by_access_rules {
        log::info!("Request from {} allowed by access rules, skipping threat intelligence and WAF but checking content", peer_addr.ip());

        // Perform content scanning even for trusted IPs
        log::debug!("Checking for content scanner (access rules bypass): method={}, path={}", req_parts.method, req_parts.uri.path());
        if let Some(scanner) = crate::content_scanning::get_global_content_scanner() {
            log::debug!("Content scanner found, checking if should scan (access rules bypass)");
            if scanner.should_scan(&req_parts, &req_body_bytes, peer_addr) {
                log::debug!("should_scan returned true, scanning content (access rules bypass)");

                // Check if content-type is multipart and scan accordingly
                let content_type = req_parts.headers
                    .get("content-type")
                    .and_then(|h| h.to_str().ok());

                let scan_result = if let Some(ct) = content_type {
                    if let Some(boundary) = crate::content_scanning::extract_multipart_boundary(ct) {
                        log::debug!("Detected multipart content, scanning parts individually");
                        scanner.scan_multipart_content(&req_body_bytes, &boundary).await
                    } else {
                        scanner.scan_content(&req_body_bytes).await
                    }
                } else {
                    scanner.scan_content(&req_body_bytes).await
                };

                match scan_result {
                    Ok(scan_result) => {
                        if scan_result.malware_detected {
                            log::warn!("Malware detected from trusted IP {}: {} {} - signature: {:?}",
                                peer_addr, req_parts.method, req_parts.uri,
                                scan_result.signature);

                            // Generate access log for blocked request with content scanning details
                            let dst_addr = parse_upstream_addr(&ctx.upstream);
                            let threat_data = threat::get_threat_intel(&peer_addr.ip().to_string()).await.ok().flatten();
                            if let Err(e) = HttpAccessLog::create_from_parts(
                                &req_parts,
                                &req_body_bytes,
                                peer_addr,
                                dst_addr,
                                tls_fingerprint,
                                ResponseData::for_malware_blocked_request(scan_result.signature, scan_result.error, None, threat_data.as_ref()),
                                None,
                                threat_data.as_ref(),
                                server_cert_info.as_ref(),
                            )
                            .await
                            {
                                log::warn!("Failed to log blocked request: {}", e);
                            }

                            return Ok(build_proxy_error_response(
                                StatusCode::FORBIDDEN,
                                "malware_detected",
                            ));
                        }
                    }
                    Err(e) => {
                        log::warn!("Content scanning failed for trusted IP: {}", e);
                        // On scanning error, allow the request to proceed
                    }
                }
            }
        }

        // Forward directly to upstream without threat intelligence or WAF checks
        match forward_to_upstream_with_body(&req_parts, req_body_bytes.clone(), ctx.clone()).await {
            Ok(response) => {
                // Capture response body for logging
                let (response_parts, response_body) = response.into_parts();
                let response_body_bytes = match response_body.collect().await {
                    Ok(collected) => collected.to_bytes(),
                    Err(e) => {
                        log::warn!("Failed to read response body: {}", e);
                        bytes::Bytes::new()
                    }
                };

                // Log successful requests with access rules bypass flag
                let dst_addr = parse_upstream_addr(&ctx.upstream);
                let temp_response = Response::from_parts(response_parts.clone(), Full::new(response_body_bytes.clone()).map_err(|never| match never {}).boxed());
                let mut response_data = ResponseData::from_response(temp_response).await.unwrap_or_else(|e| {
                    log::warn!("Failed to process response for logging: {}", e);
                    ResponseData::for_blocked_request("logging_error", 500, None, None)
                });

                // Add access rules bypass information to the response data
                if let Some(response_json) = response_data.response_json.as_object_mut() {
                    response_json.insert("access_rules_bypass".to_string(), serde_json::Value::Bool(true));
                }

                // Fetch threat intelligence data for trusted IP requests
                let threat_data = threat::get_threat_intel(&peer_addr.ip().to_string()).await.ok().flatten();

                if let Err(e) = HttpAccessLog::create_from_parts(
                    &req_parts,
                    &req_body_bytes,
                    peer_addr,
                    dst_addr,
                    tls_fingerprint,
                    response_data,
                    None,
                    threat_data.as_ref(),
                    server_cert_info.as_ref(),
                )
                .await
                {
                    log::warn!("Failed to log access request: {}", e);
                }

                // Reconstruct response
                let response = Response::from_parts(response_parts, Full::new(response_body_bytes).map_err(|never| match never {}).boxed());
                return Ok(response);
            }
            Err(err) => {
                log::error!(
                    "proxy error from {}: {err:?}",
                    peer.map(|p| p.to_string())
                        .unwrap_or_else(|| "<unknown>".into())
                );
                return Ok(build_proxy_error_response(
                    StatusCode::BAD_GATEWAY,
                    "proxy_error",
                ));
            }
        }
    }

    // Check for captcha challenge requirement before applying wirefilter rules
    let user_agent = req_parts
        .headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Extract captcha token from headers or cookies (removed query parameters for security)
    let captcha_token = req_parts
        .headers
        .get("x-captcha-token")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            // Check cookies for captcha token
            req_parts.headers
                .get("cookie")
                .and_then(|h| h.to_str().ok())
                .and_then(|cookie_str| {
                    cookie_str.split(';')
                        .find(|cookie| cookie.trim().starts_with("captcha_token="))
                        .and_then(|cookie| cookie.split('=').nth(1))
                })
        })
        .unwrap_or("")
        .to_string();

    log::debug!("Extracted captcha token for IP {}: length={}, from_header={}, from_cookie={}",
                peer_addr.ip(),
                captcha_token.len(),
                req_parts.headers.get("x-captcha-token").is_some(),
                req_parts.headers.get("cookie").map_or(false, |h| h.to_str().map_or(false, |s| s.contains("captcha_token="))));

    // Check if captcha challenge is required based on threat intelligence
    let challenge_required = match threat::get_waf_fields(&peer_addr.ip().to_string()).await {
        Ok(Some(waf_fields)) => waf_fields.threat_advice == "challenge",
        _ => false,
    };

    // Handle captcha challenge logic
    if challenge_required {
        log::debug!("Captcha challenge required for IP: {}, token length: {}", peer_addr.ip(), captcha_token.len());

        // Validate captcha token if present
        let captcha_validated = if !captcha_token.is_empty() {
            log::debug!("Validating captcha token for IP: {}", peer_addr.ip());
            match validate_captcha_token(&captcha_token, &peer_addr.ip().to_string(), &user_agent).await {
                Ok(true) => {
                    log::debug!("Captcha token validated successfully for IP: {}", peer_addr.ip());
                    true
                }
                Ok(false) => {
                    log::debug!("Captcha token validation failed for IP: {}", peer_addr.ip());
                    false
                }
                Err(e) => {
                    log::warn!("Captcha token validation error for IP {}: {}", peer_addr.ip(), e);
                    false
                }
            }
        } else {
            log::debug!("No captcha token provided for IP: {}", peer_addr.ip());
            false
        };

        if !captcha_validated {
            // Reuse existing token if available, otherwise generate new one
            let captcha_token = if !captcha_token.is_empty() {
                log::debug!("Reusing existing captcha token for threat challenge IP: {}", peer_addr.ip());
                captcha_token
            } else {
                // Extract JA4 fingerprint from TLS fingerprint if available
                let ja4_fingerprint = tls_fingerprint.as_ref().map(|fp| fp.ja4.clone());

                // Generate a new captcha token
                match generate_captcha_token(
                    peer_addr.ip().to_string(),
                    user_agent.clone(),
                    ja4_fingerprint,
                ).await {
                    Ok(token) => {
                        log::debug!("Generated new captcha token for threat challenge IP: {}", peer_addr.ip());
                        token.token
                    },
                    Err(e) => {
                        log::error!("Failed to generate captcha token for IP {}: {}", peer_addr.ip(), e);
                        return Ok(build_proxy_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "captcha_token_generation_failed",
                        ));
                    }
                }
            };

            // Generate captcha challenge HTML with JWT token
            let challenge_html = match apply_captcha_challenge_with_token(&captcha_token) {
                Ok(html) => html,
                Err(e) => {
                    log::warn!("Failed to generate captcha challenge HTML with token: {}. Falling back to basic challenge.", e);
                    // Fallback to basic captcha challenge without token
                    match apply_captcha_challenge() {
                        Ok(html) => html,
                        Err(e2) => {
                            log::error!("Failed to generate basic captcha challenge HTML: {}", e2);
                            return Ok(build_proxy_error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "captcha_challenge_generation_failed",
                            ));
                        }
                    }
                }
            };

            log::info!("Captcha challenge required for IP: {}", peer_addr.ip());

            // Generate access log for captcha challenge
            let dst_addr = parse_upstream_addr(&ctx.upstream);
            let threat_data = threat::get_threat_intel(&peer_addr.ip().to_string()).await.ok().flatten();
            if let Err(e) = HttpAccessLog::create_from_parts(
                &req_parts,
                &req_body_bytes,
                peer_addr,
                dst_addr,
                tls_fingerprint,
                ResponseData::for_blocked_request("captcha_challenge_required", 403, None, threat_data.as_ref()),
                None,
                threat_data.as_ref(),
                server_cert_info.as_ref(),
            )
            .await
            {
                log::warn!("Failed to log captcha challenge request: {}", e);
            }

            // Return captcha challenge page with token
            let body = challenge_html;
            let boxed = Full::new(Bytes::from(body))
                .map_err(|never| match never {})
                .boxed();
            let response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Cache-Control", "no-cache, no-store, must-revalidate")
                .header("Pragma", "no-cache")
                .header("Expires", "0")
                .header("X-Captcha-Token", &captcha_token)
                .header("Set-Cookie", format!("captcha_token={}; Path=/; Max-Age=3600; SameSite=Lax; HttpOnly", captcha_token))
                .body(boxed)
                .unwrap();

            return Ok(response);
        }
    }

    // Apply wirefilter rules before forwarding to upstream
    if let Some(filter) = get_global_http_filter() {
        match filter.should_block_request_from_parts(&req_parts, &req_body_bytes, peer_addr).await {
            Ok(Some(waf_result)) => {
                log::info!("Request {} by wirefilter rule '{}' from {}: {} {}",
                    match waf_result.action {
                        crate::wirefilter::WafAction::Block => "blocked",
                        crate::wirefilter::WafAction::Challenge => "challenged",
                        crate::wirefilter::WafAction::Allow => "allowed",
                    },
                    waf_result.rule_name,
                    peer_addr, req_parts.method, req_parts.uri);

                match waf_result.action {
                    crate::wirefilter::WafAction::Block => {
                        // Fetch threat intelligence data for access log
                        let threat_data = threat::get_threat_intel(&peer_addr.ip().to_string()).await.ok().flatten();

                        // Generate access log for blocked request
                        let dst_addr = parse_upstream_addr(&ctx.upstream);
                        if let Err(e) = HttpAccessLog::create_from_parts(
                            &req_parts,
                            &req_body_bytes,
                            peer_addr,
                            dst_addr,
                            tls_fingerprint,
                            ResponseData::for_blocked_request("request_blocked_by_filter", 403, Some(waf_result.clone()), threat_data.as_ref()),
                            Some(&waf_result),
                            threat_data.as_ref(),
                            server_cert_info.as_ref(),
                        )
                        .await
                        {
                            log::warn!("Failed to log blocked request: {}", e);
                        }

                        return Ok(build_proxy_error_response(
                            StatusCode::FORBIDDEN,
                            "request_blocked_by_filter",
                        ));
                    }
                    crate::wirefilter::WafAction::Challenge => {
                        // Check if there's already a validated captcha token
                        let captcha_validated = if !captcha_token.is_empty() {
                            log::debug!("Validating captcha token for wirefilter challenge IP: {}", peer_addr.ip());
                            match validate_captcha_token(&captcha_token, &peer_addr.ip().to_string(), &user_agent).await {
                                Ok(true) => {
                                    log::debug!("Captcha token validated successfully for wirefilter challenge IP: {}", peer_addr.ip());
                                    true
                                }
                                Ok(false) => {
                                    log::debug!("Captcha token validation failed for wirefilter challenge IP: {}", peer_addr.ip());
                                    false
                                }
                                Err(e) => {
                                    log::warn!("Captcha token validation error for wirefilter challenge IP {}: {}", peer_addr.ip(), e);
                                    false
                                }
                            }
                        } else {
                            log::debug!("No captcha token provided for wirefilter challenge IP: {}", peer_addr.ip());
                            false
                        };

                        if captcha_validated {
                            log::debug!("Captcha already validated for wirefilter challenge IP: {}, allowing request", peer_addr.ip());

                            // Generate access log for challenged request that was allowed
                            let dst_addr = parse_upstream_addr(&ctx.upstream);
                            let threat_data = threat::get_threat_intel(&peer_addr.ip().to_string()).await.ok().flatten();

                            // Create a temporary response for logging
                            let temp_response = Response::builder()
                                .status(200)
                                .body(http_body_util::Full::new(bytes::Bytes::new()).map_err(|never| match never {}).boxed())
                                .unwrap();
                            let response_data = ResponseData::from_response(temp_response).await.unwrap_or_else(|_| {
                                ResponseData::for_blocked_request("challenge_passed", 200, Some(waf_result.clone()), threat_data.as_ref())
                            });

                            if let Err(e) = HttpAccessLog::create_from_parts(
                                &req_parts,
                                &req_body_bytes,
                                peer_addr,
                                dst_addr,
                                tls_fingerprint,
                                response_data,
                                Some(&waf_result),
                                threat_data.as_ref(),
                                server_cert_info.as_ref(),
                            )
                            .await
                            {
                                log::warn!("Failed to log challenged request: {}", e);
                            }

                            // Continue processing the request
                        } else {
                            // Reuse existing token if available, otherwise generate new one
                            let captcha_token = if !captcha_token.is_empty() {
                                log::debug!("Reusing existing captcha token for WAF challenge IP: {}", peer_addr.ip());
                                captcha_token
                            } else {
                                // Extract JA4 fingerprint from TLS fingerprint if available
                                let ja4_fingerprint = tls_fingerprint.as_ref().map(|fp| fp.ja4.clone());

                                // Generate a new captcha token for WAF challenge
                                match generate_captcha_token(
                                    peer_addr.ip().to_string(),
                                    user_agent.clone(),
                                    ja4_fingerprint,
                                ).await {
                                    Ok(token) => {
                                        log::debug!("Generated new captcha token for WAF challenge IP: {}", peer_addr.ip());
                                        token.token
                                    },
                                    Err(e) => {
                                        log::error!("Failed to generate captcha token for WAF challenge IP {}: {}", peer_addr.ip(), e);
                                        return Ok(build_proxy_error_response(
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                            "captcha_token_generation_failed",
                                        ));
                                    }
                                }
                            };

                        // Generate captcha challenge HTML with JWT token
                        let challenge_html = match apply_captcha_challenge_with_token(&captcha_token) {
                            Ok(html) => html,
                            Err(e) => {
                                log::warn!("Failed to generate captcha challenge HTML with token: {}. Falling back to basic challenge.", e);
                                // Fallback to basic captcha challenge without token
                                match apply_captcha_challenge() {
                                    Ok(html) => html,
                                    Err(e2) => {
                                        log::error!("Failed to generate basic captcha challenge HTML: {}", e2);
                                        return Ok(build_proxy_error_response(
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                            "captcha_challenge_generation_failed",
                                        ));
                                    }
                                }
                            }
                        };

                        log::info!("Captcha challenge required for IP: {}", peer_addr.ip());

                        // Generate access log for captcha challenge
                        let dst_addr = parse_upstream_addr(&ctx.upstream);
                        let threat_data = threat::get_threat_intel(&peer_addr.ip().to_string()).await.ok().flatten();
                        let response_data = ResponseData::for_blocked_request("captcha_challenge_required", 403, None, threat_data.as_ref());
                        if let Err(e) = HttpAccessLog::create_from_parts(
                            &req_parts,
                            &req_body_bytes,
                            peer_addr,
                            dst_addr,
                            tls_fingerprint,
                            response_data,
                            None,
                            threat_data.as_ref(),
                            server_cert_info.as_ref(),
                        ).await {
                            log::warn!("Failed to log captcha challenge request: {}", e);
                        }

                        // Return captcha challenge page with token
                        let body = challenge_html;
                        let boxed = Full::new(Bytes::from(body))
                            .map_err(|never| match never {})
                            .boxed();
                        return Ok(Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .header("Content-Type", "text/html; charset=utf-8")
                            .header("Cache-Control", "no-cache, no-store, must-revalidate")
                            .header("Pragma", "no-cache")
                            .header("Expires", "0")
                            .header("X-Captcha-Token", &captcha_token)
                            .header("Set-Cookie", format!("captcha_token={}; Path=/; Max-Age=3600; SameSite=Lax; HttpOnly", captcha_token))
                            .body(boxed)
                            .unwrap());
                        }
                    }
                    crate::wirefilter::WafAction::Allow => {
                        // Request allowed, continue processing
                    }
                }
            }
            Ok(None) => {
                // Request allowed, continue processing
            }
            Err(e) => {
                log::warn!("Wirefilter error: {}", e);
                // On filter error, allow the request to proceed
            }
        }
    }

    // Perform content scanning after WAF rules
    log::debug!("Checking for content scanner: method={}, path={}", req_parts.method, req_parts.uri.path());
    if let Some(scanner) = crate::content_scanning::get_global_content_scanner() {
        log::debug!("Content scanner found, checking if should scan");
        if scanner.should_scan(&req_parts, &req_body_bytes, peer_addr) {
            log::debug!("should_scan returned true, scanning content");

            // Check if content-type is multipart and scan accordingly
            let content_type = req_parts.headers
                .get("content-type")
                .and_then(|h| h.to_str().ok());

            let scan_result = if let Some(ct) = content_type {
                if let Some(boundary) = crate::content_scanning::extract_multipart_boundary(ct) {
                    log::debug!("Detected multipart content, scanning parts individually");
                    scanner.scan_multipart_content(&req_body_bytes, &boundary).await
                } else {
                    scanner.scan_content(&req_body_bytes).await
                }
            } else {
                scanner.scan_content(&req_body_bytes).await
            };

            match scan_result {
                    Ok(scan_result) => {
                        if scan_result.malware_detected {
                            log::warn!("Malware detected from {}: {} {} - signature: {:?}",
                                peer_addr, req_parts.method, req_parts.uri,
                                scan_result.signature);

                            // Generate access log for blocked request with content scanning details
                            let dst_addr = parse_upstream_addr(&ctx.upstream);
                            let threat_data = threat::get_threat_intel(&peer_addr.ip().to_string()).await.ok().flatten();
                            if let Err(e) = HttpAccessLog::create_from_parts(
                                &req_parts,
                                &req_body_bytes,
                                peer_addr,
                                dst_addr,
                                tls_fingerprint,
                                ResponseData::for_malware_blocked_request(scan_result.signature, scan_result.error, None, threat_data.as_ref()),
                                None,
                                threat_data.as_ref(),
                                server_cert_info.as_ref(),
                            )
                            .await
                            {
                                log::warn!("Failed to log blocked request: {}", e);
                            }

                            return Ok(build_proxy_error_response(
                                StatusCode::FORBIDDEN,
                                "malware_detected",
                            ));
                        }
                    }
                Err(e) => {
                    log::warn!("Content scanning failed: {}", e);
                    // On scanning error, allow the request to proceed
                }
            }
        } else {
            log::debug!("should_scan returned false, not scanning");
        }
    } else {
        log::debug!("No content scanner found");
    }

    match forward_to_upstream_with_body(&req_parts, req_body_bytes.clone(), ctx.clone()).await {
        Ok(response) => {
            // Capture response body for logging
            let (response_parts, response_body) = response.into_parts();
            let response_body_bytes = match response_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    log::warn!("Failed to read response body: {}", e);
                    bytes::Bytes::new()
                }
            };

            // Log successful requests before reconstructing response
            let dst_addr = parse_upstream_addr(&ctx.upstream);
            let temp_response = Response::from_parts(response_parts.clone(), Full::new(response_body_bytes.clone()).map_err(|never| match never {}).boxed());
            let response_data = ResponseData::from_response(temp_response).await.unwrap_or_else(|e| {
                log::warn!("Failed to process response for logging: {}", e);
                ResponseData::for_blocked_request("logging_error", 500, None, None)
            });

            // Fetch threat intelligence data for successful requests
            let threat_data = threat::get_threat_intel(&peer_addr.ip().to_string()).await.ok().flatten();

            // Check if this request was challenged by WAF (indicated by presence of captcha token)
            let was_challenged = req_parts.headers.get("x-captcha-token").is_some() ||
                                req_parts.headers.get("cookie")
                                    .and_then(|h| h.to_str().ok())
                                    .map_or(false, |s| s.contains("captcha_token="));

            // Skip logging if this request was already logged due to WAF challenge
            if was_challenged {
                log::debug!("Skipping duplicate access log for challenged request from {}", peer_addr.ip());
            } else {
                // If the request was challenged, we need to determine which WAF rule triggered it
                // For now, we'll create a generic WAF result for challenged requests
                let waf_result = None; // No WAF result for non-challenged requests

                if let Err(e) = HttpAccessLog::create_from_parts(
                    &req_parts,
                    &req_body_bytes,
                    peer_addr,
                    dst_addr,
                    tls_fingerprint,
                    response_data,
                    waf_result.as_ref(),
                    threat_data.as_ref(),
                    server_cert_info.as_ref(),
                )
                .await
                {
                    log::warn!("Failed to log access request: {}", e);
                }
            }

            // Reconstruct response
            let response = Response::from_parts(response_parts, Full::new(response_body_bytes).map_err(|never| match never {}).boxed());
            Ok(response)
        }
        Err(err) => {
            log::error!(
                "proxy error from {}: {err:?}",
                peer.map(|p| p.to_string())
                    .unwrap_or_else(|| "<unknown>".into())
            );
            Ok(build_proxy_error_response(
                StatusCode::BAD_GATEWAY,
                "proxy_error",
            ))
        }
    }
}

pub async fn serve_proxy_conn<S>(
    stream: S,
    peer: Option<SocketAddr>,
    ctx: Arc<ProxyContext>,
    tls_fingerprint: Option<&TlsFingerprint>,
    server_cert_info: Option<ServerCertInfo>,
) -> Result<(), anyhow::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| proxy_http_service(req, ctx.clone(), peer, tls_fingerprint, server_cert_info.clone())),
        )
        .await
        .map_err(|e| anyhow!("http1 connection error: {e}"))
}

// pub async fn run_control_plane( ... ) { /* omitted for brevity */ }

pub async fn run_custom_tls_proxy(
    listener: TcpListener,
    server_config: ServerConfigWithCert,
    ctx: Arc<ProxyContext>,
    tls_state: SharedTlsState,
    skels: Vec<Arc<bpf::FilterSkel<'static>>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    tls_state
        .set_running_detail("custom TLS certificate active")
        .await;
    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(tuple) => tuple,
                    Err(e) => {
                        log::error!("tls accept error: {e}");
                        continue;
                    }
                };
                let ctx_clone = ctx.clone();
                let tls_state_clone = tls_state.clone();
                let server_config_clone = server_config.clone();
                let skels_clone = skels.clone();
                tokio::spawn(async move {
                    // Handle PROXY protocol if enabled
                    let (stream, real_client_addr) = if ctx_clone.proxy_protocol_enabled {
                        use crate::proxy_protocol::ProxyProtocolStream;
                        match ProxyProtocolStream::new(stream, true, ctx_clone.proxy_protocol_timeout_ms).await {
                            Ok(proxy_stream) => {
                                let real_addr = proxy_stream.real_client_addr().unwrap_or(peer);
                                log::debug!("PROXY protocol detected: real client {} -> proxy {}", real_addr, peer);
                                (proxy_stream.inner(), real_addr)
                            }
                            Err(e) => {
                                log::warn!("Failed to parse PROXY protocol header: {}, dropping connection", e);
                                return;
                            }
                        }
                    } else {
                        (stream, peer)
                    };

                    // Handle TLS fingerprinting based on PROXY protocol setting
                    let (stream, fingerprint) = if ctx_clone.proxy_protocol_enabled {
                        // When PROXY protocol is enabled, skip fingerprinting to avoid stream conflicts
                        // But we'll create a minimal fingerprint later when we know it's HTTPS
                        (stream, None)
                    } else {
                        // Normal TLS fingerprinting when PROXY protocol is disabled
                        match FingerprintTcpStream::new(stream).await {
                            Ok(s) => {
                                let fingerprint = s.fingerprint().cloned();
                                (s.inner, fingerprint)
                            }
                            Err(err) => {
                                log::debug!("Connection disconnected during TLS fingerprinting from {peer}: {err}");
                                return;
                            }
                        }
                    };

                    let peer_addr = match stream.peer_addr() {
                        Ok(addr) => addr,
                        Err(err) => {
                            log::error!("failed to get peer address: {err}");
                            return;
                        }
                    };
                    // Pre-TLS ban check (both IPv4 and IPv6) - use real client address if available
                    let ban_check_addr = real_client_addr;
                    if is_ipv4_banned(ban_check_addr, &skels_clone) || is_ipv6_banned(ban_check_addr, &skels_clone) {
                        let mut s = stream;
                        let _ = s.write_all(BANNED_MESSAGE.as_bytes()).await;
                        let _ = s.shutdown().await;
                        return;
                    }
                    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);

                    match acceptor.await {
                        Ok(start) => {
                            // Check SNI against domain filter
                            if ctx_clone.domain_filter.is_enabled() {
                                let client_hello = start.client_hello();
                                let sni = client_hello.server_name();
                                if let Some(sni_str) = sni {
                                    if !ctx_clone.domain_filter.is_allowed(sni_str) {
                                        log::warn!("TLS SNI '{}' blocked by domain filter from {}", sni_str, peer_addr);
                                        return;
                                    }
                                } else {
                                    // No SNI present - block if filter is enabled
                                    log::warn!("TLS connection without SNI blocked by domain filter from {}", peer_addr);
                                    return;
                                }
                            }

                            match start.into_stream(server_config_clone.config.clone()).await {
                                Ok(tls_stream) => {
                                    if let Err(err) = serve_proxy_conn(tls_stream, Some(real_client_addr), ctx_clone.clone(), fingerprint.as_ref(), server_config_clone.cert_info.clone()).await {
                                    log::error!("TLS proxy error from {real_client_addr}: {err:?}");
                                        tls_state_clone
                                            .set_error_detail(format!("last connection error: {err}"))
                                            .await;
                                    }
                                }
                                Err(err) => {
                                    log::warn!("TLS handshake error from {peer_addr}: {err}");
                                    tls_state_clone
                                        .set_error_detail(format!("handshake failure: {err}"))
                                        .await;
                                }
                            }
                        }
                        Err(err) => {
                            log::warn!("TLS handshake error from {peer_addr}: {err}");
                            tls_state_clone
                                .set_error_detail(format!("handshake failure: {err}"))
                                .await;
                        }
                    }
                });
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    log::info!("custom TLS proxy shutdown signal received");
                    break;
                }
            }
        }
    }
    Ok(())
}

pub async fn run_acme_http01_proxy(
    https_listener: TcpListener,
    http_listener: TcpListener,
    acme_config: &crate::cli::AcmeConfig,
    redis_config: &crate::cli::RedisConfig,
    domains: Vec<String>,
    ctx: Arc<ProxyContext>,
    tls_state: SharedTlsState,
    skels: Vec<Arc<bpf::FilterSkel<'static>>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if !acme_config.accept_tos {
        return Err(anyhow!(
            "ACME mode requires accept_tos: true in config to acknowledge the certificate authority terms"
        ));
    }

    if domains.is_empty() {
        return Err(anyhow!("ACME mode requires at least one domain"));
    }

    let contacts = if acme_config.contacts.is_empty() {
        vec![]
    } else {
        acme_config.contacts
            .iter()
            .map(|c| ensure_mailto(c))
            .collect::<Vec<_>>()
    };

    tls_state
        .set_running_detail(format!(
            "ACME HTTP-01 manager initializing for domains {:?}",
            domains
        ))
        .await;

    // Initialize Redis cache
    let redis_cache = RedisAcmeCache::new(redis_config.prefix.clone() + ":acme").await?;

    // Shared store for HTTP-01 challenge tokens
    let challenge_store: ChallengeStore = Arc::new(RwLock::new(std::collections::HashMap::new()));

    // Determine directory URL
    let directory_url = if let Some(dir) = &acme_config.directory {
        dir.clone()
    } else if acme_config.use_prod {
        LetsEncrypt::Production.url().to_string()
    } else {
        LetsEncrypt::Staging.url().to_string()
    };

    // Shared certificate configuration
    let cert_config: Arc<RwLock<Option<ServerConfigWithCert>>> = Arc::new(RwLock::new(None));

    // Spawn ACME certificate manager task
    let cert_config_clone = cert_config.clone();
    let challenge_store_clone = challenge_store.clone();
    let domains_clone = domains.clone();
    let directory_url_clone = directory_url.clone();
    let contacts_clone = contacts.clone();
    let redis_cache_clone = redis_cache.clone();
    let tls_state_clone = tls_state.clone();

    tokio::spawn(async move {
        if let Err(_err) = manage_acme_certificate_with_retry(
            domains_clone,
            directory_url_clone,
            contacts_clone,
            redis_cache_clone,
            cert_config_clone,
            challenge_store_clone,
            tls_state_clone,
        )
        .await
        {
            // Error logging is handled by the retry function
            // Note: tls_state_clone is already moved into the retry function
        }
    });

    tls_state
        .set_running_detail("ACME HTTP-01 certificate manager running")
        .await;

    // Spawn HTTP server for ACME challenges and regular HTTP traffic
    let http_ctx = ctx.clone();
    let http_skels = skels.clone();
    let mut http_shutdown = shutdown.clone();
    let challenge_store_http = challenge_store.clone();

    tokio::spawn(async move {
                loop {
            tokio::select! {
                accept = http_listener.accept() => {
                    match accept {
                        Ok((stream, peer)) => {
                            // Handle PROXY protocol if enabled
                            let (stream, real_client_addr) = if http_ctx.proxy_protocol_enabled {
                                use crate::proxy_protocol::ProxyProtocolStream;
                                match ProxyProtocolStream::new(stream, true, http_ctx.proxy_protocol_timeout_ms).await {
                                    Ok(proxy_stream) => {
                                        let real_addr = proxy_stream.real_client_addr().unwrap_or(peer);
                                        log::debug!("PROXY protocol detected: real client {} -> proxy {}", real_addr, peer);
                                        (proxy_stream.inner(), real_addr)
                                    }
                                    Err(e) => {
                                        log::warn!("Failed to parse PROXY protocol header: {}, dropping connection", e);
                                        continue;
                                    }
                                }
                            } else {
                                (stream, peer)
                            };

                            // Check if banned (both IPv4 and IPv6) - use real client address if available
                            if is_ipv4_banned(real_client_addr, &http_skels) || is_ipv6_banned(real_client_addr, &http_skels) {
                                let mut s = stream;
                                let _ = s.write_all(BANNED_MESSAGE.as_bytes()).await;
                                let _ = s.shutdown().await;
                                    continue;
                                }

                            let ctx_clone = http_ctx.clone();
                            let challenges = challenge_store_http.clone();

                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let ctx_service = ctx_clone.clone();
                                let challenges_service = challenges.clone();

                                let service = service_fn(move |req: Request<Incoming>| {
                                    let path = req.uri().path().to_string();
                                    let challenges_req = challenges_service.clone();
                                    let ctx_req = ctx_service.clone();

                                    async move {
                                        if path.starts_with("/.well-known/acme-challenge/") {
                                            if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
                                                let store = challenges_req.read().await;
                                                if let Some(key_auth) = store.get(token) {
                                                    let response = Response::builder()
                                                        .status(StatusCode::OK)
                                                        .header("Content-Type", "text/plain")
                                                        .body(Full::new(Bytes::from(key_auth.clone())).map_err(|e| match e {}).boxed())
                                                        .unwrap();
                                                    return Ok(response);
                                                }
                                            }
                                            let response = Response::builder()
                                                .status(StatusCode::NOT_FOUND)
                                                .body(Full::new(Bytes::from("Challenge not found")).map_err(|e| match e {}).boxed())
                                                .unwrap();
                                            return Ok(response);
                                        } else {
                                            proxy_http_service(req, ctx_req, Some(real_client_addr), None, None).await
                                        }
                                    }
                                });

                                if let Err(err) = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                            log::warn!("HTTP connection error from {peer}: {err}");
                                }
                            });
                        }
                        Err(err) => {
                            log::warn!("HTTP accept error: {err}");
                        }
                    }
                }
                changed = http_shutdown.changed() => {
                    if changed.is_ok() && *http_shutdown.borrow() {
                        log::info!("HTTP server shutdown signal received");
                        break;
                    }
                }
            }
        }
    });

    // HTTPS server loop
    loop {
        tokio::select! {
            accept = https_listener.accept() => {
                match accept {
                    Ok((stream, peer)) => {
                        // Handle PROXY protocol if enabled
                        let (stream, real_client_addr) = if ctx.proxy_protocol_enabled {
                            use crate::proxy_protocol::ProxyProtocolStream;
                            match ProxyProtocolStream::new(stream, true, ctx.proxy_protocol_timeout_ms).await {
                                Ok(proxy_stream) => {
                                    let real_addr = proxy_stream.real_client_addr().unwrap_or(peer);
                                    log::debug!("PROXY protocol detected: real client {} -> proxy {}", real_addr, peer);
                                    (proxy_stream.inner(), real_addr)
                                }
                                Err(e) => {
                                    log::warn!("Failed to parse PROXY protocol header: {}, dropping connection", e);
                                    continue;
                                }
                            }
                        } else {
                            (stream, peer)
                        };

                        // Check if banned (both IPv4 and IPv6) - use real client address if available
                        if is_ipv4_banned(real_client_addr, &skels) || is_ipv6_banned(real_client_addr, &skels) {
                            let mut s = stream;
                            let _ = s.write_all(BANNED_MESSAGE.as_bytes()).await;
                            let _ = s.shutdown().await;
                            continue;
                        }

                        let cert_cfg = cert_config.read().await.clone();
                        let Some(config_with_cert) = cert_cfg else {
                            log::warn!("HTTPS connection from {real_client_addr} but certificate not ready yet");
                            continue;
                        };

                        let ctx_clone = ctx.clone();
                        let tls_state_clone = tls_state.clone();

                        tokio::spawn(async move {
                            // Skip TLS fingerprinting if PROXY protocol was used to avoid stream state conflicts
                            let (stream, fingerprint) = if ctx_clone.proxy_protocol_enabled {
                                // When PROXY protocol is enabled, skip fingerprinting to avoid stream conflicts
                                (stream, None)
                            } else {
                                // Normal TLS fingerprinting when PROXY protocol is disabled
                                match FingerprintTcpStream::new(stream).await {
                                    Ok(s) => {
                                        let fingerprint = s.fingerprint().cloned();
                                        (s.inner, fingerprint)
                                    }
                                    Err(err) => {
                                        log::debug!("Connection disconnected during TLS fingerprinting from {peer}: {err}");
                                        return;
                                    }
                                }
                            };

                            let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
                            match acceptor.await {
                                Ok(start) => {
                                    // Check SNI against domain filter
                                    if ctx_clone.domain_filter.is_enabled() {
                                        let client_hello = start.client_hello();
                                        let sni = client_hello.server_name();
                                        if let Some(sni_str) = sni {
                                            if !ctx_clone.domain_filter.is_allowed(sni_str) {
                                    log::info!("TLS SNI '{}' blocked by domain filter from {}", sni_str, peer);
                                                return;
                                            }
                                        } else {
                                            // No SNI present - block if filter is enabled
                                            log::info!("TLS connection without SNI blocked by domain filter from {}", peer);
                                            return;
                                        }
                                    }

                                    match start.into_stream(config_with_cert.config.clone()).await {
                                        Ok(tls_stream) => {
                                            if let Err(err) = serve_proxy_conn(tls_stream, Some(real_client_addr), ctx_clone, fingerprint.as_ref(), config_with_cert.cert_info.clone()).await {
                                                log::error!("HTTPS proxy error from {real_client_addr}: {err:?}");
                                                tls_state_clone.set_error_detail(format!("HTTPS session error: {err}")).await;
                            } else {
                                tls_state_clone.set_running_detail("ACME certificate active").await;
                                            }
                                        }
                                        Err(err) => {
                                            log::warn!("TLS handshake error from {peer}: {err}");
                                        }
                                    }
                                }
                                Err(err) => {
                                    log::warn!("TLS accept error from {peer}: {err}");
                                }
                            }
                        });
                    }
                    Err(err) => {
                        log::warn!("HTTPS accept error: {err}");
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    log::info!("HTTPS server shutdown signal received");
                    break;
                }
            }
        }
    }

    Ok(())
}

pub async fn run_http_proxy(
    listener: TcpListener,
    ctx: Arc<ProxyContext>,
    _skels: Vec<Arc<bpf::FilterSkel<'static>>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(tuple) => tuple,
                    Err(e) => { log::error!("http accept error: {e}"); continue; }
                };
                let ctx_clone = ctx.clone();
                let skel_clone = None::<Arc<bpf::FilterSkel<'static>>>; // not used in plain HTTP path
                tokio::spawn(async move {
                    if let Err(err) = handle_http_connection(stream, peer, ctx_clone, skel_clone).await {
                        log::error!("http connection error: {err:?}");
                    }
                });
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() { break; }
            }
        }
    }
    Ok(())
}

async fn handle_http_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    ctx: Arc<ProxyContext>,
    _skel: Option<Arc<bpf::FilterSkel<'static>>>,
) -> Result<()> {
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use crate::proxy_protocol::ProxyProtocolStream;

    // Handle PROXY protocol if enabled
    let (stream, real_client_addr) = if ctx.proxy_protocol_enabled {
        match ProxyProtocolStream::new(stream, true, ctx.proxy_protocol_timeout_ms).await {
            Ok(proxy_stream) => {
                let real_addr = proxy_stream.real_client_addr().unwrap_or(peer);
                log::debug!("PROXY protocol detected: real client {} -> proxy {}", real_addr, peer);
                (proxy_stream.inner(), real_addr)
            }
            Err(e) => {
                log::warn!("Failed to parse PROXY protocol header: {}, dropping connection", e);
                return Ok(());
            }
        }
    } else {
        (stream, peer)
    };

    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        async move { proxy_http_service(req, ctx, Some(real_client_addr), None, None).await }
    });

    let io = TokioIo::new(stream);
    let conn = http1::Builder::new().serve_connection(io, service);
    if let Err(err) = conn.await {
        log::warn!("HTTP connection error: {err}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_blocked_request_access_log() {
        // Create a simple request using Request::builder
        let req = Request::builder()
            .method("GET")
            .uri("https://example.com/test?param=value")
            .body(http_body_util::Full::new(Bytes::new()))
            .unwrap();

        let (req_parts, _body) = req.into_parts();
        let req_body_bytes = Bytes::new();
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let dst_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

        // Create a test server certificate info
        let server_cert_info = Some(ServerCertInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "1234567890".to_string(),
            not_before: "2023-01-01T00:00:00Z".to_string(),
            not_after: "2024-01-01T00:00:00Z".to_string(),
            fingerprint_sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
        });

        // Test the blocked request access log function
        let result = HttpAccessLog::create_from_parts(
            &req_parts,
            &req_body_bytes,
            peer_addr,
            dst_addr,
            None,
            ResponseData::for_blocked_request("test_block_reason", 403, None, None),
            None,
                                None,
                                server_cert_info.as_ref(),
                            )
        .await;

        // Should succeed
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_empty_body_sha256_and_host_extraction() {
        // Create a request with Host header and empty body
        let req = Request::builder()
            .method("GET")
            .uri("/test")
            .header("Host", "example.com")
            .body(http_body_util::Full::new(Bytes::new()))
            .unwrap();

        let (req_parts, _body) = req.into_parts();
        let req_body_bytes = Bytes::new();
        let peer_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let dst_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

        // Create a test server certificate info
        let server_cert_info = Some(ServerCertInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            serial_number: "1234567890".to_string(),
            not_before: "2023-01-01T00:00:00Z".to_string(),
            not_after: "2024-01-01T00:00:00Z".to_string(),
            fingerprint_sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
        });

        // Test the access log function
        let result = HttpAccessLog::create_from_parts(
            &req_parts,
            &req_body_bytes,
            peer_addr,
            dst_addr,
            None,
            ResponseData::for_blocked_request("test_block_reason", 403, None, None),
            None,
                                None,
                                server_cert_info.as_ref(),
                            )
        .await;

        // Should succeed
        assert!(result.is_ok());

        // Verify empty body SHA256
        let empty_sha256 = format!("{:x}", sha2::Sha256::digest(b""));
        assert_eq!(empty_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        // Verify host extraction from Host header
        let extracted_host = req_parts.headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .unwrap_or_else(|| "unknown".to_string());
        assert_eq!(extracted_host, "example.com");
    }
}
