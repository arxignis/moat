use gethostname::gethostname;
use local_ip_address::local_ip;
use std::convert::Infallible;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context as TaskContext, Poll};

use crate::arxignis::{ArxignisClient, ScanRequest, verify_captcha_token};
use crate::cli::Args;
use crate::domain_filter::DomainFilter;
use crate::proxy_utils::{ProxyBody, forward_to_upstream_with_body};
use crate::wirefilter::get_global_http_filter;
use crate::{bpf, utils::bpf_utils};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use clap::ValueEnum;
use futures_rustls::rustls::{ClientConfig as AcmeClientConfig, RootCertStore};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::HOST;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use libbpf_rs::MapCore;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_acme::{AccountCache, CertCache};
use rustls_pemfile::{certs, private_key};
use serde::Serialize;
use serde::ser::Serializer;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock, watch};
use tokio_rustls::LazyConfigAcceptor;
use tokio_stream::wrappers::TcpListenerStream;

use self::tls_fingerprint::{Fingerprint as TlsFingerprint, fingerprint_client_hello};

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

#[derive(Debug)]
pub struct FingerprintTcpStream {
    inner: TcpStream,
    peer_addr: SocketAddr,
    fingerprint: Option<TlsFingerprint>,
}

impl FingerprintTcpStream {
    pub async fn new(stream: TcpStream) -> io::Result<Self> {
        let peer_addr = stream.peer_addr()?;
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
    pub fn new(inner: TcpListenerStream) -> Self {
        Self {
            inner,
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
                Poll::Ready(Ok((stream, fp, peer))) => {
                    log_tls_fingerprint(peer, fp.as_ref());
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

pub fn log_tls_fingerprint(peer: SocketAddr, fingerprint: Option<&TlsFingerprint>) {
    if let Some(fp) = fingerprint {
        println!(
            "TLS client {peer}: ja4={} ja4_raw={} ja4_unsorted={} ja4_raw_unsorted={} version={} sni={} alpn={}",
            fp.ja4,
            fp.ja4_raw,
            fp.ja4_unsorted,
            fp.ja4_raw_unsorted,
            fp.tls_version,
            fp.sni.as_deref().unwrap_or("-"),
            fp.alpn.as_deref().unwrap_or("-")
        );
    }
}

pub fn ipv4_to_u32_be(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn is_ipv4_banned(peer: SocketAddr, skels: &[Arc<bpf::FilterSkel<'static>>]) -> bool {
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
                    .lookup(&key_bytes, libbpf_rs::MapFlags::ANY)
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

fn is_ipv6_banned(peer: SocketAddr, skels: &[Arc<bpf::FilterSkel<'static>>]) -> bool {
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
                    .lookup(&key_bytes, libbpf_rs::MapFlags::ANY)
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

#[derive(Clone)]
pub struct ProxyContext {
    pub client: Client<HttpConnector, Full<Bytes>>,
    pub upstream: Uri,
    pub domain_filter: DomainFilter,
    pub tls_only: bool,
    pub arxignis: Option<ArxignisClient>,
}

#[derive(Clone)]
pub struct RedisAcmeCache {
    pub prefix: String,
    pub connection: Arc<Mutex<ConnectionManager>>,
}

impl RedisAcmeCache {
    pub async fn new(redis_url: &str, prefix: String) -> Result<Self> {
        let client = redis::Client::open(redis_url)?;
        let manager = client
            .get_connection_manager()
            .await
            .context("failed to create redis connection manager")?;
        Ok(Self {
            prefix,
            connection: Arc::new(Mutex::new(manager)),
        })
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
        let mut conn = self.connection.lock().await;
        let value: Option<Vec<u8>> = conn.get(key).await?;
        Ok(value)
    }

    async fn store_cert(
        &self,
        domains: &[String],
        directory_url: &str,
        cert: &[u8],
    ) -> std::result::Result<(), Self::EC> {
        let key = self.key("cert", domains, directory_url, &[]);
        let mut conn = self.connection.lock().await;
        conn.set::<_, _, ()>(key, cert).await?;
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
        let mut conn = self.connection.lock().await;
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
        let mut conn = self.connection.lock().await;
        conn.set::<_, _, ()>(key, account).await?;
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

fn parse_cert_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    Ok(certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|cert| cert.into_owned())
        .collect())
}

fn extract_cert_info_from_der(cert_der: &CertificateDer<'static>) -> Option<ServerCertInfo> {
    Some(ServerCertInfo {
        subject: "unknown".to_string(),
        issuer: "unknown".to_string(),
        serial_number: "unknown".to_string(),
        not_before: "unknown".to_string(),
        not_after: "unknown".to_string(),
        fingerprint_sha256: format!("{:x}", Sha256::digest(cert_der.as_ref())),
    })
}

// Helper function to load or create instant-acme account
async fn load_or_create_account(
    cache: &RedisAcmeCache,
    directory_url: &str,
    contacts: &[String],
) -> Result<instant_acme::Account> {
    use instant_acme::{Account, AccountCredentials, NewAccount};

    let account_key = cache.key("account", &[], directory_url, contacts);
    let mut conn = cache.connection.lock().await;

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

    // Store account credentials
    let credentials_json = serde_json::to_vec(&credentials)?;
    let _: () = conn.set(&account_key, &credentials_json).await?;

    Ok(account)
}

// Helper to load private key from Redis
async fn load_private_key_from_redis(
    cache: &RedisAcmeCache,
    domains: &[String],
    directory_url: &str,
) -> Result<Option<PrivateKeyDer<'static>>> {
    use rustls::pki_types::PrivatePkcs8KeyDer;

    let key = cache.key("privkey", domains, directory_url, &[]);
    let mut conn = cache.connection.lock().await;

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
    let mut conn = cache.connection.lock().await;
    conn.set::<_, _, ()>(key, private_key_der).await?;
    Ok(())
}

// Manage ACME certificate lifecycle with instant-acme
async fn manage_acme_certificate(
    domains: Vec<String>,
    directory_url: String,
    contacts: Vec<String>,
    cache: RedisAcmeCache,
    cert_config: Arc<RwLock<Option<ServerConfigWithCert>>>,
    challenge_store: Arc<RwLock<std::collections::HashMap<String, String>>>,
) -> Result<()> {
    use instant_acme::{AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus};
    use rustls::pki_types::PrivatePkcs8KeyDer;

    // Try to load existing certificate
    if let Ok(Some(cert_pem_bytes)) = cache.load_cert(&domains, &directory_url).await {
        if let Ok(cert_pem) = String::from_utf8(cert_pem_bytes) {
            if let Ok(certs) = parse_cert_chain(&cert_pem) {
                if let Ok(Some(private_key)) =
                    load_private_key_from_redis(&cache, &domains, &directory_url).await
                {
                    log::info!("Loaded existing certificate from cache");
                    let config = ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs.clone(), private_key)?;
                    let cert_info = extract_cert_info_from_der(&certs[0]);
                    *cert_config.write().await = Some(ServerConfigWithCert {
                        config: Arc::new(config),
                        cert_info,
                    });
                    return Ok(());
                }
            }
        }
    }

    // Need to obtain new certificate
    log::info!("Obtaining new ACME certificate for {:?}", domains);

    let account = load_or_create_account(&cache, &directory_url, &contacts).await?;

    // Create order
    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

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
                failed_domains.push((
                    domain.clone(),
                    format!("Challenge notification failed: {}", e),
                ));
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

    // Wait for order to be ready
    let mut tries = 0;
    let state = loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let state = order.refresh().await?;

        match state.status {
            OrderStatus::Ready => {
                log::info!("Order status: Ready");
                break state;
            }
            OrderStatus::Invalid => {
                // Fetch detailed error information
                log::error!("Order became invalid. Checking authorization status...");

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
                    log::info!(
                        "Order status: {:?} (attempt {}/10)",
                        state.status,
                        tries + 1
                    );
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
        log::warn!(
            "Order became invalid after {} tries and status: {:?}",
            tries,
            state.status
        );
        return Err(anyhow!(
            "Order became invalid after {} tries and status: {:?}",
            tries,
            state.status
        ));
    }

    log::info!("Order status: Ready");

    // Generate private key and CSR
    let private_key = rcgen::KeyPair::generate()?;

    // Create certificate parameters for CSR
    let mut params = rcgen::CertificateParams::new(domains.clone())?;
    params.distinguished_name = rcgen::DistinguishedName::new();

    // Finalize order with CSR
    order.finalize().await?;

    // Download certificate
    let cert_chain_pem = loop {
        match order.certificate().await? {
            Some(cert) => break cert,
            None => {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    };

    log::info!("Successfully obtained ACME certificate!");

    // Store certificate in Redis
    cache
        .store_cert(&domains, &directory_url, cert_chain_pem.as_bytes())
        .await?;

    // Store private key in Redis
    let private_key_der = private_key.serialize_der();
    store_private_key_in_redis(&cache, &domains, &directory_url, &private_key_der).await?;

    // Parse and configure
    let certs = parse_cert_chain(&cert_chain_pem)?;
    let private_key_rustls = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der));

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), private_key_rustls)?;
    let cert_info = extract_cert_info_from_der(&certs[0]);
    *cert_config.write().await = Some(ServerConfigWithCert {
        config: Arc::new(config),
        cert_info,
    });

    Ok(())
}

pub fn load_custom_server_config(cert: &Path, key: &Path) -> Result<ServerConfigWithCert> {
    let certs = load_certificates(cert)?;
    let key = load_private_key(key)?;
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

pub fn build_upstream_uri(incoming: &Uri, upstream: &Uri) -> Result<Uri> {
    let mut parts = upstream.clone().into_parts();
    parts.path_and_query.replace(
        incoming
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| "/".parse().unwrap()),
    );
    Uri::from_parts(parts).map_err(|e| anyhow!("failed to construct upstream uri: {e}"))
}

pub fn build_proxy_error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    const BLOCK_HTML: &str = include_str!("../../templates/block.html");

    let should_render_block = matches!(
        status,
        StatusCode::FORBIDDEN
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
    ) || matches!(
        message,
        "waf_block"
            | "waf_error"
            | "malware_block"
            | "request_blocked_by_filter"
            | "forbidden_domain"
            | "blocked"
    );

    let (content_type, body_bytes) = if should_render_block {
        (
            "text/html; charset=utf-8",
            Bytes::from_static(BLOCK_HTML.as_bytes()),
        )
    } else {
        let payload = json!({ "ok": false, "error": message }).to_string();
        ("application/json", Bytes::from(payload))
    };

    let boxed = Full::new(body_bytes)
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .body(boxed)
        .expect("valid response")
}

async fn create_access_log(
    req_parts: &hyper::http::request::Parts,
    req_body_bytes: &Bytes,
    peer_addr: SocketAddr,
    dst_addr: SocketAddr,
    tls_fingerprint: Option<&TlsFingerprint>,
    response_data: ResponseData,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use chrono::Utc;
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = Utc::now();
    let request_id = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(dur) => format!("req_{}", dur.as_nanos()),
        Err(_) => "req_unknown".to_string(),
    };

    let uri = &req_parts.uri;
    let method = req_parts.method.to_string();
    let scheme = uri
        .scheme()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "http".to_string());
    let host = uri.host().map(|h| h.to_string()).unwrap_or_else(|| {
        req_parts
            .headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_string())
            .unwrap_or_else(|| "unknown".to_string())
    });

    let port = uri
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();

    let mut headers = HashMap::new();
    let mut user_agent = None;
    let mut content_type = None;
    for (name, value) in req_parts.headers.iter() {
        let key = name.as_str().to_string();
        let val = value.to_str().unwrap_or("").to_string();
        if key.eq_ignore_ascii_case("user-agent") {
            user_agent = Some(val.clone());
        }
        if key.eq_ignore_ascii_case("content-type") {
            content_type = Some(val.clone());
        }
        headers.insert(key, val);
    }

    const MAX_BODY_SIZE: usize = 1024 * 1024;
    let body_truncated = req_body_bytes.len() > MAX_BODY_SIZE;
    let logged_body = if body_truncated {
        req_body_bytes.slice(..MAX_BODY_SIZE)
    } else {
        req_body_bytes.clone()
    };
    let body_str = String::from_utf8_lossy(&logged_body).to_string();
    let body_sha256 = if req_body_bytes.is_empty() {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()
    } else {
        format!("{:x}", Sha256::digest(req_body_bytes))
    };

    let tls_details = tls_fingerprint.map(|fp| {
        json!({
            "version": fp.tls_version,
            "cipher": "TLS_AES_128_GCM_SHA256",
            "alpn": fp.alpn,
            "sni": fp.sni,
            "ja4": fp.ja4,
            "ja4one": fp.ja4_unsorted,
            "ja4l": "0_0_64",
            "ja4t": fp.ja4_unsorted,
            "ja4h": fp.ja4_unsorted
        })
    });

    let access_log = json!({
        "event_type": "http_access_log",
        "schema_version": "1.0.0",
        "timestamp": timestamp.to_rfc3339(),
        "request_id": request_id,
        "http": {
            "method": method,
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": path,
            "query": query,
            "query_hash": if query.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::Value::String(format!("{:x}", Sha256::digest(query.as_bytes())))
            },
            "headers": headers,
            "user_agent": user_agent,
            "content_type": content_type,
            "content_length": req_body_bytes.len() as u64,
            "body": body_str,
            "body_sha256": body_sha256,
            "body_truncated": body_truncated
        },
        "client": {
            "ip": peer_addr.ip().to_string(),
            "port": peer_addr.port()
        },
        "server": {
            "hostname": gethostname().to_string_lossy(),
            "ipaddress": local_ip().map(|ip| ip.to_string()).unwrap_or_else(|_| "unknown".to_string()),
            "upstream": {
                "hostname": dst_addr.ip().to_string(),
                "port": dst_addr.port(),
            }
        },
        "tls": tls_details,
        "response": response_data.response_json,
        "blocking": response_data.blocking_info.unwrap_or(serde_json::Value::Null)
    });

    log::info!("{}", serde_json::to_string(&access_log)?);
    Ok(())
}

struct ResponseData {
    response_json: serde_json::Value,
    blocking_info: Option<serde_json::Value>,
}

impl ResponseData {
    async fn from_response(
        response: Response<ProxyBody>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let (response_parts, response_body) = response.into_parts();
        let response_body_bytes = response_body.collect().await?.to_bytes();
        let response_body_str = String::from_utf8_lossy(&response_body_bytes).to_string();
        let response_content_type = response_parts
            .headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let response_json = json!({
            "status": response_parts.status.as_u16(),
            "status_text": response_parts.status.canonical_reason().unwrap_or("Unknown"),
            "content_type": response_content_type,
            "content_length": response_body_bytes.len() as u64,
            "body": response_body_str
        });

        Ok(ResponseData {
            response_json,
            blocking_info: None,
        })
    }

    fn for_blocked_request(block_reason: &str, status_code: u16) -> Self {
        let status_text = match status_code {
            403 => "Forbidden",
            426 => "Upgrade Required",
            429 => "Too Many Requests",
            _ => "Blocked",
        };
        let response_json = json!({
            "status": status_code,
            "status_text": status_text,
            "content_type": "application/json",
            "content_length": 0,
            "body": format!("{{\"ok\":false,\"error\":\"{}\"}}", block_reason)
        });
        let blocking_info = json!({
            "blocked": true,
            "reason": block_reason
        });
        ResponseData {
            response_json,
            blocking_info: Some(blocking_info),
        }
    }
}

pub async fn proxy_http_service(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext>,
    peer: Option<SocketAddr>,
    tls_fingerprint: Option<&TlsFingerprint>,
    _server_cert_info: Option<ServerCertInfo>,
) -> Result<Response<ProxyBody>, Infallible> {
    let peer_addr = peer.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
    let (req_parts, req_body) = req.into_parts();
    let req_body_bytes = match req_body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            log::warn!("Failed to read request body: {}", e);
            return Ok(build_proxy_error_response(
                StatusCode::BAD_REQUEST,
                "body_read_error",
            ));
        }
    };

    if ctx.tls_only {
        let is_acme_challenge = req_parts
            .uri
            .path()
            .starts_with("/.well-known/acme-challenge/");
        if !is_acme_challenge && tls_fingerprint.is_none() {
            let dst_addr = ctx
                .upstream
                .authority()
                .and_then(|a| a.as_str().parse().ok())
                .unwrap_or_else(|| "127.0.0.1:80".parse().unwrap());
            if let Err(e) = create_access_log(
                &req_parts,
                &req_body_bytes,
                peer_addr,
                dst_addr,
                tls_fingerprint,
                ResponseData::for_blocked_request(
                    "tls_required",
                    StatusCode::UPGRADE_REQUIRED.as_u16(),
                ),
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

    if ctx.domain_filter.is_enabled() {
        let host = req_parts
            .headers
            .get(HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ctx.domain_filter.is_allowed(host) {
            let dst_addr = ctx
                .upstream
                .authority()
                .and_then(|a| a.as_str().parse().ok())
                .unwrap_or_else(|| "127.0.0.1:80".parse().unwrap());
            if let Err(e) = create_access_log(
                &req_parts,
                &req_body_bytes,
                peer_addr,
                dst_addr,
                tls_fingerprint,
                ResponseData::for_blocked_request(
                    "forbidden_domain",
                    StatusCode::FORBIDDEN.as_u16(),
                ),
            )
            .await
            {
                log::warn!("Failed to log forbidden domain: {}", e);
            }
            return Ok(build_proxy_error_response(
                StatusCode::FORBIDDEN,
                "forbidden_domain",
            ));
        }
    }

    if let Some(filter) = get_global_http_filter() {
        match filter.should_block_request_from_parts(&req_parts, &req_body_bytes, peer_addr) {
            Ok(true) => {
                log::info!(
                    "Request blocked by wirefilter from {}: {} {}",
                    peer_addr,
                    req_parts.method,
                    req_parts.uri
                );
                let dst_addr = ctx
                    .upstream
                    .authority()
                    .and_then(|a| a.as_str().parse().ok())
                    .unwrap_or_else(|| "127.0.0.1:80".parse().unwrap());
                if let Err(e) = create_access_log(
                    &req_parts,
                    &req_body_bytes,
                    peer_addr,
                    dst_addr,
                    tls_fingerprint,
                    ResponseData::for_blocked_request(
                        "request_blocked_by_filter",
                        StatusCode::FORBIDDEN.as_u16(),
                    ),
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
            Ok(false) => {}
            Err(e) => {
                log::warn!("Wirefilter error: {}", e);
            }
        }
    }

    if let Some(arx) = ctx.arxignis.as_ref() {
        let remote_ip = peer_addr.ip().to_string();

        let threat_response = arx.get_threat(&remote_ip).await.ok();
        if let Some(ref threat) = threat_response {
            match threat.advice.as_deref() {
                Some("block") => {
                    if matches!(arx.mode, crate::arxignis::ArxignisMode::Monitor) {
                        log::info!(
                            "Arxignis advised block for {}, but running in monitor mode",
                            remote_ip
                        );
                    } else {
                        return Ok(build_proxy_error_response(StatusCode::FORBIDDEN, "blocked"));
                    }
                }
                Some("challenge") => {
                    if !matches!(arx.mode, crate::arxignis::ArxignisMode::Monitor) {
                        if let Some(cookie_hdr) = req_parts
                            .headers
                            .get(hyper::header::COOKIE)
                            .and_then(|v| v.to_str().ok())
                        {
                            for cookie in cookie_hdr.split(';') {
                                let cookie = cookie.trim();
                                if let Some(value) = cookie.strip_prefix("ax_captcha=") {
                                    let ja4 = tls_fingerprint.map(|f| f.ja4.as_str());
                                    let ua = req_parts
                                        .headers
                                        .get(hyper::header::USER_AGENT)
                                        .and_then(|v| v.to_str().ok())
                                        .unwrap_or("");
                                    if verify_captcha_token(value, &remote_ip, ua, ja4) {
                                        log::debug!(
                                            "Captcha bypass token accepted for {remote_ip}"
                                        );
                                        break;
                                    }
                                }
                            }
                        }

                        let provider = &arx.captcha.provider;
                        let site_key = arx.captcha.site_key.as_deref().unwrap_or("");
                        let secret_ok = arx.captcha.secret_key.as_ref().is_some();
                        if provider.is_some() && !site_key.is_empty() && secret_ok {
                            let captcha_response = crate::arxignis::extract_captcha_response(
                                &arx.captcha.provider,
                                &req_parts.headers,
                                &req_body_bytes,
                            );
                            if let Some(res_val) = captcha_response.as_deref() {
                                let valid = arx
                                    .validate_captcha(res_val, &remote_ip)
                                    .await
                                    .unwrap_or(false);
                                if !valid {
                                    return Ok(build_proxy_error_response(
                                        StatusCode::FORBIDDEN,
                                        "captcha_failed",
                                    ));
                                }
                            } else {
                                return Ok(build_proxy_error_response(
                                    StatusCode::FORBIDDEN,
                                    "captcha_required",
                                ));
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        let is_https = tls_fingerprint.is_some();
        let event = crate::arxignis::build_event_from_request(
            &req_parts.headers,
            req_parts.method.as_str(),
            &req_parts.uri,
            &req_body_bytes,
            &remote_ip,
            threat_response.as_ref(),
            is_https,
        );

        match arx
            .send_filter(
                &event,
                &format!(
                    "{}:{}",
                    remote_ip,
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
                ),
            )
            .await
        {
            Ok(decision) => {
                if decision.action.as_deref() == Some("block")
                    && matches!(arx.mode, crate::arxignis::ArxignisMode::Block)
                {
                    return Ok(build_proxy_error_response(
                        StatusCode::FORBIDDEN,
                        "waf_block",
                    ));
                }
            }
            Err(e) => {
                log::warn!("WAF error: {}", e);
                if matches!(arx.mode, crate::arxignis::ArxignisMode::Block) {
                    return Ok(build_proxy_error_response(
                        StatusCode::FORBIDDEN,
                        "waf_error",
                    ));
                }
            }
        }

        if !req_body_bytes.is_empty() {
            let content_type = event
                .http
                .content_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".to_string());
            let scan = ScanRequest {
                content_type,
                body: String::from_utf8_lossy(&req_body_bytes).to_string(),
            };
            if let Ok(scan_decision) = arx.send_scan(&scan).await {
                let virus = scan_decision.virus_detected.unwrap_or(false)
                    || scan_decision.files_infected.unwrap_or(0) > 0;
                if virus {
                    return Ok(build_proxy_error_response(
                        StatusCode::FORBIDDEN,
                        "malware_block",
                    ));
                }
            }
        }
    }

    match forward_to_upstream_with_body(&req_parts, req_body_bytes.clone(), ctx.clone()).await {
        Ok(response) => {
            let (response_parts, response_body) = response.into_parts();
            let response_body_bytes = match response_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    log::warn!("Failed to read response body: {}", e);
                    Bytes::new()
                }
            };

            let dst_addr = ctx
                .upstream
                .authority()
                .and_then(|a| a.as_str().parse().ok())
                .unwrap_or_else(|| "127.0.0.1:80".parse().unwrap());

            let temp_response = Response::from_parts(
                response_parts.clone(),
                Full::new(response_body_bytes.clone())
                    .map_err(|never| match never {})
                    .boxed(),
            );
            let response_data = match ResponseData::from_response(temp_response).await {
                Ok(data) => data,
                Err(e) => {
                    log::warn!("Failed to process response for logging: {}", e);
                    ResponseData::for_blocked_request(
                        "logging_error",
                        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    )
                }
            };
            if let Err(e) = create_access_log(
                &req_parts,
                &req_body_bytes,
                peer_addr,
                dst_addr,
                tls_fingerprint,
                response_data,
            )
            .await
            {
                log::warn!("Failed to log access request: {}", e);
            }

            let response = Response::from_parts(
                response_parts,
                Full::new(response_body_bytes)
                    .map_err(|never| match never {})
                    .boxed(),
            );
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
            service_fn(move |req| {
                proxy_http_service(
                    req,
                    ctx.clone(),
                    peer,
                    tls_fingerprint,
                    server_cert_info.clone(),
                )
            }),
        )
        .await
        .map_err(|e| anyhow!("http1 connection error: {e}"))
}

// pub async fn run_control_plane(
//     listener: TcpListener,
//     state: AppState,
//     mut shutdown: watch::Receiver<bool>,
// ) -> Result<()> {
//     loop {
//         tokio::select! {
//             accept = listener.accept() => {
//                 let (stream, peer) = match accept {
//                     Ok(tuple) => tuple,
//                     Err(e) => {
//                         eprintln!("control-plane accept error: {e}");
//                         continue;
//                     }
//                 };
//                 let state_clone = state.clone();
//                 tokio::spawn(async move {
//                     let io = TokioIo::new(stream);
//                     if let Err(e) = http1::Builder::new()
//                         .serve_connection(io, service_fn(move |req| handle(req, peer, state_clone.clone())))
//                         .with_upgrades()
//                         .await
//                     {
//                         eprintln!("control-plane connection error from {peer}: {e}");
//                     }
//                 });
//             }
//             changed = shutdown.changed() => {
//                 if changed.is_ok() && *shutdown.borrow() {
//                     println!("control-plane shutdown signal received");
//                     break;
//                 }
//             }
//         }
//     }
//     Ok(())
// }

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
                        eprintln!("tls accept error: {e}");
                        continue;
                    }
                };
                let ctx_clone = ctx.clone();
                let tls_state_clone = tls_state.clone();
                let config_with_cert = server_config.clone();
                let skels_clone = skels.clone();
                tokio::spawn(async move {
                    let stream = match FingerprintTcpStream::new(stream).await {
                        Ok(s) => {
                            log_tls_fingerprint(s.peer_addr(), s.fingerprint());
                            s
                        }
                        Err(err) => {
                            log::error!("failed to prepare TLS stream from {peer}: {err}");
                            return;
                        }
                    };

                    let peer_addr = stream.peer_addr();
                    let fingerprint = stream.fingerprint().cloned();
                    // Pre-TLS ban check (support both IPv4 and IPv6)
                    if is_ipv4_banned(peer_addr, &skels_clone) || is_ipv6_banned(peer_addr, &skels_clone) {
                        let mut s = stream.inner;
                        if let Err(err) = tokio::io::AsyncWriteExt::write_all(&mut s, BANNED_MESSAGE.as_bytes()).await {
                            log::warn!("Failed to send ban banner to {peer_addr}: {err}");
                        }
                        if let Err(err) = tokio::io::AsyncWriteExt::shutdown(&mut s).await {
                            log::warn!("Failed to shutdown banned socket for {peer_addr}: {err}");
                        }
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
                                    log::warn!("TLS connection without SNI blocked by domain filter from {}", peer_addr);
                                    return;
                                }
                            }

                            match start.into_stream(config_with_cert.config.clone()).await {
                                Ok(tls_stream) => {
                                    if let Err(err) = serve_proxy_conn(
                                        tls_stream,
                                        Some(peer_addr),
                                        ctx_clone.clone(),
                                        fingerprint.as_ref(),
                                        config_with_cert.cert_info.clone(),
                                    ).await {
                                        log::error!("TLS proxy error from {peer_addr}: {err:?}");
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
                    println!("custom TLS proxy shutdown signal received");
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
    args: &Args,
    ctx: Arc<ProxyContext>,
    tls_state: SharedTlsState,
    skels: Vec<Arc<bpf::FilterSkel<'static>>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if !args.acme_accept_tos {
        return Err(anyhow!(
            "ACME mode requires --acme-accept-tos to acknowledge the certificate authority terms"
        ));
    }

    let domains = args.acme_domains.clone();
    if domains.is_empty() {
        return Err(anyhow!("ACME mode requires at least one domain"));
    }

    let contacts = if args.acme_contacts.is_empty() {
        vec![]
    } else {
        args.acme_contacts
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
    let redis_cache = RedisAcmeCache::new(&args.redis_url, args.redis_prefix.clone()).await?;

    // Shared store for HTTP-01 challenge tokens
    type ChallengeStore = Arc<RwLock<std::collections::HashMap<String, String>>>;
    let challenge_store: ChallengeStore = Arc::new(RwLock::new(std::collections::HashMap::new()));

    // Determine directory URL
    let directory_url = if let Some(dir) = &args.acme_directory {
        dir.clone()
    } else if args.acme_use_prod {
        instant_acme::LetsEncrypt::Production.url().to_string()
    } else {
        instant_acme::LetsEncrypt::Staging.url().to_string()
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
        if let Err(err) = manage_acme_certificate(
            domains_clone,
            directory_url_clone,
            contacts_clone,
            redis_cache_clone,
            cert_config_clone,
            challenge_store_clone,
        )
        .await
        {
            log::error!("ACME certificate manager error: {err:?}");
            tls_state_clone
                .set_error_detail(format!("ACME error: {err}"))
                .await;
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
                            if is_ipv4_banned(peer, &http_skels) || is_ipv6_banned(peer, &http_skels) {
                                let mut s = stream;
                                if let Err(err) = tokio::io::AsyncWriteExt::write_all(&mut s, BANNED_MESSAGE.as_bytes()).await {
                                    log::warn!("Failed to send ban banner to {peer}: {err}");
                                }
                                if let Err(err) = tokio::io::AsyncWriteExt::shutdown(&mut s).await {
                                    log::warn!("Failed to shutdown banned socket for {peer}: {err}");
                                }
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
                                            proxy_http_service(req, ctx_req, Some(peer), None, None).await
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
                        if is_ipv4_banned(peer, &skels) || is_ipv6_banned(peer, &skels) {
                            let mut s = stream;
                            if let Err(err) = tokio::io::AsyncWriteExt::write_all(&mut s, BANNED_MESSAGE.as_bytes()).await {
                                log::warn!("Failed to send ban banner to {peer}: {err}");
                            }
                            if let Err(err) = tokio::io::AsyncWriteExt::shutdown(&mut s).await {
                                log::warn!("Failed to shutdown banned socket for {peer}: {err}");
                            }
                            continue;
                        }

                        let cert_cfg = cert_config.read().await.clone();
                        let Some(config_with_cert) = cert_cfg else {
                            log::warn!("HTTPS connection from {peer} but certificate not ready yet");
                            continue;
                        };

                        let ctx_clone = ctx.clone();
                        let tls_state_clone = tls_state.clone();
                        let skels_clone = skels.clone();

                        tokio::spawn(async move {
                            let stream = match FingerprintTcpStream::new(stream).await {
                                Ok(s) => {
                                    let fingerprint = s.fingerprint().cloned();
                                    log_tls_fingerprint(s.peer_addr(), s.fingerprint());
                                    (s, fingerprint)
                                }
                                Err(err) => {
                                    log::error!("failed to prepare TLS stream from {peer}: {err}");
                                    return;
                                }
                            };

                            let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream.0);
                            match acceptor.await {
                                Ok(start) => {
                                    // Check SNI against domain filter
                                    if ctx_clone.domain_filter.is_enabled() {
                                        let client_hello = start.client_hello();
                                        let sni = client_hello.server_name();
                                        if let Some(sni_str) = sni {
                                            if !ctx_clone.domain_filter.is_allowed(sni_str) {
                                                log::warn!("TLS SNI '{}' blocked by domain filter from {}", sni_str, peer);
                                                return;
                                            }
                                        } else {
                                            // No SNI present - block if filter is enabled
                                            log::warn!("TLS connection without SNI blocked by domain filter from {}", peer);
                                            return;
                                        }
                                    }

                                    if is_ipv4_banned(peer, &skels_clone) || is_ipv6_banned(peer, &skels_clone) {
                                        log::info!("Connection from {peer} banned after handshake preparation");
                                        return;
                                    }

                                    match start.into_stream(config_with_cert.config.clone()).await {
                                        Ok(tls_stream) => {
                                            if let Err(err) = serve_proxy_conn(tls_stream, Some(peer), ctx_clone, stream.1.as_ref(), config_with_cert.cert_info.clone()).await {
                                                log::error!("HTTPS proxy error from {peer}: {err:?}");
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
    skels: Vec<Arc<bpf::FilterSkel<'static>>>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(tuple) => tuple,
                    Err(e) => { log::warn!("HTTP accept error: {e}"); continue; }
                };
                let ctx_clone = ctx.clone();
                let skels_clone = skels.clone();
                tokio::spawn(async move {
                    if is_ipv4_banned(peer, &skels_clone) || is_ipv6_banned(peer, &skels_clone) {
                        let mut s = stream;
                        if let Err(err) = tokio::io::AsyncWriteExt::write_all(&mut s, BANNED_MESSAGE.as_bytes()).await {
                            log::warn!("Failed to send ban banner to {peer}: {err}");
                        }
                        if let Err(err) = tokio::io::AsyncWriteExt::shutdown(&mut s).await {
                            log::warn!("Failed to shutdown banned socket for {peer}: {err}");
                        }
                        return;
                    }

                    if let Err(err) = handle_http_connection(stream, peer, ctx_clone).await {
                        log::warn!("http connection error: {err:?}");
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
) -> Result<()> {
    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        async move { proxy_http_service(req, ctx, Some(peer), None, None).await }
    });

    let io = TokioIo::new(stream);
    let conn = http1::Builder::new().serve_connection(io, service);
    if let Err(err) = conn.await {
        log::warn!("HTTP connection error: {err}");
    }
    Ok(())
}

// #[tokio::main]
// async fn main() -> Result<()> {
//     install_ring_crypto_provider()?;
//     let args = Args::parse();

//     let upstream_uri = match args.tls_mode {
//         TlsMode::Disabled => None,
//         _ => {
//             let upstream = args
//                 .upstream
//                 .as_ref()
//                 .ok_or_else(|| anyhow!("--upstream is required when TLS mode is not disabled"))?;
//             let parsed = upstream
//                 .parse::<Uri>()
//                 .context("failed to parse --upstream as URI")?;
//             if parsed.scheme().is_none() || parsed.authority().is_none() {
//                 return Err(anyhow!(
//                     "upstream URI must be absolute (e.g. http://127.0.0.1:8081)"
//                 ));
//             }
//             Some(parsed)
//         }
//     };

//     if args.tls_mode == TlsMode::Custom
//         && (args.tls_cert_path.is_none() || args.tls_key_path.is_none())
//     {
//         return Err(anyhow!(
//             "--tls-cert-path and --tls-key-path are required for custom TLS mode"
//         ));
//     }

//     let tls_state = SharedTlsState::new(
//         args.tls_mode,
//         args.acme_domains.clone(),
//         args.tls_cert_path.as_ref().map(|p| p.display().to_string()),
//     );

//     let control_listener = TcpListener::bind(args.control_addr)
//         .await
//         .context("failed to bind control socket")?;
//     println!(
//         "HTTP control-plane listening on http://{}",
//         args.control_addr
//     );

//     let (shutdown_tx, shutdown_rx) = watch::channel(false);

//     let boxed_open: Box<MaybeUninit<libbpf_rs::OpenObject>> = Box::new(MaybeUninit::uninit());
//     let open_object: &'static mut MaybeUninit<libbpf_rs::OpenObject> = Box::leak(boxed_open);
//     let skel_builder = bpf::FilterSkelBuilder::default();

//     let state = match skel_builder.open(open_object).and_then(|o| o.load()) {
//         Ok(mut skel) => {
//             let ifindex = match if_nametoindex(args.iface.as_str()) {
//                 Ok(index) => index as i32,
//                 Err(e) => {
//                     return Err(anyhow!(
//                         "failed to get interface index for '{}': {e}",
//                         args.iface
//                     ));
//                 }
//             };

//             match skel.progs.firewall.attach_xdp(ifindex) {
//                 Ok(link) => {
//                     skel.links = bpf::FilterLinks {
//                         firewall: Some(link),
//                     };
//                     println!(
//                         "Attached XDP program to interface '{}' (ifindex {})",
//                         args.iface, ifindex
//                     );
//                 }
//                 Err(e) => {
//                     return Err(anyhow!(
//                         "failed to attach XDP program. Your environment may not support it: {e}"
//                     ));
//                 }
//             }

//             AppState {
//                 skel: Some(Arc::new(skel)),
//                 tls_state: tls_state.clone(),
//             }
//         }
//         Err(e) => {
//             eprintln!("WARN: failed to load BPF skeleton: {e}. Control endpoints will be limited.");
//             AppState {
//                 skel: None,
//                 tls_state: tls_state.clone(),
//             }
//         }
//     };

//     let control_state = state.clone();
//     let control_shutdown = shutdown_rx.clone();
//     let control_handle = tokio::spawn(async move {
//         if let Err(err) = run_control_plane(control_listener, control_state, control_shutdown).await
//         {
//             eprintln!("control-plane task terminated: {err:?}");
//         }
//     });

//     let tls_handle = if let (Some(upstream), TlsMode::Disabled) = (&upstream_uri, args.tls_mode) {
//         unreachable!("TLS mode disabled but upstream parsed: {upstream}");
//     } else if let Some(upstream) = upstream_uri.clone() {
//         let mut builder = Client::builder(TokioExecutor::new());
//         builder.timer(TokioTimer::new());
//         builder.pool_timer(TokioTimer::new());
//         let client: Client<_, Full<Bytes>> = builder.build_http();
//         let proxy_ctx = Arc::new(ProxyContext { client, upstream });
//         match args.tls_mode {
//             TlsMode::Custom => {
//                 let cert = args.tls_cert_path.as_ref().unwrap();
//                 let key = args.tls_key_path.as_ref().unwrap();
//                 let config = load_custom_server_config(cert, key)?;
//                 let listener = TcpListener::bind(args.tls_addr)
//                     .await
//                     .context("failed to bind TLS socket")?;
//                 println!("HTTPS proxy listening on https://{}", args.tls_addr);
//                 let shutdown = shutdown_rx.clone();
//                 let tls_state_clone = tls_state.clone();
//                 Some(tokio::spawn(async move {
//                     if let Err(err) = run_custom_tls_proxy(
//                         listener,
//                         config.clone(),
//                         proxy_ctx,
//                         tls_state_clone,
//                         shutdown,
//                     )
//                     .await
//                     {
//                         eprintln!("custom TLS proxy terminated: {err:?}");
//                     }
//                 }))
//             }
//             TlsMode::Acme => {
//                 let listener = TcpListener::bind(args.tls_addr)
//                     .await
//                     .context("failed to bind TLS socket")?;
//                 println!("HTTPS proxy (ACME) listening on https://{}", args.tls_addr);
//                 let tls_state_clone = tls_state.clone();
//                 let shutdown = shutdown_rx.clone();
//                 let args_clone = args.clone();
//                 Some(tokio::spawn(async move {
//                     if let Err(err) = run_acme_tls_proxy(
//                         listener,
//                         &args_clone,
//                         proxy_ctx,
//                         tls_state_clone,
//                         shutdown,
//                     )
//                     .await
//                     {
//                         eprintln!("ACME TLS proxy terminated: {err:?}");
//                     }
//                 }))
//             }
//             TlsMode::Disabled => None,
//         }
//     } else {
//         None
//     };

//     signal::ctrl_c().await?;
//     println!("Shutdown signal received, stopping servers...");
//     let _ = shutdown_tx.send(true);

//     if let Some(handle) = tls_handle {
//         if let Err(err) = handle.await {
//             eprintln!("TLS task join error: {err}");
//         }
//     }

//     if let Err(err) = control_handle.await {
//         eprintln!("control-plane join error: {err}");
//     }

//     Ok(())
// }
