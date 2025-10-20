use std::convert::Infallible;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context as TaskContext, Poll};
use gethostname::gethostname;
use local_ip_address::local_ip;

use crate::cli::Args;
use crate::config::fetch_config;
use crate::config::Config;
use crate::domain_filter::DomainFilter;
use crate::wirefilter::HttpFilter;
use crate::{bpf, utils::bpf_utils};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use clap::ValueEnum;
use futures_rustls::rustls::{ClientConfig as AcmeClientConfig, RootCertStore};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, HOST};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use libbpf_rs::{MapCore, MapFlags};
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls_acme::{AccountCache, CertCache};
use rustls_pemfile::{certs, private_key};
use serde::ser::Serializer;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Mutex, RwLock};
use tokio_rustls::LazyConfigAcceptor;
use tokio_stream::wrappers::TcpListenerStream;

use self::tls_fingerprint::{fingerprint_client_hello, Fingerprint as TlsFingerprint};

// Global wirefilter instance for HTTP request filtering
static HTTP_FILTER: OnceLock<HttpFilter> = OnceLock::new();

/// Initialize the global HTTP filter with a test rule that blocks POST requests
pub fn init_http_filter() -> Result<()> {
    let filter = HttpFilter::new_test_filter()?;
    HTTP_FILTER.set(filter).map_err(|_| anyhow!("Failed to initialize HTTP filter"))?;
    println!("HTTP filter initialized with test rule: blocking POST requests");
    Ok(())
}

/// Initialize the global HTTP filter with config from API
pub async fn init_http_filter_with_config(base_url: String, api_key: String) -> Result<()> {
    match fetch_config(base_url, api_key).await {
        Ok(config_response) => {
            let filter = HttpFilter::new_from_config(&config_response.config)?;
            HTTP_FILTER.set(filter).map_err(|_| anyhow!("Failed to initialize HTTP filter"))?;
            println!("HTTP filter initialized with {} WAF rules from config",
                config_response.config.waf_rules.rules.len());
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to fetch config for HTTP filter: {}", e);
            // Fallback to test filter
            init_http_filter()
        }
    }
}

/// Update the global HTTP filter with new config
pub async fn update_http_filter_with_config(base_url: String, api_key: String) -> Result<()> {
    match fetch_config(base_url, api_key).await {
        Ok(config_response) => {
            if let Some(filter) = HTTP_FILTER.get() {
                filter.update_from_config(&config_response.config)?;
                println!("HTTP filter updated with {} WAF rules from config",
                    config_response.config.waf_rules.rules.len());
            } else {
                eprintln!("HTTP filter not initialized, cannot update");
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to fetch config for HTTP filter update: {}", e);
            Err(anyhow!("Failed to fetch config: {}", e))
        }
    }
}

/// Update the global HTTP filter using an already-fetched Config value
pub fn update_http_filter_from_config_value(config: &Config) -> Result<()> {
    if let Some(filter) = HTTP_FILTER.get() {
        filter.update_from_config(config)?;
        println!(
            "HTTP filter updated with {} WAF rules from config",
            config.waf_rules.rules.len()
        );
        Ok(())
    } else {
        eprintln!("HTTP filter not initialized, cannot update");
        Ok(())
    }
}

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
                        eprintln!("bpf recently_banned_ips lookup error for {peer}: {e}");
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
                        eprintln!("bpf recently_banned_ips_v6 lookup error for {peer}: {e}");
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

pub fn header_json() -> (hyper::header::HeaderName, hyper::header::HeaderValue) {
    (
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    )
}

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
type ProxyBody = BoxBody<Bytes, hyper::Error>;

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

pub fn json(s: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::<Bytes>::from(Bytes::from(format!("{s}\n"))));
    let (k, v) = header_json();
    r.headers_mut().insert(k, v);
    r
}

#[derive(Clone)]
pub struct ProxyContext {
    pub client: Client<HttpConnector, Full<Bytes>>,
    pub upstream: Uri,
    pub domain_filter: DomainFilter,
    pub tls_only: bool,
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

// Type alias for challenge storage
type ChallengeStore = Arc<RwLock<std::collections::HashMap<String, String>>>;

// Helper function to load or create instant-acme account
async fn load_or_create_account(
    cache: &RedisAcmeCache,
    directory_url: &str,
    contacts: &[String],
) -> Result<Account> {
    let account_key = cache.key("account", &[], directory_url, contacts);
    let mut conn = cache.connection.lock().await;

    // Try to load existing account
    if let Ok(Some(account_data)) = conn.get::<_, Option<Vec<u8>>>(&account_key).await {
        // Deserialize account credentials
        if let Ok(credentials) = serde_json::from_slice::<AccountCredentials>(&account_data) {
            if let Ok(account) = Account::from_credentials(credentials).await {
                println!("Loaded existing ACME account from cache");
                return Ok(account);
            }
        }
    }

    // Create new account
    println!("Creating new ACME account");
    let url = if directory_url.contains("staging") || directory_url.contains("pebble") {
        instant_acme::LetsEncrypt::Staging.url()
    } else {
        instant_acme::LetsEncrypt::Production.url()
    };

    let contacts: Vec<&str> = contacts.iter().map(|s| s.as_str()).collect();
    let (account, credentials) = Account::create(
        &NewAccount {
            contact: &contacts,
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        url,
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

// Parse PEM certificate chain
fn parse_cert_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut cursor = std::io::Cursor::new(pem.as_bytes());
    Ok(certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|cert| cert.into_owned())
        .collect())
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
                if let Ok(Some(private_key)) =
                    load_private_key_from_redis(&cache, &domains, &directory_url).await
                {
                    println!("Loaded existing certificate from cache");
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
    println!("Obtaining new ACME certificate for {:?}", domains);

    let account = load_or_create_account(&cache, &directory_url, &contacts).await?;

    // Create order
    let identifiers: Vec<Identifier> =
        domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await?;

    // Process authorizations
    let authorizations = order.authorizations().await?;
    for authz in &authorizations {
        // Find HTTP-01 challenge
        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
            .ok_or_else(|| anyhow!("No HTTP-01 challenge found"))?;

        // Get key authorization
        let key_auth = order.key_authorization(challenge).as_str().to_string();

        // Store challenge response
        {
            let mut store = challenge_store.write().await;
            store.insert(challenge.token.clone(), key_auth.clone());
        }

        println!("Set HTTP-01 challenge for token: {}", challenge.token);

        // Notify ACME server to validate
        order.set_challenge_ready(&challenge.url).await?;
    }

    // Wait for order to be ready
    let mut tries = 0;
    let state = loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let state = order.refresh().await?;
        if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
            break state;
        }
        tries += 1;
        if tries >= 10 {
            return Err(anyhow!(
                "Order status: {:?}, gave up after {} tries",
                state.status,
                tries
            ));
        }
    };

    if state.status == OrderStatus::Invalid {
        println!("Order became invalid after {} tries and status: {:?}", tries, state.status);
        return Err(anyhow!("Order became invalid after {} tries and status: {:?}", tries, state.status));
    }

    println!("Order status: Ready");

    // Generate private key and CSR
    let private_key = rcgen::KeyPair::generate()?;

    // Create certificate parameters for CSR
    let mut params = rcgen::CertificateParams::new(domains.clone())?;
    params.distinguished_name = rcgen::DistinguishedName::new();

    // Generate CSR (Certificate Signing Request)
    let csr = params.serialize_request(&private_key)?;
    let csr_der = csr.der();

    // Finalize order with CSR
    order.finalize(csr_der).await?;

    // Download certificate
    let cert_chain_pem = loop {
        match order.certificate().await? {
            Some(cert) => break cert,
            None => {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    };

    println!("Successfully obtained ACME certificate!");

    // Store certificate in Redis
    cache
        .store_cert(&domains, &directory_url, cert_chain_pem.as_bytes())
        .await?;

    // Store private key in Redis
    let private_key_der = private_key.serialize_der();
    store_private_key_in_redis(
        &cache,
        &domains,
        &directory_url,
        &private_key_der,
    )
    .await?;

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

    // Extract certificate info from the first certificate
    let cert_info = extract_cert_info_from_der(&certs[0]);

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("unable to build rustls server config: {e}"))?;
    let mut config = Arc::new(config);
    Arc::get_mut(&mut config)
        .expect("arc get mutable")
        .alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(ServerConfigWithCert {
        config,
        cert_info,
    })
}

pub fn ensure_mailto(contact: &str) -> String {
    if contact.starts_with("mailto:") {
        contact.to_string()
    } else {
        format!("mailto:{contact}")
    }
}

pub fn extract_cert_info_from_der(cert_der: &CertificateDer<'static>) -> Option<ServerCertInfo> {
    use x509_parser::prelude::*;

    // Parse the X.509 certificate
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref()).ok()?;

    // Extract subject
    let subject = cert.subject().to_string();

    // Extract issuer
    let issuer = cert.issuer().to_string();

    // Extract serial number
    let serial_number = format!("{:X}", cert.serial);

    // Extract validity dates
    let validity = cert.validity();
    let not_before = validity.not_before.to_string();
    let not_after = validity.not_after.to_string();

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
    let body = json!({
        "ok": false,
        "error": message,
    })
    .to_string();
    let boxed = Full::new(Bytes::from(body))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(boxed)
        .expect("valid response")
}

pub async fn forward_to_upstream_with_body(
    req_parts: &hyper::http::request::Parts,
    body_bytes: bytes::Bytes,
    ctx: Arc<ProxyContext>,
) -> Result<Response<ProxyBody>> {
    let upstream_uri = build_upstream_uri(&req_parts.uri, &ctx.upstream)?;
    let mut builder = Request::builder()
        .method(req_parts.method.clone())
        .version(req_parts.version)
        .uri(upstream_uri.clone());

    for (name, value) in req_parts.headers.iter() {
        if name != HOST {
            builder = builder.header(name, value.clone());
        }
    }

    let mut outbound = builder
        .body(Full::new(body_bytes))
        .map_err(|e| anyhow!("failed to build proxy request: {e}"))?;

    if let Some(authority) = upstream_uri.authority() {
        outbound.headers_mut().insert(
            HOST,
            HeaderValue::from_str(authority.as_str())
                .map_err(|e| anyhow!("invalid upstream authority: {e}"))?,
        );
    }

    let response = ctx
        .client
        .request(outbound)
        .await
        .map_err(|e| anyhow!("upstream request error: {e}"))?;
    let (parts, body) = response.into_parts();
    let boxed = body.boxed();
    Ok(Response::from_parts(parts, boxed))
}

async fn log_access_request_with_body(
    req_parts: &hyper::http::request::Parts,
    req_body_bytes: &bytes::Bytes,
    response: &Response<ProxyBody>,
    response_body_bytes: &bytes::Bytes,
    _peer: SocketAddr,
    tls_fingerprint: Option<&TlsFingerprint>,
    ctx: &ProxyContext,
    server_cert_info: Option<&ServerCertInfo>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create a simplified access log for now
    let timestamp = chrono::Utc::now();
    let request_id = format!("req_{}", timestamp.timestamp_nanos_opt().unwrap_or(0));

    let uri = req_parts.uri.clone();
    let method = req_parts.method.to_string();
    let scheme = uri
        .scheme()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "http".to_string());
    // Extract host and port from Host header or URI
    let host_header = req_parts.headers.get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    // Parse host:port from Host header
    let (host, port) = if let Some(colon_pos) = host_header.find(':') {
        let host_part = &host_header[..colon_pos];
        let port_part = host_header[colon_pos + 1..].parse::<u16>().unwrap_or_else(|_| {
            if scheme == "https" { 443 } else { 80 }
        });
        (host_part.to_string(), port_part)
    } else {
        (host_header.to_string(), if scheme == "https" { 443 } else { 80 })
    };
    let path = uri.path().to_string();
    let query = uri.query().unwrap_or("").to_string();

    // Extract headers
    let mut headers = std::collections::HashMap::new();
    let mut user_agent = None::<String>;
    let mut content_type = None::<String>;

    for (name, value) in req_parts.headers.iter() {
        let key = name.to_string();
        let val = value.to_str().unwrap_or("").to_string();
        if name.as_str().eq_ignore_ascii_case("user-agent") {
            user_agent = Some(val.clone());
        }
        if name.as_str().eq_ignore_ascii_case("content-type") {
            content_type = Some(val.clone());
        }
        headers.insert(key, val);
    }

    // Process request body
    let body_str = String::from_utf8_lossy(req_body_bytes).to_string();
    let body_sha256 = format!("{:x}", sha2::Sha256::digest(req_body_bytes));

    // Create access log entry
    let access_log = serde_json::json!({
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
            "query_hash": if query.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(format!("{:x}", sha2::Sha256::digest(query.as_bytes()))) },
            "headers": headers,
            "user_agent": user_agent,
            "content_type": content_type,
            "content_length": req_body_bytes.len() as u64,
            "body": body_str,
            "body_sha256": body_sha256,
            "body_truncated": false
        },
        "server": {
            "hostname": gethostname().to_string_lossy(),
            "ipaddress": local_ip().map(|ip| ip.to_string()).unwrap_or_else(|_| "unknown".to_string()),
            "upstream": {
                "hostname": ctx.upstream.host().unwrap_or("unknown").to_string(),
                "port": ctx.upstream.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 }),
            },
        },
        "tls": tls_fingerprint.map(|fp| serde_json::json!({
            "version": fp.tls_version,
            "cipher": fp.cipher_suite.clone().unwrap_or_else(|| "UNKNOWN_CIPHER".to_string()),
            "alpn": fp.alpn,
            "sni": fp.sni,
            "ja4": fp.ja4,
            "ja4one": fp.ja4_unsorted,
            "ja4l": fp.ja4l,
            "ja4t": fp.ja4_unsorted,
            "ja4h": fp.ja4_unsorted,
            "server_cert": server_cert_info.map(|cert| serde_json::json!({
                "subject": cert.subject,
                "issuer": cert.issuer,
                "serial_number": cert.serial_number,
                "not_before": cert.not_before,
                "not_after": cert.not_after,
                "fingerprint_sha256": cert.fingerprint_sha256
            }))
        })),
        "response": {
            "status": response.status().as_u16(),
            "status_text": response.status().canonical_reason().unwrap_or("Unknown"),
            "content_type": response.headers().get("content-type").and_then(|h| h.to_str().ok()),
            "content_length": response.headers().get("content-length").and_then(|h| h.to_str().ok()).and_then(|s| s.parse::<u64>().ok()),
            "headers": response.headers().iter().map(|(name, value)| (name.to_string(), value.to_str().unwrap_or("").to_string())).collect::<std::collections::HashMap<String, String>>(),
            "body": String::from_utf8_lossy(response_body_bytes).to_string(),
            "body_sha256": format!("{:x}", sha2::Sha256::digest(response_body_bytes)),
            "body_truncated": false
        }
    });

    println!("{}", serde_json::to_string(&access_log)?);
    Ok(())
}

pub async fn proxy_http_service(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext>,
    peer: Option<SocketAddr>,
    tls_fingerprint: Option<&TlsFingerprint>,
    server_cert_info: Option<ServerCertInfo>,
) -> Result<Response<ProxyBody>, Infallible> {
    let peer_addr = peer.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());

    // Extract request details for logging before consuming the request
    let (req_parts, req_body) = req.into_parts();
    let req_body_bytes = match req_body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            eprintln!("Failed to read request body: {}", e);
            return Ok(build_proxy_error_response(
                StatusCode::BAD_REQUEST,
                "body_read_error",
            ));
        }
    };

    // Check TLS-only mode: if enabled and no TLS fingerprint, don't forward
    if ctx.tls_only && tls_fingerprint.is_none() {
        // For ACME challenges, we need to allow HTTP requests
        let is_acme_challenge = req_parts.uri.path().starts_with("/.well-known/acme-challenge/");

        if !is_acme_challenge {
            // Not an ACME challenge and no TLS - return 426 Upgrade Required
            return Ok(build_proxy_error_response(
                StatusCode::UPGRADE_REQUIRED,
                "tls_required",
            ));
        }
    }

    // Apply wirefilter rules before forwarding to upstream
    if let Some(filter) = HTTP_FILTER.get() {
        match filter.should_block_request_from_parts(&req_parts, &req_body_bytes, peer_addr) {
            Ok(true) => {
                println!("Request blocked by wirefilter from {}: {} {}",
                    peer_addr, req_parts.method, req_parts.uri);
                return Ok(build_proxy_error_response(
                    StatusCode::FORBIDDEN,
                    "request_blocked_by_filter",
                ));
            }
            Ok(false) => {
                // Request allowed, continue processing
            }
            Err(e) => {
                eprintln!("Wirefilter error: {}", e);
                // On filter error, allow the request to proceed
            }
        }
    }

    match forward_to_upstream_with_body(&req_parts, req_body_bytes.clone(), ctx.clone()).await {
        Ok(response) => {
            // Capture response body for logging
            let (response_parts, response_body) = response.into_parts();
            let response_body_bytes = match response_body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(e) => {
                    eprintln!("Failed to read response body: {}", e);
                    bytes::Bytes::new()
                }
            };

            // Reconstruct response
            let response = Response::from_parts(response_parts, Full::new(response_body_bytes.clone()).map_err(|never| match never {}).boxed());

            // Log successful requests
            if let Err(e) = log_access_request_with_body(
                &req_parts,
                &req_body_bytes,
                &response,
                &response_body_bytes,
                peer_addr,
                tls_fingerprint,
                &ctx,
                server_cert_info.as_ref(),
            )
            .await
            {
                eprintln!("Failed to log access request: {}", e);
            }
            Ok(response)
        }
        Err(err) => {
            eprintln!(
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
                        eprintln!("tls accept error: {e}");
                        continue;
                    }
                };
                let ctx_clone = ctx.clone();
                let tls_state_clone = tls_state.clone();
                let server_config_clone = server_config.clone();
                let skels_clone = skels.clone();
                tokio::spawn(async move {
                    let stream = match FingerprintTcpStream::new(stream).await {
                        Ok(s) => {
                            s
                        }
                        Err(err) => {
                            eprintln!("failed to prepare TLS stream from {peer}: {err}");
                            return;
                        }
                    };

                    let peer_addr = stream.peer_addr();
                    let fingerprint = stream.fingerprint().cloned();
                    // Pre-TLS ban check (both IPv4 and IPv6)
                    if is_ipv4_banned(peer_addr, &skels_clone) || is_ipv6_banned(peer_addr, &skels_clone) {
                        let mut s = stream.inner;
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
                                        eprintln!("TLS SNI '{}' blocked by domain filter from {}", sni_str, peer_addr);
                                        return;
                                    }
                                } else {
                                    // No SNI present - block if filter is enabled
                                    eprintln!("TLS connection without SNI blocked by domain filter from {}", peer_addr);
                                    return;
                                }
                            }

                            match start.into_stream(server_config_clone.config.clone()).await {
                                Ok(tls_stream) => {
                                    if let Err(err) = serve_proxy_conn(tls_stream, Some(peer_addr), ctx_clone.clone(), fingerprint.as_ref(), server_config_clone.cert_info.clone()).await {
                                        eprintln!("TLS proxy error from {peer_addr}: {err:?}");
                                        tls_state_clone
                                            .set_error_detail(format!("last connection error: {err}"))
                                            .await;
                                    }
                                }
                                Err(err) => {
                                    eprintln!("TLS handshake error from {peer_addr}: {err}");
                                    tls_state_clone
                                        .set_error_detail(format!("handshake failure: {err}"))
                                        .await;
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!("TLS handshake error from {peer_addr}: {err}");
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
    let challenge_store: ChallengeStore = Arc::new(RwLock::new(std::collections::HashMap::new()));

    // Determine directory URL
    let directory_url = if let Some(dir) = &args.acme_directory {
        dir.clone()
    } else if args.acme_use_prod {
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
            eprintln!("ACME certificate manager error: {err:?}");
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
                            // Check if banned (both IPv4 and IPv6)
                            if is_ipv4_banned(peer, &http_skels) || is_ipv6_banned(peer, &http_skels) {
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
                                            proxy_http_service(req, ctx_req, Some(peer), None, None).await
                                        }
                                    }
                                });

                                if let Err(err) = http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                                    eprintln!("HTTP connection error from {peer}: {err}");
                                }
                            });
                        }
                        Err(err) => {
                            eprintln!("HTTP accept error: {err}");
                        }
                    }
                }
                changed = http_shutdown.changed() => {
                    if changed.is_ok() && *http_shutdown.borrow() {
                        println!("HTTP server shutdown signal received");
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
                        // Check if banned (both IPv4 and IPv6)
                        if is_ipv4_banned(peer, &skels) || is_ipv6_banned(peer, &skels) {
                            let mut s = stream;
                            let _ = s.write_all(BANNED_MESSAGE.as_bytes()).await;
                            let _ = s.shutdown().await;
                            continue;
                        }

                        let cert_cfg = cert_config.read().await.clone();
                        let Some(config_with_cert) = cert_cfg else {
                            eprintln!("HTTPS connection from {peer} but certificate not ready yet");
                            continue;
                        };

                        let ctx_clone = ctx.clone();
                        let tls_state_clone = tls_state.clone();

                        tokio::spawn(async move {
                            let stream = match FingerprintTcpStream::new(stream).await {
                                Ok(s) => {
                                    let fingerprint = s.fingerprint().cloned();
                                    (s, fingerprint)
                                }
                                Err(err) => {
                                    eprintln!("failed to prepare TLS stream from {peer}: {err}");
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
                                                eprintln!("TLS SNI '{}' blocked by domain filter from {}", sni_str, peer);
                                                return;
                                            }
                                        } else {
                                            // No SNI present - block if filter is enabled
                                            eprintln!("TLS connection without SNI blocked by domain filter from {}", peer);
                                            return;
                                        }
                                    }

                                    match start.into_stream(config_with_cert.config.clone()).await {
                                        Ok(tls_stream) => {
                                            if let Err(err) = serve_proxy_conn(tls_stream, Some(peer), ctx_clone, stream.1.as_ref(), config_with_cert.cert_info.clone()).await {
                                                eprintln!("HTTPS proxy error from {peer}: {err:?}");
                                                tls_state_clone.set_error_detail(format!("HTTPS session error: {err}")).await;
                                            } else {
                                                tls_state_clone.set_running_detail("ACME certificate active").await;
                                            }
                                        }
                                        Err(err) => {
                                            eprintln!("TLS handshake error from {peer}: {err}");
                                        }
                                    }
                                }
                                Err(err) => {
                                    eprintln!("TLS accept error from {peer}: {err}");
                                }
                            }
                        });
                    }
                    Err(err) => {
                        eprintln!("HTTPS accept error: {err}");
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    println!("HTTPS server shutdown signal received");
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
                    Err(e) => {
                        eprintln!("http accept error: {e}");
                        continue;
                    }
                };

                let ctx_clone = ctx.clone();
                let skel_clone = None::<Arc<bpf::FilterSkel<'static>>>; // not used in plain HTTP path
                tokio::spawn(async move {
                    if let Err(err) = handle_http_connection(stream, peer, ctx_clone, skel_clone).await {
                        eprintln!("http connection error: {err:?}");
                    }
                });
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    println!("HTTP server shutdown signal received");
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn handle_http_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    ctx: Arc<ProxyContext>,
    skel: Option<Arc<bpf::FilterSkel<'static>>>,
) -> Result<()> {
    // Simple HTTP proxy without TLS
    use hyper::server::conn::http1;
    use hyper::service::service_fn;

    use hyper_util::rt::TokioIo;

    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        let _skel = skel.clone();
        async move {
            proxy_http_service(req, ctx, Some(peer), None, None).await
        }
    });

    let io = TokioIo::new(stream);
    let conn = http1::Builder::new()
        .serve_connection(io, service);

    if let Err(err) = conn.await {
        eprintln!("HTTP connection error: {err}");
    }

    Ok(())
}
