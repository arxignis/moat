use std::convert::Infallible;
use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use futures::StreamExt;
use futures_rustls::rustls::{ClientConfig as AcmeClientConfig, RootCertStore};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HOST, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use libbpf_rs::MapCore;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use nix::net::if_::if_nametoindex;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_acme::{AccountCache, AcmeConfig, CertCache, UseChallenge};
use rustls_pemfile::{certs, private_key};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::{Mutex, RwLock, watch};
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::TcpListenerStream;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The network interface to attach the XDP program to.
    #[arg(short, long)]
    iface: String,

    /// HTTP control-plane bind address.
    #[arg(long, default_value = "0.0.0.0:8080")]
    control_addr: SocketAddr,

    /// HTTPS reverse-proxy bind address.
    #[arg(long, default_value = "0.0.0.0:8443")]
    tls_addr: SocketAddr,

    /// TLS operating mode.
    #[arg(long, value_enum, default_value_t = TlsMode::Disabled)]
    tls_mode: TlsMode,

    /// Upstream origin URL (required unless TLS is disabled).
    #[arg(long)]
    upstream: Option<String>,

    /// Path to custom certificate (PEM) when using custom TLS mode.
    #[arg(long)]
    tls_cert_path: Option<PathBuf>,

    /// Path to custom private key (PEM) when using custom TLS mode.
    #[arg(long)]
    tls_key_path: Option<PathBuf>,

    /// Domains for ACME certificate issuance (comma separated or repeated).
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    acme_domains: Vec<String>,

    /// ACME contact addresses (mailto: optional, comma separated or repeated).
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    acme_contacts: Vec<String>,

    /// Use Let's Encrypt production directory instead of staging.
    #[arg(long)]
    acme_use_prod: bool,

    /// Override ACME directory URL (useful for Pebble or other test CAs).
    #[arg(long)]
    acme_directory: Option<String>,

    /// Explicitly accept the ACME Terms of Service.
    #[arg(long, default_value_t = false)]
    acme_accept_tos: bool,

    /// Custom CA bundle for the ACME directory (PEM file).
    #[arg(long)]
    acme_ca_root: Option<PathBuf>,

    /// Redis connection URL for ACME cache storage.
    #[arg(long, default_value = "redis://127.0.0.1/0")]
    redis_url: String,

    /// Namespace prefix for Redis ACME cache entries.
    #[arg(long, default_value = "bpf-firewall:acme")]
    redis_prefix: String,
}

#[derive(ValueEnum, Copy, Clone, Debug, PartialEq, Eq)]
enum TlsMode {
    Disabled,
    Custom,
    Acme,
}

impl TlsMode {
    fn as_str(&self) -> &'static str {
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
struct TlsStatusSnapshot {
    mode: TlsMode,
    enabled: bool,
    detail: String,
    domains: Vec<String>,
    custom_cert: Option<String>,
}

#[derive(Clone)]
struct SharedTlsState {
    inner: Arc<RwLock<TlsStatusSnapshot>>,
}

impl SharedTlsState {
    fn new(mode: TlsMode, domains: Vec<String>, custom_cert: Option<String>) -> Self {
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

    async fn set_running_detail(&self, detail: impl Into<String>) {
        let mut guard = self.inner.write().await;
        guard.enabled = true;
        guard.detail = detail.into();
    }

    async fn set_error_detail(&self, detail: impl Into<String>) {
        let mut guard = self.inner.write().await;
        guard.enabled = false;
        guard.detail = detail.into();
    }

    async fn snapshot(&self) -> TlsStatusSnapshot {
        self.inner.read().await.clone()
    }
}

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/filter.skel.rs"));
}

#[derive(Clone)]
struct AppState {
    skel: Option<Arc<bpf::FilterSkel<'static>>>,
    tls_state: SharedTlsState,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LpmKey {
    prefixlen: u32,
    addr: u32,
}

unsafe impl plain::Plain for LpmKey {}

fn ipv4_to_u32_be(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn header_json() -> (hyper::header::HeaderName, hyper::header::HeaderValue) {
    (
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    )
}

fn install_ring_crypto_provider() -> Result<()> {
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

fn load_acme_client_config(path: Option<&Path>) -> Result<Arc<AcmeClientConfig>> {
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
        roots.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned()
        );
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

fn parse_ip_param(req: &Request<Incoming>) -> Result<Ipv4Addr, String> {
    let uri = req.uri();
    let query = uri.query().unwrap_or("");
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == "ip" {
                return v
                    .parse::<Ipv4Addr>()
                    .map_err(|_| "invalid ip parameter".to_string());
            }
        }
    }
    Err("missing ip parameter".to_string())
}

fn json(s: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::<Bytes>::from(Bytes::from(format!("{s}\n"))));
    let (k, v) = header_json();
    r.headers_mut().insert(k, v);
    r
}

async fn handle(
    req: Request<Incoming>,
    peer: SocketAddr,
    state: AppState,
) -> Result<Response<Full<Bytes>>, Infallible> {
    println!("src ip: {}", peer.ip());
    let path = req.uri().path();
    let method = req.method();

    if path == "/" && method == &Method::GET {
        let tls_snapshot = state.tls_state.snapshot().await;
        let body = json(
            &json!({
                "status": "ok",
                "service": "bpf-firewall",
                "remote_addr": peer.ip(),
                "tls": tls_snapshot
            })
            .to_string(),
        );
        return Ok(body);
    }

    if path == "/ban" && method == &Method::POST {
        #[derive(Deserialize)]
        struct BanBody {
            ips: Vec<String>,
        }

        let Some(skel) = state.skel.as_ref() else {
            let mut r = json("{\"ok\":false,\"error\":\"bpf not loaded\"}");
            *r.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            return Ok(r);
        };

        let bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                let mut r = json(&format!(
                    "{{\"ok\":false,\"error\":\"body read error: {e}\"}}"
                ));
                *r.status_mut() = StatusCode::BAD_REQUEST;
                return Ok(r);
            }
        };

        let parsed: Result<BanBody, _> = serde_json::from_slice(&bytes);
        let body = match parsed {
            Ok(body) => body,
            Err(e) => {
                let mut r = json(&format!("{{\"ok\":false,\"error\":\"invalid json: {e}\"}}"));
                *r.status_mut() = StatusCode::BAD_REQUEST;
                return Ok(r);
            }
        };

        let mut ok = 0usize;
        let mut failed = vec![];
        for ip_str in body.ips {
            match ip_str.parse::<Ipv4Addr>() {
                Ok(ip) => {
                    let key = LpmKey {
                        prefixlen: 32,
                        addr: ipv4_to_u32_be(ip),
                    };
                    let key_bytes: &[u8] = unsafe { plain::as_bytes(&key) };
                    let value: u32 = 0;
                    let value_bytes: &[u8] = unsafe { plain::as_bytes(&value) };

                    if let Err(e) = skel.maps.banned_ips.update(
                        key_bytes,
                        value_bytes,
                        libbpf_rs::MapFlags::ANY,
                    ) {
                        failed.push((ip, e.to_string()));
                    } else {
                        ok += 1;
                    }
                }
                Err(e) => failed.push((Ipv4Addr::UNSPECIFIED, e.to_string())),
            }
        }

        let resp = json(
            &json!({
                "ok": failed.is_empty(),
                "banned": ok,
                "failed": failed.iter().map(|(ip, err)| {
                    json!({"ip": ip.to_string(), "error": err})
                }).collect::<Vec<_>>()
            })
            .to_string(),
        );
        return Ok(resp);
    }

    if path == "/unban" && method == &Method::DELETE {
        let Some(skel) = state.skel.as_ref() else {
            let mut r = json("{\"ok\":false,\"error\":\"bpf not loaded\"}");
            *r.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            return Ok(r);
        };

        let resp = match parse_ip_param(&req) {
            Ok(ip) => {
                let key = LpmKey {
                    prefixlen: 32,
                    addr: ipv4_to_u32_be(ip),
                };
                let key_bytes: &[u8] = unsafe { plain::as_bytes(&key) };
                match skel.maps.banned_ips.delete(key_bytes) {
                    Ok(_) => json(&format!("{{\"ok\":true,\"ip\":\"{ip}\"}}")),
                    Err(e) => {
                        let mut r = json(&format!(
                            "{{\"ok\":false,\"error\":\"map delete failed: {e}\"}}"
                        ));
                        *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        r
                    }
                }
            }
            Err(e) => {
                let mut r = json(&format!("{{\"ok\":false,\"error\":\"{e}\"}}"));
                *r.status_mut() = StatusCode::BAD_REQUEST;
                r
            }
        };
        return Ok(resp);
    }

    if path == "/status" && method == &Method::GET {
        let Some(skel) = state.skel.as_ref() else {
            let mut r = json("{\"ok\":false,\"error\":\"bpf not loaded\"}");
            *r.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            return Ok(r);
        };

        let banned_count = {
            let mut iter = skel.maps.banned_ips.keys();
            let mut count = 0usize;
            for _ in &mut iter {
                count += 1;
            }
            count
        };

        let resp = json(&json!({"ok": true, "banned_count": banned_count}).to_string());
        return Ok(resp);
    }

    if path == "/recent" && method == &Method::GET {
        let Some(skel) = state.skel.as_ref() else {
            let mut r = json("{\"ok\":false,\"error\":\"bpf not loaded\"}");
            *r.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            return Ok(r);
        };

        let mut ips = Vec::new();
        let mut iter = skel.maps.recently_banned_ips.keys();
        for bytes in &mut iter {
            if bytes.len() == std::mem::size_of::<LpmKey>() {
                let mut arr = [0u8; std::mem::size_of::<LpmKey>()];
                arr.copy_from_slice(&bytes);
                if let Ok(parsed) = plain::from_bytes::<LpmKey>(&arr) {
                    let ip = Ipv4Addr::from(parsed.addr);
                    ips.push(json!({ "ip": ip.to_string() }));
                }
            }
        }

        let resp = json(&json!({"ok": true, "recent": ips}).to_string());
        return Ok(resp);
    }

    if path == "/inspect" && method == &Method::GET {
        let Some(skel) = state.skel.as_ref() else {
            let mut r = json("{\"ok\":false,\"error\":\"bpf not loaded\"}");
            *r.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            return Ok(r);
        };

        let resp = match parse_ip_param(&req) {
            Ok(ip) => {
                let key = LpmKey {
                    prefixlen: 32,
                    addr: ipv4_to_u32_be(ip),
                };
                let key_bytes: &[u8] = unsafe { plain::as_bytes(&key) };
                let banned = skel
                    .maps
                    .banned_ips
                    .lookup(key_bytes, libbpf_rs::MapFlags::ANY)
                    .map(|o| o.is_some())
                    .unwrap_or(false);
                let recent = skel
                    .maps
                    .recently_banned_ips
                    .lookup(key_bytes, libbpf_rs::MapFlags::ANY)
                    .map(|o| o.is_some())
                    .unwrap_or(false);
                json(
                    &json!({
                        "ok": true,
                        "ip": ip,
                        "banned": banned,
                        "recently_banned": recent
                    })
                    .to_string(),
                )
            }
            Err(e) => {
                let mut r = json(&format!("{{\"ok\":false,\"error\":\"{e}\"}}"));
                *r.status_mut() = StatusCode::BAD_REQUEST;
                r
            }
        };
        return Ok(resp);
    }

    let mut not_found = json("{\"ok\":false,\"error\":\"not found\"}");
    *not_found.status_mut() = StatusCode::NOT_FOUND;
    Ok(not_found)
}

#[derive(Clone)]
struct ProxyContext {
    client: Client<HttpConnector, Full<Bytes>>,
    upstream: Uri,
}

struct RedisAcmeCache {
    prefix: String,
    connection: Arc<Mutex<ConnectionManager>>,
}

impl RedisAcmeCache {
    async fn new(redis_url: &str, prefix: String) -> Result<Self> {
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

    fn key(&self, kind: &str, domains: &[String], directory_url: &str, extra: &[String]) -> String {
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

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
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

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).with_context(|| format!("failed to open private key file {:?}", path))?;
    let mut reader = BufReader::new(file);
    let key = private_key(&mut reader)
        .with_context(|| format!("failed to parse private key in {:?}", path))?
        .ok_or_else(|| anyhow!("no private key found in {:?}", path))?;
    Ok(key)
}

fn load_custom_server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
    let certs = load_certificates(cert)?;
    let key = load_private_key(key)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("unable to build rustls server config: {e}"))?;
    let mut config = Arc::new(config);
    Arc::get_mut(&mut config)
        .expect("arc get mutable")
        .alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn ensure_mailto(contact: &str) -> String {
    if contact.starts_with("mailto:") {
        contact.to_string()
    } else {
        format!("mailto:{contact}")
    }
}

fn build_upstream_uri(incoming: &Uri, upstream: &Uri) -> Result<Uri> {
    let mut parts = upstream.clone().into_parts();
    parts.path_and_query.replace(
        incoming
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| "/".parse().unwrap()),
    );
    Uri::from_parts(parts).map_err(|e| anyhow!("failed to construct upstream uri: {e}"))
}

fn build_proxy_error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
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

async fn forward_to_upstream(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext>,
) -> Result<Response<ProxyBody>> {
    let upstream_uri = build_upstream_uri(req.uri(), &ctx.upstream)?;
    let mut builder = Request::builder()
        .method(req.method().clone())
        .version(req.version())
        .uri(upstream_uri.clone());

    for (name, value) in req.headers().iter() {
        if name != &HOST {
            builder = builder.header(name, value.clone());
        }
    }

    let body_bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| anyhow!("proxy request body read error: {e}"))?
        .to_bytes();

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

async fn proxy_http_service(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext>,
    peer: Option<SocketAddr>,
) -> Result<Response<ProxyBody>, Infallible> {
    match forward_to_upstream(req, ctx.clone()).await {
        Ok(response) => Ok(response),
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

async fn serve_proxy_conn<S>(
    stream: S,
    peer: Option<SocketAddr>,
    ctx: Arc<ProxyContext>,
) -> Result<(), anyhow::Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| proxy_http_service(req, ctx.clone(), peer)),
        )
        .await
        .map_err(|e| anyhow!("http1 connection error: {e}"))
}

async fn run_control_plane(
    listener: TcpListener,
    state: AppState,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(tuple) => tuple,
                    Err(e) => {
                        eprintln!("control-plane accept error: {e}");
                        continue;
                    }
                };
                let state_clone = state.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service_fn(move |req| handle(req, peer, state_clone.clone())))
                        .with_upgrades()
                        .await
                    {
                        eprintln!("control-plane connection error from {peer}: {e}");
                    }
                });
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    println!("control-plane shutdown signal received");
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn run_custom_tls_proxy(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    ctx: Arc<ProxyContext>,
    tls_state: SharedTlsState,
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
                let acceptor = acceptor.clone();
                let ctx_clone = ctx.clone();
                let tls_state_clone = tls_state.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            if let Err(err) = serve_proxy_conn(tls_stream, Some(peer), ctx_clone.clone()).await {
                                eprintln!("TLS proxy error from {peer}: {err:?}");
                                tls_state_clone.set_error_detail(format!("last connection error: {err}")).await;
                            }
                        }
                        Err(err) => {
                            eprintln!("TLS handshake error from {peer}: {err}");
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

async fn run_acme_tls_proxy(
    listener: TcpListener,
    args: &Args,
    ctx: Arc<ProxyContext>,
    tls_state: SharedTlsState,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    if !args.acme_accept_tos {
        return Err(anyhow!(
            "ACME mode requires --acme-accept-tos to acknowledge the certificate authority terms"
        ));
    }

    let redis_cache = RedisAcmeCache::new(&args.redis_url, args.redis_prefix.clone()).await?;
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
            "ACME manager initializing for domains {:?}",
            domains
        ))
        .await;

    let client_config = load_acme_client_config(args.acme_ca_root.as_deref())?;
    let base_acme_config = AcmeConfig::new_with_client_config(domains.clone(), client_config);

    let acme_config = base_acme_config
        .contact(contacts.iter().map(|s| s.as_str()))
        .cache(redis_cache)
        .challenge_type(UseChallenge::TlsAlpn01);

    let acme_config = if let Some(directory_url) = args.acme_directory.as_ref() {
        acme_config.directory(directory_url)
    } else {
        acme_config.directory_lets_encrypt(args.acme_use_prod)
    };

    let mut incoming = acme_config.tokio_incoming(
        TcpListenerStream::new(listener),
        vec![b"http/1.1".to_vec(), b"acme-tls/1".to_vec()],
    );

    tls_state
        .set_running_detail("ACME certificate manager running")
        .await;

    loop {
        tokio::select! {
            next_conn = incoming.next() => {
                match next_conn {
                    Some(Ok(tls_stream)) => {
                        let ctx_clone = ctx.clone();
                        let tls_state_clone = tls_state.clone();
                        let peer = tls_stream
                            .get_ref()
                            .get_ref()
                            .0
                            .get_ref()
                            .peer_addr()
                            .ok();
                        tokio::spawn(async move {
                            if let Err(err) = serve_proxy_conn(tls_stream, peer, ctx_clone).await {
                                eprintln!("ACME TLS proxy error: {err:?}");
                                tls_state_clone.set_error_detail(format!("TLS session error: {err}")).await;
                            } else {
                                tls_state_clone.set_running_detail("ACME certificate active").await;
                            }
                        });
                    }
                    Some(Err(err)) => {
                        eprintln!("ACME TLS accept error: {err}");
                        tls_state
                            .set_error_detail(format!("ACME accept error: {err}"))
                            .await;
                    }
                    None => break,
                }
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    println!("ACME TLS proxy shutdown signal received");
                    break;
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    install_ring_crypto_provider()?;
    let args = Args::parse();

    let upstream_uri = match args.tls_mode {
        TlsMode::Disabled => None,
        _ => {
            let upstream = args
                .upstream
                .as_ref()
                .ok_or_else(|| anyhow!("--upstream is required when TLS mode is not disabled"))?;
            let parsed = upstream
                .parse::<Uri>()
                .context("failed to parse --upstream as URI")?;
            if parsed.scheme().is_none() || parsed.authority().is_none() {
                return Err(anyhow!(
                    "upstream URI must be absolute (e.g. http://127.0.0.1:8081)"
                ));
            }
            Some(parsed)
        }
    };

    if args.tls_mode == TlsMode::Custom
        && (args.tls_cert_path.is_none() || args.tls_key_path.is_none())
    {
        return Err(anyhow!(
            "--tls-cert-path and --tls-key-path are required for custom TLS mode"
        ));
    }

    let tls_state = SharedTlsState::new(
        args.tls_mode,
        args.acme_domains.clone(),
        args.tls_cert_path.as_ref().map(|p| p.display().to_string()),
    );

    let control_listener = TcpListener::bind(args.control_addr)
        .await
        .context("failed to bind control socket")?;
    println!(
        "HTTP control-plane listening on http://{}",
        args.control_addr
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let boxed_open: Box<MaybeUninit<libbpf_rs::OpenObject>> = Box::new(MaybeUninit::uninit());
    let open_object: &'static mut MaybeUninit<libbpf_rs::OpenObject> = Box::leak(boxed_open);
    let skel_builder = bpf::FilterSkelBuilder::default();

    let state = match skel_builder.open(open_object).and_then(|o| o.load()) {
        Ok(mut skel) => {
            let ifindex = match if_nametoindex(args.iface.as_str()) {
                Ok(index) => index as i32,
                Err(e) => {
                    return Err(anyhow!(
                        "failed to get interface index for '{}': {e}",
                        args.iface
                    ));
                }
            };

            match skel.progs.firewall.attach_xdp(ifindex) {
                Ok(link) => {
                    skel.links = bpf::FilterLinks {
                        firewall: Some(link),
                    };
                    println!(
                        "Attached XDP program to interface '{}' (ifindex {})",
                        args.iface, ifindex
                    );
                }
                Err(e) => {
                    return Err(anyhow!(
                        "failed to attach XDP program. Your environment may not support it: {e}"
                    ));
                }
            }

            AppState {
                skel: Some(Arc::new(skel)),
                tls_state: tls_state.clone(),
            }
        }
        Err(e) => {
            eprintln!("WARN: failed to load BPF skeleton: {e}. Control endpoints will be limited.");
            AppState {
                skel: None,
                tls_state: tls_state.clone(),
            }
        }
    };

    let control_state = state.clone();
    let control_shutdown = shutdown_rx.clone();
    let control_handle = tokio::spawn(async move {
        if let Err(err) = run_control_plane(control_listener, control_state, control_shutdown).await
        {
            eprintln!("control-plane task terminated: {err:?}");
        }
    });

    let tls_handle = if let (Some(upstream), TlsMode::Disabled) = (&upstream_uri, args.tls_mode) {
        unreachable!("TLS mode disabled but upstream parsed: {upstream}");
    } else if let Some(upstream) = upstream_uri.clone() {
        let mut builder = Client::builder(TokioExecutor::new());
        builder.timer(TokioTimer::new());
        builder.pool_timer(TokioTimer::new());
        let client: Client<_, Full<Bytes>> = builder.build_http();
        let proxy_ctx = Arc::new(ProxyContext { client, upstream });
        match args.tls_mode {
            TlsMode::Custom => {
                let cert = args.tls_cert_path.as_ref().unwrap();
                let key = args.tls_key_path.as_ref().unwrap();
                let config = load_custom_server_config(cert, key)?;
                let acceptor = TlsAcceptor::from(config);
                let listener = TcpListener::bind(args.tls_addr)
                    .await
                    .context("failed to bind TLS socket")?;
                println!("HTTPS proxy listening on https://{}", args.tls_addr);
                let shutdown = shutdown_rx.clone();
                let tls_state_clone = tls_state.clone();
                Some(tokio::spawn(async move {
                    if let Err(err) = run_custom_tls_proxy(
                        listener,
                        acceptor,
                        proxy_ctx,
                        tls_state_clone,
                        shutdown,
                    )
                    .await
                    {
                        eprintln!("custom TLS proxy terminated: {err:?}");
                    }
                }))
            }
            TlsMode::Acme => {
                let listener = TcpListener::bind(args.tls_addr)
                    .await
                    .context("failed to bind TLS socket")?;
                println!("HTTPS proxy (ACME) listening on https://{}", args.tls_addr);
                let tls_state_clone = tls_state.clone();
                let shutdown = shutdown_rx.clone();
                let args_clone = args.clone();
                Some(tokio::spawn(async move {
                    if let Err(err) = run_acme_tls_proxy(
                        listener,
                        &args_clone,
                        proxy_ctx,
                        tls_state_clone,
                        shutdown,
                    )
                    .await
                    {
                        eprintln!("ACME TLS proxy terminated: {err:?}");
                    }
                }))
            }
            TlsMode::Disabled => None,
        }
    } else {
        None
    };

    signal::ctrl_c().await?;
    println!("Shutdown signal received, stopping servers...");
    let _ = shutdown_tx.send(true);

    if let Some(handle) = tls_handle {
        if let Err(err) = handle.await {
            eprintln!("TLS task join error: {err}");
        }
    }

    if let Err(err) = control_handle.await {
        eprintln!("control-plane join error: {err}");
    }

    Ok(())
}
