use std::convert::Infallible;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context as TaskContext, Poll};

use crate::cli::Args;
use crate::{bpf, utils::bpf_utils};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use bytes::Bytes;
use clap::ValueEnum;
use futures::StreamExt;
use futures_rustls::rustls::{ClientConfig as AcmeClientConfig, RootCertStore};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HOST, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use libbpf_rs::{MapCore, MapFlags};
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisError};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_acme::{AccountCache, AcmeConfig, CertCache, UseChallenge};
use rustls_pemfile::{certs, private_key};
use serde::Serialize;
use serde::ser::Serializer;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, RwLock, watch};
use tokio_rustls::LazyConfigAcceptor;
use tokio_stream::wrappers::TcpListenerStream;

use self::tls_fingerprint::{Fingerprint as TlsFingerprint, fingerprint_client_hello};

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

mod tls_fingerprint;

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
    skel: Option<Arc<bpf::FilterSkel<'static>>>,
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
            skel,
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

fn is_ipv4_banned(peer: SocketAddr, skel: &Option<Arc<bpf::FilterSkel<'static>>>) -> bool {
    let Some(skel) = skel.as_ref() else {
        return false;
    };
    match peer.ip() {
        std::net::IpAddr::V4(ip) => {
            let key_bytes = bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, 32);
            match skel
                .maps
                .recently_banned_ips
                .lookup(&key_bytes, MapFlags::ANY)
            {
                Ok(Some(flag)) => flag == vec![1u8],
                Ok(None) => false,
                Err(e) => {
                    eprintln!("bpf recently_banned_ips lookup error for {peer}: {e}");
                    false
                }
            }
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
}

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

pub fn load_custom_server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
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

pub async fn forward_to_upstream(
    req: Request<Incoming>,
    ctx: Arc<ProxyContext>,
) -> Result<Response<ProxyBody>> {
    let upstream_uri = build_upstream_uri(req.uri(), &ctx.upstream)?;
    let mut builder = Request::builder()
        .method(req.method().clone())
        .version(req.version())
        .uri(upstream_uri.clone());

    for (name, value) in req.headers().iter() {
        if name != HOST {
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

pub async fn proxy_http_service(
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

pub async fn serve_proxy_conn<S>(
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
    server_config: Arc<ServerConfig>,
    ctx: Arc<ProxyContext>,
    tls_state: SharedTlsState,
    skel: Option<Arc<bpf::FilterSkel<'static>>>,
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
                let config = server_config.clone();
                let skel_clone = skel.clone();
                tokio::spawn(async move {
                    let stream = match FingerprintTcpStream::new(stream).await {
                        Ok(s) => {
                            log_tls_fingerprint(s.peer_addr(), s.fingerprint());
                            s
                        }
                        Err(err) => {
                            eprintln!("failed to prepare TLS stream from {peer}: {err}");
                            return;
                        }
                    };

                    let peer_addr = stream.peer_addr();
                    // Pre-TLS ban check
                    if is_ipv4_banned(peer_addr, &skel_clone) {
                        let mut s = stream.inner;
                        let _ = s.write_all(BANNED_MESSAGE.as_bytes()).await;
                        let _ = s.shutdown().await;
                        return;
                    }
                    let acceptor = LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);

                    match acceptor.await {
                        Ok(start) => {
                            match start.into_stream(config).await {
                                Ok(tls_stream) => {
                                    if let Err(err) = serve_proxy_conn(tls_stream, Some(peer_addr), ctx_clone.clone()).await {
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

pub async fn run_acme_tls_proxy(
    listener: TcpListener,
    args: &Args,
    ctx: Arc<ProxyContext>,
    tls_state: SharedTlsState,
    skel: Option<Arc<bpf::FilterSkel<'static>>>,
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

    let base_listener =
        FingerprintingTcpListener::new(TcpListenerStream::new(listener), skel.clone());
    // Wrap the stream to drop banned connections before ACME takes over
    let fingerprinting_listener =
        futures::stream::unfold((base_listener, skel.clone()), |(mut l, skel)| {
            Box::pin(async move {
                loop {
                    match l.next().await {
                        Some(Ok(mut stream)) => {
                            let peer = match stream.peer_addr() {
                                Ok(p) => p,
                                Err(_) => {
                                    continue;
                                }
                            };
                            if is_ipv4_banned(peer, &skel) {
                                let _ = stream.write_all(BANNED_MESSAGE.as_bytes()).await;
                                let _ = stream.shutdown().await;
                                continue;
                            }
                            // Wrap the stream in Ok to match expected Result type
                            return Some((Ok(stream), (l, skel)));
                        }
                        Some(Err(e)) => {
                            // Yield the error as Err
                            return Some((Err(e), (l, skel)));
                        }
                        None => return None,
                    }
                }
            })
        });
    let mut incoming = acme_config.tokio_incoming(
        fingerprinting_listener,
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
                            if let Err(err) =
                                serve_proxy_conn(tls_stream, peer, ctx_clone).await
                            {
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
