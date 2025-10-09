use std::collections::HashSet;
use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use hyper::body::{Bytes, Incoming};
use hyper::header;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use once_cell::sync::Lazy;
use reqwest::Client as ReqwestClient;
use reqwest::header::{HeaderName as ReqwestHeaderName, HeaderValue as ReqwestHeaderValue};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use url::Url;

use http_body_util::{BodyExt, Full};

#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;
#[cfg(target_os = "linux")]
use tokio::sync::Mutex;

#[cfg(target_os = "linux")]
mod bpf {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/filter.skel.rs"
    ));
}

const DEFAULT_HTTP_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_UPSTREAM: &str = "http://127.0.0.1:8081";

static DASHBOARD_HTML: Lazy<&'static str> =
    Lazy::new(|| include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/static/index.html")));

type HttpResponse = Response<Full<Bytes>>;

#[derive(Debug, Clone)]
struct Settings {
    listen_addr: SocketAddr,
    upstream: Url,
    disable_bpf: bool,
}

impl Settings {
    fn from_env() -> Result<Self> {
        let listen_addr = parse_addr_from_env("BPF_FIREWALL_HTTP_ADDR", DEFAULT_HTTP_ADDR)?;
        let upstream = parse_upstream_from_env("BPF_FIREWALL_UPSTREAM", DEFAULT_UPSTREAM)?;
        let disable_bpf = parse_bool_env("BPF_FIREWALL_DISABLE_BPF", false)?;
        Ok(Self {
            listen_addr,
            upstream,
            disable_bpf,
        })
    }
}

fn parse_addr_from_env(var: &str, default: &str) -> Result<SocketAddr> {
    let value = std::env::var(var).unwrap_or_else(|_| default.to_string());
    value
        .parse::<SocketAddr>()
        .with_context(|| format!("unable to parse {var} as SocketAddr"))
}

fn parse_upstream_from_env(var: &str, default: &str) -> Result<Url> {
    let value = std::env::var(var).unwrap_or_else(|_| default.to_string());
    let parsed = Url::parse(&value)?;
    if parsed.scheme() != "http" {
        return Err(anyhow!(
            "upstream must use http:// scheme (certmagic/Caddy handles TLS); got {}",
            parsed
        ));
    }
    Ok(parsed)
}

fn parse_bool_env(var: &str, default: bool) -> Result<bool> {
    match std::env::var(var) {
        Ok(val) => match val.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(true),
            "0" | "false" | "no" | "off" => Ok(false),
            other => Err(anyhow!("env {var} invalid bool value: {other}")),
        },
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(anyhow!("env {var} error: {err}")),
    }
}

#[derive(Clone)]
struct AppState {
    backend: FirewallBackend,
    html_body: &'static str,
    upstream: Url,
    client: ReqwestClient,
}

impl AppState {
    fn new(backend: FirewallBackend, upstream: Url, client: ReqwestClient) -> Self {
        Self {
            backend,
            html_body: *DASHBOARD_HTML,
            upstream,
            client,
        }
    }
}

#[derive(Clone)]
enum FirewallBackend {
    #[cfg(target_os = "linux")]
    Ebpf(Arc<EbpfBackend>),
    Memory(Arc<MemoryBackend>),
}

impl FirewallBackend {
    async fn ban(&self, key: u32) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Ebpf(backend) => backend.ban(key).await,
            Self::Memory(backend) => backend.ban(key).await,
        }
    }

    async fn mark_recent(&self, key: u32) -> Result<()> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Ebpf(backend) => backend.mark_recent(key).await,
            Self::Memory(backend) => backend.mark_recent(key).await,
        }
    }

    async fn status(&self, key: u32) -> Result<(bool, bool)> {
        match self {
            #[cfg(target_os = "linux")]
            Self::Ebpf(backend) => backend.status(key).await,
            Self::Memory(backend) => backend.status(key).await,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            #[cfg(target_os = "linux")]
            Self::Ebpf(_) => "ebpf",
            Self::Memory(_) => "memory",
        }
    }
}

#[cfg(target_os = "linux")]
mod ebpf_backend {
    use super::*;
    use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
    use libbpf_rs::{MapCore, MapFlags};

    pub struct EbpfBackend {
        skel: Mutex<bpf::FilterSkel<'static>>,
    }

    impl EbpfBackend {
        pub async fn new() -> Result<Self> {
            let skel = load_bpf()?;
            Ok(Self {
                skel: Mutex::new(skel),
            })
        }

        pub async fn ban(&self, key: u32) -> Result<()> {
            let guard = self.skel.lock().await;
            let key_bytes = key.to_ne_bytes();
            let value: [u8; 1] = [1u8];
            guard
                .maps
                .banned_ips
                .update(&key_bytes, &value, MapFlags::ANY)?;
            guard.maps.recently_banned_ips.delete(&key_bytes)?;
            Ok(())
        }

        pub async fn mark_recent(&self, key: u32) -> Result<()> {
            let guard = self.skel.lock().await;
            let key_bytes = key.to_ne_bytes();
            let value: [u8; 1] = [1u8];
            guard
                .maps
                .recently_banned_ips
                .update(&key_bytes, &value, MapFlags::ANY)?;
            guard.maps.banned_ips.delete(&key_bytes)?;
            Ok(())
        }

        pub async fn status(&self, key: u32) -> Result<(bool, bool)> {
            let guard = self.skel.lock().await;
            let key_bytes = key.to_ne_bytes();
            let banned_hit = guard
                .maps
                .banned_ips
                .lookup(&key_bytes, MapFlags::ANY)?
                .map(|_| true)
                .unwrap_or(false);
            let recent_hit = guard
                .maps
                .recently_banned_ips
                .lookup(&key_bytes, MapFlags::ANY)?
                .map(|_| true)
                .unwrap_or(false);
            Ok((banned_hit, recent_hit))
        }
    }

    fn load_bpf() -> Result<bpf::FilterSkel<'static>> {
        let storage = Box::leak(Box::new(MaybeUninit::<libbpf_rs::OpenObject>::uninit()));
        let builder = bpf::FilterSkelBuilder::default();
        let open_skel = builder.open(storage)?;
        let mut skel = open_skel.load()?;
        skel.attach()?;
        Ok(skel)
    }
}

#[cfg(not(target_os = "linux"))]
mod ebpf_backend {
    use super::*;

    #[allow(dead_code)]
    #[derive(Debug)]
    pub struct EbpfBackend;

    #[allow(dead_code)]
    impl EbpfBackend {
        pub async fn new() -> Result<Self> {
            Err(anyhow!("eBPF backend requires Linux"))
        }

        pub async fn ban(&self, _key: u32) -> Result<()> {
            Err(anyhow!("eBPF backend unavailable on this platform"))
        }

        pub async fn mark_recent(&self, _key: u32) -> Result<()> {
            Err(anyhow!("eBPF backend unavailable on this platform"))
        }

        pub async fn status(&self, _key: u32) -> Result<(bool, bool)> {
            Err(anyhow!("eBPF backend unavailable on this platform"))
        }
    }
}

#[cfg(target_os = "linux")]
use ebpf_backend::EbpfBackend;

#[derive(Default)]
struct MemoryBackend {
    banned: RwLock<HashSet<u32>>,
    recent: RwLock<HashSet<u32>>,
}

impl MemoryBackend {
    async fn ban(&self, key: u32) -> Result<()> {
        self.banned.write().await.insert(key);
        self.recent.write().await.remove(&key);
        Ok(())
    }

    async fn mark_recent(&self, key: u32) -> Result<()> {
        self.recent.write().await.insert(key);
        self.banned.write().await.remove(&key);
        Ok(())
    }

    async fn status(&self, key: u32) -> Result<(bool, bool)> {
        let banned = self.banned.read().await.contains(&key);
        let recent = self.recent.read().await.contains(&key);
        Ok((banned, recent))
    }
}

fn full_body(data: impl Into<Bytes>) -> Full<Bytes> {
    Full::new(data.into())
}

fn json_response(status: StatusCode, body: String) -> HttpResponse {
    let mut resp = Response::new(full_body(Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    resp
}

fn html_response(html: &'static str) -> HttpResponse {
    let mut resp = Response::new(full_body(Bytes::from(html)));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    resp
}

fn wants_html(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(hyper::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html"))
        .unwrap_or(false)
}

fn parse_ip_param(req: &Request<Incoming>) -> Result<Ipv4Addr, String> {
    let query = req.uri().query().unwrap_or("");
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == "ip" {
                return v.parse::<Ipv4Addr>().map_err(|_| "invalid ip".to_string());
            }
        }
    }
    Err("missing ip".to_string())
}

async fn handle_request(
    req: Request<Incoming>,
    peer: SocketAddr,
    state: AppState,
) -> Result<HttpResponse, Infallible> {
    match route_request(req, peer, state).await {
        Ok(resp) => Ok(resp),
        Err(err) => Ok(json_response(
            StatusCode::BAD_GATEWAY,
            format!("{{\"ok\":false,\"error\":\"{}\"}}\n", err),
        )),
    }
}

async fn route_request(
    req: Request<Incoming>,
    peer: SocketAddr,
    state: AppState,
) -> Result<HttpResponse> {
    let path = req.uri().path();
    let method = req.method();

    if path == "/" && method == Method::GET {
        if wants_html(&req) {
            return Ok(html_response(state.html_body));
        }
        return Ok(json_response(
            StatusCode::OK,
            format!(
                "{{\"status\":\"ok\",\"backend\":\"{}\",\"service\":\"bpf-firewall\",\"remote_addr\":\"{}\"}}\n",
                state.backend.name(),
                peer.ip()
            ),
        ));
    }

    if (path == "/ui" || path == "/index.html") && method == Method::GET {
        return Ok(html_response(state.html_body));
    }

    if path == "/ban" && method == Method::PUT {
        return handle_ban(&state, &req, true).await;
    }

    if path == "/recently-ban" && method == Method::PUT {
        return handle_ban(&state, &req, false).await;
    }

    if path == "/status" && method == Method::GET {
        return handle_status(&state, &req).await;
    }

    proxy_request(req, state).await
}

async fn handle_ban(state: &AppState, req: &Request<Incoming>, ban: bool) -> Result<HttpResponse> {
    match parse_ip_param(req) {
        Ok(ip) => {
            let key = ipv4_to_u32_be(ip);
            if ban {
                state.backend.ban(key).await?;
                Ok(json_response(
                    StatusCode::OK,
                    format!("{{\"ok\":true,\"banned\":\"{}\"}}\n", ip),
                ))
            } else {
                state.backend.mark_recent(key).await?;
                Ok(json_response(
                    StatusCode::OK,
                    format!("{{\"ok\":true,\"recently_banned\":\"{}\"}}\n", ip),
                ))
            }
        }
        Err(err) => Ok(json_response(
            StatusCode::BAD_REQUEST,
            format!("{{\"ok\":false,\"error\":\"{}\"}}\n", err),
        )),
    }
}

async fn handle_status(state: &AppState, req: &Request<Incoming>) -> Result<HttpResponse> {
    match parse_ip_param(req) {
        Ok(ip) => {
            let key = ipv4_to_u32_be(ip);
            let (banned, recent) = state.backend.status(key).await?;
            Ok(json_response(
                StatusCode::OK,
                format!(
                    "{{\"ok\":true,\"ip\":\"{}\",\"banned\":{},\"recently_banned\":{}}}\n",
                    ip, banned, recent
                ),
            ))
        }
        Err(err) => Ok(json_response(
            StatusCode::BAD_REQUEST,
            format!("{{\"ok\":false,\"error\":\"{}\"}}\n", err),
        )),
    }
}

async fn proxy_request(req: Request<Incoming>, state: AppState) -> Result<HttpResponse> {
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes().to_vec();
    let upstream_uri = build_upstream_uri(&state.upstream, parts.uri.path(), parts.uri.query())?;

    let reqwest_method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())?;
    let mut builder = state.client.request(reqwest_method, upstream_uri.as_str());

    for (name, value) in parts.headers.iter() {
        if is_hop_header_name(name.as_str()) || name == header::HOST {
            continue;
        }
        if let (Ok(header_name), Ok(header_value)) = (
            ReqwestHeaderName::from_bytes(name.as_str().as_bytes()),
            ReqwestHeaderValue::from_bytes(value.as_bytes()),
        ) {
            builder = builder.header(header_name, header_value);
        }
    }

    let response = builder.body(body_bytes).send().await?;
    let status = StatusCode::from_u16(response.status().as_u16())?;
    let headers = response.headers().clone();
    let bytes = response.bytes().await?;

    let mut proxied = Response::new(full_body(Bytes::copy_from_slice(&bytes)));
    *proxied.status_mut() = status;
    for (name, value) in headers.iter() {
        if is_hop_header_name(name.as_str()) {
            continue;
        }
        if let Ok(hname) = header::HeaderName::from_bytes(name.as_str().as_bytes()) {
            proxied.headers_mut().insert(hname, value.clone());
        }
    }

    Ok(proxied)
}

fn ipv4_to_u32_be(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn is_hop_header_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn build_upstream_uri(base: &Url, path: &str, query: Option<&str>) -> Result<Url> {
    let mut url = base.clone();
    url.set_path(path);
    url.set_query(query);
    Ok(url)
}

#[tokio::main]
async fn main() -> Result<()> {
    let settings = Settings::from_env()?;
    let http_client = ReqwestClient::builder().http1_only().build()?;

    #[cfg(target_os = "linux")]
    let backend = if settings.disable_bpf {
        println!("BPF disabled via env; using in-memory backend");
        FirewallBackend::Memory(Arc::new(MemoryBackend::default()))
    } else {
        match EbpfBackend::new().await {
            Ok(inner) => {
                println!("Loaded eBPF firewall backend");
                FirewallBackend::Ebpf(Arc::new(inner))
            }
            Err(err) => {
                eprintln!("Failed to initialize eBPF backend: {err}");
                println!("Falling back to in-memory backend");
                FirewallBackend::Memory(Arc::new(MemoryBackend::default()))
            }
        }
    };

    #[cfg(not(target_os = "linux"))]
    let backend = {
        if !settings.disable_bpf {
            println!("eBPF backend unavailable on this platform; using in-memory backend");
        }
        FirewallBackend::Memory(Arc::new(MemoryBackend::default()))
    };

    let state = AppState::new(backend, settings.upstream.clone(), http_client);

    let listener = TcpListener::bind(settings.listen_addr).await?;
    println!(
        "HTTP reverse proxy listening on http://{} (upstream {})",
        settings.listen_addr, settings.upstream
    );

    let shutdown = CancellationToken::new();
    let shutdown_signal = shutdown.clone();

    let server_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_signal.cancelled() => break,
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((stream, peer)) => {
                            let state_clone = state.clone();
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                if let Err(err) = http1::Builder::new()
                                    .serve_connection(
                                        io,
                                        service_fn(move |req| handle_request(req, peer, state_clone.clone())),
                                    )
                                    .with_upgrades()
                                    .await
                                {
                                    eprintln!("connection error from {peer}: {err}");
                                }
                            });
                        }
                        Err(err) => eprintln!("accept error: {err}"),
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("Shutting down (Ctrl-C) ...");
            shutdown.cancel();
        }
        res = server_task => {
            if let Err(err) = res {
                eprintln!("server task error: {err}");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_rewrite_with_query() {
        let base = Url::parse("http://localhost:9000").unwrap();
        let url = build_upstream_uri(&base, "/foo", Some("bar=baz")).unwrap();
        assert_eq!(url.as_str(), "http://localhost:9000/foo?bar=baz");
    }

    #[test]
    fn upstream_rewrite_without_query() {
        let base = Url::parse("http://upstream.internal:8081").unwrap();
        let url = build_upstream_uri(&base, "/", None).unwrap();
        assert_eq!(url.as_str(), "http://upstream.internal:8081/");
    }
}
