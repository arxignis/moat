use std::convert::Infallible;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Result;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use libbpf_rs::skel::SkelBuilder;
use tokio::net::TcpListener;

mod bpf {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/filter.skel.rs"
    ));
}

#[derive(Clone)]
struct AppState<'a> {
    skel: std::sync::Arc<bpf::FilterSkel<'a>>,
}

fn ipv4_to_u32_be(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn header_json() -> (hyper::header::HeaderName, hyper::header::HeaderValue) {
    (
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    )
}

fn parse_ip_param(req: &Request<hyper::body::Incoming>) -> Result<Ipv4Addr, String> {
    let uri = req.uri();
    let query = uri.query().unwrap_or("");
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == "ip" {
                return v.parse::<Ipv4Addr>().map_err(|_| "invalid ip".to_string());
            }
        }
    }
    Err("missing ip".to_string())
}

async fn handle(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    state: AppState<'_>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = req.uri().path();
    let method = req.method();

    // Helper to build JSON responses
    let json = |s: &str| -> Response<Full<Bytes>> {
        let mut r = Response::new(Full::<Bytes>::from(Bytes::from(format!("{}\n", s))));
        let (k, v) = header_json();
        r.headers_mut().insert(k, v);
        r
    };

    // Root: health
    if path == "/" && method == hyper::Method::GET {
        let body = format!(
            "{{\"status\":\"ok\",\"service\":\"bpf-firewall\",\"remote_addr\":\"{}\"}}",
            peer.ip()
        );
        return Ok(json(&body));
    }

    // PUT /ban?ip=1.2.3.4
    if path == "/ban" && method == hyper::Method::PUT {
        let resp = match parse_ip_param(&req) {
            Ok(ip) => {
                let key = ipv4_to_u32_be(ip);
                // value is a u8 flag set to 1
                let one: u8 = 1;
                unsafe {
                    let banned = (*state.skel.maps.banned_ips).as_mut().unwrap();
                    let recently = (*state.skel.maps.recently_banned_ips).as_mut().unwrap();
                    let _ = banned.update(
                        &key.to_ne_bytes(),
                        &one.to_ne_bytes(),
                        libbpf_rs::MapFlags::ANY,
                    );
                    let _ = recently.delete(&key.to_ne_bytes());
                }
                json(&format!("{{\"ok\":true,\"banned\":\"{}\"}}", ip))
            }
            Err(e) => {
                let mut r = json(&format!("{{\"ok\":false,\"error\":\"{}\"}}", e));
                *r.status_mut() = hyper::StatusCode::BAD_REQUEST;
                r
            }
        };
        return Ok(resp);
    }

    // PUT /recently-ban?ip=1.2.3.4
    if path == "/recently-ban" && method == hyper::Method::PUT {
        let resp = match parse_ip_param(&req) {
            Ok(ip) => {
                let key = ipv4_to_u32_be(ip);
                let one: u8 = 1;
                unsafe {
                    let banned = (*state.skel.maps.banned_ips).as_mut().unwrap();
                    let recently = (*state.skel.maps.recently_banned_ips).as_mut().unwrap();
                    let _ = recently.update(
                        &key.to_ne_bytes(),
                        &one.to_ne_bytes(),
                        libbpf_rs::MapFlags::ANY,
                    );
                    let _ = banned.delete(&key.to_ne_bytes());
                }
                json(&format!("{{\"ok\":true,\"recently_banned\":\"{}\"}}", ip))
            }
            Err(e) => {
                let mut r = json(&format!("{{\"ok\":false,\"error\":\"{}\"}}", e));
                *r.status_mut() = hyper::StatusCode::BAD_REQUEST;
                r
            }
        };
        return Ok(resp);
    }

    // GET /status?ip=1.2.3.4
    if path == "/status" && method == hyper::Method::GET {
        let resp = match parse_ip_param(&req) {
            Ok(ip) => {
                let key = ipv4_to_u32_be(ip);
                let (in_banned, in_recent);
                unsafe {
                    let banned = (*state.skel.maps.banned_ips).as_mut().unwrap();
                    let recently = (*state.skel.maps.recently_banned_ips).as_mut().unwrap();
                    let b = banned.lookup(&key.to_ne_bytes());
                    let r = recently.lookup(&key.to_ne_bytes());
                    in_banned = b.is_ok() && b.unwrap().is_some();
                    in_recent = r.is_ok() && r.unwrap().is_some();
                }
                json(&format!(
                    "{{\"ok\":true,\"ip\":\"{}\",\"banned\":{},\"recently_banned\":{}}}",
                    ip, in_banned, in_recent
                ))
            }
            Err(e) => {
                let mut r = json(&format!("{{\"ok\":false,\"error\":\"{}\"}}", e));
                *r.status_mut() = hyper::StatusCode::BAD_REQUEST;
                r
            }
        };
        return Ok(resp);
    }

    // Fallback 404
    let mut not_found = json("{\"ok\":false,\"error\":\"not found\"}");
    *not_found.status_mut() = hyper::StatusCode::NOT_FOUND;
    Ok(not_found)
}

#[tokio::main]
async fn main() -> Result<()> {
    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let listener = TcpListener::bind(addr).await?;
    println!("HTTP server listening on http://{addr}");
    // Load and open BPF skeleton
    let open_object = MaybeUninit::uninit();
    let skel_builder = bpf::FilterSkelBuilder::default();

    let 

    let state = AppState {
        skel: std::sync::Arc::new(skel),
    };

    loop {
        tokio::select! {
            res = listener.accept() => {
                let (stream, peer) = match res {
                    Ok(s) => s,
                    Err(e) => { eprintln!("accept error: {e}"); continue; }
                };

                let state = state.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service_fn(move |req| handle(req, peer, state.clone())))
                        .with_upgrades()
                        .await
                    {
                        eprintln!("connection error from {peer}: {e}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                println!("Shutting down HTTP server (Ctrl-C) ...");
                break;
            }
        }
    }

    Ok(())
}
