// use std::{
//     convert::Infallible,
//     net::{IpAddr, SocketAddr},
// };

// use bytes::Bytes;
// use http_body_util::Full;
// use hyper::{Request, Response};
// use libbpf_rs::{MapCore, MapFlags, btf::types};
// use serde::Deserialize;

// use crate::{AppState, header_json, utils::bpf_utils::ipv4_to_u32_be};
// use crate::{parse_cidr_param, types::lpm_key};

// pub async fn handle(
//     req: Request<hyper::body::Incoming>,
//     peer: SocketAddr,
//     state: AppState<'_>,
// ) -> Result<Response<Full<Bytes>>, Infallible> {
//     println!("src ip: {}", peer.ip().to_string());
//     let path = req.uri().path();
//     let method = req.method();

//     // Helper to build JSON responses
//     let json = |s: &str| -> Response<Full<Bytes>> {
//         let mut r = Response::new(Full::<Bytes>::from(Bytes::from(format!("{}\n", s))));
//         let (k, v) = header_json();
//         r.headers_mut().insert(k, v);
//         r
//     };

//     let peer_ip = peer.ip();
//     if let IpAddr::V4(block_ip) = peer_ip {
//         let block_ip_u32: u32 = block_ip.into();
//         let block_ip_be = block_ip_u32.to_be();

//         let my_ip_key: lpm_key = lpm_key {
//             prefixlen: 32_u32,
//             addr: block_ip_be,
//         };

//         let my_ip_key_bytes = unsafe { plain::as_bytes(&my_ip_key) };

//         if let Some(flag) = state
//             .clone()
//             .skel
//             .unwrap()
//             .maps
//             .recently_banned_ips
//             .lookup(my_ip_key_bytes, MapFlags::ANY)
//             .unwrap()
//         {
//             println!("result of recently banned ip lookup: {:?}", flag);
//             if flag == vec![1_u8] {
//                 return Ok(Response::new(Full::<Bytes>::from(Bytes::from(
//                     "HAAAAAAHAHAHAAAAA....YOU HAVE ENTERED MY DUNGEON....you will not leave here alive (you have been banned)",
//                 ))));
//             }
//         }
//     }

//     // Root: health
//     if path == "/" && method == hyper::Method::GET {
//         let body = format!(
//             "{{\"status\":\"ok\",\"service\":\"bpf-firewall\",\"remote_addr\":\"{}\"}}",
//             peer.ip()
//         );
//         return Ok(json(&body));
//     }

//     // POST /ban with JSON body {"ips":["1.2.3.4", ...]}
//     if path == "/ban" && method == &Method::POST {
//         #[derive(Deserialize)]
//         struct BanBody {
//             ips: Vec<String>,
//         }

//         let Some(skel) = state.skel.as_ref() else {
//             let mut r = json("{\"ok\":false,\"error\":\"bpf not loaded\"}");
//             *r.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
//             return Ok(r);
//         };

//         // Aggregate body
//         let bytes = match req.into_body().collect().await {
//             Ok(c) => c.to_bytes(),
//             Err(e) => {
//                 let mut r = json(&format!(
//                     "{{\"ok\":false,\"error\":\"body read error: {}\"}}",
//                     e
//                 ));
//                 *r.status_mut() = hyper::StatusCode::BAD_REQUEST;
//                 return Ok(r);
//             }
//         };
//         let parsed: Result<BanBody, _> = serde_json::from_slice(&bytes);
//         let body = match parsed {
//             Ok(v) => v,
//             Err(e) => {
//                 let mut r = json(&format!(
//                     "{{\"ok\":false,\"error\":\"invalid json: {}\"}}",
//                     e
//                 ));
//                 *r.status_mut() = hyper::StatusCode::BAD_REQUEST;
//                 return Ok(r);
//             }
//         };

//         let mut ok = 0usize;
//         let mut errs: Vec<(String, String)> = Vec::new();
//         for s in body.ips {
//             match s.parse::<IpAddr>() {
//                 Ok(ip) => {
//                     let key = LpmKey {
//                         prefixlen: 32,
//                         addr: ipv4_to_u32_be(ip),
//                     };
//                     let key_bytes: &[u8] = unsafe { plain::as_bytes(&key) };
//                     let one: u8 = 1;
//                     if let Err(e) =
//                         skel.maps
//                             .banned_ips
//                             .update(key_bytes, &[one], libbpf_rs::MapFlags::ANY)
//                     {
//                         errs.push((ip.to_string(), e.to_string()));
//                     } else {
//                         let _ = skel.maps.recently_banned_ips.delete(key_bytes);
//                         ok += 1;
//                     }
//                 }
//                 Err(_) => errs.push((s, "invalid ip".to_string())),
//             }
//         }

//         let mut resp = format!("{{\"ok\":true,\"banned_count\":{},\"errors\":[", ok);
//         for (i, (ip, err)) in errs.iter().enumerate() {
//             if i > 0 {
//                 resp.push(',');
//             }
//             resp.push_str(&format!(
//                 "{{\"ip\":\"{}\",\"error\":\"{}\"}}",
//                 ip,
//                 err.replace('"', "'")
//             ));
//         }
//         resp.push_str("]}");
//         return Ok(json(&resp));
//     }

//     // PUT /ban?target=1.2.3.4/24
//     if path == "/ban" && method == hyper::Method::PUT {
//         let resp = match parse_cidr_param(&req) {
//             Ok((ip, prefixlen)) => {
//                 let key = LpmKey {
//                     prefixlen,
//                     addr: ipv4_to_u32_be(ip),
//                 };
//                 let key_bytes: &[u8] = unsafe { plain::as_bytes(&key) };
//                 let one: u8 = 1; // presence flag
//                 // Update banned, remove from recently
//                 let Some(skel) = state.skel.as_ref() else {
//                     let mut r = json("{\"ok\":false,\"error\":\"bpf not loaded\"}");
//                     *r.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
//                     return Ok(r);
//                 };
//                 let res_upd =
//                     skel.maps
//                         .banned_ips
//                         .update(key_bytes, &[one], libbpf_rs::MapFlags::ANY);
//                 if let Err(e) = res_upd {
//                     let mut r = json(&format!(
//                         "{{\"ok\":false,\"error\":\"failed to ban: {}\"}}",
//                         e
//                     ));
//                     *r.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
//                     return Ok(r);
//                 }
//                 let _ = skel.maps.recently_banned_ips.delete(key_bytes);
//                 json(&format!(
//                     "{{\"ok\":true,\"banned\":\"{}/{}\"}}",
//                     ip, prefixlen
//                 ))
//             }
//             Err(e) => {
//                 let mut r = json(&format!("{{\"ok\":false,\"error\":\"{}\"}}", e));
//                 *r.status_mut() = hyper::StatusCode::BAD_REQUEST;
//                 r
//             }
//         };
//         return Ok(resp);
//     }

//     // PUT /recently-ban?target=1.2.3.4/24
//     if path == "/recently-ban" && method == hyper::Method::PUT {
//         let resp = match parse_cidr_param(&req) {
//             Ok((ip, prefixlen)) => {
//                 let key = LpmKey {
//                     prefixlen,
//                     addr: ipv4_to_u32_be(ip),
//                 };
//                 let key_bytes: &[u8] = unsafe { plain::as_bytes(&key) };
//                 let one: u8 = 1;
//                 let Some(skel) = state.skel.as_ref() else {
//                     let mut r = json("{\"ok\":false,\"error\":\"bpf not loaded\"}");
//                     *r.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
//                     return Ok(r);
//                 };
//                 let res_upd = skel.maps.recently_banned_ips.update(
//                     key_bytes,
//                     &[one],
//                     libbpf_rs::MapFlags::ANY,
//                 );
//                 if let Err(e) = res_upd {
//                     let mut r = json(&format!(
//                         "{{\"ok\":false,\"error\":\"failed to set recently-banned: {}\"}}",
//                         e
//                     ));
//                     *r.status_mut() = hyper::StatusCode::INTERNAL_SERVER_ERROR;
//                     return Ok(r);
//                 }
//                 let _ = skel.maps.banned_ips.delete(key_bytes);
//                 json(&format!(
//                     "{{\"ok\":true,\"recently_banned\":\"{}/{}\"}}",
//                     ip, prefixlen
//                 ))
//             }
//             Err(e) => {
//                 let mut r = json(&format!("{{\"ok\":false,\"error\":\"{}\"}}", e));
//                 *r.status_mut() = hyper::StatusCode::BAD_REQUEST;
//                 r
//             }
//         };
//         return Ok(resp);
//     }

//     // GET /status?target=1.2.3.4
//     if path == "/status" && method == hyper::Method::GET {
//         let resp = match parse_cidr_param(&req) {
//             Ok((ip, prefixlen)) => {
//                 let key = LpmKey {
//                     prefixlen,
//                     addr: ipv4_to_u32_be(ip),
//                 };
//                 let key_bytes: &[u8] = unsafe { plain::as_bytes(&key) };
//                 let Some(skel) = state.skel.as_ref() else {
//                     let mut r = json("{\"ok\":false,\"error\":\"bpf not loaded\"}");
//                     *r.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
//                     return Ok(r);
//                 };
//                 let b = skel
//                     .maps
//                     .banned_ips
//                     .lookup(key_bytes, libbpf_rs::MapFlags::ANY);
//                 let r = skel
//                     .maps
//                     .recently_banned_ips
//                     .lookup(key_bytes, libbpf_rs::MapFlags::ANY);
//                 let in_banned = b.as_ref().map(|o| o.is_some()).unwrap_or(false);
//                 let in_recent = r.as_ref().map(|o| o.is_some()).unwrap_or(false);
//                 json(&format!(
//                     "{{\"ok\":true,\"ip\":\"{}\",\"banned\":{},\"recently_banned\":{}}}",
//                     ip, in_banned, in_recent
//                 ))
//             }
//             Err(e) => {
//                 let mut r = json(&format!("{{\"ok\":false,\"error\":\"{}\"}}", e));
//                 *r.status_mut() = hyper::StatusCode::BAD_REQUEST;
//                 r
//             }
//         };
//         return Ok(resp);
//     }

//     // Fallback 404
//     let mut not_found = json("{\"ok\":false,\"error\":\"not found\"}");
//     *not_found.status_mut() = hyper::StatusCode::NOT_FOUND;
//     Ok(not_found)
// }
