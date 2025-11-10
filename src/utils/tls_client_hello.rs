use pingora_core::protocols::ClientHelloWrapper;
use crate::utils::tls_fingerprint::Fingerprint;
use log::{debug};
use std::sync::Arc;
use std::collections::HashMap;
use std::sync::Mutex;
use std::net::SocketAddr;
use std::sync::OnceLock;

/// Global storage for TLS fingerprints keyed by connection peer address
/// This is a temporary storage until the fingerprint can be moved to session context
static TLS_FINGERPRINTS: OnceLock<Mutex<HashMap<String, Arc<Fingerprint>>>> = OnceLock::new();

fn get_fingerprint_map() -> &'static Mutex<HashMap<String, Arc<Fingerprint>>> {
    TLS_FINGERPRINTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Public function to access the fingerprint map
/// This is used by tls_acceptor_wrapper to store fingerprints
pub fn get_fingerprint_map_public() -> &'static Mutex<HashMap<String, Arc<Fingerprint>>> {
    get_fingerprint_map()
}

/// Generate JA4 fingerprint from ClientHello raw bytes
/// This is called after ClientHello is extracted by ClientHelloWrapper
pub fn generate_fingerprint_from_client_hello(
    hello: &pingora_core::protocols::tls::client_hello::ClientHello,
    peer_addr: Option<pingora_core::protocols::l4::socket::SocketAddr>,
) -> Option<Arc<Fingerprint>> {
    let peer_addr_str = peer_addr.as_ref()
        .and_then(|a| a.as_inet())
        .map(|inet| format!("{}:{}", inet.ip(), inet.port()))
        .unwrap_or_else(|| "unknown".to_string());

    debug!("Generating fingerprint from ClientHello: Peer: {}, SNI={:?}, ALPN={:?}, raw_len={}",
           peer_addr_str, hello.sni, hello.alpn, hello.raw.len());

    // Generate JA4 fingerprint from raw ClientHello bytes
    if let Some(fingerprint) = crate::utils::tls_fingerprint::fingerprint_client_hello(&hello.raw) {
        let fingerprint_arc: Arc<Fingerprint> = Arc::new(fingerprint);

        // Store fingerprint temporarily if we have peer address
        // Convert pingora SocketAddr to std::net::SocketAddr for storage
        if let Some(ref addr) = peer_addr {
            if let Some(inet) = addr.as_inet() {
                let std_addr = SocketAddr::new(inet.ip().into(), inet.port());
                let key = format!("{}", std_addr);
                if let Ok(mut map) = get_fingerprint_map().lock() {
                    map.insert(key, fingerprint_arc.clone());
                }
            }
        }

        // Log fingerprint details at info level
        debug!(
            "TLS Fingerprint extracted - Peer: {}, JA4: {}, JA4_Raw: {}, JA4_Unsorted: {}, JA4_Raw_Unsorted: {}, TLS_Version: {}, Cipher: {:?}, SNI: {:?}, ALPN: {:?}",
            peer_addr_str,
            fingerprint_arc.ja4,
            fingerprint_arc.ja4_raw,
            fingerprint_arc.ja4_unsorted,
            fingerprint_arc.ja4_raw_unsorted,
            fingerprint_arc.tls_version,
            fingerprint_arc.cipher_suite,
            fingerprint_arc.sni,
            fingerprint_arc.alpn
        );

        debug!("Generated JA4 fingerprint: {}", fingerprint_arc.ja4);
        return Some(fingerprint_arc);
    }

    debug!("Failed to generate fingerprint from ClientHello: Peer: {}, raw_len={}", peer_addr_str, hello.raw.len());
    None
}

/// Extract ClientHello from a stream and generate JA4 fingerprint
/// Returns the fingerprint if extraction was successful
/// The stream should be wrapped with ClientHelloWrapper before TLS handshake
#[cfg(unix)]
pub fn extract_and_fingerprint<S: std::os::unix::io::AsRawFd>(
    stream: S,
    peer_addr: Option<std::net::SocketAddr>,
) -> Option<Arc<Fingerprint>> {
    let mut wrapper = ClientHelloWrapper::new(stream);

    match wrapper.extract_client_hello() {
        Ok(Some(hello)) => {
            // Convert std::net::SocketAddr to pingora SocketAddr
            use pingora_core::protocols::l4::socket::SocketAddr as PingoraAddr;
            let pingora_addr = peer_addr.map(|addr| PingoraAddr::Inet(addr));
            generate_fingerprint_from_client_hello(&hello, pingora_addr)
        }
        Ok(None) => {
            debug!("No ClientHello detected in stream");
            None
        }
        Err(e) => {
            debug!("Failed to extract ClientHello: {:?}", e);
            None
        }
    }
}

/// Get stored TLS fingerprint for a peer address
pub fn get_fingerprint(peer_addr: &SocketAddr) -> Option<Arc<Fingerprint>> {
    let key = format!("{}", peer_addr);
    if let Ok(map) = get_fingerprint_map().lock() {
        map.get(&key).cloned()
    } else {
        None
    }
}

/// Remove stored TLS fingerprint for a peer address
pub fn remove_fingerprint(peer_addr: &SocketAddr) {
    let key = format!("{}", peer_addr);
    if let Ok(mut map) = get_fingerprint_map().lock() {
        map.remove(&key);
    }
}

#[cfg(not(unix))]
pub fn extract_and_fingerprint<S>(
    _stream: S,
    _peer_addr: Option<SocketAddr>,
) -> Option<Arc<Fingerprint>> {
    // ClientHello extraction is only supported on Unix
    None
}

