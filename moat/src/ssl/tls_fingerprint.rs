use sha2::{Digest, Sha256};
use tls_parser::{
    TlsClientHelloContents, TlsExtension, TlsExtensionType, TlsMessage, TlsMessageHandshake,
    parse_tls_extensions, parse_tls_plaintext,
};

/// GREASE values as defined in RFC 8701.
pub const TLS_GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// High level JA4 fingerprint summary derived from a TLS ClientHello.
#[derive(Debug, Clone)]
pub struct Fingerprint {
    pub ja4: String,
    pub ja4_raw: String,
    pub ja4_unsorted: String,
    pub ja4_raw_unsorted: String,
    pub ja4l: String,
    pub tls_version: String,
    pub cipher_suite: Option<String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
}

/// Attempt to parse a TLS ClientHello from the supplied bytes and, if successful,
/// return the corresponding JA4 fingerprints.
pub fn fingerprint_client_hello(data: &[u8]) -> Option<Fingerprint> {
    let (_, record) = parse_tls_plaintext(data).ok()?;
    for message in record.msg.iter() {
        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) = message {
            let signature = extract_tls_signature_from_client_hello(client_hello).ok()?;
            let sorted = signature.generate_ja4_with_order(false);
            let unsorted = signature.generate_ja4_with_order(true);
            return Some(Fingerprint {
                ja4: sorted.full.value().to_string(),
                ja4_raw: sorted.raw.value().to_string(),
                ja4_unsorted: unsorted.full.value().to_string(),
                ja4_raw_unsorted: unsorted.raw.value().to_string(),
                ja4l: calculate_ja4l(data.len()),
                tls_version: signature.version.to_string(),
                cipher_suite: signature.preferred_cipher_suite.map(cipher_suite_to_string),
                sni: signature.sni.clone(),
                alpn: signature.alpn.clone(),
            });
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TlsVersion {
    V1_3,
    V1_2,
    V1_1,
    V1_0,
    Ssl3_0,
    Ssl2_0,
    Unknown(u16),
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsVersion::V1_3 => write!(f, "13"),
            TlsVersion::V1_2 => write!(f, "12"),
            TlsVersion::V1_1 => write!(f, "11"),
            TlsVersion::V1_0 => write!(f, "10"),
            TlsVersion::Ssl3_0 => write!(f, "s3"),
            TlsVersion::Ssl2_0 => write!(f, "s2"),
            TlsVersion::Unknown(_) => write!(f, "00"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Ja4Fingerprint {
    Sorted(String),
    Unsorted(String),
}

impl Ja4Fingerprint {
    fn value(&self) -> &str {
        match self {
            Ja4Fingerprint::Sorted(v) => v,
            Ja4Fingerprint::Unsorted(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Ja4RawFingerprint {
    Sorted(String),
    Unsorted(String),
}

impl Ja4RawFingerprint {
    fn value(&self) -> &str {
        match self {
            Ja4RawFingerprint::Sorted(v) => v,
            Ja4RawFingerprint::Unsorted(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Ja4Payload {
    full: Ja4Fingerprint,
    raw: Ja4RawFingerprint,
}

#[derive(Debug, Clone, PartialEq)]
struct Signature {
    version: TlsVersion,
    cipher_suites: Vec<u16>,
    preferred_cipher_suite: Option<u16>,
    extensions: Vec<u16>,
    elliptic_curves: Vec<u16>,
    elliptic_curve_point_formats: Vec<u8>,
    signature_algorithms: Vec<u16>,
    sni: Option<String>,
    alpn: Option<String>,
}

impl Signature {
    fn generate_ja4_with_order(&self, original_order: bool) -> Ja4Payload {
        let filtered_ciphers = filter_grease_values(&self.cipher_suites);
        let filtered_extensions = filter_grease_values(&self.extensions);
        let filtered_sig_algs = filter_grease_values(&self.signature_algorithms);

        let protocol = "t";
        let tls_version_str = format!("{}", self.version);
        let sni_indicator = if self.sni.is_some() { "d" } else { "i" };
        let cipher_count = format!("{:02}", self.cipher_suites.len().min(99));
        let extension_count = format!("{:02}", self.extensions.len().min(99));
        let (alpn_first, alpn_last) = match &self.alpn {
            Some(alpn) => first_last_alpn(alpn),
            None => ('0', '0'),
        };
        let ja4_a = format!(
            "{protocol}{tls_version_str}{sni_indicator}{cipher_count}{extension_count}{alpn_first}{alpn_last}"
        );

        let mut ciphers_for_b = filtered_ciphers;
        if !original_order {
            ciphers_for_b.sort_unstable();
        }
        let ja4_b_raw = ciphers_for_b
            .iter()
            .map(|c| format!("{c:04x}"))
            .collect::<Vec<String>>()
            .join(",");

        let mut extensions_for_c = filtered_extensions;
        if !original_order {
            extensions_for_c.retain(|&ext| ext != 0x0000 && ext != 0x0010);
            extensions_for_c.sort_unstable();
        }
        let extensions_str = extensions_for_c
            .iter()
            .map(|e| format!("{e:04x}"))
            .collect::<Vec<String>>()
            .join(",");

        let sig_algs_str = filtered_sig_algs
            .iter()
            .map(|s| format!("{s:04x}"))
            .collect::<Vec<String>>()
            .join(",");

        let ja4_c_raw = if sig_algs_str.is_empty() {
            extensions_str
        } else if extensions_str.is_empty() {
            sig_algs_str
        } else {
            format!("{extensions_str}_{sig_algs_str}")
        };

        let ja4_b_hash = hash12(&ja4_b_raw);
        let ja4_c_hash = hash12(&ja4_c_raw);

        let ja4_hashed = format!("{ja4_a}_{ja4_b_hash}_{ja4_c_hash}");
        let ja4_raw_full = format!("{ja4_a}_{ja4_b_raw}_{ja4_c_raw}");

        let full = if original_order {
            Ja4Fingerprint::Unsorted(ja4_hashed)
        } else {
            Ja4Fingerprint::Sorted(ja4_hashed)
        };
        let raw = if original_order {
            Ja4RawFingerprint::Unsorted(ja4_raw_full)
        } else {
            Ja4RawFingerprint::Sorted(ja4_raw_full)
        };

        Ja4Payload { full, raw }
    }
}

fn extract_tls_signature_from_client_hello(
    client_hello: &TlsClientHelloContents,
) -> Result<Signature, ()> {
    let cipher_suites: Vec<u16> = client_hello.ciphers.iter().map(|c| c.0).collect();
    let preferred_cipher_suite = cipher_suites.first().copied();

    let mut extensions = Vec::new();
    let mut sni = None;
    let mut alpn = None;
    let mut signature_algorithms = Vec::new();
    let mut elliptic_curves = Vec::new();
    let mut elliptic_curve_point_formats = Vec::new();

    if let Some(ext_data) = &client_hello.ext
        && let Ok((_remaining, parsed_extensions)) = parse_tls_extensions(ext_data)
    {
        for extension in &parsed_extensions {
            let ext_type: u16 = TlsExtensionType::from(extension).into();
            if !is_grease_value(ext_type) {
                extensions.push(ext_type);
            }
            match extension {
                TlsExtension::SNI(sni_list) => {
                    if let Some((_, hostname)) = sni_list.first() {
                        sni = String::from_utf8(hostname.to_vec()).ok();
                    }
                }
                TlsExtension::ALPN(alpn_list) => {
                    if let Some(protocol) = alpn_list.first() {
                        alpn = String::from_utf8(protocol.to_vec()).ok();
                    }
                }
                TlsExtension::SignatureAlgorithms(sig_algs) => {
                    signature_algorithms = sig_algs.clone();
                }
                TlsExtension::EllipticCurves(curves) => {
                    elliptic_curves = curves.iter().map(|c| c.0).collect();
                }
                TlsExtension::EcPointFormats(formats) => {
                    elliptic_curve_point_formats = formats.to_vec();
                }
                _ => {}
            }
        }
    }

    let version = determine_tls_version(&client_hello.version, &extensions);

    Ok(Signature {
        version,
        cipher_suites,
        preferred_cipher_suite,
        extensions,
        elliptic_curves,
        elliptic_curve_point_formats,
        signature_algorithms,
        sni,
        alpn,
    })
}

fn determine_tls_version(
    legacy_version: &tls_parser::TlsVersion,
    extensions: &[u16],
) -> TlsVersion {
    if extensions.contains(&TlsExtensionType::SupportedVersions.into()) {
        return TlsVersion::V1_3;
    }

    match *legacy_version {
        tls_parser::TlsVersion::Tls13 => TlsVersion::V1_3,
        tls_parser::TlsVersion::Tls12 => TlsVersion::V1_2,
        tls_parser::TlsVersion::Tls11 => TlsVersion::V1_1,
        tls_parser::TlsVersion::Tls10 => TlsVersion::V1_0,
        tls_parser::TlsVersion::Ssl30 => TlsVersion::Ssl3_0,
        other => TlsVersion::Unknown(other.into()),
    }
}

fn is_grease_value(value: u16) -> bool {
    TLS_GREASE_VALUES.contains(&value)
}

fn filter_grease_values(values: &[u16]) -> Vec<u16> {
    values
        .iter()
        .copied()
        .filter(|v| !is_grease_value(*v))
        .collect()
}

fn first_last_alpn(s: &str) -> (char, char) {
    let replace_nonascii_with_9 = |c: char| if c.is_ascii() { c } else { '9' };
    let mut chars = s.chars();
    let first = chars.next().map(replace_nonascii_with_9).unwrap_or('0');
    let last = if s.len() == 1 {
        '0'
    } else {
        chars
            .next_back()
            .map(replace_nonascii_with_9)
            .unwrap_or('0')
    };
    (first, last)
}

fn hash12(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let hex = format!("{:x}", digest);
    hex[..12].to_string()
}

/// Calculate JA4L (latency-like fingerprint) based on packet size.
fn calculate_ja4l(packet_size: usize) -> String {
    let estimated_client_rtt = if packet_size > 1500 {
        50
    } else if packet_size > 1000 {
        30
    } else {
        10
    };
    let estimated_server_rtt = estimated_client_rtt + 5;
    format!("{}_{}_{}", estimated_client_rtt, estimated_server_rtt, packet_size)
}

fn cipher_suite_to_string(cipher_suite: u16) -> String {
    match cipher_suite {
        0x1301 => "TLS_AES_128_GCM_SHA256".to_string(),
        0x1302 => "TLS_AES_256_GCM_SHA384".to_string(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".to_string(),
        0x1304 => "TLS_AES_128_CCM_SHA256".to_string(),
        0x1305 => "TLS_AES_128_CCM_8_SHA256".to_string(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".to_string(),
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".to_string(),
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".to_string(),
        0x009e => "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0x009f => "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0x0035 => "TLS_RSA_WITH_AES_128_GCM_SHA256".to_string(),
        0x0036 => "TLS_RSA_WITH_AES_256_GCM_SHA384".to_string(),
        0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA".to_string(),
        0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256".to_string(),
        0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256".to_string(),
        _ => format!("UNKNOWN_CIPHER_{:04x}", cipher_suite),
    }
}
