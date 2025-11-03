use sha2::{Digest, Sha256};
use hyper::HeaderMap;

/// JA4T: TCP Fingerprint from TCP options
/// Official Format: {window_size}_{tcp_options}_{mss}_{window_scale}
/// Example: "65535_2-4-8-1-3_1460_7"
/// Reference: https://github.com/FoxIO-LLC/ja4/blob/main/zeek/ja4t/main.zeek
#[derive(Debug, Clone)]
pub struct Ja4tFingerprint {
    pub fingerprint: String,
    pub window_size: u16,
    pub ttl: u16,
    pub mss: u16,
    pub window_scale: u8,
    pub options: Vec<u8>,
}

impl Ja4tFingerprint {
    /// Generate JA4T fingerprint from TCP parameters
    /// TCP options are represented by their kind numbers:
    /// 0 = EOL, 1 = NOP, 2 = MSS, 3 = Window Scale, 4 = SACK Permitted,
    /// 5 = SACK, 8 = Timestamps, etc.
    pub fn from_tcp_data(
        window_size: u16,
        ttl: u16,
        mss: u16,
        window_scale: u8,
        options: &[u8],
    ) -> Self {
        // Extract TCP option kinds
        let mut option_kinds = Vec::new();
        let mut i = 0;

        while i < options.len() {
            let kind = options[i];

            match kind {
                0 => break, // EOL
                1 => {
                    // NOP - single byte
                    option_kinds.push(kind);
                    i += 1;
                }
                _ => {
                    // Options with length
                    if i + 1 < options.len() {
                        let len = options[i + 1] as usize;
                        option_kinds.push(kind);
                        i += len.max(2);
                    } else {
                        break;
                    }
                }
            }
        }

        // Build fingerprint: window_size_options_mss_window_scale
        // Official format from Zeek implementation
        let options_str = option_kinds
            .iter()
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let fingerprint = format!("{}_{}_{}_{}",
            window_size,
            if options_str.is_empty() { "0" } else { &options_str },
            mss,
            window_scale
        );

        Self {
            fingerprint,
            window_size,
            ttl,
            mss,
            window_scale,
            options: option_kinds,
        }
    }

    /// Get the JA4T hash (first 12 characters of SHA-256)
    pub fn hash(&self) -> String {
        let digest = Sha256::digest(self.fingerprint.as_bytes());
        let hex = format!("{:x}", digest);
        hex[..12].to_string()
    }
}

/// JA4H: HTTP Header Fingerprint
/// Official Format: {method}{version}{cookie}{referer}{header_count}{language}_{headers_hash}_{cookie_names_hash}_{cookie_values_hash}
/// Example: "ge11cr15enus_a1b2c3d4e5f6_123456789abc_def012345678"
/// Reference: https://github.com/FoxIO-LLC/ja4/blob/main/zeek/ja4h/main.zeek
#[derive(Debug, Clone)]
pub struct Ja4hFingerprint {
    pub fingerprint: String,
    pub method: String,
    pub version: String,
    pub has_cookie: bool,
    pub has_referer: bool,
    pub header_count: usize,
    pub language: String,
}

impl Ja4hFingerprint {
    /// Generate JA4H fingerprint from HTTP request
    pub fn from_http_request(
        method: &str,
        version: &str,
        headers: &HeaderMap,
    ) -> Self {
        // Method: first 2 letters, lowercase (ge=GET, po=POST, etc.)
        let method_str = method.to_lowercase();
        let method_code = if method_str.len() >= 2 {
            &method_str[..2]
        } else {
            "un" // unknown
        };

        // Version: 10, 11, 20, 30
        let version_code = match version {
            "HTTP/0.9" => "09",
            "HTTP/1.0" => "10",
            "HTTP/1.1" => "11",
            "HTTP/2.0" | "HTTP/2" => "20",
            "HTTP/3.0" | "HTTP/3" => "30",
            _ => "00",
        };

        // Check if Cookie and Referer headers exist
        let has_cookie = headers.contains_key("cookie");
        let cookie_flag = if has_cookie { "c" } else { "n" };

        let has_referer = headers.contains_key("referer");
        let referer_flag = if has_referer { "r" } else { "n" };

        // Extract language from Accept-Language header
        let language = if let Some(lang_header) = headers.get("accept-language") {
            if let Ok(lang_str) = lang_header.to_str() {
                // Take first language, remove hyphens, lowercase, pad to 4 chars
                let primary_lang = lang_str.split(',').next().unwrap_or("");
                let clean_lang = primary_lang
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .replace('-', "")
                    .to_lowercase();

                let mut lang_code = clean_lang.chars().take(4).collect::<String>();
                while lang_code.len() < 4 {
                    lang_code.push('0');
                }
                lang_code
            } else {
                "0000".to_string()
            }
        } else {
            "0000".to_string()
        };

        // Collect header names (excluding Cookie and Referer)
        let mut header_names: Vec<String> = headers
            .iter()
            .filter_map(|(name, _)| {
                let name_str = name.as_str().to_lowercase();
                if name_str == "cookie" || name_str == "referer" {
                    None
                } else {
                    Some(name_str)
                }
            })
            .collect();

        header_names.sort();
        let header_count = header_names.len().min(99);
        let header_count_str = format!("{:02}", header_count);

        // Create header hash
        let header_string = header_names.join(",");
        let header_hash = if header_string.is_empty() {
            "000000000000".to_string()
        } else {
            let digest = Sha256::digest(header_string.as_bytes());
            let hex = format!("{:x}", digest);
            hex[..12].to_string()
        };

        // Parse cookies if they exist
        let (cookie_names_hash, cookie_values_hash) = if let Some(cookie_value) = headers.get("cookie") {
            if let Ok(cookie_str) = cookie_value.to_str() {
                // Parse cookie pairs: name=value; name2=value2
                let mut cookie_names: Vec<String> = Vec::new();
                let mut cookie_values: Vec<String> = Vec::new();

                for part in cookie_str.split(';') {
                    let trimmed = part.trim();
                    if let Some((name, _value)) = trimmed.split_once('=') {
                        cookie_names.push(name.trim().to_string());
                        cookie_values.push(trimmed.to_string()); // Full "name=value"
                    }
                }

                // Sort separately
                cookie_names.sort();
                cookie_values.sort();

                // Hash separately
                let names_hash = if cookie_names.is_empty() {
                    "000000000000".to_string()
                } else {
                    let digest = Sha256::digest(cookie_names.join(",").as_bytes());
                    let hex = format!("{:x}", digest);
                    hex[..12].to_string()
                };

                let values_hash = if cookie_values.is_empty() {
                    "000000000000".to_string()
                } else {
                    let digest = Sha256::digest(cookie_values.join(",").as_bytes());
                    let hex = format!("{:x}", digest);
                    hex[..12].to_string()
                };

                (names_hash, values_hash)
            } else {
                ("000000000000".to_string(), "000000000000".to_string())
            }
        } else {
            ("000000000000".to_string(), "000000000000".to_string())
        };

        // Build fingerprint: {method}{version}{cookie}{referer}{count}{lang}_{headers}_{cookie_names}_{cookie_values}
        let fingerprint = format!(
            "{}{}{}{}{}{}_{}_{}_{}",
            method_code,
            version_code,
            cookie_flag,
            referer_flag,
            header_count_str,
            language,
            header_hash,
            cookie_names_hash,
            cookie_values_hash
        );

        Self {
            fingerprint,
            method: method.to_string(),
            version: version.to_string(),
            has_cookie,
            has_referer,
            header_count,
            language,
        }
    }
}

/// JA4L: Latency Fingerprint
/// Official Format: {rtt_microseconds}_{ttl}
/// Measures round-trip time between SYN and SYNACK packets
/// Example: "12500_64" (12.5ms RTT, TTL 64)
/// Reference: https://github.com/FoxIO-LLC/ja4/blob/main/zeek/ja4l/main.zeek
#[derive(Debug, Clone)]
pub struct Ja4lMeasurement {
    pub syn_time: Option<u64>,      // Microseconds
    pub synack_time: Option<u64>,   // Microseconds
    pub ack_time: Option<u64>,      // Microseconds
    pub ttl_client: Option<u8>,
    pub ttl_server: Option<u8>,
}

impl Ja4lMeasurement {
    pub fn new() -> Self {
        Self {
            syn_time: None,
            synack_time: None,
            ack_time: None,
            ttl_client: None,
            ttl_server: None,
        }
    }

    /// Record SYN packet timestamp
    pub fn set_syn(&mut self, timestamp_us: u64, ttl: u8) {
        self.syn_time = Some(timestamp_us);
        self.ttl_client = Some(ttl);
    }

    /// Record SYNACK packet timestamp
    pub fn set_synack(&mut self, timestamp_us: u64, ttl: u8) {
        self.synack_time = Some(timestamp_us);
        self.ttl_server = Some(ttl);
    }

    /// Record ACK packet timestamp
    pub fn set_ack(&mut self, timestamp_us: u64) {
        self.ack_time = Some(timestamp_us);
    }

    /// Generate JA4L client fingerprint
    /// Format: {client_rtt_us}_{client_ttl}
    /// RTT = (ACK - SYNACK) / 2
    pub fn fingerprint_client(&self) -> Option<String> {
        let synack = self.synack_time?;
        let ack = self.ack_time?;
        let ttl = self.ttl_client?;

        // Calculate client-side RTT (half of ACK-SYNACK time)
        let rtt_us = (ack.saturating_sub(synack)) / 2;

        Some(format!("{}_{}", rtt_us, ttl))
    }

    /// Generate JA4L server fingerprint
    /// Format: {server_rtt_us}_{server_ttl}
    /// RTT = (SYNACK - SYN) / 2
    pub fn fingerprint_server(&self) -> Option<String> {
        let syn = self.syn_time?;
        let synack = self.synack_time?;
        let ttl = self.ttl_server?;

        // Calculate server-side RTT (half of SYNACK-SYN time)
        let rtt_us = (synack.saturating_sub(syn)) / 2;

        Some(format!("{}_{}", rtt_us, ttl))
    }

    /// Legacy format for compatibility (if needed)
    /// Returns both client and server measurements
    pub fn fingerprint_combined(&self) -> Option<String> {
        let client = self.fingerprint_client()?;
        let server = self.fingerprint_server()?;

        Some(format!("c:{},s:{}", client, server))
    }
}

impl Default for Ja4lMeasurement {
    fn default() -> Self {
        Self::new()
    }
}

/// JA4S: TLS Server Response Fingerprint
/// Official Format: {proto}{version}{ext_count}{alpn}_{cipher}_{extensions_hash}
/// Example: "t130200_1301_a56c5b993250"
/// Reference: https://github.com/FoxIO-LLC/ja4/blob/main/zeek/ja4s/main.zeek
#[derive(Debug, Clone)]
pub struct Ja4sFingerprint {
    pub fingerprint: String,
    pub proto: String,
    pub version: String,
    pub cipher: u16,
    pub extensions: Vec<u16>,
    pub alpn: Option<String>,
}

impl Ja4sFingerprint {
    /// Generate JA4S fingerprint from TLS ServerHello
    ///
    /// # Arguments
    /// * `is_quic` - true if QUIC, false if TCP TLS
    /// * `version` - TLS version (0x0304 for TLS 1.3, etc.)
    /// * `cipher` - Cipher suite selected by server
    /// * `extensions` - List of extension codes from ServerHello
    /// * `alpn` - ALPN protocol selected (e.g., "h2", "http/1.1")
    pub fn from_server_hello(
        is_quic: bool,
        version: u16,
        cipher: u16,
        extensions: &[u16],
        alpn: Option<&str>,
    ) -> Self {
        // Proto: q=QUIC, t=TCP
        let proto = if is_quic { "q" } else { "t" };

        // Version mapping
        let version_str = match version {
            0x0304 => "13",  // TLS 1.3
            0x0303 => "12",  // TLS 1.2
            0x0302 => "11",  // TLS 1.1
            0x0301 => "10",  // TLS 1.0
            0x0300 => "s3",  // SSL 3.0
            0x0002 => "s2",  // SSL 2.0
            0xfeff => "d1",  // DTLS 1.0
            0xfefd => "d2",  // DTLS 1.2
            0xfefc => "d3",  // DTLS 1.3
            _ => "00",
        };

        // Extension count (max 99)
        let ext_count = format!("{:02}", extensions.len().min(99));

        // ALPN: first and last character
        let alpn_code = if let Some(alpn_str) = alpn {
            if alpn_str.is_empty() {
                "00".to_string()
            } else if alpn_str.len() == 1 {
                let ch = alpn_str.chars().next().unwrap();
                format!("{}{}", ch, ch)
            } else {
                let first = alpn_str.chars().next().unwrap();
                let last = alpn_str.chars().last().unwrap();
                format!("{}{}", first, last)
            }
        } else {
            "00".to_string()
        };

        // Build part A
        let part_a = format!("{}{}{}{}", proto, version_str, ext_count, alpn_code);

        // Build part B (cipher in hex)
        let part_b = format!("{:04x}", cipher);

        // Build part C (extensions hash)
        let ext_strings: Vec<String> = extensions.iter().map(|e| format!("{:04x}", e)).collect();
        let ext_string = ext_strings.join(",");
        let part_c = if ext_string.is_empty() {
            "000000000000".to_string()
        } else {
            let digest = Sha256::digest(ext_string.as_bytes());
            let hex = format!("{:x}", digest);
            hex[..12].to_string()
        };

        let fingerprint = format!("{}_{}_{}",part_a, part_b, part_c);

        Self {
            fingerprint,
            proto: proto.to_string(),
            version: version_str.to_string(),
            cipher,
            extensions: extensions.to_vec(),
            alpn: alpn.map(|s| s.to_string()),
        }
    }

    /// Get raw (non-hashed) fingerprint
    pub fn raw(&self) -> String {
        let proto = &self.proto;
        let version = &self.version;
        let ext_count = format!("{:02}", self.extensions.len().min(99));
        let alpn_code = self.alpn.as_ref().map_or("00".to_string(), |a| {
            if a.is_empty() {
                "00".to_string()
            } else if a.len() == 1 {
                format!("{}{}", a, a)
            } else {
                format!("{}{}", a.chars().next().unwrap(), a.chars().last().unwrap())
            }
        });

        let part_a = format!("{}{}{}{}", proto, version, ext_count, alpn_code);
        let part_b = format!("{:04x}", self.cipher);
        let ext_strings: Vec<String> = self.extensions.iter().map(|e| format!("{:04x}", e)).collect();
        let part_c = ext_strings.join(",");

        format!("{}_{}_{}",  part_a, part_b, part_c)
    }
}

/// JA4X: X.509 Certificate Fingerprint
/// Official Format: {issuer_rdns_hash}_{subject_rdns_hash}_{extensions_hash}
/// Example: "aae71e8db6d7_b186095e22b6_c1a4f9e7d8b3"
/// Reference: https://github.com/FoxIO-LLC/ja4/blob/main/rust/ja4x/src/lib.rs
#[derive(Debug, Clone)]
pub struct Ja4xFingerprint {
    pub fingerprint: String,
    pub issuer_rdns: String,
    pub subject_rdns: String,
    pub extensions: String,
}

impl Ja4xFingerprint {
    /// Generate JA4X fingerprint from X.509 certificate attributes
    ///
    /// # Arguments
    /// * `issuer_oids` - List of issuer RDN OIDs in hex (e.g., ["550406", "55040a"])
    /// * `subject_oids` - List of subject RDN OIDs in hex
    /// * `extension_oids` - List of extension OIDs in hex
    pub fn from_x509(
        issuer_oids: &[String],
        subject_oids: &[String],
        extension_oids: &[String],
    ) -> Self {
        let issuer_rdns = issuer_oids.join(",");
        let subject_rdns = subject_oids.join(",");
        let extensions = extension_oids.join(",");

        let issuer_hash = if issuer_rdns.is_empty() {
            "000000000000".to_string()
        } else {
            let digest = Sha256::digest(issuer_rdns.as_bytes());
            let hex = format!("{:x}", digest);
            hex[..12].to_string()
        };

        let subject_hash = if subject_rdns.is_empty() {
            "000000000000".to_string()
        } else {
            let digest = Sha256::digest(subject_rdns.as_bytes());
            let hex = format!("{:x}", digest);
            hex[..12].to_string()
        };

        let extensions_hash = if extensions.is_empty() {
            "000000000000".to_string()
        } else {
            let digest = Sha256::digest(extensions.as_bytes());
            let hex = format!("{:x}", digest);
            hex[..12].to_string()
        };

        let fingerprint = format!("{}_{}_{}",  issuer_hash, subject_hash, extensions_hash);

        Self {
            fingerprint,
            issuer_rdns,
            subject_rdns,
            extensions,
        }
    }

    /// Get raw (non-hashed) fingerprint
    pub fn raw(&self) -> String {
        format!("{}_{}_{}",  self.issuer_rdns, self.subject_rdns, self.extensions)
    }

    /// Helper to convert OID string to hex representation
    /// Example: "2.5.4.3" -> "550403"
    pub fn oid_to_hex(oid: &str) -> String {
        let parts: Vec<u32> = oid.split('.').filter_map(|s| s.parse().ok()).collect();
        if parts.len() < 2 {
            return String::new();
        }

        let mut result: Vec<u8> = vec![(parts[0] * 40 + parts[1]) as u8];

        for &part in &parts[2..] {
            let encoded = Self::encode_variable_length(part);
            result.extend(encoded);
        }

        result.iter().map(|b| format!("{:02x}", b)).collect::<String>()
    }

    /// Encode value as variable-length quantity (for OID encoding)
    fn encode_variable_length(mut value: u32) -> Vec<u8> {
        let mut output = Vec::new();
        let mut mask = 0x00;

        while value >= 0x80 {
            output.insert(0, ((value & 0x7F) | mask) as u8);
            value >>= 7;
            mask = 0x80;
        }
        output.insert(0, (value | mask) as u8);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;

    #[test]
    fn test_ja4t_fingerprint() {
        let ja4t = Ja4tFingerprint::from_tcp_data(
            65535, // window_size
            64,    // ttl
            1460,  // mss
            7,     // window_scale
            &[2, 4, 5, 180, 4, 2, 8, 10], // TCP options (MSS, SACK, Timestamps)
        );

        assert_eq!(ja4t.window_size, 65535);
        assert_eq!(ja4t.ttl, 64);
        assert_eq!(ja4t.mss, 1460);
        assert_eq!(ja4t.window_scale, 7);
        // Official format: {window_size}_{options}_{mss}_{window_scale}
        assert!(ja4t.fingerprint.starts_with("65535_"));
        assert!(ja4t.fingerprint.contains("_1460_7"));
        assert!(!ja4t.hash().is_empty());
        assert_eq!(ja4t.hash().len(), 12);
    }

    #[test]
    fn test_ja4h_fingerprint() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "Mozilla/5.0".parse().unwrap());
        headers.insert("accept", "*/*".parse().unwrap());
        headers.insert("accept-language", "en-US,en;q=0.9".parse().unwrap());
        headers.insert("cookie", "session=abc123; id=xyz789".parse().unwrap());
        headers.insert("referer", "https://example.com".parse().unwrap());

        let ja4h = Ja4hFingerprint::from_http_request(
            "GET",
            "HTTP/1.1",
            &headers,
        );

        assert_eq!(ja4h.method, "GET");
        assert_eq!(ja4h.version, "HTTP/1.1");
        assert!(ja4h.has_cookie);
        assert!(ja4h.has_referer);
        assert_eq!(ja4h.language, "enus");
        // Official format: {method}{version}{cookie}{referer}{count}{lang}_{headers}_{cookie_names}_{cookie_values}
        assert!(ja4h.fingerprint.starts_with("ge11cr"));
        assert!(ja4h.fingerprint.contains("enus_"));
        // Should have 4 parts separated by underscores
        assert_eq!(ja4h.fingerprint.matches('_').count(), 3);
    }

    #[test]
    fn test_ja4l_measurement() {
        let mut ja4l = Ja4lMeasurement::new();

        // Simulate TCP handshake timing (in microseconds)
        ja4l.set_syn(1000000, 64);        // SYN at 1s, TTL 64
        ja4l.set_synack(1025000, 128);    // SYNACK at 1.025s, TTL 128 (25ms later)
        ja4l.set_ack(1050000);            // ACK at 1.050s (25ms after SYNACK)

        // Client fingerprint: (ACK - SYNACK) / 2 = (1050000 - 1025000) / 2 = 12500μs
        let client_fp = ja4l.fingerprint_client().unwrap();
        assert_eq!(client_fp, "12500_64");

        // Server fingerprint: (SYNACK - SYN) / 2 = (1025000 - 1000000) / 2 = 12500μs
        let server_fp = ja4l.fingerprint_server().unwrap();
        assert_eq!(server_fp, "12500_128");
    }

    #[test]
    fn test_ja4s_fingerprint() {
        // TLS 1.3 ServerHello with extensions
        let ja4s = Ja4sFingerprint::from_server_hello(
            false,                          // TCP (not QUIC)
            0x0304,                         // TLS 1.3
            0x1301,                         // TLS_AES_128_GCM_SHA256
            &[0x002b, 0x0033],              // supported_versions, key_share
            Some("h2"),                     // ALPN
        );

        assert_eq!(ja4s.proto, "t");
        assert_eq!(ja4s.version, "13");
        assert_eq!(ja4s.cipher, 0x1301);
        assert!(ja4s.fingerprint.starts_with("t1302h2_1301_"));
        assert_eq!(ja4s.fingerprint.matches('_').count(), 2);

        // Verify raw format
        let raw = ja4s.raw();
        assert!(raw.starts_with("t1302h2_1301_"));
        assert!(raw.contains("002b,0033") || raw.contains("002b") && raw.contains("0033"));
    }

    #[test]
    fn test_ja4s_quic() {
        // QUIC ServerHello
        let ja4s = Ja4sFingerprint::from_server_hello(
            true,                           // QUIC
            0x0304,                         // TLS 1.3
            0x1302,                         // TLS_AES_256_GCM_SHA384
            &[0x002b],                      // supported_versions
            Some("h3"),                     // HTTP/3
        );

        assert_eq!(ja4s.proto, "q");
        assert!(ja4s.fingerprint.starts_with("q1301h3_1302_"));
    }

    #[test]
    fn test_ja4x_fingerprint() {
        // X.509 certificate with common OIDs
        let issuer_oids = vec![
            "550406".to_string(),  // countryName
            "55040a".to_string(),  // organizationName
            "550403".to_string(),  // commonName
        ];

        let subject_oids = vec![
            "550406".to_string(),  // countryName
            "550403".to_string(),  // commonName
        ];

        let extensions = vec![
            "551d0f".to_string(),  // keyUsage
            "551d25".to_string(),  // extKeyUsage
            "551d11".to_string(),  // subjectAltName
        ];

        let ja4x = Ja4xFingerprint::from_x509(&issuer_oids, &subject_oids, &extensions);

        // Should have 3 parts separated by underscores
        assert_eq!(ja4x.fingerprint.matches('_').count(), 2);

        // Each hash should be 12 characters
        let parts: Vec<&str> = ja4x.fingerprint.split('_').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 12);
        assert_eq!(parts[1].len(), 12);
        assert_eq!(parts[2].len(), 12);

        // Verify raw format
        let raw = ja4x.raw();
        assert!(raw.contains("550406,55040a,550403"));
        assert!(raw.contains("551d0f,551d25,551d11"));
    }

    #[test]
    fn test_ja4x_oid_conversion() {
        // Test OID to hex conversion
        assert_eq!(Ja4xFingerprint::oid_to_hex("2.5.4.3"), "550403");
        assert_eq!(Ja4xFingerprint::oid_to_hex("2.5.4.6"), "550406");
        assert_eq!(Ja4xFingerprint::oid_to_hex("2.5.4.10"), "55040a");
        assert_eq!(Ja4xFingerprint::oid_to_hex("2.5.29.15"), "551d0f");

        // Invalid OID
        assert_eq!(Ja4xFingerprint::oid_to_hex("2"), "");
        assert_eq!(Ja4xFingerprint::oid_to_hex(""), "");
    }
}

