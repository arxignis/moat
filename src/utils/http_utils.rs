use std::net::IpAddr;

/// Parse IP or CIDR notation into network and prefix length
pub fn parse_ip_or_cidr(entry: &str) -> Option<(IpAddr, u8)> {
    let s = entry.trim();
    if s.is_empty() {
        return None;
    }

    if s.contains('/') {
        let mut parts = s.split('/');
        let ip_str = parts.next()?.trim();
        let prefix_str = parts.next()?.trim();
        if parts.next().is_some() {
            return None; // malformed
        }

        let ip = ip_str.parse::<IpAddr>().ok()?;
        let prefix: u8 = prefix_str.parse().ok()?;

        // Validate prefix length
        match ip {
            IpAddr::V4(_) => {
                if prefix > 32 {
                    return None;
                }
            }
            IpAddr::V6(_) => {
                if prefix > 128 {
                    return None;
                }
            }
        }

        Some((ip, prefix))
    } else {
        // Single IP address
        let ip = s.parse::<IpAddr>().ok()?;
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Some((ip, prefix))
    }
}

/// Check if an IP address is within a CIDR range
pub fn is_ip_in_cidr(ip: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => {
            let ip_u32 = u32::from(ip);
            let net_u32 = u32::from(network);
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX.checked_shl((32 - prefix_len) as u32).unwrap_or(0)
            };
            (ip_u32 & mask) == (net_u32 & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) => {
            let ip_bytes = ip.octets();
            let net_bytes = network.octets();
            let prefix_bytes = prefix_len / 8;
            let remaining_bits = prefix_len % 8;

            // Check full bytes
            for i in 0..prefix_bytes as usize {
                if ip_bytes[i] != net_bytes[i] {
                    return false;
                }
            }

            // Check remaining bits
            if remaining_bits > 0 && prefix_bytes < 16 {
                let mask = 0xFF << (8 - remaining_bits);
                if (ip_bytes[prefix_bytes as usize] & mask) != (net_bytes[prefix_bytes as usize] & mask) {
                    return false;
                }
            }

            true
        }
        _ => false, // Different IP versions
    }
}

