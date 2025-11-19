use crate::utils::structs::InnerMap;
use crate::http_proxy::proxyhttp::LB;
use async_trait::async_trait;
use std::sync::atomic::Ordering;
use log::debug;

#[async_trait]
pub trait GetHost {
    fn get_host(&self, peer: &str, path: &str, backend_id: Option<&str>) -> Option<InnerMap>;
    fn get_header(&self, peer: &str, path: &str) -> Option<Vec<(String, String)>>;
}
#[async_trait]
impl GetHost for LB {
    fn get_host(&self, peer: &str, path: &str, backend_id: Option<&str>) -> Option<InnerMap> {
        if let Some(b) = backend_id
            && let Some(bb) = self.ump_byid.get(b) {
            // println!("BIB :===> {:?}", Some(bb.value()));
            return Some(bb.value().clone());
        }

        // Check arxignis_paths first - these paths work regardless of hostname
        // Try exact match first
        if let Some(arxignis_path_entry) = self.arxignis_paths.get(path) {
            let (servers, index) = arxignis_path_entry.value();
            if !servers.is_empty() {
                let idx = index.fetch_add(1, Ordering::Relaxed) % servers.len();
                debug!("Using Gen0Sec path {} -> {}", path, servers[idx].address);
                return Some(servers[idx].clone());
            }
        }
        // If no exact match, try prefix/wildcard matching - check if any configured path is a prefix of the request path
        // Collect all matches and use the longest one (most specific match)
        let mut best_match: Option<(String, InnerMap, usize)> = None;
        for entry in self.arxignis_paths.iter() {
            let pattern = entry.key();
            // Handle wildcard patterns ending with /* - strip the /* for matching
            let (pattern_prefix, is_wildcard) = if pattern.ends_with("/*") {
                (pattern.strip_suffix("/*").unwrap_or(pattern.as_str()), true)
            } else {
                (pattern.as_str(), false)
            };

            // Check if the request path starts with the pattern prefix (prefix match)
            if path.starts_with(pattern_prefix) {
                // For wildcard patterns (ending with /*), match any path that starts with the prefix
                // For non-wildcard patterns, ensure it's a proper path segment match
                let is_valid_match = if is_wildcard {
                    // Wildcard pattern: match if path starts with prefix (already checked above)
                    true
                } else if pattern_prefix.ends_with('/') {
                    // Pattern ends with /, so it matches any path starting with it
                    true
                } else if path.len() == pattern_prefix.len() {
                    // Exact match (already handled above, but keep for completeness)
                    true
                } else if let Some(next_char) = path.chars().nth(pattern_prefix.len()) {
                    // Next character after prefix should be / for proper path segment match
                    next_char == '/'
                } else {
                    false
                };

                if is_valid_match {
                    let (servers, index) = entry.value();
                    if !servers.is_empty() {
                        let idx = index.fetch_add(1, Ordering::Relaxed) % servers.len();
                        let matched_server = servers[idx].clone();
                        let prefix_len = pattern_prefix.len();
                        // Keep the longest (most specific) match based on the prefix length
                        if best_match.as_ref().is_none_or(|(_, _, best_len)| prefix_len > *best_len) {
                            best_match = Some((pattern.clone(), matched_server, prefix_len));
                        }
                    }
                }
            }
        }
        if let Some((pattern, server, _)) = best_match {
            debug!("Using Gen0Sec path pattern {} -> {} (matched path: {})", pattern, server.address, path);
            return Some(server);
        }
        // If no prefix match, try progressively shorter paths (same logic as regular upstreams)
        let mut current_path = path.to_string();
        loop {
            if let Some(arxignis_path_entry) = self.arxignis_paths.get(&current_path) {
                let (servers, index) = arxignis_path_entry.value();
                if !servers.is_empty() {
                    let idx = index.fetch_add(1, Ordering::Relaxed) % servers.len();
                    debug!("Using Gen0Sec path {} -> {} (matched from {})", current_path, servers[idx].address, path);
                    return Some(servers[idx].clone());
                }
            }
            if let Some(pos) = current_path.rfind('/') {
                current_path.truncate(pos);
            } else {
                break;
            }
        }

        let host_entry = self.ump_upst.get(peer)?;
        let mut current_path = path.to_string();
        let mut best_match: Option<InnerMap> = None;
        loop {
            if let Some(entry) = host_entry.get(&current_path) {
                let (servers, index) = entry.value();
                if !servers.is_empty() {
                    let idx = index.fetch_add(1, Ordering::Relaxed) % servers.len();
                    best_match = Some(servers[idx].clone());
                    break;
                }
            }
            if let Some(pos) = current_path.rfind('/') {
                current_path.truncate(pos);
            } else {
                break;
            }
        }
        if best_match.is_none()
            && let Some(entry) = host_entry.get("/") {
            let (servers, index) = entry.value();
            if !servers.is_empty() {
                let idx = index.fetch_add(1, Ordering::Relaxed) % servers.len();
                best_match = Some(servers[idx].clone());
            }
        }
        // println!("Best Match :===> {:?}", best_match);
        best_match
    }
    fn get_header(&self, peer: &str, path: &str) -> Option<Vec<(String, String)>> {
        let host_entry = self.headers.get(peer)?;
        let mut current_path = path.to_string();
        let mut best_match: Option<Vec<(String, String)>> = None;
        loop {
            if let Some(entry) = host_entry.get(&current_path)
                && !entry.value().is_empty() {
                best_match = Some(entry.value().clone());
                break;
            }
            if let Some(pos) = current_path.rfind('/') {
                current_path.truncate(pos);
            } else {
                break;
            }
        }
        if best_match.is_none()
            && let Some(entry) = host_entry.get("/")
            && !entry.value().is_empty() {
            best_match = Some(entry.value().clone());
        }
        best_match
    }
}
