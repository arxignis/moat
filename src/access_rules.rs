use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::select;
use tokio::task::JoinHandle;
use tokio::time::{Duration, MissedTickBehavior, interval};

use crate::bpf;
use crate::config;
use crate::config::{fetch_config, global_config};
use crate::wirefilter::update_http_filter_from_config_value;
use crate::firewall::{Firewall, MOATFirewall};
use crate::utils::http_utils::{parse_ip_or_cidr, is_ip_in_cidr};

// Store previous rules state for comparison
type PreviousRules = Arc<Mutex<HashSet<(Ipv4Addr, u32)>>>;
type PreviousRulesV6 = Arc<Mutex<HashSet<(Ipv6Addr, u32)>>>;

/// Start a background task that fetches access rules every 10 seconds and
/// applies them to the `banned_ips` BPF map in the provided skeleton.
///
/// Contract:
/// - Inputs: `banned_ip_map` is the BPF LPM_TRIE for banned IPv4s (key = lpm_key, value = u8 flag)
///   `api_key` is the ArxIgnis API key
///   `shutdown` is a watch receiver that signals graceful shutdown when set to true
/// - Behavior: Runs immediately, then every 10s; on fetch error, logs and continues
/// - Returns: JoinHandle for the spawned task
pub fn start_access_rules_updater(
    base_url: String,
    skels: Vec<Arc<bpf::FilterSkel<'static>>>,
    api_key: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> JoinHandle<()> {
    // Initialize previous rules state
    let previous_rules = Arc::new(Mutex::new(HashSet::new()));
    let previous_rules_v6 = Arc::new(Mutex::new(HashSet::new()));
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        if let Err(e) = fetch_and_apply(base_url.clone(), api_key.clone(), &skels, &previous_rules, &previous_rules_v6).await {
            log::error!("initial access rules update failed: {e}");
        }

        loop {
            select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { break; }
                }
                _ = ticker.tick() => {
                    if let Err(e) = fetch_and_apply(base_url.clone(), api_key.clone(), &skels, &previous_rules, &previous_rules_v6).await {
                        log::error!("periodic access rules update failed: {e}");
                    }
                }
            }
        }
    })
}

/// Apply access rules once using the current global config snapshot
pub fn init_access_rules_from_global(
    skels: &Vec<Arc<bpf::FilterSkel<'static>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if skels.is_empty() {
        return Ok(());
    }
    if let Ok(guard) = global_config().read() {
        if let Some(cfg) = guard.as_ref() {
            let previous_rules: PreviousRules = Arc::new(Mutex::new(std::collections::HashSet::new()));
            let previous_rules_v6: PreviousRulesV6 = Arc::new(Mutex::new(std::collections::HashSet::new()));
            let resp = config::ConfigApiResponse { success: true, config: cfg.clone() };
            apply_rules(skels, &resp, &previous_rules, &previous_rules_v6)?;
        }
    }
    Ok(())
}

async fn fetch_and_apply(
    base_url: String,
    api_key: String,
    skels: &Vec<Arc<bpf::FilterSkel<'static>>>,
    previous_rules: &PreviousRules,
    previous_rules_v6: &PreviousRulesV6,
) -> Result<(), Box<dyn std::error::Error>> {
    // Refresh global config from API
    let _ = fetch_config(base_url, api_key).await;

    // Read from global config and apply if available
    if let Ok(guard) = global_config().read() {
        if let Some(cfg) = guard.as_ref() {
            // Update WAF wirefilter when config changes
            if let Err(e) = update_http_filter_from_config_value(cfg) {
                log::error!("failed to update HTTP filter from config: {e}");
            }
            if skels.is_empty() {
                return Ok(());
            }
            apply_rules(
                skels,
                &config::ConfigApiResponse { success: true, config: cfg.clone() },
                previous_rules,
                previous_rules_v6,
            )?;
            return Ok(());
        }
    }
    Ok(())
}

fn apply_rules(
    skels: &Vec<Arc<bpf::FilterSkel<'_>>>,
    resp: &config::ConfigApiResponse,
    previous_rules: &PreviousRules,
    previous_rules_v6: &PreviousRulesV6,
) -> Result<(), Box<dyn std::error::Error>> {
    fn parse_ipv4_ip_or_cidr(entry: &str) -> Option<(Ipv4Addr, u32)> {
        let s = entry.trim();
        if s.is_empty() {
            return None;
        }
        if s.contains(':') {
            // IPv6 not supported by IPv4 map
            return None;
        }
        if !s.contains('/') {
            return Ipv4Addr::from_str(s).ok().map(|ip| (ip, 32));
        }
        let mut parts = s.split('/');
        let ip_str = parts.next()?.trim();
        let prefix_str = parts.next()?.trim();
        if parts.next().is_some() {
            // malformed
            return None;
        }
        let ip = Ipv4Addr::from_str(ip_str).ok()?;
        let prefix: u32 = prefix_str.parse::<u8>().ok()? as u32;
        if prefix > 32 {
            return None;
        }
        let ip_u32 = u32::from(ip);
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX.checked_shl(32 - prefix).unwrap_or(0)
        };
        let net = Ipv4Addr::from(ip_u32 & mask);
        Some((net, prefix))
    }

    // Helper: parse IPv6 or IPv6/CIDR into (network, prefix)
    fn parse_ipv6_ip_or_cidr(entry: &str) -> Option<(Ipv6Addr, u32)> {
        let s = entry.trim();
        if s.is_empty() {
            return None;
        }
        if !s.contains(':') {
            // IPv4 not supported by IPv6 map
            return None;
        }
        if !s.contains('/') {
            return Ipv6Addr::from_str(s).ok().map(|ip| (ip, 128));
        }
        let mut parts = s.split('/');
        let ip_str = parts.next()?.trim();
        let prefix_str = parts.next()?.trim();
        if parts.next().is_some() {
            // malformed
            return None;
        }
        let ip = Ipv6Addr::from_str(ip_str).ok()?;
        let prefix: u32 = prefix_str.parse::<u8>().ok()? as u32;
        if prefix > 128 {
            return None;
        }
        Some((ip, prefix))
    }

    let mut current_rules: HashSet<(Ipv4Addr, u32)> = HashSet::new();
    let mut current_rules_v6: HashSet<(Ipv6Addr, u32)> = HashSet::new();

    let rule = &resp.config.access_rules;

    // Parse block.ips
    for ip_str in &rule.block.ips {
        if ip_str.contains(':') {
            // IPv6 address
            if let Some((net, prefix)) = parse_ipv6_ip_or_cidr(ip_str) {
                current_rules_v6.insert((net, prefix));
            } else {
                log::warn!("invalid IPv6 ip/cidr ignored: {}", ip_str);
            }
        } else {
            // IPv4 address
            if let Some((net, prefix)) = parse_ipv4_ip_or_cidr(ip_str) {
                current_rules.insert((net, prefix));
            } else {
                log::warn!("invalid IPv4 ip/cidr ignored: {}", ip_str);
            }
        }
    }

    // Parse block.country values
    for country_map in &rule.block.country {
        for (_cc, list) in country_map.iter() {
            for ip_str in list {
                if ip_str.contains(':') {
                    // IPv6 address
                    if let Some((net, prefix)) = parse_ipv6_ip_or_cidr(ip_str) {
                        current_rules_v6.insert((net, prefix));
                    } else {
                        log::warn!("invalid IPv6 ip/cidr ignored: {}", ip_str);
                    }
                } else {
                    // IPv4 address
                    if let Some((net, prefix)) = parse_ipv4_ip_or_cidr(ip_str) {
                        current_rules.insert((net, prefix));
                    } else {
                        log::warn!("invalid IPv4 ip/cidr ignored: {}", ip_str);
                    }
                }
            }
        }
    }

    // Parse block.asn values
    for asn_map in &rule.block.asn {
        for (_asn, list) in asn_map.iter() {
            for ip_str in list {
                if ip_str.contains(':') {
                    // IPv6 address
                    if let Some((net, prefix)) = parse_ipv6_ip_or_cidr(ip_str) {
                        current_rules_v6.insert((net, prefix));
                    } else {
                        log::warn!("invalid IPv6 ip/cidr ignored: {}", ip_str);
                    }
                } else {
                    // IPv4 address
                    if let Some((net, prefix)) = parse_ipv4_ip_or_cidr(ip_str) {
                        current_rules.insert((net, prefix));
                    } else {
                        log::warn!("invalid IPv4 ip/cidr ignored: {}", ip_str);
                    }
                }
            }
        }
    }

    // Compare with previous rules to detect changes
    let mut previous_rules_guard = previous_rules.lock().unwrap();
    let mut previous_rules_v6_guard = previous_rules_v6.lock().unwrap();

    // Check if rules have changed
    let ipv4_changed = *previous_rules_guard != current_rules;
    let ipv6_changed = *previous_rules_v6_guard != current_rules_v6;

    // If neither family changed, skip quietly with a single log entry
    if !ipv4_changed && !ipv6_changed {
        log::debug!("No IPv4 or IPv6 access rule changes detected, skipping BPF map updates");
        return Ok(());
    }

    log::info!("Access rules changed, applying updates to BPF maps");

    // Compute diffs once against snapshots
    let prev_v4_snapshot = previous_rules_guard.clone();
    let prev_v6_snapshot = previous_rules_v6_guard.clone();
    let removed_v4: Vec<(Ipv4Addr, u32)> = prev_v4_snapshot.difference(&current_rules).cloned().collect();
    let added_v4: Vec<(Ipv4Addr, u32)> = current_rules.difference(&prev_v4_snapshot).cloned().collect();
    let removed_v6: Vec<(Ipv6Addr, u32)> = prev_v6_snapshot.difference(&current_rules_v6).cloned().collect();
    let added_v6: Vec<(Ipv6Addr, u32)> = current_rules_v6.difference(&prev_v6_snapshot).cloned().collect();

    // Apply to all BPF skeletons
    for s in skels.iter() {
        let mut fw = MOATFirewall::new(s);
        if ipv4_changed {
            for (net, prefix) in &removed_v4 {
                if let Err(e) = fw.unban_ip(*net, *prefix) {
                    log::error!("IPv4 unban failed for {}/{}: {}", net, prefix, e);
                }
            }
            for (net, prefix) in &added_v4 {
                if let Err(e) = fw.ban_ip(*net, *prefix) {
                    log::error!("IPv4 ban failed for {}/{}: {}", net, prefix, e);
                }
            }
        }
        if ipv6_changed {
            for (net, prefix) in &removed_v6 {
                if let Err(e) = fw.unban_ipv6(*net, *prefix) {
                    log::error!("IPv6 unban failed for {}/{}: {}", net, prefix, e);
                }
            }
            for (net, prefix) in &added_v6 {
                if let Err(e) = fw.ban_ipv6(*net, *prefix) {
                    log::error!("IPv6 ban failed for {}/{}: {}", net, prefix, e);
                }
            }
        }
    }

    // Update previous snapshots once after applying to all skels
    if ipv4_changed { *previous_rules_guard = current_rules; }
    if ipv6_changed { *previous_rules_v6_guard = current_rules_v6; }

    Ok(())
}

/// Check if an IP address is allowed by access rules
/// Returns true if the IP is explicitly allowed, false otherwise
pub fn is_ip_allowed_by_access_rules(ip: IpAddr) -> bool {
    if let Ok(guard) = global_config().read() {
        if let Some(cfg) = guard.as_ref() {
            let allow_rules = &cfg.access_rules.allow;

            // Check direct IP matches
            for ip_str in &allow_rules.ips {
                if let Ok(allowed_ip) = ip_str.parse::<IpAddr>() {
                    if ip == allowed_ip {
                        return true;
                    }
                }

                // Check CIDR ranges
                if let Some((network, prefix_len)) = parse_ip_or_cidr(ip_str) {
                    if is_ip_in_cidr(ip, network, prefix_len) {
                        return true;
                    }
                }
            }

            // Check country-based allow rules
            for country_map in &allow_rules.country {
                for (_country_code, ip_list) in country_map.iter() {
                    for ip_str in ip_list {
                        if let Some((network, prefix_len)) = parse_ip_or_cidr(ip_str) {
                            if is_ip_in_cidr(ip, network, prefix_len) {
                                return true;
                            }
                        }
                    }
                }
            }

            // Check ASN-based allow rules
            for asn_map in &allow_rules.asn {
                for (_asn, ip_list) in asn_map.iter() {
                    for ip_str in ip_list {
                        if let Some((network, prefix_len)) = parse_ip_or_cidr(ip_str) {
                            if is_ip_in_cidr(ip, network, prefix_len) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}
