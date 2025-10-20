use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::select;
use tokio::task::JoinHandle;
use tokio::time::{Duration, MissedTickBehavior, interval};

use crate::bpf;
use crate::config;
use crate::firewall::{Firewall, MOATFirewall};

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
    skel: Option<Arc<bpf::FilterSkel<'static>>>,
    api_key: String,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> JoinHandle<()> {
    // Initialize previous rules state
    let previous_rules = Arc::new(Mutex::new(HashSet::new()));
    let previous_rules_v6 = Arc::new(Mutex::new(HashSet::new()));
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

        if let Err(e) = fetch_and_apply(base_url.clone(), api_key.clone(), skel.as_ref(), &previous_rules, &previous_rules_v6).await {
            eprintln!("initial access rules update failed: {e}");
        }

        loop {
            select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { break; }
                }
                _ = ticker.tick() => {
                    if let Err(e) = fetch_and_apply(base_url.clone(), api_key.clone(), skel.as_ref(), &previous_rules, &previous_rules_v6).await {
                        eprintln!("periodic access rules update failed: {e}");
                    }
                }
            }
        }
    })
}

async fn fetch_and_apply(
    base_url: String,
    api_key: String,
    skel: Option<&Arc<bpf::FilterSkel<'static>>>,
    previous_rules: &PreviousRules,
    previous_rules_v6: &PreviousRulesV6,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = config::fetch_config(base_url.clone(), api_key.clone()).await?;
    if let Some(s) = skel {
        apply_rules_to_skel(s, &resp, previous_rules, previous_rules_v6)?;
    }
    Ok(())
}

fn apply_rules_to_skel(
    skel: &bpf::FilterSkel<'_>,
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
                eprintln!("invalid IPv6 ip/cidr ignored: {}", ip_str);
            }
        } else {
            // IPv4 address
            if let Some((net, prefix)) = parse_ipv4_ip_or_cidr(ip_str) {
                current_rules.insert((net, prefix));
            } else {
                eprintln!("invalid IPv4 ip/cidr ignored: {}", ip_str);
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
                        eprintln!("invalid IPv6 ip/cidr ignored: {}", ip_str);
                    }
                } else {
                    // IPv4 address
                    if let Some((net, prefix)) = parse_ipv4_ip_or_cidr(ip_str) {
                        current_rules.insert((net, prefix));
                    } else {
                        eprintln!("invalid IPv4 ip/cidr ignored: {}", ip_str);
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
                        eprintln!("invalid IPv6 ip/cidr ignored: {}", ip_str);
                    }
                } else {
                    // IPv4 address
                    if let Some((net, prefix)) = parse_ipv4_ip_or_cidr(ip_str) {
                        current_rules.insert((net, prefix));
                    } else {
                        eprintln!("invalid IPv4 ip/cidr ignored: {}", ip_str);
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

    if !ipv4_changed && !ipv6_changed {
        println!("No changes detected, skipping BPF map updates");
        return Ok(());
    }

    println!("Rules changed, applying updates to BPF maps");

    let mut fw = MOATFirewall::new(skel);

    if ipv4_changed {
        // Remove old IPv4 rules that are no longer needed
        for (net, prefix) in previous_rules_guard.difference(&current_rules) {
            if let Err(e) = fw.unban_ip(*net, *prefix) {
                eprintln!("IPv4 unban failed for {}/{}: {}", net, prefix, e);
            }
        }

        // Add new IPv4 rules
        for (net, prefix) in current_rules.difference(&*previous_rules_guard) {
            if let Err(e) = fw.ban_ip(*net, *prefix) {
                eprintln!("IPv4 ban failed for {}/{}: {}", net, prefix, e);
            }
        }

        // Update previous rules
        *previous_rules_guard = current_rules;
    }

    if ipv6_changed {
        // Remove old IPv6 rules that are no longer needed
        for (net, prefix) in previous_rules_v6_guard.difference(&current_rules_v6) {
            if let Err(e) = fw.unban_ipv6(*net, *prefix) {
                eprintln!("IPv6 unban failed for {}/{}: {}", net, prefix, e);
            }
        }

        // Add new IPv6 rules
        for (net, prefix) in current_rules_v6.difference(&*previous_rules_v6_guard) {
            if let Err(e) = fw.ban_ipv6(*net, *prefix) {
                eprintln!("IPv6 ban failed for {}/{}: {}", net, prefix, e);
            }
        }

        // Update previous rules
        *previous_rules_v6_guard = current_rules_v6;
    }

    Ok(())
}
