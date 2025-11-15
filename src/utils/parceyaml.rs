use crate::utils::healthcheck;
use crate::utils::state::{is_first_run, mark_not_first_run};
use crate::utils::structs::*;
use crate::utils::tools::{clone_dashmap, clone_dashmap_into, print_upstreams};
use dashmap::DashMap;
use log::{error, info, warn};
use std::sync::atomic::AtomicUsize;
// use std::sync::mpsc::{channel, Receiver, Sender};
use std::{env, fs};
// use tokio::sync::oneshot::{Receiver, Sender};

pub async fn load_configuration(d: &str, kind: &str) -> Option<Configuration> {
    let yaml_data = match kind {
        "filepath" => match fs::read_to_string(d) {
            Ok(data) => {
                info!("Reading upstreams from {}", d);
                data
            }
            Err(e) => {
                error!("Reading: {}: {:?}", d, e);
                warn!("Running with empty upstreams list, update it via API");
                return None;
            }
        },
        "content" => {
            info!("Reading upstreams from API post body");
            d.to_string()
        }
        _ => {
            error!("Mismatched parameter, only filepath|content is allowed");
            return None;
        }
    };

    let parsed: Config = match serde_yaml::from_str(&yaml_data) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to parse upstreams file: {}", e);
            return None;
        }
    };

    let mut toreturn = Configuration::default();

    populate_headers_and_auth(&mut toreturn, &parsed).await;
    toreturn.typecfg = parsed.provider.clone();

    match parsed.provider.as_str() {
        "file" => {
            populate_file_upstreams(&mut toreturn, &parsed).await;
            Some(toreturn)
        }
        "consul" => {
            toreturn.consul = parsed.consul;
            toreturn.consul.is_some().then_some(toreturn)
        }
        "kubernetes" => {
            toreturn.kubernetes = parsed.kubernetes;
            toreturn.kubernetes.is_some().then_some(toreturn)
        }
        _ => {
            warn!("Unknown provider {}", parsed.provider);
            None
        }
    }
}

async fn populate_headers_and_auth(config: &mut Configuration, parsed: &Config) {
    // Handle new config format with nested config: section
    if let Some(global_config) = &parsed.config {
        // Use values from config: section if present
        config.extraparams.sticky_sessions = global_config.sticky_sessions;
        config.extraparams.https_proxy_enabled = Some(global_config.https_proxy_enabled);
        config.extraparams.rate_limit = global_config.global_rate_limit;

        if let Some(headers) = &global_config.global_headers {
            let mut hl = Vec::new();
            for header in headers {
                if let Some((key, val)) = header.split_once(':') {
                    hl.push((key.trim().to_string(), val.trim().to_string()));
                }
            }

            let global_headers = DashMap::new();
            global_headers.insert("/".to_string(), hl);
            config.headers.insert("GLOBAL_HEADERS".to_string(), global_headers);
        }

        if let Some(rate) = &global_config.global_rate_limit {
            info!("Applied Global Rate Limit : {} request per second", rate);
        }

        // Store healthcheck settings from upstreams config
        config.healthcheck_interval = global_config.healthcheck_interval;
        config.healthcheck_method = global_config.healthcheck_method.clone();
    } else {
        // Fallback to old format (top-level fields)
        if let Some(headers) = &parsed.headers {
            let mut hl = Vec::new();
            for header in headers {
                if let Some((key, val)) = header.split_once(':') {
                    hl.push((key.trim().to_string(), val.trim().to_string()));
                }
            }

            let global_headers = DashMap::new();
            global_headers.insert("/".to_string(), hl);
            config.headers.insert("GLOBAL_HEADERS".to_string(), global_headers);
        }

        config.extraparams.sticky_sessions = parsed.sticky_sessions;
        config.extraparams.https_proxy_enabled = None; // Legacy format doesn't have this
        config.extraparams.rate_limit = parsed.rate_limit;

        if let Some(rate) = &parsed.rate_limit {
            info!("Applied Global Rate Limit : {} request per second", rate);
        }
    }

    if let Some(auth) = &parsed.authorization {
        let name = auth.get("type").unwrap_or(&"".to_string()).to_string();
        let creds = auth.get("creds").unwrap_or(&"".to_string()).to_string();
        config.extraparams.authentication.insert("authorization".to_string(), vec![name, creds]);
    } else {
        config.extraparams.authentication = DashMap::new();
    }
}

async fn populate_file_upstreams(config: &mut Configuration, parsed: &Config) {
    // Handle arxignis_paths first - these are global paths that work across all hostnames
    if let Some(arxignis_paths) = &parsed.arxignis_paths {
        info!("Processing {} Gen0Sec paths", arxignis_paths.len());
        for (path, path_config) in arxignis_paths {
            let mut server_list = Vec::new();
            for server in &path_config.servers {
                if let Some((ip, port_str)) = server.split_once(':') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        let https_proxy_enabled = path_config.https_proxy_enabled.unwrap_or(false);
                        let ssl_enabled = path_config.ssl_enabled.unwrap_or(true);
                        let http2_enabled = path_config.http2_enabled.unwrap_or(false);
                        server_list.push(InnerMap {
                            address: ip.trim().to_string(),
                            port,
                            ssl_enabled,
                            http2_enabled,
                            https_proxy_enabled,
                            rate_limit: path_config.rate_limit,
                            healthcheck: path_config.healthcheck,
                        });
                    }
                }
            }
            config.arxignis_paths.insert(path.clone(), (server_list, AtomicUsize::new(0)));
            info!("Gen0Sec path {} -> {} backend(s)", path, config.arxignis_paths.get(path).unwrap().0.len());
        }
    }

    let imtdashmap = UpstreamsDashMap::new();
    if let Some(upstreams) = &parsed.upstreams {
        for (hostname, host_config) in upstreams {
            // Store certificate mapping if specified
            if let Some(certificate_name) = &host_config.certificate {
                config.certificates.insert(hostname.clone(), certificate_name.clone());
                info!("Upstream {} will use certificate: {}", hostname, certificate_name);
            }

            let path_map = DashMap::new();
            let header_list = DashMap::new();
            for (path, path_config) in &host_config.paths {
                if let Some(rate) = &path_config.rate_limit {
                    info!("Applied Rate Limit for {} : {} request per second", hostname, rate);
                }

                let mut hl: Vec<(String, String)> = Vec::new();
                build_headers(&path_config.headers, config, &mut hl);
                header_list.insert(path.clone(), hl);

                let mut server_list = Vec::new();
                for server in &path_config.servers {
                    if let Some((ip, port_str)) = server.split_once(':') {
                        if let Ok(port) = port_str.parse::<u16>() {
                            let https_proxy_enabled = path_config.https_proxy_enabled.unwrap_or(false);
                            let ssl_enabled = path_config.ssl_enabled.unwrap_or(true); // Default to SSL
                            let http2_enabled = path_config.http2_enabled.unwrap_or(false); // Default to HTTP/1.1
                            server_list.push(InnerMap {
                                address: ip.trim().to_string(),
                                port,
                                ssl_enabled,
                                http2_enabled,
                                https_proxy_enabled,
                                rate_limit: path_config.rate_limit,
                                healthcheck: path_config.healthcheck,
                            });
                        }
                    }
                }
                path_map.insert(path.clone(), (server_list, AtomicUsize::new(0)));
            }
            config.headers.insert(hostname.clone(), header_list);
            imtdashmap.insert(hostname.clone(), path_map);
        }

        if is_first_run() {
            clone_dashmap_into(&imtdashmap, &config.upstreams);
            mark_not_first_run();
        } else {
            let y = clone_dashmap(&imtdashmap);
            let r = healthcheck::initiate_upstreams(y).await;
            clone_dashmap_into(&r, &config.upstreams);
        }
        info!("Upstream Config:");
        print_upstreams(&config.upstreams);
    }
}
pub fn parce_main_config(path: &str) -> AppConfig {
    parce_main_config_with_log_level(path, None)
}

pub fn parce_main_config_with_log_level(path: &str, log_level: Option<&str>) -> AppConfig {
    let data = fs::read_to_string(path).unwrap();
    let mut cfo: AppConfig = serde_yaml::from_str(&*data).expect("Failed to parse main config file");
    log_builder(log_level);
    cfo.healthcheck_method = cfo.healthcheck_method.to_uppercase();
    if let Some((ip, port_str)) = cfo.config_address.split_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            cfo.local_server = Option::from((ip.to_string(), port));
        }
    }
    if let Some(tlsport_cfg) = cfo.proxy_address_tls.clone() {
        if let Some((_, port_str)) = tlsport_cfg.split_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                cfo.proxy_port_tls = Some(port);
            }
        }
    };
    cfo.proxy_tls_grade = parce_tls_grades(cfo.proxy_tls_grade.clone());
    cfo
}

fn parce_tls_grades(what: Option<String>) -> Option<String> {
    match what {
        Some(g) => match g.to_ascii_lowercase().as_str() {
            "high" => {
                // info!("TLS grade set to: [ HIGH ]");
                Some("high".to_string())
            }
            "medium" => {
                // info!("TLS grade set to: [ MEDIUM ]");
                Some("medium".to_string())
            }
            "unsafe" => {
                // info!("TLS grade set to: [ UNSAFE ]");
                Some("unsafe".to_string())
            }
            _ => {
                warn!("Error parsing TLS grade, defaulting to: `medium`");
                Some("medium".to_string())
            }
        },
        None => {
            warn!("TLS grade not set, defaulting to: medium");
            Some("b".to_string())
        }
    }
}

fn log_builder(log_level: Option<&str>) {
    // Use provided log level, or fall back to RUST_LOG env var, or default to "info"
    let log_level = log_level
        .map(|s| s.to_string())
        .or_else(|| std::env::var("RUST_LOG").ok())
        .unwrap_or_else(|| "info".to_string());
    unsafe {
        match log_level.as_str() {
            "info" => env::set_var("RUST_LOG", "info"),
            "error" => env::set_var("RUST_LOG", "error"),
            "warn" => env::set_var("RUST_LOG", "warn"),
            "debug" => env::set_var("RUST_LOG", "debug"),
            "trace" => env::set_var("RUST_LOG", "trace"),
            "off" => env::set_var("RUST_LOG", "off"),
            _ => {
                println!("Error reading log level, defaulting to: INFO");
                env::set_var("RUST_LOG", "info")
            }
        }
    }
    // Use try_init() to avoid panic if logger is already initialized (e.g., from main.rs)
    let _ = env_logger::builder().try_init();
}

pub fn build_headers(path_config: &Option<Vec<String>>, config: &Configuration, hl: &mut Vec<(String, String)>) {
    if let Some(headers) = &path_config {
        for header in headers {
            if let Some((key, val)) = header.split_once(':') {
                hl.push((key.trim().to_string(), val.trim().to_string()));
            }
        }
        if let Some(push) = config.headers.get("GLOBAL_HEADERS") {
            for k in push.iter() {
                for x in k.value() {
                    hl.push(x.to_owned());
                }
            }
        }
    }
}
