use crate::utils::discovery::{APIUpstreamProvider, Discovery, FromFileProvider};
use crate::utils::parceyaml::load_configuration;
use crate::utils::structs::Configuration;
use crate::utils::healthcheck;
use crate::http_proxy::proxyhttp::LB;
use async_trait::async_trait;
use dashmap::DashMap;
use futures::channel::mpsc;
use futures::{SinkExt, StreamExt};
use log::{error, info};
use pingora_core::server::ShutdownWatch;
use pingora_core::services::background::BackgroundService;
use std::sync::Arc;

#[async_trait]
impl BackgroundService for LB {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        info!("Starting Pingora background service for upstreams management");
        let (mut tx, mut rx) = mpsc::channel::<Configuration>(1);
        let tx_api = tx.clone();

        // Skip if no upstreams config file is provided (e.g., when using new config format)
        if self.config.upstreams_conf.is_empty() {
            info!("No upstreams config file specified, Pingora proxy system not initialized");
            return;
        }

        info!("Loading upstreams configuration from: {}", self.config.upstreams_conf);
        let config = match load_configuration(self.config.upstreams_conf.clone().as_str(), "filepath").await {
            Some(cfg) => {
                info!("Upstreams configuration loaded successfully");
                cfg
            },
            None => {
                error!("Failed to load upstreams configuration from: {}", self.config.upstreams_conf);
                return;
            }
        };

        match config.typecfg.as_str() {
            "file" => {
                info!("Running File discovery, requested type is: {}", config.typecfg);
                tx.send(config).await.unwrap();
                let file_load = FromFileProvider {
                    path: self.config.upstreams_conf.clone(),
                };
                let _ = tokio::spawn(async move { file_load.start(tx).await });
            }
            _ => {
                error!("Unknown discovery type: {}", config.typecfg);
            }
        }

        let api_load = APIUpstreamProvider {
            address: self.config.config_address.clone(),
            masterkey: self.config.master_key.clone(),
            config_api_enabled: self.config.config_api_enabled.clone(),
            tls_address: self.config.config_tls_address.clone(),
            tls_certificate: self.config.config_tls_certificate.clone(),
            tls_key_file: self.config.config_tls_key_file.clone(),
            file_server_address: self.config.file_server_address.clone(),
            file_server_folder: self.config.file_server_folder.clone(),
        };
        let _ = tokio::spawn(async move { api_load.start(tx_api).await });

        // Use AppConfig values as defaults
        let (default_healthcheck_method, default_healthcheck_interval) = (self.config.healthcheck_method.clone(), self.config.healthcheck_interval);
        let mut healthcheck_method = default_healthcheck_method.clone();
        let mut healthcheck_interval = default_healthcheck_interval;
        let mut healthcheck_started = false;

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    break;
                }
                val = rx.next() => {
                    match val {
                        Some(ss) => {
                            // Update healthcheck settings from upstreams config if available
                            if let Some(interval) = ss.healthcheck_interval {
                                healthcheck_interval = interval;
                            }
                            if let Some(method) = &ss.healthcheck_method {
                                healthcheck_method = method.clone();
                            }

                            // Start healthcheck on first config load
                            if !healthcheck_started {
                                let uu_clone = self.ump_upst.clone();
                                let ff_clone = self.ump_full.clone();
                                let im_clone = self.ump_byid.clone();
                                let method_clone = healthcheck_method.clone();
                                let interval_clone = healthcheck_interval;
                                let _ = tokio::spawn(async move {
                                    healthcheck::hc2(uu_clone, ff_clone, im_clone, (&*method_clone.to_string(), interval_clone.to_string().parse().unwrap())).await
                                });
                                healthcheck_started = true;
                            }

                            // Update arxignis_paths (global paths that work across all hostnames)
                            self.arxignis_paths.clear();
                            for entry in ss.arxignis_paths.iter() {
                                let (servers, counter) = entry.value();
                                let new_counter = std::sync::atomic::AtomicUsize::new(counter.load(std::sync::atomic::Ordering::Relaxed));
                                self.arxignis_paths.insert(entry.key().clone(), (servers.clone(), new_counter));
                            }

                            crate::utils::tools::clone_dashmap_into(&ss.upstreams, &self.ump_full);
                            crate::utils::tools::clone_dashmap_into(&ss.upstreams, &self.ump_upst);
                            let current = self.extraparams.load_full();
                            let mut new = (*current).clone();
                            new.sticky_sessions = ss.extraparams.sticky_sessions;
                            new.https_proxy_enabled = ss.extraparams.https_proxy_enabled;
                            new.authentication = ss.extraparams.authentication.clone();
                            new.rate_limit = ss.extraparams.rate_limit;
                            self.extraparams.store(Arc::new(new));
                            self.headers.clear();

                            for entry in ss.upstreams.iter() {
                                let global_key = entry.key().clone();
                                let global_values = DashMap::new();
                                let mut target_entry = ss.headers.entry(global_key).or_insert_with(DashMap::new);
                                target_entry.extend(global_values);
                                self.headers.insert(target_entry.key().to_owned(), target_entry.value().to_owned());
                            }

                            for path in ss.headers.iter() {
                                let path_key = path.key().clone();
                                let path_headers = path.value().clone();
                                self.headers.insert(path_key.clone(), path_headers);
                                if let Some(global_headers) = ss.headers.get("GLOBAL_HEADERS") {
                                    if let Some(existing_headers) = self.headers.get(&path_key) {
                                        crate::utils::tools::merge_headers(existing_headers.value(), &global_headers);
                                    }
                                }
                            }

                            // Update upstreams certificate mappings
                            if let Some(certs_arc) = &self.certificates {
                                if let Some(certs) = certs_arc.load().as_ref() {
                                    certs.set_upstreams_cert_map(ss.certificates.clone());
                                    info!("Updated upstreams certificate mappings: {} entries", ss.certificates.len());
                                }
                            }
                            // info!("Upstreams list is changed, updating to:");
                            // print_upstreams(&self.ump_full);
                        }
                        None => {}
                    }
                }
            }
        }
    }
}
