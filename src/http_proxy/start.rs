// use rustls::crypto::ring::default_provider;
use crate::http_proxy::proxyhttp::LB;
use crate::utils::structs::Extraparams;
use crate::utils::tls;
use crate::utils::tls::CertificateConfig;

use arc_swap::ArcSwap;
use ctrlc;
use dashmap::DashMap;
use log::{debug, info, warn};
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::prelude::{background_service, Opt};
use pingora_core::server::Server;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;

pub fn run() {
    run_with_config(None)
}

pub fn run_with_config(config: Option<crate::cli::Config>) {
    // default_provider().install_default().expect("Failed to install rustls crypto provider");
    let maincfg = if let Some(cfg) = config {
        cfg.pingora.to_app_config()
    } else {
        // Fallback to old parsing method for backward compatibility
        let parameters = Some(Opt::parse_args()).unwrap();
        let file = parameters.conf.clone().unwrap();
        crate::utils::parceyaml::parce_main_config(file.as_str())
    };

    // Skip old proxy system if no proxy addresses are configured (using new config format)
    if maincfg.proxy_address_http.is_empty() {
        info!("Pingora proxy system disabled (no proxy_address_http configured)");
        info!(
            "Using new HTTP server on: {}:{}",
            maincfg.proxy_address_http,
            maincfg.proxy_port_tls.unwrap_or(443)
        );
        return;
    }

    info!(
        "Starting Pingora proxy system on HTTP: {}",
        maincfg.proxy_address_http
    );
    if let Some(ref tls_addr) = maincfg.proxy_address_tls {
        info!("Pingora proxy TLS enabled on: {}", tls_addr);
    }

    // Pass None to avoid pingora parsing the config file (we use our own parser above)
    let mut server = Server::new(None).unwrap();
    
    // Use proxy_protocol_enabled from config
    if maincfg.proxy_protocol_enabled {
        info!("PROXY protocol support enabled - Pingora will parse headers before HTTP/TLS");
        // Enable PROXY protocol globally in Pingora
        pingora_core::protocols::proxy_protocol::set_proxy_protocol_enabled(true);
    }
    
    server.bootstrap();

    let uf_config = Arc::new(DashMap::new());
    let ff_config = Arc::new(DashMap::new());
    let im_config = Arc::new(DashMap::new());
    let hh_config = Arc::new(DashMap::new());
    let ap_config = Arc::new(DashMap::new());

    let ec_config = Arc::new(ArcSwap::from_pointee(Extraparams {
        sticky_sessions: false,
        https_proxy_enabled: None,
        authentication: DashMap::new(),
        rate_limit: None,
    }));

    let cfg = Arc::new(maincfg);

    let certificates_arc: Arc<ArcSwap<Option<Arc<tls::Certificates>>>> =
        Arc::new(ArcSwap::from_pointee(None));

    let lb = LB {
        ump_upst: uf_config,
        ump_full: ff_config,
        ump_byid: im_config,
        arxignis_paths: ap_config,
        config: cfg.clone(),
        headers: hh_config,
        extraparams: ec_config,
        tcp_fingerprint_collector: None, // TODO: Pass from main.rs if available
        certificates: Some(certificates_arc.clone()),
    };

    let grade = cfg
        .proxy_tls_grade
        .clone()
        .unwrap_or_else(|| "medium".to_string());
    info!("TLS grade set to: [ {} ]", grade);

    let bg_srvc = background_service("bgsrvc", lb.clone());
    let mut proxy = pingora_proxy::http_proxy_service(&server.configuration, lb.clone());
    let bind_address_http = cfg.proxy_address_http.clone();
    let bind_address_tls = cfg.proxy_address_tls.clone();

    crate::utils::tools::check_priv(bind_address_http.as_str());

    match bind_address_tls {
        Some(bind_address_tls) => {
            crate::utils::tools::check_priv(bind_address_tls.as_str());
            let (tx, rx): (Sender<Vec<CertificateConfig>>, Receiver<Vec<CertificateConfig>>) =
                channel();
            let certs_path = cfg.proxy_certificates.clone().unwrap();
            thread::spawn(move || {
                crate::utils::tools::watch_folder(certs_path, tx).unwrap();
            });
            let certificate_configs = rx.recv().unwrap();

            if let Some(first_set) = tls::Certificates::new(
                &certificate_configs,
                grade.as_str(),
                cfg.default_certificate.as_ref(),
            ) {
                let first_set_arc: Arc<tls::Certificates> = Arc::new(first_set);
                certificates_arc.store(Arc::new(Some(first_set_arc.clone())
                    as Option<Arc<tls::Certificates>>));

                // Set global certificates for SNI callback
                tls::set_global_certificates(first_set_arc.clone());

                let default_cert_path = first_set_arc.default_cert_path.clone();
                let default_key_path = first_set_arc.default_key_path.clone();

                // Create TlsSettings with SNI callback for certificate selection
                let tls_settings = match tls::create_tls_settings_with_sni(
                    &default_cert_path,
                    &default_key_path,
                    grade.as_str(),
                    Some(first_set_arc.clone()),
                ) {
                    Ok(settings) => settings,
                    Err(e) => {
                        warn!(
                            "Failed to create TlsSettings with SNI callback: {}, falling back to default",
                            e
                        );
                        let mut settings = TlsSettings::intermediate(
                            &default_cert_path,
                            &default_key_path,
                        )
                        .expect("unable to load or parse cert/key");
                        tls::set_tsl_grade(&mut settings, grade.as_str());
                        tls::set_alpn_prefer_h2(&mut settings);
                        settings
                    }
                };

                // Register ClientHello callback to generate fingerprints
                #[cfg(unix)]
                {
                    use log::info;
                    use pingora_core::listeners::set_client_hello_callback;
                    use pingora_core::protocols::l4::socket::SocketAddr;
                    use pingora_core::protocols::tls::client_hello::ClientHello;

                    set_client_hello_callback(Some(
                        |hello: &ClientHello, peer_addr: Option<SocketAddr>| {
                            let peer_str = peer_addr
                                .as_ref()
                                .and_then(|a| a.as_inet())
                                .map(|inet| format!("{}:{}", inet.ip(), inet.port()))
                                .unwrap_or_else(|| "unknown".to_string());
                            debug!(
                                "ClientHello callback invoked for peer: {}, SNI: {:?}, ALPN: {:?}, raw_len={}",
                                peer_str,
                                hello.sni,
                                hello.alpn,
                                hello.raw.len()
                            );
                            // Generate fingerprint from ClientHello
                            if let Some(_fp) =
                                crate::utils::tls_client_hello::generate_fingerprint_from_client_hello(
                                    hello,
                                    peer_addr,
                                )
                            {
                                debug!("Fingerprint generated successfully for peer: {}", peer_str);
                            } else {
                                warn!("Failed to generate fingerprint for peer: {}", peer_str);
                            }
                        },
                    ));
                    info!("TLS ClientHello callback registered for fingerprint generation");
                }

                proxy.add_tls_with_settings(&bind_address_tls, None, tls_settings);
            } else {
                info!("TLS listener disabled: no certificates found in directory. TLS will be enabled when certificates are added.");
            }

            let certs_for_watcher = certificates_arc.clone();
            let default_cert_for_watcher = cfg.default_certificate.clone();
            thread::spawn(move || {
                while let Ok(new_configs) = rx.recv() {
                    let new_certs =
                        tls::Certificates::new(&new_configs, grade.as_str(), default_cert_for_watcher.as_ref());
                    if let Some(new_certs) = new_certs {
                        certs_for_watcher.store(Arc::new(Some(Arc::new(new_certs))));
                    }
                }
            });
        }
        None => {}
    }

    info!("Running HTTP listener on :{}", bind_address_http.as_str());
    proxy.add_tcp(bind_address_http.as_str());

    server.add_service(proxy);
    server.add_service(bg_srvc);

    thread::spawn(move || server.run_forever());

    if let (Some(user), Some(group)) = (cfg.rungroup.clone(), cfg.runuser.clone()) {
        crate::utils::tools::drop_priv(
            user,
            group,
            cfg.proxy_address_http.clone(),
            cfg.proxy_address_tls.clone(),
        );
    }

    let (tx, rx) = channel();
    ctrlc::set_handler(move || {
        tx.send(()).expect("Could not send signal on channel.")
    })
    .expect("Error setting Ctrl-C handler");
    rx.recv()
        .expect("Could not receive from channel.");
    info!("Signal received ! Exiting...");
}
