use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;

pub type UpstreamsDashMap = DashMap<String, DashMap<String, (Vec<InnerMap>, AtomicUsize)>>;

pub type UpstreamsIdMap = DashMap<String, InnerMap>;
pub type Headers = DashMap<String, DashMap<String, Vec<(String, String)>>>;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ServiceMapping {
    pub upstream: String,
    pub hostname: String,
    pub path: Option<String>,
    #[serde(default)]
    pub force_https: Option<bool>,
    pub rate_limit: Option<isize>,
    pub headers: Option<Vec<String>>,
}

// pub type Services = DashMap<String, Vec<(String, Option<String>)>>;

#[derive(Clone, Debug, Default)]
pub struct Extraparams {
    pub sticky_sessions: bool,
    pub https_proxy_enabled: Option<bool>,
    pub authentication: DashMap<String, Vec<String>>,
    pub rate_limit: Option<isize>,
}
#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Kubernetes {
    pub servers: Option<Vec<String>>,
    pub services: Option<Vec<ServiceMapping>>,
    pub tokenpath: Option<String>,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
pub struct Consul {
    pub servers: Option<Vec<String>>,
    pub services: Option<Vec<ServiceMapping>>,
    pub token: Option<String>,
}
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default)]
    pub https_proxy_enabled: bool,
    #[serde(default)]
    pub sticky_sessions: bool,
    #[serde(default)]
    pub global_rate_limit: Option<isize>,
    #[serde(default)]
    pub global_headers: Option<Vec<String>>,
    #[serde(default)]
    pub healthcheck_interval: Option<u16>,
    #[serde(default)]
    pub healthcheck_method: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default)]
    pub config: Option<GlobalConfig>,
    #[serde(default)]
    pub sticky_sessions: bool,
    #[serde(default)]
    pub arxignis_paths: Option<HashMap<String, PathConfig>>,
    #[serde(default)]
    pub upstreams: Option<HashMap<String, HostConfig>>,
    #[serde(default)]
    pub globals: Option<HashMap<String, Vec<String>>>,
    #[serde(default)]
    pub headers: Option<Vec<String>>,
    #[serde(default)]
    pub authorization: Option<HashMap<String, String>>,
    #[serde(default)]
    pub consul: Option<Consul>,
    #[serde(default)]
    pub kubernetes: Option<Kubernetes>,
    #[serde(default)]
    pub rate_limit: Option<isize>,
}

fn default_provider() -> String {
    "file".to_string()
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HostConfig {
    pub paths: HashMap<String, PathConfig>,
    pub rate_limit: Option<isize>,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub acme: Option<crate::acme::upstreams_reader::UpstreamsAcmeConfig>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PathConfig {
    pub servers: Vec<String>,
    #[serde(default, alias = "force_https")]
    pub https_proxy_enabled: Option<bool>,
    #[serde(default)]
    pub ssl_enabled: Option<bool>,
    #[serde(default)]
    pub http2_enabled: Option<bool>,
    #[serde(default)]
    pub headers: Option<Vec<String>>,
    #[serde(default)]
    pub rate_limit: Option<isize>,
    #[serde(default)]
    pub healthcheck: Option<bool>,
}
#[derive(Debug, Default)]
pub struct Configuration {
    pub arxignis_paths: DashMap<String, (Vec<InnerMap>, AtomicUsize)>,
    pub upstreams: UpstreamsDashMap,
    pub headers: Headers,
    pub consul: Option<Consul>,
    pub kubernetes: Option<Kubernetes>,
    pub typecfg: String,
    pub extraparams: Extraparams,
    pub certificates: DashMap<String, String>, // hostname -> certificate_name mapping
    pub healthcheck_interval: Option<u16>,
    pub healthcheck_method: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub healthcheck_interval: u16,
    pub healthcheck_method: String,
    pub master_key: String,
    pub upstreams_conf: String,
    pub config_address: String,
    pub proxy_address_http: String,
    pub config_api_enabled: bool,
    pub config_tls_address: Option<String>,
    pub config_tls_certificate: Option<String>,
    pub config_tls_key_file: Option<String>,
    pub proxy_address_tls: Option<String>,
    pub proxy_port_tls: Option<u16>,
    pub local_server: Option<(String, u16)>,
    pub proxy_certificates: Option<String>,
    pub proxy_tls_grade: Option<String>,
    pub default_certificate: Option<String>,
    pub file_server_address: Option<String>,
    pub file_server_folder: Option<String>,
    pub runuser: Option<String>,
    pub rungroup: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InnerMap {
    pub address: String,
    pub port: u16,
    pub ssl_enabled: bool,
    pub http2_enabled: bool,
    pub https_proxy_enabled: bool,
    pub rate_limit: Option<isize>,
    pub healthcheck: Option<bool>,
}

#[allow(dead_code)]
impl InnerMap {
    pub fn new() -> Self {
        Self {
            address: Default::default(),
            port: Default::default(),
            ssl_enabled: Default::default(),
            http2_enabled: Default::default(),
            https_proxy_enabled: Default::default(),
            rate_limit: Default::default(),
            healthcheck: Default::default(),
        }
    }
}
