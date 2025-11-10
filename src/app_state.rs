use crate::{bpf};
use std::sync::Arc;
use crate::bpf_stats::BpfStatsCollector;
use crate::utils::tcp_fingerprint::TcpFingerprintCollector;

#[derive(Clone)]
pub struct AppState {
    pub skels: Vec<Arc<bpf::FilterSkel<'static>>>,
    pub ifindices: Vec<i32>,
    pub bpf_stats_collector: BpfStatsCollector,
    pub tcp_fingerprint_collector: TcpFingerprintCollector,
}


