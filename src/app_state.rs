use crate::{bpf, http::SharedTlsState};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub skels: Vec<Arc<bpf::FilterSkel<'static>>>,
    pub tls_state: SharedTlsState,
    pub ifindices: Vec<i32>,
}


