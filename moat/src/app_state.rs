use crate::{bpf, ssl::SharedTlsState};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub skels: Vec<Arc<bpf::FilterSkel<'static>>>,
    pub tls_state: SharedTlsState,
}
