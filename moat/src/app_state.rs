use crate::{bpf, ssl::SharedTlsState};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub skel: Option<Arc<bpf::FilterSkel<'static>>>,
    pub tls_state: SharedTlsState,
}
