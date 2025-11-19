use once_cell::sync::Lazy;
use std::sync::RwLock;

#[derive(Debug)]
pub struct SharedState {
    pub first_run: bool,
}

pub static GLOBAL_STATE: Lazy<RwLock<SharedState>> = Lazy::new(|| RwLock::new(SharedState { first_run: true }));

pub fn mark_not_first_run() {
    let mut state = GLOBAL_STATE.write().expect("Lock poisoned");
    state.first_run = false;
}

pub fn is_first_run() -> bool {
    let state = GLOBAL_STATE.read().expect("Lock poisoned");
    state.first_run
}
