mod access;
mod concurrency;
mod service;
mod workflow;

use std::collections::BTreeMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

use axum::Router;

use crate::ApplicationState;

pub(crate) struct ControllerState {
    workflows: Mutex<BTreeMap<String, u8>>,
    safe_claims: AtomicUsize,
    vulnerable_claims: AtomicUsize,
}

impl ControllerState {
    pub(crate) fn new() -> Self {
        Self {
            workflows: Mutex::new(BTreeMap::new()),
            safe_claims: AtomicUsize::new(0),
            vulnerable_claims: AtomicUsize::new(0),
        }
    }
}

pub(crate) fn controller_routes() -> Router<ApplicationState> {
    Router::new()
        .merge(access::access_routes())
        .merge(workflow::workflow_routes())
        .merge(concurrency::concurrency_routes())
        .merge(service::service_routes())
}
