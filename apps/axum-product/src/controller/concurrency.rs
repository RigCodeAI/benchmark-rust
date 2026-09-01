use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::Router;

use crate::ApplicationState;

pub(super) fn concurrency_routes() -> Router<ApplicationState> {
    Router::new()
        .route("/controller/race/safe/reset", post(race_safe_reset))
        .route("/controller/race/safe/claim", post(race_safe_claim))
        .route("/controller/race/safe/oracle", get(race_safe_oracle))
        .route(
            "/controller/race/vulnerable/reset",
            post(race_vulnerable_reset),
        )
        .route(
            "/controller/race/vulnerable/claim",
            post(race_vulnerable_claim),
        )
        .route(
            "/controller/race/vulnerable/oracle",
            get(race_vulnerable_oracle),
        )
}

async fn race_safe_reset(State(state): State<ApplicationState>) -> StatusCode {
    state.controller.safe_claims.store(0, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

async fn race_safe_claim(State(state): State<ApplicationState>, headers: HeaderMap) -> StatusCode {
    let _ = headers.get("x-sivere-concurrency");
    if !scheduled(&headers) {
        return StatusCode::CONFLICT;
    }
    if state
        .controller
        .safe_claims
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        StatusCode::OK
    } else {
        StatusCode::CONFLICT
    }
}

async fn race_safe_oracle(State(state): State<ApplicationState>) -> StatusCode {
    if state.controller.safe_claims.load(Ordering::SeqCst) <= 1 {
        StatusCode::OK
    } else {
        StatusCode::CONFLICT
    }
}

async fn race_vulnerable_reset(State(state): State<ApplicationState>) -> StatusCode {
    state
        .controller
        .vulnerable_claims
        .store(0, Ordering::SeqCst);
    StatusCode::NO_CONTENT
}

async fn race_vulnerable_claim(
    State(state): State<ApplicationState>,
    headers: HeaderMap,
) -> StatusCode {
    let _ = headers.get("x-sivere-concurrency");
    if !scheduled(&headers) {
        return StatusCode::CONFLICT;
    }
    let available = state.controller.vulnerable_claims.load(Ordering::SeqCst) == 0;
    // The controller releases both prepared requests together. Keep the stale
    // decision live long enough for both server tasks to observe it without
    // introducing an application-side barrier that can deadlock a constrained
    // runtime.
    tokio::time::sleep(Duration::from_millis(75)).await;
    if available {
        state
            .controller
            .vulnerable_claims
            .fetch_add(1, Ordering::SeqCst);
        StatusCode::OK
    } else {
        StatusCode::CONFLICT
    }
}

async fn race_vulnerable_oracle(State(state): State<ApplicationState>) -> StatusCode {
    if state.controller.vulnerable_claims.load(Ordering::SeqCst) <= 1 {
        StatusCode::OK
    } else {
        StatusCode::CONFLICT
    }
}

fn scheduled(headers: &HeaderMap) -> bool {
    headers
        .get("x-sivere-concurrency")
        .and_then(|value| value.to_str().ok())
        == Some("release")
}
