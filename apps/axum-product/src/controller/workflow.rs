use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;

use crate::ApplicationState;

pub(super) fn workflow_routes() -> Router<ApplicationState> {
    Router::new()
        .route(
            "/controller/workflow/control/reset",
            post(workflow_control_reset),
        )
        .route(
            "/controller/workflow/control/execute",
            post(workflow_control_execute),
        )
        .route("/controller/workflow/safe/reset", post(workflow_safe_reset))
        .route(
            "/controller/workflow/safe/execute",
            post(workflow_safe_execute),
        )
        .route(
            "/controller/workflow/vulnerable/reset",
            post(workflow_vulnerable_reset),
        )
        .route(
            "/controller/workflow/vulnerable/execute",
            post(workflow_vulnerable_execute),
        )
}

async fn workflow_control_reset(State(state): State<ApplicationState>) -> StatusCode {
    reset(&state, "control");
    StatusCode::OK
}

async fn workflow_control_execute(
    State(state): State<ApplicationState>,
) -> (StatusCode, &'static str) {
    execute(&state, "control", true)
}

async fn workflow_safe_reset(State(state): State<ApplicationState>) -> StatusCode {
    reset(&state, "safe");
    StatusCode::OK
}

async fn workflow_safe_execute(
    State(state): State<ApplicationState>,
) -> (StatusCode, &'static str) {
    execute(&state, "safe", true)
}

async fn workflow_vulnerable_reset(State(state): State<ApplicationState>) -> StatusCode {
    reset(&state, "vulnerable");
    StatusCode::OK
}

async fn workflow_vulnerable_execute(
    State(state): State<ApplicationState>,
) -> (StatusCode, &'static str) {
    execute(&state, "vulnerable", false)
}

fn reset(state: &ApplicationState, key: &str) {
    state
        .controller
        .workflows
        .lock()
        .expect("benchmark workflow lock")
        .insert(key.to_owned(), 0);
}

fn execute(state: &ApplicationState, key: &str, enforce_limit: bool) -> (StatusCode, &'static str) {
    let mut workflows = state
        .controller
        .workflows
        .lock()
        .expect("benchmark workflow lock");
    let count = workflows.entry(key.to_owned()).or_insert(0);
    if enforce_limit && *count >= 1 {
        return (StatusCode::CONFLICT, "limit-enforced");
    }
    *count = count.saturating_add(1);
    (StatusCode::OK, "executed")
}
