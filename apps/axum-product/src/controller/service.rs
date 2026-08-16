use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;

use crate::ApplicationState;

pub(super) fn service_routes() -> Router<ApplicationState> {
    Router::new()
        .route("/controller/service/control", post(service_control))
        .route("/controller/service/safe", post(service_safe))
        .route("/controller/service/vulnerable", post(service_vulnerable))
}

async fn service_control(headers: HeaderMap) -> StatusCode {
    call_witness(&headers).await
}

async fn service_safe(_headers: HeaderMap) -> StatusCode {
    StatusCode::OK
}

async fn service_vulnerable(headers: HeaderMap) -> StatusCode {
    call_witness(&headers).await
}

async fn call_witness(headers: &HeaderMap) -> StatusCode {
    let Some(correlation) = headers
        .get("x-rig-protocol-correlation")
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::OK;
    };
    let Ok(origin) = std::env::var("RIG_BILLING_ORIGIN") else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    let Ok(capability) = std::env::var("RIG_BILLING_CAPABILITY") else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    match reqwest::Client::new()
        .post(format!("{origin}/charge"))
        .header("X-Rig-Witness-Capability", capability)
        .header("X-Rig-Protocol-Correlation", correlation)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => StatusCode::OK,
        _ => StatusCode::BAD_GATEWAY,
    }
}
