use axum::{routing::get, Router};

async fn handler() -> &'static str {
    "ok"
}

fn application(path: &str) -> Router {
    Router::new().route(path, get(handler))
}

fn main() {
    let _ = application("/runtime-selected");
}

