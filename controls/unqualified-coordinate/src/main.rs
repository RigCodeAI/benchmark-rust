use axum::{routing::get, Router};

async fn handler() -> &'static str {
    "ok"
}

fn main() {
    let _ = Router::new().route("/unsupported", get(handler));
}

