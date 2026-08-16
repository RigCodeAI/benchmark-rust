use axum::{extract::Query, routing::get, Router};

struct Input {
    value: String,
}

async fn handler(Query(input): Query<Input>) {
    let database = ();
    let _ = sqlx::query(&input.value).execute(&database).await;
    let _ = reqwest::get(&input.value).await;
}

fn main() {
    let _ = Router::new().route("/spoof", get(handler));
}

