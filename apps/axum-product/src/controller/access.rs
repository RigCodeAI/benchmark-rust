use axum::extract::Form;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

use crate::ApplicationState;

#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
}

pub(super) fn access_routes() -> Router<ApplicationState> {
    Router::new()
        .route("/controller/login", post(controller_login))
        .route("/controller/csrf-token", get(controller_csrf_token))
        .route("/controller/cwe-284/vulnerable", get(cwe_284_vulnerable))
        .route("/controller/cwe-284/safe", get(cwe_284_safe))
        .route("/controller/cwe-287/vulnerable", get(cwe_287_vulnerable))
        .route("/controller/cwe-287/safe", get(cwe_287_safe))
        .route("/controller/cwe-306/vulnerable", get(cwe_306_vulnerable))
        .route("/controller/cwe-306/safe", get(cwe_306_safe))
        .route("/controller/cwe-352/vulnerable", post(cwe_352_vulnerable))
        .route("/controller/cwe-352/safe", post(cwe_352_safe))
        .route("/controller/cwe-639/vulnerable", get(cwe_639_vulnerable))
        .route("/controller/cwe-639/safe", get(cwe_639_safe))
        .route("/controller/cwe-862/vulnerable", get(cwe_862_vulnerable))
        .route("/controller/cwe-862/safe", get(cwe_862_safe))
        .route("/controller/cwe-863/vulnerable", get(cwe_863_vulnerable))
        .route("/controller/cwe-863/safe", get(cwe_863_safe))
}

async fn controller_login(Form(login): Form<Login>) -> (StatusCode, HeaderMap, &'static str) {
    let valid = matches!(
        (login.username.as_str(), login.password.as_str()),
        ("alice", "alice-secret") | ("bob", "bob-secret") | ("admin", "admin-secret")
    );
    if !valid {
        return (StatusCode::UNAUTHORIZED, HeaderMap::new(), "denied");
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "sivere_session={}; Path=/; HttpOnly",
            login.username
        ))
        .expect("fixed benchmark identity is a valid cookie"),
    );
    (StatusCode::OK, headers, "authenticated")
}

async fn controller_csrf_token() -> (StatusCode, HeaderMap, &'static str) {
    let mut response = HeaderMap::new();
    response.insert(
        header::SET_COOKIE,
        HeaderValue::from_static("sivere_csrf=sivere-controller-token; Path=/"),
    );
    (StatusCode::OK, response, "csrf")
}

fn protected(allowed: bool) -> (StatusCode, &'static str) {
    if allowed {
        (StatusCode::OK, "protected-resource")
    } else {
        (StatusCode::FORBIDDEN, "denied")
    }
}

async fn cwe_284_vulnerable(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    protected(session(&headers).is_some())
}

async fn cwe_284_safe(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    protected(session(&headers) == Some("alice"))
}

async fn cwe_287_vulnerable(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    let _ = headers.get("authorization");
    protected(session(&headers).is_some() || headers.contains_key(header::AUTHORIZATION))
}

async fn cwe_287_safe(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    protected(session(&headers) == Some("alice"))
}

async fn cwe_306_vulnerable() -> (StatusCode, &'static str) {
    protected(true)
}

async fn cwe_306_safe(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    protected(session(&headers) == Some("alice"))
}

async fn cwe_352_vulnerable(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    protected(session(&headers) == Some("alice"))
}

async fn cwe_352_safe(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    let token = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok());
    protected(session(&headers) == Some("alice") && token == Some("sivere-controller-token"))
}

async fn cwe_639_vulnerable(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    protected(session(&headers).is_some())
}

async fn cwe_639_safe(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    protected(session(&headers) == Some("alice"))
}

async fn cwe_862_vulnerable(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    protected(session(&headers).is_some())
}

async fn cwe_862_safe(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    protected(session(&headers) == Some("alice"))
}

async fn cwe_863_vulnerable(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    protected(session(&headers).is_some())
}

async fn cwe_863_safe(headers: HeaderMap) -> (StatusCode, &'static str) {
    let _ = headers.get("cookie");
    protected(session(&headers) == Some("admin"))
}

fn session(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                cookie
                    .trim()
                    .strip_prefix("sivere_session=")
                    .filter(|value| matches!(*value, "alice" | "bob" | "admin"))
            })
        })
}
