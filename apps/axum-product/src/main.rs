use axum::{
    body::{to_bytes, Body},
    extract::{Form, Multipart, Path, Query, Request, State},
    http::HeaderMap,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use sqlx::SqlitePool;
use std::fs::read_to_string as aliased_read_to_string;
use std::sync::Arc;

include!("generated_handlers.rs");
mod controller;
mod parity;
mod rust_specific;

#[derive(Clone)]
pub(crate) struct ApplicationState {
    database: SqlitePool,
    controller: Arc<controller::ControllerState>,
}

#[derive(Deserialize)]
struct TextInput {
    value: String,
}

#[derive(Deserialize)]
struct UrlInput {
    url: String,
}

#[derive(Clone)]
struct MiddlewareInput {
    value: String,
}

#[derive(Clone)]
struct RequestExtension {
    value: String,
}

#[derive(Clone)]
struct AuthenticatedPrincipal {
    subject: String,
}

async fn middleware_source(mut request: Request, next: Next) -> Response {
    let value = request
        .headers()
        .get("x-sivere-middleware")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    request.extensions_mut().insert(MiddlewareInput { value });
    next.run(request).await
}

async fn extension_source(mut request: Request, next: Next) -> Response {
    let value = request
        .headers()
        .get("x-sivere-extension")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    request.extensions_mut().insert(RequestExtension { value });
    next.run(request).await
}

async fn authenticated_principal(mut request: Request, next: Next) -> Response {
    let subject = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    request
        .extensions_mut()
        .insert(AuthenticatedPrincipal { subject });
    next.run(request).await
}

fn observe_source(value: impl AsRef<std::path::Path>) {
    let _ = std::fs::read_to_string(value);
}

async fn source_query(Query(input): Query<TextInput>) -> &'static str {
    observe_source(input.value);
    "ok"
}

async fn source_path(Path(value): Path<String>) -> &'static str {
    observe_source(value);
    "ok"
}

async fn source_form(Form(input): Form<TextInput>) -> &'static str {
    observe_source(input.value);
    "ok"
}

async fn source_json(Json(input): Json<TextInput>) -> &'static str {
    observe_source(input.value);
    "ok"
}

async fn source_header(headers: HeaderMap) -> &'static str {
    let value = headers
        .get("x-sivere-source")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    observe_source(value);
    "ok"
}

async fn source_cookie(jar: CookieJar) -> &'static str {
    let value = jar
        .get("sivere_source")
        .map(|cookie| cookie.value())
        .unwrap_or_default();
    observe_source(value);
    "ok"
}

async fn source_multipart(mut multipart: Multipart) -> &'static str {
    if let Ok(Some(field)) = multipart.next_field().await {
        if let Ok(value) = field.text().await {
            observe_source(value);
        }
    }
    "ok"
}

async fn source_body(body: Body) -> &'static str {
    if let Ok(bytes) = to_bytes(body, 64 * 1024).await {
        if let Ok(value) = String::from_utf8(bytes.to_vec()) {
            observe_source(value);
        }
    }
    "ok"
}

async fn source_middleware(Extension(input): Extension<MiddlewareInput>) -> &'static str {
    observe_source(input.value);
    "ok"
}

async fn source_extension(Extension(input): Extension<RequestExtension>) -> &'static str {
    observe_source(input.value);
    "ok"
}

async fn source_principal(Extension(principal): Extension<AuthenticatedPrincipal>) -> &'static str {
    observe_source(principal.subject);
    "ok"
}

async fn sql_raw(
    Query(input): Query<TextInput>,
    State(state): State<ApplicationState>,
) -> &'static str {
    let statement = format!("SELECT name FROM item WHERE name = '{}'", input.value);
    let _ = sqlx::query(&statement).execute(&state.database).await;
    "ok"
}

async fn sql_constant(
    Query(_input): Query<TextInput>,
    State(state): State<ApplicationState>,
) -> &'static str {
    let _ = sqlx::query("SELECT name FROM item WHERE id = 1")
        .execute(&state.database)
        .await;
    "ok"
}

async fn sql_bound(
    Query(input): Query<TextInput>,
    State(state): State<ApplicationState>,
) -> &'static str {
    let _ = sqlx::query("SELECT name FROM item WHERE id = ?")
        .bind(input.value)
        .execute(&state.database)
        .await;
    "ok"
}

async fn process_shell(Query(input): Query<TextInput>) -> &'static str {
    let command = format!("printf '%s' {}", input.value);
    let _ = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .output();
    "ok"
}

async fn process_argv(Query(input): Query<TextInput>) -> &'static str {
    let _ = std::process::Command::new("/usr/bin/printf")
        .arg("%s")
        .arg(input.value)
        .output();
    "ok"
}

async fn process_stored_builder(Query(input): Query<TextInput>) -> &'static str {
    macro_rules! terminal_output {
        ($command:expr) => {
            $command.output()
        };
    }
    let mut command = std::process::Command::new("/usr/bin/printf");
    command.arg("%s").arg(input.value);
    let _ = terminal_output!(&mut command);
    "ok"
}

async fn file_from_path(Path(value): Path<String>) -> &'static str {
    // The disposable benchmark workspace is the effect boundary: a successful
    // write proves that the request-controlled path was acted upon without
    // touching developer files or external state.
    let _ = std::fs::write(value, b"sivere-owned-path-effect");
    "ok"
}

async fn file_constant(Query(_input): Query<TextInput>) -> &'static str {
    let _ = std::fs::read_to_string("/tmp/sivere-benchmark-rust-safe-file");
    "ok"
}

async fn outbound_dynamic(Query(input): Query<UrlInput>) -> &'static str {
    let _ = reqwest::get(input.url).await;
    "ok"
}

async fn outbound_constant(Query(_input): Query<UrlInput>) -> &'static str {
    let _ = reqwest::get("http://127.0.0.1:9/sivere-safe-control").await;
    "ok"
}

async fn outbound_builder(Query(input): Query<UrlInput>) -> &'static str {
    let client = reqwest::Client::new();
    let method = reqwest::Method::GET;
    let _ = client.request(method, input.url).send().await;
    "ok"
}

async fn html_active(Query(input): Query<TextInput>) -> axum::response::Html<String> {
    axum::response::Html(format!("<script>void \"{}\"</script>", input.value))
}

async fn html_encoded(Query(input): Query<TextInput>) -> axum::response::Html<String> {
    let encoded = input
        .value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;");
    axum::response::Html(format!("<main>{encoded}</main>"))
}

struct UnresolvedBody(String);

impl IntoResponse for UnresolvedBody {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}

fn unresolved_body(value: String) -> UnresolvedBody {
    UnresolvedBody(format!("<main>{value}</main>"))
}

async fn html_unresolved(Query(input): Query<TextInput>) -> axum::response::Html<UnresolvedBody> {
    let body = unresolved_body(input.value);
    axum::response::Html(body)
}

async fn json_echo(Json(_input): Json<TextInput>) -> &'static str {
    "ok"
}

fn generic_read<P: AsRef<std::path::Path>>(path: P) {
    let _ = std::fs::read_to_string(path);
}

trait PathReader {
    fn read(path: &str);
}

struct TraitPathReader;

impl PathReader for TraitPathReader {
    fn read(path: &str) {
        let _ = std::fs::read_to_string(path);
    }
}

fn macro_read(path: &str) {
    let _ = std::fs::read_to_string(path);
}

macro_rules! compiler_expanded_read {
    ($path:expr) => {
        macro_read($path)
    };
}

async fn alias_shape(Query(input): Query<TextInput>) -> &'static str {
    let _ = aliased_read_to_string(input.value);
    "ok"
}

async fn generic_shape(Query(input): Query<TextInput>) -> &'static str {
    generic_read(input.value);
    "ok"
}

async fn trait_shape(Query(input): Query<TextInput>) -> &'static str {
    <TraitPathReader as PathReader>::read(&input.value);
    "ok"
}

async fn macro_shape(Query(input): Query<TextInput>) -> &'static str {
    compiler_expanded_read!(&input.value);
    "ok"
}

async fn spawned_shape(Query(input): Query<TextInput>) -> &'static str {
    let path = input.value;
    let _ = tokio::spawn(async move {
        let _ = std::fs::read_to_string(path);
    })
    .await;
    "ok"
}

async fn compiler_process_builder(Query(input): Query<TextInput>) -> &'static str {
    let mut command = std::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(format!("printf '%s' {}", input.value));
    let _ = command.output();
    "ok"
}

async fn compiler_reqwest_builder(Query(input): Query<UrlInput>) -> &'static str {
    let client = reqwest::Client::new();
    let _ = client.get(input.url).send().await;
    "ok"
}

async fn compiler_html_generic(Query(input): Query<TextInput>) -> axum::response::Html<String> {
    let body = format!("<main>{}</main>", input.value);
    axum::response::Html(body)
}

#[cfg(feature = "compiler-shapes")]
fn active_feature_routes() -> Router<ApplicationState> {
    Router::new().route("/active", get(feature_selected_handler))
}

#[cfg(feature = "compiler-shapes")]
async fn feature_selected_handler(Query(input): Query<TextInput>) -> &'static str {
    let _ = std::fs::read_to_string(input.value);
    "ok"
}

#[cfg(not(feature = "compiler-shapes"))]
fn inactive_feature_routes() -> Router<ApplicationState> {
    Router::new().route("/inactive", get(feature_unselected_handler))
}

#[cfg(not(feature = "compiler-shapes"))]
async fn feature_unselected_handler(Query(input): Query<TextInput>) -> &'static str {
    let _ = std::fs::read_to_string(input.value);
    "ok"
}

fn compiler_shape_routes() -> Router<ApplicationState> {
    Router::new()
        .route("/alias", get(alias_shape))
        .route("/generic", get(generic_shape))
        .route("/trait", get(trait_shape))
        .route("/macro", get(macro_shape))
        .route("/generated", get(generated_shape))
        .route("/spawned", get(spawned_shape))
        .route("/process-builder", get(compiler_process_builder))
        .route("/reqwest-builder", get(compiler_reqwest_builder))
        .route("/html-generic", get(compiler_html_generic))
        .nest("/feature", active_feature_routes())
}

fn source_shape_routes() -> Router<ApplicationState> {
    Router::new()
        .route("/query", get(source_query))
        .route("/path/{value}", get(source_path))
        .route("/form", post(source_form))
        .route("/json", post(source_json))
        .route("/header", get(source_header))
        .route("/cookie", get(source_cookie))
        .route("/multipart", post(source_multipart))
        .route("/body", post(source_body))
        .route("/middleware", get(source_middleware))
        .route("/extension", get(source_extension))
        .route("/principal", get(source_principal))
}

fn sql_routes() -> Router<ApplicationState> {
    Router::new()
        .route("/raw", get(sql_raw))
        .route("/constant", get(sql_constant))
        .route("/bound", get(sql_bound))
}

fn application(state: ApplicationState) -> Router {
    Router::new()
        .nest("/sql", sql_routes())
        .route("/process/shell", get(process_shell))
        .route("/process/argv", get(process_argv))
        .route("/process/stored-builder", get(process_stored_builder))
        .route("/files/{value}", get(file_from_path))
        .route("/files/constant", get(file_constant))
        .route("/outbound/dynamic", get(outbound_dynamic))
        .route("/outbound/constant", get(outbound_constant))
        .route("/outbound/builder", get(outbound_builder))
        .route("/html/active", get(html_active))
        .route("/html/encoded", get(html_encoded))
        .route("/html/unresolved", get(html_unresolved))
        .route("/json/echo", post(json_echo))
        .nest("/compiler", compiler_shape_routes())
        .nest("/sources", source_shape_routes())
        .nest("/parity", parity::routes())
        .nest("/rust-specific", rust_specific::routes())
        .merge(controller::controller_routes())
        .layer(axum::middleware::from_fn(authenticated_principal))
        .layer(axum::middleware::from_fn(extension_source))
        .layer(axum::middleware::from_fn(middleware_source))
        .with_state(state)
}

#[tokio::main]
async fn main() {
    std::fs::write("sivere-xxe-canary.txt", "SIVERE_XXE_EFFECT")
        .expect("create scanner-owned XML effect canary");
    // The vulnerable XML controls intentionally reproduce the unsafe native
    // parser policy. The safe controls use a parser that never resolves DTDs.
    unsafe {
        libxml::bindings::xmlSubstituteEntitiesDefault(1);
    }
    let database = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("create benchmark database");
    sqlx::query("CREATE TABLE item (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
        .execute(&database)
        .await
        .expect("initialize benchmark database");
    let bind_address =
        std::env::var("BENCHMARK_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_owned());
    let listener = tokio::net::TcpListener::bind(&bind_address)
        .await
        .expect("bind benchmark listener");
    axum::serve(
        listener,
        application(ApplicationState {
            database,
            controller: Arc::new(controller::ControllerState::new()),
        }),
    )
    .await
    .expect("serve benchmark application");
}
