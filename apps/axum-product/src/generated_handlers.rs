async fn generated_shape(
    axum::extract::Query(input): axum::extract::Query<TextInput>,
) -> &'static str {
    let _ = std::fs::read_to_string(input.value);
    "ok"
}
