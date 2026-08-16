#[cfg(feature = "dangerous")]
async fn feature_selected_handler() {
    let _ = std::fs::read_to_string("/tmp/feature-selected");
}

fn main() {}
