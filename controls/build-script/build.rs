fn main() {
    // This sentinel must never be created by benchmark discovery. The control
    // repository is inspected, never built.
    let _ = std::fs::write("sivere-build-script-executed", "unexpected");
}
