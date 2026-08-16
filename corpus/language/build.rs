use std::process::Command;

fn main() {
    let rustc = std::env::var_os("RUSTC").expect("Cargo must provide RUSTC");
    let output = Command::new(rustc)
        .arg("--version")
        .output()
        .expect("query the benchmark compiler");
    assert!(output.status.success(), "benchmark compiler query failed");
    let version = String::from_utf8(output.stdout).expect("rustc version must be UTF-8");
    let version = version
        .split_whitespace()
        .nth(1)
        .expect("rustc version is missing");
    assert_eq!(
        version, "1.97.1",
        "BenchmarkRust must be compiled by the locked rustc 1.97.1 toolchain"
    );
    let host = std::env::var("HOST").expect("Cargo must provide HOST");
    println!("cargo:rustc-env=RIG_BENCHMARK_RUSTC_COORDINATE=rustc-{version}-{host}");
    println!("cargo:rerun-if-changed=build.rs");
}
