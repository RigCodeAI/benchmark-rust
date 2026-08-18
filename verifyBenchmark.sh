#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo run --quiet --locked -- verify

cargo +1.97.1 test --locked --manifest-path corpus/language/Cargo.toml
cargo +1.97.1 check --locked --manifest-path apps/axum-product/Cargo.toml

echo "BenchmarkRust verification complete"
