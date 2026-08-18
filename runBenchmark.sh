#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
TOOLCHAIN=${BENCHMARK_RUST_TOOLCHAIN:-1.97.1}

case "${1:-}" in
  --help|-h)
    echo "usage: $0"
    echo "Starts Axum 0.8.9 at http://127.0.0.1:3000 using Rust $TOOLCHAIN."
    exit 0
    ;;
  "") ;;
  *) echo "usage: $0" >&2; exit 2 ;;
esac

command -v cargo >/dev/null 2>&1 || {
  echo "Cargo is required. Install Rustup and toolchain $TOOLCHAIN." >&2
  exit 2
}

cd "$ROOT"
exec cargo "+$TOOLCHAIN" run --release --locked \
  --manifest-path apps/axum-product/Cargo.toml
