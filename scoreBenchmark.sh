#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

exec cargo run --quiet --release --locked -- score-results "$@"
