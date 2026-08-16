# Rust web-framework coordinate qualification

Status: qualification evidence, not Rust promotion, 2026-08-15

Rig's Rust web adapter currently recognizes these exact coordinate families:

| Framework | Framework versions | rustc versions | Product result |
| --- | --- | --- | --- |
| Axum | 0.8.8, 0.8.9 | 1.96.1, 1.97.1 | Five-slice matrix passed |
| Actix Web | 4.14.1 | 1.97.1 | Five-slice qualification passed |

The five-slice qualification contains vulnerable and safe SQL injection,
command injection, path traversal, XSS, and SSRF obligations. Every matrix run
uses ordinary `rig run`; the runner provisions the signed adapter into a
disposable copy, compiles with the repository-selected rustup toolchain,
launches the real application, sends authenticated HTTP traffic, collects
attempt-correlated runtime evidence, and seals and publishes the result.

Each completed matrix cell produced:

```text
TP=5 FP=0 FN=0 TN=5
requests=10/10 failed=0
sealed_transcripts=5
publication=FINAL coverage=COMPLETE
```

The locked fixtures are
[`axum-product`](../benchmarks/rust-framework-qualification-v1/axum-product)
and
[`actix-product`](../benchmarks/rust-framework-qualification-v1/actix-product).
They are qualification fixtures, not independent held-out applications.

## Actix Web boundary

Actix support covers explicit
`App::route(path, web::method().to(handler))` registrations, qualified
extractors, route middleware, the existing Rust sink observers, and
`HttpServer::bind` loopback enforcement. Attribute routes, dynamically composed
`service`/`configure` graphs, and unresolved resource/scope composition fail
closed and cannot contribute to `COMPLETE`.

The Actix adapter consumes and removes Rig's private request capability before
application code runs. It binds the grant to the exact route and method, emits
hook health before traffic so every capture member can certify, and preserves
target stdout/stderr on a mid-scan failure.

## Adjacent-version boundary

The Axum 0.8.8/0.8.9 × rustc 1.96.1/1.97.1 matrix proves compatibility for the
five authoritative runtime slices. It does not by itself promote the complete
43-category Rust family. A full exact Axum 0.8.8/rustc 1.96.1 BenchmarkRust run
completed in 344.3 seconds with 1,070 applicable requests, five explicit
transport exclusions, zero failed or unattempted applicable requests, 23 sealed
transcripts, all 117 runtime obligations resolved, and zero unexpected facts.
The 31 locked direct vulnerable cases were all found and none of the 31 safe
cases produced a finding.

The final result nevertheless remained `CANNOT_CERTIFY`: discovery retained 60
explicit unsupported facts, including the benchmark's deliberately ambiguous
controls plus unresolved extractor, merge, builder, macro, and typed-capture
shapes. Their sealed members therefore remained partial. This is a real
full-family capability blocker, not an adjacent-version accuracy pass, and the
five-minute local SLO was also missed.

Axum 0.8.8 and 0.8.9 retain one semantic catalog identity where their observed
response-body and redirect contracts are the same, but Rig verifies the exact
registry checksum for the installed patch. A lockfile containing some other
Axum patch cannot inherit either patch's authority.

The frozen unsupported-coordinate control was moved from Axum 0.8.8 to Axum
0.8.7 when 0.8.8 entered this matrix. The control still proves that an adjacent
but unqualified framework patch fails closed before product execution.

## Independent held-out gate

Independent held-out evidence is deliberately not checked into this repository
and was not available during this qualification. Rig therefore continues to
report the held-out promotion gate as unsatisfied. Promotion requires three
distinct external repository IDs, independently owned truth digests, vulnerable
and safe coverage across all 43 categories, authenticated product evidence,
`FINAL`, and `COMPLETE`. Checked-in Axum or Actix fixtures can never satisfy that
gate. See
[`BenchmarkRust held-out evidence`](../held-out/README.md).

## Reproduction

Install the exact toolchains, build Rig, and run the fixture normally:

```bash
rustup toolchain install 1.96.1 --profile minimal
rustup toolchain install 1.97.1 --profile minimal
cargo build --release --bin rig --manifest-path native-runtime/Cargo.toml

OUTPUT="$(mktemp -d /tmp/rig-rust-framework.XXXXXX)/result"
set +e
native-runtime/target/release/rig run \
  benchmarks/rust-framework-qualification-v1/actix-product \
  --framework actix-web \
  --output "$OUTPUT"
STATUS=$?
set -e
test "$STATUS" -eq 10
jq '{framework, runtime, coverage_verdict, finding_count, denominator}' \
  "$OUTPUT/rust-scan-result.json"
```

Exit 10 means the scan completed with findings. An unqualified framework,
runtime, ambiguous target, unresolved dynamic route, or unsafe build boundary
returns the stable fail-closed setup error instead of a clean result.
