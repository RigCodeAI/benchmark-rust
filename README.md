# BenchmarkRust v1

BenchmarkRust is the complete qualification benchmark for Rig's first Rust
target family:

```text
rustc 1.97.1
Axum 0.8.9
Tokio 1.53.1
SQLx 0.8.6
reqwest 0.12.28
```

The benchmark is complete; Rust product support is not yet qualified. That
distinction is enforced in the retained report instead of being left to prose.

The suite locks 43 categories and four controls per category:

| Control | Required product result |
| --- | --- |
| Vulnerable | `FINDING` at the category's required evidence grade |
| Safe | `CLEAN` with a closed denominator |
| Unknown | `UNKNOWN` with an explicit capability gap |
| Unsupported | `UNSUPPORTED` for the exact unqualified coordinate |

All 172 controls are implemented by the native language corpus. The independent
scorer additionally requires ordinary product evidence, held-out applications,
sealed transcripts, authenticated readback, deterministic replay, hostile-input
containment, `FINAL`, `COMPLETE`, and zero false positives or false negatives
before setting `promotion_eligible=true`.

## Run the complete benchmark contract

```console
make test-rust-benchmark
```

This builds the native Rig binary, builds and executes the 172-case language
corpus with the pinned Rust 1.97.1 toolchain, compiles the exact Axum application
with that same toolchain, runs the application through ordinary `rig run`,
verifies the signed publication and compiler-shape runtime findings, projects only evidence-backed benchmark cases,
runs discovery twice, exercises the hostile/fail-closed controls, and writes:

```text
benchmarks/benchmark-rust-v1/qualification-report-v2.json
```

The current expected contract result is:

```text
required_categories=43
required_controls=172
built_controls=172
planned_controls=0
corpus_complete=true
corpus_executed=true
corpus_runtime_coordinate=rustc-1.97.1-<qualified-host>
foundation_conformance_passed=true
deterministic_replay_passed=true
hostile_repository_passed=true
resource_budgets_passed=true
ordinary_product_path_passed=false
sealed_transcripts_verified=true
authenticated_readback_verified=true
publication_state=FINAL
coverage_verdict=CANNOT_CERTIFY
promotion_eligible=false
```

The current ordinary-product score is:

```text
TP=43 FP=0 FN=0 TN=43
unknown_controls_passed=42
unsupported_controls_passed=43  # after the required fail-closed control run
evidence_grade_mismatches=0
unresolved=1
```

The same ordinary product run must also prove these compiler-backed shapes before
the scorer accepts its evidence:

- imported call aliases;
- stored process and reqwest client builders;
- generic and trait helper dispatch;
- declarative macros expanding to instrumented helpers;
- literal repository-local generated source;
- active-feature inclusion and inactive-feature exclusion;
- `Html<String>` variable bodies; and
- request-context propagation across `tokio::spawn`.

It must additionally prove eleven Axum request-source shapes end to end:

- query, path, form, JSON, literal header, and literal cookie values;
- stream-all multipart text, plus a bounded raw body;
- a middleware-derived value and an application extension, each bound to its
  exact physical request header; and
- an authenticated-principal-shaped extension whose logical principal identity is
  preserved separately from its `Authorization` transport.

For every shape, the projector requires matching compiler discovery, generated
traffic, a route-bound runtime finding, and the signed instrumentation inventory.
These are qualification obligations rather than extra CWE score rows. Unsupported
or ambiguous extractor/provider shapes fail closed as described in
[`docs/rust-axum-source-coverage.md`](docs/rust-axum-source-coverage.md).

The scorer checks retained `rust-compiler-facts.json` and
`rust-instrumentation-report.json` against the runtime findings. Merely
inventorying these shapes cannot pass.

The same run writes `rust-build-provenance.json` before Cargo can execute target
code. The scorer requires deterministic readback for the safe build/proc-macro
controls and uses the identical non-executing inspector for vulnerable and unknown
controls. Local executable build code is hashed and blocked; missing source remains
`UNKNOWN`. It is never executed by the qualification harness.

It is intentionally not promoted. The current Rust adapter closes the first five
vertical slices—CWE-22 path traversal, CWE-78 command injection, CWE-79 XSS,
CWE-89 SQL injection, and CWE-918 SSRF—plus 19 Python-equivalent semantic
categories and nine Rust-specific runtime/build-provenance categories, with one
authoritative positive and one authoritative safe control per slice. Those
categories and their exact coordinates are documented in
[`docs/rust-python-semantic-parity.md`](docs/rust-python-semantic-parity.md)
and
[`docs/rust-specific-security-coverage.md`](docs/rust-specific-security-coverage.md).
The compiler-shape routes add qualification obligations without being counted as
new CWE score rows; deliberately unresolved provider/macro and semantic shapes
remain explicit `UNKNOWN` controls. Controller-owned authorization,
authentication, CSRF, tenant-isolation, workflow, concurrency, and multi-service
cases execute through the same ordinary product path and are documented in
[`docs/rust-controller-security-coverage.md`](docs/rust-controller-security-coverage.md).
Independent held-out evidence also remains unavailable by design. The benchmark
therefore measures the product honestly instead of converting the executable
language corpus's expected answers into product evidence.

The target host must have the `1.97.1` rustup toolchain installed. The Make target
uses `cargo +1.97.1` explicitly, and the corpus embeds its actual compiler/host
coordinate. The scorer rejects a binary built by an adjacent compiler or for an
unqualified host; `rust-version` alone is not treated as exact-coordinate proof.

## Score ordinary product evidence

The ordinary product path normalizes its authenticated publications into
`rig-benchmark-rust-product-evidence/v1`. The normalizer is not allowed to infer
truth; it verifies the campaign signature and developer artifact manifest, then
projects only case-bound findings, closed negative obligations, and explicit
capability gaps from retained product artifacts.

To reproduce the locked application projection directly:

```console
RUN_ROOT="$(mktemp -d /tmp/rig-benchmark-rust.XXXXXX)"

set +e
native-runtime/target/release/rig run \
  benchmarks/benchmark-rust-v1/apps/axum-product \
  --output "$RUN_ROOT/scan"
STATUS=$?
set -e

# Exit 10 means a completed scan with findings.
test "$STATUS" -eq 10

set +e
native-runtime/target/release/rig run \
  benchmarks/benchmark-rust-v1/controls/unqualified-coordinate \
  --output "$RUN_ROOT/unsupported-scan" \
  2> "$RUN_ROOT/unsupported-result.json"
UNSUPPORTED_STATUS=$?
set -e

# Exit 30 is the required fail-closed decision for an unqualified coordinate.
test "$UNSUPPORTED_STATUS" -eq 30

native-runtime/target/release/rig benchmark-rust \
  --suite benchmarks/benchmark-rust-v1 \
  --corpus-executable \
    native-runtime/target/benchmark-rust-corpus/release/rig-benchmark-rust-language-corpus \
  --scan-result "$RUN_ROOT/scan/rust-scan-result.json" \
  --unsupported-result "$RUN_ROOT/unsupported-result.json" \
  --projected-evidence-output "$RUN_ROOT/product-evidence.json" \
  --output "$RUN_ROOT/qualification.json"
```

The projector is deliberately conservative: a safe case is emitted only when its
exact `(route, handler, source, sink)` obligation appears in authenticated
campaign coverage as resolved and the route has no matching finding. It does not
require unrelated, unimplemented categories to be complete before recognizing
that slice-specific TN. A positive receives only the evidence grade actually
supported by the finding, and a missing case remains a false negative or
unresolved obligation.

Preprojected immutable evidence can still be scored with `--product-evidence`:

```console
native-runtime/target/release/rig benchmark-rust \
  --suite benchmarks/benchmark-rust-v1 \
  --corpus-executable \
    native-runtime/target/benchmark-rust-corpus/release/rig-benchmark-rust-language-corpus \
  --product-evidence /immutable/run/benchmark-rust-product-evidence.json \
  --held-out-evidence /immutable/held-out-a/evidence.json \
  --held-out-evidence /immutable/held-out-b/evidence.json \
  --held-out-evidence /immutable/held-out-c/evidence.json \
  --require-promotion \
  --output /immutable/run/benchmark-rust-qualification.json
```

`--require-promotion` exits 30 until every authority gate passes. Without that
flag, the command exits successfully when the benchmark harness itself is
complete and deterministic, while the report still exposes product gaps.

The accepted evidence envelope is defined by
[`product-evidence-v1.schema.json`](product-evidence-v1.schema.json). Evidence is
bound to its canonical SHA-256 digest. The scorer rejects missing and duplicate
case IDs, unrecognized findings, insufficient evidence grades, failed requests,
unexpected facts, unresolved obligations, open coverage, and non-final
publication.

## Layers

1. `corpus/language` executes vulnerable, safe, unknown, and unsupported
   semantic controls for every category without Python or another language
   runtime.
2. `apps/axum-product` is the exact-coordinate framework application used by
   ordinary `rig run` qualification.
3. `controls` contains dynamic discovery, provider-spoofing, adjacent-coordinate,
   custody, determinism, and resource-budget checks.
4. `held-out` defines the independent evidence gate. Checked-in fixtures can
   never satisfy it.

The source, manifests, and lockfiles are content-bound in `truth-v1.json`.
Generated Cargo `target` directories and mutable live-run artifacts are never
retained inside the corpus.

The architecture and promotion policy are documented in the
[BenchmarkRust qualification plan](docs/benchmark-rust-plan.md).
