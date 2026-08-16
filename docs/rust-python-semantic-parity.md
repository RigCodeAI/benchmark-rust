# Rust Python-equivalent semantic coverage

Status: qualified tranche, Rust product promotion pending, version 1, 2026-08-15

This document records the Python-equivalent sink and semantic categories that
Rig's exact Rust/Axum family supports through the ordinary `rig run` product
path. It is a capability boundary, not a claim that Rust support is fully
qualified.

The tranche adds 19 categories to the five existing SQL, process, filesystem,
HTML, and outbound HTTP slices. BenchmarkRust now retains 24 authoritative
positives and 24 authoritative safe controls. Nine additional Rust-specific
categories are documented separately; ten controller-owned categories remain
incomplete, so Rig correctly publishes `CANNOT_CERTIFY` and Rust remains in
`QUALIFICATION`.

## Exact family

The evidence below is qualified only for the checksummed Cargo.lock coordinates
in BenchmarkRust:

- rustc 1.97.1, Axum 0.8.9, and Tokio 1.53.1;
- `http` 1.5.0, `maud` 0.27.0, `minijinja` 2.13.0, and `tracing`
  0.1.44;
- `md5` 0.8.1, `sha2` 0.10.9, `fastrand` 2.3.0, and `rand` 0.9.2;
- `fancy-regex` 0.19.0, `cookie` 0.18.2, and `serde_json` 1.0.108;
- `libxml` 0.3.21, `sxd-document` 0.3.2, and `sxd-xpath` 0.4.2;
- `ldap3` 0.11.5, `rhai` 1.25.1, `redis` 0.32.7, and reqwest
  0.12.28.

The compiler fact graph must resolve the exact call and the package name,
version, registry source, and checksum must match. A syntactically similar local
crate, path dependency, adjacent version, unresolved dynamic boundary, or
unsupported call shape produces an explicit capability gap. It cannot produce a
finding, a true negative, or `COMPLETE`.

## Category ledger

| CWE | Security statement | Qualified Rust boundary | Required evidence |
| --- | --- | --- | --- |
| CWE-113 | Request input retained response-header structure | `http::HeaderValue::from_str` | Runtime semantic structure |
| CWE-116 | Active HTML was emitted without the required encoding | `maud::PreEscaped`; encoded control | Runtime semantic encoding |
| CWE-1336 | Request input became template source and was evaluated | `minijinja::Environment::render_str` | Runtime semantic evaluation |
| CWE-200 | Sensitive canary crossed a response boundary | `axum::body::Body::from` | Runtime value flow |
| CWE-201 | Sensitive canary crossed an outbound boundary | `reqwest::Body::from` | Runtime value flow |
| CWE-328 | A weak hash algorithm was used | `md5::compute`; SHA-256 control | Runtime property |
| CWE-330 | A non-cryptographic generator was used | `fastrand::u64`; `rand::random` control | Runtime property |
| CWE-400 | Source-controlled regex caused pathological engine work | qualified `fancy-regex` evaluation | Runtime effect |
| CWE-501 | Untrusted request data crossed a session trust boundary | `Cookie::new`; digested control | Runtime value flow/property |
| CWE-502 | A custom deserializer performed an application effect | `serde_json::from_str` into the qualified custom type | Runtime semantic policy |
| CWE-532 | Sensitive canary crossed a logging boundary | `tracing::Span::record` | Runtime value flow |
| CWE-601 | Request input controlled a redirect target | `axum::response::Redirect::temporary` | Runtime semantic target control |
| CWE-611 | The exact parser resolved an external entity | `libxml2` parse with `XML_PARSE_NOENT`; `sxd-document` control | Runtime effect |
| CWE-614 | A session cookie was emitted without `Secure` | `cookie::CookieBuilder::build` | Runtime property |
| CWE-643 | Request input became XPath grammar | `sxd_xpath` evaluation; constant expression control | Runtime semantic structure |
| CWE-776 | The exact parser expanded the entity graph | `libxml2` entity substitution; `sxd-document` control | Runtime effect |
| CWE-90 | Request input became LDAP filter grammar | `ldap3::parse_filter`; `ldap_escape` control | Runtime semantic structure |
| CWE-94 | Request input became executable code and evaluation succeeded | `rhai::Engine::eval`; scoped-data control | Runtime effect |
| CWE-943 | Request input became a NoSQL command/operator | `redis::cmd`; literal command control | Runtime semantic structure |

Sensitive response, outbound, and log findings remain distinct product rules.
Logging APIs include explicit logging coordinates and tracing record boundaries;
they are not projected as outbound disclosure.

## Evidence and safe-control policy

Every positive is correlated to a real request attempt, source, handler, exact
runtime sink, and semantic property or observed effect. In particular:

- ReDoS uses `fancy-regex`'s real backtracking VM and observes its configured
  runtime backtrack limit. Nested syntax alone is not sufficient.
- XXE reads a scanner-owned local canary through the qualified libxml2 parser.
- XML expansion compares concrete parser output with the input entity graph.
- dynamic code requires the exact evaluator to accept and execute the script;
- LDAP and NoSQL distinguish grammar/operator placement from escaped or literal
  data; and
- weak algorithms and cookie attributes are exact runtime properties, so they do
  not require a separate exploit payload.

A safe result is authoritative only when the exact safe boundary ran, emitted its
negative semantic property where applicable, and its route/source/sink
obligation closed without a matching finding. A source marker that disappeared
without a recognized protection is not automatically safe.

Each category also has an ambiguous boundary. The compiler records it as an
explicit category-specific capability gap, and the benchmark requires `UNKNOWN`.
This prevents an incomplete semantic model from becoming a clean result.

## Qualification result

The ordinary product qualification run produced:

```text
tranche: TP=19 FP=0 FN=0 TN=19
whole current benchmark: TP=43 FP=0 FN=0 TN=43
evidence_grade_mismatches=0
publication_state=FINAL
coverage_verdict=CANNOT_CERTIFY
```

The retained path used 422 planned requests, 417 attempted requests, 23 sealed
transcripts, authenticated readback, and final native publication. Five planner
entries are transport-unrepresentable controls, not failed requests.

The Rust memory/build-provenance tranche is now closed separately. The remaining
false negatives belong to controller-owned authorization, authentication,
workflow, and concurrency slices. They are intentionally visible in the locked
denominator. Rust cannot be promoted until those categories, the held-out
applications, and adjacent-host requirements all pass with `FINAL` and
`COMPLETE`.

## Reproduction

Run the complete contract with:

```console
make test-rust-benchmark
```

For the ordinary product path and projector commands, see the
[BenchmarkRust README](../benchmarks/benchmark-rust-v1/README.md). The native
semantic registry is implemented in
`native-runtime/crates/language/src/rust_discovery/semantic_sinks.rs`; runtime
observations are emitted by
`native-runtime/crates/rust-runtime-adapter/src/rust_semantic.rs`.
