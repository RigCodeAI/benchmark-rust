# BenchmarkRust hostile and fail-closed controls

These repositories test behavior that must never inherit authority from a
similar-looking supported application:

- `dynamic-route` uses runtime-selected route text. MIR call/type resolution does
  not invent a canonical path, so it remains explicitly unresolved.
- `provider-spoof` supplies repository-local crates named like qualified SQLx
  and reqwest releases. Package names and versions alone must not grant support.
- `unqualified-coordinate` uses an adjacent Axum version and must fail closed.
- repository-local literal `include!` source and active Cargo features are now
  positive compiler-shape cases in the ordinary Axum product. `OUT_DIR`
  generation and direct arbitrary macro sinks remain separate fail-closed
  boundaries.
- `build-script` and `proc-macro` contain resolvable local compile-time code. The
  production provenance inspector hashes that code and blocks it without asking
  Cargo to execute it.
- `build-provenance-unknown` and `proc-macro-provenance-unknown` declare missing
  executable source. They must remain explicit provenance `UNKNOWN` controls.

The ordinary Axum product is the negative build/proc-macro control: its complete
workspace inventory contains neither local executable boundary and every locked
dependency has content-addressed provenance. An environment variable cannot turn
one of the hostile controls into a qualified sandbox.

The native benchmark additionally bounds truth and source sizes, rejects
symlinks and path escapes, runs the language-corpus executable with a five-second
deadline and empty environment, and performs deterministic discovery twice.
Passing these controls qualifies the benchmark harness—not the Rust product
adapter.
