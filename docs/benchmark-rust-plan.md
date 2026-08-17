# BenchmarkRust qualification plan

Status: executable qualification benchmark, product promotion pending, version 1,
2026-08-15

BenchmarkRust is the promotion benchmark for Rust application support in Rig. It
is not a Rust translation of Python syntax fixtures. It preserves the security
question, evidence grade, negative control, and coverage obligation of the Python
ledger while using idiomatic Rust applications and real Rust providers.

## Qualification claim

The first promotion family remains intentionally exact, with adjacent
coordinates tracked as qualification evidence:

- rustc 1.96.1 and 1.97.1 on qualified hosts;
- Axum 0.8.8 and 0.8.9 with Tokio 1.53.1;
- Actix Web 4.14.1 as the second qualification framework;
- SQLx 0.8.6 and reqwest 0.12.28;
- a signed `rustc-mir-v1` build adapter and the matching runtime adapter/model
  pack.

A passing result means an arbitrary repository in this family can use ordinary
`rig run`, not a benchmark-only scanner. Rig must provision an immutable build,
discover and exercise the application, authenticate runtime evidence, seal every
capture, publish the final result, and close the declared denominator.

## Suite shape

BenchmarkRust has four independently reported layers:

1. **Language corpus.** Fully labeled, small Rust programs exercise each relevant
   source, transformation, sink, and safe usage. Every category has vulnerable,
   safe, unknown, and unsupported controls.
2. **Framework product application.** One ordinary multi-route Axum repository is
   run with `rig run`. It covers routing, extractors, middleware, state, async
   propagation, response construction, and the first real provider coordinates.
   Compiler-shape routes require runtime findings through aliases, stored/client
   builders, generics, traits, declarative-macro helper expansion, literal
   generated source, active features, and propagated Tokio spawn context.
3. **Hostile-build corpus.** Workspaces contain lockfile spoofing, path
   dependencies, build scripts, proc macros, symlinks, conflicting wrappers,
   feature-dependent sinks, generated code, and resource-budget attacks. They
   must be safely contained or rejected before authority is claimed.
4. **Held-out applications.** At least two third-party Axum applications and one
   independently authored application remain unavailable to adapter/model
   development until scoring.

The checked-in suite under `benchmarks/benchmark-rust-v1` implements all 172
language controls, the framework foundation, hostile controls, deterministic
replay, resource budgets, and the native product-evidence scorer. The full Make
target now invokes the framework application through ordinary `rig run`, verifies
its signed publication, and conservatively projects the retained product score.
A retained scorecard cannot promote Rust until the product and held-out layers
close all 172 controls at the required evidence grades.

Both the corpus and product fixture are built with `cargo +1.97.1`. The corpus
embeds the compiler and host triple into its scorer input; an adjacent/default
toolchain cannot satisfy the exact-coordinate gate.

## Cross-language denominator

Every category in `python_parity_categories` from the native language support
policy is required. The truth manifest classifies each one as:

- `DIRECT`: the same security statement applies directly in Rust;
- `ADAPTED`: the statement applies through Rust-specific APIs or ownership;
- `CONTROLLER`: Rig's language-neutral journey engine owns the decision, but the
  Rust target must still supply complete routes, sessions, state, and evidence;
- `NOT_APPLICABLE`: allowed only with a reviewed proof explaining why the entire
  exact coordinate cannot express the behavior. An absent model is never
  not-applicable.

Rust-specific additions include unsafe/FFI memory boundaries, panic denial of
service, build-script and proc-macro execution, and dependency/build provenance.
They are additive and cannot compensate for a missing Python-parity category.

## Required controls per category

Each promoted category needs all four control types:

| Control | Required result |
| --- | --- |
| Vulnerable | Published finding with the declared evidence grade and exact site |
| Safe | No finding for the fully exercised obligation |
| Unknown | `UNKNOWN`/incomplete with the declared capability reason |
| Unsupported | Fail closed before a clean or vulnerable claim |

All emitted categories are scored. A finding outside the locked truth is a false
positive, not an ignored side result. Missing, duplicate, unlocalized, or
unresolved cases prevent `COMPLETE`.

## Executable slices

The corpus is organized in this order:

1. Axum literal and nested route discovery; query/path/form/JSON/header/cookie,
   multipart, bounded raw-body, middleware, extension, and authenticated-principal
   sources; dynamic route, unread multipart, arbitrary raw request, and ambiguous
   provider controls.
2. SQLx raw statement versus bound data, including grammar/string/comment/
   identifier placement and unknown builders.
3. Standard/Tokio process and filesystem boundaries, including shell versus argv,
   containment, symlink, and stored-builder controls.
4. reqwest destination control, redirects, DNS/connect/TLS/proxy phases, and OOB
   receipt controls.
5. Axum HTML output contexts and encoding, followed by templates and response
   middleware.
6. Nineteen Python-equivalent semantic categories, documented in
   [Rust Python-equivalent semantic coverage](rust-python-semantic-parity.md).
7. Rust-specific memory, FFI, panic and content-addressed build-provenance
   categories.
8. The remaining controller-owned categories from the locked manifest.

Slice 8 now executes through the ordinary Rust product path. Its exact policy,
evidence, safe-negative, and failure contracts are documented in
[`Rust controller-owned security coverage`](rust-controller-security-coverage.md).

All four-way language controls are executable, but their in-process semantic
oracle is foundation evidence rather than product evidence. The current product
adapter produces authoritative runtime evidence for the first five slices, the
19 categories in slice 6, all nine Rust-specific categories in slice 7, and all
ten controller-owned categories in slice 8. It does not lower the denominator or
convert an unexecuted safe case into a true negative.

The locked projector maps the current Axum routes for the first five slices and
the 19 Python-equivalent semantic categories. It accepts a positive only from a
matching published rule, route, sink family, and required evidence grade. A safe
result requires the exact stable
`(route, handler, source, sink)` obligation to be resolved in authenticated
campaign coverage and no matching route finding. An unknown case requires an
explicit discovery capability reason. Publication and developer artifact
signatures are verified before any observation is scored. The
unqualified-coordinate repository is also executed through ordinary `rig run`;
its exact fail-closed error is projected into the 43 unsupported controls.

The current ordinary-product classification score is 43 TP / 0 FP / 0 FN /
43 TN, with all 43 expected unknown controls projected, zero evidence-grade
mismatches, and zero unresolved controls. The raw product envelope remains
`CANNOT_CERTIFY` because the benchmark deliberately contains truth-declared
unsupported semantic coordinates. This is an accuracy checkpoint, not Rust
promotion: an ordinary closed product envelope and the independently held-out
applications must still pass before `COMPLETE` and `promotion_eligible=true`.

Build-script and proc-macro qualification is pre-execution evidence. Rig hashes
resolved local executable source and blocks it, inventories the lockfile's package
source/checksum coordinates, and retains the canonical provenance receipt. Missing
or unsafe source is `UNKNOWN`. The benchmark never runs a hostile `build.rs` or
proc macro to manufacture an effect.

Source breadth is a separate non-score product gate. Eleven `/sources/*` routes
must preserve logical source identity, map to the exact generated wire transport,
produce attempt-correlated runtime findings, and appear in the signed v3
instrumentation inventory. In particular, a principal remains a `principal`
source while its marker is delivered through its compiler-proven identity header.
The source gate cannot change a TP/TN count and rejects product evidence when any
shape is missing. See [Rust Axum source coverage](rust-axum-source-coverage.md).

## Product-path requirements

For each ordinary application run, qualification verifies:

- exact Git/tree, Cargo.lock, feature, profile, target, rustc, adapter, and model
  pack identities;
- no repository mutation and an enforceably disposable build directory;
- request-capability issuance/consumption and attempt/fence correlation;
- producer registration, completion acknowledgement, sealed event storage, and
  capture-chain verification;
- deterministic controller frames, inventories, journeys, transcripts, reduction,
  coverage, publication, authenticated readback, JSON, SARIF, and Markdown;
- `FINAL`, `COMPLETE`, zero failed required requests, zero unexpected facts, and
  zero unresolved obligations.

The benchmark runner may orchestrate repeated ordinary `rig run` commands. It may
not call private discovery or instrumentation functions to obtain a better score.

## Scoring and promotion

The primary score is exact truth by `(category, repository path, sink identity)`.
Line numbers are display metadata, not the sole identity. Reports include TP, FP,
FN, and TN per category, evidence-grade mismatches, discovery/coverage mismatches,
unexpected findings, resource use, and cold/warm duration.

Rust promotion requires:

- every inherited and Rust-specific category represented by four control types;
- zero known FP and FN in the locked and held-out suites;
- every positive at the required evidence grade;
- all hostile-build and resource-budget controls passing;
- deterministic replay and identical semantic score on both initial hosts;
- ordinary `rig run`, sealed transcripts, authenticated readback, `FINAL`, and
  `COMPLETE`;
- no Python, Node, or Go prerequisite for the controller or benchmark scorer.

Until then, the suite state is `QUALIFICATION`, never `QUALIFIED`. This means the
benchmark is complete enough to measure the product, not that the product has
passed it.

The adjacent Axum coordinate matrix and the Actix five-slice result are
documented in
[`Rust web-framework coordinate qualification`](rust-framework-coordinate-qualification.md).
Those runs do not satisfy the independent held-out gate, and the full adjacent
BenchmarkRust application currently exceeds its five-minute qualification SLO.

## Version fan-out

Adjacent rustc, Tokio, Axum, and provider versions are grouped only when
compiler-hook, public-API, async-context, and semantic signatures are shown
equivalent. Axum 0.8.8/0.8.9 across rustc 1.96.1/1.97.1 has passed the five-slice
product matrix; the 43-category family and both supported hosts remain separate
promotion gates. Actix Web 4.14.1 has passed its first exact product slice and
remains qualification-only. Rocket, Warp, and generic Hyper follow. Any changed
hook signature creates a new family and returns affected cases to unsupported
until requalified.
