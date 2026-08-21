# Rust-specific security coverage

Status: locked exact-coordinate tranche, Rust product promotion pending, version 1,
2026-08-15

This document records the Rust-specific security evidence implemented by ordinary
`sivere run` and BenchmarkRust. It is deliberately narrower than a claim of general
Rust memory-safety or software-supply-chain coverage.

## Exact evidence envelope

The locked tranche covers rustc 1.97.1, Axum 0.8.9, Tokio 1.53.1, the checksummed
BenchmarkRust lockfile, and Sivere's `rustc-mir-v1` adapter. Every runtime finding is
bound to an authenticated request attempt, source, handler, compiler-resolved sink
identity, runtime semantic property, sealed transcript, and final publication.

| Category | Vulnerable control proves | Safe control proves | Required grade |
| --- | --- | --- | --- |
| CWE-119 | A request-derived index violated the qualified memory-operation precondition | The operation used a bounded access | `RUNTIME_MEMORY` |
| CWE-125 | An out-of-bounds read precondition was reached and intercepted | The read used a checked lookup | `RUNTIME_MEMORY` |
| CWE-416 | A use-after-lifetime operation was attempted and intercepted | The use occurred while the allocation remained live | `RUNTIME_MEMORY` |
| CWE-787 | An out-of-bounds write precondition was reached and intercepted | The write used a checked mutable lookup | `RUNTIME_MEMORY` |
| RUST-UNSAFE-BLOCK | Request data violated the declared unsafe-operation contract | The unsafe boundary's precondition was checked | `RUNTIME_MEMORY` |
| RUST-FFI-BOUNDARY | Request data crossed the qualified C ABI boundary without its declared length contract | The maximum-length contract was enforced before the call | `RUNTIME_MEMORY` |
| RUST-PANIC-DOS | A request-derived value caused a real panic in the handler and Sivere contained the unwind | The equivalent parse used a fallible result | `RUNTIME_EFFECT` |
| CWE-400 | A request-controlled regular expression produced a bounded timeout or measured superlinear growth | The equivalent expression completed every bounded trial | `RUNTIME_EFFECT` |
| RUST-BUILD-RS-EXECUTION | A repository-local build script exists, its bytes were hashed, and Sivere blocked it before execution | The closed workspace inventory contains no local build script | `BUILD_PROVENANCE` |
| RUST-PROC-MACRO-EXECUTION | A repository-local proc macro exists, its bytes were hashed, and Sivere blocked it before execution | The closed workspace inventory contains no local proc macro | `BUILD_PROVENANCE` |

Every category also has an explicit ambiguous control that must remain `UNKNOWN`
and an adjacent-coordinate control that must remain `UNSUPPORTED`. A missing model
can never become a clean result.

## Memory and panic safety policy

Sivere does not perform undefined behavior to prove a memory weakness. The qualified
memory monitor evaluates the concrete request-derived index, allocation state, or
unsafe precondition and stops before an invalid raw access. The published statement
is therefore "the unsafe operation's precondition was violated and the monitor
blocked UB," not "memory corruption occurred." The safe controls execute checked
Rust operations and close their exact source/handler/sink obligations.

The panic control is different: it produces a real Rust panic under the concrete
request, catches the unwind at the instrumented boundary, records
`panic_observed=true` and `request_contained=true`, and lets the application remain
available for subsequent probes. The resource-exhaustion control uses bounded
regular-expression trials and reports only an observed timeout or superlinear
growth; it never permits an unbounded denial-of-service trial. Process aborts,
`panic=abort`, detached task panics, allocator corruption, Miri, ASan, memory
exhaustion, task/queue fan-out, and OS-level crash/resource effects are outside this
first envelope.

## Build and dependency provenance

Before Cargo can run repository code, Sivere writes `rust-build-provenance.json`. The
content-addressed report contains:

- every local `build.rs` and proc-macro manifest/source path that Sivere can resolve;
- a SHA-256 digest of each resolved executable source file;
- every `Cargo.lock` package name, version, source, checksum, and disposition;
- the lockfile digest, policy state, reason codes, and canonical receipt digest.

Resolved local build scripts and proc macros are `BLOCKED_UNTRUSTED`. A declared
source that is missing, symlinked, oversized, outside the repository, or otherwise
unreadable is `UNKNOWN`; Sivere does not ask Cargo to resolve or execute it. Registry
dependencies with lockfile checksums and workspace members are
`CONTENT_ADDRESSED`; unresolved Git or other non-checksummed sources remain
`UNKNOWN`.

An environment variable cannot grant build-execution authority. Until Sivere owns a
qualified and attested hermetic sandbox, any local build script or proc macro blocks
application launch with `native_rust_build_execution_containment_required`. The
provenance artifact is retained even for that blocked run. This detects and prevents
unreviewed compile-time execution; it does not by itself prove that the code is
malicious.

## Qualification result

The current BenchmarkRust ordinary-product projection records:

```text
Rust-specific tranche: TP=9 FP=0 FN=0 TN=9
unknown controls passed=9
unsupported controls passed=9
evidence-grade mismatches=0

Whole BenchmarkRust: TP=43 FP=0 FN=0 TN=43
publication_state=FINAL
coverage_verdict=CANNOT_CERTIFY
```

The ten remaining false negatives are controller-owned authorization,
authentication, CSRF, tenant-isolation, workflow, and concurrency categories. One
additional unresolved control is the pre-existing CWE-22 unknown case. Independent
held-out Rust applications are still absent, so Rust remains in `QUALIFICATION`.

## Deliberate remaining boundaries

This tranche does not yet claim broad recognition of arbitrary raw-pointer
arithmetic, inline assembly, custom allocators, native libraries, generated FFI
bindings, dependency-owned build scripts/proc macros, or all panic/resource paths.
Those require compiler/MIR pattern fan-out, native sanitizer or allocator evidence,
qualified ABI/model packs, a real build sandbox, and independent held-out
applications. Until each boundary is qualified, Sivere reports `UNKNOWN` or blocks the
build instead of issuing a clean result.

Reproduce the locked result with:

```console
make test-rust-benchmark
```

The benchmark architecture and broader promotion requirements are documented in
[BenchmarkRust qualification plan](benchmark-rust-plan.md).
