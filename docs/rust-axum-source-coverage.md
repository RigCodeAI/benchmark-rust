# Rust Axum source coverage

Status: implemented qualification envelope, version 1, 2026-08-15

Rig's first Rust target family discovers and drives the following Axum 0.8.9
request sources through ordinary `rig run` on rustc 1.97.1. Discovery is bound to
compiler facts from the exact disposable Cargo build; campaign traffic and runtime
findings remain bound to the signed attempt capability.

| Logical application source | Qualified Axum shape | Generated transport |
| --- | --- | --- |
| Query | `Query<T>` with string-bearing named struct fields or a supported scalar | URL query field |
| Path | `Path<T>` with route placeholders or string-bearing fields | Percent-encoded path segment |
| Form | `Form<T>` with string-bearing fields | URL-encoded form field |
| JSON | `Json<T>` with string-bearing fields | JSON object field |
| Header | `HeaderMap` with a literal `get`, `get_all`, index, or `contains_key` | HTTP header value |
| Cookie | `CookieJar` with a literal lookup | Cookie value |
| Multipart | `Multipart` consumed with `next_field()` | Deterministic multipart text field named `value` |
| Body stream | bare `String`, `Bytes`, or `Body` handler input | Bounded raw `text/plain` body |
| Middleware value | `Extension<T>` inserted by registered `from_fn` middleware from one literal request header | Compiler-bound header |
| Application extension | `Extension<T>` inserted by registered `from_fn` middleware from one literal request header | Compiler-bound header |
| Authenticated principal | principal/identity/claims-shaped `Extension<T>` inserted by registered middleware from one literal request header | Compiler-bound identity header |

The extension cases preserve two identities. The logical identity is what the
handler consumes (`middleware`, `extension`, or `principal`); the physical
transport is the exact request header proven to construct it. Both identities and
the middleware derivation are retained in discovery, campaign, and instrumentation
artifacts. A principal source proves that a request-derived identity reached the
handler. It does not, by itself, prove that the middleware authenticated the
credential or that authorization policy is correct; those are controller-owned
differential obligations.

## Fail-closed boundaries

Rig does not claim these shapes from source spelling alone:

- An `Extension<T>` without a uniquely registered, compiler-inventoried provider
  is unresolved.
- Middleware with multiple candidate request inputs, headers, or inserted types is
  unresolved rather than guessed.
- `Request<Body>` field-by-field extraction remains unresolved. Qualified raw-body
  inputs are the direct `String`, `Bytes`, and `Body` handler forms.
- Multipart handlers that do not consume `next_field()` have no invented source.
  Named-file selection, filenames, content types, file bytes, and mixed field/file
  policies require separate qualification.
- Dynamic router construction or middleware graphs that the compiler adapter
  cannot bind keep discovery and coverage incomplete.
- Database/session-loaded principals, signed-token claims, cookie-derived
  identities, multi-stage middleware transformations, custom extractors, and
  arbitrary `FromRequest` implementations remain capability gaps.
- `TypedHeader<T>` names are inventoried as candidates, but do not earn this
  source-breadth qualification until their exact `axum-extra` feature coordinate
  and runtime fixture are added to BenchmarkRust.
- Raw request and body reads remain subject to campaign limits; an oversized or
  ambiguous body cannot contribute to `COMPLETE`.

If generated traffic does not enter the handler, correlate to its attempt, and
reach an eligible runtime sink, the obligation remains unresolved.

## Qualification

BenchmarkRust contains eleven non-score source-shape routes. Its native projector
requires every route to have the expected logical source, physical transport,
runtime finding, and signed instrumentation inventory. It also requires a
non-empty authentication declaration for the principal route. The routes cover
query, path, form, JSON, header, cookie, multipart, raw body, middleware-derived
values, extension-derived values, and authenticated principals.

The source-shape gate is additive to the locked five-CWE score. It cannot improve
that score by expectation injection: a missing source, transport binding, runtime
finding, or instrumentation fact rejects product evidence before scoring.
