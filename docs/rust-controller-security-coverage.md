# Rust controller-owned security coverage

Status: implemented qualification slice, 2026-08-15

Rust targets use Rig's language-neutral controller for policy and protocol
categories. The Rust adapter supplies exact Axum route discovery, launch, session
traffic, request timing, and authenticated publication; the controller owns the
security decision. No Rust source-to-sink finding is substituted for a policy
differential or stateful protocol observation.

## Qualified category contract

The pinned `rustc 1.97.1` / Axum 0.8.9 product application exercises vulnerable,
safe, unknown, and unsupported controls for these ten categories:

| Category | Published rule | Authoritative evidence |
| --- | --- | --- |
| CWE-284 improper access control | `RIG.ACCESS_CONTROL.IMPROPER` | Authorized identity succeeds; identity that policy says must be denied receives an equivalent protected result. |
| CWE-287 improper authentication | `RIG.AUTHENTICATION.IMPROPER` | Valid session succeeds; explicitly invalid credential is accepted for the same operation. |
| CWE-306 missing authentication | `RIG.AUTHENTICATION.MISSING` | Authenticated session succeeds; isolated anonymous session receives the same protected result. |
| CWE-352 CSRF | `RIG.CSRF.MISSING_OR_INVALID` | Valid session and acquired token succeed; the isolated session succeeds after Rig omits the token. |
| CWE-639 tenant isolation | `RIG.AUTHORIZATION.CROSS_TENANT` | Owning tenant succeeds; a separately authenticated foreign tenant receives the same resource. |
| CWE-862 missing authorization | `RIG.AUTHORIZATION.MISSING` | Authorized control succeeds; the declared unauthorized identity succeeds. |
| CWE-863 incorrect authorization | `RIG.AUTHORIZATION.INCORRECT` | Required role succeeds; an insufficient role receives the protected operation. |
| CWE-840 business-limit bypass | `RIG.BUSINESS_LOGIC.LIMIT_BYPASS` | Valid lane succeeds; the declared over-limit lane succeeds with the required terminal equivalence. |
| CWE-362 race condition | `RIG.CONCURRENCY.RACE_CONDITION` | Prepared requests are released together, successes exceed the declared limit, and a postcondition oracle independently reports violation. |
| CWE-841 multi-service workflow | `RIG.MULTI_SERVICE.FORBIDDEN_INTERACTION` | A positive-control downstream call reaches a capability-authenticated witness; the forbidden subject correlation reaches that same method and path. |

The engine also retains the existing CWE-639 direct-object rule
`RIG.AUTHORIZATION.BROKEN_OBJECT_LEVEL` as a distinct product claim. The locked
BenchmarkRust CWE-639 row qualifies tenant-boundary enforcement; it does not use
that separate IDOR claim to earn the same score twice.

## Configuration and execution

The ordinary `rig run` path loads `.rig.json` once and constructs controller
journeys after framework discovery. Every selector must resolve to an
authoritative discovered route. Rig then:

1. creates isolated identity sessions using declared login policies;
2. acquires and injects CSRF tokens for positive controls, or deliberately omits
   them for a declared CSRF subject;
3. runs authorization/control lanes with fixed resource and tenant identities;
4. runs business lanes in declared order;
5. prepares 2–32 concurrency requests before releasing them through one native
   barrier, then invokes the application-owned state oracle; and
6. starts capability-authenticated loopback witnesses, injects only their
   generated origin/capability into the disposable target, and correlates exact
   downstream method/path interactions by digests.

Controller probes are signed into the campaign and request denominator but do
not receive IAST marker capabilities. This prevents a declared policy identifier
from being projected as a runtime taint flow.

## Safe controls and fail-closed behavior

A safe control is an authoritative true negative only when its exact obligation
is resolved:

- the positive control completed;
- the subject received a recognized denial, or remained absent from the verified
  downstream witness as required;
- concurrency worker outcomes were all recognized and the state oracle agreed;
- every expected controller obligation appears in the report's resolved set;
- the controller report is digest-valid, byte-equal to its embedded publication,
  `COMPLETE`, and has no unresolved obligations; and
- the overall campaign remains authenticated and final.

Missing routes, failed login/token bootstrap, timeouts, unrecognized statuses,
failed positive controls, body-equivalence ambiguity, conflicting concurrency
facts, missing service witnesses, or model/configuration gaps become `UNKNOWN`.
They cannot produce a clean decision. An unsupported compiler/framework
coordinate fails before target execution.

Unknown benchmark controls are not synthetic clean results. They verify that the
published policy requires an explicit declared policy or invariant; undeclared
roles, tenants, business rules, and downstream expectations therefore remain
capability gaps.

## Evidence and artifacts

`rig run` publishes:

- `authorization-report.json` with exact kind, weakness, test, resource,
  identities, statuses, body equivalence, decision, and obligation;
- `workflow-security-report.json` with ordered lane results, synchronized worker
  outcomes, state-oracle result, or capability-authenticated interaction digests;
- findings using the exact rule/CWE mapping above; and
- the reports under the signed final Rust scan result and developer artifact
  manifest.

BenchmarkRust reads these product artifacts back through the ordinary public
result. It does not call planner or grader internals. A vulnerable case requires
the exact resolved decision and matching published finding; a safe case requires
the exact enforcement decision; an unknown requires the explicit fail-closed
policy.

## Boundaries

Rig does not infer arbitrary roles, object ownership, tenant membership,
business limits, valid workflow order, or forbidden downstream effects from
source code. Those are application policy and must be declared or supplied by a
future independently qualified policy-discovery component. HTTP is the qualified
multi-service witness protocol in this slice; Kafka, AMQP, gRPC, WebSocket,
service-mesh, cache, and cloud-provider effects remain unsupported until they
have protocol-specific authenticated witnesses.

The executable reference is
`benchmarks/benchmark-rust-v1/apps/axum-product/.rig.json`. The cross-language
controller specification is
[`Workflow, concurrency, and multi-service security`](workflow-concurrency-multiservice-security.md).
