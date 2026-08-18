# Scanner integration

## SARIF 2.1.0

Each SARIF result supplies its category in `properties.category`, its CWE in
`properties.cwe`, or in a `ruleId` containing `CWE-<number>`. Language-specific
categories such as `RUST-FFI-BOUNDARY` use `properties.category`. Every result
must also supply one matchable identity:

```json
{
  "ruleId": "MYTOOL/CWE-89",
  "message": {"text": "SQL injection"},
  "properties": {
    "cwe": "CWE-89",
    "route": "/sql/raw"
  }
}
```

SAST integrations may instead provide `properties.benchmark_case_id` plus a
standard SARIF physical location. The public case catalog documents stable IDs,
routes, repository paths, and logical source/sink locations.

## Generic JSON

JSON uses `schemas/scanner-results-v1.schema.json`:

```json
{
  "schema_version": "security-benchmark-scanner-results/v1",
  "benchmark_id": "suite-id-from-benchmark.yaml",
  "tool": {"name": "My Scanner", "version": "1.2.3", "kind": "SAST"},
  "findings": [
    {"category": "CWE-89", "route": "/route", "rule_id": "MY.SQL"}
  ]
}
```

## CSV

CSV headers are:

```text
category,case_id,route,path,line,rule_id
```

`category` is required. At least one of `case_id`, `route`, or `path` is required.
RFC-style quoted commas and doubled quotes are supported.

Category identifiers are the stable uppercase values in `cases/catalog.json`.
They include both standard `CWE-<number>` identifiers and the benchmark's
language-specific `RUST-*` categories.

## Publishing a result

Keep the original raw scanner output, the normalized submission if one was needed,
the exact benchmark commit, and all three generated scorecards. Do not publish
source code, credentials, or results from a non-benchmark target in this repository.
