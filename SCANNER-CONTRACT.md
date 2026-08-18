# Scanner contracts

BenchmarkRust has two deliberately separate contracts.

## Public accuracy contract

Any scanner may submit SARIF 2.1.0, CSV, or JSON conforming to
`schemas/scanner-results-v1.schema.json`. Findings identify a standard CWE or
Rust-specific security category and at least one public case identity: route,
case-bearing repository location, or stable case ID. No Rig
publication, transcript, compiler inventory, runtime coordinate, or evidence grade
is required.

```bash
./scoreBenchmark.sh --results results/my-tool.sarif --output-dir results/my-tool
```

Absence on a vulnerable case is an FN. A finding on a safe case is an FP.
Unmapped findings are FP, while duplicate reports do not improve the score.

## High-assurance qualification contract

Products claiming runtime/compiler evidence and complete coverage may additionally
emit `schemas/qualification-evidence-v1.schema.json`. It binds observations to the
exact repository, compiler, framework, publication, coverage, transcript, and
authenticated-readback coordinates.

```bash
cargo run --release --locked -- score \
  --truth truth-v1.json \
  --evidence /immutable/scanner-evidence.json \
  --output /immutable/qualification.json
```

`--held-out` may be repeated. `--require-promotion` exits 30 until every authority
gate passes.

The scanner must never read benchmark truth during analysis. Product adapters may
read the public catalog, but the benchmark-owned scorer alone compares observations
with truth.
