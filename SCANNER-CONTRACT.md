# Scanner contract

BenchmarkRust is scanner-neutral. A scanner adapter must produce a JSON document
conforming to `product-evidence-v1.schema.json`; the benchmark-owned scorer is the
only component permitted to compare those observations with `truth-v1.json`.

The adapter must bind observations to the exact repository, runtime, framework,
publication, coverage, transcript, and authenticated-readback coordinates in the
evidence envelope. It must not read the truth file while scanning. Missing cases
remain missing and are scored as false negatives or unresolved controls.

```console
cargo run --release -- score \
  --truth truth-v1.json \
  --evidence /immutable/scanner-evidence.json \
  --output /immutable/score.json
```

`--held-out` may be repeated. `--require-promotion` exits 30 until the score,
closed-envelope, and independent held-out gates all pass.
