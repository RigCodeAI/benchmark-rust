# BenchmarkRust quickstart

## 1. Install the exact toolchain

```bash
rustup toolchain install 1.97.1
cargo +1.97.1 --version
```

## 2. Start the benchmark application

```bash
./runBenchmark.sh
```

Leave it running at `http://127.0.0.1:3000`.

## 3. Run a scanner

- SAST: scan `apps/axum-product`.
- DAST/IAST: scan the running application.
- Hybrid tools may do both.

Export findings as SARIF 2.1.0, the JSON schema under `schemas`, or the CSV
columns documented in `docs/scanner-integration.md`.

## 4. Create a scorecard

```bash
./scoreBenchmark.sh \
  --results /path/to/scanner-results.sarif \
  --output-dir results/my-tool-1.2.3
```

Open `results/my-tool-1.2.3/scorecard.html`. JSON and CSV versions are emitted
for automation.

## 5. Verify the benchmark itself

```bash
./verifyBenchmark.sh
```

This verifies the independent scorer, generated case catalog, all example input
formats, the exact Rust corpus, and the Axum application build.
