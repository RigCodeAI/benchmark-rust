# BenchmarkRust

BenchmarkRust is a fully runnable open-source Rust application-security benchmark
designed to measure the accuracy of vulnerability-detection tools. Static,
dynamic, interactive, and hybrid security tools can analyze the same Axum
application and score their results against benchmark-owned truth.

The suite contains vulnerable and safe cases across 43 security categories. It
also includes explicit `UNKNOWN` and `UNSUPPORTED` controls for tools that make
stronger claims about coverage, compiler behavior, build provenance, runtime
evidence, or supported coordinates.

The independent scorer accepts SARIF 2.1.0, JSON, and CSV submissions and produces
JSON, CSV, and HTML scorecards. A tool can receive a public accuracy score without
implementing BenchmarkRust's optional high-assurance evidence contract.

Documentation is available in the [quick start](QUICKSTART.md),
[scanner integration guide](docs/scanner-integration.md), and
[scoring guide](docs/scoring.md). The benchmark methodology and truth-independence
rules are described in [methodology](docs/methodology.md).

## Running BenchmarkRust

- `./runBenchmark.sh` — run the Axum benchmark locally on port 3000.
- `docker compose up --build` — run the application in an isolated container.
- `./scoreBenchmark.sh --results PATH` — score SARIF, JSON, or CSV results.
- `./verifyBenchmark.sh` — verify the scorer, catalogs, application, and corpus.

Equivalent `make run`, `make score RESULTS=PATH`, and `make verify` commands are
also provided.

BenchmarkRust is maintained by ZeroSurface and released under the MIT License.
Published results should identify the exact benchmark release or commit and
include enough scanner configuration to reproduce the result.
