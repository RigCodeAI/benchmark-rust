# BenchmarkRust held-out evidence

Held-out applications are not checked into this directory. Their independent
truth must remain unavailable to Rust adapter and model development.

Promotion requires evidence from at least three distinct repositories. Across
those repositories, independent truth must exercise vulnerable and safe cases
for every one of the 43 categories. Every run must use ordinary `sivere run`, the
exact qualified runtime/framework coordinate, sealed transcripts, authenticated
readback, `FINAL`, and `COMPLETE`.

Normalize each run into `sivere-benchmark-rust-product-evidence/v1`, validate it
against `../product-evidence-v1.schema.json`, set `layer` to `HELD_OUT`, and bind
it to the independent truth digest. Pass each document with a repeated
`--held-out-evidence` argument. The native scorer rejects duplicate repository
IDs, missing category breadth, mismatched evidence grades, open coverage, and
unrecognized case IDs.

Checked-in fixtures can test the protocol, but they can never satisfy this gate.

