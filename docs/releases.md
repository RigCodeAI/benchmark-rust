# Releases and provenance

Release tags use `vMAJOR.MINOR.PATCH`. The release workflow verifies the benchmark,
builds the independent scorer, archives the tagged source, publishes
`SHA256SUMS`, and requests a GitHub artifact attestation.

Consumers should pin both the tag and commit digest. Downstream qualification
records the immutable benchmark commit and invokes the benchmark-owned scorer.
Release provenance does not itself claim that any scanner passed the benchmark.
