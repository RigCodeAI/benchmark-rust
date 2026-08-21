# Public schemas

`scanner-results-v1.schema.json` is the vendor-neutral JSON submission format.
SARIF 2.1.0 and the documented CSV format are accepted without conversion to a
Sivere publication. `public-scorecard-v1.schema.json` describes the JSON accuracy
scorecard.

`qualification-evidence-v1.schema.json` is a copy of the stronger, separately
versioned assurance contract. It includes runtime coordinates, evidence grades,
sealed transcripts, authenticated readback, and closed coverage. The root copy
is retained for compatibility with existing qualification clients.
