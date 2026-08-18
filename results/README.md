# Results

`examples/` contains synthetic non-Rig submissions that demonstrate JSON, SARIF,
CSV, and scorecard generation. They are interface fixtures, not product claims.

Reproducible third-party submissions should use:

```text
results/<tool>/<version>/raw.*
results/<tool>/<version>/scorecard.json
results/<tool>/<version>/scorecard.csv
results/<tool>/<version>/scorecard.html
results/<tool>/<version>/README.md
```

The accompanying README should identify the scanner version, benchmark commit,
command, environment, and submitter. Never include credentials or unrelated
customer source.
