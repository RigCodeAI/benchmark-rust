# Methodology and truth firewall

The repository serves two audiences: any scanner seeking a reproducible public
accuracy score, and high-assurance products seeking runtime/evidence qualification.
Those claims are intentionally separate.

```text
benchmark application ──scanner──> raw observations
                                      │
public truth ──benchmark scorer───────┘
```

The scanner may know the public application and case catalog, as it can with any
open benchmark. It must not read canonical truth while scanning or manufacture
negative results from expected answers. The independent scorer performs the only
truth comparison.

Public benchmarks can demonstrate reproducibility and expose regressions, but
cannot alone prove generalization. Promotion therefore requires separately
governed held-out applications that are not developed in this tree.

ZeroSurface maintains this repository and uses it as a product regression gate.
Changes to product code do not automatically change benchmark truth. Benchmark
commits are pinned by digest in downstream qualification jobs.
