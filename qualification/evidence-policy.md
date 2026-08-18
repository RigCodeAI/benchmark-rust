# High-assurance evidence policy

The public score answers whether a scanner identified the vulnerable and safe
controls. Qualification answers whether a product can also support authoritative
runtime, build, coverage, and clean-state claims.

Qualification requires, as applicable:

- vulnerable, safe, unknown, and unsupported observations;
- the category's declared evidence grade;
- exact runtime and framework coordinates;
- execution through the ordinary product path;
- `FINAL` publication and closed coverage;
- zero failed requests, unexpected facts, or unresolved obligations;
- verified sealed transcripts and authenticated readback;
- deterministic, hostile-input, and resource-budget controls; and
- independently governed held-out applications.

A tool that cannot produce these fields can still receive a complete public
accuracy score. Missing assurance evidence never becomes a clean or promoted
qualification result.
