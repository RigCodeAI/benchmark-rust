# Adding or changing a test

1. Open an issue describing the security statement, CWE, vulnerable behavior,
   safe control, unknown boundary, unsupported coordinate, and expected evidence.
2. Implement all four controls. A category is not complete with only a vulnerable
   example.
3. Add ordinary application coverage where the claim concerns a framework or
   runtime behavior.
4. Update the canonical truth document and every affected source digest.
5. Regenerate the public catalog with `make catalog`.
6. Run `make verify`.
7. Include an independent explanation of why the safe control is authoritative.

Expected results must not be changed merely to make a scanner pass. Truth changes
require review from someone who did not implement the corresponding scanner logic.
Generated catalogs must always be byte-identical to the canonical truth projection.
