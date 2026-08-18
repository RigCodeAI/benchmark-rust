# Scoring

## Public accuracy score

The four controls have deliberately different meanings:

| Control | Plain-language meaning |
| --- | --- |
| Vulnerable | The application performs the unsafe behavior; a capable scanner should report it. |
| Safe | The same security boundary is exercised with an effective defense; reporting it is a false positive. |
| Unknown | The boundary is recognized, but the available evidence cannot support a vulnerable or clean conclusion. |
| Unsupported | The runtime, framework, API, or transport coordinate is outside the declared capability. |

The public denominator contains one vulnerable and one safe case per CWE.

| Expected case | Scanner reports it | Result |
| --- | --- | --- |
| Vulnerable | Yes | True positive |
| Vulnerable | No | False negative |
| Safe | Yes | False positive |
| Safe | No | True negative |

An unmapped finding is counted as a false positive. Duplicate reports of the same
case are reported but counted once. Findings that explicitly identify an unknown
or unsupported assurance control are disclosed as unscored and do not become
positive or negative accuracy evidence.

The scorecard reports:

```text
TPR = TP / (TP + FN)
FPR = FP / (FP + TN)
balanced accuracy = (TPR + (1 - FPR)) / 2
```

Category rows have one vulnerable and one safe control, making category failures
easy to inspect rather than hiding them in a single aggregate.

## Qualification score

Qualification adds the unknown and unsupported controls, required evidence grade,
exact runtime/framework identity, final publication, closed coverage, sealed
transcript verification, authenticated readback, unexpected facts, unresolved
obligations, and held-out evidence. A perfect public accuracy score does not imply
qualification or promotion.
