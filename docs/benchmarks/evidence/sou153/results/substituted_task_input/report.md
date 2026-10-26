# Paired development regression

Development comparison of recorded runs. Not held-out efficacy, general safety or readiness evidence.

| Question | Status |
|---|---|
| Execution | completed |
| Input validity | valid |
| Comparability | non_comparable |
| Completeness | per_side_only |
| Unknown outcomes | unavailable |

## Reasons (non-comparable)

- `upstream_mismatch`: differs in ['source_inventory_sha256']
- `input_binding_failed`: supplied source bytes do not reproduce the declared identities

## Input binding

Overall: **mismatch**. identity of the supplied inputs; not proof that the producer executed them

| Link | Status |
|---|---|
| run_to_plan | verified |
| case_semantic_input | mismatch |
| source_to_inventory | mismatch |
| injections_to_plan | verified |

## Completeness: baseline

| Domain | Planned | Attempted | Evaluable | Unknown | Incomplete | Not run |
|---|---|---|---|---|---|---|
| all | 48 | 48 | 48 | 0 | 0 | 0 |
| attacked | 24 | 24 | 24 | 0 | 0 | 0 |
| benign | 24 | 24 | 24 | 0 | 0 | 0 |

## Completeness: candidate

| Domain | Planned | Attempted | Evaluable | Unknown | Incomplete | Not run |
|---|---|---|---|---|---|---|
| all | 48 | 48 | 48 | 0 | 0 | 0 |
| attacked | 24 | 24 | 24 | 0 | 0 | 0 |
| benign | 24 | 24 | 24 | 0 | 0 | 0 |

## Stopped, not-run and timeout

Stopped and not-run units have no evaluator outcome; they are never counted as successes.

| Side | Stopped units by producer reason | Not run | Timeouts |
|---|---|---|---|
| baseline | none | 0 | not available (undistinguished) |
| candidate | none | 0 | not available (undistinguished) |

## Not computed

- Uncertainty: not_computed_in_checkpoint
- Latency: not_computed_in_checkpoint

## Limitations

- Development comparison of recorded runs; not held-out efficacy, general safety or pilot readiness evidence.
- Revision pins and the run's source inventory hash are producer declarations; this tool checks their consistency, not which binary or policy actually executed.
- Input binding checks the identity of the supplied inputs, not that the producer executed them. Per-case full input, label and family are verified only through a case manifest inside the inventoried source; without one that link stays unverified (genuine upstream AgentDojo has none).
- Paired differences are conditional on units evaluable in both runs; with partial coverage only the missing-outcome bounds on the planned set account for missing outcomes; they are not confidence intervals.
- Without declared semantic families, correlated variants are grouped by known plan dependencies only.
- Unknown outcomes are unavailable in this producer contract; timeouts are not distinguishable.
- Checkpoint scope: family-aware uncertainty and latency distributions are not computed yet.
