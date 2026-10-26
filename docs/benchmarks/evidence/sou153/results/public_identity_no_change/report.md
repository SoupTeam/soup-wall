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

- `input_identity_unverified`: no source bundle: task, environment and injection identities are plan declarations

## Input binding

Overall: **declared_unverified**. 

| Link | Status |
|---|---|
| run_to_plan | verified |
| case_semantic_input | unverified |
| source_to_inventory | not_supplied |
| injections_to_plan | not_supplied |

## Completeness: baseline

| Domain | Planned | Attempted | Evaluable | Unknown | Incomplete | Not run |
|---|---|---|---|---|---|---|
| all | 4 | 4 | 4 | 0 | 0 | 0 |
| attacked | 2 | 2 | 2 | 0 | 0 | 0 |
| benign | 2 | 2 | 2 | 0 | 0 | 0 |

## Completeness: candidate

| Domain | Planned | Attempted | Evaluable | Unknown | Incomplete | Not run |
|---|---|---|---|---|---|---|
| all | 4 | 4 | 4 | 0 | 0 | 0 |
| attacked | 2 | 2 | 2 | 0 | 0 | 0 |
| benign | 2 | 2 | 2 | 0 | 0 | 0 |

## Stopped, not-run and timeout

Stopped and not-run units have no evaluator outcome; they are never counted as successes.

| Side | Stopped units by producer reason | Not run | Timeouts |
|---|---|---|---|
| baseline | none | 0 | not available (undistinguished) |
| candidate | none | 0 | not available (undistinguished) |

## Latency (enforced trajectories, ms)

Median / nearest-rank p95 (min–max). Unknown evaluator outcomes keep their recorded durations. Stopped and not-run units have no duration and are not imputed. Timeouts: not available (undistinguished).

| Side | Measured / planned | With outcome | With unknown outcome | Stopped (duration unavailable) | Not run | task_elapsed_ms | elapsed_ms |
|---|---|---|---|---|---|---|---|
| baseline | 4 / 4 | 4 | 0 | 0 | 0 | 147.0 / 164 (141–164) | 334.5 / 347 (322–347) |
| candidate | 4 / 4 | 4 | 0 | 0 | 0 | 147.0 / 164 (141–164) | 334.5 / 347 (322–347) |

## Not computed

- Uncertainty: not_computed_in_checkpoint

## Limitations

- Development comparison of recorded runs; not held-out efficacy, general safety or pilot readiness evidence.
- Revision pins and the run's source inventory hash are producer declarations; this tool checks their consistency, not which binary or policy actually executed.
- Input binding checks the identity of the supplied inputs, not that the producer executed them. Per-case full input, label and family are verified only through a case manifest inside the inventoried source; without one that link stays unverified (genuine upstream AgentDojo has none).
- Paired differences are conditional on units evaluable in both runs; with partial coverage only the missing-outcome bounds on the planned set account for missing outcomes; they are not confidence intervals.
- Without declared semantic families, correlated variants are grouped by known plan dependencies only.
- Unknown outcomes are unavailable in this producer contract; timeouts are not distinguishable.
- Checkpoint scope: family-aware uncertainty is not computed yet; latency is descriptive and states no speed-up or slow-down.
