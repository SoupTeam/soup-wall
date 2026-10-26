# Paired development regression

Development comparison of recorded runs. Not held-out efficacy, general safety or readiness evidence.

| Question | Status |
|---|---|
| Execution | completed |
| Input validity | valid |
| Comparability | verified_comparable |
| Completeness | complete |
| Unknown outcomes | unavailable |

## Input binding

Overall: **verified**. identity of the supplied inputs; not proof that the producer executed them

| Link | Status |
|---|---|
| run_to_plan | verified |
| case_semantic_input | verified |
| source_to_inventory | verified |
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

## Outcomes (enforced trajectories)

Missing-outcome bounds use the fixed planned set with every missing outcome set to 0 or 1; they are not confidence intervals. Paired differences use the complete-case intersection, a different subset.

| Metric | Planned / paired | Baseline | Candidate | Improved / regressed | Paired difference | Difference bounds | Overall change |
|---|---|---|---|---|---|---|---|
| missed_attack_rate (lower is better) | 24 / 24 | 12/24 = 0.500 | 2/24 = 0.083 | 10 / 0 | -0.416667 | [-0.417, -0.417] | not_established: no missing outcomes, but no uncertainty is computed |
| benign_utility_rate (higher is better) | 24 / 24 | 22/24 = 0.917 | 22/24 = 0.917 | 0 / 0 | 0.0 | [0.000, 0.000] | not_established: no missing outcomes, but no uncertainty is computed |
| attacked_utility_rate (higher is better) | 24 / 24 | 12/24 = 0.500 | 2/24 = 0.083 | 0 / 10 | -0.416667 | [-0.417, -0.417] | not_established: no missing outcomes, but no uncertainty is computed |
| benign_interruption_rate (lower is better) | 24 / 24 | 2/24 = 0.083 | 2/24 = 0.083 | 0 / 0 | 0.0 | [0.000, 0.000] | not_established: no missing outcomes, but no uncertainty is computed |

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
