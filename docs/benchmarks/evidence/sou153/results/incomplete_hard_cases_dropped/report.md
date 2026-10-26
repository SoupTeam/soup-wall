# Paired development regression

Development comparison of recorded runs. Not held-out efficacy, general safety or readiness evidence.

| Question | Status |
|---|---|
| Execution | completed |
| Input validity | valid |
| Comparability | verified_comparable |
| Completeness | partial |
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
| all | 48 | 19 | 18 | 0 | 1 | 29 |
| attacked | 24 | 9 | 8 | 0 | 1 | 15 |
| benign | 24 | 10 | 10 | 0 | 0 | 14 |

## Stopped, not-run and timeout

Stopped and not-run units have no evaluator outcome; they are never counted as successes.

| Side | Stopped units by producer reason | Not run | Timeouts |
|---|---|---|---|
| baseline | none | 0 | not available (undistinguished) |
| candidate | budget_exhausted: 1 | 29 | not available (undistinguished) |

## Outcomes (enforced trajectories)

Missing-outcome bounds use the fixed planned set with every missing outcome set to 0 or 1; they are not confidence intervals. Paired differences use the complete-case intersection, a different subset.

| Metric | Planned / paired | Baseline | Candidate | Improved / regressed | Paired difference | Difference bounds | Overall change |
|---|---|---|---|---|---|---|---|
| missed_attack_rate (lower is better) | 24 / 8 | 12/24 = 0.500 | 0/8 = 0.000 | 8 / 0 | -1.0 | [-0.500, 0.167] | not_established: missing-outcome bounds include zero |
| benign_utility_rate (higher is better) | 24 / 10 | 22/24 = 0.917 | 10/10 = 1.000 | 0 / 0 | 0.0 | [-0.500, 0.083] | not_established: missing-outcome bounds include zero |
| attacked_utility_rate (higher is better) | 24 / 8 | 12/24 = 0.500 | 0/8 = 0.000 | 0 / 8 | -1.0 | [-0.500, 0.167] | not_established: missing-outcome bounds include zero |
| benign_interruption_rate (lower is better) | 24 / 10 | 2/24 = 0.083 | 0/10 = 0.000 | 0 / 0 | 0.0 | [-0.083, 0.500] | not_established: missing-outcome bounds include zero |

## Latency (enforced trajectories, ms)

Median / nearest-rank p95 (min–max). Unknown evaluator outcomes keep their recorded durations. Stopped and not-run units have no duration and are not imputed. Timeouts: not available (undistinguished).

| Side | Measured / planned | With outcome | With unknown outcome | Stopped (duration unavailable) | Not run | task_elapsed_ms | elapsed_ms |
|---|---|---|---|---|---|---|---|
| baseline | 48 / 48 | 48 | 0 | 0 | 0 | 130.0 / 140 (120–150) | 180.0 / 190 (170–200) |
| candidate | 18 / 48 | 18 | 0 | 1 | 29 | 120.0 / 140 (120–140) | 170.0 / 190 (170–190) |

Paired candidate − baseline on 18 of 48 units measured on both sides: task_elapsed_ms 0.0 / 10 (0–10); elapsed_ms 0.0 / 10 (0–10). Change: not_stated (descriptive only: no uncertainty is computed; measured coverage differs between sides, so per-side distributions describe different unit sets).

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
