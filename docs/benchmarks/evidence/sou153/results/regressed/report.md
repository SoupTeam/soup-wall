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
| missed_attack_rate (lower is better) | 24 / 24 | 12/24 = 0.500 | 18/24 = 0.750 | 0 / 6 | 0.25 | [0.250, 0.250] | not_established: family-cluster uncertainty insufficient_clusters |
| benign_utility_rate (higher is better) | 24 / 24 | 22/24 = 0.917 | 18/24 = 0.750 | 0 / 4 | -0.166667 | [-0.167, -0.167] | not_established: family-cluster uncertainty insufficient_clusters |
| attacked_utility_rate (higher is better) | 24 / 24 | 12/24 = 0.500 | 18/24 = 0.750 | 6 / 0 | 0.25 | [0.250, 0.250] | not_established: family-cluster uncertainty insufficient_clusters |
| benign_interruption_rate (lower is better) | 24 / 24 | 2/24 = 0.083 | 6/24 = 0.250 | 0 / 4 | 0.166667 | [0.167, 0.167] | not_established: family-cluster uncertainty insufficient_clusters |

## Latency (enforced trajectories, ms)

Median / nearest-rank p95 (min–max). Unknown evaluator outcomes keep their recorded durations. Stopped and not-run units have no duration and are not imputed. Timeouts: not available (undistinguished).

| Side | Measured / planned | With outcome | With unknown outcome | Stopped (duration unavailable) | Not run | task_elapsed_ms | elapsed_ms |
|---|---|---|---|---|---|---|---|
| baseline | 48 / 48 | 48 | 0 | 0 | 0 | 130.0 / 140 (120–150) | 180.0 / 190 (170–200) |
| candidate | 48 / 48 | 48 | 0 | 0 | 0 | 130.0 / 150 (120–150) | 180.0 / 200 (170–200) |

Paired candidate − baseline on 48 of 48 units measured on both sides: task_elapsed_ms 0.0 / 30 (-10–30); elapsed_ms 0.0 / 30 (-10–30). Change: not_stated (descriptive only: no uncertainty is computed for latency).

## Family-cluster uncertainty

Pairs cluster bootstrap over 6 resampling units (semantic families merged with dependency clusters; families bound_by_source_inventory), seed 153, 2000 replicates, 95% percentile intervals, reported only with at least 10 effective clusters. Conditional on paired-evaluable units; approximate and optimistic near the minimum.

| Metric | Paired units | Clusters (effective) | Status | Difference | Improved share | Regressed share |
|---|---|---|---|---|---|---|
| missed_attack_rate | 24 | 6 (6.0) | insufficient_clusters | 0.25 n/a | 0.0 n/a | 0.25 n/a |
| benign_utility_rate | 24 | 6 (6.0) | insufficient_clusters | -0.166667 n/a | 0.0 n/a | 0.166667 n/a |
| attacked_utility_rate | 24 | 6 (6.0) | insufficient_clusters | 0.25 n/a | 0.25 n/a | 0.0 n/a |
| benign_interruption_rate | 24 | 6 (6.0) | insufficient_clusters | 0.166667 n/a | 0.0 n/a | 0.166667 n/a |

## Limitations

- Development comparison of recorded runs; not held-out efficacy, general safety or pilot readiness evidence.
- Revision pins and the run's source inventory hash are producer declarations; this tool checks their consistency, not which binary or policy actually executed.
- Input binding checks the identity of the supplied inputs, not that the producer executed them. Per-case full input, label and family are verified only through a case manifest inside the inventoried source; without one that link stays unverified (genuine upstream AgentDojo has none).
- Paired differences and their family-cluster intervals are conditional on units evaluable in both runs; with partial coverage only the missing-outcome bounds on the planned set account for missing outcomes, and those bounds are not confidence intervals.
- Family-cluster intervals treat resampling units as independent and exchangeable draws from the families of interest; they are approximate percentile intervals that tend to be too narrow with few clusters, and none is reported below the effective-cluster minimum. They describe this development set, not held-out performance.
- Without declared semantic families no uncertainty is computed; correlated variants are then grouped by known plan dependencies only.
- Unknown outcomes are unavailable in this producer contract; timeouts are not distinguishable.
- Latency is descriptive and states no speed-up or slow-down.
