# Paired development regression

Development comparison of recorded runs. Not held-out efficacy, general safety or readiness evidence.

| Question | Status |
|---|---|
| Execution | completed |
| Input validity | valid |
| Comparability | conditionally_comparable |
| Completeness | complete |
| Unknown outcomes | unavailable |

## Gaps

- `case_semantic_input_unverified`: no case manifest inside the inventoried source binds each case ID to its user task and environment content; the inventory hash alone covers the source only as a whole
- `semantic_families_unavailable`: no bound case manifest or --families: correlated variants are grouped only by known plan dependencies

## Input binding

Overall: **partially_verified**. identity of the supplied inputs; not proof that the producer executed them

| Link | Status |
|---|---|
| run_to_plan | verified |
| case_semantic_input | unverified |
| source_to_inventory | verified |
| injections_to_plan | verified |

## Completeness: baseline

| Domain | Planned | Attempted | Evaluable | Unknown | Incomplete | Not run |
|---|---|---|---|---|---|---|
| all | 16 | 16 | 16 | 0 | 0 | 0 |
| attacked | 8 | 8 | 8 | 0 | 0 | 0 |
| benign | 8 | 8 | 8 | 0 | 0 | 0 |

## Completeness: candidate

| Domain | Planned | Attempted | Evaluable | Unknown | Incomplete | Not run |
|---|---|---|---|---|---|---|
| all | 16 | 16 | 16 | 0 | 0 | 0 |
| attacked | 8 | 8 | 8 | 0 | 0 | 0 |
| benign | 8 | 8 | 8 | 0 | 0 | 0 |

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
| missed_attack_rate (lower is better) | 8 / 8 | 0/8 = 0.000 | 0/8 = 0.000 | 0 / 0 | 0.0 | [0.000, 0.000] | not_established: family-cluster uncertainty families_unavailable |
| benign_utility_rate (higher is better) | 8 / 8 | 3/8 = 0.375 | 3/8 = 0.375 | 0 / 0 | 0.0 | [0.000, 0.000] | not_established: family-cluster uncertainty families_unavailable |
| attacked_utility_rate (higher is better) | 8 / 8 | 3/8 = 0.375 | 3/8 = 0.375 | 0 / 0 | 0.0 | [0.000, 0.000] | not_established: family-cluster uncertainty families_unavailable |
| benign_interruption_rate (lower is better) | 8 / 8 | 0/8 = 0.000 | 0/8 = 0.000 | 0 / 0 | 0.0 | [0.000, 0.000] | not_established: family-cluster uncertainty families_unavailable |

## Latency (enforced trajectories, ms)

Median / nearest-rank p95 (min–max). Unknown evaluator outcomes keep their recorded durations. Stopped and not-run units have no duration and are not imputed. Timeouts: not available (undistinguished).

| Side | Measured / planned | With outcome | With unknown outcome | Stopped (duration unavailable) | Not run | task_elapsed_ms | elapsed_ms |
|---|---|---|---|---|---|---|---|
| baseline | 16 / 16 | 16 | 0 | 0 | 0 | 178.5 / 263 (131–263) | 777.5 / 952 (728–952) |
| candidate | 16 / 16 | 16 | 0 | 0 | 0 | 187.0 / 345 (150–345) | 1023.0 / 1176 (934–1176) |

Paired candidate − baseline on 16 of 16 units measured on both sides: task_elapsed_ms 17.5 / 128 (-59–128); elapsed_ms 233.0 / 316 (79–316). Change: not_stated (descriptive only: no uncertainty is computed for latency).

## Family-cluster uncertainty

Not computed: semantic families unavailable: no bound case manifest or --families.

## Limitations

- Development comparison of recorded runs; not held-out efficacy, general safety or pilot readiness evidence.
- Revision pins and the run's source inventory hash are producer declarations; this tool checks their consistency, not which binary or policy actually executed.
- Input binding checks the identity of the supplied inputs, not that the producer executed them. Per-case full input, label and family are verified only through a case manifest inside the inventoried source; without one that link stays unverified (genuine upstream AgentDojo has none).
- Paired differences and their family-cluster intervals are conditional on units evaluable in both runs; with partial coverage only the missing-outcome bounds on the planned set account for missing outcomes, and those bounds are not confidence intervals.
- Family-cluster intervals treat resampling units as independent and exchangeable draws from the families of interest; they are approximate percentile intervals that tend to be too narrow with few clusters, and none is reported below the effective-cluster minimum. They describe this development set, not held-out performance.
- Without declared semantic families no uncertainty is computed; correlated variants are then grouped by known plan dependencies only.
- Unknown outcomes are unavailable in this producer contract; timeouts are not distinguishable.
- Latency is descriptive and states no speed-up or slow-down.
