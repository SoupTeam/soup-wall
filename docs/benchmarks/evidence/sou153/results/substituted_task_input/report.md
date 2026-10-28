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

## Latency (enforced trajectories, ms)

Median / nearest-rank p95 (min–max). Unknown evaluator outcomes keep their recorded durations. Stopped and not-run units have no duration and are not imputed. Timeouts: not available (undistinguished).

| Side | Measured / planned | With outcome | With unknown outcome | Stopped (duration unavailable) | Not run | task_elapsed_ms | elapsed_ms |
|---|---|---|---|---|---|---|---|
| baseline | 48 / 48 | 48 | 0 | 0 | 0 | 130.0 / 140 (120–150) | 180.0 / 190 (170–200) |
| candidate | 48 / 48 | 48 | 0 | 0 | 0 | 135.0 / 140 (120–150) | 185.0 / 190 (170–200) |

## Family-cluster uncertainty

Not computed: no comparable outcomes.

## Limitations

- Development comparison of recorded runs; not held-out efficacy, general safety or pilot readiness evidence.
- Revision pins and the run's source inventory hash are producer declarations; this tool checks their consistency, not which binary or policy actually executed.
- Input binding checks the identity of the supplied inputs, not that the producer executed them. Per-case full input, label and family are verified only through a case manifest inside the inventoried source; without one that link stays unverified (genuine upstream AgentDojo has none).
- Paired differences and their family-cluster intervals are conditional on units evaluable in both runs; with partial coverage only the missing-outcome bounds on the planned set account for missing outcomes, and those bounds are not confidence intervals.
- Family-cluster intervals treat resampling units as independent and exchangeable draws from the families of interest; they are approximate percentile intervals that tend to be too narrow with few clusters, and none is reported below the effective-cluster minimum. They describe this development set, not held-out performance.
- Without declared semantic families no uncertainty is computed; correlated variants are then grouped by known plan dependencies only.
- Unknown outcomes are unavailable in this producer contract; timeouts are not distinguishable.
- Latency is descriptive and states no speed-up or slow-down.
