# Native performance comparison

Classification: **compatible** (identity_control).

| Role | Input | Original SHA-256 | Custody | Source | Binaries | Build |
|---|---|---|---|---|---|---|
| baseline | `docs/operations/evidence/sou-141/native-final-ask-series-summary.json` | `e11625ecad25734e…` | committed_blob | verified_git_objects | declared_only | not_retained |
| candidate | `docs/operations/evidence/sou-141/native-final-ask-series-summary.json` | `e11625ecad25734e…` | committed_blob | verified_git_objects | declared_only | not_retained |

## Reasons

- none

## Strata (continuation, ms)

Status counts cover trials of qualified runs; trials of unqualified runs are excluded and counted.

| Profile | Condition | Role | Planned | Excluded (unqualified runs) | Measured / failed / timed out / incomplete / not run | Runs | p50 | p95 | max | 3000 ms p95 |
|---|---|---|---:|---:|---|---:|---:|---:|---:|---|
| filesystem | post_cache_drop_setup_rewarmed | baseline | 40 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1199.0 | 1265.4 | 1298.2 | met |
| filesystem | post_cache_drop_setup_rewarmed | candidate | 40 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1199.0 | 1265.4 | 1298.2 | met |
| filesystem | warm | baseline | 40 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1205.9 | 1256.8 | 1270.2 | met |
| filesystem | warm | candidate | 40 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1205.9 | 1256.8 | 1270.2 | met |
| git | post_cache_drop_setup_rewarmed | baseline | 40 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1579.6 | 1678.9 | 1692.2 | met |
| git | post_cache_drop_setup_rewarmed | candidate | 40 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1579.6 | 1678.9 | 1692.2 | met |
| git | warm | baseline | 40 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1594.0 | 1634.9 | 1665.0 | met |
| git | warm | candidate | 40 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1594.0 | 1634.9 | 1665.0 | met |

## Differences (candidate minus baseline, ms)

- filesystem / post_cache_drop_setup_rewarmed: marginal percentile differences p50 0.0, p95 0.0, max 0.0; paired differences (n=40) p50 0.0, p95 0.0, min 0.0, max 0.0, all zero: True
- filesystem / warm: marginal percentile differences p50 0.0, p95 0.0, max 0.0; paired differences (n=40) p50 0.0, p95 0.0, min 0.0, max 0.0, all zero: True
- git / post_cache_drop_setup_rewarmed: marginal percentile differences p50 0.0, p95 0.0, max 0.0; paired differences (n=40) p50 0.0, p95 0.0, min 0.0, max 0.0, all zero: True
- git / warm: marginal percentile differences p50 0.0, p95 0.0, max 0.0; paired differences (n=40) p50 0.0, p95 0.0, min 0.0, max 0.0, all zero: True

## Limits

- Percentiles: nearest rank: the value at rank ceil(q * n) of the ascending sample, unrounded (pilot_ask_latency.summarize). Published sw-ask-series/1 distributions round to 0.001 ms first; reproduction uses that producer convention.
- Inference: descriptive only. independent_clusters_below_minimum: at most 2 runs per stratum, minimum 10 effective clusters (DEC-SOU153-20261027) no_accepted_performance_cluster_method: the SOU-153 bootstrap is approved only for AgentDojo semantic families repeated_trials_within_a_run_are_dependent: one qualifier process and host per run
- Not retained: cleanup, external_build_time, first_observable_pending, preparation_elapsed, raw_stage_events, trace_observed.
- Engineering latency diagnostics for recorded native Ask series only.
- Not a security or protection qualification, not task effectiveness, not product or pilot readiness.
- Trace-on is the only observer mode of this producer; no trace-off result exists here, and none would qualify protection.
- The 3000 ms continuation p95 criterion and the 5000 ms first-pending bound are existing engineering criteria, reported separately; no new budget is approved.
- A same-report identity control proves the comparator, not a performance change between revisions.
