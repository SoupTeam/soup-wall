# Native performance comparison

Classification: **non-comparable** (two_reports).

| Role | Input | Original SHA-256 | Custody | Source | Binaries | Build |
|---|---|---|---|---|---|---|
| baseline | `docs/operations/evidence/sou-141/native-final-ask-series-summary.json` | `e11625ecad25734e…` | committed_blob | verified_git_objects | declared_only | not_retained |
| candidate | `docs/operations/evidence/sou-141/wsl2-ask-series.json` | `7238dce777f03bde…` | committed_blob | unavailable | unavailable | not_retained |

## Reasons

- `binary_identity_unverified` (binaries): binary digests are not independently bound
- `build_profile_unverified` (build): build profile is not bound to the measured binaries
- `cpu_count_unverified` (cpu_count): not retained on one side
- `environment_mismatch` (platform): differs
- `host_instance_unverified` (host_instance): neither report retains its host instance; same-host conditions cannot be established
- `kernel_unverified` (kernel): not retained on one side
- `machine_unverified` (machine): not retained on one side
- `memory_unverified` (memory): not retained on one side
- `producer_format_mismatch` (producer_format): differs
- `source_unverified` (source): independent verification unavailable
- `trace_requested_unverified` (trace_requested): not retained on one side
- `workload_unverified` (workload): independent verification unavailable

## Strata (primary endpoint: continuation_ms (ms))

Counts are measured / failed / timed out / incomplete / not run. Distributions use qualified runs only; trials of unqualified runs stay counted under all runs.

| Stratum | Condition | Role | Planned | All runs | Excluded (unqualified runs) | Qualified runs | Runs | p50 | p95 | max | Engineering criterion |
|---|---|---|---:|---|---:|---|---:|---:|---:|---:|---|
| filesystem | declared_cold_unverified | baseline | – | absent | – | – | – | – | – | – | – |
| filesystem | declared_cold_unverified | candidate | 40 | 40 / 0 / 0 / 0 / 0 | 40 | 0 / 0 / 0 / 0 / 0 | 0 | n/a | n/a | n/a | not_evaluable_no_qualified_run |
| filesystem | declared_warm_unverified | baseline | – | absent | – | – | – | – | – | – | – |
| filesystem | declared_warm_unverified | candidate | 20 | 20 / 0 / 0 / 0 / 0 | 20 | 0 / 0 / 0 / 0 / 0 | 0 | n/a | n/a | n/a | not_evaluable_no_qualified_run |
| filesystem | post_cache_drop_setup_rewarmed | baseline | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1199.0 | 1265.4 | 1298.2 | met |
| filesystem | post_cache_drop_setup_rewarmed | candidate | – | absent | – | – | – | – | – | – | – |
| filesystem | undeclared | baseline | – | absent | – | – | – | – | – | – | – |
| filesystem | undeclared | candidate | 20 | 20 / 0 / 0 / 0 / 0 | 20 | 0 / 0 / 0 / 0 / 0 | 0 | n/a | n/a | n/a | not_evaluable_no_qualified_run |
| filesystem | warm | baseline | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1205.9 | 1256.8 | 1270.2 | met |
| filesystem | warm | candidate | – | absent | – | – | – | – | – | – | – |
| git | declared_cold_unverified | baseline | – | absent | – | – | – | – | – | – | – |
| git | declared_cold_unverified | candidate | 40 | 40 / 0 / 0 / 0 / 0 | 40 | 0 / 0 / 0 / 0 / 0 | 0 | n/a | n/a | n/a | not_evaluable_no_qualified_run |
| git | declared_warm_unverified | baseline | – | absent | – | – | – | – | – | – | – |
| git | declared_warm_unverified | candidate | 20 | 20 / 0 / 0 / 0 / 0 | 20 | 0 / 0 / 0 / 0 / 0 | 0 | n/a | n/a | n/a | not_evaluable_no_qualified_run |
| git | post_cache_drop_setup_rewarmed | baseline | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1579.6 | 1678.9 | 1692.2 | met |
| git | post_cache_drop_setup_rewarmed | candidate | – | absent | – | – | – | – | – | – | – |
| git | undeclared | baseline | – | absent | – | – | – | – | – | – | – |
| git | undeclared | candidate | 20 | 20 / 0 / 0 / 0 / 0 | 20 | 0 / 0 / 0 / 0 / 0 | 0 | n/a | n/a | n/a | not_evaluable_no_qualified_run |
| git | warm | baseline | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1594.0 | 1634.9 | 1665.0 | met |
| git | warm | candidate | – | absent | – | – | – | – | – | – | – |

## Differences (candidate minus baseline, primary endpoint)

- none: no comparable stratum. No speed-up, merged p95 or verdict is reported.

## Limits

- Percentiles: nearest rank: the value at rank ceil(q * n) of the ascending sample, unrounded (pilot_ask_latency.summarize). Published sw-ask-series/1 distributions round to 0.001 ms first; reproduction uses that producer convention.
- Inference: descriptive only. independent_clusters_below_minimum: at most 2 runs per stratum, minimum 10 effective clusters (DEC-SOU153-20261027) no_accepted_performance_cluster_method: the SOU-153 bootstrap is approved only for AgentDojo semantic families repeated_trials_within_a_run_are_dependent: one qualifier process and host per run
- Not retained: cleanup, external_build_time, first_observable_pending, preparation_elapsed, raw_stage_events, trace_observed.
- Engineering latency diagnostics for recorded native Ask series only.
- Not a security or protection qualification, not task effectiveness, not product or pilot readiness.
- Trace-on is the only observer mode of this producer; no trace-off result exists here, and none would qualify protection.
- The 3000 ms continuation p95 criterion and the 5000 ms first-pending bound are existing engineering criteria, reported separately; no new budget is approved.
- A same-report identity control proves the comparator, not a performance change between revisions.
