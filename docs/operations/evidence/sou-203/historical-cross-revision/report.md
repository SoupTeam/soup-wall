# Native performance comparison

Classification: **incomplete** (two_reports).

| Role | Input | Original SHA-256 | Custody | Source | Binaries | Build |
|---|---|---|---|---|---|---|
| baseline | `docs/operations/evidence/sou-141/native-ask-series-summary.json` | `5364532d0d404bfe…` | committed_blob | verified_git_objects | declared_only | not_retained |
| candidate | `docs/operations/evidence/sou-141/native-final-ask-series-summary.json` | `e11625ecad25734e…` | committed_blob | verified_git_objects | declared_only | not_retained |

## Reasons

- `binary_identity_unverified` (binaries): binary digests are not independently bound
- `build_profile_unverified` (build): build profile is not bound to the measured binaries
- `host_instance_unverified` (host_instance): neither report retains its host instance; same-host conditions cannot be established
- `mem_total_differs_materiality_unassessed` (memory): reported MemTotal_kb differs; same-boot/same-host conditions are not established and no tolerance is approved

## Strata (primary endpoint: continuation_ms (ms))

Counts are measured / failed / timed out / incomplete / not run. Distributions use qualified runs only; trials of unqualified runs stay counted under all runs.

| Stratum | Condition | Role | Planned | All runs | Excluded (unqualified runs) | Qualified runs | Runs | p50 | p95 | max | Engineering criterion |
|---|---|---|---:|---|---:|---|---:|---:|---:|---:|---|
| filesystem | post_cache_drop_setup_rewarmed | baseline | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 991.6 | 1058.5 | 1107.6 | met |
| filesystem | post_cache_drop_setup_rewarmed | candidate | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1199.0 | 1265.4 | 1298.2 | met |
| filesystem | warm | baseline | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 993.4 | 1035.5 | 1064.6 | met |
| filesystem | warm | candidate | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1205.9 | 1256.8 | 1270.2 | met |
| git | post_cache_drop_setup_rewarmed | baseline | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1365.5 | 1413.2 | 1520.8 | met |
| git | post_cache_drop_setup_rewarmed | candidate | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1579.6 | 1678.9 | 1692.2 | met |
| git | warm | baseline | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1335.4 | 1409.8 | 1425.5 | met |
| git | warm | candidate | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1594.0 | 1634.9 | 1665.0 | met |

## Differences (candidate minus baseline, primary endpoint)

- none: no comparable stratum. No speed-up, merged p95 or verdict is reported.

## Observer and trace semantics

- baseline: timing qualify-pilot-ask.py harness monotonic clock; collector monotonic clock for stages; trace strace seccomp-bpf requested (fallback possible); the observed mode is not retained
- candidate: timing qualify-pilot-ask.py harness monotonic clock; collector monotonic clock for stages; trace strace seccomp-bpf requested (fallback possible); the observed mode is not retained

## Limits

- Percentiles: nearest rank: the value at rank ceil(q * n) of the ascending sample of measured trials, unrounded (pilot_ask_latency.summarize); failed, timed-out, incomplete and not-run trials are counted, never imputed. Ask series: published distributions round to 0.001 ms first; reproduction uses that producer convention.
- Inference: descriptive only. independent_clusters_below_minimum: at most 2 runs per stratum, minimum 10 effective clusters (DEC-SOU153-20261027) no_accepted_performance_cluster_method: the SOU-153 bootstrap is approved only for AgentDojo semantic families repeated_trials_are_dependent: Ask: trials within a run share one qualifier process and one host
- Not retained: cleanup, external_build_time, first_observable_pending, preparation_elapsed, raw_stage_events, trace_observed.
- Engineering performance diagnostics for the recorded reports only.
- Not a security or protection qualification, not task effectiveness, not product or pilot readiness.
- No new budget or threshold is approved.
- A same-report identity control proves the comparator, not a performance change between revisions.
- Ask: trace-on (strace seccomp-bpf) is the only observer mode of this producer; no trace-off result exists here, and none would qualify protection.
