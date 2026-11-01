# Native performance comparison

Classification: **non-comparable** (two_reports).

| Role | Input | Original SHA-256 | Custody | Source | Binaries | Build |
|---|---|---|---|---|---|---|
| baseline | `docs/operations/evidence/sou106/measured-report.json` | `6f3173364ded8d34…` | committed_blob | verified_git_objects | declared_only | not_retained |
| candidate | `docs/operations/evidence/sou-141/native-final-ask-series-summary.json` | `e11625ecad25734e…` | committed_blob | verified_git_objects | declared_only | not_retained |

## Reasons

- `binary_identity_unverified` (binaries): binary digests are not independently bound
- `build_profile_unverified` (build): build profile is not bound to the measured binaries
- `cpu_count_unverified` (cpu_count): not retained on one side
- `endpoint_mismatch` (endpoint:continuation_ms): endpoint definition differs
- `endpoint_mismatch` (endpoint:first_pending_asset_verification_ms): endpoint definition differs
- `endpoint_mismatch` (endpoint:host_elapsed_ms): endpoint definition differs
- `endpoint_mismatch` (endpoint:host_start_ms): endpoint definition differs
- `endpoint_mismatch` (endpoint:post_observed_total_ms): endpoint definition differs
- `endpoint_mismatch` (primary_endpoint): different primary endpoint
- `endpoint_mismatch` (stage_clock): stage clock differs
- `host_instance_unverified` (host_instance): neither report retains its host instance; same-host conditions cannot be established
- `kernel_unverified` (kernel): not retained on one side
- `machine_unverified` (machine): not retained on one side
- `memory_unverified` (memory): not retained on one side
- `platform_unverified` (platform): not retained on one side
- `producer_format_mismatch` (producer_format): differs
- `trace_requested_unverified` (trace_requested): not retained on one side
- `trial_design_mismatch` (design): differs
- `trial_design_mismatch` (profiles): differs
- `workload_or_harness_changed` (workload): measurement harness differs between sources

## Strata (primary endpoint: continuation_ms (ms), host_start_ms (ms))

Counts are measured / failed / timed out / incomplete / not run. Distributions use qualified runs only; trials of unqualified runs stay counted under all runs.

| Stratum | Condition | Role | Planned | All runs | Excluded (unqualified runs) | Qualified runs | Runs | p50 | p95 | max | Engineering criterion |
|---|---|---|---:|---|---:|---|---:|---:|---:|---:|---|
| control/benign | fresh_host_per_arm_os_cache_uncontrolled | baseline | 12 | 12 / 0 / 0 / 0 / 0 | 0 | 12 / 0 / 0 / 0 / 0 | 1 | 1209.0 | 1267.8 | 1267.8 | none approved |
| control/benign | fresh_host_per_arm_os_cache_uncontrolled | candidate | – | absent | – | – | – | – | – | – | – |
| control/refusal | fresh_host_per_arm_os_cache_uncontrolled | baseline | 8 | 8 / 0 / 0 / 0 / 0 | 0 | 8 / 0 / 0 / 0 / 0 | 1 | 1202.6 | 1370.9 | 1370.9 | none approved |
| control/refusal | fresh_host_per_arm_os_cache_uncontrolled | candidate | – | absent | – | – | – | – | – | – | – |
| filesystem | post_cache_drop_setup_rewarmed | baseline | – | absent | – | – | – | – | – | – | – |
| filesystem | post_cache_drop_setup_rewarmed | candidate | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1199.0 | 1265.4 | 1298.2 | met |
| filesystem | warm | baseline | – | absent | – | – | – | – | – | – | – |
| filesystem | warm | candidate | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1205.9 | 1256.8 | 1270.2 | met |
| git | post_cache_drop_setup_rewarmed | baseline | – | absent | – | – | – | – | – | – | – |
| git | post_cache_drop_setup_rewarmed | candidate | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1579.6 | 1678.9 | 1692.2 | met |
| git | warm | baseline | – | absent | – | – | – | – | – | – | – |
| git | warm | candidate | 40 | 40 / 0 / 0 / 0 / 0 | 0 | 40 / 0 / 0 / 0 / 0 | 2 | 1594.0 | 1634.9 | 1665.0 | met |
| protected/benign | fresh_host_per_arm_os_cache_uncontrolled | baseline | 12 | 10 / 2 / 0 / 0 / 0 | 0 | 10 / 2 / 0 / 0 / 0 | 1 | 6830.4 | 7749.5 | 7749.5 | none approved |
| protected/benign | fresh_host_per_arm_os_cache_uncontrolled | candidate | – | absent | – | – | – | – | – | – | – |
| protected/refusal | fresh_host_per_arm_os_cache_uncontrolled | baseline | 8 | 8 / 0 / 0 / 0 / 0 | 0 | 8 / 0 / 0 / 0 / 0 | 1 | 6789.5 | 6871.7 | 6871.7 | none approved |
| protected/refusal | fresh_host_per_arm_os_cache_uncontrolled | candidate | – | absent | – | – | – | – | – | – | – |

## Report-level endpoints (baseline, single values, never compared)

- `asset_install_and_daemon_prepare_ms`: 10816.6 ms (asset install and daemon preparation only)
- `external_build_time`: not_measured_prebuilt_selected_binaries none (not measured by this producer)
- `observable_ask_latency`: not_applicable none (the workload has no operator Ask decision)
- `preparation_ms`: 11845.5 ms (run start through selection verification, asset install and daemon preparation)
- `source_and_selection_verification_ms`: 1028.9 ms (run start to verified source and selection)

## Differences (candidate minus baseline, primary endpoint)

- none: no comparable stratum. No speed-up, merged p95 or verdict is reported.

## Limits

- Percentiles: nearest rank: the value at rank ceil(q * n) of the ascending sample, unrounded (pilot_ask_latency.summarize). Published sw-ask-series/1 distributions round to 0.001 ms first; reproduction uses that producer convention.
- Inference: descriptive only. independent_clusters_below_minimum: at most 2 runs per stratum, minimum 10 effective clusters (DEC-SOU153-20261027) no_accepted_performance_cluster_method: the SOU-153 bootstrap is approved only for AgentDojo semantic families repeated_trials_within_a_run_are_dependent: one qualifier process and host per run
- Not retained: cleanup, external_build_time, failed_arm_timings, first_observable_pending, host_instance, preparation_elapsed, raw_stage_events, trace_observed.
- Outcomes: Row status and the gate are the producer's development workflow outcomes. A protected refusal is witnessed by the producer's own repository witness (effect_observed, original_opens) and is not re-observed here. No status is security or protection effectiveness evidence.
- Engineering latency diagnostics for recorded native Ask series only.
- Not a security or protection qualification, not task effectiveness, not product or pilot readiness.
- Trace-on is the only observer mode of this producer; no trace-off result exists here, and none would qualify protection.
- The 3000 ms continuation p95 criterion and the 5000 ms first-pending bound are existing engineering criteria, reported separately; no new budget is approved.
- A same-report identity control proves the comparator, not a performance change between revisions.
