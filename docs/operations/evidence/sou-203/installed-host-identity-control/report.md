# Native performance comparison

Classification: **incomplete** (identity_control).

| Role | Input | Original SHA-256 | Custody | Source | Binaries | Build |
|---|---|---|---|---|---|---|
| baseline | `docs/operations/evidence/sou106/measured-report.json` | `6f3173364ded8d34…` | committed_blob | verified_git_objects | declared_only | not_retained |
| candidate | `docs/operations/evidence/sou106/measured-report.json` | `6f3173364ded8d34…` | committed_blob | verified_git_objects | declared_only | not_retained |

## Reasons

- `binary_identity_unverified` (binaries): binary digests are not independently bound
- `build_profile_unverified` (build): build profile is not bound to the measured binaries
- `cpu_count_unverified` (cpu_count): not retained on one side
- `kernel_unverified` (kernel): not retained on one side
- `machine_unverified` (machine): not retained on one side
- `memory_unverified` (memory): not retained on one side
- `platform_unverified` (platform): not retained on one side
- `trace_requested_unverified` (trace_requested): not retained on one side

## Strata (primary endpoint: host_start_ms (ms))

Counts are measured / failed / timed out / incomplete / not run. Distributions use qualified runs only; trials of unqualified runs stay counted under all runs.

| Stratum | Condition | Role | Planned | All runs | Excluded (unqualified runs) | Qualified runs | Runs | p50 | p95 | max | Engineering criterion |
|---|---|---|---:|---|---:|---|---:|---:|---:|---:|---|
| control/benign | fresh_host_per_arm_os_cache_uncontrolled | baseline | 12 | 12 / 0 / 0 / 0 / 0 | 0 | 12 / 0 / 0 / 0 / 0 | 1 | 1209.0 | 1267.8 | 1267.8 | none approved |
| control/benign | fresh_host_per_arm_os_cache_uncontrolled | candidate | 12 | 12 / 0 / 0 / 0 / 0 | 0 | 12 / 0 / 0 / 0 / 0 | 1 | 1209.0 | 1267.8 | 1267.8 | none approved |
| control/refusal | fresh_host_per_arm_os_cache_uncontrolled | baseline | 8 | 8 / 0 / 0 / 0 / 0 | 0 | 8 / 0 / 0 / 0 / 0 | 1 | 1202.6 | 1370.9 | 1370.9 | none approved |
| control/refusal | fresh_host_per_arm_os_cache_uncontrolled | candidate | 8 | 8 / 0 / 0 / 0 / 0 | 0 | 8 / 0 / 0 / 0 / 0 | 1 | 1202.6 | 1370.9 | 1370.9 | none approved |
| protected/benign | fresh_host_per_arm_os_cache_uncontrolled | baseline | 12 | 10 / 2 / 0 / 0 / 0 | 0 | 10 / 2 / 0 / 0 / 0 | 1 | 6830.4 | 7749.5 | 7749.5 | none approved |
| protected/benign | fresh_host_per_arm_os_cache_uncontrolled | candidate | 12 | 10 / 2 / 0 / 0 / 0 | 0 | 10 / 2 / 0 / 0 / 0 | 1 | 6830.4 | 7749.5 | 7749.5 | none approved |
| protected/refusal | fresh_host_per_arm_os_cache_uncontrolled | baseline | 8 | 8 / 0 / 0 / 0 / 0 | 0 | 8 / 0 / 0 / 0 / 0 | 1 | 6789.5 | 6871.7 | 6871.7 | none approved |
| protected/refusal | fresh_host_per_arm_os_cache_uncontrolled | candidate | 8 | 8 / 0 / 0 / 0 / 0 | 0 | 8 / 0 / 0 / 0 / 0 | 1 | 6789.5 | 6871.7 | 6871.7 | none approved |

## Identity control

Identical evidence on both sides: 38 trial pairs, all paired differences zero: **True**. comparator control only: identical evidence must give zero paired differences. It establishes no provenance, no compatibility and no performance change.

## Report-level endpoints (baseline, single values, never compared)

- `asset_install_and_daemon_prepare_ms`: 10816.6 ms (asset install and daemon preparation only)
- `external_build_time`: not_measured_prebuilt_selected_binaries none (not measured by this producer)
- `observable_ask_latency`: not_applicable none (the workload has no operator Ask decision)
- `preparation_ms`: 11845.5 ms (run start through selection verification, asset install and daemon preparation)
- `source_and_selection_verification_ms`: 1028.9 ms (run start to verified source and selection)

## Report-level endpoints (candidate, single values, never compared)

- `asset_install_and_daemon_prepare_ms`: 10816.6 ms (asset install and daemon preparation only)
- `external_build_time`: not_measured_prebuilt_selected_binaries none (not measured by this producer)
- `observable_ask_latency`: not_applicable none (the workload has no operator Ask decision)
- `preparation_ms`: 11845.5 ms (run start through selection verification, asset install and daemon preparation)
- `source_and_selection_verification_ms`: 1028.9 ms (run start to verified source and selection)

## Differences (candidate minus baseline, primary endpoint)

- none: no comparable stratum. No speed-up, merged p95 or verdict is reported.

## Limits

- Percentiles: nearest rank: the value at rank ceil(q * n) of the ascending sample, unrounded (pilot_ask_latency.summarize). Published sw-ask-series/1 distributions round to 0.001 ms first; reproduction uses that producer convention.
- Inference: descriptive only. independent_clusters_below_minimum: at most 1 runs per stratum, minimum 10 effective clusters (DEC-SOU153-20261027) no_accepted_performance_cluster_method: the SOU-153 bootstrap is approved only for AgentDojo semantic families repeated_trials_within_a_run_are_dependent: one qualifier process and host per run
- Not retained: failed_arm_timings, host_instance, trace_observed.
- Outcomes: Row status and the gate are the producer's development workflow outcomes. A protected refusal is witnessed by the producer's own repository witness (effect_observed, original_opens) and is not re-observed here. No status is security or protection effectiveness evidence.
- Engineering latency diagnostics for recorded native Ask series only.
- Not a security or protection qualification, not task effectiveness, not product or pilot readiness.
- Trace-on is the only observer mode of this producer; no trace-off result exists here, and none would qualify protection.
- The 3000 ms continuation p95 criterion and the 5000 ms first-pending bound are existing engineering criteria, reported separately; no new budget is approved.
- A same-report identity control proves the comparator, not a performance change between revisions.
