# Native performance comparison

Classification: **non-comparable** (two_reports).

| Role | Input | Original SHA-256 | Custody | Source | Binaries | Build |
|---|---|---|---|---|---|---|
| baseline | `docs/operations/evidence/sou106/attempt-2.json` | `db4e047e104b2e67…` | committed_blob | verified_git_objects | declared_only | not_retained |
| candidate | `docs/operations/evidence/sou106/measured-report.json` | `6f3173364ded8d34…` | committed_blob | verified_git_objects | declared_only | not_retained |

## Reasons

- `binary_identity_unverified` (binaries): binary digests are not independently bound
- `build_profile_unverified` (build): build profile is not bound to the measured binaries
- `cpu_count_unverified` (cpu_count): not retained on one side
- `host_instance_unverified` (host_instance): neither report retains its host instance; same-host conditions cannot be established
- `kernel_unverified` (kernel): not retained on one side
- `machine_unverified` (machine): not retained on one side
- `memory_unverified` (memory): not retained on one side
- `platform_unverified` (platform): not retained on one side
- `trace_requested_unverified` (trace_requested): not retained on one side
- `workload_or_harness_changed` (workload): measurement harness differs between sources

## Strata (primary endpoint: host_start_ms (ms))

Counts are measured / failed / timed out / incomplete / not run. Distributions use qualified runs only; trials of unqualified runs stay counted under all runs.

| Stratum | Condition | Role | Planned | All runs | Excluded (unqualified runs) | Qualified runs | Runs | p50 | p95 | max | Engineering criterion |
|---|---|---|---:|---|---:|---|---:|---:|---:|---:|---|
| control/benign | fresh_host_per_arm_os_cache_uncontrolled | baseline | 12 | 11 / 1 / 0 / 0 / 0 | 0 | 11 / 1 / 0 / 0 / 0 | 1 | 1423.0 | 1463.7 | 1463.7 | none approved |
| control/benign | fresh_host_per_arm_os_cache_uncontrolled | candidate | 12 | 12 / 0 / 0 / 0 / 0 | 0 | 12 / 0 / 0 / 0 / 0 | 1 | 1209.0 | 1267.8 | 1267.8 | none approved |
| control/refusal | fresh_host_per_arm_os_cache_uncontrolled | baseline | 8 | 8 / 0 / 0 / 0 / 0 | 0 | 8 / 0 / 0 / 0 / 0 | 1 | 1412.8 | 1552.2 | 1552.2 | none approved |
| control/refusal | fresh_host_per_arm_os_cache_uncontrolled | candidate | 8 | 8 / 0 / 0 / 0 / 0 | 0 | 8 / 0 / 0 / 0 / 0 | 1 | 1202.6 | 1370.9 | 1370.9 | none approved |
| protected/benign | fresh_host_per_arm_os_cache_uncontrolled | baseline | 12 | 9 / 3 / 0 / 0 / 0 | 0 | 9 / 3 / 0 / 0 / 0 | 1 | 5098.7 | 5794.5 | 5794.5 | none approved |
| protected/benign | fresh_host_per_arm_os_cache_uncontrolled | candidate | 12 | 10 / 2 / 0 / 0 / 0 | 0 | 10 / 2 / 0 / 0 / 0 | 1 | 6830.4 | 7749.5 | 7749.5 | none approved |
| protected/refusal | fresh_host_per_arm_os_cache_uncontrolled | baseline | 8 | 8 / 0 / 0 / 0 / 0 | 0 | 8 / 0 / 0 / 0 / 0 | 1 | 5088.4 | 5446.6 | 5446.6 | none approved |
| protected/refusal | fresh_host_per_arm_os_cache_uncontrolled | candidate | 8 | 8 / 0 / 0 / 0 / 0 | 0 | 8 / 0 / 0 / 0 / 0 | 1 | 6789.5 | 6871.7 | 6871.7 | none approved |

## Report-level endpoints (baseline, single values, never compared)

- `asset_install_and_daemon_prepare_ms`: 14332.9 ms (asset install and daemon preparation only)
- `external_build_time`: not_measured_prebuilt_selected_binaries none (not measured by this producer)
- `observable_ask_latency`: not_applicable none (the workload has no operator Ask decision)
- `preparation_ms`: 15686.5 ms (run start through selection verification, asset install and daemon preparation)
- `source_and_selection_verification_ms`: 1353.5 ms (run start to verified source and selection)

## Report-level endpoints (candidate, single values, never compared)

- `asset_install_and_daemon_prepare_ms`: 10816.6 ms (asset install and daemon preparation only)
- `external_build_time`: not_measured_prebuilt_selected_binaries none (not measured by this producer)
- `observable_ask_latency`: not_applicable none (the workload has no operator Ask decision)
- `preparation_ms`: 11845.5 ms (run start through selection verification, asset install and daemon preparation)
- `source_and_selection_verification_ms`: 1028.9 ms (run start to verified source and selection)

## Differences (candidate minus baseline, primary endpoint)

- none: no comparable stratum. No speed-up, merged p95 or verdict is reported.

## Observer and trace semantics

- baseline: timing qualify-installed-pilot.py driver monotonic clock around a fresh Claude Code host per arm and a scripted loopback provider; trace no trace or observer mode is recorded by this producer
- candidate: timing qualify-installed-pilot.py driver monotonic clock around a fresh Claude Code host per arm and a scripted loopback provider; trace no trace or observer mode is recorded by this producer

## Limits

- Percentiles: nearest rank: the value at rank ceil(q * n) of the ascending sample of measured trials, unrounded (pilot_ask_latency.summarize); failed, timed-out, incomplete and not-run trials are counted, never imputed. Installed host: the published gate uses agentdojo_protocol.distribution (median = mean of the two middle values for even n); SOU-203 reports nearest-rank p50, so it can differ from a published median. Per-call distributions count calls, not arms.
- Inference: descriptive only. independent_clusters_below_minimum: at most 1 runs per stratum, minimum 10 effective clusters (DEC-SOU153-20261027) no_accepted_performance_cluster_method: the SOU-153 bootstrap is approved only for AgentDojo semantic families repeated_trials_are_dependent: Installed host: calls within an arm share one host process; all arms of a report share one runner and dispatch; the control arm always runs first
- Not retained: failed_arm_timings, host_instance, trace_observed.
- Outcomes: Row status and the gate are the producer's development workflow outcomes. A protected refusal is witnessed by the producer's own repository witness (effect_observed, original_opens) and is not re-observed here. No status is security or protection effectiveness evidence.
- Engineering performance diagnostics for the recorded reports only.
- Not a security or protection qualification, not task effectiveness, not product or pilot readiness.
- No new budget or threshold is approved.
- A same-report identity control proves the comparator, not a performance change between revisions.
- Installed host: row status and the gate are producer development outcomes; protected refusals are producer-witnessed, never independently observed protection.
