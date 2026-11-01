# Native performance comparison

Classification: **incomplete** (identity_control).

| Role | Input | Original SHA-256 | Custody | Source | Binaries | Build |
|---|---|---|---|---|---|---|
| baseline | `docs/operations/evidence/sou-124/native-attempt2-baseline.json` | `e7d29d905ba82006…` | committed_blob | commit_tree_verified_files_not_declared | declared_only | not_retained |
| candidate | `docs/operations/evidence/sou-124/native-attempt2-baseline.json` | `e7d29d905ba82006…` | committed_blob | commit_tree_verified_files_not_declared | declared_only | not_retained |

## Reasons

- `binary_identity_unverified` (binaries): binary digests are not independently bound
- `build_profile_unverified` (build): build profile is not bound to the measured binaries
- `cpu_count_unverified` (cpu_count): not retained on one side
- `kernel_unverified` (kernel): not retained on one side
- `machine_unverified` (machine): not retained on one side
- `memory_unverified` (memory): not retained on one side
- `platform_unverified` (platform): not retained on one side
- `source_contents_unverified` (source): commit and tree verified; tracked file contents are not bound by a declared files_sha256
- `trace_requested_unverified` (trace_requested): not retained on one side

## Strata (primary endpoint: continuation_ms (ms))

Counts are measured / failed / timed out / incomplete / not run. Distributions use qualified runs only; trials of unqualified runs stay counted under all runs.

| Stratum | Condition | Role | Planned | All runs | Excluded (unqualified runs) | Qualified runs | Runs | p50 | p95 | max | Engineering criterion |
|---|---|---|---:|---|---:|---|---:|---:|---:|---:|---|
| filesystem | undeclared | baseline | 20 | 20 / 0 / 0 / 0 / 0 | 0 | 20 / 0 / 0 / 0 / 0 | 1 | 8742.4 | 8841.0 | 8850.2 | not_met |
| filesystem | undeclared | candidate | 20 | 20 / 0 / 0 / 0 / 0 | 0 | 20 / 0 / 0 / 0 / 0 | 1 | 8742.4 | 8841.0 | 8850.2 | not_met |
| git | undeclared | baseline | 20 | 20 / 0 / 0 / 0 / 0 | 0 | 20 / 0 / 0 / 0 / 0 | 1 | 11216.2 | 11310.1 | 11385.9 | not_met |
| git | undeclared | candidate | 20 | 20 / 0 / 0 / 0 / 0 | 0 | 20 / 0 / 0 / 0 / 0 | 1 | 11216.2 | 11310.1 | 11385.9 | not_met |

## Identity control

Identical evidence on both sides: 40 trial pairs, all paired differences zero: **True**. comparator control only: identical evidence must give zero paired differences. It establishes no provenance, no compatibility and no performance change.

## Differences (candidate minus baseline, primary endpoint)

- none: no comparable stratum. No speed-up, merged p95 or verdict is reported.

## Limits

- Percentiles: nearest rank: the value at rank ceil(q * n) of the ascending sample, unrounded (pilot_ask_latency.summarize). Published sw-ask-series/1 distributions round to 0.001 ms first; reproduction uses that producer convention.
- Inference: descriptive only. independent_clusters_below_minimum: at most 1 runs per stratum, minimum 10 effective clusters (DEC-SOU153-20261027) no_accepted_performance_cluster_method: the SOU-153 bootstrap is approved only for AgentDojo semantic families repeated_trials_within_a_run_are_dependent: one qualifier process and host per run
- Not retained: cleanup, external_build_time, first_observable_pending, preparation_elapsed, raw_stage_events, trace_observed.
- Engineering latency diagnostics for recorded native Ask series only.
- Not a security or protection qualification, not task effectiveness, not product or pilot readiness.
- Trace-on is the only observer mode of this producer; no trace-off result exists here, and none would qualify protection.
- The 3000 ms continuation p95 criterion and the 5000 ms first-pending bound are existing engineering criteria, reported separately; no new budget is approved.
- A same-report identity control proves the comparator, not a performance change between revisions.
