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

## Observer and trace semantics

- baseline: timing qualify-pilot-ask.py harness monotonic clock; collector monotonic clock for stages; trace strace seccomp-bpf requested (fallback possible); the observed mode is not retained
- candidate: timing qualify-pilot-ask.py harness monotonic clock; collector monotonic clock for stages; trace strace seccomp-bpf requested (fallback possible); the observed mode is not retained

## Limits

- Percentiles: nearest rank: the value at rank ceil(q * n) of the ascending sample of measured trials, unrounded (pilot_ask_latency.summarize); failed, timed-out, incomplete and not-run trials are counted, never imputed. Ask qualification: published p50/p95 are nearest rank on unrounded values.
- Inference: descriptive only. independent_clusters_below_minimum: at most 1 runs per stratum, minimum 10 effective clusters (DEC-SOU153-20261027) no_accepted_performance_cluster_method: the SOU-153 bootstrap is approved only for AgentDojo semantic families repeated_trials_are_dependent: Ask: trials within a run share one qualifier process and one host
- Not retained: cleanup, first_observable_pending, preparation_elapsed, raw_stage_events, trace_observed.
- Engineering performance diagnostics for the recorded reports only.
- Not a security or protection qualification, not task effectiveness, not product or pilot readiness.
- No new budget or threshold is approved.
- A same-report identity control proves the comparator, not a performance change between revisions.
- Ask: trace-on (strace seccomp-bpf) is the only observer mode of this producer; no trace-off result exists here, and none would qualify protection.
