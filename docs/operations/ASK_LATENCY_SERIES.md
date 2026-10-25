# Cold and warm original-server Ask latency series (SOU-141)

This note covers the evidence tool only. It changes no timeout, TTL, scan bound,
resource limit or admission rule, and it does not move verification after approval.

## What is measured

`scripts/qualify-ask-series.py run` executes the existing
`scripts/qualify-pilot-ask.py --approval-samples N` workflow once per entry of a
plan that is written to `manifest.json` before the first trial. Per profile
(`filesystem`, `git`) it records, for every trial:

- continuation time: operator decision attempt to the correlated original-server
  result (`decision_to_result_ms`, monotonic). The existing p95 target of 3000 ms
  is unchanged;
- the per-stage timings that the harness collector prints
  (`mcp_asset_verification_timing`: `runtime_and_libraries`, `package_tree`,
  `selected_profile`), grouped by pass within each host launch;
- the first-pass asset-verification total per host launch, as a **proxy** for the
  work done before the pending approval is published (the harness does not print a
  call-start event, so the exact first-pending time is not available here);
- the reuse counts (`immutable_files`, `leased_files`, `rehashed_files`).

p50, p95 (nearest rank) and worst are reported per run and pooled per run kind,
always with planned, successful, failed and incomplete counts. The worst trial is
never dropped.

## Cold and warm

- `cold`: `sync` followed by `drop_caches` immediately before the run. The drop must
  be shown by a measurable page-cache shrink. If it cannot be shown the run is
  labeled `cold_unavailable`, stays in the report, and is excluded from the cold pool.
- `warm`: started right after the previous run, with no cache drop.
- A plan starts with `cold`, has at most six runs, and is declared up front, for
  example `cold,warm,cold,warm`. Every attempt (also failed or timed-out) is kept in
  `runs/NN-kind/run.json`. The series is `complete` only when every planned run
  produced a validated report with all planned trials successful; otherwise it is
  `incomplete` and the command exits non-zero. A missed 3000 ms target is reported
  under `performance_blockers`; add `--fail-on-blocker` to make it fail the command.

## Running on native Ubuntu

Dispatch `mcp-real-filesystem.yml` on the branch with `native_preparation_only=true`
and `ask_series=cold,warm,cold,warm`. The job reuses the existing native preparation,
the real installed Ask capture/resume check and the hash-locked offline inputs, then
runs the series with `--require-verified-reuse` and exact-source validation (clean
tree, expected commit, build receipt, selected binary digests). The job cap for this
mode is 180 minutes. The artifact contains `manifest.json`, `summary.json`, each
`run.json`, each `qualification.json` and each `stage-events.jsonl`. Private
harness output (grants, raw arguments, traces) stays in a separate directory and is
not uploaded. `ask_series` cannot be combined with `ask_latency_baseline_sha`.

The first-use list/inspect/approve path, input tamper before and after pending,
expiry, rejection, changed run binding, replay, daemon loss and stop are not
re-implemented here. They stay covered by the existing original-host qualification
(`scripts/verify-sou105-selected-approval.py`, 13 cases per family) that the native
job and the WSL2 runs execute.

## Costs

Each run is 40 approvals (20 per profile) through the real host and original servers.
Measured on a 6-vCPU, 3.7 GiB WSL2 machine, one run takes about 17 to 20 minutes, so a
four-run plan is roughly 70 to 80 minutes before preparation. Native hosted-runner
timing is not assumed here; the artifact records `wall_seconds` per run.

## Supported evidence and limits

- Only `platform_kind: native_linux` results are native Linux evidence. A WSL2 kernel
  is labeled `wsl2` and never stands in for native results. WSL2 has its own
  preparation and acceptance; the official native preparation scripts refuse it.
- WSL2 does not provide fs-verity, so there every verified input is leased or
  rehashed. Such results do not demonstrate the optimized fs-verity path.
- Operator decisions are explicit same-user CLI actions in an owned harness, not proof
  of physical presence. The provider is scripted and loopback-only; no paid model call
  is made (`paid_api_calls` is validated as 0).
- `mcp_real_approval_timing` events (decision-side stages) are not printed by this
  harness, so decision-side stage distributions come from the SOU-105 acceptance logs
  instead, not from the series.
- Run-to-run variance on shared or small machines is real. The series reports it
  instead of hiding it; a single slow cold run is not by itself a code defect.
