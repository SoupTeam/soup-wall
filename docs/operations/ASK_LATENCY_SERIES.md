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
- per-trial collector stage timings from the reuse proof
  (`verified_inputs_resume.diagnostic_timings`, present with `--require-verified-reuse`):
  asset verification (`runtime_and_libraries`, `package_tree`, `selected_profile`) for
  pass 1 (before the pending approval is published) and pass 2 (revalidation after the
  approval), and the approval stages (`profile_and_assets`, `policy_boundary`,
  `classifier`, `daemon_redemption`, `original_dispatch`, `original_response`,
  `result_inspection`, with their `post_observed_ms` total);
- first-pending: the sum of the pass-1 asset-verification stages per trial, i.e. the
  collector-side work before the pending approval is published. It does not include
  the host call start, so it is a lower bound of the operator-visible wait. The
  5-second pending bound itself is enforced and reported by the SOU-105 acceptance
  (`pending approval state missed declared deadline`);
- the reuse counts (`immutable_files`, `leased_files`, `rehashed_files`);
- the raw stage events copied from the private harness logs (`stage-events.jsonl`) as a
  cross-check.

p50, p95 (nearest rank) and worst are reported per run and pooled per run kind,
always with planned, successful, failed and incomplete counts. The worst trial is
never dropped.

## Cold and warm

- `cold`: `sync` followed by `drop_caches` immediately before the run. The drop must
  be shown by a measurable page-cache shrink. If it cannot be shown the run is
  labeled `cold_unavailable`, stays in the report, and is excluded from the cold pool.
  This is a pre-run condition only. The qualifier then prepares the original launch
  (hashes and copies the selected binaries, installs and hashes both profiles) and
  reads the same pages again before any timed approval, and no cache drop happens
  between trials. So the trials of a `cold` run are not claimed to be cold Ask
  samples. Pooled results call this kind `post_cache_drop_setup_rewarmed` and report
  the first trial per profile (`initial_trial_ms`) apart from the repetitions
  (`repeat_trials_ms`). A genuinely cold per-trial barrier is not implemented.
- `warm`: started right after the previous run, with no cache drop.
- A plan starts with `cold`, has at most six runs, and is declared up front, for
  example `cold,warm,cold,warm`. Every attempt (also failed or timed-out) is kept in
  `runs/NN-kind/run.json`.
- A run qualifies only when its subprocess exited successfully (`exit_code` 0, no
  `failure`) and its report validated against the current source and selected inputs.
  A report left behind by a failed subprocess is kept for inspection but never
  qualifies. Pooled distributions use qualified runs only; every other attempt of the
  kind stays in `unqualified_runs` with its own totals, and `summary.json` carries an
  `attempts` ledger.
- The series is `complete` only when every planned run qualified with all planned
  trials successful; otherwise it is `incomplete` and the command exits non-zero. A
  missed 3000 ms target is reported under `performance_blockers`; add
  `--fail-on-blocker` to make it fail the command.

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
On a GitHub-hosted `ubuntu-24.04` runner the final series (`12f3f2b`) took 555.8 to
557.1 seconds per run (`wall_seconds` in each `run.json`; an earlier series on the same
runner took 615 to 634 seconds), and the whole four-run dispatch, including native
preparation, finished in 1 hour 4 minutes. On a 6-vCPU, 3.7 GiB WSL2 laptop a run took
roughly 17 to 20 minutes by wall clock (not recorded in a report). Retained results are
in `docs/operations/evidence/sou-141/`.

## Supported evidence and limits

- Only `platform_kind: native_linux` results are native Linux evidence. A WSL2 kernel
  is labeled `wsl2` and never stands in for native results. WSL2 has its own
  preparation and acceptance; the official native preparation scripts refuse it.
- On the WSL2 machine no fs-verity reuse was observed (`immutable_files` is 0), and the
  same was observed on the native hosted runner. Whether the kernel, the file system or
  the profile files lack verity was not investigated, so these results do not
  demonstrate an fs-verity path.
- Operator decisions are explicit same-user CLI actions in an owned harness, not proof
  of physical presence. The provider is scripted and loopback-only; no paid model call
  is made (`paid_api_calls` is validated as 0).
- Stage timings come from the collector's own monotonic clock and start when the
  collector observes the approval, not when the operator decides. Without
  `--require-verified-reuse` (for example a WSL2 run) the per-trial diagnostics are not
  attached to the qualification report, and only the raw stage events remain.
- Even with the real reuse proof present, `immutable_files` can be 0 (fs-verity not in
  use). Reuse then rests on read leases and most files are still rehashed, so
  `package_tree` hashing dominates both passes.
- Run-to-run variance on shared or small machines is real. The series reports it
  instead of hiding it; a single slow cold run is not by itself a code defect.
