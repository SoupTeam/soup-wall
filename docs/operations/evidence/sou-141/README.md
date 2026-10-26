# SOU-141 evidence: cold and warm original-server Ask latency

This directory holds the retained evidence for the series tool in
`scripts/qualify-ask-series.py`. Nothing here was edited by hand except where
stated. Native results and WSL2 results are separate and are never pooled.

## Native Linux (`native_linux`), exact source

- Source: commit `12f3f2bff98d77693a19c541f9a0a2ef8e708b89`, tree
  `82046c012a4a8b93d74cea33f1e45cd8fae83130`, clean working tree. Commits added after
  it on this branch only add this evidence and the note; they do not change code.
- Machine: GitHub-hosted `ubuntu-24.04` runner (4 CPUs, about 16 GiB RAM, kernel
  `6.17.0-1022-azure`), workflow run 40249648823 (workflow `mcp-real-filesystem.yml`
  with `native_preparation_only=true`, `ask_series=cold,warm,cold,warm`).
- Plan declared in `native-ask-series-manifest.json` before the first trial. 20
  approvals per profile per run, `--require-verified-reuse`, pinned hash-locked inputs.
- Status: `complete`, `performance_blockers: []`. All 4 runs validated, 160 of 160
  trials succeeded (0 failed, 0 incomplete). Raw per-trial values and every run are in
  `native-ask-series-summary.json`.

Runs (each ran about 9 minutes; the whole dispatch took 1 h 4 min):

| Run | Kind | Validated | Wall seconds |
|---|---|---|---|
| 1 | cold | yes | 555.8 |
| 2 | warm | yes | 556.2 |
| 3 | cold | yes | 556.3 |
| 4 | warm | yes | 557.1 |

Pooled per kind (two runs each, 40 trials per profile), milliseconds:

| Kind | Profile | Trials (ok/planned) | Continuation p50 / p95 / worst (ms) | First-pending asset verification p50 / p95 / worst (ms) | p95 target 3000 ms |
|---|---|---|---|---|---|
| cold | filesystem | 40/40 | 992 / 1059 / 1108 | 1093 / 1150 / 1154 | met |
| cold | git | 40/40 | 1366 / 1413 / 1521 | 1317 / 1357 / 1466 | met |
| warm | filesystem | 40/40 | 993 / 1035 / 1065 | 1104 / 1141 / 1142 | met |
| warm | git | 40/40 | 1335 / 1410 / 1426 | 1317 / 1340 / 1431 | met |

Stage distributions (p50 / p95 / worst, milliseconds):

| Kind | Profile | package_tree pass 1 | package_tree pass 2 | runtime_and_libraries pass 1 | approval stages after observation (total) |
|---|---|---|---|---|---|
| cold | filesystem | 970 / 1026 / 1028 | 743 / 756 / 824 | 122 / 131 / 134 | 916 / 955 / 1001 |
| cold | git | 1247 / 1288 / 1387 | 1064 / 1083 / 1171 | 68 / 69 / 77 | 1276 / 1303 / 1429 |
| warm | filesystem | 979 / 1017 / 1025 | 742 / 754 / 762 | 123 / 135 / 140 | 911 / 945 / 957 |
| warm | git | 1246 / 1271 / 1352 | 1063 / 1084 / 1112 | 67 / 71 / 77 | 1276 / 1304 / 1347 |

Notes on reading these numbers:

- Continuation is the operator decision attempt to the correlated original-server
  result (`decision_to_result_ms`, monotonic). The 3000 ms p95 target is unchanged and
  was met by a wide margin in every run.
- First-pending is the sum of the three pass-1 asset-verification stages per trial, the
  collector work before the pending approval is published. It excludes the host call
  start, so it is a lower bound of the operator-visible wait. The worst value seen was
  1466 ms. The 5-second pending bound is enforced and reported by the SOU-105
  acceptance, not by this series.
- Cold and warm runs came out almost the same. The page-cache drop was shown in both
  cold runs (cached memory fell from 6297160 kB to 313280 kB, and from 1039988 kB to
  315004 kB), so the cold label is earned. Why it made no visible latency difference
  here was not investigated; package_tree hashing dominates in both.
- `immutable_files` was 0 in every trial, with 52 (filesystem) or 144 (git) leased
  files and 4037 or 5673 rehashed files per approval. So no fs-verity reuse was
  observed on this runner. Whether the kernel, file system or profile files lack
  verity was not investigated.
- The runner was shared: load average 1.4 to 2.8 and CPU pressure around 5 to 7 percent
  during runs (`conditions_before` and `conditions_after` in each run record).

## WSL2 (`wsl2`)

Machine: WSL2 on a 6-vCPU laptop with 3.6 GiB RAM, kernel `6.6.114.1-microsoft-standard-WSL2`.
The official native preparation scripts refuse WSL, so inputs were prepared separately.

`wsl2-ask-series.json`: four runs on source `eb6aa6a5` (before the current main). Run 1 was
the first run after setup and is undeclared; runs 2 (warm), 3 (cold) and 4 (cold) follow
the declared definitions. These runs were summarized after the fact, so their `validated`
field is false and no per-stage timings are included (without the verified-reuse report the
collector passes cannot be separated reliably). Pooled over the two cold runs
(40 trials per profile): filesystem p95 2974 ms (target met), git p95 4816 ms, worst
5256 ms (target not met). The warm run: filesystem p95 2887 ms, git p95 2401 ms (both met).
Slow git trials come in runs of consecutive trials (for example 17 of 20 in run 3, then a drop)
rather than at random. The cause was not identified.

`wsl2-acceptance.json`: every SOU-105 selected-approval acceptance attempt on this
machine, including failed ones:

- `sou105-wsl-1` failed before any git case (missing libtcl/libtk for the bundled
  python), an environment problem.
- `sou105-wsl-2` passed on `eb6aa6a5`.
- `sou105-wsl-3-pr` and `sou105-wsl-4-pr-warm` failed with "pending approval state missed
  declared deadline" in the git family (on the first case and on the tenth). Source was
  `7d1b025`, which differs from main `a5c6172` only in series tooling, workflow and
  documentation; no Rust code and not the acceptance script. So these runs say how
  `a5c6172` behaves on this machine.
- `sou105-wsl-5-base` passed on `eb6aa6a5`, as a control on the same machine.
- Between `eb6aa6a5` and `a5c6172` main gained SOU-83 create-only work, including a
  change that loads and releases a pinned original filesystem write profile. That is a
  plausible but unproven cause. On this machine git `package_tree` takes about 4.3 s
  (p50), close to the 5 s pending bound, so the margin is thin. No claim is made that
  this is a regression or that it is not.

## Limits

- Operator decisions are explicit same-user actions in an owned harness, not proof of
  physical presence. The provider is scripted and loopback-only; no paid model call was
  made.
- Stage timings come from the collector clock and start when the collector observes the
  approval.
- No runtime code was changed. The native repeated trials did not reproduce a defect.
  The WSL2 margin on the git profile is reported here for a separate decision.
- The existing first-use list/inspect/approve path, input tamper, expiry, rejection,
  changed run binding, replay, daemon loss and stop cases stay covered by the SOU-105
  original-host qualification (13 cases per family), not re-implemented here.
