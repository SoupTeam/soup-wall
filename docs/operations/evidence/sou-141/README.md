# SOU-141 evidence: cold and warm original-server Ask latency

This directory holds the retained evidence for the series tool in
`scripts/qualify-ask-series.py`. Nothing here was edited by hand except where
stated. Native results and WSL2 results are separate and are never pooled.

## Scope of this evidence

These results are historical evidence for the exact commit named below and for nothing
else. The branch was merged with newer main afterwards, which changes executable code
(for example the admission, native approval and original-create code and the SOU-105
acceptance script). Later functional CI results are not performance qualification.
The measurement files are kept unchanged, and the reviewed tool was fixed after this
run (see "Review follow-up"). The final qualification on the reviewed source
is the section "Final exact-source series (`4b99b6e`)" below.

## Native Linux (`native_linux`), measured commit

- Source: commit `12f3f2bff98d77693a19c541f9a0a2ef8e708b89`, tree
  `82046c012a4a8b93d74cea33f1e45cd8fae83130`, clean working tree. Only the series
  tooling, workflow and documentation of this PR differed from main `a5c6172` at that commit. The branch head has
  moved on since (see above), so this is not evidence for the current head.
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

Pooled per kind (two runs each, 40 trials per profile), milliseconds. "cold" here means
post-cache-drop, setup-rewarmed (see above):

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
- Cold and warm runs came out almost the same. The page-cache drop before the run was
  shown in both `cold` runs (cached memory fell from 6297160 kB to 313280 kB, and from
  1039988 kB to 315004 kB). It is a pre-run condition only: the qualifier prepares the
  original launch afterwards and re-reads the inputs before any timed approval, and the
  cache is not dropped between trials. So the `cold` rows below are post-cache-drop,
  setup-rewarmed measurements, not 40 cold Ask samples. Package_tree hashing dominates
  in both kinds.
- `immutable_files` was 0 in every trial, with 52 (filesystem) or 144 (git) leased
  files and 4037 or 5673 rehashed files per approval. So no fs-verity reuse was
  observed on this runner. Whether the kernel, file system or profile files lack
  verity was not investigated.
- The runner was shared: load average 1.4 to 2.8 and CPU pressure around 5 to 7 percent
  during runs (`conditions_before` and `conditions_after` in each run record).

## Final exact-source series (`4b99b6e`)

Run after the review fixes and after refreshing the branch from main `46921f8`, with the
fixed tool (successful execution plus validation required, cold kind labeled as a pre-run
cache drop only).

- Source: commit `4b99b6efee6bfd3e603b207d841015d179962977`, tree
  `5db4a81ee8e65e389663c974abb690d5fb34ed6a`, clean working tree. Files:
  `native-final-ask-series-manifest.json` and `native-final-ask-series-summary.json`.
- Machine: GitHub-hosted `ubuntu-24.04` runner, kernel `6.17.0-1022-azure`, workflow run
  40346352153, plan `cold,warm,cold,warm`, 20 approvals per profile per run,
  `--require-verified-reuse`.
- Status `complete`, `performance_blockers: []`, `attempts.qualified_runs: [1, 2, 3, 4]`,
  no unqualified attempt. 160 of 160 trials succeeded.
- The two `cold` runs are post-cache-drop, setup-rewarmed measurements (cached memory fell
  from 5446144 kB to 313792 kB and from 1042564 kB to 315332 kB before the run). They are
  not cold Ask samples: the setup re-reads the inputs and the cache is not dropped between
  trials.

| Run | Kind | Qualified | Wall seconds |
|---|---|---|---|
| 1 | cold | yes (exit 0, validated) | 622.2 |
| 2 | warm | yes (exit 0, validated) | 613.4 |
| 3 | cold | yes (exit 0, validated) | 614.7 |
| 4 | warm | yes (exit 0, validated) | 613.4 |

Pooled per kind (two runs each, 40 trials per profile), milliseconds:

| Kind | Profile | Trials (ok/planned) | Continuation p50 / p95 / worst (ms) | First trial per run (ms) | Repetitions p50 / p95 / worst (ms) | First-pending asset verification p50 / p95 / worst (ms) | p95 target 3000 ms |
|---|---|---|---|---|---|---|---|
| post-drop, setup-rewarmed | filesystem | 40/40 | 1199 / 1265 / 1298 | 1235, 1265 | 1199 / 1267 / 1298 | 1233 / 1319 / 1330 | met |
| post-drop, setup-rewarmed | git | 40/40 | 1580 / 1679 / 1692 | 1546, 1670 | 1580 / 1682 / 1692 | 1503 / 1561 / 1611 | met |
| warm | filesystem | 40/40 | 1206 / 1257 / 1270 | 1186, 1201 | 1206 / 1268 / 1270 | 1246 / 1306 / 1315 | met |
| warm | git | 40/40 | 1594 / 1635 / 1665 | 1591, 1542 | 1598 / 1640 / 1665 | 1501 / 1543 / 1553 | met |

Stage distributions (p50 / p95 / worst, milliseconds):

| Kind | Profile | package_tree pass 1 | package_tree pass 2 | runtime_and_libraries pass 1 | approval stages after observation (total) |
|---|---|---|---|---|---|
| post-drop, setup-rewarmed | filesystem | 1123 / 1201 / 1208 | 922 / 940 / 950 | 119 / 131 / 142 | 1125 / 1157 / 1172 |
| post-drop, setup-rewarmed | git | 1435 / 1489 / 1543 | 1267 / 1310 / 1378 | 67 / 71 / 72 | 1508 / 1575 / 1624 |
| warm | filesystem | 1129 / 1191 / 1198 | 925 / 945 / 950 | 118 / 133 / 140 | 1126 / 1146 / 1152 |
| warm | git | 1433 / 1474 / 1485 | 1271 / 1303 / 1323 | 66 / 70 / 72 | 1518 / 1572 / 1593 |

Notes:

- Every run stayed well inside the 3000 ms p95 target. The worst trial was 1692 ms
  (git). The worst first-pending lower bound was 1611 ms against the 5 s pending bound.
- The numbers are slower than the earlier series on `12f3f2b` (git continuation p95 about
  1.64 to 1.68 s against 1.41 s, filesystem about 1.26 s against 1.05 s). Different
  runner instance and a different source (main moved). The cause was not investigated and
  is not attributed to either.
- The first trial per profile is not slower than the repetitions here, and the post-drop
  and warm kinds are again almost the same.
- Again no fs-verity reuse was observed: `immutable_files` was 0 in every trial, with 52
  (filesystem) or 144 (git) leased files per approval. Limits are as for the earlier series.

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

## Review follow-up

The review of this PR found that the first version of the tool could report a complete,
passing series from a run whose subprocess had failed or whose report did not validate
for the current source. The tool now requires successful execution plus validation,
keeps every other attempt visible with its own totals, and states that the `cold` kind
is a pre-run cache drop only. Negative regression tests cover a valid-looking report
left by a failed subprocess and an unvalidated run. The 160 trials above were produced by
the earlier version of the tool and are kept as they were; all four runs there exited
successfully and validated, so the gating change does not alter them.

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
