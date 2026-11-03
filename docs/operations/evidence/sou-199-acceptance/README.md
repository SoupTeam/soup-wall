# SOU-199 development acceptance ledger

Base: accepted `b385e7506ab26896637f348e3180e52d1fc6d423`.
This ledger distinguishes offline simulation, observed native feature behavior
and final shared merge qualification. No configuration or simulation is claimed
as active protection. Native Linux feature qualification passed on the implementation commit recorded
below; full Ready/security/current-main admission is TL-owned.

Local macOS checks used read-only source, scratch-only writes, loopback-only
networking and isolated environment/cache paths. The new command is Linux-only;
these local checks do not typecheck or execute its Linux module.

| Check | Actual result | Source snapshot SHA-256 | Log SHA-256 |
| --- | --- | --- | --- |
| Workspace tests | 1951 passed, 0 failed, 13 explicit platform/environment ignores | `0e2188e14ff349bdb68e2ac32b7dccec5f36e10b2df0015d85f7efafbc547b87` | `c91a5803a8f057584ca4f0924c12a6e0f579b9c9212aaeaa3ae4725cbe6c4976` |
| Workspace all-target Clippy, `-D warnings` | passed | `228f2790388a10da4e0ee3658d217e74d1b70bd0e0009697f01b5d5dca6d85cc` | `f9bcfd133a1ffc82f99ba2e84f1dff41c8bd25e02a3f88de7e2bcc85b4ee267b` |
| Formatting, two policy grader controls, 21 existing build-custody controls | passed | `c0b45a846ad1cb0f73d75ca01f7e514ed5b737ab2cf1ede045766b734ee5c713` | `1115fb5039207e06ed69388e71fffbfa70115b08b94d9520490645efe263743b` |
| Generated shared workflow consistency and ten CI-component regressions | passed before the final equivalent manual-only input expression adjustment | `99ee97e951cd7c6ae455aeab143786b36ad6709139ed07efc035a524152e3048` | `9c37921242c11e86853de42ef8104c96d4f8b58928a6de5f88d56682a603af26` |

Source snapshots hash ordered repository-relative file names and their actual
bytes. Later Linux implementation hardening is not retroactively attributed to
the earlier macOS runs. The source-bound focused Linux run will retain the exact
commit, binary identity, build/test/lint receipts and all 22 installed qualifier
cases. The qualifier's raw policy/examples, stdout, stderr and syscall traces stay
private. Only the bounded report and hashes are eligible for retained evidence.

## Retained first Linux attempt

Run `41306920087`, exact source `529363b7eae2c225595688c439ea9878ea8ff269`,
successfully built the executable and ran all eight new protocol tests: seven
passed and one failed. The failed fixture expected destructive-call taint from
an unrelated prior result without the evaluator's required derivation evidence.
It was corrected to the existing accepted explicit secret-egress hard-Deny
control. The required outcome remains Deny; no product evaluator, floor or rule
was changed. Its Ask and unsupported controls were retained.

Artifact `13083856750` has ZIP SHA-256
`97a3ff7502e9f079b648f27e1806756717d56028a13cb9416d4d3643dd20cc31`;
all four unique safe members and CRCs were independently verified. This failed
attempt is not acceptance and did not reach the installed qualifier.

The corrected supplied Deny/Ask/unsupported example was independently executed
through the existing installed offline evaluator on macOS before repeating
Linux: passed. Source snapshot
`5bc1c7dd62baf75d454f94c15181046bc635c57c16d5c13f98335b24ae7d9ef5`,
log SHA-256 `0681b714fe9976943408b6a51fff8f1b788bf1b5aea809fb7e7ea52fa891d678`.
That is evaluator-fixture validation, not Linux feature qualification.

## Retained second Linux attempt and setup correction

Run `41308203949`, source `6b8da1c22c32428e4dd93cdde284bfc8748dc8c5`,
built successfully; all eight protocol and both grader tests passed. The installed
qualifier stopped before its first case because its fixture assumed an
`AGENTFW_HOME` override that lifecycle installation does not support. The driver
now uses the actual `$HOME/.agentfw` installation path. No product code changed.
All 22 cases in that failed attempt remain unattempted; Clippy was not reached.
Artifact `13083654534`, six unique safe members with verified CRCs, ZIP SHA-256
`3e306e124eb275af665c591b3c206242a9399fe3fea17d08196293e5f712bfb2`.

The corrected actual installed path and source-validation setup passed locally
on macOS (snapshot `f52ffd1699988f49de26ed5f25d92f86cc89e62b87131700e2a52b212d556fc1`,
log `e06e7274480eb661ff6384222f7fce035c0997d1ffc01a5d64ca0c071f778bfa`).
Both corrected grader controls also passed (same snapshot, log
`ce758dce47ade14cc82e1735d9951d79df677d90691641c6269dd0b3aa8a42af`).
These macOS setup checks do not substitute for native Linux qualification.

## Observed installed feature qualification (third attempt)

Run `41311134127`, source `793e153c8ec88a43f3db8af895309dffde1ff465`,
passed all eight protocol tests, both grader tests and all 22 actual installed
Linux CLI cases. Measured commands made zero network syscalls and zero child
execs; active policy, project and sibling witnesses stayed unchanged. The job
subsequently failed Linux Clippy on one redundant `Ok(...?)` wrapper. That wrapper
is removed without changing the result/error behavior.

Artifact `13085283547`, seven unique safe members with verified CRCs, ZIP SHA-256
`233564a84304e22d1a8a11d8385df2f023b1cd3329eedffefd27f03268004fab`.
The native report is feature evidence; the failed overall job is not a clean
qualification. Local formatting, two grader and 21 build-custody controls passed
after the lint correction: snapshot
`14b91fe690592ad56ebb798a07d3e8ec2bc020c3117e07b329a484c51083d825`, log
`6662411cb3f8d4f0d3e1a7d63bb51043c5d01e2075a6667b1f8756e1c3fc9df5`.

## Clean focused Linux qualification

Run [41311691014](https://github.com/SoupTeam/soup-wall/actions/runs/41311691014),
exact implementation source `016af04f5b948e02d46cd28972e802c3f830ff1e`, passed:
source build, eight protocol tests, two grader controls, all 22 installed cases,
Linux all-target Clippy with `-D warnings`, and formatting. The other feature
jobs were explicitly skipped by the manual focus; this is not a full Ready run.

Installed executable SHA-256:
`35e3147fc5cf33bf02c6f17a3d647683e876be298e3efe601144b8903b3ea9d0`.
All 28 measured CLI invocations made zero network syscalls and zero child execs.
Source and installed binary stayed unchanged; every case retained unchanged
active-policy, project and sibling witnesses. Offline evaluation is simulation,
not observed runtime admission or active protection.

Artifact `13086306000`, seven unique safe members with independently verified
CRCs, ZIP SHA-256
`e741c13ba9fe04677f485e106b4e355687f2d8101d2358db2b2f6dbd756565c1`.
Finite report SHA-256:
`4a1e7c0fe10313e5f5da35f41cf155c79ecd7b8ca7e4aeddcc205010604dacec`.
The retained report was independently regraded with the current strict grader.
Raw inputs, stdout, stderr and syscall traces were not published.

This final ledger-only follow-up does not change implementation, tests or CI.
The Draft is ready for maintainer code review, with final shared Ready/security
and exact-current-main admission still belonging to the maintainer.
