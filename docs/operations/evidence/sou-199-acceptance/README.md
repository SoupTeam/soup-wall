# SOU-199 development acceptance ledger

Base: accepted `b385e7506ab26896637f348e3180e52d1fc6d423`.
This ledger distinguishes offline simulation, observed native feature behavior
and final shared merge qualification. No configuration or simulation is claimed
as active protection. Native Linux feature evidence is pending at the initial
implementation commit; full Ready/security/current-main admission is TL-owned.

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
