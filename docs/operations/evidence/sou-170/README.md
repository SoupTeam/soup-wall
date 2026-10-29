# SOU-170 installed quota evidence

## Current lifecycle and diagnosis composition

Accepted base: `144512b3ed11f985c922d9911cba26f07599dea9`. Reviewed diagnosis
history: `b30d2bd1e6d95d94f63e52b5b234ec15c60ff401`; its branch is unchanged.
Qualified source: `fa1732a7c49f591c66d456031301d9486b8969cf`, tree
`c00c3adcfbd4aea5b488db05b8556522f1044104`.

The focused [native run 40698883037](https://github.com/SoupTeam/soup-wall/actions/runs/40698883037),
job `122853070027`, passed. Artifact `12820384961`, ZIP SHA-256
`6d22cf00553af47f0b3224c9a78c597248f4db1b18cdd660c335bb1e34eaf400`,
contains the exact reports below. Actual Agent SHA-256:
`4c964c8411195e8efa8bce9b97e4287e66d0d693a5894b012a1eadc08fffcf8e`.

- [composition-trial-plan.json](composition-trial-plan.json) freezes the 25-case
  quota inventory before execution. All 23 original cases remain; two added
  cases exercise active-run Refresh without budget refill and a refreshed-v2
  plan followed by fresh Ask and real read-only diagnosis.
- [composition-native-quota.json](composition-native-quota.json): 25/25 passed,
  zero failed/incomplete. Three approved attempts retain two credits across
  two explicitly confirmed refresh publications: two physical writes succeed,
  the third target remains unchanged with typed quota exhaustion. Every
  refreshed plan preserves the exact quota contract/ceilings and old plan.
  A new run uses fresh Ask, rejects old authority, reads back exact replacement
  bytes, and executes default and explicit output-check diagnosis without
  changing private state, targets or the sentinel. Diagnosis retains unknown
  commit/delivery/model-consumption boundaries.
- [composition-native-original-edit.json](composition-native-original-edit.json):
  23/23 original installed cases and all 14 diagnostic cases passed. The latter
  are explicitly eight actual installed observations and six simulated
  retained-state controls; these are not 14 real fault executions.
- [composition-native-stop.json](composition-native-stop.json): 12/12 passed,
  including real Stop followed by read-only diagnosis with preserved state.
- [composition-native-refresh.json](composition-native-refresh.json): 23/23
  passed. Both actual replacements/readbacks, new exact bindings, old authority
  refusal, interruption controls and cleanup remain required.
- [composition-native-verification.json](composition-native-verification.json)
  records independent bounded ZIP/JSON checks of source/tree/binary/component,
  canonical profiles, monotone counts, unchanged limits, actual effects,
  private-state preservation and owned cleanup. All 133 focused native Rust
  tests passed (63+31+5+6+10+5+13), plus 28 Python controls, strict Agent Clippy
  and fmt. No ignored or failed focused Rust tests. No artifact code was
  executed by this independent verification.
- [composition-local-qualification.json](composition-local-qualification.json)
  retains 1922 passed / zero failed / 13 existing ignored workspace tests,
  workspace/all-target strict Clippy, script controls, generator and docs checks.
  The stale isolated Git-index documentation failure and exact-index correction
  remain recorded.
- [composition-attempt-1.json](composition-attempt-1.json) and
  [composition-attempt-1-original-edit.json](composition-attempt-1-original-edit.json)
  retain failed run 40697167080 on source `88c097fc`. Original 23 cases and all
  14 diagnosis cases passed; Stop then failed at its second case because a
  qualification helper parsed only `}` from a successful pretty-printed JSON
  document. The bounded status parser and negative regressions were corrected;
  runtime bytes did not change. Stop's 1 passed / 1 failed / 10 incomplete and
  the unexecuted Refresh/quota inventories are not represented as success.

Execution used actual installed Agent/component, genuine pinned restricted
Claude and an owned scripted loopback provider outside read-only source,
non-root private writable scratch and a private network namespace. No paid
inference, global host changes or model-effectiveness claim. Local counters and
matching output bytes are not authenticated execution/commit/delivery proof.
Final shared Ready, current-source CI/admission and main delivery remain TL-owned.
The subsequent upstream helper sync `785b934b` contains the same status JSON
implementation plus bounded Stop failure-observation retention and its test.
All Agent source bytes remain identical to qualified `fa1732a7`; 29 focused
Python controls, generator/fmt and 333 Markdown / 1161 links pass after that
sync. This does not attribute a new native run to the later retention commit.
The final helper sync `e0ece8d8` adds an explicit qualification-only
`diagnosis_response_not_object` error. Both regression sets are preserved and
aligned to that code; 30 focused Python controls, generator/fmt and 334 Markdown /
1163 links pass. Valid-status behavior and all Agent source bytes remain
unchanged. The new upstream correction report is retained in its own source
history; no new native run is inferred from this script/test sync.
Historical results below retain their exact earlier source attribution.

# Historical independent implementation evidence

Accepted independent base: `db4f006d74957fc1a8dc1a0a4be40c3b887d8a01`.
Qualified source: `66e126486ea9b21f0104051a3f97a65561ee21ea`, tree `30d22de2eba1e43890a6206c7691a529ad399d77`.
Actual Agent binary: SHA-256 `cbfef36de57efcfdba73e0a74c3c5bda1a641b9c829fbd17f49bdd89f42caa36`.

The focused native [run 40679977662](https://github.com/SoupTeam/soup-wall/actions/runs/40679977662), job `122787990877`, passed. Official artifact `12811928830`, ZIP SHA-256 `078d96e4ea53a83f4f525e8e6dcb59cebba9cdb17226dc2b5cbe17c31197b6b7`, has four unique safe members with verified CRCs.

- [trial-plan.json](trial-plan.json) freezes all 23 installed quota cases before native execution. The successful run attempted and passed all 23, with zero failures/incomplete cases.
- [native-quota.json](native-quota.json) is the exact sanitized artifact report. Actual installed Agent/component and pinned genuine restricted Claude used an owned scripted loopback provider, outside read-only source. Useful create and replace include independently checked bytes and readback. Two separately approved Unicode writes reach the exact aggregate byte limit; lowering that aggregate ceiling by one byte preserves the second target. Operation exhaustion and empty writes are counted separately.
- Every refusal keeps original schema/path/root/classifier/policy/Ask floors. Rejected/no approval consume zero credits. An admitted attempt permanently charges its full payload and operation, including known noncommit. No active refund, reset or top-up exists.
- Disposable postcommit witnesses first perform the real publication. Withheld transport keeps known committed counters spent. SIGSTOP before the successful publication syscall returns, followed by independently observed bytes and controller SIGKILL, retains an indeterminate publication, not a false known success or no-write claim. Fresh explicit preparation/new run/Ask succeeds and the old epoch token is rejected. Two other runs execute independently and preserve sentinels.
- The actual two-tool host batch remains subject to the accepted transport's overlap refusal; it proves at most one physical effect. Native Rust barrier controls independently prove one reservation among 16 contenders and exactly one file among two real creators. This does not claim parallel RPC support.
- [native-original-edit.json](native-original-edit.json) retains all 23 unchanged legacy installed cases, also 23/23 passed. [native-verification.json](native-verification.json) records parent-side bounded ZIP/JSON verification of exact source/tree/binary/component/profile digests, all numeric accounting transitions, observed effects and owned process cleanup. No artifact code was executed by this verification.
- Native checks passed **53 Rust tests** (19 + 6 + 10 + 5 + 13), nine script controls, strict Agent Clippy and fmt; no failed/ignored Rust tests or compiler warnings. Mac workspace: 1911 passed, zero failed, 13 existing ignored; strict workspace Clippy/fmt and CI/documentation checks passed. Runtime execution used private writable scratch, read-only source, non-root/no capabilities and a private loopback-only network. No paid calls or global settings changes.
- [native-attempts.json](native-attempts.json) and [native-attempt-1.json](native-attempt-1.json) preserve the first failure: legacy 23/23 passed, but the new driver compared a legacy plan format with the qualification-report format. Quota inventory was 2 attempted / 1 passed / 1 failed / 21 incomplete. Correcting only this checker and adding a response-contract regression led to the successful second run; no runtime protection changed. [local-qualification.json](local-qualification.json) retains the original Clippy cfg issue, the unchanged macOS nonblocking accept calibration failure and the isolated Git-index documentation failure, plus all successful corrections.

These are per-run conservative ceilings, not host/user/cross-run enforcement or model-efficacy evidence. Known counts are separate from indeterminate publication. Matching current bytes do not prove a previous call completed. Later retention/documentation commits change no qualified runtime, test, driver or workflow bytes. One final current-main shared Ready CI, CodeQL/admission and main delivery remain TL-owned; this Draft is not merged or Done.
