# Native Windows authority and recovery acceptance (SOU-103)

This guide covers the two focused acceptance controls in `agentfw`. Run them on
native Windows before interpreting a failure as a daemon or authority defect.
The fixture reports only stable phase/reason labels, relative milliseconds and
HTTP completion counts. Do not attach raw grants, tokens, request bodies, user
paths or unsanitized test output to an issue.

## Historical failures and reproduction

The accepted starting source was `130884fa5292feb650660700be726c276b804f24`.
The implementation branch was refreshed onto accepted `main`
`d49efa5aec1d47a1471e4e67b343c85a8a392353` before Ready qualification.
On PR #192, Windows job `118600045198` (run `39414466980`, attempt 1,
`windows-latest`, Actions runner `1000035599`, source
`f71f9bf3c37fa18e10f7f15ab36bb74539ae06dd`) failed the useful hook
control with `native_hook_authority_invalid`. The unchanged attempt 2 job
`118607120167` passed. The test had minted a 500 ms real-clock grant *before*
session admission and the useful hook. A slow setup could therefore reach the
positive assertion after the grant expired. That is a timing boundary in the
test, not evidence that the verifier accepted an expired grant.

Earlier Windows job `118551489109` (run `39399814493`, attempt 1, Actions
runner `1000034304`, source
`a3c01215386c3b081935a7b3e2472725a217e5ce`) failed the recovery
control at the final baseline-running guard; an unchanged retry passed. On
native Windows 11 Pro `10.0.26200`, Rust `1.99.1`
`x86_64-pc-windows-gnu`, the unmodified control failed 3/20 standalone
attempts (35,995 ms) and 1/10 further attempts. Instrumenting only the
fixture and probe boundary reproduced 2/40 failures (66,211 ms). First
failure: fixture ready at 0 ms; 4 accepted connections, only 3 complete HTTP
requests, 4 response writes, 479 ms elapsed; probe outcome
`http_transport_error`; first failed assertion was the final baseline-running
guard. The original fixture wrote `200 OK` after one `read`, even when that
read lacked the HTTP header terminator. A response on an incomplete request
can race the client's write/receive path. A later failure had 11 accepted,
9 complete requests and an attempted baseline restart; the journal remained.

## Correction and controls

The fixture waits for a complete bounded HTTP request, signals readiness
before recovery, and replies with an explicit complete health response only
for a valid request. Split, truncated and oversized request controls exercise
the reader. Partial response, `503` and wrong-process health controls must
leave the recovery journal intact. The healthy control must prove a complete
request, response and matching original baseline before the journal clears.
The production 500 ms health probe and journal/ownership guard are unchanged.

The child authority control now executes its useful hook with a test-minted
30 second grant. It then checks native event expiry using the existing test
clock and checks hook expiry separately with an already expired signed proof
against the real wall clock after an injected delay. The verifier's production
clock, exclusive expiry and signature checks are unchanged. Existing replay
and wrong-identity tests remain required controls.

## Commands

From the repository root, with the repository Rust toolchain and a native
Windows linker available on `PATH`, run:

```powershell
cargo test -p agentfw --test native_endpoint review36_expired_child_authority_must_not_authorize_hooks -- --nocapture
cargo test -p agentfw --lib recovery_resumes_when_interrupted_with_compensated_reservation_and_original_baseline_healthy -- --nocapture
cargo test -p agentfw --lib recovery_retains_journal_for_partial_or_unhealthy_or_unowned_health -- --nocapture
cargo test -p agentfw --lib health_fixture_waits_for_complete_bounded_request -- --nocapture
cargo test -p agentfw --test native_endpoint scoped_hook_proof_authenticates_identity_and_rejects_claim_swaps
cargo test -p agentfw --test native_endpoint scoped_grant_cannot_replay_into_a_restarted_daemon
```

The local reproduction used the existing MinGW kit and Rust GNU import
libraries; its user-specific installation paths are intentionally omitted.
Run Linux compatibility controls with the same test filters under Linux/WSL.
Do not retry an effectful recovery within one attempt. Record every separate
process invocation and its exit status for repeated-run evidence.

## After-run evidence

On native Windows 11 Pro `10.0.26200` with Rust `1.99.1`
`x86_64-pc-windows-gnu`, at accepted source
`ff0facd9be65d5b7947c7dbf5dac971fb04803df`, the corrected positive recovery control
passed 20/20 standalone processes in 33,538 ms. The full focused set then
ran five separate controls per attempt: useful/expired authority; exact
healthy baseline recovery; healthy recovery beside a stalled partial HTTP
request; partial-response/503/wrong-identity journal retention; and bounded
request framing. Each result below is the ordered result of those five
controls, not a retry inside an operation.

| Attempt | Results | Elapsed since start (ms) |
| --- | --- | ---: |
| 1 | pass, pass, pass, pass, pass | 9,229 |
| 2 | pass, pass, pass, pass, pass | 18,377 |
| 3 | pass, pass, pass, pass, pass | 27,286 |
| 4 | pass, pass, pass, pass, pass | 37,251 |
| 5 | pass, pass, pass, pass, pass | 46,423 |
| 6 | pass, pass, pass, pass, pass | 55,386 |
| 7 | pass, pass, pass, pass, pass | 64,397 |
| 8 | pass, pass, pass, pass, pass | 74,297 |
| 9 | pass, pass, pass, pass, pass | 83,376 |
| 10 | pass, pass, pass, pass, pass | 93,264 |
| 11 | pass, pass, pass, pass, pass | 102,487 |
| 12 | pass, pass, pass, pass, pass | 111,420 |
| 13 | pass, pass, pass, pass, pass | 120,556 |
| 14 | pass, pass, pass, pass, pass | 129,673 |
| 15 | pass, pass, pass, pass, pass | 139,809 |
| 16 | pass, pass, pass, pass, pass | 148,742 |
| 17 | pass, pass, pass, pass, pass | 158,845 |
| 18 | pass, pass, pass, pass, pass | 167,852 |
| 19 | pass, pass, pass, pass, pass | 177,943 |
| 20 | pass, pass, pass, pass, pass | 186,924 |

Total: 20 attempts, 100 control invocations, zero failures or skips,
186,927 ms. Intermediate fixture versions were **not** accepted: the first
complete-reader version had two failed control invocations across 20
four-control attempts, and the concurrent
version before explicitly resetting accepted sockets to blocking mode had
five failed control invocations across 20 attempts. Their sanitized
first-failure evidence showed three complete, owned
health probes followed by a transport error on a connection with zero bytes
read. The final correction explicitly sets each accepted stream to blocking
mode with a bounded read timeout before consuming HTTP headers.

After rebasing the single implementation commit onto accepted `main`
`d49efa5aec1d47a1471e4e67b343c85a8a392353`, the same five controls
were run again as separate native Windows processes. All five passed on
every attempt:

| Attempt | Controls passed | Elapsed since start (ms) |
| --- | ---: | ---: |
| 1 | 5/5 | 11,005 |
| 2 | 5/5 | 20,041 |
| 3 | 5/5 | 29,775 |
| 4 | 5/5 | 38,919 |
| 5 | 5/5 | 47,854 |
| 6 | 5/5 | 57,716 |
| 7 | 5/5 | 67,562 |
| 8 | 5/5 | 76,711 |
| 9 | 5/5 | 85,844 |
| 10 | 5/5 | 94,847 |
| 11 | 5/5 | 103,988 |
| 12 | 5/5 | 112,811 |
| 13 | 5/5 | 121,865 |
| 14 | 5/5 | 130,893 |
| 15 | 5/5 | 141,193 |
| 16 | 5/5 | 150,820 |
| 17 | 5/5 | 160,623 |
| 18 | 5/5 | 169,721 |
| 19 | 5/5 | 179,499 |
| 20 | 5/5 | 188,382 |

Total on the refreshed base: 20 attempts, 100/100 passing controls, zero
skips, 188,385 ms. An initial repetition script accidentally selected the
CLI executable instead of the unit-test executable for two invocations; no
recovery control ran in those invocations. The script was stopped, the test
binary was confirmed with `--list`, and the valid 20-attempt series above
started afresh. Those two invalid harness invocations are excluded from the
acceptance count.

On WSL2 Ubuntu (Linux `6.18.33.1-microsoft-standard-WSL2`, Rust `1.99.1`),
the corresponding healthy recovery, stalled-request recovery,
partial/503/wrong-identity journal controls, bounded reader, useful/expired
authority and real expiry-boundary tests passed 6/6. The replay and
wrong-identity hook controls also passed 2/2. The current-source Ready CI
qualification is recorded in the pull request. Local synthetic fixtures do
not certify a deployed daemon or an end-to-end product release.
After the `d49efa5` refresh, the Linux healthy recovery,
partial/503/wrong-identity journal control, and authority control passed
again (3/3); the matching Windows controls also passed before the 20-attempt
series above.

`cargo fmt --all -- --check`, `python scripts/check_docs.py` (221 Markdown
files, 842 links), and Linux `cargo clippy --locked -p agentfw --all-targets
-- -D warnings` also passed. The first Clippy attempt exhausted the WSL
temporary filesystem while writing incremental query caches; it was rerun
without incremental compilation after removing only this task's temporary
incremental cache. No Clippy finding was suppressed.
