# SOU-88 resource Ask confirmation evidence

## Review follow-up

The review of `5a7a66f4e7cd66ad27bf9b0574b7bd1c68afa7c8` accepted the
hard-floor, ambiguous-classification, strict platform and terminal-invalidation
fixes. The remaining blocker was production read/GET execution acceptance.

Earlier descriptions of `resource_approval_witness.rs` as filesystem/network
execution proof were incorrect. Those tests invoke the native authorization
router only. The test-side simulated create was removed; the tests now explicitly
name single-use **authorization** rather than execution. No historical API
receipt is evidence of an actual read or HTTPS request.

## Execution witnesses

`crates/agentfw/tests/support/resource_approval_execution.rs`, included by
`mcp_admission.rs` only on Linux, runs two acceptance tests:

- `sou88_read_document_real_executor_approval_controls`
- `sou88_https_get_real_tls_receiver_approval_controls`

Each uses a real `agentfw mcp --native-admission` subprocess, its real discovery
child, production rule-baseline classifier, authenticated production Axum native
router, and the production constrained resource executor. The router is hosted
in the test process; this is not an installed service/restart or model/UI test.
The Ask policy and resources belong to disposable fixture directories.

Each operation exercises six scenarios: rejection, actual TTL expiration,
mutation of approved arguments in transport, cancellation while pending,
duplicate request while pending, and approval. Before approval, all scenarios
assert no protected read and no target connection. Failed controls assert no
protected effect. The successful call releases the actual document/receiver
body, duplicate operator approval fails, an actual captured redemption request
is replayed against the router and refused as spent, and the repeated MCP
request ID closes without another effect.

After rejection, expiration and mutation, a different request in the same
collector session must obtain a new approval and complete useful work.
Cancellation and overlapping/duplicate input deliberately close the collector;
no promise to resume those closed sessions is made. All scenarios assert zero
child tool-call dispatches.

### Independent observations

- Read: Linux `inotify` watches `IN_ACCESS` on the protected file. The test does
  not open/read it while watching. Metadata checks and O_PATH pinning are not
  counted as a protected byte read. The successful reply must contain the exact
  original file contents; refusal/replay must produce no new access event.
- GET: a separate Python process owns a local TLS socket and append-only ledger
  of accepted connections, TLS handshakes and HTTP requests. Each approval
  produces exactly one connection and `GET /document?item=7`; refused controls
  produce zero connections/requests. The result must contain the real receiver
  document. This reuses the existing SOU-56 owned receiver and disposable CA,
  retaining normal hostname/CA/expiry validation. The private endpoint exception
  pins only the owned loopback address and port; production network rules are
  unchanged.
- Argument mutation changes only arguments before the authentic router sees
  redemption. The fixture never manufactures Allow, resource bindings, or
  executor output. A fresh request subsequently succeeds with unchanged policy.

The existing collector create-file acceptance remains in
`sou88_resource_create_ask_operator_approval_runs_once_and_reject_zero_execution`.
It verifies production creation and exact contents, independently of the API
single-use authorization suite.

## Reproduction and retained output

On Linux with Python 3, OpenSSL and the locked Rust dependencies:

```sh
cargo test --locked -p agentfw --test mcp_admission sou88 -- --nocapture
cargo test --locked -p agentfw --test resource_approval_witness -- --nocapture
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
```

The `Constrained MCP HTTPS GET` workflow runs both suites on the exact PR head
and retains `sou88-execution.log` and `sou88-authorization.log` alongside its
existing source, toolchain and binary identities. Each completed execution
scenario emits `SOU88_EXECUTION operation=... scenario=... passed=true` only after
its effect and refusal assertions pass.

Local macOS checks cover the platform refusal, existing collector compatibility,
formatting and warnings-denied Clippy. They cannot establish the Linux-only
positive execution cases. Linux CI results and final source identity are recorded below; adding a witness
alone is not a passing result.

## Local verification (macOS, 2026-10-18)

Isolated source copy, repository read-only to target processes, no external
network, only loopback fixture traffic and disposable scratch writes allowed.

- `cargo test --offline --locked --workspace`: exit 0; **1,478 passed, 0 failed,
  11 ignored**, across 65 reported suites. Ignored/unsupported platform cases
  are not claimed as passing Linux execution evidence.
- `cargo clippy --offline --locked --all-targets -- -D warnings`: exit 0.
- `cargo fmt --all -- --check`: exit 0.
- Existing SOU-88 collector tests: 2 passed; native authorization suite on macOS:
  the single explicit non-Linux platform-refusal test passed.

Initial local runs exposed the stale non-Linux-positive unit expectation (fixed
in this change), then the sandbox's refusal of `/bin/ps` used by existing process
cleanup witnesses. The final passing run allowed only that read-only system
helper outside the child sandbox while retaining source-write and external
network restrictions. Those earlier failures are not represented as passes.

The final Linux execution results are recorded below, separately from local macOS results.

## First Linux execution attempt (retained failure)

[Run 39128972509](https://github.com/SoupTeam/soup-wall/actions/runs/39128972509)
compiled the new witnesses and passed both rejection/real useful-continuation
controls. It then failed a too-specific test expectation: an expired approved
record is terminally `closed` when redeemed. The follow-up explicitly queries
and asserts `state=expired` before releasing the held real redemption, then
requires the closed refusal and zero effect. It does not weaken production checks.
The arm64 fixture image additionally lacked the original source-path Python
script. The receiver is now embedded in the test binary; disposable certificate
creation is self-contained. These initial CI failures are not passing evidence.

The second Linux attempt [39129351972](https://github.com/SoupTeam/soup-wall/actions/runs/39129351972)
passed all six read controls and the five GET refusal controls on Linux. Its GET
positive assertion incorrectly treated the metadata content block as the body;
the log retained the real successful TLS response and original second-block
document. The follow-up asserts both the production metadata and exact original
UTF-8 body bytes, including for useful continuations. That failed assertion is
not relabelled as a complete passing suite.

## Final Linux acceptance

Runtime/test source: `85e3c5d96eb7b87490b5258378f9cd275dfe9720`.
The [exact-head HTTPS workflow](https://github.com/SoupTeam/soup-wall/actions/runs/39129742339)
completed successfully; artifact `sou56-https-get-evidence` retains the source and
binary identity, Clippy output, both SOU-88 logs and full real HTTPS report.

| Check | Observed result |
| --- | --- |
| SOU-88 collector integrations | 4 passed, 0 failed |
| New read/GET execution controls | 12/12 passed |
| Native authorization witnesses | 9 passed, 0 failed |
| Agent unit tests on Linux | 499 passed, 0 failed, 2 ignored |
| Native endpoint tests | 120 passed, 0 failed |
| Actual owned HTTPS regression scenarios | 48/48 passed, 0 skipped |
| Warnings-denied all-target agentfw Clippy | passed |

[Linux fixture baselines](https://github.com/SoupTeam/soup-wall/actions/runs/39129742419)
additionally passed **259/259 cases on each of amd64 and arm64**, including all
12 new controls per architecture. Those jobs tested PR merge source
`050658fe50cf456049d398fd64c4754510172c88`; all **649 recorded build input
hashes** were independently compared with runtime head `85e3c5d` and matched.
The receiver ledger on each architecture recorded exactly four connections,
four verified TLS transports and four `GET /document?item=7` requests: the three
approved useful continuations after refusals plus the separate approved scenario.
Each scenario asserts zero preapproval/failed-control sockets, zero child tool
calls, original result bytes, and no replay effect before its passing marker.

[Machine-readable summary](sou-88-execution-2026-10-18.json) binds source hashes,
image/binary identities, log hashes, per-control outcomes and receiver counts.
The artifacts retain the original logs; this summary contains no tokens, keys,
private approval grants or protected production data. Subsequent evidence-only
commits preserve the tested runtime and test source hashes. Maintainer approval
and remaining general PR checks are separate from these observed results.

## Current-main integration and general CI follow-up

The lead accepted the read/GET execution evidence and resolved the final inline
thread in [review 5563163358](https://github.com/SoupTeam/soup-wall/pull/179#pullrequestreview-5563163358).
That acceptance is not a green status for the entire PR.

On evidence-only head `02464de`, `required-linux-git`
[attempt 1](https://github.com/SoupTeam/soup-wall/actions/runs/39130548373/attempts/1)
failed during real overlap/cancellation. The retained collector log reports
`mcp_owner_sandbox_failed`; the bounded summary reported six completed reads,
zero completed refusal controls and verified cleanup. This was a fail-closed
sandbox termination, not a demonstrated authorization bypass. The precise cause
of the sandbox exit was not established. The unchanged runtime had passed this
workflow on the three preceding heads. One justified
[attempt 2](https://github.com/SoupTeam/soup-wall/actions/runs/39130548373/attempts/2)
on the same head passed; the failed attempt and artifacts remain retained. No
sandbox controls, lease deadlines or acceptance checks were disabled.

The Windows security job on the same head failed two classifier-dependent
integration fixtures: a real Python classifier hit its two-second deadline and
a cancellation fixture consequently did not reach native admission. The
production fail-closed deadlines remain unchanged. Those two known stateless
fixtures now explicitly prepare Python/script imports before the measured MCP
phase; their real collector calls retain the exact original classification,
policy, zero-effect and timing assertions. Fault/malformed/timeout classifier
tests are not warmed and still exercise the original failure boundary.

The branch integrates main `de54c0065d158203c6a840f4a60bc3eed6bddb29`
(accepted POST PR #165). Existing SOU-88 `Policy`/`Admission` test constructors
explicitly set the new `post` field to `None`; a real POST-profile unit regression
checks that POST is still outside resource Ask approval scope. Historical
execution hashes above describe runtime `85e3c5d`, not this later merged
candidate. Complete merged runtime/security/admission results must be assessed
on the new head; current results are linked in the PR description.

Local isolated verification of the integrated source completed with **1,487
passed, 0 failed, 11 ignored** across 65 reported workspace suites. Warnings-denied
workspace/all-target Clippy and formatting passed. The two affected
classifier-dependent integration tests were additionally run individually and
passed on macOS. Windows-specific preparation still requires the new hosted
Windows security run; local macOS execution is not evidence of that result.

### Audit lock handoff regression found by complete CI

The current-main candidate `cad431e` passed Windows security and the real Git
sandbox workflow, but the Linux all-features job
[117689701629](https://github.com/SoupTeam/soup-wall/actions/runs/39132266829/job/117689701629)
failed `rotates_prunes_and_reopens_without_exceeding_declared_bytes`: reopening
immediately after `drop(sink)` reported another audit writer. `flock` is tied to
an open file description; a descriptor inherited by a concurrent fork can retain
that lock beyond the writer's close. A deterministic duplicate-descriptor probe
reproduced this close-only failure without timing or test retries.

Audit retention now wraps the acquired lock in an owning-process guard. The
acquiring process explicitly unlocks on Drop (including failed-open paths);
a forked/inherited copy cannot unlock the live parent's writer. Two Linux unit
regressions check immediate reopen while the old description remains open and
that a non-owner copy cannot release the writer. Existing second-writer refusal
and audit integrity/retention checks remain enforced. A local POSIX probe using
the actual extracted guard code passed owner handoff, non-owner refusal and new
owner exclusion. This probe is not presented as a complete Linux audit suite;
the new exact-head Linux CI must validate the module and all-features suite.
