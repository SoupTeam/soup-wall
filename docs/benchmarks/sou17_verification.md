# SOU-17 independent failure, overlap and replay verification

This procedure extends the initial [Task 3 resilience suite](task3_resilience.md)
for [SOU-17](https://linear.app/soup-wall/issue/SOU-17/task-11-independently-verify-failure-overlap-and-replay-behavior),
[roadmap R06, bounded P01–P02](../ROADMAP.md). It uses existing production code and
safe local fixtures. Owner: konung3; PR review coordinator: Nari_Ab.

The production adapter tests import
`soup_wall_adapter::runner::{run_enforcement_pipeline, evaluate_baseline_policy}`;
actual Native/MCP fixtures use the shared classifier/policy and native admission
boundary. On historical preparation base
`fdf4bf716a87b88f17a6241e710bb447885fb8df`, these components were tested separately,
which did not establish the integrated milestone. Current main adds production
classification/policy gating, all five generic reply shapes and operation-level
bounded Unix resource reads. No competing test-local pipeline replaces those
production components. Unsupported mappings are explicitly refused.

## Current CI lifecycle correction — 2026-10-14

The [6a57bef lifecycle verification](evidence/sou17_ci_lifecycle_2026-10-14.md)
in [PR #113](https://github.com/SoupTeam/soup-wall/pull/113) follows the retained
native macOS and ARM64 failures on the previous reviewed head. New Unix pipe/socket
I/O uses cancellation-safe descriptors and physical frame completion. Exact clean-source
checks pass: 126 boundary regressions, 10 resource, 15 generic and 11 pending cases,
64 Ask refusals followed by useful continuation, and 1,030 workspace tests.
Thirty serial pairs have zero false interruptions; mean overhead is 40.625 ms and
p99 57.346 ms. Original CI failures and non-reproducing local repetitions remain
raw evidence; neither the proposed transport diagnosis nor local passes prove the
exact hosted failure cause. **SOU-17 remains open** for new-head required CI,
review, scan disposition, merge and affected actual-main verification.

## Previous local repair verification — 2026-10-14

Hosted CI subsequently rejected the previous head; the following records historical
local success only. The linked current lifecycle supplement governs acceptance.


The [bb64321 repair verification](evidence/sou17_candidate_bb64321_2026-10-14.md)
in [PR #113](https://github.com/SoupTeam/soup-wall/pull/113) passes 123/123 exact-source
boundary regressions, the 15-case generic profile, ten-case constrained read
profile, pending-admission and 64-Ask continuation checks. FIFO replacement is
refused promptly and useful same-session reads recover. Unsupported overlap is
refused at classification/admission/result gates and during large reply
backpressure; already-permitted first reads and exposed bytes remain honestly
recorded. Large sequential/EOF positive controls pass. The final serial 30-pair
sample has zero authorized interruptions, mean paired overhead 40.312 ms and p99
47.110 ms; it is a local child-backed fixture measurement, not a population or
inline-executor performance claim.

The [rejected 28001eb checkpoint](evidence/sou17_repair_28001eb_2026-10-14.md)
retains the independently exposed reply-write gap and preceding experiments.
The final report/archives retain original failures, source/binary/configuration,
raw witnesses, checks, skips and reproducible commands. **SOU-17 remains open**
for Nari's requested review, required CI/rescan disposition, merge and affected
verification on actual updated main. Local verification does not establish a
release or deployed protection. Any later code change requires affected checks
again on its new exact revision.

## Original main recheck — 2026-10-14

The [current-main 5fc6d72 verification](evidence/sou17_candidate_5fc6d72_2026-10-14.md)
records 112/112 existing regressions, the 15-case generic profile and ten-case
resource profile. The selected production `read_document` executor now performs
useful constrained file reads with independent content and native result witnesses;
it is no longer an unfinished-executor dependency. Two additional probes establish
an admitted FIFO read that hangs and unsupported inline overlap that releases both
results. Focused [SOU-44](https://linear.app/soup-wall/issue/SOU-44/refuse-post-admission-fifo-replacement-without-blocking-the)
and [SOU-45](https://linear.app/soup-wall/issue/SOU-45/enforce-unsupported-overlap-refusal-for-inline-constrained-mcp-reads)
repairs and exact-source reruns are required. **SOU-17 remains open** until the
confirmed failures, reviewed delivery and accepted limits are satisfied. The dated
report retains original failures, grader corrections, false interruptions, latency,
raw outcomes and source/configuration identities.

[October 14 CodeQL triage](../operations/evidence/CODE_SCANNING_TRIAGE_2026-10-14.md)
confirms one open Critical / 85 closed main alerts and working exact-source
Rust/Python/Actions scans. The open permission-mode finding is an evidence-backed
false-positive recommendation pending review; no dismissal was performed and this
is not a claimed zero-alert scan. Static analysis does not establish runtime
protection.

## Historical candidate recheck — 2026-10-12

The [main 45b611a recheck](evidence/sou17_candidate_45b611a_2026-10-12.md) verifies
PR #82's actual five-shape production policy routing: 107 existing regressions,
a strict 15-case generic profile, 64-refusal continuation and useful authorized
mixed-action send. Invalid replies remain distinct from semantic policy refusals.
The strict profile checks final executor/receiver ledgers, complete client/server
transcripts and native call/result binding; its 26 grader regressions reject false
passes. The existing native macOS CI job runs it on the exact source and retains
raw results. The report includes paired 30-read latency, false interruptions,
failures/skips, hashes and reproducible commands. **SOU-17 stays open** for SOU-15's
reviewed constrained resource executor and exact-candidate final acceptance.

[October 12 CodeQL follow-up](../operations/evidence/CODE_SCANNING_TRIAGE_2026-10-12.md)
confirms zero open / 81 closed main alerts, individual justified fixture dismissals
and a working exact-source Rust scan. This does not establish runtime enforcement.

## Historical candidate recheck — 2026-10-11

The [main 9b055a6 recheck](evidence/sou17_candidate_9b055a6_2026-10-11.md)
adds production-classifier lifecycle checks, pending-admission cancellation and
hard-Deny overlap diagnostics, and paired local request latency measurement.
The overlap diagnostic records a real Deny-to-Ask mismatch for Write on a
ReadOnly tool at high uncertainty, with zero executor entries. Unknown/mixed
technical refusals remain separate from ordinary policy outcomes. The dated
report retains exact source/configuration, independent effects and result bytes,
false interruptions, failures and unavailable-environment skips. **SOU-17 stays
open** for the reviewed final SOU-15 candidate and recorded blockers.

[October 11 CodeQL triage](../operations/evidence/CODE_SCANNING_TRIAGE_2026-10-11.md)
records six open Critical findings and reviewer-pending false-positive
recommendations. A working scan does not clear those alerts or prove enforcement.

## Previous candidate recheck — c0add0b, 2026-10-10

The [c0add0b recheck](evidence/sou17_candidate_c0add0b_2026-10-10.md) confirms the
refusal-capacity repair: 64 Ask refusals leave zero effects and a subsequent useful
call executes once with its original result released. The unchanged verification
probes observed all 12 matrix expectations; 105 discovered regressions and two
additional receipt tests passed. Typed native resource authorization/receipt checks
now have regressions, while generic resource execution is explicitly unsupported.
Unknown/mixed mappings and final production integration remain pending. **SOU-17
stays open** for reviewed integration/configuration, remaining acceptance checks
and agreed limits; this report preserves the earlier failure evidence below.

## Previous candidate recheck — b76910a, 2026-10-10

The [b76910a recheck](evidence/sou17_candidate_b76910a_2026-10-10.md) confirms that
SOU-15's new authoritative Ask gate prevents the previously observed execution:
zero effects and original result bytes. Existing 91 regressions and 17 additional
tests pass. New production classifier probes retain technical Unknown/mixed refusals
as a separate outcome. A repeated-refusal regression fails: after 64 Ask calls,
a fresh benign Allow does not execute. New standalone probes and strict witness
graders make both observations reproducible. **Acceptance remains blocked** by
this regression and the outstanding SOU-15 boundary/review requirements.

## Historical candidate verification — 2026-10-10

The [dated candidate report](evidence/sou17_candidate_a8b237d_2026-10-10.md)
records an independent clean-source run of SOU-15 PR #62 at
`a8b237d8237bdda534ca294bf1ebed7af8d469bd`: 91/91 regressions and 18 additional
input/resource tests passed. A separate production-boundary diagnostic recorded
shared-policy Ask together with one execution and 122 original result bytes
released. Shared verdicts remain advisory, extracted resources are not bound to
policy/receipts, and executor destination confinement is not verified.
**Integrated acceptance remains blocked.** The dated report retains raw outcomes,
source/configuration hashes, fixture-only latency/false-interruption observations,
a runnable diagnostic and the refreshed CodeQL inventory. The historical
preparation results below remain unchanged.

## Reproduce and retain raw evidence

Use the Rust/native compiler/Python prerequisites in [DEVELOPMENT](../DEVELOPMENT.md).
Tests bind loopback listeners and start a synthetic Python MCP server; they need no
external model, model credentials, production data or paid access. Cache dependencies
with `cargo fetch --locked` before adding `--offline`.

From a clean checkout of the exact revision under review:

```sh
python3 scripts/verify-sou17.py --expected-commit "$(git rev-parse HEAD)" --offline
```

For preparation with uncommitted changes, explicitly add `--allow-dirty`; that run
records the patch and file hashes and cannot count as final candidate acceptance.
Use `--out target/sou17-verification` to select the evidence parent directory.
The command builds and enumerates the adapter `resilience_tests`, native
`native_endpoint`, and actual MCP `mcp_admission` targets. It runs each discovered
test individually, rejects empty/misfiltered runs, bounds each test to 60 seconds,
and retains failures, timeouts and skips instead of counting them as passes.

Each run writes JSON and Markdown summaries, original test output, exact source
revision and dirty state, source/lockfile/policy/test hashes, toolchain/host identity,
binary hashes and emitted `SOU17_EVIDENCE` records. Registry and policy definitions
remain in the fixture source; emitted records identify actual fixture hashes where
provided. The launcher reuses the existing Docker baseline's report/process helpers;
it does not define another internal event contract or execution policy.

The existing native macOS CI job runs this command pinned to `GITHUB_SHA` and
retains its raw logs/JSON/Markdown in `task3-native-macos-resilience` for 14 days.
A workflow definition is not evidence of a passed platform check.

The shared Docker procedure remains `python3 scripts/test-environment.py` in
[DEVELOPMENT](../DEVELOPMENT.md#shared-local-agentmcp-test-environment). Docker on
macOS exercises Linux; retain a native run separately. On macOS, use a canonical
`TMPDIR` if the native boundary rejects the `/var` symlink.

## Required observations

| Case | Witness and expected outcome |
| --- | --- |
| Malformed JSON, missing fields, invalid scores including NaN/infinities | Shared runner refuses; zero executor entries and no filesystem marker |
| Unknown/read+unknown, mixed read+delete/send/permissions | Imported policy keeps Ask/Deny blocked before executor entry |
| Overlapping Read, Write, Unknown and a hard-risk label, with uncertainty 1.0 | Deny survives all tested label positions/directions; 24 independent zero-effect checks |
| Useful benign call | Original arguments/IDs reach the real fixture once and its correlated result reaches the client |
| Allowed executor returns an error after an effect | Effect count stays one; original correlated error is inspected and returned when admitted |
| Replay with the same ID but changed tool/arguments | First call executes once; second call is refused without a new effect |
| Unsupported two-call batch | Gateway refuses the batch; neither call reaches the fixture |
| Second call while a first result is pending | First effect remains; second call is refused; pending protected result is not released |
| Unsupported cancellation before a call | Session closes before any tool effect |
| Cancellation after an effect while result is gated | Session closes with one recorded effect and no original result released |
| Two sessions on the same real daemon | A denied call in one session does not interrupt a permitted call in its peer; equal native IDs are session-scoped |
| Fresh daemon restart with an old result pending | Old completion is withheld; a new gateway/session can perform a useful call using the same native ID |
| Startup/post-manifest outage and admission timeout | No executor effect; gateway refuses/terminates |
| Result-stage outage | One effect already happened; original result bytes are withheld |

The MCP executor witness is the independent server ledger containing original
synthetic JSON-RPC calls. The release witness is actual gateway stdout; a filesystem
marker proves when a result has been prepared but remains gated. Refusal/error text
may reach the client without the original protected result. An error, EOF, or a
self-reported `executed: false` alone is never evidence that nothing ran. Withholding
a result cannot undo the tool's side effect.

Cancellation is currently an unsupported notification. The pending-admission
probe sends the original notification only after the production classifier's
ready marker, then releases classification. Separate native HTTP gate checks
record what happens when cancellation is queued during admission. These are
negative transport diagnostics, not support for immediate cancellation or rollback.
An effect recorded before transport refusal must remain visible. Define the
supported cancellation semantics on the integrated candidate before claiming
cancellation support. Existing pipelined/concurrent checks test explicit refusal, not support for
parallel calls. Batch support is also refused.

## Local validation — 2026-10-09

Preparation on macOS arm64, Rust 1.99.0, Python 3.14.3, default Cargo features,
locked offline dependencies, dev/test debug information disabled and incremental
compilation disabled:

| Contributor check | Outcome |
| --- | --- |
| Shared adapter resilience target | 19 passed; no failures/ignored cases |
| Actual MCP target | 25 passed; no failures/ignored cases |
| Native HTTP endpoint target | 28 passed; no failures/ignored cases |
| Workspace Rust tests | 857 passed, 0 failed, 5 ignored |
| Formatting and workspace/all-target Clippy with warnings denied | Passed |
| Python script tests | 150 run: 145 passed, 5 Windows-specific skips |
| Python benchmark tests | 44 run: 28 passed, 16 individual skips; two additional class-level skips |
| Documentation checker | 49 Markdown files, 249 local links, 0 errors |

The five ignored Rust checks need a live model, disposable Redis/PostgreSQL or real
OIDC/SAML configuration. Benchmark skips require explicitly selected AgentDojo or
native Agent environments; two class-level skip records are outside Python's
`Ran 44 tests` count. No unavailable environment is counted as successful acceptance.
The exact-source launcher and CI artifacts identify the tested revision and retain
individual raw outcomes; these preparation counts do not close the integration gate.

## Metrics and remaining runtime acceptance

The report records raw test outcomes and fixture elapsed time, including subprocess
startup, deliberate waits and cleanup. This is not classifier latency or enforcement
overhead; do not subtract unrelated test durations as a performance estimate.
Classification accuracy, uncertainty calibration and a held-out false-block rate are
not measured here. The separate latency probe compares paired calls to the same
local server and requires original-call, executor and released-result witnesses.
Its direct server is a measurement control only. Startup and the declared warmup
are excluded; per-call Python classifier startup remains part of the protected
request. Raw observations and the measurement scope accompany any percentiles. The positive controls check useful calls and session isolation;
their regression pass count is not a general false-interruption rate.

SOU-15 supplied the integrated main `5fc6d72…` candidate with its classifier,
registry/schema/resource/policy configuration and selected bounded Unix read
executor. The current report runs the prepared suites through that production
boundary and independently records remaining failures. The focused repairs are
locally verified on exact candidate `bb64321…`; required review/CI and the affected
actual-main rerun remain pending. Preserve coverage of invalid classifier outputs,
trusted hard-Deny versus weaker classification, Unknown/Ask, model-service failure,
session isolation, replay/restart and independent execution/release witnesses.
Record unsupported mapping, failure or skip explicitly. [The accepted contract](../../contract/updated_contract2.md) requires zero
forbidden executions and zero interruptions of declared authorized Allow fixtures.
Its 15 ms mean / 50 ms p99 and 1% interruption proposals are future targets, not
accepted production gates. Unsupported mappings and unmet accepted limits keep
SOU-17 open; the local regression launcher cannot approve acceptance.

The original October 12 acceptance window required the candidate by 15:00,
blocking failure reports by 18:00 and verification by 23:59. This historical target
is not evidence that acceptance was completed. Later rechecks retain their actual
dates. Any code change after a run requires the affected checks again on the new
revision.

## Historical code scanning triage — 2026-10-09

The [October 11 inventory](../operations/evidence/CODE_SCANNING_TRIAGE_2026-10-11.md)
supersedes the scan revisions below while preserving this historical evidence.

Authorized GitHub access showed **6 open Critical alerts and 74 closed alerts** for
`is:open branch:main`. Each open alert lists only `main` among affected branches.
Other unscanned branches are not certified. The current alert snippets and the Rust
configuration's last scan both identify exact main commit
`fdf4bf716a87b88f17a6241e710bb447885fb8df`, scanned October 8.

[CodeQL Rust configuration](https://github.com/SoupTeam/soup-wall/security/code-scanning/tools/CodeQL/status/configurations/automatic/2b7122206b8ac86cd7b88fd927bd502861908b2a6bfb3dfdcf2968009cb71086)
reported working as expected: CodeQL 2.27.1, `/language:rust`, rust-queries 0.1.43,
rust-all 0.2.22 and threat-models 1.0.58. Default setup also shows Python and Actions
at that commit, with push and pull-request scan events targeting main. This does not
verify required-check/ruleset enforcement; [SOU-18](https://linear.app/soup-wall/issue/SOU-18/task-12-verify-clean-setup-and-actual-active-protection-status)
owns that configuration acceptance. No scan settings were changed or duplicated.

All six findings use `rust/hard-coded-cryptographic-value`:

| Alert | Location | Assessment and rationale |
| --- | --- | --- |
| [85](https://github.com/SoupTeam/soup-wall/security/code-scanning/85) | `provider_baseline.rs:165` | False-positive recommendation: PBKDF2 known-answer input; fixed expected bytes/FIPS rejection |
| [86](https://github.com/SoupTeam/soup-wall/security/code-scanning/86) | `provider_baseline.rs:193` | False-positive recommendation: compliant PBKDF2 known-answer parameters and fixed expected bytes |
| [87](https://github.com/SoupTeam/soup-wall/security/code-scanning/87) | `provider_baseline.rs:524` | False-positive recommendation: negative test asserts unsupported algorithm before parsing |
| [88](https://github.com/SoupTeam/soup-wall/security/code-scanning/88) | `provider_baseline.rs:549` | False-positive recommendation: FIPS negative test rejects SHA-1 PBKDF2 |
| [89](https://github.com/SoupTeam/soup-wall/security/code-scanning/89) | `provider_parity.rs:502` | False-positive recommendation: fixed PBKDF2 provider-parity expected output and FIPS rejection |
| [90](https://github.com/SoupTeam/soup-wall/security/code-scanning/90) | `provider_parity.rs:532` | False-positive recommendation: compliant fixed PBKDF2 parity inputs/expected output |

Both files are under `vendor/kryptering/tests/`, explicit Cargo integration-test
targets separate from the `src/lib.rs` production library. The application workspace
excludes the vendored crate as a member, although production uses its library as a
dependency. Source searches found no production inclusion of these test files;
release packaging ships application binaries and the vendored licence. Fixed
cryptographic test vectors are intentional inputs, with no evidence of a deployed
credential at these locations. Randomizing them to silence CodeQL would weaken the
known-answer checks.

[Machine-readable inventory and source links](../operations/evidence/CODE_SCANNING_TRIAGE_2026-10-09.json)
record each URL/rule/severity/path/commit/hash and assessment. **All six alerts remain
open.** No dismissal, code fix or remediation issue was made: the inspected findings
do not establish a production defect. Nari coordinates technical review; no
CODEOWNERS assignment for these findings has been verified. Record
reviewer-supported disposition and any actual
dismissal rationale, then refresh scan evidence on the final candidate. A working scan
with open recommendations is not a clean scan, and static analysis does not establish
tool-call enforcement effectiveness.
