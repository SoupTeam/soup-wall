# SOU-17 current-main execution and failure verification — 2026-10-14

Owner: konung3. Review coordinator: Nari_Ab. Roadmap: R06, bounded P01–P02.

The updated main candidate `5fc6d72fd73ebe9faa70c56607fc492163df1a42`, including
[SOU-15 PR #107](https://github.com/SoupTeam/soup-wall/pull/107), supplies actual
operation-level constrained execution for the selected Unix `read_document`
profile. Useful authorized file reads are now independently witnessed at the
production native/MCP boundary. This replaces the earlier dependency on an
unfinished resource executor; it does not establish arbitrary tool confinement.

**This exact main revision is not accepted.** The existing 112 regressions,
15-case generic classification profile and ten-case bounded resource profile
pass. Two additional independent probes establish an admitted FIFO read that
hangs and unsupported overlapping inline reads that are both executed/released.
[SOU-44](https://linear.app/soup-wall/issue/SOU-44/refuse-post-admission-fifo-replacement-without-blocking-the)
and [SOU-45](https://linear.app/soup-wall/issue/SOU-45/enforce-unsupported-overlap-refusal-for-inline-constrained-mcp-reads)
record focused owner repairs and regression requirements. Passing existing tests
cannot erase those findings. SOU-17 remains open until the relevant fixes are
reviewed and verified on a new exact revision.

[Structured observations and raw-artifact manifest](sou17_candidate_5fc6d72_2026-10-14.json)
retain source/configuration identities, native execution/release witnesses, raw
outcomes, latency and the confirmed failures. Earlier dated reports remain
historical evidence; no failing run has been relabelled as a pass.

The [deterministic raw evidence archive](sou17_candidate_5fc6d72_2026-10-14_raw.tar.gz)
contains the original launcher/probe JSON, grader comparison and logs, Python
check logs, additional failure observations/reproduction sources and CodeQL UI
metadata/source excerpts. `MANIFEST.json` records each original byte length and
SHA-256. Reviewers can download/extract it and inspect the actual ordered native
audits, final ledgers and client/server transcripts embedded in those JSON files;
the report does not depend only on inaccessible local output paths. The archive
contains synthetic fixtures and local source metadata, not operator profile
token/configuration files or credential-bearing request headers.

## Exact source and tested scope

| Input | Recorded identity |
| --- | --- |
| Clean production commit, unchanged before/after original probes | `5fc6d72fd73ebe9faa70c56607fc492163df1a42` |
| Production tree | `ee49a2ffc0e78136767e4075223c5129fd3e5dd7` |
| Tracked input digest | `3c13497dc96c677c64a249e53e0d9eb8ca26a2db63a353a3f6096acc51f6e28b` |
| Agent binary SHA-256 | `a11ac87ef488feb64f62ac2db7794db09f79364164227d130c6bfb2a329e1dd5` |
| Real rule baseline SHA-256 | `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd` |
| Cargo.lock SHA-256 | `408062e53fc9330027e9d118499633755e8ba7e4c8bd0bd386266667f5f940ad` |

Native macOS arm64, Darwin 25.3.0, Rust/Cargo 1.99.0 and Python 3.14.3;
default Cargo features, locked offline dependencies, debug information and
incremental compilation disabled. The candidate was pristine during its original
verification. New graders and independent probes used separate directories.
The imported production adapter/classifier/policy and actual native/MCP admission
remain authoritative; there is no competing test-local execution pipeline.
Fixtures use published synthetic content, temporary owned files and loopback
services. No external model, paid request, production secret or external receiver
was used.

The constrained profile supports bounded UTF-8 reads through a pinned Unix
workspace root and allowlisted regular paths. Absolute and relative authorized
reads return the exact owned file contents. Child operation ledgers remain empty
because this profile executes its file read in the gateway; an empty child ledger
alone is therefore not evidence of no execution. Original file contents, native
call/result bindings and the client transcript provide the positive read/release
witnesses. Arbitrary subprocess, generic network, write/delete/permissions and
other platform confinement are outside this bounded acceptance.

## Existing tests and independent resource profile

| Check | Outcome on original main |
| --- | --- |
| Exact-source launcher | 112/112: adapter resilience 19, actual MCP 56, native HTTP 37; no failures, timeouts or skips |
| Generic five-shape classifier boundary | 15/15; four executor entries, 505 original result bytes; zero forbidden effects/releases |
| Pending admission and hard-Deny overlap | 11/11; no technical-unsupported or inconclusive rows |
| Repeated Ask continuation | 64 Ask refusals, zero executor entries; one useful follow-up executes and releases its original result |
| Existing `sou15_*` native resource regressions | 9/9, no ignored cases; a subset of the launcher tests, not nine additional unique cases |
| Strict bounded resource profile | 10/10; authentic admitted reads, explicit refusals, protected result withholding and useful error recovery |
| Updated resource grader | 13 test methods passed; 15 explicit adversarial witness mutations all rejected |
| Initial clean-main Python script suite | 460 run: 450 passed, ten native-Windows skips |
| Initial clean-main Python benchmark suite | 44 run: 28 passed, 16 individual skips; two additional class-level skip records outside the run count |

The shared/native suites exercise malformed JSON and scores, missing fields,
Unknown/read+Unknown, mixed dangerous actions, hard-Deny overlap, duplicate/replayed
IDs, cancellation, daemon outage/timeout/restart, peer-session isolation, benign
usefulness and errors after partial effects. Deny and unconfirmed Ask are observed
before executor entry; result-stage refusal is measured separately. An allowed
executor's witnessed side effect remains recorded even if execution or result
delivery later fails. Withholding content cannot undo that effect.

| Resource case | Production observation |
| --- | --- |
| Absolute and relative read | Read/Allow classification; authentic bound call and result Allows; exact file text reaches client |
| Unlisted file | Authentic native call refusal; no child call or private file content released |
| Traversal and symlink | Resource path refusal before native reservation; no protected content released |
| Unsupported tool | Bound classification followed by `resource_executor_unsupported` before native reservation; no execution or protected result |
| Result withholding | Read admitted; native result gate refuses release; original file content absent from client |
| Configured workspace mismatch | Explicit refusal before execution |
| Missing workspace | Startup refused before MCP initialization/call or fixture-server startup |
| Read-error recovery | 70 admitted read failures retain honest correlated errors; a subsequent useful authorized read succeeds in the same session |

The original resource grader scored the same raw observations **9/10** because it
expected a native Allow reservation for `unsupported-tool`. Current production
refuses this unsupported executor before reservation. The updated grader requires
bound classification, the exact unsupported refusal, no native reservation, no
forwarded operation and no protected content. It scores **10/10** on the unchanged
raw observation set; the comparison and original failure are retained. Missing,
unbound or contradictory evidence still fails. This grader correction is separate
from the two confirmed runtime defects below.

## Confirmed failures and linked remediation

**SOU-44 — admitted special-file replacement can hang a bounded read (High).**
After the real daemon returns an enforcing `sw-native/resources/1` Allow receipt,
an owned local proxy replaces only the approved regular leaf with a FIFO and
returns the original receipt unchanged. The real rule baseline classifies Read;
one authentic native call is admitted. The gateway stays alive without a correlated
response for **4.010 seconds**. There is no native result, child tool invocation or
original protected content release. The file change is the verifier's deliberate
fault injection, not a tool write; the monitored `files_unchanged` field concerns
other canaries and must not be read as proof that the approved leaf stayed unchanged.

`PinnedWorkspace::open_file` opens the leaf using blocking
`O_RDONLY | O_NOFOLLOW | O_CLOEXEC` before `fstat` checks whether it is a regular
file. Opening a FIFO without a writer prevents that check from running. The
inline synchronous operation also blocks the gateway loop's pending deadline
handling. A separate production-helper probe confirms the blocked kernel open.
Replacing the leaf during classification, before authorization, was correctly
refused as `native_resource_argument_mismatch`; that earlier success does not
negate the post-Allow failure. No unauthorized disclosure is claimed.

Owner/reviewer: Nari_Ab; independent verifier: konung3. Repair acceptance requires
a prompt non-regular-file refusal at the actual admitted MCP boundary, zero
original content release, native reservation cleanup and a useful regular read
afterwards. The original admitted-FIFO, helper and pre-admission diagnostic
artifacts are separately identified in the manifest.

**SOU-45 — unsupported inline overlap is processed instead of refused (Medium).**
Two valid `read_document` requests are written to gateway stdin together, before
awaiting either response. Both are classified/admitted and return the owned
authorized document: **two native call Allows and two released native results**.
The child ledger is empty and the collector exits normally. This demonstrates
serialized inline processing, not simultaneous OS execution or an authorization
bypass. The accepted unsupported-concurrency behavior requires explicit refusal;
queue support has not been agreed.

The inline resource branch does not set `Pending::Call`, unlike the child-backed
path covered by the existing concurrency test. Owner/reviewer: Nari_Ab;
independent verifier: konung3. Repair acceptance must exercise overlap queued
during classification, call admission and result gating, refuse the second
unsupported call before its execution/protected release, preserve honest first
effects and reservation cleanup, and retain useful sequential reads/session
isolation. The diagnostic's expected-single-read grade is deliberately failing;
its two original replies and ordered native audit are retained.

All owned fault-injection subprocesses, listeners and temporary profiles were
cleaned up. A first probe with an incorrect classifier setting failed at startup
and is retained separately as infrastructure failure, not a runtime pass.

## Latency and false interruptions

Thirty paired useful reads compare the same direct local child-backed fixture
with its protected production path. Startup and one warmup pair are excluded;
per-call Python classifier startup remains included. All 60 measured rows have
complete final execution/result witnesses: **zero of 30 protected authorized
reads interrupted**, with no missing, unknown or anomalous rows.

| Milliseconds | Direct request | Protected request | Paired overhead |
| --- | --- | --- | --- |
| p50 | 0.230 | 40.883 | 40.673 |
| p95 | 0.361 | 144.101 | 143.915 |
| p99, nearest rank | 6.556 | 165.066 | 164.786 |
| Mean overhead | — | — | 48.751 |

Other verification probes ran concurrently on the host during this sample and
may inflate the tail. These retained observations are not isolated-load latency,
the new constrained read executor's performance, classifier accuracy/calibration
or a population false-block rate. No numeric latency gate was agreed; future
contract proposals are not accepted production limits. The two confirmed failures
are not counted as successful acceptance because this small benign sample passed.

## Code scanning and delivery status

[October 14 independent triage](../../operations/evidence/CODE_SCANNING_TRIAGE_2026-10-14.md)
records **one open Critical / 85 closed main alerts** and working Rust, Python and
Actions CodeQL analyses of the exact `5fc6d72…` source. Alert #112 reports the Unix
permission mode `0o600` as a hard-coded nonce. Source and displayed flow establish
an evidence-backed false positive; it remains open for coordinator review and no
dismissal was performed. No confirmed code-scanning defect was identified.
The runtime findings SOU-44/SOU-45 remain distinct from static analysis.

The initial candidate's narrowed execution positive is established, but its
confirmed availability/overlap failures keep SOU-17 open. Implementation fixes,
their regression checks and this report must pass normal repository review.
After a code change, rerun affected checks on the new exact revision and record
its binary/configuration identities; do not reuse original-main passing counts
as evidence for modified code. Hosted CI, other platforms and protected active
deployment are separate claims and are not established by these local results.

## Reproduce and retain outcomes

Use prerequisites in [DEVELOPMENT](../../DEVELOPMENT.md). Create a clean detached
candidate and a separate fresh output directory. Keep the verification/report
checkout separate so that an updated grader does not dirty the candidate.
On macOS use canonical `TMPDIR`; fetch locked dependencies before `--offline`
if they are not cached. These commands need temporary loopback listeners.

```sh
SOU17_VERIFY_REPO="$(pwd)"
SOU17_COMMIT=5fc6d72fd73ebe9faa70c56607fc492163df1a42
SOU17_CHECKOUT="$(mktemp -d "${TMPDIR:-/tmp}/sou17-source.XXXXXX")"
git worktree add --detach "$SOU17_CHECKOUT" "$SOU17_COMMIT"
export CARGO_TARGET_DIR="$SOU17_VERIFY_REPO/target/sou17-current-build"
SOU17_OUT="$SOU17_VERIFY_REPO/target/sou17-current-reproduction"
(cd "$SOU17_CHECKOUT" && python3 scripts/verify-sou17.py \
  --expected-commit "$SOU17_COMMIT" --offline --out "$SOU17_OUT/exact")
SOU17_BINARY="$CARGO_TARGET_DIR/debug/agentfw"
SOU17_BINARY_SHA="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$SOU17_BINARY")"
python3 scripts/verify-sou17-generic-boundary.py \
  --repo "$SOU17_CHECKOUT" --agentfw "$SOU17_BINARY" \
  --expected-commit "$SOU17_COMMIT" --expected-binary-sha256 "$SOU17_BINARY_SHA" \
  --output "$SOU17_OUT/generic"
python3 scripts/verify-sou17-pending-admission.py --repo "$SOU17_CHECKOUT" \
  --agentfw "$SOU17_BINARY" --expected-commit "$SOU17_COMMIT" --output "$SOU17_OUT/pending"
python3 scripts/verify-sou17-refusal-capacity.py --repo "$SOU17_CHECKOUT" \
  --agentfw "$SOU17_BINARY" --expected-commit "$SOU17_COMMIT" --output "$SOU17_OUT/capacity"
python3 scripts/verify-sou18-resources.py --run --repo "$SOU17_CHECKOUT" \
  --agentfw "$SOU17_BINARY" --expected-commit "$SOU17_COMMIT" --output "$SOU17_OUT/resources"
python3 -m unittest discover -s scripts/tests -p 'test_sou18_resources.py' -v
python3 scripts/measure-sou17-latency.py --repo "$SOU17_CHECKOUT" \
  --agentfw "$SOU17_BINARY" --expected-commit "$SOU17_COMMIT" \
  --pairs 30 --output "$SOU17_OUT/latency"
```

Download/extract the retained raw observation set separately from any reproduction:

```sh
mkdir -p target/sou17-retained-evidence
tar -xzf docs/benchmarks/evidence/sou17_candidate_5fc6d72_2026-10-14_raw.tar.gz \
  -C target/sou17-retained-evidence
```

The launcher/profile commands emit bounded fixture outcomes, not execution
approval. Preserve original JSON/transcripts before rerunning. Reproduce the
additional FIFO failure by substituting the approved owned leaf only after an
authentic Allow receipt; reproduce overlap by sending both native calls before
waiting for either response. Their frozen source hashes and raw observations
are retained in the report manifest and linked owner issues. Do not infer failure
from timeout alone: reconcile authentic admission, observed process state,
independent side effects and actual released bytes.
