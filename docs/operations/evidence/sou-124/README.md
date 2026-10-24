# SOU-124 qualification evidence

## Current-base terminal-cleanup follow-up

The accepted SOU-125 integration `e17d73a` was source-approved, but its current-base
CI `40070620829` failed in the Ask lifecycle witness with
`unexpected_launcher_exit_cleanup`. Nine cases passed; the filesystem approve
case remained failed with four later cases incomplete. Its primary launcher and
owned cleanup had succeeded. The failing operation was `sibling.finish()` after
explicitly rejecting the independent run. The retained diagnostics did not
identify which namespace acknowledgement was missing; the failed sample is not
dismissed or relabelled.

A regression reproduces a concrete terminal-order defect: without an operator
Stop marker, `cleanup_waiter` returned success without consulting the daemon or
existing owners. Normal host-group TERM/KILL could therefore destroy collectors
before they acknowledged namespace cleanup. Terminal cleanup now revokes only
this run's two exact grants, closing admission and waking enrolled owners, then
uses the existing bounded acknowledgement wait before signalling the pinned,
unreaped host group. An acknowledgement failure still performs physical cleanup
and reaping, then propagates the failure. Normal completion creates no Stop
marker and cannot become a fake `stopped` outcome. Foreign, unavailable or
unconfirmed ownership still refuses; all existing effect assertions and budgets
remain.

The new unavailable-observer regression failed on the original implementation.
After the correction it and a real loopback HTTP ordering/acknowledgement control
pass, including a foreign-owner refusal and no fake Stop marker. Local workspace
qualification passes 1716 Rust tests (13 existing ignores) and 1245 Python tests
(1166 passed, 79 existing platform/optional skips), with zero failures. Strict
clippy/formatting and current native qualification are recorded separately in
`terminal-cleanup-order-correction.json`. The earlier performance comparison
below remains attributed to its measured source; it is not a claim that the
post-integration failure or this new native qualification passed.

The first follow-up CI on `e340932` exposed a platform mistake in the new
loopback test: Windows explicitly refuses `read_file(private=true)` for the
unsupported run-scoped contract before reaching a daemon, so the positive witness
waited for a request that could never happen. Both new RunGuard witnesses now
use `cfg(unix)`, matching the existing sealed-owner/receipt test boundary. Their
bodies and all assertions remain unchanged on Linux/macOS; no runtime logic is
changed by this test-platform correction. The failed Windows job is retained in
`terminal-cleanup-witness-platform.json`. Current Windows and native CI remain
required before readiness. An explicit non-Unix negative witness now asserts the
unsupported-contract error and zero native HTTP requests against a live endpoint;
Windows coverage is not silently skipped or misreported as successful cleanup.

The same run failed the original Git Reject case with
`collector_retirement_unconfirmed` (three passed, one failed, ten incomplete).
Both Git owner and budget cleanup were verified, but the final Git collector
completion/acknowledgement was absent. The real collector handled Ctrl-C but had
no SIGTERM handler, allowing host shutdown to abruptly terminate that completion
path. SIGTERM is now intercepted before owner creation and cancels transport
through the existing full cleanup path. Missing or foreign acknowledgements
remain failures. This source defect is consistent with the missing completion;
the historical trace did not retain a terminal signal and does not prove which
signal caused that sample. `collector-terminal-signal-correction.json` preserves
the failure and finite observations.

Full native lifecycle qualification retains all 14 existing cases and adds one
Git-only `collector_term` probe. It signals the kernel-observed owned collector
through a start-time-checked pidfd while the original Ask is pending, and requires
a correlated refused result, zero original dispatch/effects, normal collector
exit, authenticated cleanup and complete owned-process retirement. There is no
useful-followup claim for this terminal cancellation probe; all existing useful
continuation assertions and deadlines remain. Approval-only timing samples and
the 80-row comparison denominator are unchanged. Current native proof remains
required; local tests cannot supply that result.

The current-base integration includes main `2b07991` (SOU-122). Both workflow
conflicts preserve optional comparison validation and compiler/interpreter
attestation; the generated component workflow is checked against its sources.
Local development uses Homebrew Rust 1.99.0 on macOS, while current CI must attest
and qualify the accepted lane pins (1.99.1, native Linux 1.94.1).

A second terminal-path control reproduces another independent failure boundary:
Rust `eprintln!` panics if the host closes a collector diagnostic pipe. Terminal
records preceded the authenticated cleanup ACK, and the stderr-drain worker also
logged before returning its actual result. Diagnostic writes now use a local
non-panicking writer with identical output formatting. This ignores only the
reporting write error; transport/drain quota errors and every cleanup/ACK result
remain authoritative. A real Unix subprocess with its diagnostic reader closed
fails on the original implementation and passes after correction, while the
original 1 MiB stderr quota still refuses. Its parent bounds execution, kills and
reaps on timeout. `closed-diagnostic-cleanup-correction.json` records this local
proof and its limits; it does not attribute EPIPE to the historical CI sample or
claim a native owner/ACK qualification from that subprocess.

## Current native comparison

`native-linux-current.json` records the passing comparison in run `40052146937`
on exact clean runtime/harness source
`6da8216b07bb936e2da5908fbae64726ffedcb3a`. All eighty same-runner approvals
completed: twenty filesystem and twenty Git samples on each side, with zero
failed/incomplete cases. Independently recomputed candidate p50/p95 was
1054.528047/1118.506491 ms for filesystem and 1668.458611/1727.172854 ms for Git.
Baseline was 3050.336640/3126.399458 ms and 3651.970215/3732.601800 ms.
Both candidate p95 values meet the unchanged 3000 ms target.

Every candidate and both preflight samples had a genuine selected-collector reuse
observation scoped to the completed original approval (52 retained leases for
filesystem, 144 for Git). All original effects, useful follow-ups, peer progress,
cross-run controls and owned cleanup passed. Strict real-kernel/process-budget
qualification and all eleven Linux identity controls passed. The optional
already-verity-enabled fixture was ignored; no actual fs-verity reuse, paid
provider, live-model effectiveness or physical human presence is claimed.

The **whole workflow failed after the passing comparison**: the subsequent
first-use demo refused `profile_package_changed` before execution. Preparing
hash-locked wheels had run the already authenticated package's Python with `-I`
but without `-B`. Isolated Python ignores `PYTHONDONTWRITEBYTECODE` and can add
`__pycache__` inside that package. The download now uses explicit `-B` and checks
the authenticated package digest before and after. An offline local behavioral
control reproduced 300 added bytecode files without `-B` and verified an unchanged
tree with it. Eighty CI workflow controls pass with one intentional skip.
`offline-input-bytecode-correction.json` records this follow-up. No Rust or
measured Ask harness changed; current full CI separately qualifies the workflow
and demo correction. A passing comparison is not a claim that the failed whole
workflow passed. Source identities and all report/log digests remain attributable.

The first full CI on `37143e3` passed the first-use demo, but its separate
Ask lifecycle witness stopped at the first Git expiry case with
`useful_followup_pending_missing`. It had started the follow-up's 20-second poll
before the deliberately 20-second primary expiry; the primary refusal and next
proposal were observed only at the end of that wait. The correction first
observes the original pending expiry, then starts the separate useful request's
existing poll. Host/call/broker/poll values remain 90/25/20-or-30/20 seconds.
Original-expiry attribution, effect/cleanup assertions and the approve/measurement
branch are unchanged. Regression controls reproduce the former overlapping-clock
failure without real sleeps and reject unbounded, invalid or unobserved expiry.
All 36 focused Ask controls and the full local Python suite (1229 run, 1150
passed, 79 existing platform/optional skips) pass. The failed native row, finite
diagnostics and raw-report digest remain in
`expiry-followup-scheduling-correction.json`; current full CI still determines
readiness.

The subsequent `f6963c6` full CI (`40058255940`) passed all fourteen Ask
lifecycle cases, including both original-expiry refusals with zero dispatch/effect
and a useful continuation. Git refused 57 ms after its original deadline;
filesystem refused 45 ms after its original deadline. Clean source before/after,
unchanged workspace and the raw report digest are retained in
`expiry-followup-scheduling-correction.json`. This corrects the earlier summary
that placed the failure before the expiry cases: the separate later
selected-server approval witness missed its unchanged five-second
pending observation: its traced capture alone took 4733.702660 ms for runtime/
libraries and 4299.371333 ms for the package. Separately, the prepared demo's Ask
case observed all three useful correlated results and two operator decisions,
but the owned entry hit its unchanged 60-second overall timeout. Both observers
still used ordinary ptrace interception, including stops for unselected metadata
syscalls. They now request the same seccomp-assisted tracing mode used by the
passing paired measurement, retaining their exact original syscall sets, all
positive/negative effect assertions and every original deadline. Reports explicitly
record a request with possible fallback, not an unproved installed filter.
`witness-observer-consistency-correction.json` preserves both failures and local
Python results (1229 run, 1150 passed, 79 existing skips). A fresh current native
CI must validate the correction; no passing lifecycle result is inferred from
the local run or the previous 80-sample comparison.

## Historical passing comparison on 1137780

`native-linux-1137780.json` records passing run `40038036266` on exact clean
runtime/harness source `11377802ba4fa9868bf7502fc798fd0f3f06e7a4`. Both sides
completed twenty filesystem and twenty Git approvals on one native Linux runner,
with zero failed/incomplete samples. Candidate filesystem p50/p95 was
1870.729004/1938.429574 ms; Git was 2862.994321/2914.567600 ms. Both p95 values
meet the 3000 ms target. Baseline p50/p95 was 5566.666193/5597.575073 ms and
6471.589357/6553.200421 ms respectively. Percentiles and full denominators were
independently recomputed from all eighty durations.

Every candidate used real retained leases (52 filesystem, 144 Git), and every
original call, useful follow-up and owned cleanup passed. Cross-run isolation
controls passed for all filesystem samples. The strict kernel witness also
filled and released the 512-descriptor process budget across independent owners.
Ten Linux identity controls passed; the optional already-verity-enabled fixture
was ignored. No fs-verity reuse, physical human presence or live-model
effectiveness is claimed. Full raw report hashes and per-sample proof/effect
receipts remain attributable to the workflow artifact. Historical failures below
remain failures. Final main integration and current required CI are separate
checks; they do not relabel the measured source.

The first full Ready CI on `ba9441c` found a newer-stable Rust deprecation and
three non-deterministic identity tests. Two unlink/recreate fixtures could reuse
the same inode within one timestamp quantum; they now retain the displaced inode
with rename, keeping the replacement assertion. The third exposed missing
completeness validation inside the tree-walk helper: its production caller
already compared the full tree digest, but the helper now independently checks
the captured cardinality. Each visited path must already exist in the captured
set, so equal cardinality also proves no path disappeared, even with matching
directory timestamps. A new negative control models that exact condition.
Lease slot reservation now uses portable compare-exchange instead of a
deprecated API, without warning suppression. The follow-up requires fresh native
qualification and current CI; the `1137780` timings are not relabelled.

`native-644abcc-observer-failure.json` retains the subsequent run `40047008403`.
Strict real leases, all eleven Linux identity controls, installed-profile resume
and two-profile preflight passed. Baseline completed all forty samples; the
candidate had three successful Git samples, one observer failure and thirty-six
incomplete cases. It is not a passing current performance result. The raw write
record was private and not retained, so its exact syntax is unknown.

The observer follow-up handles zero-transfer/restarted writes and zero-length
iovecs without crediting any bytes. It requires one real reuse event followed by
the same original call's observed verification, dispatch, response and successful
inspection. Only that completed diagnostic window closes; independent wire,
kernel-effect and cleanup witnesses still consume the entire trace. Unknown
positive writes inside the window, missing/mismatched/foreign completion, duplicate
reuse and missing proof still refuse. Ambiguous shutdown diagnostics cannot
invalidate a previously completed invocation's history. Closed stderr no longer
hides a failure diagnosis; only a finite kind and record digest are exported.

## Historical native attempt 6

`native-attempt6.json` retains the same-runner comparison from run `40010363488`
on exact candidate `d95e000a445708aaa4446d910576cf929baaf740`. All forty baseline
and forty candidate approvals completed with original effects and verified
cleanup; no sample failed or remained incomplete. Candidate filesystem p50/p95
were 2015.973892/2053.221803 ms; Git was 3212.695048/3274.838387 ms. Baseline
filesystem was 5566.812997/5976.986912 ms and Git 6456.692781/6493.114153 ms.
The strict real-lease witness, ten Linux identity controls and original-profile
capture/resume passed; the optional already-verity-enabled fixture was not run.

**Git still misses the 3000 ms p95 target. This is a performance blocker.**
Raw report hashes and all sample durations/proof counts are retained, and the
nearest-rank percentiles were independently recomputed. Every candidate used
actual retained kernel leases. No previous ordinary-ptrace baseline was mixed
into this seccomp-assisted comparison. Neither side made paid provider calls.

The next bounded correction increases the per-Ask lease capacity from 96 to 256
for the larger Python package (with a 512-descriptor process-wide cap), and avoids
unused verity queries when no verity proof was captured. Redundant caller-side
directory observations are removed while retaining both descent closure checks.
Files without a retained proof are still fully rehashed;
existing verity proofs are still remeasured, and lost leases still refuse.
The follow-up requires fresh native measurements before Ready for review.

## Earlier native attempts

The second native attempt (`39989703005`, exact source `d37383e`) passed the
strict real-kernel lease witness. Its baseline completed all 20 filesystem and
20 Git approvals, with no failed/incomplete samples. Baseline p50/p95 were
8742.44/8840.96 ms for filesystem and 11216.22/11310.10 ms for Git. The candidate
failed to publish its first Git pending approval within the unchanged witness
deadline; the other 39 planned samples remain explicitly incomplete. This is
not a completed before/after comparison or a passing optimization.

`native-attempt2-{comparison,baseline,candidate}.json` preserve those bounded
reports and their raw SHA-256 values. Current follow-up replaces repeated Linux
userspace ancestor traversal with O_PATH/descriptor canonical identity, retaining
all metadata and link checks, and adds a two-profile correctness preflight before
the full paired measurement. Preflight cannot satisfy or shrink the 40-row
performance denominator; original deadlines and effect assertions are unchanged.
Only finite diagnostic codes, stage timings and trace hashes are retained on
failure. A fresh native run is required; the PR remains Draft.

`native-attempt3-preflight.json` retains the failed two-profile preflight on
`3f22f94`. The Linux O_PATH control then lacked a followed final-file symlink
case. The correction preserves normal runtime symlinks while still rejecting
replacement/retargeting, and authenticates stderr diagnostics from blocking
worker threads using successful kernel clone lineage. Actual installed-profile
capture/resume now runs before any long measurement. A fresh complete native
result remains required; local correction checks do not claim its success.

`native-attempt4-preflight.json` records source `77fae98`: real installed-profile
capture/resume passed, but the traced host's package-tree capture did not finish
before the unchanged pending witness deadline. Runtime/library capture completed
in 1466.78 ms. The descriptor-tree correction removes repeated regular-leaf
path opens while retaining the complete metadata/content checks and all parent
closure checks. `descriptor-tree-correction.json` records passing local checks;
its Linux branch and performance still require fresh native qualification.

`native-attempt5-preflight.json` retains the ordinary-ptrace run on `9c5e87b`.
Its stricter tree controls and untraced real-profile capture/resume passed, but
the traced host still did not publish pending within its original deadline.
The common paired harness now requests seccomp-assisted strace with the identical
selected syscall/effect set; old ordinary-ptrace baseline samples are not reused.
A separate Linux-only correction gates verity claims to known kernel filesystem
implementations, since FUSE forwards that ioctl to userspace. Local and native
check attribution remains explicit in `proof-fs-trace-boundary.json`; no passing
native or performance result is claimed for this correction yet.

The sections below are historical checkpoints, not current readiness claims.

## Verified input reuse follow-up

`input_reuse_review.json` records implementation `e571245` and exact source hashes
after adding per-Ask verified input observations, conditional fs-verity immutable
reuse, and unit/relay controls.
The complete Rust workspace passes with 1661 passed, 0 failed and 13 ignored;
strict clippy, formatting and whitespace checks pass. These remain macOS observations,
not Linux performance qualification.

## Cleanup review follow-up

`review.json` records implementation `deb5aa7` and exact source hashes after
ensuring that failed latency accounting cannot bypass owned-process cleanup.
All active hosts and the daemon receive a cleanup attempt even when an earlier
owner's cleanup fails. The Python 3.11 supported suite passes: 1101 run, 1039
passed, 62 skipped, no failures. Eleven focused Ask controls pass, including
eight accounting/host/daemon failure combinations. Reintroducing the accounting
ordering defect makes the regression fail. Rust is unchanged from the original
checkpoint below. This does not implement input reuse or supply Linux samples;
the performance blocker and Draft status remain.

Implementation checkpoint: `77ec1a5ed5c2214cf641fb8d7ba86eab22c43a86`, based on
accepted main `cdd9d36c65a592455e4f421268758adb6db744b8`.
`development.json` records its tree and the exact changed-file SHA-256 values.
An evidence-only follow-up commit does not claim another implementation was run.

## Verified locally

- Isolated branch Cargo target, canonical `TMPDIR=/private/tmp`:
  `cargo test --offline --workspace --locked`: 1656 passed, 0 failed, 13 ignored.
- `cargo clippy --offline --workspace --all-targets -- -D warnings`,
  `cargo fmt --all -- --check`, and `git diff --check`: pass.
- Python 3.11 supported suite: 1100 run, 1038 passed, 62 skipped, no failures.
  Of the skips, 59 are the existing platform/optional skips and three are the
  unchanged Linux `/proc` process-group controls. The product tests were not
  edited to skip them. Their initial unsupported failures remain described below.
- Focused Ask scheduling/accounting/CLI tests: ten pass, including nonzero exit
  on a missed target and preservation of failed/incomplete sample denominators.

## Failed development attempts retained

The first broad Rust run used macOS's redirected `/var` temporary root. It
reported 546 passed, 11 failed, one ignored: classifier-package tests refused a
symlinked profile. The protection was not relaxed. Repeating with canonical
`TMPDIR=/private/tmp` resolved that setup problem. An initial offline focused
run also lacked a locked dev dependency; the declared dependencies were installed
before the successful runs.

An early shared Cargo target was used for both development checkouts. A later
SOU-125 compile could not resolve its newly added public module despite the
source declaration. Those mixed-cache diagnostics are not accepted evidence.
The final runs used separate targets with all workspace package artifacts
cleaned and rebuilt. Private raw logs remain outside the repository; the
successful log hashes are recorded in `development.json`.

## Historical initial platform blocker

The real preparation platform check was invoked on this host. It returned
`ValueError: native_linux_x86_64_required` before starting a process. There is
no native Linux or WSL acceptance report here, and no baseline/after samples.
The performance target is unmet/unmeasured and repeated full verification is
still present. The implementation is a runnable profiling first slice, **not**
the completed optimization. No timeouts, witnesses or authority checks were
weakened, and no paid provider call or live-model effectiveness claim was made.
