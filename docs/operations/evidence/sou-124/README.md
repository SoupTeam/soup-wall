# SOU-124 development evidence

## Current native result and correction

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
