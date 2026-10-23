# SOU-124 development evidence

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

## Explicit blocker

The real preparation platform check was invoked on this host. It returned
`ValueError: native_linux_x86_64_required` before starting a process. There is
no native Linux or WSL acceptance report here, and no baseline/after samples.
The performance target is unmet/unmeasured and repeated full verification is
still present. The implementation is a runnable profiling first slice, **not**
the completed optimization. No timeouts, witnesses or authority checks were
weakened, and no paid provider call or live-model effectiveness claim was made.
