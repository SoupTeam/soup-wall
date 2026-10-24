# SOU-122 evidence: compiler and interpreter inputs of the native lane

This directory retains the evidence of one green run of the internal Linux pilot
candidate on the head of PR #231.

- Workflow: `mcp-real-filesystem.yml`, job `native-ubuntu-2404`
- Run id: `40002053780` (attempt 2, green; see "Failed attempts")
- Source commit: `b8d369b1adce52edf5328214d4d7c40cd73ec4ff`
  (tree `ce56802a6d83fdf991168f53a26d978b9e738860`, clean checkout)
- The PR head after this evidence was added differs from that commit only by the
  files in this directory.

## Scope

This is **input attestation**. It records which compiler and interpreter
executables were invoked in the run and that they match the pins in
`profiles/toolchain/linux-pilot-toolchain.json`. It does not claim
byte-identical binaries and it is not a certification of the whole product.
Pilot readiness stays "not certified" in the qualification report.

The native lane stays on Rust 1.94.1 and pins and runtime policy are unchanged.
The repository default (`rust-toolchain.toml`) is 1.99.1; the native job
overrides it with `RUSTUP_TOOLCHAIN=1.94.1`, and the attestation records both.

## Selected identities (from this run)

`rustc` and `cargo` are resolved from `PATH` through the rustup shim
(`resolved_via: rustup-shim`, `rustup which`), those exact files are run, and
the verifier refuses the run when they are not the executables in the sysroot
that `rustc` reports.

| Input | Identity |
| --- | --- |
| rustc 1.94.1 | commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, host `x86_64-unknown-linux-gnu`, executable sha256 `ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d` |
| cargo 1.94.1 | executable sha256 `b7561ebe947acf816451536f19871ea4810f6be3f82fd252feab6ca7be8396f5` |
| Python (classifier) | CPython 3.12.15, executable sha256 `53dab24bf9e0e9c490088a53d71770b6f027b057678b313648e75f7fc87a675e` |
| `Cargo.lock` | sha256 `b603e17ee717ea60c80db5a0eb0b2b0837659d9cea9e917654900610ae42798e` (443 packages, tracked) |
| `rust-toolchain.toml` | sha256 `5a7b7b624394e3ece3fb4c9e0391aa400eeebf7a7a1efd18e74c5b68b71cd65e` |

The 1.94.1 commit hash is recorded in the attestation but is not enforced: the
pins file deliberately does not change in this PR. Enforcing it would be a
separate decision.

Binaries built in the same run (`selected-hashes.txt`):

| Artifact | sha256 |
| --- | --- |
| `agentfw` | `d9d2c000b4f279d0e3be05cb33e1550f69efa413ac6ce48d2656cf3b6bdaa11b` |
| `git_launcher` | `ff5a971ec12db6a234da1d2f9ba6b1679ffaf5be918a165376728cdba49e19d7` |
| `sandbox_tests` | `c577fb0da6839ef3e7716e687a7ae6611d922b6fdfb22421cf72c8cb249d2099` |
| source-built `git` | `2176191737ea70888df8ba9ce47353ae45611c7197f832c9a235c00926663d35` |
| source-built `bwrap` | `48785c2018cf6f3b6ec45c5ae2fff9df9784316e86211201bb8dbb8af1d414a8` |
| `node.tar.xz` (input archive) | `9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37` |

These hashes differ from the earlier green run on `2d45bc3` only where the
source commit differs (the Rust and interpreter executables and the input
archives are identical).

## Retained files

| File | What it shows |
| --- | --- |
| `native-attestation.json` | Output of `scripts/verify-pilot-toolchain.py --lane native`: status `verified`, every check, executable hashes and how they were resolved. |
| `selected-hashes.txt` | Hashes of the executables selected for the run. |
| `preparation-summary.json` | Native/source preparation summaries, the two refusals below, and timings. |
| `original-server-results.json` | Useful results returned by the original filesystem and Git servers in the same run (read, diff, show, status). |
| `installed-pilot-qualification-report.json` | Qualification report, status `passed`, scope `development-installed-host-scripted-provider`, `pilot_readiness: not_certified`. |
| `prepared-pilot-acceptance-report.json` | Prepared-pilot acceptance report, status `passed`, provider `owned-scripted-loopback`, `live_model_effectiveness: not_tested`. |

## Refused inputs (negative evidence from the same run)

- Native prerequisites with a wrong archive digest were refused:
  `git_archive_digest_mismatch` (`active_protection: false`).
- A changed source commit was refused: `candidate_source_mismatch`.
- The previous generation was preserved in both cases, and verified reuse
  worked (`verified_reuse_seconds` 0.655 versus a clean build of 102.751 s).

## Failed attempts

None of these was masked or retried until green.

1. The attestation step hashed `cargo` under an 8 MiB limit written for small
   files. Fixed with a separate 512 MiB limit for executables, plus a test.
2. `rust-toolchain.toml` listed `components` while 1.99.1 was installed with
   the minimal profile, so console-recovery failed on `bin/cargo-fmt`. Fixed by
   removing `components` from the file and requesting `rustfmt, clippy` in the
   three jobs that need them; the central workflow was regenerated.
3. The native builder crashed with `FileNotFoundError` while scanning the target
   directory (Cargo removes incremental temporary files between listing and
   `lstat`). The same race was fixed on `main` in `72e61f1`, which also handles
   vanished directories; this PR takes that version and keeps the regression
   test that fails without a fix.
4. Review finding: `cargo` was run from `PATH` but the sysroot `cargo` was
   hashed, so a same-version `cargo` elsewhere on `PATH` could pass unrecorded.
   Fixed by resolving, running and hashing the same executable (rustup shims
   resolved explicitly) and refusing mismatches, with regressions for distinct
   `PATH` and sysroot binaries. The evidence above comes from the run that
   includes this fix.
5. Run `40002053780`, attempt 1, failed with `unrelated_state_changed` in the
   prepared-pilot acceptance. All ten cases had completed; the final check found
   the unrelated sentinel process gone. That sentinel is `sleep 600`, and on a
   slower runner the qualification took longer than 600 s (cases ran about 10%
   slower than in the earlier green run). Attempt 2 of the same run passed. The
   fixed 600 s sentinel is a fragility of the acceptance script, outside this
   PR's scope.
6. Earlier runs of this PR also failed on the runner image (`ci / test`, apt 403
   after `ubuntu-latest` moved to Ubuntu 26.04) and on a stale merge candidate
   after `main` moved (`ci_impact` and the SOU-91 admission); both passed after
   a re-run or a branch update with no change to the code under test.

Earlier run ids: `39959222092`, `39969674462`, `39972746870`; the earlier green
run on `2d45bc3` was `39976331865`.

## What is and is not reproduced

- Reproducible by source identity: the same commit, pins file, lockfile hash and
  toolchain file reproduce the same attestation checks. The Rust release and
  host are enforced for both lanes; the rustc commit hash is enforced for the
  main pin only and recorded for the 1.94.1 lane.
- Not claimed: byte-for-byte identical binaries. Executable hashes are retained
  as observations of this run, not as a promise of future equality.
- Not covered: the digest-pinned Docker builder images (listed in the
  attestation, not verified) and `vps-ci.yml`, which uses `rustup run stable`.
