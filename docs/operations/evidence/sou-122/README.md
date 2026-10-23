# SOU-122 evidence: compiler and interpreter inputs of the native lane

This directory retains the evidence of one green run of the internal Linux pilot
candidate on the final commit of PR #231.

- Workflow: `mcp-real-filesystem.yml`, job `native-ubuntu-2404`
- Run id: `39976331865`
- Source commit: `2d45bc3c9981f0cdb44d52bf89368287375f49a2`
  (tree `f6706709177f584d33737ccc148290954ad37385`, clean checkout)

## Scope

This is **input attestation**. It records which compiler and interpreter
executables were selected for the run and that they match the pins in
`profiles/toolchain/linux-pilot-toolchain.json`. It does not claim
byte-identical binaries and it is not a certification of the whole product.
Pilot readiness stays "not certified" in the qualification report.

The native lane stays on Rust 1.94.1. The repository default
(`rust-toolchain.toml`) is 1.99.1; the native job overrides it with
`RUSTUP_TOOLCHAIN=1.94.1`, and the attestation records both values.

## Selected identities (from this run)

| Input | Identity |
| --- | --- |
| rustc 1.94.1 | commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`, host `x86_64-unknown-linux-gnu`, executable sha256 `ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d` |
| cargo 1.94.1 | executable sha256 `b7561ebe947acf816451536f19871ea4810f6be3f82fd252feab6ca7be8396f5` |
| Python (classifier) | CPython 3.12.15, executable sha256 `53dab24bf9e0e9c490088a53d71770b6f027b057678b313648e75f7fc87a675e` |
| `Cargo.lock` | sha256 `b603e17ee717ea60c80db5a0eb0b2b0837659d9cea9e917654900610ae42798e` (443 packages, tracked) |
| `rust-toolchain.toml` | sha256 `5a7b7b624394e3ece3fb4c9e0391aa400eeebf7a7a1efd18e74c5b68b71cd65e` |

The 1.94.1 commit hash above is now pinned (`commit_prefix` `e408947bf`) in the
pins file and enforced by `--lane native`. Before this change the lane
recorded the hash but did not enforce it.

Binaries built in the same run (`selected-hashes.txt`):

| Artifact | sha256 |
| --- | --- |
| `agentfw` | `af73df828a8ba1e8cbdf0016c2bc58de1bde2386f27abb27648fef848be6c564` |
| `git_launcher` | `509f51a56bd1861c337d662e4b89dd56cf98fa6e6ce0701413f16c71f9d65da9` |
| `sandbox_tests` | `15453352962dd0ba64ec1942a847f1dfd88a911d04f61a3cf554a3575ad85da4` |
| source-built `git` | `e23c5a17c6673d5ea46e59730ec38889313d97b43d9d7ce90ada37ddaab707ba` |
| source-built `bwrap` | `4d2044d04519dad2d47068676c95d0e9348fb3ad73db7497e18810a0e6e3134e` |
| `node.tar.xz` (input archive) | `9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37` |

## Retained files

| File | What it shows |
| --- | --- |
| `native-attestation.json` | Output of `scripts/verify-pilot-toolchain.py --lane native`: status `verified`, every check, executable hashes. |
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
  worked (`verified_reuse_seconds` 0.96 versus a clean build of 145.274 s).

## Failed attempts before the green run

Each failure was fixed in this PR and none was masked or retried until green:

1. The attestation step hashed `cargo` under an 8 MiB limit, written for small
   files. Fixed with a separate 512 MiB limit for executables, plus a test.
2. `rust-toolchain.toml` listed `components` while the 1.99.1 toolchain was
   installed with the minimal profile, so console-recovery failed on
   `bin/cargo-fmt`. Fixed by removing `components` from the file and
   requesting `rustfmt, clippy` in the three jobs that need them; the central
   workflow was regenerated.
3. The native builder crashed with `FileNotFoundError` while scanning the
   target directory: Cargo removes incremental temporary files between the
   listing and the `lstat`. Fixed in `scripts/build-native-pilot-inputs.py`
   (a vanished file no longer counts), with a regression test that fails
   without the fix. This is a SOU-119 builder defect, kept in this PR as the
   reviewers asked.

Earlier run ids on this PR: `39959222092`, `39969674462`, `39972746870`.
A separate `ci / test` failure (apt 403 after `ubuntu-latest` moved to
Ubuntu 26.04) came from the runner image, not from this change, and passed on
re-run.

## What is and is not reproduced

- Reproducible by source identity: the same commit, pins file, lockfile hash
  and toolchain file reproduce the same attestation checks. The Rust release,
  rustc commit hash and host are enforced for both lanes.
- Not claimed: byte-for-byte identical binaries. Executable hashes are
  retained as observations of this run, not as a promise of future equality.
- Not covered: the digest-pinned Docker builder images (listed in the
  attestation, not verified) and `vps-ci.yml`, which uses `rustup run stable`.
