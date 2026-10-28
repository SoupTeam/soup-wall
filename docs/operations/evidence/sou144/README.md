# SOU-144 current-source qualification

Accepted base: `8ead460e7460a8168459e0f02ea25c1eb2d8f7d4`.
Qualified implementation: `e296ad2d5fcca35da481fb0a3d9c18c4c357f1bf`,
tree `b9f454c84c07f72a572b90211f5c9969b7301eac`. Original authorship and
all earlier incomplete outcomes below remain retained.

[Native Linux run 40750046744](https://github.com/SoupTeam/soup-wall/actions/runs/40750046744)
passed **17 inspector tests, 71 production-validator regressions, one selected-validator
regression, eight Python witness controls and all six independent CLI/syscall cases**.
Artifact `12844146202` has archive SHA-256
`2470afffed7937433a23beeb765b539648ac4fc2d1ae67db5eb30ea898e29d2d`.
The parent independently checked the bounded archive, source/tree, complete case
inventory, zero network/child/mutation syscalls, unchanged synthetic workspaces,
absent helper traps and no launch/protection claims. It executed no artifact code.

- [Original finite CLI report](native-inspection-e296ad2d.json).
- [Independent verification and retained attempt ledger](native-verification-e296ad2d.json).
- Agent binary SHA-256: `322a242c1df5662668005f91fbd25138eab4be4d97308692ec68fca9b6611b01`.
- Local macOS workspace: **1913 passed, zero failed, 13 existing ignored**;
  strict Agent all-target Clippy and workspace formatting passed.

All target execution used read-only source, private writable scratch, an isolated
PID/network namespace and a nonroot process with all capabilities dropped. Existing
mmap regressions also used a private in-memory `/dev/shm`; the host filesystem was
not made writable. Two runner setup failures preceded target execution. The next
attempt passed all 17 inspector tests, but nine existing mmap regressions could
not create their fixtures in that namespace. This failed attempt remains retained
as artifact `12841784604`; providing the private tmpfs fixed that environment defect.
No test, production limit, expected verdict or timeout was weakened.

The current accepted `--git-profile-format` interface and response field remain;
the optional short kind cannot be combined with an explicit format. All six
reviewed formats reuse their current production validators. Extended-profile
layout checks are conditional on runtime object/view proof and never grant launch
authority. Conditional layout compatibility keeps the accepted preparation caller
usable. Tracked links are checked by the selected production graph validator,
without following their targets. Default v1 remains narrow.

SOU-144 author-side qualification is complete; shared Ready CI, admission and
integration remain TL-owned. Inspection does not attest sandbox enforcement,
live-model efficacy, WSL/storage support or permission for release.

## Historical development checkpoints (not current blockers)


Base: accepted main `eb6aa6a531cef67a0eac307404da981a5a600f07`, a descendant of
requested `2af7015e414485b55822f372517969c49a80bcde`.

Historical status at the original delivery: **Linux execution not verified**.
No product, sandbox-enforcement, live-model or release acceptance is claimed.

## Local checks, 2026-10-25

Windows / Python 3.13.12:

- `python -B -m unittest discover -s scripts/tests -p test_pilot_workspace_witness.py -v`:
  **7/7 passed**. These validate the syscall-trace parser and independent
  snapshot controls, not execution of the Rust inspector. TEMP/TMP selected
  an owned writable directory under target. A subsequent run without that
  environment failed one test with sandbox temporary-directory PermissionError;
  the corrected-environment rerun passed 7/7. No test was disabled.
- `python -B scripts/check_pilot_workspaces.py --agentfw target/debug/agentfw --expected-commit eb6aa6a531cef67a0eac307404da981a5a600f07 --output target/sou144-windows-attempt-1`:
  **exit 1 / incomplete / native_linux_required**, zero runtime cases executed.
  [Retained first attempt](windows-attempt-1.json).

## Precise remaining blocker

The local machine has no available Cargo/Rust compiler and no selected usable
Linux host. No toolchain, WSL or host package was installed. Rust compilation,
formatting, the 14 Linux inspector tests, production-validator regressions and
six independent CLI/syscall witnesses remain unexecuted locally. Seven passing
Python controls do not substitute for these checks.

The next operator can run the focused commands in the
[inspection guide](../../PILOT_WORKSPACE_INSPECTION.md#focused-verification)
against the exact Draft PR commit. Retain build identity and all failed/incomplete
attempts, then append the resulting exact-source evidence. Final shared CI,
admission and main integration remain TL-owned. No shared CI configuration was
changed or heavyweight matrix dispatched by this increment.

## Draft formatting follow-up

Implementation source: `59b6a24bc9f1a0495cabf21d9158a383082c4d51`.
The existing [Draft CI run](https://github.com/SoupTeam/soup-wall/actions/runs/40207696526)
parsed the Rust source but failed the formatting check. Its 30 rustfmt hunks
were applied to the three affected Rust files, without installing local tools
or changing shared CI. This is formatting feedback, not a compilation/test pass.
Local documentation check: 277 Markdown files / 990 links / zero errors.
The subsequent Draft result must be checked separately; Linux compilation and
runtime witness blockers remain until explicitly executed.

## Verified Draft result and source-binding control

The existing [Draft CI rerun](https://github.com/SoupTeam/soup-wall/actions/runs/40207887190)
passed at `9f257af` after the formatting correction. Draft checks include rustfmt;
they do not compile/run this inspector or establish Ready admission.

A subsequent focused driver control refuses dirty tracked source before claiming
a commit, and the runtime report includes source tree and Linux kernel/architecture.
Python controls now pass **8/8** with owned TEMP/TMP. Documentation remains
277 files / 990 links / zero errors. Linux compilation, 14 Rust inspector tests,
production-validator regressions and six syscall witnesses remain outstanding.
