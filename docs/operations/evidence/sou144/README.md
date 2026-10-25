# SOU-144 development evidence

Base: accepted main `eb6aa6a531cef67a0eac307404da981a5a600f07`, a descendant of
requested `2af7015e414485b55822f372517969c49a80bcde`.

Status: **implementation prepared; Linux execution not verified**. Keep Draft.
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
