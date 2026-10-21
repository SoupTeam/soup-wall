# SOU-108: shared CI compatibility diagnosis

Baseline: accepted `main` at `7af550291782cf3c11cffc8d7b30bb071f4bf5e9`.
The original failures were recorded in [PR #214's Ready run](https://github.com/SoupTeam/soup-wall/actions/runs/39603080085).
The Rust failure repeated in `test`, `all-features` and policy composition; these are
three reports of the same test, not three defects.

## Python evaluation

On Ubuntu/WSL with Python 3.14.4, run:

```sh
python3 eval/sou13/run_tests.py --expect-skipped 150
```

On the baseline this first failed while building the CP1 synthetic shell cases:
`sou13.sandbox.EvidenceError: unreliable execution: sandbox_violation
['import:collections'] []`. Python 3.14's `shlex.shlex.__init__` defers
`from collections import deque` until tokenization. The frozen CP1 import guard
sees that import inside the fixture and refuses it. This is a standard-library
version mismatch, not a new classifier label or admission decision.

`eval/sou13/sou13/sandbox.py` and `fixtures.py` are covered by the CP1 owner freeze.
Changing the guard or tokenizer would invalidate the source-identity check. The
reviewed evaluation contract is Python 3.12, so the existing classifier CI job
now selects that version explicitly. On Python 3.14+, `run_tests.py` exits 2
with the incompatibility before any suite runs; it does not turn the failures
into skips. Direct fixture imports of `collections` and forbidden modules
remain blocked, while shell tokenization and derived action labels run under
the supported interpreter. Python 3.14 support would require a separately
approved CP1 re-freeze.

## Linux executable fixture

On Ubuntu/WSL with Rust 1.99.1, run on the baseline:

```sh
stat -Lc '%n links=%h owner=%u mode=%a' /usr/bin/env
cargo test --locked -p agentfw --lib wrapped_argument_limit_is_checked_before_writing
```

Here `/usr/bin/env` resolves to `/usr/lib/cargo/bin/coreutils/env`, a
115-link coreutils binary. The test previously passed this host executable
to `wrapped`, which rejected it with `unsafe or unavailable executable` at
`crates/agentfw/src/mcp/connection.rs:1111`. The production `nlink == 1`,
owner, mode and path checks are correct. The fixture now copies the executable
to an owned, private, single-link temporary file, checks that it really runs,
then exercises the exact 256-argument positive and 257-argument rejection.
The rejection occurs in `wrapped` before any server process or stdin write;
the config bytes and ownership record remain unchanged. A hard-linked copy
is separately refused by the same production validator.

## Recheck

```sh
python3.12 eval/sou13/run_tests.py --expect-skipped 150
python3.12 eval/sou13/scripts_cp2/check_release_privacy.py --root eval/sou13
python3.12 eval/sou35/run_tests.py
cargo test --locked -p agentfw --lib
cargo test --locked --all-features -p agentfw --lib
cargo fmt --all -- --check
```

The public SOU-13 suite intentionally retains 150 named private-artifact skips;
its ledger must report zero failures and errors. No private dataset is needed
for these checks.
