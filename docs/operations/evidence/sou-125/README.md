# SOU-125 evidence

## Current native qualification

`native-linux.json` retains the bounded report from native Ubuntu 24.04 job
`120504983982`, run `39975116499`, on exact clean source `d5d7813`. All eleven
prepared-run lifecycle controls and four stop scenarios passed. It includes
actual concurrent original hosts/servers, selected-only process cleanup, useful
peer progress, no future dispatch, interrupted stop and honest partial failures.
Raw traces and credentials are excluded; this is scripted-provider qualification,
not live-model effectiveness. Historical local-only reports below retain their
original source attribution.


## Cleanup confirmation and terminal disposition follow-up

`cleanup_review.json` records implementation `219acb2` and the exact source hashes
after adding exact-owner namespace cleanup obligations at `/native/pilot-cleanup/v1`,
authenticated terminal disposition confirmation in `pilot-run.py`, and prepared stop
witness qualification in `scripts/prepared_stop_witness.py`.
The complete Rust workspace passes with 1671 passed, 0 failed and 13 ignored;
strict clippy, formatting and whitespace checks pass. Both unit suites in Python
pass: `test_prepared_stop_witness.py` (10/10) and `test_pilot_run.py` (16/16).
Full Python test suite: 1100 passed, 0 regressions; 8 known Linux `/proc` and process-group
controls remain unsupported on macOS. These remain macOS observations, not Linux qualification.

Implementation checkpoint: `22c3dbe6059afe1e4a7a4669d3816b245459364e`, based
independently on accepted main `cdd9d36c65a592455e4f421268758adb6db744b8`.
`development.json` records its tree and exact changed-file SHA-256 values.
Evidence-only follow-ups are not relabelled as tested implementation changes.

## Concurrency review follow-up

`review.json` records implementation `fa6619b` and the exact source hashes after
fixing stop receipt contention and the inspection terminal-lock boundary.
The complete Rust workspace passes with 1667 passed, 0 failed and 13 ignored;
strict clippy, formatting and whitespace checks pass. Both regression tests
were also checked with the individual defect reintroduced: each failed as
required. The initial sandboxed run could not bind local fixture ports (26
failures); the same source passed with owned loopback fixture access. That
failed log's digest is retained. Python source is unchanged from the initial
checkpoint below. These remain macOS observations, not Linux qualification.

## Verified locally

- Canonical temporary root and an isolated branch Cargo target:
  `cargo test --offline --workspace --locked -- --test-threads=1`:
  1665 passed, 0 failed, 13 ignored.
- Strict workspace/all-target clippy, Cargo format and diff whitespace checks pass.
- Python 3.11 supported suite: 1095 run, 1033 passed, 62 skipped, no failures.
  The three explicitly unsupported checks use Linux `/proc`; they remain
  unchanged in source and were not represented as passing. The other 59 skips
  are the existing platform/optional controls.
- Five native-router stop regressions pass: active and unenrolled grant
  revocation, replay refusal, wrong/foreign identity, malformed requests,
  pending and approved proposal cleanup, unrelated-run usefulness, and the
  existing hard Deny on reflected untrusted content after fresh reconnect.
- Receipt/configuration regressions pin exact run bytes, authentication,
  monotonic transitions, linked-file refusal and refusal to send credentials
  to a changed daemon destination. The Python lifecycle file has thirteen
  passing tests, including retained interrupted-stop state.

## Failed development attempts retained

The first unfiltered Python run used the host Python 3.14 without `urllib3`.
It ran 1094 tests and reported one failure, four errors and 59 skips: one missing
dependency and unsupported Linux process-group controls on macOS. A separate
Python 3.11 virtualenv supplied the dependency; a local runner explicitly marked
the three unchanged `/proc` controls unsupported. No Linux expectation was
changed to make a macOS result pass.

An early parallel/mixed-cache Rust run reported an unchanged
`profile_lifecycle::install_works_with_nonexistent_relative_home` failure; that
case passed in isolation. Another development compile could not find the new
public stop module while two checkouts shared one target. Those outputs remain
diagnostics, not final evidence. All workspace artifacts were rebuilt in a
separate target and the final complete run was serialized and green.

The hard-Deny fixture was also corrected during development: its destructive
call initially omitted the previously read untrusted content. The final test
reflects that content, checks shared-host taint before and after stop, and pins
the existing `deny-tainted-destructive` rule; the detector/policy was not changed.

## Historical platform limitation

The initial local macOS arm64 probe refused native Linux execution with
`native_linux_x86_64_required`. That diagnostic remains valid for the local host.
The current native Ubuntu evidence above closes this platform qualification gap
for its exact source; it does not relabel earlier local-only reports.
