# SOU-200 development acceptance ledger

Base: accepted `b385e7506ab26896637f348e3180e52d1fc6d423`, later merged with
current `main`. This ledger separates local macOS checks, observed native Linux
behavior and final shared merge qualification. Final Ready/security/current-main
admission and merge are TL-owned; no full Ready matrix was dispatched.

## Local macOS checks

The maintenance module and its launch gate are Linux-only. These checks run the
platform-independent Python logic and do not compile or execute the Rust gate.

| Check | Result |
| --- | --- |
| `test_pilot_maintenance.py` | 17 passed |
| `test_pilot_maintenance_qualification.py` | 5 passed |
| `test_prepared_qualification_coverage.py` (incl. new maintenance dispatch control) | 13 passed |
| `cargo check -p agentfw --all-targets`, `cargo fmt --all --check` | passed |
| Generated shared workflow consistency (`ci_components.py --check`) | in sync |
| Full `scripts/tests` suite compared with base | no new failures (116 pre-existing macOS/environment failures on both) |

## Observed native Linux run

Workflow `mcp-real-filesystem.yml`, manual dispatch with `maintenance_only` and
`native_preparation_only`, run `41318756808`, exact source
`a7e1592ff0729bb8421814522acad4f525c3af16`, kernel `7.0.0-1014-aws`. The installed
component was built from that commit (74 files). The Linux job succeeded:
17 maintenance tests, 27 existing run-operation tests and 5 qualification-shape
tests passed, then the installed qualifier passed all 12 required cases against the
original host with owned synthetic inputs and a scripted loopback provider.

| Case | Observed |
| --- | --- |
| `readonly-preview` | no selected-program start, no network connect, home unchanged |
| `useful-before-enter` | useful run completed before maintenance |
| `existing-run-draining` | after `enter`, status `draining` with 1 active run |
| `entered-new-run-refused` | new launch refused; 0 protected process starts, 0 provider connects (syscall-traced) |
| `sibling-independent` | sibling installation ran useful work (2 results), all processes stopped |
| `stale-leave-refused` | old confirmation could not clear maintenance |
| `fresh-leave` | fresh confirmation left maintenance |
| `existing-useful-after-enter` | the run started before `enter` completed with 2 useful results and confirmed cleanup |
| `new-useful-after-leave` | a new run after `leave` completed with 2 useful results |
| `same-bytes-marker-replaced` | replaced marker refused launch; 0 starts, 0 connects |
| `partial-transition-refused` | half-written transition refused launch; 0 starts, 0 connects |
| `dead-owner-uncertain` | claimed run whose owner died reported `uncertain`, launch refused; 0 starts, 0 connects |

Report-level facts: `source_unchanged` true, `project_unchanged` true, receiver
requests 0. Retained report SHA-256
`73a934e6986959663c22b2ad0d54cb4caee6f84fdd9ee957e7f27b22ae9a8b63`, log SHA-256
`9beeeab1fe63931dc82bb071941ce243b65ca080ec4d2fe5b88e5b1a450617e2`. Raw syscall
traces stay private; the retained artifact holds only the bounded report and log.
Later commits changing only this ledger and documentation are not re-qualified.

## Earlier failed attempts (kept visible)

- Run `41314192316` (`01a4c772`): the focused step wrapped the qualifier in an
  outer network namespace; `ip link set lo up` was not permitted. The Rust build
  had succeeded. Workflow-only defect.
- Run `41315549767` (`f391a236`) and `41317225201` (`cff8e49712`): unit tests passed;
  the first installed command was refused. A stage-localized finite `detail` was
  added to the refusal; it showed `untrusted_parent`, caused by selecting an
  interpreter below the world-writable hosted toolcache. The qualifier now uses the
  root-owned `/usr/bin/python3.12`. The strict binding refusal itself was correct.

## Review follow-up (not part of the recorded run)

The run above (source `a7e1592f`) predates review of `584aa323`, which found two gaps:
named project presets (`project run`) launched without the maintenance context, and a
marker bound to its first selection reported `eligible` while admission refused after
an ordinary selection change. They are fixed in later commits: presets carry the same
installation context, and the marker now gates the installation scope while a changed
selection is reported and adopted only by a freshly confirmed `enter`/`leave`. The new
`named-project-refused` case and the Python controls for both fixes are source-bound
to those later commits; the 12 recorded cases remain evidence for `a7e1592f` only until
a new focused native run records the 13-case matrix for the final head.

## Not claimed

Only the owned scripted-provider flows above were observed. Live model
effectiveness, real credentials, other platforms, concurrent heavy load and
configured-but-unexercised paths are not claimed as observed protection.
