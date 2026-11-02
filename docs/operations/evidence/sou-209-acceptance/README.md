# SOU-209 development acceptance ledger

Base: accepted `main` `f66a2242` (merge of PR #334). Local macOS checks, observed native Linux behavior
and the TL-owned final merge qualification are kept separate. No full Ready matrix was dispatched by the
author; only the focused manual mode below.

## Local macOS checks (platform-independent logic only)

The installed command, the maintenance gate, preparation and `policy-candidate` are Linux-only
(`policy_candidate` is `cfg(target_os = "linux")`, so its Rust changes are compiled and tested only on
native Linux, never on macOS).

| Check | Result |
| --- | --- |
| `test_pilot_policy_activation.py` (new) | 64 passed, including public `operation`/`main` recovery of a real marker-new/state-old split |
| Full `scripts/tests` vs. the `main` base | same set of pre-existing macOS/environment failures, none new |
| `cargo fmt --all --check`, `ci_components.py --check`, `check_docs.py` | clean |

## Native Linux (installed front door)

_Results pending: no native run has been recorded for this ledger yet._ Required cases:
`useful-read-under-base`, `candidate-inert`, `preview-inert`, `open-installation-refused`,
`live-run-refused`, `tampered-candidate-refused`, `stale-confirmation-refused`,
`killed-staging-keeps-old-generation`, `concurrent-confirmation`, `activation-observed`,
`newly-denied-zero-execution`, `hard-deny-ask-preserved`, `interrupted-publication-recovered`,
`revert-fresh-authority`, `owned-cleanup`.

## Known boundaries

* Activation covers `deny_actions` candidates only; `deny_tools` and destination subsets remain authoring-only.
* Crash points between journal intent, marker and front-door state are covered by unit controls with an
  injection seam, including the public `recover` dispatch. Natively, a SIGKILL is delivered during staging and an OS-enforced
  storage fault (immutable state file, `chattr`) on the front-door state write of a revert reproduces marker-new/state-old
  with a stale temporary; the fault is cleared before the public `recover`.
* A selected, previewed or recovered state is never observed protection.
