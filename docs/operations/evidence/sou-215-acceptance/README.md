# SOU-215 development acceptance ledger

Base: accepted `main` `9a3c5b38`. Local macOS checks, observed native Linux behavior and the maintainer-owned final
merge qualification are kept separate. Only the focused manual mode below is dispatched by the author. Missing external
acceptance remains NOT_READY; nothing here is a release approval.

## Local macOS checks (platform-independent logic only)

The installed command, preparation and live status are Linux-only. These run the descriptor, conformance and front-door
refusal logic.

| Check | Result |
| --- | --- |
| `test_pilot_scope.py` (new) | 34 passed: every bound source/constant drift, descriptor shape tampering, operation partition, exclusions, conformance deviations, scope gate, status states, parser, coordinated forwarding |
| `test_pilot_project_presets.py`, `test_pilot_front_door.py`, `test_pilot_front_door_component.py`, `test_prepared_qualification_coverage.py` | no new failures (the 4 `Status` live-run controls fail on macOS on `main` as well) |
| Full `scripts/tests` vs. `main` | 2629 -> 2663 tests; no new failures (224 vs 225 pre-existing macOS/environment failures) |
| `pilot_scope.py --check`, `check_docs.py`, `ci_components.py --check`, `cargo fmt --all --check` | pass |

## Native Linux (installed front door)

_Results pending: no native run has been recorded for this ledger yet._ Required cases of the installed driver's
`--pilot-scope-only` mode: the standard `component-install`, `preview-zero-effect`, `prepare-and-reuse`,
`existing-selection-status`, `status-configured`, `useful` (useful filesystem read and Git history, refused
write/reset/send with independent witnesses and live `observed-live` status with `scope.mode: enforce`), `status-after-run`
and `cancel` cases run on the scope-selected prefix, plus `scope-selected-through-preview-and-prepare`, `excluded-option-preview`,
`standard-cases-ran-under-scope`, `excluded-capability-refused`, `tampered-scope-refused`, `unselected-claims-nothing`,
`status-never-claims-more` and `owned-cleanup`. The existing `qualify-installed-pilot.py --run` command and the first-use demo
`pilot-demo.py --run` then run on the generation prepared by the scope-selected prefix for daemon loss, refused effects and
cleanup (installed pilot) and the explicit single-use Ask control, timeout and daemon-loss recovery (demo).

## Known boundaries

* The scope is opt-in (`--scope linux-v1`); without it behavior is unchanged and nothing is claimed.
* Named project presets report `scope_conformance` but do not enforce a scope; direct preparation scripts remain outside it.
* The scope selects and describes; qualification evidence is separate and bound to exact source. No live-model effectiveness
  or universal-firewall claim is made.
