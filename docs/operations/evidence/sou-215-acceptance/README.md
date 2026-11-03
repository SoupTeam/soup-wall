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

Workflow `mcp-real-filesystem.yml`, manual dispatch with `installed_focus: pilot-scope` and `native_preparation_only`, on a
native Ubuntu 24.04 x86_64 runner outside the checkout with the pinned original servers, genuine Claude Code 2.1.251 and the
owned scripted loopback provider (no model account or paid call).

### Attempt 1 (kept)

Run `41629304663`, source `184e3a10`: the scope driver (16 of 16: the 8 standard installed cases plus the 8 scope cases) and the
existing `qualify-installed-pilot.py --run` (12 of 12) passed. The task also requires the explicit single-use Ask control, which
the installed-pilot report does not contain (its cases cover reads, refused untrusted input, parallel cancellation, collector
recovery, daemon loss and bad-input controls). That gap was closed by adding the existing first-use demo to the same focus,
not by changing any case or limit.

### Attempt 2 (passed)

Run `41631180107`, exact source `e3d629869c0cb048c778005470f62a3fe1485c5a`, clean tree:

| Command | Result | Report SHA-256 |
| --- | --- | --- |
| `qualify-installed-front-door.py --run --pilot-scope-only` | passed: standard `component-install`, `preview-zero-effect`, `prepare-and-reuse`, `existing-selection-status`, `status-configured`, `useful`, `status-after-run`, `cancel` and all 8 scope cases | `e05505b8a5fecfabfeaf017cfc8566d306503c695cf47390784e5ad0a912fa3f` |
| `qualify-installed-pilot.py --run` on the scope-selected generation | passed (12 cases: exact installed inputs, sandbox positive, witness calibration, read and history, inspect and diff, untrusted-input refusal, independent conversation, parallel cancellation, collector recovery, daemon fresh conversation, bad-input controls, final cleanup) | `a567b667d2e30f604fecf4166f47397fc93b4d4f30c63eba88466ef13cd0d876` |
| `pilot-demo.py --run` on the same generation | passed (12 cases: plan, occupied-port, stale-source, changed-selection, provider-unavailable, useful-refusal, **ask**, default, cancel, **daemon-loss**, host-crash, timeout) | `7df839b6cbea2542709636843b4aaf25cf430d5b4df9963c44c8317f15508180` |

Scope cases, all `passed`: `scope-selected-through-preview-and-prepare` (recorded descriptor identity, preview selected with no
refusals and no effects), `excluded-option-preview`, `standard-cases-ran-under-scope` (live status during the useful and cancel
runs reported `scope.state: conforming`, `scope.mode: enforce` and `unqualified`; 2 useful and 3 refused results),
`excluded-capability-refused` (`scope_excludes_capability`, 0 selected-program starts, 0 network connections, prefix and recorded
state byte-identical), `tampered-scope-refused` (status `document-changed`; run refused with `scope_document_changed` and zero
starts; state restored), `unselected-claims-nothing`, `status-never-claims-more`, `owned-cleanup`. Log SHA-256 values:
scope driver `d2fd6b990198c6fc124a287cac9df39928fd87fd6d59350d0849fbadea879f2d`, installed pilot
`cef286c82e3899c5d09b587a9891851a0f4fd8c563255f69ee0207333b1abaad`, demo
`cc19ea1ce7a4c679457fe739034a2c5977fef8bd002787e12871769a82276def` (artifact `sou215-pilot-scope-41631180107-1`).
Later commits that change only this ledger are not re-qualified.

## Known boundaries

* The scope is opt-in (`--scope linux-v1`); without it behavior is unchanged and nothing is claimed.
* Named project presets report `scope_conformance` but do not enforce a scope; direct preparation scripts remain outside it.
* The scope selects and describes; qualification evidence is separate and bound to exact source. No live-model effectiveness
  or universal-firewall claim is made.
