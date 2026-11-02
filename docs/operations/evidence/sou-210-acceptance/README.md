# SOU-210 development acceptance ledger

Base: accepted `main` `f66a2242` (merge of PR #334). This ledger separates local macOS
checks, observed native Linux behavior and the final shared merge qualification, which is
TL-owned. No full Ready matrix was dispatched. The installed qualifier is **new and had not
run natively when this ledger was written**; the native section below is filled in only
from retained workflow runs and keeps failed attempts visible.

## Local macOS checks (platform-independent logic only)

The catalog's POSIX descriptor logic, bounds, identities, confirmations, selection and
`pilot-run.py` refusal paths run on macOS; cgroup delegation, the root probe, protected
hosts and the installed front door are Linux-only and are **not** exercised here.

| Check | Result |
| --- | --- |
| `test_pilot_budget_presets.py` (new) | 50 passed |
| `test_pilot_project_presets.py`, `test_pilot_maintenance.py`, `test_prepared_qualification_coverage.py` (incl. new budget-preset dispatch control) | passed |
| Full `scripts/tests` vs. `origin/main` base | 2357 -> 2408 tests; identical set of 217 pre-existing macOS/environment failures on both sides, none new |
| `cargo test -p agentfw --lib configuration_identity_vector` | passed (Rust pins the identity vector the Python catalog also pins) |
| `cargo clippy --all-targets -- -D warnings`, `cargo fmt --all --check` | clean |
| `python3 scripts/ci_components.py --check`, `scripts/check_docs.py` | in sync / 0 errors |
| Real `agentfw pilot-budget --config` as the strict validator, built locally | accepted the canonical bytes with the exact Python identity; refused pids 15, unaligned memory, wall > 3 600 000 and a root outside `/sys/fs/cgroup`; `--probe` refused on macOS and was reported as `delegation_unverified` |

## What the unit controls cover

Adversarial controls are in `scripts/tests/test_pilot_budget_presets.py`:

* **Substitution / replacement:** symlinked, hard-linked, oversized, group-readable or deleted
  catalog; replaced store directory; shared or linked Agent home; unknown store entries;
  record with a forged config digest, extra field, bool-as-int or unknown baseline; replaced
  delegated root (device, inode or owner) at check time and at run time.
* **Races:** two writers with one record digest (exactly one wins, loser sees `store_busy`
  then `version_stale`); removal and re-creation with identical inputs yields a new digest.
* **Cancellation / crash:** interruption between temporary write and publication keeps the
  previous catalog and removes the temporary; a leftover temporary and a half-staged first
  store never wedge or are adopted.
* **Stale versions:** stale update/remove digest, stale or absent preset confirmation, no-op
  update, project selection made stale by a preset update or removal, `pilot-run.py` refusing
  a changed preset before any daemon, probe or process exists and never retrying unbudgeted.
* **Bounds:** every limit at, below and above the floor/ceiling, both baselines, the memory
  step and non-integer types; bounds are source-pinned against `linux_budget.rs`.
* **Selection:** preset vs. file budget conflict, partial run flags, project run words pass
  name + digest + home and never a budget file; existing unbudgeted and file-budget catalogs
  stay valid.

## Native Linux (installed front door)

Workflow `mcp-real-filesystem.yml`, manual dispatch with `installed_focus: budget-presets` and
`native_preparation_only`. Required cases: `inert-preview`, `two-independent-presets`,
`bounds-refused`, `unverified-delegation-refused`, `stale-update-refused`, `concurrent-update`,
`damaged-store`, `two-budgeted-reads`, `controller-limit-witness`, `update-during-run`,
`stale-profile-zero-start`, `unavailable-delegation-zero-start`, `root-replaced-refused`,
`owned-cleanup`.

_Results pending: no native run has been recorded for this ledger yet._

## Known boundaries

* Presets configure; they never claim enforcement. Activity is witnessed only by the existing
  engine receipts and by the qualifier's direct `memory.max`/`pids.max`/`cpu.max` reads.
* The preview executes the existing strict validator binary (one child process of the supplied
  `agentfw`); it starts no protected process, probe, cgroup or network connection.
* A memory/pids *exhaustion* kill witness is the existing SOU-142 pressure qualification's job and
  is not duplicated here; this slice witnesses the exact configured controller limits on live leaves.
* Owner-loss before descriptor handback remains the documented unsupported boundary.
