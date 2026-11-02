# SOU-210 development acceptance ledger

Base: accepted `main` `f66a2242` (merge of PR #334). This ledger separates local macOS
checks, observed native Linux behavior and the final shared merge qualification, which is
TL-owned. No full Ready matrix was dispatched. Only the focused manual mode below was run;
the native section is filled in from retained workflow runs and keeps failed attempts visible.

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

### Attempt 1 (failed, kept)

Run `41413543382`, source `0b73b507`. The unit step failed before the installed qualifier
started: `PreparedRunIntegration` lacked the provider fixture that native Linux requires,
so `pilot-run.py` stopped at `provider_unavailable` instead of reaching the preset check.
Test-only defect (the product refusal was unchanged); fixed in `91176ee5`.

### Attempt 2 (passed)

Run `41414791512` (`native-ubuntu-2404` success), exact source
`91176ee5c77ea0fa732d6a5a99889b88a2088683`, clean tree, installed component, genuine pinned
hosts, scripted loopback provider and owned synthetic projects, inside a disposable
`Delegate=cpu memory pids` systemd service. The 50 unit tests, `cargo fmt --all --check`
and all 14 installed cases passed; the service was confirmed removed.

| Case | Observed |
| --- | --- |
| `inert-preview` | strace: 0 selected-program starts, 0 network connects; only the wrapper plus its one validator child; home and roots unchanged |
| `two-independent-presets` | two presets on two delegated roots; distinct root and config identities; both roots still empty |
| `bounds-refused` | pids 15, memory 4096, wall 3 600 001 refused as out of range; pids 129 refused under `prepared-pilot-default`; nothing stored |
| `unverified-delegation-refused` | undelegated root refused (`delegation_unverified`); nothing stored |
| `stale-update-refused` | stale digest refused; `check` reported `selected-not-validated`, `--probe` `available-not-active`, `witnessed_active` false |
| `concurrent-update` | two contenders on one digest: exactly one succeeded |
| `damaged-store` | damaged catalog refused; restored bytes accepted |
| `two-budgeted-reads` | both budgeted original-host runs completed useful, independent reads |
| `controller-limit-witness` | live leaves under each root (2 each) read back the exact `memory.max`, `pids.max`, `cpu.max`, `memory.swap.max`; each run's frozen snapshot matched its preset identity |
| `update-during-run` | update of a busy unchanged root accepted (`busy-root-unchanged`); running leaves kept their original `pids.max`; frozen snapshots unchanged; both runs kept running |
| `stale-profile-zero-start` | project selection made stale by the update refused; 0 selected starts, 0 connects |
| `unavailable-delegation-zero-start` | removed delegated root refused at check and run; 0 selected starts, 0 connects |
| `root-replaced-refused` | recreated root (new inode) refused as `root_changed` |
| `owned-cleanup` | one run stopped, the sibling continued and finished; all processes stopped, roots empty, sources unchanged, receiver effects 0, no provider canary in catalog or output |

Retained report SHA-256 `7b0483b919c1de03591b539199cb4c9e6786f5e872aee62bafd689ca40bd49fa`,
log SHA-256 `dfc77271441abc0f9f70680c61f9821ed0657d8eca45dfaa4958ee7f1829b06c`
(artifact `sou210-installed-budget-presets-41414791512-1`). Raw syscall traces stay private.
Later commits that change only this ledger are not re-qualified.

## Known boundaries

* Presets configure; they never claim enforcement. Activity is witnessed only by the existing
  engine receipts and by the qualifier's direct `memory.max`/`pids.max`/`cpu.max` reads.
* The preview executes the existing strict validator binary (one child process of the supplied
  `agentfw`); it starts no protected process, probe, cgroup or network connection.
* A memory/pids *exhaustion* kill witness is the existing SOU-142 pressure qualification's job and
  is not duplicated here; this slice witnesses the exact configured controller limits on live leaves.
* Owner-loss before descriptor handback remains the documented unsupported boundary.
