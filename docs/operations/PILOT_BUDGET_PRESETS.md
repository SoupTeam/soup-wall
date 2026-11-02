# Named installed Linux resource-budget presets (SOU-210)

`agentfw pilot budget-preset` keeps up to 16 named, nonsecret resource budgets for one
installed Linux pilot (one explicit Agent home). A preset is *configuration*. It does
not start anything, create or change a cgroup, enable a controller, or claim that a
budget is active. Enforcement stays with the accepted launcher and cgroup engine
described in [PREPARED_PILOT_LINUX_BUDGETS.md](PREPARED_PILOT_LINUX_BUDGETS.md); this
interface only replaces hand-edited JSON with a reviewed, versioned catalog and an
exact per-run selection.

Native Ubuntu 24.04 x86-64 only, like the installed front door. On other hosts every
command refuses with `budget_preset_native_linux_required`.

## What a preset contains

| Field | Meaning |
| --- | --- |
| `config` | The existing `sw-mcp/linux-cgroup-budget/1` object: delegation root, `memoryMaxBytes`, `pidsMax`, `cpuQuotaMicros`, `wallMillis`. |
| `config_sha256` | The engine's own configuration identity (compact sorted JSON), checked against the engine on every use. |
| `root` | Separate identity of the delegated directory: device, inode, owner. |
| `baseline` | The accepted ceiling the limits were validated against. |
| `version` | Random, replaced on every update. The *record digest* confirms exact old state. |

Nothing else is stored: no owner token, grant, session, provider material, run id or
"active" flag. The catalog is a private 128 KiB file written by atomic replacement.

## Accepted bounds and baselines

Values are restrictions inside what the accepted engine already permits; the CLI never
tunes, widens or "recommends" anything and all four limits are required.

| Limit | Accepted range | `prepared-pilot-default` ceiling |
| --- | --- | --- |
| `--memory-max-bytes` | 64 MiB to 16 GiB, multiple of 65 536 | 268 435 456 |
| `--pids-max` | 16 to 4 096 | 64 |
| `--cpu-quota-micros` | 1 000 to 1 600 000 | 100 000 |
| `--wall-millis` | 1 000 to 3 600 000 | 30 000 |

`--baseline accepted-bounds` (default) allows the whole accepted range;
`--baseline prepared-pilot-default` additionally refuses anything looser than the
documented prepared-pilot selection. Memory-swap, controllers and CPU period are not
configurable. A source-pinned unit test fails if these bounds or the identity vector
drift from the Rust engine (`linux_budget.rs`).

The delegation root must be an existing, already delegated cgroup directory below
`/sys/fs/cgroup/`, owned by you and mode 0700 (no `..`, links or unusual characters).
The command never creates it and never repairs delegation.

## Commands

```sh
H="--home /absolute/private/agent-home"
agentfw pilot $H budget-preset inspect [--name NAME]
agentfw pilot $H budget-preset create --name small --agentfw /abs/agentfw \
  --root /sys/fs/cgroup/operator-owned/small --memory-max-bytes 268435456 \
  --pids-max 64 --cpu-quota-micros 100000 --wall-millis 30000
# Review new_config_sha256, then repeat with --expected-config-sha256 DIGEST --apply
agentfw pilot $H budget-preset check --name small --agentfw /abs/agentfw [--probe]
agentfw pilot $H budget-preset update --name small ... --expected-version OLD_DIGEST
# Review old_digest/new_config_sha256, repeat with --expected-config-sha256 and --apply
agentfw pilot $H budget-preset remove --name small --expected-version DIGEST [--apply]
```

* `create`, `update` and `remove` preview by default (`mutates: false`).
  Preview runs only the existing strict validator (`agentfw pilot-budget --config`): no
  probe, no cgroup, no provider access, no network, no protected process.
* `--apply` needs the **exact** `new_config_sha256` from the preview. `update` and
  `remove` additionally need the **exact** current record digest (`--expected-version`).
  A stale digest, even for an identical re-created record, refuses (`budget_preset_version_stale`).
* Applying a create or update first runs the engine's read-only delegation probe. A root
  that is not delegated/enabled/empty/owned refuses and publishes nothing. If a running
  instance holds the *unchanged* root (`pilot_budget_root_busy`), changing only the limits
  is allowed and reported as `delegation: busy-root-unchanged`; a different or newly
  selected busy root is refused. The probe never proves that a protected process ran.
* `check` verifies the stored root identity and the engine's identity for the stored
  bytes. `--probe` adds the read-only delegation probe. Output keeps three states apart:
  `configured` (catalog), `probed` (`--probe` observed availability) and
  `witnessed_active` (always `false` here; only a run's own engine receipt can witness
  activity). `resource_budget` is `selected-not-validated` or `available-not-active`.
* `--agentfw` is an absolute, canonical, owned, non-writable-by-others executable used only
  for its validator/probe subcommand.
* `remove` is refused while a named project selects the preset (`budget_preset_in_use`).
  `inspect`/`check` list the projects that select it (`selected_by`).

## Selecting a preset

Selection is explicit, by name **and exact digest**, and never ambient
(`AGENTFW_MCP_LINUX_BUDGET` still cannot select a prepared run's budget).

* **Named project:** `agentfw pilot project create|update ... --budget-preset small` stores
  `{preset, digest}` in the project record. It is mutually exclusive with `--linux-budget`.
  The project's own record digest therefore confirms the selection: updating or removing
  the preset afterwards makes the project refuse (`budget_preset_stale` / `_missing`) until
  you explicitly `project update` it. Existing projects without a budget and with a
  budget *file* keep working unchanged.
* **One run:** `agentfw pilot run --prefix P --budget-preset small --budget-preset-digest DIGEST`
  (both are required; a name alone could pick a newer version).

Both paths end in `pilot-run.py`, the only launcher. It resolves the preset **again at
launch**: the catalog must be valid, the record digest and the delegated root's
device/inode/owner must still match, and the canonical bytes are frozen into the run's
private snapshot. The existing probe, canonical-SHA verification, native-launcher pin and
exclusive root lease then apply unchanged, and the engine's identity must equal the
catalog's. The same resolution is repeated immediately before any host starts.

A missing, changed, corrupt, relocated or unavailable preset **refuses the run**
(`executed: false`). There is no retry without a budget and no fallback to an older
version. Direct `pilot-run.py --linux-budget FILE` keeps its existing behaviour and cannot
be combined with a preset.

## Running instances

A run freezes its configuration when it starts. Updating or removing a preset (or the
project that selected it) cannot change the limits of an already running instance.
Future launches revalidate and refuse if the preset changed. Two presets name two
independent roots; one run stopping does not affect the other.

## Failure modes (finite reasons)

`budget_preset_stale`, `_missing`, `_root_changed`, `_root_invalid`, `_limit_out_of_range`,
`_limit_exceeds_baseline`, `_delegation_busy`, `_delegation_unverified`, `_engine_refused`,
`_confirmation_required`, `_version_stale`, `_unchanged`, `_in_use`, `_store_busy`,
`_store_invalid`, `_store_changed`, `_catalog_missing`, `_private_file_required`. The store
refuses links, hard links, foreign owners or modes, replaced parents/directories,
unknown fields, bad identities, extra entries and corruption. A writer killed before
publication leaves the previous complete catalog; its temporary file is ignored and swept
by the next writer, and a half-created first store is never adopted. Nothing is
repaired automatically.

## Qualification

Local, platform-independent controls: `python3 -B -m unittest scripts.tests.test_pilot_budget_presets`
(storage, bounds, identity vector, confirmation, concurrent writers, cancellation, replaced
root, stale/removed preset, selection, pilot-run refusal before daemon start) and the
workflow-dispatch coverage test. The manual `installed_focus: budget-presets` workflow mode
runs `qualify-budget-presets.py` through the installed front door in a disposable
delegated systemd service: inert preview, two independent presets, refused bounds and
undelegated root, stale/concurrent updates, damaged catalog, two simultaneously budgeted
original-host reads, exact `memory.max`/`pids.max`/`cpu.max`/`memory.swap.max` on each live
leaf, preset update during a run, stale-profile and unavailable-root zero-start refusals,
replaced-root refusal, the unnamed `pilot run --budget-preset` path (exact live limits from the updated preset, and a
stale-digest zero-start refusal) and complete owned cleanup. It does not replace TL-owned final Ready
qualification and admission. Failed or incomplete attempts are retained, never rewritten.
