# Explicit budgets for prepared pilot runs (SOU-142)

The prepared entry supports an explicit operator selection:

```sh
python3 -B scripts/pilot-run.py --selection /absolute/preparation/generations/ID/selection.json \
  --expected-commit FULL_COMMIT --linux-budget /absolute/private/linux-budget.json
# Add --run only after reviewing the plan.
```

The default remains read-only: it reads bounded owned input bytes and reports
`selected-not-validated`; it does not execute a selected binary, create run state,
probe a controller, or claim enforcement. Without the flag it reports `unbudgeted`.
Ambient `AGENTFW_MCP_LINUX_BUDGET` cannot select a prepared run's authority.

Use the existing `sw-mcp/linux-cgroup-budget/1` JSON schema and accepted limits:

```json
{"format":"sw-mcp/linux-cgroup-budget/1","delegationRoot":"/sys/fs/cgroup/operator-owned/pilot","memoryMaxBytes":268435456,"pidsMax":64,"cpuQuotaMicros":100000,"wallMillis":30000}
```

The file must be a bounded regular owned file, without symlinks or shared write.
The selected subtree must already exist, be owned by the operator, mode 0700,
contain no processes or child cgroups, and have the accepted cpu/memory/pids
controllers delegated and enabled. The normal launch never enables controllers,
adopts an occupied subtree, changes global settings or repairs delegation. Do not
select the cgroup containing your shell, unrelated jobs, or a running pilot.
Unavailable environments refuse the requested budget; they do not retry without it.
The example describes a selection, not a portable delegation setup command.

## Runtime contract

Before daemon startup the prepared entry freezes input bytes in its private run
and calls `agentfw pilot-budget --config FILE --probe`. This uses the existing
strict parser and the engine's read-only delegation/capability checks; an availability probe never proves
that a protected process ran. The native launcher verifies the preflight's
canonical SHA-256, freezes another private run snapshot, pins the root identity,
and holds an exclusive cooperating-run lease until terminal cleanup. An occupied
root or changed configuration refuses before the host/original servers execute.

The native `pilot-launch --linux-budget FILE` contract is reusable independently.
An optional `--linux-budget-sha256 DIGEST` binds a previously inspected identity.
Both original-server commands receive the frozen `AGENTFW_MCP_LINUX_BUDGET`, a
private host-session binding, `--pilot-budget-binding` and its frozen digest. CLI and environment
must agree: losing environment variables cannot silently downgrade that command
to an unbudgeted collector. Session, server, paths, root and config identity are
checked before preparing a protected child. The verified configuration is moved into
admission once. Runtime preparation never rereads the mutable selection file or
environment to choose limits; the existing engine compares the pinned root identity
before creating a leaf. The read-only preflight cannot orphan a probe cgroup if
its process is killed.

The SOU-79 engine enforces each original server's aggregate process
**tree** in its own leaf. Filesystem and Git are independent siblings. This is
not a claim that the daemon, Claude host, or their combined CPU/memory is inside
one shared budget. The operator's delegated substrate remains intact.

Leaf creation now occurs in the existing outside crash owner, after its
authenticated collector connection and pinned parent identity exist. The owner
retains cleanup authority while the collector adopts the exact pinned leaf and
control descriptors over a private socket. Sandbox startup waits for that
adoption acknowledgement. The original monotonic budget epoch includes this
handoff; no limits or accounting rules are reset or widened.

## Status and cleanup

`resource_budget` binds the config SHA-256 and bounded per-child observations.
`configured-not-observed` is not active. `active-at-attachment` requires the real
engine's verified attachment; a vanished leaf without a final receipt is
`unresolved`. Only a final engine receipt confirming cleanup can contribute to
`closed-enforced`. Budget refusal, incomplete records or unconfirmed cleanup
cannot yield a successful terminal launcher exit. Public observations contain
finite reason codes and reviewed numeric counters; no raw PID diagnostics,
child capabilities, environment dumps or delegation paths are exported.

Records are bounded to 64 attempts, private, and updated through their pinned
owned inode. Record replacement is preserved and rejected. SIGKILL can leave an
incomplete record; it is never converted into success just because a process is
gone. Existing namespace ownership, revocation, Ask decisions and physical cleanup
remain responsible for each child. No broad process or cgroup sweep is added.

Inspect retained run state without launching anything:

```sh
agentfw pilot-budget --binding /absolute/run/.agentfw/pilot-budgets/HOST/linux-budget-binding.json
```

The prepared wrapper collects this bounded summary before removing ordinary
private state, including failure paths. Existing authenticated stop receipts keep
their existing retention and recovery behavior.

## Qualification boundary

Run local CLI and parser/refusal controls with:

```sh
cargo test -p agentfw --lib pilot_budget
cargo test -p agentfw --test pilot_budget
python3 -B -m unittest scripts.tests.test_pilot_run
```

On a qualified native Ubuntu 24.04 x86-64 preparation and an already delegated
empty owned root, the existing original-host driver accepts:

```sh
python3 -B scripts/qualify-prepared-pilot-run.py --selection ABSOLUTE_SELECTION \
  --expected-commit FULL_COMMIT --strace /usr/bin/strace --linux-budget ABSOLUTE_BUDGET \
  --linux-budget-peer ABSOLUTE_INDEPENDENT_PEER_BUDGET \
  --output ABSOLUTE_NEW_OUTPUT
```

It checks both original-server records in useful/Ask/default and ordinary
failure/cancellation cases. For budgeted qualification, its emergency-stop section requires a second explicit
normal budget on an independent owned delegated root. Both runs must finish with
bound receipts, the peer must remain useful after the selected run stops, and
all owned leaves and members must be gone. Omitting this peer input refuses
qualification rather than silently running the stop control without budgets.
Native memory/PID/wall calibration, independent sibling survival, restart/capacity
recovery, budgeted emergency-stop and abrupt parent-loss observations are required
before final qualification. macOS parser/CLI results do not replace those Linux
witnesses. Preserve every failed/incomplete native attempt. Do not change limits,
timeouts, policy floors or expected labels to make one pass. Final shared
CI/admission/main integration remains TL-owned.

The manual native workflow has two independent bounded SOU-142 phases:
`prepared_budget_phase: baseline` and `prepared_budget_phase: pressure`.
Run both on the **same exact source commit**. Each receives its own disposable
15-minute service and retains the existing 2 GiB / 256-task outer caps. This
separates the long lifecycle/stop suite from six original pressure/peer/recovery
controls without increasing any deadline, policy floor, workload concurrency or
product budget. The default workflow phase is baseline; a successful baseline
alone is not full qualification. The pressure projection requires all six
controls, original kernel refusals, surviving useful peers, fresh recovery and
empty owned roots. It explicitly requires separate baseline proof. Preserve
both exact source/config/binary identities, and failed/incomplete attempts.

The pressure phase prepares a fresh owned Git fixture with a real HEAD and
30,000 identical small files in a supported eight-level index directory. This
keeps normal status output small while exercising Git 2.51.2's own ordinary
index-preload threads; it adds no worker executable, environment test switch,
server patch or Git config setting. The existing eight MCP proposals and all
resource limits remain unchanged. The memory case changes a genuinely tracked
file, so `git_diff HEAD` can read its existing 40 MiB calibration input. Earlier
unborn-HEAD / untracked-input attempts are retained as incomplete, never as
observed resource refusals. Fixture setup refuses existing-project selections
and repositories with an existing HEAD; it cannot rewrite a user repository.

## Focused native first slice

The existing manual `sou79-resource-budgets.yml` workflow accepts
`prepared_focus: "142"` on this branch. This selects only native Ubuntu
24.04 compile/unit/Clippy controls in a transient ordinary-user service. Candidate
source is read-only, writes stay in isolated scratch (plus the explicitly owned
delegation for budget controls), and candidate execution has only private
loopback networking. Dependency fetch is a separate trusted setup step that
requires manifests and Cargo configuration to match reviewed main
`04efdf1d959599238a0a9a3eb42cbe26b3531b74`. Raw target logs remain private;
retained artifacts contain bounded status, hashes and projected compiler messages.

This is a compile/capability slice, not original-host or final admission evidence.
The default `off` keeps the existing manual budget qualification unchanged.

The earlier first slice reproduced an empty orphan when the collector died
between leaf creation and owner startup. Retain that failed attempt. New ignored
native controls kill the collector during nonmutating preparation and during
descriptor handoff, and require production cleanup of the exact observed inode.
Those controls require an explicit original-server profile and candidate binary;
compilation or the separate adoption unit control cannot stand in for them.
Loss of the outside cleanup owner itself before handoff is a separate unresolved
failure boundary. An unconfirmed same-name leaf must never be swept or reported
as successfully cleaned.
