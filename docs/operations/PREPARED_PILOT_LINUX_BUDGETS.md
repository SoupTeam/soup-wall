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
strict parser and an empty owned engine leaf; an availability probe never proves
that a protected process ran. The native launcher verifies the preflight's
canonical SHA-256, freezes another private run snapshot, pins the root identity,
and holds an exclusive cooperating-run lease until terminal cleanup. An occupied
root or changed configuration refuses before the host/original servers execute.

The native `pilot-launch --linux-budget FILE` contract is reusable independently.
An optional `--linux-budget-sha256 DIGEST` binds a previously inspected identity.
Both original-server commands receive the frozen `AGENTFW_MCP_LINUX_BUDGET`, a
private host-session binding, and `--pilot-budget-binding`. CLI and environment
must agree: losing environment variables cannot silently downgrade that command
to an unbudgeted collector. Session, server, paths, root and config identity are
checked before preparing a protected child.

The unchanged SOU-79 engine enforces each original server's aggregate process
**tree** in its own leaf. Filesystem and Git are independent siblings. This is
not a claim that the daemon, Claude host, or their combined CPU/memory is inside
one shared budget. The operator's delegated substrate remains intact.

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
  --output ABSOLUTE_NEW_OUTPUT
```

It checks both original-server records in useful/Ask/default and ordinary
failure/cancellation cases. Its separate emergency-stop section still exercises
the original unbudgeted contract; it is not evidence of budgeted stop coverage.
Native memory/PID/wall calibration, independent sibling survival, restart/capacity
recovery, budgeted emergency-stop and abrupt parent-loss observations are required
before final qualification. macOS parser/CLI results do not replace those Linux
witnesses. Preserve every failed/incomplete native attempt. Do not change limits,
timeouts, policy floors or expected labels to make one pass. Final shared
CI/admission/main integration remains TL-owned.
