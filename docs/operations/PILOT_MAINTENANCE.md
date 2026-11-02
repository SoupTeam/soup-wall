# Installed pilot maintenance mode

Maintenance mode lets an operator pause **new** launches for one owned Linux pilot
installation (one explicit Agent home) while existing runs continue. It is local
admission control only. It does not stop, approve, reset, roll back, back up,
update or uninstall anything, and it grants no authority.

## Commands

All commands are run through the installed front door for the Agent home being
paused. `--prefix` and `--state-root` must be the same values the pilot was
prepared with.

```sh
agentfw pilot --home "$AGENT_HOME" maintenance status  --prefix "$PREFIX" --state-root "$STATE"
agentfw pilot --home "$AGENT_HOME" maintenance preview --prefix "$PREFIX" --state-root "$STATE" --operation enter
agentfw pilot --home "$AGENT_HOME" maintenance enter   --prefix "$PREFIX" --state-root "$STATE" --confirm <confirmation_sha256>
agentfw pilot --home "$AGENT_HOME" maintenance preview --prefix "$PREFIX" --state-root "$STATE" --operation leave
agentfw pilot --home "$AGENT_HOME" maintenance leave   --prefix "$PREFIX" --state-root "$STATE" --confirm <confirmation_sha256>
```

- `status` and `preview` are read-only. Neither creates locks or enrolls a home.
- `enter` and `leave` require the `confirmation_sha256` of a **fresh** preview. The
  digest covers the current marker, the installation/selection/root binding and
  the observed run inventory, so a preview taken before any change is refused
  (`maintenance_confirmation_stale`).
- The first `enter` enrolls the home. A home that was never enrolled launches as
  before; `leave` on a never-enrolled home is refused.

## What is bound

The marker governs one installation: the Agent home, the installed component home
and the directory identities of those two roots. A marker is never inherited from
another home: a sibling installation is unaffected and keeps launching, and a launch
or transition for a different installation scope is refused
(`maintenance_scope_changed`).

The marker also records the launch binding it last saw (selection, state root, pinned
selected programs/profiles/policy and their root identities). That record is
informational for admission: ordinary selection changes, `update` and named project
presets bind different selections and must not strand an enrolled home. `status` and
`preview` report `selection_binding` as `current` or `changed`. Only a freshly
confirmed `enter` or `leave` adopts a changed binding; the confirmation digest covers
the old marker state and the new binding, and the signed old state stays in the
transition history. A stale confirmation, or one for another scope, is never accepted.

The marker has a permanent inode, a keyed authenticator and a synced transition
journal. Symlinks, hard links, foreign owners, wrong modes, replaced directories,
same-bytes replacement, duplicate JSON fields and partial writes are refused and
never repaired or recreated by a reader.

Selected executables must satisfy the existing owner, mode and trusted-ancestor
checks. Use a protected input path rather than a shared writable tool cache; the
qualified Ubuntu 24.04 fixture selects `/usr/bin/python3.12` explicitly. Reprepare
after changing the selected interpreter so its actual identity is pinned.
Maintenance does not make an otherwise untrusted executable eligible.

## Launch exclusion

A new launch through the installed front door is admitted at two points while
holding a short shared gate. This covers `run` and named project presets
(`project run`); both carry the same installation context into the run supervisor:

1. before the private run state is created, and
2. immediately before the Claude host process is spawned. The Rust launcher holds
   the gate through the actual `spawn` and revalidates through the installed
   component's verified helper.

`enter` takes the same gate exclusively, so entering and a new launch cannot
interleave: a launch either started before the transition (and is then an existing
run) or is refused. The gate is **not** held for the host's lifetime, so entering
maintenance never waits for running sessions.

A launch is refused, with no host, provider or server started, when the marker is
entered, missing, corrupt, stale, unauthenticated or half-written, or when the run
inventory is uncertain. Refusal reasons are finite, for example
`maintenance_entered`, `maintenance_state_uncertain`, `maintenance_scope_changed`,
`maintenance_runs_uncertain` and `maintenance_transition_busy`.

## Status and drain

`status` reports one of:

| `drain` | Meaning |
| --- | --- |
| `draining` | at least one enrolled run is verified alive (supervisor identity matches) |
| `enrolled-runs-drained` | every enrolled run has a confirmed terminal record |
| `uncertain` | a run intent exists without a terminal record and no live supervisor, a legacy or foreign run cannot be attributed, or the inventory is incomplete |

A terminal record is written only after the accepted process-group stop and receipt
cleanup succeed. A missing PID, an empty process list or a vanished run directory
is never treated as drained. `empty_process_list_proves_drain` is always `false`.
`new_launches` is `refused` unless the marker is open, governs this installation
(`installation` is `matches`) and the inventory is certain.

Existing hosts keep their sessions, risk and authority state. To stop a run, use
the existing exact-run stop separately; maintenance mode adds no killing mechanism.

## Leaving and recovery

`leave` requires a fresh preview, a certain inventory and an intact marker. It is
refused when the marker is uncertain or a transition is pending. After a crash in
the middle of a transition the home stays closed to new launches. Only an explicit,
freshly confirmed `enter` recovers it conservatively; the interrupted intent is
kept as signed `unresolved-*.json` evidence. Nothing is deleted, and a stale or
replayed marker, history or journal cannot clear another owner's maintenance.

## Limits

The marker is capped at 32 KiB, history at 128 events, and 64 enrolled runs. Reaching
a cap refuses with a finite reason rather than dropping records. Two new launches
that start at the same instant may briefly refuse each other with
`maintenance_transition_busy`; retry. The feature is Linux-only, local to one
filesystem, and covers launches that go through the installed front door of the
enrolled home. Direct preparation scripts remain outside it.

## Qualification

`scripts/qualify-installed-front-door.py --run --maintenance-only` (manual
`installed_focus=maintenance` + `native_preparation_only=true` dispatch) exercises the installed
binary on owned synthetic inputs with syscall tracing and an independent receiver.
Required cases: read-only preview, useful run before enter, existing run draining,
new run refused after enter, sibling unaffected, stale leave refused, fresh leave,
existing run completing after enter, useful run after leave, named project run
refused while entered, same-bytes marker replacement, partial transition and a crashed owner left uncertain. A configured,
simulated or skipped case is not reported as observed protection.
