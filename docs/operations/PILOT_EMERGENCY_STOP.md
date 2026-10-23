# Stop one owned pilot run (SOU-125, development slice)

This branch starts independently from accepted `main`
`cdd9d36c65a592455e4f421268758adb6db744b8`. It extends the existing launcher and
native session lifecycle; it does not add a service manager or remove installed
asset generations. Keep the PR Draft until the Linux acceptance controls below
have run on its exact source.

## Baseline lifecycle inventory

The accepted launcher already owns the host process group and cleans it on
completion, TERM/INT, timeout and daemon loss. `RunGuard` already authenticates
live Ask runs with sealed manifests, and native terminal retirement already
spends enrolled grants and closes session proposals. The prepared Python
supervisor owns its private daemon and launcher and refuses occupied foreign
ports. The missing path was an authenticated second-terminal stop that revokes
both enrolled and not-yet-enrolled run grants before signalling the owned host.
This change reuses those mechanisms. Legacy direct launches without the prepared
liveness contract keep their existing lifecycle.

## Operator command

For the prepared original Linux pilot, the launcher prints its run ID and daemon
home. From a second terminal, use the **same installed agentfw executable**:

```text
agentfw pilot-approval --home /absolute/private/run/.agentfw --run RUN_ID stop
```

Both Ask-enabled and non-Ask prepared launches receive a run identity. Fixtures,
mock launchers and unsupported platforms do not gain a production stop path.
The run ID is a selector, not authority. The command authenticates the private
record against the live launcher's sealed manifest, exact executable and process
start identity, then holds a Linux pidfd before any signal. It never selects a
target by process name or a bare PID search. Linked, hard-linked, malformed,
foreign and stale records do not authorize a signal.

## Revocation and completion

The authenticated, loopback-only native stop operation binds to the expected
daemon instance, registry, host and exact filesystem/Git grant digests. Under
the same lock that guards session admission, it spends both grants, including
one whose collector has not enrolled yet. Current lineage checks refuse revoked
grants immediately. Existing terminal retirement then closes sessions and their
pending/approved proposals without clearing shared-host risk history.

The CLI durably records intent before requesting revocation, then signals only
the pinned launcher. The existing supervisor cleans its host group and verifies
collector/pending retirement. A signed, exact-run `stopped` receipt is written
only after host cleanup and revocation are confirmed. No rollback of already
dispatched effects is claimed. Repeating the command with that receipt returns
`already_stopped` without contacting a potentially replaced service or signalling
a process. Stop transitions cannot move backwards under concurrent callers.

The prepared-run supervisor still stops its owned launcher and daemon. It retains
the private run directory when stop intent exists so an interrupted operation or
completed receipt is not silently erased. This retained directory contains
private logs and local synthetic daemon credentials; do not publish it. It is
not an install-generation cleanup receipt. Remove it only after its process and
authority state has been independently verified and the receipt is no longer
needed; automatic retention bounds/cleanup are outside this slice.

## Partial failure and restart

Daemon loss, restart, an inaccessible pidfd, failed revocation or unconfirmed
cleanup returns an error rather than `stopped`. On daemon loss the CLI still
requests cleanup from its authenticated live launcher, but retains the request
and does not claim revocation succeeded. A recorded request whose owner has
already disappeared reports incomplete cleanup; an unverified/stale owner
reports unknown ownership. Preserve the private state for diagnosis. Never
substitute another PID or operate on a new daemon instance to finish an old stop.

A new run must obtain a new run ID, daemon-instance binding, child grants and
proposals. Old grants and approvals remain unusable; a fresh grant does not clear
the existing shared-host sticky risk. A new daemon instance refuses old
instance-bound authority even if the old private token file remains available.

## Required Linux acceptance before Ready

The local development host is macOS arm64; this is not native Linux qualification.
The socket-free native-router tests cover selected-vs-unrelated run authority,
unenrolled grants, signed-grant replay, pending and approved proposal cleanup,
wrong auth/host/instance/registry, malformed authority maps and fresh authority.
Receipt tests cover exact run bytes, authentication, monotonic transitions and
linked-file refusal. These tests do not prove real host process cleanup.

Still required on current source: two simultaneous actual prepared runs plus an
unrelated listener/process, selected-host and both-collector termination, zero
future dispatch, no orphan children, a useful task on the other run, daemon loss,
host crash, cancellation, stale/PID-reuse records, interrupted cleanup and hard
Deny after reconnect. Retain sanitized original-server/kernel witnesses and
failed attempts. This branch makes no native-host or safe-restart qualification
claim until those controls pass. No paid provider calls, real secrets, private
datasets, public release, CI-admission change or expensive duplicate matrix.
