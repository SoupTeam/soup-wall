# Stop one owned pilot run (SOU-125)

This implementation uses accepted `main` `acf59af` and extends the existing
launcher and native session lifecycle. The exact-source native Ubuntu 24.04
qualification is retained in `evidence/sou-125/native-linux.json`. It uses the
original host and installed servers with an owned scripted loopback provider;
it does not measure live-model effectiveness.

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
the pinned launcher. A bound selected collector registers its cleanup obligation
before preparing/spawning the existing namespace owner, under the same native
session lock used by revocation. A grant spent before registration cannot start
that owner. The collector discharges the obligation only after its existing
namespace owner, resource budget, child reap and stderr boundaries confirm
cleanup. Registration and confirmation require the exact enrolled session epoch
and private owner capability as well as native authentication. The one-purpose
confirmation remains possible after session retirement, without reviving the
session or its authority. Obligations are bounded; an unconfirmed one remains a
failure even after its grant expires. This is a trusted-collector protocol,
not remote process attestation.

The launcher allows these existing owners a bounded cleanup opportunity before
host-group termination, including when the host exits before its queued TERM is
handled. It keeps the group leader unreaped, checks TERM/KILL errors and bounds
Linux reap/group-empty observation. It then independently verifies that all
selected cleanup obligations, collector sessions and pending approvals have
closed. A signed, exact-run `stopped` receipt is written only after those checks
and revocation are confirmed. No rollback of already
dispatched effects is claimed. Repeating the command with that receipt returns
`already_stopped` without contacting a potentially replaced service or signalling
a process. Stop transitions cannot move backwards under concurrent callers.
Concurrent operator/launcher receipt writes wait up to two seconds for the short
metadata lock instead of abandoning final confirmation on ordinary contention.
An occupied or failed lock still reports an error. Terminal output and daemon
requests never hold that lock: a blocked `inspect` pipe cannot prevent stop,
and an inspection interrupted by stop cannot persist a fresh inspection receipt.

An intercepted TERM can become a successful `stopped` outcome only with the
exact authenticated terminal receipt. Requested/revoked intent, cancellation,
timeout, daemon loss or a failed host cannot substitute for it. The prepared-run
supervisor independently verifies the exact run/launcher/home receipt through
the installed operator CLI; an exit code or a JSON status alone is insufficient.

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
The cleanup-confirmation and terminal-disposition follow-up has verified local
formatting, clippy and unit suites on macOS arm64 (1671 passed in the Rust
workspace, 10/10 in stop witness, 16/16 in pilot-run). Keep the PR Draft until
the required current-source native Linux witnesses pass.
The socket-free native-router tests cover selected-vs-unrelated run authority,
unenrolled grants, signed-grant replay, pending and approved proposal cleanup,
wrong auth/host/instance/registry, malformed authority maps and fresh authority.
Receipt tests cover exact run bytes, authentication, monotonic transitions and
linked-file refusal. These tests do not prove real host process cleanup.

Native Ubuntu 24.04 qualification on `d5d7813` passed all eleven prepared-run
lifecycle controls and four emergency-stop scenarios. Two simultaneous actual
prepared runs and an unrelated listener/process were observed: only the selected
run stopped, its host, both collectors and namespace helpers disappeared, no
future original dispatch occurred, and the peer completed useful filesystem and
Git operations after the stop. Interrupted stop resumed successfully; daemon
loss and frozen namespace cleanup retained honest incomplete outcomes.

Stale/foreign record controls include forged process-start ticks; they do not
claim to force kernel PID reuse. Native cancellation and host-crash controls
also passed. Unit/router controls separately cover spent grant/receipt replay,
fresh authority and shared-host hard Deny after reconnect. Raw authority,
provider contents and syscall traces are excluded from retained evidence. No
paid provider calls, real secrets, private datasets or public release are used.
