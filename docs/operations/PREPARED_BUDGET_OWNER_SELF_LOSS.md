# Outside-owner loss before descriptor handback

This is the remaining SOU-142 fault-boundary handoff. The accepted collector-loss
controls in [prepared Linux budgets](PREPARED_PILOT_LINUX_BUDGETS.md) do not exercise
SIGKILL of the separate outside cleanup owner. Neither a successful diagnostic
job nor observer cleanup qualifies full SOU-142 acceptance.

## Current production boundary

The actual Agent owner authenticates its collector and pins the delegated root,
creates/configures the cgroup with the existing engine, retains cleanup handles,
then sends eight descriptors to the collector. Original sandbox startup waits for
successful adoption acknowledgement. Killing the collector in this interval lets
the surviving owner clean its own leaf; killing that owner before transfer is a
different failure. A collector that never received its inode capability cannot
infer ownership from the random name, unchanged limits, empty membership or a
dead-owner pidfd. It must preserve an unconfirmed same-name replacement.

## Exact native diagnostic

The manual `sou79-resource-budgets.yml` workflow adds one explicit development
phase, `prepared_budget_phase=owner-loss`, with `prepared_focus=142` and
`prepared_host=true`. The ordinary baseline/pressure qualification and product
limits are unchanged. This phase never qualifies shared admission by itself.

The existing trusted setup provides exact candidate Agent/libtest images, the
pinned original filesystem/Git profiles and an already delegated empty disposable
root. Candidate code runs as an ordinary user, from read-only source and binaries,
with scratch-only writes, explicit owned cgroup access and private loopback.

For each original profile, `scripts/ci/observe-owner-self-loss.py`:

1. Follows only its own collector helper and descendants through kernel ptrace
   custody. Verifies the actual owner executable digest and process generation.
2. Stops the owner at **sendmsg entry**, parses the bounded actual prepared-budget
   message and its eight distinct SCM_RIGHTS descriptors, and independently pins
   the stated leaf inode. The syscall has not transferred descriptor custody.
3. Sends SIGKILL through that owner's pidfd; requires its signal exit and the real
   collector's startup refusal. No original sandbox executable may start before
   adoption, and all traced processes must stop.
4. Observes the same empty leaf for the unchanged 3000 ms cleanup interval. A
   retained orphan is `blocked`, `acceptance_pass=false` and
   `production_cleanup_verified=false`, never a successful cleanup receipt.
5. Performs separately labelled fixture hygiene on only that independently pinned
   empty inode. This is `observer_cleanup_*`, not production recovery. The public
   parent projection retains this distinction and the remaining fault gap.

The only Rust change is an ignored collector test helper. Its actual Agent owner
uses the unchanged production path, with no production barrier, environment test
switch, modified runtime, altered syscall result or raised deadline. The observer
reads the stopped owner's message; it never rewrites memory/registers or replaces
the sendmsg result. A kernel/ptrace limitation, unexpected message, process drift,
missing marker or uncertain cleanup is `incomplete`, not a successful negative.

The public projection is finite: source/runtime/profile/config hashes, observed
boundary, signal/generation checks, descriptor count, zero execution/members,
remaining orphan and separate cleanup custody. Raw IPC bytes, nonces, process
identifiers, argv, paths and private diagnostic logs are not exported.

## Replacement-safe follow-up decision

A preannounced pathname is insufficient. An owner may create a leaf, die before
communicating its inode, and have that name replaced before the collector checks
it. Sweeping the current name would destroy independently created inventory.
Renaming this ambiguous state or moving the same unrecorded mkdir between actors
does not solve the ownership problem.

Two explicit wider contracts can be reviewed separately: operator-provisioned,
bounded leaf slots pinned by a surviving actor **before** runtime mutation; or a
surviving creation guardian with an agreed failure/transaction model. Either
needs cancellation, supersession, restart and custody controls. This handoff does
not silently add either engine, require a root daemon or change delegation.

## Evidence status

Development source is based on accepted main
`3c9cfb08c0f1498676dcc70de131bd2f324dd13b`. Native source
`39415fb717ad22b50701100aeebc96927e0b9690` reproduces the orphan for both actual
filesystem and Git profiles in run `40285176569`. The independently checked
[retained result](evidence/sou-142-owner-self-loss/native-observation.json) is
`blocked-diagnostic-verified`; production cleanup and full acceptance remain false.
Linux build/unit/adoption controls and strict Clippy passed. This completes the
requested diagnostic handoff and identifies the remaining creation-custody decision.
Failed and incomplete attempts remain retained.
