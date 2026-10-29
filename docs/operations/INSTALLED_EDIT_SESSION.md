# Installed private-output edit session

SOU-161 adds an explicit `agentfw edit-session` entry on native Linux x86_64.
The existing installed read-only pilot remains the default. This entry does not
upgrade an existing MCP profile and never runs an original server's `write_file`.

## Supported boundary

Use an operator-owned private output directory on a supported local Linux
filesystem. The operator must be the sole writer; cooperating Agent operations
also use the accepted directory lock. This is not compare-and-swap against
arbitrary external writers. Shared or concurrently mutable project trees are
unsupported. Existing replacement rules remain unchanged: one regular direct
child, one link, private metadata, fixed old identity and SHA-256, and at most
4096 UTF-8 bytes. Creation uses the existing no-clobber executor.

Install the reviewed Agent and its verified pilot component first; see
[the installed pilot guide](PILOT_INSTALLED_FRONT_DOOR.md). Select the repository
pinned genuine Claude Code 2.1.251 Linux executable. All runtime paths must be
canonical, protected regular files, with protected owned ancestors. Writable
non-sticky runtime parents are refused. Preparation records the installed component,
source identity, interpreter, classifier, Agent and Claude digests. Changed
inputs require a fresh explicit preparation.

## Preview and explicit preparation

Create separate private directories for output, immutable plans and run state.
The state and plan directories must be outside the output tree. Use absolute
canonical paths. This example permits creation and subsequent reads of exactly
`report.txt`, plus reads of `source.txt`:

```sh
agentfw edit-session preview \
  --home /absolute/agent-home --claude /absolute/claude \
  --root /absolute/private-output --private-sole-writer \
  --read source.txt --read report.txt --create report.txt

agentfw edit-session prepare --apply --out /absolute/plans/report-plan \
  --home /absolute/agent-home --claude /absolute/claude \
  --root /absolute/private-output --private-sole-writer \
  --read source.txt --read report.txt --create report.txt
```

`preview`, and `prepare` without `--apply`, do not write state or grant execution
authority. Preparation publishes a new directory without replacing an existing
plan. Save its displayed `profile_sha256`. No registry, execution or authority
JSON needs to be written by hand. At most eight direct-child targets may be
selected; wildcards, hidden names, aliases and create-plus-replace combinations
are rejected.

For explicitly selected per-run mutation and cumulative byte ceilings, see
[installed edit quotas](INSTALLED_EDIT_QUOTAS.md). Omitting those options keeps
the existing v1 profile semantics.

For replacement select `--read report.txt --replace report.txt`. Preparation
captures that exact old object and content digest. The generated tool schema
requires those fixed old facts; it never silently refreshes an outdated version.

## Run and decide Ask

Place the prompt in a bounded private UTF-8 file, then run:

```sh
agentfw edit-session run --plan /absolute/plans/report-plan \
  --sha256 DISPLAYED_PROFILE_SHA256 --state /absolute/runs \
  --prompt-file /absolute/prompt.txt
```

Provider inputs come from the operator's supported provider environment, as for
the accepted pilot. Only the intended genuine Claude host receives them. Its
settings, user home, plugins, hooks and executable search path are isolated;
builtins and unselected MCP servers are disabled. There is no paid-provider
requirement for the qualification: it uses an owned scripted loopback provider.

The command prints the private run directory. From a second terminal:

```sh
agentfw edit-session ask --run /absolute/runs/edit-RUN_ID list
agentfw edit-session ask --run /absolute/runs/edit-RUN_ID inspect PENDING_ID
agentfw edit-session ask --run /absolute/runs/edit-RUN_ID approve PENDING_ID \
  --binding DISPLAYED_BINDING_SHA256
# Or:
agentfw edit-session ask --run /absolute/runs/edit-RUN_ID reject PENDING_ID
```

Inspect shows the exact target, operation, identities and old/new digests. It
redacts raw arguments for both create and replacement. A decision applies to one
exact pending call. Approval cannot redeem a different binding, replay a spent
call, override independent Deny floors or survive a daemon epoch change.
The existing 120-second approval lifetime is unchanged. Run lifetime is bounded
by 180 seconds, including the Ask wait. Ctrl-C cancels the owned run.

The daemon owns a compiled declaration-only adapter with no filesystem API or
external discovery runtime. All selected operations pass through the existing
classifier, native resource broker, approval and executor. The runtime pins the
adapter as part of the reviewed Agent image and rechecks root identity for every
call. Authenticated transport is single-use and bound to the exact profile,
server and host session; reconnecting requires a new run. The default daemon
cannot activate this endpoint through caller-supplied configuration.

## Outcomes and recovery

A host completion is not a claim that every proposed edit succeeded. Inspect
the selected run with the installed read-only diagnosis:

```sh
agentfw edit-session status --run /absolute/runs/edit-RUN_ID
agentfw edit-session status --run /absolute/runs/edit-RUN_ID --json
```

Status uses bounded private records and authenticated loopback observations;
it never launches a host, dispatches a tool, decides Ask, refreshes a plan or
retries a mutation. It creates no files by default. The versioned report keeps
live daemon observations, retained local evidence and optional current-output
observations separate. Local records are operator-controlled evidence, not
authenticated runtime attestation. A PID or successful host exit does not prove
that a selected mutation committed or that its result reached the model.

If the daemon is unavailable, its instance has changed, audit is missing or
truncated, or records cannot be attributed to this exact run, keep the reported
uncertainty. A publication gate precedes the actual filesystem change; it is
not a commit receipt. A recorded allowed result is not proof of delivery or
model consumption. Create and replacement are diagnosed separately. Older runs
without retained diagnostic bindings remain incomplete evidence.

For an explicit, bounded digest observation of only the declared direct-child
targets, add `--check-output`. Matching current bytes are an observed postcondition,
not proof of who wrote them. Status refuses linked, non-regular, unowned,
oversized or redirected state rather than following it or scanning directories.
It never renders file content or raw arguments.

The short recovery flow is: inspect status, inspect the intended target
independently if the result is uncertain, prepare a fresh exact plan when an
edit is still needed, then obtain new exact approval. Never reuse old Ask
decisions or spent receipts. To share the fixed allowlist through the existing
private support exporter, select a new directory outside the run:

```sh
agentfw edit-session status --run /absolute/runs/edit-RUN_ID \
  --support-bundle /absolute/private/new-support
```

The export contains typed outcomes, validated identity digests and evidence
provenance/completeness, plus the existing hash manifest. It excludes prompts,
contents, raw arguments/results, provider inputs, tokens, grants, private paths
and arbitrary exception text. Publication remains private and create-new;
there is no upload.

An interrupted run is failed/indeterminate. If publication committed before a
result was lost or withheld, the bytes remain committed: cancellation does not
roll them back and this entry never automatically retries the mutation.

Read-only status treats the Stop producer's run-revocation record as strictly
bound descriptive metadata, including at ordinary completed-run cleanup. It does
not infer commit, delivery, rollback or authenticated Stop confirmation from it.
A retained `operator_stop` outcome is reported separately from cancellation;
missing or malformed bindings keep the diagnosis incomplete.

Private run state retains the audit and exact native approval records. Host
stdout/stderr are drained within fixed caps; only byte counts and digests are
retained, never raw model output or provider credentials. A killed daemon cannot
approve stale records: Ask requires the matching live authenticated epoch.
Prepare a new plan after independently inspecting an uncertain target.

## Archive and clean one completed run

SOU-171 adds an explicit installed entry through the verified helper component.
It operates independently of stop/revoke and read-only incident diagnostics.
Install the matching reviewed Agent/component first. Use an existing private
mode-0700 archive directory outside the selected run and a canonical run path:

```sh
umask 077
agentfw edit-session archive --home /absolute/agent-home preview \
  --run /absolute/runs/edit-RUN_ID --destination /absolute/private-archives \
  > /absolute/private-archives/plan.json

agentfw edit-session archive --home /absolute/agent-home apply \
  --plan /absolute/private-archives/plan.json --confirm DISPLAYED_PLAN_SHA256
```

Preview writes only JSON to stdout. It selects one exact completed run and
enumerates its bounded file/directory inventory, identities, hashes, reclaimable
bytes, preserved data and excluded evidence. A plan lasts 15 minutes. Apply
rechecks the exact inventory and destination inode, then exclusively publishes
and verifies a private sanitized ZIP; all original run state is still retained.
The archive contains only an allowlisted audit projection and a manifest with
hashes, finite terminal facts and explicit evidence limitations. It is **not a
full forensic backup**. Raw audit, prompts, tool payloads, credentials, child
authority, host state, provider inputs, environment and absolute paths are
excluded. Unknown audit event types are counted, not presented as complete
execution evidence. Malformed or partial raw audit refuses archival.

Cleanup requires separate explicit acknowledgement of irreversible raw-evidence
loss. Independently retain any raw evidence you still need before using it:

```sh
agentfw edit-session archive --home /absolute/agent-home cleanup \
  --plan /absolute/private-archives/plan.json --confirm DISPLAYED_PLAN_SHA256 \
  --acknowledge-evidence-loss
```

Only the approved run inventory is removed. Output targets, immutable plans,
projects, shared assets and other runs are never traversed.
Output resource roots must remain disjoint from run state. Nested Git or
immutable-plan markers refuse the whole selection and remain in place. The accepted
SOU-149 no-follow descriptors, exclusive staging, file identity checks and
durable archive guard are reused. A durable private journal precedes detachment;
completion needs a separate durable create-new commit. A missing source or PID
does not establish completion. New launchers hold the selected daemon-home inode
lock until terminal publication, so an active run refuses archival even if a
terminal file is injected. The run-directory lock remains available for short
Stop metadata transactions. Existing accepted runs require all consistent terminal
cleanup facts and transport/run/profile/instance bindings; these are local
owner-editable evidence, not authenticated execution proof. Failed/interrupted
runs qualify only if their accepted terminal explicitly confirms process and
daemon cleanup. Unknown crash state, inconsistent bindings and new or unexpected
state members refuse and remain intact. No background pruning occurs.
Current-main run-local `profile.json`, `profile.sha256`,
`diagnostic-context.json` and `host-process.json` are descriptive snapshots,
distinct from the original external immutable plan. Only the complete exact
root set with private read-only modes is accepted. The canonical v1 profile
bytes and digest, typed nested schemas, transport resources, run/home/profile/
session/instance bindings, process identity fields and retained control owner
are checked through bounded no-follow reads. The walker rechecks those exact
bytes and file identities. No profile-selected path, executable, original plan,
PID or listener is opened or contacted by this validation. Snapshot bytes are
inventoried for explicit cleanup and excluded from the sanitized ZIP. Arbitrary
extra members, future schema versions and all nested plan markers still refuse.

Known separately versioned optional stop/control records are included in the
private inventory and excluded from the sanitized ZIP. They never substitute
for terminal cleanup and never authorize signaling here. Missing, inconsistent
or unconfirmed control evidence refuses cleanup; the stop command remains
optional. Synthetic parser fixtures complement the genuine installed
current-main Stop-to-archive-to-cleanup qualification.

`archived_source_retained`, `archived_and_cleaned`, `already_cleaned`, `refused`
and `incomplete` distinguish the outcomes. After interruption preserve the
archive, plan, journal and any quarantine. Inspect without resuming deletion:

```sh
agentfw edit-session archive --home /absolute/agent-home recover \
  --plan /absolute/private-archives/plan.json --confirm DISPLAYED_PLAN_SHA256 \
  --journal edit-cleanup-DISPLAYED_PLAN_SHA256.json
```

Recovery accepts an expired plan for read-only inspection. It never restores,
resumes or guesses successful cleanup from absent members. Repeated cleanup
requires the same verified archive and explicit durable completion commit; an
interrupted removal remains incomplete. Stop, policy, approval and expiry
semantics are unchanged. No mutation is automatically retried.

`python3 -B scripts/qualify-installed-edit-archive.py` is inert. Its opt-in
qualification uses genuine installed completed/interrupted runs, two concurrent
active roots, independent target/plan/process/sentinel witnesses and fresh
useful work. A namespace-private 64-KiB tmpfs supplies actual kernel `ENOSPC`;
trusted setup supplies an empty foreign-owned fixture. Publication/removal
interruption uses exact installed helper bytes with a qualification-only pause
and actual SIGKILL. Those controlled fault windows and synthetic parser fixtures
are distinguished from genuine host/CLI observations. The existing installed
job retains exact source/binary correlation, the original edit report and the
new archive report; failed/incomplete attempts are retained. The current
16-case archival inventory includes an ordinary current-main completed run,
typed descriptive-snapshot refusal controls and a genuine Stop after an
approved replacement committed. That Stop case checks diagnosis, explicit
evidence-loss refusal, sanitized archive publication and exact acknowledged
cleanup, with independent output/immutable-plan/sentinel/active-peer witnesses.
The earlier 14-case results remain evidence for their original source only.
## Stop one selected live run

From a second terminal, use the **same installed Agent executable** as the run:

```sh
agentfw edit-session stop --run /absolute/runs/edit-RUN_ID
agentfw edit-session stop --run /absolute/runs/edit-RUN_ID --output json-v1
```

The selected private directory must be canonical, owned and link-free. A new
bounded `control.json` is separate from the existing `run.json` contract. The
operator verifies it against the live launcher's sealed descriptor, executable,
process birth identity, exact profile/session and authenticated daemon epoch,
then pins the launcher with a Linux pidfd. Edited JSON, a PID or a process name
cannot authorize signaling. Missing kernel identity support refuses before the
host starts. Older runs without control metadata cannot use this operation.

Only the existing launcher retires its exact native authority and pending Ask,
closes its one-use transport and joins the adapter before cleaning its owned
host/relay group. Native revocation takes the same lock as admission and result
publication. It never changes policy, approval expiry, output targets, immutable
plans or sticky host risk. No general kill endpoint or second supervisor exists.

Text and versioned JSON distinguish `stopped`, `already_stopped`,
`requested_unconfirmed` and `cleanup_incomplete`. Only an authenticated owner
receipt after confirmed revocation and cleanup permits either successful status.
A queued request, dead PID or independently observed disappearance is insufficient.
All outcomes report that effects may remain committed, rollback is false and
automatic retry is false. A replacement committed before revocation remains on
disk even if its result was withheld. Inspect the target and retained native audit
before deciding what to do next; prepare fresh bindings through the ordinary flow.

Daemon authentication failure refuses without signaling or publishing intent.
If the launcher/embedded daemon crashes after intent, the result remains
unconfirmed until an owner receipt exists; repeated commands never guess success
or signal an unrelated replacement PID. Preserve `control.json`, stop request,
receipt, native audit and any incomplete state for recovery. Old requests,
receipts and approvals cannot select a freshly prepared run or daemon epoch.

`python3 -B scripts/qualify-installed-edit-stop.py` is inert. Its explicit `--run`
driver reuses the accepted installed component and genuine restricted host with
an owned loopback provider. It checks two concurrent private roots and an
unrelated process/sentinel, pending/rejected Ask, repeat/replay, post-confirmation
dispatch, committed publication and a publication/stop race, unsafe records,
unavailable daemon, launcher crash and fresh useful read/edit/read. Birth mismatch
controls simulate stale/PID-reuse identity; they do not force kernel PID reuse.
The stopped daemon shares the launcher process. Suspended-daemon and actual
SIGKILL cases retain that distinction. Parser/MAC and stalled-preamble unit
controls supplement, rather than replace, the installed observations.

The existing `linux-installed-edit` artifact retains `source.txt`, `binary.txt`,
the original 23-case `runtime/report.json` and `stop-runtime/report.json`. Match
the source commit and Agent SHA-256 across both reports and the build witnesses.
The stop report records the installed component and genuine host digests, exact
profile and daemon identities, observed owned process IDs/birth ticks, target
snapshots and audit digests. Private raw arguments, bearer tokens and provider
contents stay outside that artifact. Failed/incomplete cases remain explicit;
an observed crash cleanup never becomes an authenticated successful stop.
For another operation on the same declared targets, use the explicit
[plan refresh preview and confirmation](INSTALLED_EDIT_PLAN_REFRESH.md).
Refresh never infers previous success, retries a call or approves the next Ask.

## Qualification

`python3 -B scripts/qualify-installed-edit.py` is inert. The explicit `--run`
qualification installs exact Agent/Claude bytes outside the checkout, installs
the verified component, then uses the genuine restricted host with an owned
scripted provider. It independently checks useful read/create/read and
read/replace/read, Ask decisions, changed host/component bytes, writable runtime parents, stale
inputs, symlinks and hardlinks (both names independently retained), changed bindings, replay,
cancellation, daemon loss, fresh epochs and interruption after successful tool-result
delivery. This last case does not claim loss or withholding of the tool result.
Failed inspection exits have bounded typed diagnostics; a closed-run refusal is
reconciled with the actual Ask verdict and zero effects, while successful
inspection still must satisfy every redaction assertion. It checks
output bytes/inodes, an unrelated sentinel, discovery mutation dispatch and owned
process cleanup. This is development qualification, not a live-model efficacy or
production-readiness claim. The registered `linux-installed-edit` job runs with
read-only source, private writable scratch and no external network.

Add `--diagnose` to freeze and execute the additional status inventory: eight
native runtime cases and six explicitly simulated retained-state cases. The
runtime cases cover create/read, replace/read, pending/rejected Ask,
cancellation, daemon loss, post-publication interruption and secret-canary
support export. The fixtures cover stale identity, absent/truncated audit,
missing result after a publication gate, tampered profile and foreign run.
The missing-result fixture does not establish a real commit-before-result-loss
event. Independent target/sentinel/process witnesses check that diagnosis
does not change the selected run; only correlated bounded lease-renewal audit
appends are allowed while a real run remains live.

The corrected native qualification passed 23/23 cases, 43 focused Rust controls,
5 finite/classifier controls and strict Linux Clippy/fmt on implementation source
`07a5f1d1b2b05162e1d1d7849af577e94b802202`. Source/binary/artifact correlation and
all original attempts are retained under
[`evidence/sou-161/`](evidence/sou-161/README.md). Final shared Ready qualification,
admission and merge remain with the reviewer.

The subsequent installed status/diagnosis qualification passed all 23 existing
controls plus 14 diagnostic cases on `a7ec2de899aa55726e7488f5d31bec5044b52307`.
Eight cases observed actual installed runtime boundaries; six explicitly changed
retained state as parser fixtures. Exact source/binary/component/report hashes,
typed responses, independent witnesses, limits and both failed attempts are
retained in [the diagnosis evidence](evidence/edit-diagnostics/README.md).
