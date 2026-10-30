# Installed pilot removal

`agentfw pilot-removal` is a built-in, offline Linux x86_64 operator command.
It removes only the exact receipt-verified `pilot-front-door` component under an
explicit private Agent home. It never removes the Agent executable, a service,
provider profiles/credentials, project/Git workspaces, generated outputs, private
review/export bundles, backups or audit/history. It does not stop processes.
The default operation is a separate read-only preview; no helper or provider is
executed. Unsupported platforms retain their existing startup behavior.

This intentionally supports one finite scope, not a general home/prefix purge.
Preparation prefixes and run-state roots are explicit retained selections. Known
preparation selection/generation receipts are inventoried, not deletion grants.
For inactive prerequisite generations use the existing
[receipt-aware cleanup](PILOT_CLEANUP.md) separately; current/active/incomplete
generations and user workspaces keep that command's existing retention rules.

## Preview and explicit removal

Use the ordinary account that owns the installation. Select all preparation
prefixes and custom read-only/edit state roots used by this installation. Keep
new launches, preparation, updates and arbitrary same-UID writers quiesced for
the entire operation. Process observations and cooperative locks cannot enforce
exclusion against arbitrary programs run by the same user. Inaccessible or
inconsistent same-account process/run evidence blocks removal. A nonempty
unrecognized read-only run directory stays blocked; use its accepted stop/archive
workflow and inspect the retained evidence rather than deleting it to bypass
the blocker.

```bash
umask 077
agentfw pilot-removal preview --home /absolute/private-agent-home \
  --prefix /absolute/private-preparation-prefix \
  --state /absolute/private-run-state \
  --journal /absolute/private-recovery-parent/removal-1
```

`preview` reads only. It shows exact relative removal objects, identities,
digests, retained selections and finite blockers. No confirmation is emitted
when active or unverified run/process evidence remains. Invalid receipts,
unknown installation entries, links, special/hardlinked/foreign files, unsafe
ancestry, mounts/aliases, redirected roots and interrupted component installs
refuse without mutation. Resolve component-install interruption through its
existing recovery interface first; removal does not infer ownership of staging.

Read the inventory, then explicitly confirm its current digest:

```bash
agentfw pilot-removal apply --home /absolute/private-agent-home \
  --prefix /absolute/private-preparation-prefix \
  --state /absolute/private-run-state \
  --journal /absolute/private-recovery-parent/removal-1 \
  --confirm PREVIEW_SHA256 --consent-remove --exclusive-maintenance
```

The new journal must have an existing owner-private parent outside the selected
installation, preparation and state roots. The exact plan is durably published
before any unlink. Every original object has a durable intent before removal
and a completion record only after its parent directory is synced. The current
component pointer is removed first to disable the installed front door. Remaining
operations use built-in Agent code, never the helper being removed. The Agent
binary and private recovery journal remain available throughout. No shell,
provider/helper execution, process-name kill, force flag or broad recursive
deletion is used.

## Status and bounded resume

```bash
agentfw pilot-removal status --journal /absolute/private-recovery-parent/removal-1 \
  --expect-plan PREVIEW_SHA256 --success-ack SAVED_SUCCESS_ACK
agentfw pilot-removal resume --journal /absolute/private-recovery-parent/removal-1 \
  --expect-plan PREVIEW_SHA256 --consent-remove --exclusive-maintenance
```

Outcomes distinguish `removed`, `retained`, `failed` and `uncertain` objects.
Save the private `success_ack` from a fully successful response. Only its hash
is retained in the journal. A later status/already-removed check needs that
acknowledgement to confirm whole-operation success; an interrupted response
cannot reconstruct it from readable records. Omit it while resuming an incomplete
attempt; a fully completed resume returns its own acknowledgement.
Resume skips objects with verified completion records, rechecks all remaining
objects and rejects new occupants of any original name. A failed unlink with the
unchanged original still present may enter another recorded attempt, at most
three per object. A kill before unlink can continue. A kill between completed objects resumes the
remaining exact objects and skips the durably completed prefix. Directory
metadata is pinned after each completed child removal, so later directory
changes are not silently adopted. An unlink without a complete
durability record stays uncertain and cannot be converted into success merely
because the name is absent. A kill after unlink or failed directory sync retains
the journal and all remaining evidence, and refuses blind retry. A readable but
malformed record, replaced journal, changed root or unexpected object refuses.
Do not edit progress records to manufacture completion.

An already completed removal remains repeatable via its original journal and
digest. Reinstallation or a different object occupying an old name is a new
installation and cannot be removed by that journal. Recovery data is never
automatically purged. Store JSON outcomes privately; paths/identities in the
operator's selected inventory are private diagnostics, not public telemetry.

## Qualification

The opt-in `scripts/qualify-pilot-removal.py` uses disposable owned Linux fixtures,
a real installed component and the pinned genuine Claude host with the existing
scripted loopback provider. It checks usable installed startup, a completed
create/read edit run, live-process/edit-run refusal, read-only preview, explicit
consent, stale/tampered/link/alias/unknown-state controls, actual removal and
retained built-in recovery. Actual syscall faults exercise SIGKILL before unlink, between completed objects and
after unlink, unlink I/O failure, directory-sync failure, explicit retry and a
new object substituted before retry. Independent project/sibling/credential/run
and output witnesses remain unchanged. Reports publish only finite outcomes,
counts and exact source/binary/helper hashes; raw paths, payloads and credentials
stay private. No paid inference or personal project data is used.

Final shared Ready CI, CodeQL, exact-source candidate admission and merge are
team-lead-owned; an author Draft or a successful preview is not merge approval.
