# Explicit single-file application of an installed edit result

This Linux x86-64 operator workflow applies one explicitly selected, reviewed
private output to one existing file in a separately selected project directory.
It reuses [installed review](INSTALLED_EDIT_REVIEW.md) and the accepted
[guarded replacement boundary](CONSTRAINED_FILE_REPLACEMENT.md). An installed
Agent/component and retained run/plan are sufficient; no source checkout is needed.

The destination directory must be owned by the operator, mode `0700`, and
quiesced against every other writer, including other same-UID processes. The
target must be one direct-child, owner/group-owned `0600` regular UTF-8 file,
with one hard link and no extended attributes. Both images are at most 4096
bytes. Existing filesystem/ancestor checks and the cooperating directory flock
remain in force. The operator's sole-writer assertion is a prerequisite; a flock
does not exclude an arbitrary non-cooperating same-UID writer. Concurrently
mutable projects and multi-file publication are unsupported.

The original read-only pilot and private edit-output defaults are unchanged.
Review reports, model text and Ask approvals grant no destination-write authority.
These commands perform a separate local operator publication. They do not contact
providers, start a Claude/MCP process, decide Ask, run the applied file, or consume
or mint model execution grants.

## Review, preview, apply

Select the exact completed run, its original immutable prepared plan and digest,
one declared mutation output, and an existing destination file. The installed
run must still pass the accepted completion, cleanup, owner and immutable-profile
checks. Runtime/component anchors and the original prepared plan are rechecked.

Choose a new journal directory under an existing owner-private parent, outside
the destination, source output, selected run, immutable plan and protected runtime
roots. All paths must have canonical, non-redirected spelling. The selected
output is retained unchanged.

```bash
agentfw edit-session review --run "$RUN" --sha256 "$PROFILE_SHA256"

SELECT=(--run "$RUN" --plan "$PREPARED_PLAN" --sha256 "$PROFILE_SHA256"
        --output result.txt --root "$PROJECT_ROOT" --target selected.txt
        --journal "$NEW_PRIVATE_JOURNAL")
agentfw edit-session apply preview "${SELECT[@]}"
```

Preview creates no journal or backup and prints no private file contents. It
returns the finite `sw-installed-edit-application/1` plan and
`confirmation_sha256`, binding run/profile/component, selected output descriptor,
digest and size, destination root, complete preimage descriptor/digest/mode,
intended postimage, exclusion contract and private journal parent. To inspect
private contents, use the existing explicitly consented review display separately.

After checking the preview and actually excluding all other writers, copy that
exact confirmation and explicitly consent to retaining the bounded private
preimage:

```bash
agentfw edit-session apply commit "${SELECT[@]}" --confirm "$APPLY_CONFIRMATION" \
  --private-sole-writer --consent-private-backup
```

Application publishes a new owner-only journal with the preimage and exact plan
before target publication. It retains the staged inode in a durable intent,
uses the accepted guarded replacement, and records exact descriptor/readback and
file/directory sync completion. Save the successful response's `plan_sha256`,
`receipt_sha256` and private `success_ack`. Only the acknowledgement's hash is
retained in the journal; its random value is returned after all final checks.
A stale confirmation, existing journal, changed binding or
unsupported metadata refuses; an old application is never silently retried.

## Status, recovery and separately confirmed revert

```bash
agentfw edit-session apply status --journal "$JOURNAL" --expect-plan "$PLAN_SHA256" \
  --receipt "$APPLICATION_RECEIPT" --success-ack "$APPLICATION_ACK"
agentfw edit-session apply revert-preview --journal "$JOURNAL" \
  --expect-plan "$PLAN_SHA256" --receipt "$APPLICATION_RECEIPT" --success-ack "$APPLICATION_ACK"
agentfw edit-session apply revert --journal "$JOURNAL" --expect-plan "$PLAN_SHA256" \
  --receipt "$APPLICATION_RECEIPT" --success-ack "$APPLICATION_ACK" \
  --confirm "$REVERT_CONFIRMATION" --private-sole-writer
```

Revert has its own preview and fresh confirmation. It restores only this
application's retained preimage while the current target still matches the
recorded postimage descriptor and digest. A later user edit, even one restoring
the same bytes, invalidates that descriptor. Successful revert returns a new
receipt and acknowledgement; use both for subsequent status. Original generated output, prepared plan,
backup and application evidence are retained. Ownership/mode restrictions remain
those of guarded replacement; replacement changes the target inode/timestamps.

`recover` is a read-only alias of `status`. Without both values returned by a
successful command, an incomplete attempt stays `indeterminate` or refused.
Neither matching current bytes nor a readable receipt can reconstruct the
withheld acknowledgement. Interrupted publication,
missing/damaged records or backups, changed roots, stale source/boot bindings and
uncertain durability do not permit automatic rollback, cleanup or blind retry.
The response's `local_operator_publication` flag marks confirmed completion.
When status is `indeterminate`, the file may already have changed even though
that confirmation flag is false. Inspect the target and retained private evidence
independently. Do not edit the
journal to make an uncertain operation appear complete.

## Verification

The [opt-in qualification](../../scripts/qualify-edit-application.py) uses a
genuine installed pinned host with the existing owned loopback scripted provider
to create/replace/read private outputs, then runs offline review, preview,
application, readback and revert against disposable owned project fixtures. A
separate provider trap and unchanged retained native records witness operator-only
operations. The finite negative inventory includes stale/duplicate calls, two
concurrent application processes with exactly one winner, changed
pre/postimages, active/foreign/altered runs, links, redirection, protected-root
overlap and damaged records. An owned syscall interposer kills the operator at
the actual pre/post-rename boundary and after a visible receipt is synced, and
injects directory/receipt sync errors.
Failed attempts and incomplete controls remain failures.

Public evidence contains sanitized results and exact source/binary/helper/report
hashes only. Private payloads, backups and authority are excluded. The
`edit_application_startup` integration regression shares the Linux cfg boundary
for command grammar and implementation and checks actual startup on the compiled
platform. Final shared Ready CI, CodeQL and exact-candidate admission remain owned
by the team lead; Draft fast checks alone are not merge qualification.
