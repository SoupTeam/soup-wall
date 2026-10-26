# Completed prepared-run archival

This Linux entry point owns only completed runtime audit state. It does
not remove prepared binaries/generations, stop processes, rotate live audit
stores, or change launcher/stop/recovery semantics. The
[native qualification report](evidence/prepared-run-operations/README.md) records
genuine prepared-run state and controlled adversarial lifecycle cases.

Start with an existing private mode-0700 archive directory outside the selected
run directories. Save the read-only preview in that directory with mode 0600:

```sh
umask 077
python3 -B scripts/pilot-run-archive.py preview \
  --state-parent /absolute/state --run-id EXACT_RUN_ID \
  > /absolute/private-archives/plan.json
```

Preview writes only JSON to stdout. It accepts one to eight explicit unique run
IDs, optionally with `--minimum-age-seconds N` (up to one year). Age is an
owner-editable finished-file mtime filter, not authenticated retention policy.
Inspect `runs`, `excluded`, and `plan_sha256`. Only the exact
`audit`, `audit-run.json`, `audit-finished.json` layout is eligible. Active,
incomplete, linked, foreign, replaced or unexpected state is excluded; stop
receipts, credentials and remaining runtime authority always prevent eligibility.
The accepted empty `audit/writer.lock` file is included in the inventory and
private archive. Preview checks its existing advisory lock without creating or
rewriting the file. Archive and apply hold its exclusive nonblocking lock for
the entire operation; a live audit writer refuses cleanup. Directory generations
and individual file identities/bytes bind a preview, including rename-away-and-
back changes before apply.
Preview never searches or recursively traverses unrelated directories.

Create an explicit private archive using the preview's digest:

```sh
python3 -B scripts/pilot-run-archive.py archive \
  --plan /absolute/private-archives/plan.json --confirm EXACT_PLAN_SHA256 \
  --archive-directory /absolute/private-archives
```

Plans expire after 15 minutes. The archive contains exact selected source bytes,
file inventory/hashes, source/selection/run identities, and a bounded raw export
from the accepted retention exporter. Loss/pruning/partial-tail metadata is
retained. Corrupt, missing, malformed, oversized or interrupted audit evidence
refuses archival. Archives contain private audit data and must remain private;
nothing is uploaded automatically. Terminal output contains only finite outcomes,
selected IDs, archive filenames and hashes.

Archive publication uses exclusive mode-0600 creation, fsynced bytes, atomic
no-replace publication and directory fsync. Completed archives are reopened and
verified against every selected source member. Failed or uncertain publication
never permits source deletion. A private `.pending` file may remain after a
failure; it is not a completed archive. Repeating archive is accepted only when
the existing archive exactly matches the fresh verified bytes.

Explicitly apply the same fresh plan only after reviewing the archive result:

```sh
python3 -B scripts/pilot-run-archive.py apply \
  --plan /absolute/private-archives/plan.json --confirm EXACT_PLAN_SHA256 \
  --archive-directory /absolute/private-archives
```

Apply verifies all selected archives and current inventories before starting.
It rechecks each run, exclusively detaches the selected directory into an owned
private `.soup-wall-cleanup-…` quarantine in the selected parent, and revalidates
the detached inventory. Reappearance of the original run name refuses further
removal. Each original file descriptor stays open across exclusive staging and
the staged identity/byte checks before descriptor-relative unlinking. Links are
never followed and parent
roots are never removed. An unexpected member, changed bytes or replaced inode
refuses further work. The command never recursively removes arbitrary paths.

`archived_and_removed` means this invocation completed the selected removal.
`archived_source_retained` means an archive was verified and the source remains.
`retained` means apply stopped before detaching the source. `partial` means a
source namespace or some members changed during this invocation; remaining data
is retained in the reported quarantine, together with the complete archive.
Partial is not rollback. A repeated apply against missing state fails; absence
is not proof that this command removed it. Previously successful run outcomes
must be considered independently if a later run refuses.

If the source was removed but a final durability check failed, the outcome is
`unknown` with `source_state: removal_durability_unverified`. Preserve the
archive and inspect the reported paths; this result promises neither durable
completion nor restored source state.

Every removal quarantine receives a private, fsynced `cleanup.json` journal
before the source is detached. After a crash or interruption, inspect it using
the same plan and digest (inspection accepts an expired plan):

```sh
python3 -B scripts/pilot-run-archive.py inspect \
  --plan /absolute/private-archives/plan.json --confirm EXACT_PLAN_SHA256 \
  --archive-directory /absolute/private-archives \
  --quarantine .soup-wall-cleanup-EXACT_32_HEX_SUFFIX
```

Inspection is read-only and verifies the journal, complete archive, and remaining
member identities/hashes. It reports retained/partial/unknown state and finite
counts. Missing members never prove completion; unexpected/replaced members
remain unknown. The archive and all remaining state stay in place. SIGINT and
SIGTERM produce finite failure/partial outcomes; SIGKILL recovery uses the journal.

Do not automatically remove a quarantine or copy its remaining contents back.
Preserve it and the verified archive for inspection. Resume/interruption recovery
is deliberately conservative; there is no automatic purge
or recovery of partially removed state.

Preview exits 0 when every selected run is eligible, 2 when any is excluded.
Archive exits 0 only after verification. Apply exits 0 only when all eligible
selected runs were removed; partial/retained outcomes exit 2. Invalid plans,
unavailable archives or changed preflight selections exit 1. An excluded run is
always reported separately and is never silently removed.
An inspect command exits 0 for a verified read-only inspection; its `outcome`
still distinguishes retained, partial and unknown and never asserts removal.

The native report covers genuine completed-run archival/removal, active and
retained-stop exclusion, real foreign ownership, changed plans, three concurrent
replacement races, corrupt/oversized audit, failed archive publication,
interrupted deletion with read-only inspection, and repeated apply. Fixture
regressions separately exercise finite outcomes and additional malformed inputs.
Final CI admission and main integration remain the maintainer's responsibility.
