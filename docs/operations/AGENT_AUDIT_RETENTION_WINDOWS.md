# Bounded Agent audit retention on Windows

Windows can opt into the same version 1 JSONL segment and manifest format as
Linux. The default remains the legacy single `audit.jsonl` file. macOS retention
is unsupported. This Windows implementation supports directly mapped **local
NTFS** volumes under a non-elevated standard account. UNC, network, redirected
drives, reparse points, junctions and other filesystems are refused.

## Configure

Create a dedicated profile on local NTFS and set `audit_retention` in its
`config.yaml`. Do not also set `audit`:

```yaml
audit_retention:
  version: 1
  directory: 'C:\Users\operator\.agentfw\audit-retention'
  segment_size_bytes: 65536
  segment_count: 4
  total_disk_bytes: 512000
  max_record_bytes: 4096
```

Use the actual account's local profile path. The Agent creates a missing store
directory with a protected DACL granting access only to that user and Local
System. Existing directories, manifests, segments and lock files must already
have the expected owner and private protected DACL; startup does not repair or
adopt unsafe state. Limits are mandatory and pinned in the manifest. Changing
them requires an offline export and a new empty store. Segment size is 64 KiB
to 16 MiB, count is 2 to 64, record size is 256 bytes to 64 KiB, and the cap
must cover all configured segments plus 132 KiB of metadata, up to 1 GiB.

Writes are synchronous and bounded. A single writer owns `writer.lock` with
exclusive Windows sharing. The manifest records segment order, SHA-256 digest
for closed segments, `pruned_through`, and a pending prune. Only a verified
closed owned segment is removed. Foreign files are left alone. The local hashes
detect accidental corruption; they cannot authenticate history against its
owner. This is private local evidence, not remote tamper proof logging.

## Failure and recovery

`GET /health` exposes `audit.mode`, `audit.state`, retained count and
`pruned_through`, with a path-free `audit_unavailable` reason on failure. A
failed or short write makes the running sink unavailable until explicit offline
recovery. Native call admission and result release require their audit write;
they refuse when it fails. Existing host hook behavior still does not promise a
durable audit line after a hook Allow.

Stop the daemon, fix the storage condition, then run:

```powershell
& .\agentfw.exe audit-retention-recover --home 'C:\Users\operator\.agentfw'
```

Recovery takes the same exclusive writer ownership. It completes a valid
pending manifest publication or planned prune, verifies every retained segment
and seals an incomplete active tail as `partial_tail: true` before opening a
new segment. It does not truncate uncertain bytes, rewrite a corrupt manifest,
delete an unrecognized file, or reset live session taint or receipts. Missing
or changed closed segments and unsafe ownership/ACL/path state require private
operator inspection. Back up uncertain files before manual repair. Restart
the daemon only after recovery succeeds.

The backend flushes segment data and staged manifests and uses a handle-bound
same-directory rename. An ordinary process interruption is recoverable from
the manifest protocol. Windows storage devices and firmware may still delay or
lose acknowledged writes after sudden power loss; neither the manifest nor its
hashes provide a power-loss or adversarial integrity guarantee.

## Export and browse offline

The existing report script verifies the private store and writes a **new**
private JSONL export outside it. The same allowlist and offline HTML viewer
then project the raw export:

```powershell
python scripts/agent-audit-report.py --retained-dir 'C:\Users\operator\.agentfw\audit-retention' --output 'C:\Users\operator\audit-review\export.jsonl'
python scripts/agent-audit-report.py --input 'C:\Users\operator\audit-review\export.jsonl' --output 'C:\Users\operator\audit-review\report.html'
```

The export creates a missing output directory with a private DACL and refuses
an existing output file. `--from-segment`, `--to-segment`, `--from-ms` and
`--to-ms` select inclusive ranges. The report labels intentional pruning,
missing or corrupt segments, interrupted publication, incomplete tails and
selected ranges separately. Raw export and private daemon logs may include
sensitive content; share only a sanitized summary. The HTML makes no network
requests. An Allow record does not prove that a tool executed.

## Reproduce native acceptance

Build the Windows Agent and run the one-command acceptance as a non-elevated
standard user on local NTFS:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP 'sou95-target'
cargo build --locked -p agentfw --bin agentfw
$artifacts = cargo test --locked -p agentfw --lib --no-run --message-format=json | ConvertFrom-Json
$nativeTests = $artifacts | Where-Object { $_.reason -eq 'compiler-artifact' -and $_.profile.test -and $_.target.kind -contains 'lib' } | Select-Object -Last 1 -ExpandProperty executable
python scripts/sou95_windows_owned_acceptance.py --agent "$env:CARGO_TARGET_DIR\debug\agentfw.exe" --native-test-binary $nativeTests --output-dir "$env:TEMP\sou95-acceptance"
```

Set `CARGO_TARGET_DIR` to a local NTFS build directory and point both arguments
to the binaries built from the candidate source. The acceptance retains private raw evidence under a new
output directory and prints counts and SHA-256 identities. It requires the
installed native self-test to execute every supported scenario, exercises real
daemon hook records through multiple rotations and restarts, checks duplicate
writer refusal, interrupted rotation recovery, foreign-file preservation,
private export, selected/missing/corrupt/partial gap display and independently
measured owned disk bytes. It also executes focused native tests for sticky
short writes, partial-tail recovery, and audit failure before native admission
and result release.
Do not treat a skipped positive or a failed native control as a pass.
