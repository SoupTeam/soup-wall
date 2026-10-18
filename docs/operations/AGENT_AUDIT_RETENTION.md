# Bounded Agent audit retention on Linux

The Agent can opt into private, bounded, synchronous audit segments. The default
remains the existing single `audit.jsonl` file. The new store is supported on
Linux only; an opt-in configuration on Windows or macOS is rejected at startup.
It retains the existing audit event bodies and the separate forensic raw-body
opt-in. It does not add payload capture, upload evidence, or make local files
tamper-proof against their owner.

## Configure

Add `audit_retention` to the installed profile's `config.yaml`. Do not set
`audit` at the same time. Choose a dedicated absolute directory on a native
Linux filesystem; it is created with mode `0700` if absent. Existing directory
and files must be owner-only and owned by the Agent user.

```yaml
audit_retention:
  version: 1
  directory: /home/operator/.agentfw/audit-retention
  segment_size_bytes: 65536
  segment_count: 4
  total_disk_bytes: 512000
  max_record_bytes: 4096
```

There is no default opt-in. Limits are mandatory. Supported segment sizes are
64 KiB to 16 MiB, counts 2 to 64, and serialized records 256 bytes to 64 KiB.
The total cap must cover `count × size + 132 KiB` of metadata and must not
exceed 1 GiB. The example allows four 64 KiB segments plus the manifest,
pending manifest and lock; actual owned bytes stay below 512,000. A record
larger than the configured record or segment limit is refused before a large
serialization allocation. The sink uses a mutex and synchronous writes; it has
no asynchronous queue. Tune the record bound to cover actual native records,
including findings, without using it as a way to capture arbitrary raw data.
The manifest pins these four limits; changing them in place is refused. To
change limits, stop the daemon, retain or export the old directory privately,
and configure a new empty dedicated directory.

The Agent retains at most `segment_count` segments. Rotation syncs the old
segment, publishes its digest and order in `manifest.json`, and reserves a new
segment. Once full, only the oldest **closed, positively owned** segment is
pruned. `pruned_through` records intentional loss of earlier evidence. The
manifest is a crash-recovery checkpoint and detects accidental change to
closed segments. Its SHA-256 values do **not** authenticate the records against
an owner who can edit both segment and manifest. Do not mix this directory with
operator files. A second independent Agent writer is refused by an exclusive
nonblocking lock.

## Inspect health and recover

`GET /health` includes `audit.mode`, `audit.state`, retained segment count and
`pruned_through`. An unavailable sink reports only `audit_unavailable`; no raw
path, credential or payload is returned. Legacy mode reports `unverified`
because its historical hook write contract does not track sink health.

The bounded sink validates directory and file identities on open and before
each write. Symlinks, FIFOs, replaced paths, unsafe modes, changed closed
segments and missing retained segments stop writes or startup. A short or
failed write poisons the running sink. Native admission and result release
then fail with `native_audit_unavailable`; a successful native release is not
returned without its required audit write. Existing host hooks still ignore
audit write errors, as before. A hook Allow therefore does not guarantee a
durable audit line or execution. Monitor health and use the native boundary
when fail-closed audit evidence is required.

After fixing disk space or the underlying filesystem fault, stop the Agent and
run:

```sh
agentfw audit-retention-recover --home /home/operator/.agentfw
```

The command takes the same writer lock, verifies the retained files and
completes a valid interrupted manifest publication or planned prune. A partial
active tail is **kept**, sealed with `partial_tail: true`, and a new segment is
opened; the incomplete record is not silently treated as a successful event.
Restart the Agent only after recovery succeeds. Corrupt manifests, changed or
missing closed segments and unsafe path identities require operator inspection
and repair from a trusted backup. The command never truncates a segment or
deletes an unrecognized file. Save private copies of uncertain evidence before
repair. Recovery does not reset session taint, receipts or risk state while a
daemon is running; it is an offline storage operation followed by an explicit
daemon restart. That restart has the Agent's normal session lifecycle semantics.

## Export and browse

Create a fresh private directory outside the retained store. The export
command verifies segment order, owner/type/path identity, closed-segment
lengths and digests, then creates a new mode `0600` JSONL file. The optional
inclusive segment and UTC millisecond ranges select only retained evidence.

```sh
mkdir -m 700 "$HOME/agent-audit-review"
python3 scripts/agent-audit-report.py \
  --retained-dir "$HOME/.agentfw/audit-retention" \
  --from-segment 3 --to-segment 6 \
  --output "$HOME/agent-audit-review/export.jsonl"
python3 scripts/agent-audit-report.py \
  --input "$HOME/agent-audit-review/export.jsonl" \
  --output "$HOME/agent-audit-review/report.html"
```

`--from-ms` and `--to-ms` can additionally select event timestamps. Export is
bounded to 16 MiB, 10,000 records and 64 KiB per line. It refuses unsafe input
paths and never overwrites a prior output. The export contains raw audit fields
and must remain private. The existing offline explorer applies its strict
allowlist and report-local aliases to that export. It shows intentional
retention, missing segments, failed verification, partial tails, unsupported
schema and missing native call/result links separately. A selected range or
limit is reported as incomplete evidence. The browser makes no network
requests. A complete selected report does not prove that every external tool
effect was captured, and an Allow decision does not prove execution.

## Reproduce the owned acceptance

Use an installed Linux Agent build on a native Linux filesystem:

```sh
cargo build --locked -p agentfw --bin agentfw
python3 scripts/sou84_owned_acceptance.py \
  --agent "$PWD/target/debug/agentfw" \
  --output-dir "$HOME/sou84-owned-acceptance"
```

The command runs real native MCP positive and negative controls through
`agentfw self-test --bounded-audit-retention`, then restarts the same profile's
daemon twice and sends synthetic hook events through the authenticated route.
It requires multiple rotations and pruning, checks the configured disk cap and
a declared 256 MiB RSS acceptance ceiling, and verifies the private export and
HTML projection. It saves raw workspaces, daemon logs, export, HTML and exact
binary/configuration SHA-256 identities in the owner-only output directory.
Do not publish those raw files. Publish only sanitized counts, hashes, source
commit, checked limits and failed outcomes. This controlled path has no live
model and does not certify complete external execution capture.
The [sanitized owned acceptance record](evidence/sou-84/README.md) retains the
candidate source, binary and configuration identities and the observed limits.
