# Encrypted Console recovery (SOU-49)

This procedure extends the existing [PostgreSQL restore drill](STAGING_DRILLS.md#encrypted-postgresql-restore)
and [populated restore fixture](STAGING_DRILLS.md#populated-local-restore-fixture)
with the current managed Agent state and actual behavior after restoration.
It is a bounded internal recovery candidate; independent review and intended-environment
operator acceptance are required. No customer or default database is used by the fixture.

## Supported state and limits

The [versioned inventory](../../scripts/fixtures/console_recovery_inventory_v1.json)
binds format 1 to accepted schema source `4f428e4b983111e5b2480e40d658628e3d198fe7`.
PostgreSQL requires exactly migrations 1 through 26. SQLite has no native migration
version; the inventory binds its native table/column layouts, indexes, triggers and
expected PRAGMA versions, including lazily created managed Agent tables when present.
Unknown schemas require an explicit compatibility review, including future fleet tables.

The archive contains every native table and sequence: tenants, principals, memberships,
active/revoked credentials, approved policies, immutable Agent revisions, enrollment
credential hashes, signed deployment sequence/status/acknowledgements, security events,
webhook destinations, retry/lease ownership and usage/identity state. Comparison is
private full-row and sequence equality; counts alone cannot pass recovery.

Keep operator settings **separate**: Console admin credentials, policy issuer seeds,
Agent trust keyrings and durable active-policy caches, webhook signing key, database TLS
settings, and the external age decryption identity. Database recovery does not create
or alter a trust root. Restore to a separate target; preserve the existing Agent homes.

The supported operator tool is POSIX Python 3.10+, native `age`/`age-keygen`, and matching
PostgreSQL 16 `psql`/`pg_dump`/`pg_restore` for the tested database scope. The fixture also
uses Docker and the existing TLS fixture dependency `cryptography==50.0.2`. Windows
secret-bearing recovery is refused until its ACL boundary is implemented and verified.
Use [official age installation instructions](https://github.com/FiloSottile/age#installation).
No model/provider access is needed.

## Operator commands

Run from the reviewed source. Use existing protected operator identities, approved
recipients and secret-manager environment variables; do not paste credentials into
command arguments or shell history. All selected files must be regular, unlinked,
operator-owned `0600` files below real operator-owned `0700` parents. Choose new archive
and target paths. Do not change another account's permissions to make validation pass.
Keep the encrypted archive receipt hash separately and compare it before restoration.
Age protects ciphertext integrity and confidentiality to a recipient; it does not
authenticate the producer. Restore a known operator-created backup, never an
untrusted party's re-encrypted archive.

```sh
mkdir -m 700 /path/to/owned-recovery
mkdir -m 700 /path/to/owned-recovery/scratch
python3 scripts/console-recovery.py backup --backend sqlite \
  --database /path/to/private/source.sqlite \
  --archive /path/to/owned-recovery/console.age \
  --recipient age1_REPLACE_WITH_APPROVED_PUBLIC_RECIPIENT \
  --workdir /path/to/owned-recovery/scratch
python3 scripts/console-recovery.py restore --backend sqlite \
  --database /path/to/owned-recovery/recovered.sqlite \
  --archive /path/to/owned-recovery/console.age \
  --identity /path/to/separate-private-keys/recovery-identity.txt \
  --workdir /path/to/owned-recovery/scratch
```

SQLite uses the online backup API, so committed WAL state is included. The target
and its WAL/SHM/journal sidecars must not exist, even as empty files. Symlinks,
hardlinks, source aliases, unknown schema objects, malformed inventories and
unauthenticated/incomplete encrypted archives are refused before target creation.

For PostgreSQL, stop all Console replicas, dispatchers and other database clients
before backup and restore. Use an explicitly selected fresh database owned by a
non-superuser recovery role; grant the reviewed read-only `pg_monitor` role so actual
cluster/database identity can be established. The tool does not create databases,
terminate clients, change grants or run migrations. Provision roles/targets separately.
Remote URLs require verified TLS; the plaintext exception is literal loopback only.

```sh
# SOURCE_RECOVERY_URL and FRESH_RECOVERY_URL are populated by your secret manager.
python3 scripts/console-recovery.py backup --backend postgres \
  --database-url-env SOURCE_RECOVERY_URL --source-quiesced \
  --archive /path/to/owned-recovery/console-pg.age \
  --recipient age1_REPLACE_WITH_APPROVED_PUBLIC_RECIPIENT \
  --workdir /path/to/owned-recovery/scratch
python3 scripts/console-recovery.py restore --backend postgres \
  --database-url-env FRESH_RECOVERY_URL \
  --archive /path/to/owned-recovery/console-pg.age \
  --identity /path/to/separate-private-keys/recovery-identity.txt \
  --workdir /path/to/owned-recovery/scratch
```

The actual cluster system identifier and database OID refuse aliases even when URLs
have different spellings. Populated targets or targets with unexpected schema objects
are refused. Restore uses one strict transaction, without `--clean`, compatibility SQL
rewrites or application startup. Any non-success receipt means **do not start Console**.
Treat a failed target as quarantined until the operator investigates or replaces it.
Temporary plaintext dump/archive files are removed on success and failure. Deletion
is logical cleanup, not a claim of secure erasure on SSDs or snapshot storage.

After a successful private inventory comparison, stop the original source Console,
point the recovery Console configuration at the explicit verified target, separately
supply the unchanged operator signing settings, and start only that Console. Check
retained and revoked identities, Agent inventory, actual hook policy and a new approved
higher-sequence deployment with matching authenticated acknowledgements. A downloaded
bundle or a row marked delivered is insufficient. Do not run startup as a migration
or issue policy until these checks succeed. Keep the old source dispatcher stopped
through restored delivery, preventing two copies from dispatching the same queue.

## Stale backups

A running Agent may have accepted a deployment newer than the restored database.
It must retain that durable active policy and refuse lower/equal conflicting sequences.
The fixture records the restored sequence, actual Agent sequence, rejected deployment,
stale transport state and live hook decision; its negative result is explicitly
`recovery_complete: false`. Stop the stale recovered Console and recover a current
snapshot. Do not reset Agent counters, delete caches, manufacture acknowledgements or
change issuer trust to make recovery look successful. Automatic point-in-time
reconciliation and a new signing epoch require a separate reviewed procedure.

## Reproducible real-process witness

The command is inert without `--run`. It creates fresh owned resources, two tenants,
retained/revoked service and Agent credentials, approved policies, pending retry and
in-flight lease rows, two actual Agent processes and the actual Console. Retry/lease
metadata is explicitly seeded synthetic stopped-dispatcher state. The archive still
must preserve every original row and sequence exactly before any runtime exercise.

```sh
cargo build --locked -p llm-firewall --bin llm-firewall --example console-recovery-fixture -p agentfw --bin agentfw
cargo test --locked -p llm-firewall --example console-recovery-fixture
cargo test --locked -p llm-firewall --lib --no-run --message-format=json > /path/to/private/build.jsonl
# Select the llm_firewall lib-test executable reported in build.jsonl.
python3 scripts/console-recovery-acceptance.py --run --backend sqlite \
  --output /path/to/public-outcomes/sqlite.json \
  --webhook-driver "$PWD/scripts/console-recovery-webhook-fixture.py" \
  --outbox-test-binary /absolute/path/to/llm_firewall-lib-test
python3 scripts/console-recovery-acceptance.py --run --backend postgres \
  --output /path/to/public-outcomes/postgres.json \
  --webhook-driver "$PWD/scripts/console-recovery-webhook-fixture.py" \
  --outbox-test-binary /absolute/path/to/llm_firewall-lib-test
python3 -m unittest discover -s scripts/tests -p 'test_console_recovery*.py' -v
```

Use explicit `--console-binary`, `--agent-binary`, `--fixture-helper`, `--psql`,
`--pg-dump` and `--pg-restore` paths for non-default build/tool directories. The Linux
[CI workflow](../../.github/workflows/console-recovery.yml) builds the exact PR head,
runs both backends, and uploads only sanitized outcomes, including failures. It does
not cache secret fixture directories. Before the run, the driver declares its tested
120-second valid-restore-to-new-signed-ack objective; the separate webhook fixture
declares a 180-second bound. These are small-fixture objectives, not service RTO promises.

The positive path proves live **deny -> defer -> restored defer -> new signed deny**
with exact increasing sequences and matching acknowledgements on both Agents. It
restarts Console/database and an Agent cache, then proves stale-backup refusal before
returning to the current target. Default cleanup stops owned children and removes all
owned plaintext fixtures/container resources. `--retain-private-fixture` is explicit
diagnostic retention and prevents a complete-cleanup pass. Never publish that directory.
The sanitized report retains exact source/config/binary hashes, private equality
outcomes, API/hook/ack observations, failures, cleanup and measured durations.

### Restored webhook transport boundary

Production Console rejects local/private destinations and requires validated external
HTTPS. Those protections remain unchanged. A unit-test-only Rust fixture calls the
same native claim, HMAC/body sender and fenced completion on the restored database.
An explicit loopback adapter verifies the original event/delivery identity and HMAC,
then forwards a deterministic mapped event to the existing authenticated durable
[alert receiver](ALERT_RECEIVER.md). A missing receiver retains pending retry state;
a committed receiver effect with lost acknowledgement causes a duplicate network
attempt after receiver restart, which the durable receiver deduplicates. Native
backoff is waited, not shortened; the initial synthetic +1800s due time is advanced
explicitly as a fixture clock control.

This verifies restored outbox behavior and receiver durability at that bounded transport
seam. It **does not verify production external HTTPS delivery** and does not claim a
transaction spanning Console and receiver or exactly-once network delivery. The report
keeps that limitation machine-readable. It is not acceptance of SAML/OIDC interoperability,
remote Agent HTTPS, fleet reconciliation or release publication.

The [2026-10-15 current-state evidence](evidence/CONSOLE_RECOVERY_2026-10-15.md)
records both clean local runs, negative controls, limitations and exact source hashes.
