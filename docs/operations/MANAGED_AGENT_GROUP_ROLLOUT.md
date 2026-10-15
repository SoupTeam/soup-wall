# Staged managed Agent group policy rollout (SOU-47)

An Owner can deploy an approved policy to a frozen Agent inventory in two waves: pilots, then standard workers. The existing signed bundle and authenticated Agent acknowledgement contract is unchanged. A matching `applied` acknowledgement, including Agent, sequence, revision and digest, is required; issuance, delivery and process health do not satisfy a gate.

## State transitions

| State | Accepted transition |
| --- | --- |
| `pilot` | Exact pilot ACKs → `standard`, or `completed` for a pilot-only group |
| `standard` | Exact worker ACKs → `completed` |
| `pilot` / `standard` | Owner pause → `paused`; rejection/deadline → `rolling_back`; supersession/revocation → `failed` |
| `paused` | Owner resume restores the saved wave and evaluates its existing gate |
| Active or `completed` | Owner rollback → `rolling_back` when restorable baselines exist |
| `rolling_back` | All exact baseline ACKs → `rolled_back`; unresolved baselines, supersession, rejection or rollback deadline → `failed` |

Acknowledgement deadlines are 300 seconds from deployment issuance. Gate evaluation uses the persisted ACK timestamp: a late ACK cannot reopen an expired gate, while a timely ACK remains valid if the operator evaluates it later. ACK processing and explicit Owner `advance` evaluate transitions; GET reports an overdue Agent without issuing deployments. An entirely offline fleet requires the operator to call `advance` to process its expired deadline. A stopped gate is never bypassed by elapsed time or restart. If no affected Agent has a restorable baseline, manual rollback refuses the request rather than claiming restoration.

A group cannot be deleted during `pilot`, `standard`, `paused` or `rolling_back`. Live membership changes do not change the persisted rollout inventory or its ACK routing. Failed/rolled-back plans remain inspectable; terminal `advance` and retry behavior never allocate another deployment.

## Transaction ownership and retry behavior

Start freezes pilot/worker membership, the approved candidate digest, each Agent's initial deployment sequence and its last acknowledged applied baseline revision. The entire inventory is validated before deployment writes. Existing immutable per-Agent revisions must match the candidate and be approved. Standard Agents are checked again before promotion, including whether their individual deployment sequence changed after plan creation.

SQLite uses one `BEGIN IMMEDIATE` transaction per start, advance, pause, resume or rollback. Revision writes, signed deployment insertion and the persisted sequence map commit together. Independent store handles and Console processes share the database writer lease.

PostgreSQL uses one transaction and an exclusive tenant-row lease per orchestration transition. Individual deployment/ACK/revision operations take a shared tenant lease and the Agent enrollment lock; revocation and group membership mutations also participate in tenant locking. Competing plans in the same tenant cannot pass an overlapping-inventory check concurrently. These locks deliberately serialize orchestration within one tenant. All issuance helpers use the caller's transaction and connection; an issuance/signing/storage failure leaves neither a partial wave nor a partially persisted plan.

Repeating start for the same active candidate and issuer returns the same rollout and deployment identities. A paused start or a different active candidate is a conflict. Repeating pause, resume or pending/confirmed rollback preserves the existing state and sequences. A failed start transaction can be retried because it left no plan or orphan deployments. A repeated standard-wave transition cannot allocate an extra sequence. A retry after rollback considers only the current deployment's acknowledgement state; an older superseded unacknowledged candidate does not block a new plan.

Rollback creates new, higher-sequence signed deployments of the frozen approved baselines. The cohort includes only Agents that received candidate deployments after this plan's initial sequences. Baseline-free Agents remain explicitly unresolved; successful restoration of other Agents cannot turn that into `rolled_back`. Rollback never silently adopts a newer baseline from later deployment history.

## Operator API and status

Use `x-llm-firewall-admin-token: Bearer <token>`. All group mutations require Owner; Viewer and Operator can inspect, and Agent credentials cannot authorize an admin operation. Tenant and Agent identity checks remain in the storage and authentication layers.

| Method | Endpoint suffix under `/admin/v1/tenants/:t/groups` |
| --- | --- |
| POST / GET | Create/list groups at the collection |
| GET / DELETE | `/:g` |
| POST / GET | `/:g/members` |
| DELETE | `/:g/members/:agent` |
| POST / GET | `/:g/revisions` |
| POST | `/:g/revisions/:revision/approve` |
| POST / GET | `/:g/rollout` |
| POST | `/:g/rollout/advance`, `/pause`, `/resume`, `/rollback` |

Create/start requests retain their existing bodies, for example `{"revision":"v2","issuer_key_id":"optional-key-id"}`. Identical successful start retries retain the original HTTP 201 response and identity. GET and transition responses include the frozen plan and an `agents` map containing expected/latest sequences, acknowledgement deadline, state and last matching acknowledgement metadata. States include `not_issued`, `pending`, `overdue`, `applied`, `rejected`, `conflict`, `revoked` and `unresolved_baseline`. The view is read from one database snapshot; it contains no signing seeds, credentials or policy YAML.

## Migration and encrypted recovery

PostgreSQL migration **27** provisions the four group tables and preserves existing group-enabled v26 databases. `initial_sequences_json` records the frozen sequence inventory; `plan_sequence` supplies deterministic latest-plan ordering even when multiple plans were created in one second. Runtime group operations perform no DDL. Existing v26 group rows are retained. Plans predating the frozen inventory are refused progression with an explicit legacy-plan failure; an operator must inspect and request a baseline rollback rather than allowing an ambiguous old wave to advance.

SQLite retains its native core schema contract and lazily provisions new group tables. Existing group-enabled stores add the snapshot column transactionally when opened; fresh and upgraded DDL match the strict recovery inventory. An older active plan without a snapshot has the same fail-closed progression behavior as PostgreSQL.

The versioned recovery inventory includes all **47 SQLite tables** (lazy managed tables remain optional as complete dependent sets), **48 PostgreSQL tables** and **8 PostgreSQL sequences**. Migration numbers, columns, native logical DDL, dependencies and populated private state are checked exactly. Unknown, partial, future and tampered schemas are refused. No table or protection is skipped to make recovery pass.

New archives use schema contract 27 and its inventory. Older schema-26 archives require their matching recovery tool/inventory to restore to a fresh target first; then run the normal migration before making a new backup. This tool does not silently migrate or reinterpret an older archive during restore. Signing/trust material remains outside database archives.

## Reproduction and evidence

```sh
cargo test -p llm-firewall --test managed_group_rollout --test managed_group_atomic
SOUP_GROUP_TEST_POSTGRES_URL='<owned disposable PostgreSQL URL>' \
  cargo test -p llm-firewall --test managed_group_atomic \
  postgres_atomic_restart_and_concurrency -- --ignored
python3 -m unittest discover -s scripts/tests -p 'test_console_recovery*.py'
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

`managed_group_rollout` covers HTTP/authorization and rollout regressions. The shared SQLite/PostgreSQL controls inject failure on the second pilot, second standard worker and second rollback deployment; race independent store handles and competing overlapping groups; reopen persisted plans; check retries, superseded workers, bounded deadlines, rollback rejection and populated legacy migration. The PostgreSQL control requires an explicit disposable database and also exercises a one-connection pool.

With native `age` and `age-keygen` on PATH, run the four-Agent SQLite witness:

```sh
python3 scripts/managed-group-rollout-demo.py
```

For PostgreSQL, supply **two owned disposable databases**, with an empty restore target. The source owner needs the existing recovery inspection permissions (`pg_monitor`); use the normal migrations. `psql`, `pg_dump` and `pg_restore` must match the server's supported major version. The fixture uses literal-loopback URLs; it does not establish production TLS or multi-host certification.

```sh
export SOUP_GROUP_DEMO_DATABASE_URL='<owned disposable source URL>'
export SOUP_GROUP_DEMO_RESTORED_URL='<owned empty restore-target URL>'
python3 scripts/managed-group-rollout-demo.py --backend postgres
```

Each live witness starts one Console and four actual Agent daemons. It observes deny → allow → deny through authenticated `/hook`, an offline pilot keeping workers on baseline, wrong-digest/stale/wrong-Agent ACK refusal, persisted pause, Console restart, full encrypted backup/restore, identical retry identities, confirmed manual rollback and automatic rollback after rejection of an unpinned signer. It records source/configuration/binary identities, outcomes and process cleanup, without retaining credentials or signing material.

Current retained outcomes are `docs/operations/evidence/managed-policy-group-rollout-{sqlite,postgres}-atomic-2026-10-15.json`; the earlier three-Agent report is historical. `.github/workflows/managed-group-rollout.yml` runs both store controls and both live/recovery witnesses on each relevant PR head. Review approval and production acceptance remain separate from these local fixture results.
