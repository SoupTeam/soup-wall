# SOU-219 evidence: retry-safe individual managed deployment issuance

Base: `2a5bf6771c63c6ccf2c55d07dede512a72f26481` (accepted `main`). Scope: the individual
`POST .../revisions/{revision}/deploy` issuance only. Signatures, approval/ACK rules, enrollment,
the group rollout state machine and heartbeats are unchanged. This file records local runs by the
author; it claims no CI, CodeQL or acceptance result. Final Ready CI, candidate admission and merge
are lead-owned.

## What was run locally (macOS, exact working tree of the PR head before this ledger commit)

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | 0 warnings |
| `cargo test -p llm-firewall` (all unit and integration binaries, SQLite) | all passed, 0 failed |
| `cargo test -p llm-firewall --test managed_deployment_idempotency` | 2 passed, 1 ignored (PostgreSQL, see below) |
| same, `-- --include-ignored` with `SOUP_DEPLOY_TEST_POSTGRES_URL` set | 3 passed, run twice against one persistent database |
| `python3 scripts/ci_components.py --check`, `python3 scripts/check_docs.py` | clean |

## Console recovery inventory (found by the first focused CI run)

The first focused run (`41711423094`, source `8420894d`) passed this PR's SQLite and PostgreSQL controls but failed the
existing step `Four real Agents with encrypted SQLite recovery`: the versioned recovery inventory
(`scripts/fixtures/console_recovery_inventory_v1.json`) is a strict allowlist of tables, DDL digests and PostgreSQL
migrations 1 through N, and the new table was not in it. Following the SOU-55 precedent, the next commit adds the table
to the SQLite and PostgreSQL inventory, raises the accepted schema version from 28 to 29 in `console_recovery.py`, its
acceptance driver, unit test and `CONSOLE_RECOVERY.md`. The fixture entries were generated from live catalogs, not by
hand: the SQLite digest from SQLite itself, the PostgreSQL entries from the recovery tool's own `logical_schema()` on a
database migrated by this branch, and the generator refuses to write unless every pre-existing entry is identical to the
accepted fixture. Local checks: `inspect_sqlite` accepts a real database created by this branch's Console that contains a
key row; `scripts/tests/test_console_recovery.py` passes (8 tests need `age`, which is not installed locally, and are skipped).
The encrypted backup/restore demos themselves have not been run locally; the re-dispatched workflow is the evidence.

## Focused CI result on PostgreSQL 16 (workflow_dispatch, no full matrix)

`managed-group-rollout.yml`, run `41712688294`, exact source `a52ab1914e107b0e1097a1943d4e46037101c30e`, **passed**: the SQLite
regressions including `managed_deployment_idempotency`; the existing PostgreSQL fault/concurrency controls; the new step
`Run individual deployment idempotency controls over HTTP on PostgreSQL`; and both existing real-Agent demos with encrypted
SQLite and PostgreSQL recovery (which exercise the updated recovery inventory). The earlier run `41711423094` (source
`8420894d`) failed only the SQLite recovery step for the inventory reason above and is kept, not relabelled. The local
PostgreSQL 14 caveat below therefore no longer limits the PostgreSQL claim for this source; this is not a full Ready CI,
CodeQL or admission result. Later commits that change only this ledger are not re-qualified.

## Explicit skip and caveat: PostgreSQL

The local database was PostgreSQL **14.17** (no newer server installed, host left unchanged).
The existing migration contains the literal `841_337_611`, which PostgreSQL 16 accepts and 14 rejects, so
the migration cannot run on 14 unmodified. For the local PostgreSQL run only, that one literal was
replaced in the working tree and reverted with `git checkout` before every commit; it is not part of this
PR. CI uses PostgreSQL 16 (`managed-group-rollout.yml` service). The PostgreSQL result on a 16 server
is therefore **not yet observed** by the author; the workflow step that will produce it is
`Run individual deployment idempotency controls over HTTP on PostgreSQL`.

## Controls (`crates/proxy/tests/managed_deployment_idempotency.rs`)

Real TCP listener, `reqwest` client. Rows, keys and sequences are counted with direct SQL, deliveries
through `GET /agent/v1/policy` (the response bytes are hashed and compared with the envelope hash the
POST reported).

| Cause | Control |
| --- | --- |
| Lost response | request sent on a raw socket, closed after the commit is visible without reading the answer; retry returns sequence 1, same `issued_at_unix`, expiry and envelope hash; one row, one key, one delivery |
| Parallel callers | 16 concurrent callers, one key: exactly one `replayed:false`, one row; 8 distinct keys in parallel yield sequences 2..9 with no gap |
| Conflict | other revision, rollback flag, requested signer, other administrator: 409, no row, nothing from the original in the body; same text in another tenant is a separate key |
| Invalid keys / compatibility | short, long, bad charset, non-ASCII and repeated header: 400, no row; 8 and 128 byte keys accepted; keyless calls still issue a new sequence each time and add no `idempotency` object |
| Failure before commit | trigger makes the key insert fail: 400, zero deployment rows and zero keys, nothing deliverable; same key then issues sequence 1 |
| Crash/restart after commit | server task aborted, storage reopened, retry replays; with the signing seed removed a replay still works while a new key is refused with nothing numbered |
| Authorization | bad credential 401, viewer/operator 403, revoked administrator 401, revoked administrator rejected inside the store transaction (separate control), inactive tenant and revoked Agent 400 with no stored result returned |
| Historical retry | after sequence 2 exists, replaying sequence 1's key returns sequence 1 with current status `applied`, sequence 2 stays the pending one, max sequence stays 2; an expired envelope is returned with its original expiry |
| Older database | SQLite file without the key table gains it on first use |

## Mutation checks run by the author

Removing the in-transaction administrator recheck and ignoring the stored intent each make the
suite fail. Ignoring only the stored administrator comparison does not, because the administrator is
part of the intent digest too; that is deliberate redundancy.

## Known limits

An `issuer_key_id` that names the default signer explicitly is a different intent from omitting it.
A replay does not verify that the signing key is still trusted by the Agent keyring; the Agent
verifies the envelope itself. Keys are kept as long as their deployment rows.
