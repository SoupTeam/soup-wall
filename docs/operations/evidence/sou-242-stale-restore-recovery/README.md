# SOU-242 acceptance: owner-confirmed stale-restore recovery

Base: accepted `main` `0a146beb` (includes SOU-241, #375), successor of
`8003fac2d271156e2229c8c15c6eddb98ee2da8e`. Tested source: commit `770afe18`
(clean tree), which includes the review fixes below. Procedure: [Stale-restore recovery](../../STALE_RESTORE_RECOVERY.md).

## Real Console and Agent

`scripts/console-stale-restore-acceptance.py` on one disposable Linux host:
Console on loopback, unchanged `agentfw serve` with the opt-in heartbeat
(5 s), the supported `console_recovery.py` encrypted backup and restore, and
Chromium.

| Backend | Result | Report |
| --- | --- | --- |
| SQLite | 46 of 46 checks passed | [sqlite-report.json](sqlite-report.json) |
| PostgreSQL 16.15, TLS with an owned CA, non-superuser owner | 48 of 48 checks passed | [postgres-report.json](postgres-report.json) |

Binary SHA-256 (both runs): `llm-firewall`
`916c1723fc499a1a81c653cf08136fd8bc446526526d062214a32b3f27ea5485`, `agentfw`
`d3adb299c4695c15f611d2a25cf8ae0420fb19427199a729e04b4756030c9706` (the
Agent is unchanged by this work).

Covered, in order:

1. The Agent applies #1 (`deny`); the quiesced Console is backed up.
2. The live Console issues #2 (`allow`); the Agent applies it (`defer`).
3. The backup is restored to a fresh target (PostgreSQL: then `migrate`).
4. Original negative reproduced: a new deployment at #2 is rejected by the
   Agent, which keeps #2 and `defer` (`recovery_complete: false`).
5. Refusals: Operator and Viewer 403, Agent credential 401, other tenant
   (`evidence_wrong_audience`), revoked enrollment, tampered policy, forged
   signature, replayed #1 evidence, unknown field, changed issuer key
   material (`evidence_signature_invalid`) and changed issuer key ID
   (`issuer_changed`, both by restarting the Console).
6. A valid preview writes nothing; a revision created after it refuses the
   confirmation (`state_changed`); a wrong phrase is refused.
7. Two concurrent confirmations create exactly one fence at #2.
8. Console restart after confirmation: the fence persists, the retry is
   idempotent (`replayed`), and the Agent is unchanged.
9. The normal deploy path issues #3 above the fence. The state stays `fenced`
   in every read until the record shows the Agent's authenticated `applied`
   acknowledgement, then `complete`; `/health` reports #3 and `/hook` `deny`.
   An `applied` ACK for #2 and a foreign credential ACK for #3 are refused;
   the same evidence cannot reopen recovery.
10. Console and Agent restart keep completion and the active policy.
11. Browser as Viewer and Owner: completed state, Owner-only controls, no
    browser writes or errors.
12. The recovery tool inspects the restored store with the fence row against
    the schema 33 inventory.

Measured on this small fixture: confirm 4 ms (SQLite) and 51 ms
(PostgreSQL); fence to applied acknowledgement 1.6 s and 0.2 s.

Screenshots: [Viewer, SQLite](sqlite-recovery-viewer.png),
[Owner, PostgreSQL](postgres-recovery-owner.png).

## Review fixes (independent review at `60cf217`)

- **P1, Owner revalidation.** A database-backed Owner authenticated by the
  middleware, then revoked while the request body was held, could still
  create a fence. The fence transaction now re-reads the administrator first
  (SQLite write lock; PostgreSQL `FOR SHARE`) and refuses with
  `owner_not_active` (403). Regression `*_confirm_revalidates_owner` holds the
  real request body on a TCP connection, revokes or demotes the Owner, then
  releases it: 403 and no fence, on SQLite and PostgreSQL; a live-Owner
  control on the same path reaches the evidence rules instead.
- **P2, lost confirmation response.** The panel reported "Recovery stays
  closed" when the fence was committed but the response was lost. It now
  separates a 4xx refusal from an unknown outcome, never repeats the POST,
  reads the durable state once and shows it, and says the outcome is unknown
  if that read fails. Browser regressions cover a committed fence with an
  aborted response (exactly one reconciliation read, state `fenced`) and a
  failed reconciliation read.

## Failed attempts, retained as notes

On the uncommitted tree, before the first reviewed source:

- SQLite run 1 stopped at `preview-valid`: the restored Console had issued #2
  (rejected by the Agent) and the first rule required evidence above every
  restored row, so the real case was refused. The rule now ignores restored
  rows this Agent rejected and issues above both; a unit test covers it.
- SQLite run 2 stopped at `wrong-phrase-refused`: the check used the stale
  preview, so `state_changed` came first. The check now uses the fresh one.
- SQLite run 3 stopped at `not-complete-before-ack`: a test race (the Agent
  applied before the first read). The check now pairs each state read with a
  following record read.

Their reports were overwritten and are not retained.

## Recovery baseline

`scripts/console-recovery-acceptance.py --run --backend sqlite`: 74 checks
passed, including the original stale-backup negative
([recovery-sqlite.json](recovery-sqlite.json)), on commit `770afe18`. The PostgreSQL recovery run
needs Docker, which was not available here; `console-recovery.yml` covers it.

## Other local checks

- Rust: `managed_stale_recovery` (scenario and Owner revalidation) on SQLite
  and a disposable PostgreSQL; unit rules; full `llm-firewall` suite (376
  passed); clippy and fmt clean.
- Browser fixtures: the recovery panel (7) and the existing history, triage,
  heartbeat, enrollment, rollout and single policy suites (91).
- Fast checks: CI contract, docs, release docs manifest and recovery unit
  tests. The publication admission check fails one test here only because the
  local clone is shallow (`published_object_unavailable`).
- Rust 1.97.0 locally, not the pinned 1.99.1. Final Ready CI, CodeQL and
  admission belong to the TL.
