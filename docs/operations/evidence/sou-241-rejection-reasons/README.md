# SOU-241 acceptance: Agent policy rejection reasons

Base: `origin/main` `d7567b93` (reviewed successor of accepted
`8003fac2d271156e2229c8c15c6eddb98ee2da8e`). Tested source: commit
`15076229` (clean tree). Contract: [Agent policy rejections](../../AGENT_POLICY_REJECTIONS.md).

## Real Console and Agent

`scripts/console-agent-rejection-acceptance.py` on one disposable Linux host,
Console on loopback, unchanged `agentfw serve`, Chromium as a Viewer.

| Backend | Result | Report |
| --- | --- | --- |
| SQLite | 36 of 36 checks passed | [sqlite-report.json](sqlite-report.json) |
| PostgreSQL 16.15, TLS with an owned CA | 37 of 37 checks passed | [postgres-report.json](postgres-report.json) |

Binary SHA-256 (both runs): `llm-firewall`
`c554c364f99bc70b7be5729318e41b4fd7219d0fe0e8ae4d7cc009402a96a29e`, `agentfw`
`d3adb299c4695c15f611d2a25cf8ae0420fb19427199a729e04b4756030c9706`.

Covered, in order: baseline applied (`deny` hook verdict); untrusted issuer
(`issuer_key_unknown`); expired bundle (`bundle_expired`, Agent clock +7200 s
via an owned `LD_PRELOAD` shim); invalid policy (`policy_invalid`, approved
invalid revision row inserted into the owned store); busy native boundary kept
`delivered` with no rejection stored; the same signed candidate then applied
(`defer` verdict, `/health` sequence 5); older Agent ACK without a reason;
older Console fallback through a loopback stand-in that refuses the new field
with 422; conflicting reason and status (409), unknown code (400), unknown
field (422); foreign tenant (409) and revoked credential (401); Viewer cannot
deploy; Agent credential cannot read history; Console and Agent restart;
history, fleet and policy panels; snapshot codes; narrow layout; no browser
writes; recovery inventory accepted the live store with rejection rows; no
private value in the report, snapshot or screenshots.

Screenshots: [history](sqlite-history-reasons.png),
[policy panel](sqlite-policy-reasons.png), [fleet detail](postgres-fleet-reasons.png).
Snapshots: [SQLite](sqlite-snapshot.json), [PostgreSQL](postgres-snapshot.json).

Failed attempt, retained as a note: one PostgreSQL run on an earlier,
uncommitted tree timed out at the baseline step waiting for the Agent's
`/health` (HTTP 404 before the Agent was listening). The rerun on the
committed source passed. Its report was overwritten and is not retained.

## Recovery

`scripts/console-recovery-acceptance.py --run --backend sqlite`: 74 checks
passed ([recovery-sqlite.json](recovery-sqlite.json)). It ran on commit
`51a04829`, whose runtime inputs equal `15076229` (the later commit changes
only tests, docs, CI and the rejection acceptance script). The PostgreSQL
recovery run needs Docker, which was not available here; the
`console-recovery.yml` workflow covers it.

## Other local checks

- Rust: `managed_rejection_reasons` on SQLite and a disposable PostgreSQL;
  the full `llm-firewall` suite (372 passed, 13 ignored); `agentfw` managed
  tests. Three `agentfw` `mcp::linux_budget` tests fail in this container on
  cgroup parsing (`member_cgroup_parse`); that code is not changed here.
- Browser fixtures: history, fleet triage, heartbeat, enrollment, rollout and
  single policy (91 tests). Existing history acceptance: 30/30 SQLite, 31/31
  PostgreSQL.
- Rust 1.97.0 locally, not the pinned 1.99.1. Final Ready CI, CodeQL and
  admission belong to the TL.
