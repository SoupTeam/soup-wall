# Console fleet triage overview: evidence (2026-11-02)

Guide: [CONSOLE_FLEET_TRIAGE.md](../CONSOLE_FLEET_TRIAGE.md). Sanitized reports
and screenshots:
[console-fleet-triage-2026-11-02/](console-fleet-triage-2026-11-02/sqlite-report.json)
([PostgreSQL report](console-fleet-triage-2026-11-02/postgres-report.json)).

## Environment and scope

| Item | Value |
| --- | --- |
| Platform | hosted Ubuntu 24.04 x86_64 container, non-root user (not a physical host, not WSL2) |
| Base | main `f66a2242` |
| Source | commit `12b1ffff`, tree `da6f5286c8db16b57d8ab71c17e733b9385cc7d7`, clean |
| Console `llm-firewall` | `d08ff820fae88db492592980cb6ea4ec29dd9ff79f20f69c375bd72460cd3eff` (debug, local Rust 1.97.0, not the pinned 1.99.1) |
| Agent `agentfw` | `0bf1f6e150566b2722f3250d81a0524b4388bbcf440cd9cf299f96bd9521ec37` (same build) |
| Stores | disposable SQLite file; disposable PostgreSQL 16.15 cluster on 127.0.0.1 with TLS (owned CA, `sslmode=require`) |
| Browser | Chromium (Playwright) as Viewer, Operator and Owner |

Synthetic tenants (`Triage Alpha`, `Triage Beta`) and Agent IDs only; no
provider or model call. Agents, deployments, acknowledgements, a fetch, a
group and a revocation were created through the existing admin and Agent
APIs; one Agent applied its bundle with the unchanged `agentfw serve`. Two
states no API produces on demand were made by one direct edit each of the
run's own disposable store: deleting deployment #1 of `edge-gap` (expired
history) and moving `edge-old`'s applied time two days back (old
acknowledgement). Credentials, the database password and the run directory
stayed in memory and the private temporary directory; the script checks that
no retained report or screenshot contains them.

## Result: `scripts/console-fleet-triage-acceptance.py` passed

SQLite: **36 checks**. PostgreSQL: **37 checks** (adds the TLS migration).

| Step | Observed on both stores |
| --- | --- |
| Projection | 39 enrolled Agents in Alpha: `edge-applied` no recorded problem; rejected; pending; fetched and pending; pending with a different applied revision; revoked; never delivered; incomplete history (2 of 3 records); old acknowledgement; 30 never-delivered bulk Agents. Counts: attention 38, pending 3, rejected 1, mismatch 1, revoked 1, incomplete 1, no acknowledgement 3, old 1, no delivery 32, no recorded problem 1, complete |
| Access | Viewer, Operator and Owner read; no session and an Agent credential get 401; unknown tenant 404; invalid limit, problem, sort, age, cursor and extra parameter 400; POST is not a route |
| Isolation | Beta's same Agent ID counted alone with its own record; no credential, policy body, signed bundle or private value in a response |
| Browser counts | the ten count buttons equal the projection; "Seen 25 of 38 matching", "of 39" and "not proof of health"; page 2 completes 38 of 38 |
| Filters and sort | prefix `edge-` with all Agents lists the 9 seeded outcomes; rejected, no recorded problem and old acknowledgement each list their one Agent; oldest acknowledgement first starts with unacknowledged Agents |
| Deep links | History on `edge-gap` builds its recorded history, which reports the absent earlier sequence; Rollout on `edge-old` selects group `fleet` in the rollout panel |
| Concurrent change | `edge-pending` acknowledged through the Agent API while the pending filter was shown: the next read lists 2 of 2 and the pending count drops to 2 |
| Delayed page | a held next-page reply released after switching to Beta was not shown |
| No side effects | no non-GET browser request, unchanged URL, no browser storage; enrollments and group members unchanged |
| Restart | Console stopped: the triage read fails and the list clears; after restart Operator, Owner and Viewer each see attention 37 and no mutation control in the section |
| Layout | 390 px wide page without horizontal overflow |

Screenshots: [all outcomes](console-fleet-triage-2026-11-02/sqlite-triage-edge.png),
[narrow](console-fleet-triage-2026-11-02/postgres-triage-narrow.png).

## Focused regressions

- `crates/proxy/tests/fleet_triage.rs` (5, SQLite): flags and counts for
  each recorded problem, filters, prefix and age threshold; keyset paging by
  Agent ID and by oldest acknowledgement without loss or duplicates; HTTP
  authorization (Viewer, Operator, Owner, no session, Agent credential),
  unknown tenant and invalid queries; the 10,000-Agent count bound reported
  as incomplete; empty and unknown tenants.
- `scripts/tests/test_console_fleet_triage_browser.py` (8, synthetic
  fixtures): counts, denominators and filter buttons; pages, partial counts,
  repeated and missing Agents after changes; a stale reply after a tenant
  switch; mixed-tenant, unknown problem, HTML-shaped ID, duplicate, filter
  mismatch, wrong tenant, negative count and wrong contract responses
  refused; 401, 403, 404 and 503; deep links; local prefix refusal and empty
  state; 390 px layout.
- History, enrollment and rollout browser suites (49) still pass with the
  module on the page; `proxy_tenants.rs` checks the served page.

## Not claimed

Recorded Console evidence only: no heartbeat, liveness, runtime attestation
or active protection. No exact-pin toolchain, multi-host deployment or
production readiness.
