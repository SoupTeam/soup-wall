# Console recorded Agent history and incident snapshot: evidence (2026-11-01)

Guide: [CONSOLE_AGENT_HISTORY.md](../CONSOLE_AGENT_HISTORY.md). Sanitized
reports, snapshots and screenshots:
[console-agent-history-2026-11-01/](console-agent-history-2026-11-01/sqlite-report.json)
([PostgreSQL report](console-agent-history-2026-11-01/postgres-report.json)).

## Environment and scope

| Item | Value |
| --- | --- |
| Platform | hosted Ubuntu 24.04 x86_64 container, non-root user (not a physical host, not WSL2) |
| Base | main `b385e750` (contains the requested start `c92d62e0`) |
| Source | commit `cfa02f02` (review fixes on top of the PR's `8f88f9c9`), tree `5f8ff82426c54899406541b9f8f4c84d63417ed0`, clean |
| Console `llm-firewall` | `b2ff7afabea8a827a1b8cad3496b5d7318282bb09db6b3dcad9d822720863e6c` (debug, local Rust 1.97.0, not the pinned 1.99.1) |
| Agent `agentfw` | `aa27e2d7a3c5420a3a3545a94952aad7b068cdf01cb2c5071e372e86448f6857` (same build) |
| Stores | disposable SQLite file; disposable PostgreSQL 16.15 cluster on 127.0.0.1 with TLS (owned CA, `sslmode=require`) |
| Agent | unchanged `agentfw serve` against the Console on loopback |
| Browser | Chromium (Playwright) as a Viewer |

Synthetic tenants (`History Alpha`, `History Beta`) and Agent IDs only; no
provider or model call. Agents, deployments, a credential rotation and a
revocation were created only through the existing admin and Agent APIs.
Credentials, the database password and the run directory existed only in the
run's memory and private temporary directory; the scripts check that no
retained report, snapshot or screenshot contains them.

## Result: `scripts/console-agent-history-acceptance.py` passed

SQLite: **30 checks**. PostgreSQL: **31 checks** (adds the TLS migration).

| Step | Observed on both stores |
| --- | --- |
| Mixed history | real Agent applied #1; #2 issued and superseded; #3 signed by an untrusted key and rejected by the real Agent; rollback #4 applied; #5 fetched with the Agent credential and never acknowledged; one credential rotation |
| Timeline | Enrolled, Issued, Applied, Issued, Superseded, Issued, Rejected, Issued, Applied, Issued, Fetched, Pending; latest issued links to #5, historical last applied to #4; 2 unresolved outcomes; protection and liveness unknown |
| Export | `complete_records`, not partial, protection `unknown`; event IDs unique and scoped to the tenant and Agent; the 8 dated events in ascending time order; names the missing rotation record |
| Pagination | 56 deployments: "Loaded 50 of 56 in 1 page(s)"; the partial preview and download report 56 expected, 50 loaded, missing `[1, 6]`, file name `-partial.json`; one more page gives 56 of 56 |
| Revoked Agent | Enrolled, Issued, Pending, Revoked: the pending deployment stays unresolved |
| Isolation | Viewer and Operator read; no session and an Agent credential get 401; another tenant's Agent path 404; the same Agent ID in another tenant shows only its own record |
| Context change | a held history reply released after a tenant switch was not shown |
| No side effects | no non-GET browser request, no browser storage; deployments and credential generations unchanged after export |
| Restart | Console stopped: the panel reports the read failure with export disabled; after restart the rebuilt export has identical events |
| Layout | 390 px wide page without horizontal overflow |

Screenshots: [mixed timeline](console-agent-history-2026-11-01/sqlite-timeline-mixed.png),
[partial first page](console-agent-history-2026-11-01/postgres-partial-preview.png),
[narrow](console-agent-history-2026-11-01/sqlite-narrow.png). Snapshots:
[complete](console-agent-history-2026-11-01/sqlite-snapshot-edge-history.json),
[partial](console-agent-history-2026-11-01/postgres-snapshot-edge-many-partial.json).

## Focused regressions

- `scripts/tests/test_console_agent_history_browser.py` (18, synthetic
  fixtures): chronological mixed history and summary links; denominators per
  page and partial download; the 8-page bound; a pagination gap, an
  overlapping page, a conflicting repeat and expired older history; malformed
  and HTML-shaped records dropped, never rendered; extra private fields never
  exported; delayed replies after an Agent or tenant switch and a delayed
  older page discarded; a response for another Agent refused; a failed page
  then retry; 401, 403 and 404 clear the panel; empty, revoked and 390 px
  states; an export refused when an identifier looks like a credential.
  Review controls: a sparse sequence of 100000000 and the largest safe
  sequence derive missing ranges from the loaded records (preview measured
  under 250 ms); an unsafe 16-digit summary, record or cursor is refused or
  dropped, never rounded; interleaved known times sort by their own time and
  an applied report after the next issue is contradictory; untimed events
  stay beside their deployment. The new controls hang the previous module.
- `test_console_enrollment_browser.py` and `test_console_rollout_browser.py`
  (27) still pass with the module on the page.
- `crates/proxy/tests/proxy_tenants.rs`: the served page includes the panel
  and snapshot format without placeholders or browser storage.

## Not claimed

Recorded Console evidence only: no runtime attestation, live coverage or
heartbeat. Fetch and rejection times and credential rotations are not
recorded by the existing store. No exact-pin toolchain, multi-host deployment
or production readiness.
