# Managed Agent heartbeat: evidence (2026-11-04)

Guide: [AGENT_HEARTBEAT.md](../AGENT_HEARTBEAT.md). Sanitized reports and
screenshots:
[agent-heartbeat-2026-11-04/](agent-heartbeat-2026-11-04/sqlite-report.json)
([PostgreSQL report](agent-heartbeat-2026-11-04/postgres-report.json)).

## Environment and scope

| Item | Value |
| --- | --- |
| Platform | hosted Ubuntu 24.04 x86_64 container, non-root user (not a physical host, not WSL2) |
| Base | main `2a5bf677` (reviewed successor of `f66a2242`) |
| Source | commit `6bc29ea6` (recovery fix on top of the PR's `0b6c4cf4`), tree `0ab138feb595d685da78aa023c332b78629b0ed1`, clean |
| Console `llm-firewall` | `24baf8ae0a4c92e88fdb220d508b2c89f5baf3b42613665681de5dd9cb71c721` (debug, local Rust 1.97.0, not the pinned 1.99.1) |
| Agent `agentfw` | `b1b9668aa39bfff3c5580ed57316035c47f2ce8309d06b66f5b5953d97c1f14e` (same build) |
| Stores | disposable SQLite file; disposable PostgreSQL 16.15 cluster on 127.0.0.1 with TLS (owned CA, `sslmode=require`), source and restore databases owned by a non-superuser role |
| Agents | two unchanged `agentfw serve` processes on loopback: `edge-hb` with `SOUP_MANAGED_AGENT_HEARTBEAT=1` (interval 5 s), `edge-legacy` without |
| Runtime witness | each Agent's own `/health` managed policy and a `/hook` PreToolUse decision |
| Browser | Chromium (Playwright) as Viewer |

Synthetic tenants (`Heartbeat Alpha`, `Heartbeat Beta`) and Agent IDs only;
no provider or model call. Both Agents applied a real signed `default: deny`
revision. Credentials, the database password and the run directory stayed in
memory and the private temporary directory; the script checks that no
retained report, screenshot or first-run Agent log contains a credential.

## Result: `scripts/console-agent-heartbeat-acceptance.py` passed

SQLite: **36 checks**. PostgreSQL: **48 checks** (adds `migrate` creating the
observation schema and Console recovery with it).

| Step | Observed on both stores |
| --- | --- |
| Opt-in | `SOUP_MANAGED_AGENT_HEARTBEAT=1` without a managed Console refuses startup; the value `yes` refuses startup |
| Fresh | `edge-hb` becomes `fresh` (age 0 of 90 s); its self-reported policy (#1, digest `f9b0bb88…`) equals the Agent's own `/health`, and `/hook` denies; the server delivery record stays separate with liveness `unknown`; the sequence advances |
| Unopted | `edge-legacy`, running and denying, stays `unsupported` with no report |
| Protocol | with the Agent's credential: register, heartbeat 1, replay of 1 → `sequence_replay`, sequence 0 → 400, heartbeat 3, then 2 → `sequence_replay`; generation 7 → `epoch_mismatch`; another tenant's Agent credential → `wrong_agent`; admin token → 401; forged registration → `registration_superseded`; unknown field → 400 |
| Supersession | the probe's registration superseded the live Agent, which registered again by itself and reported again; the probe's registration is then refused |
| Isolation | the same Agent ID in Beta stays `unsupported` |
| Offline | `edge-hb` stopped: `stale` at age 91 s (Console receipt time only) |
| Restart | a new `edge-hb` process registers a new instance and is `fresh` again with a new low sequence |
| Console outage | Console stopped for 12 s: `/hook` still denies with the same policy digest; after restart `fresh` again (SQLite: the Agent re-registered after `not_registered`; PostgreSQL: registration persisted) |
| Recovery (PostgreSQL) | the source holds `edge-hb`'s observation; with the Console stopped, `console_recovery` refuses a backup while an unknown schema exists and while the observation schema has an extra table; then backs up and restores (rows and sequences verified); the restored database has no observation schema; a Console on it reports `unavailable` for both Agents; `migrate` recreates the table empty; the next read is not fresh, `edge-legacy` reads `unsupported`, and `edge-hb` registers again after the restore and is `fresh` |
| Rotation | rotation to generation 2: the old credential gets 401 at once; after the token file is replaced the same process registers under generation 2 and is `fresh` |
| Browser | the heartbeat section shows the authenticated self-report with its age, the self-reported policy and "not runtime attestation", never "healthy"; `edge-legacy` reads "No heartbeat registration … unknown"; after revocation it reads "Credential revoked"; no write request and no browser storage |
| Revocation | status `revoked`; the revoked credential gets 401; `/hook` still denies with the last verified policy |

Screenshots: [fresh](agent-heartbeat-2026-11-04/postgres-heartbeat-fresh.png),
[revoked](agent-heartbeat-2026-11-04/sqlite-heartbeat-revoked.png).

## Focused regressions

- `crates/proxy/tests/agent_heartbeat.rs` (2, SQLite over HTTP): unopted
  `unsupported`; no credential, admin token, wrong Agent, wrong epoch, unknown
  field, bad instance ID and oversized body refused; not registered;
  registration and `registered_no_report`; fresh with reported policy;
  replay, out of order, too frequent, forged registration and superseded
  instance refused; rotation (`credential_changed`, old credential 401,
  old generation and old registration refused, re-registration); admin read
  scope; revocation; a Console restart forgets observations and refuses the
  old registration.
- `agent_heartbeat` unit tests (3): fixed 90 s expiry on server receipt time
  (including a receipt time after the read time), every status, decision
  table for replay, supersession, epoch and identity, strict shapes.
- `scripts/tests/test_console_recovery.py` (19, including 3 new): the
  catalog accepts only the exact reviewed observation schema and still
  refuses any other schema; a restore target with it is not empty; an archive
  listing that contains it is refused.
- `agentfw` `managed_heartbeat` unit test: strict opt-in values, bounded
  interval, random instance IDs.
- `scripts/tests/test_console_heartbeat_browser.py` (7, synthetic fixtures):
  every status text and class with no health claim; unopted unknown; the
  30 s re-read moving fresh to stale; stale replies after Agent and tenant
  change discarded; mismatched and malformed responses refused (including
  HTML-shaped revision); 404, 503, 403 and 401 (which stops re-reads);
  390 px layout and no storage.
- Triage, history, enrollment and rollout browser suites (59) and the fleet,
  triage and served-page Rust tests still pass.

## Not claimed

An authenticated self-report only: no runtime attestation, remote command
channel, execution grant or proof of enforcement. Not measured on a physical
host, over a remote TLS edge or with multiple Console instances. No
exact-pin toolchain or production readiness. The CI job runs both
acceptance passes in addition to the existing steps; its 40-minute limit was
not changed.
