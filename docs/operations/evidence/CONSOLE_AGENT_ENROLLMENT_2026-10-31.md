# Console Agent enrollment and credential lifecycle: evidence (2026-10-31)

Guide: [CONSOLE_AGENT_ENROLLMENT.md](../CONSOLE_AGENT_ENROLLMENT.md). Sanitized
reports and screenshots: [console-agent-enrollment-2026-10-31/](console-agent-enrollment-2026-10-31/sqlite-report.json)
([PostgreSQL report](console-agent-enrollment-2026-10-31/postgres-report.json)).

## Environment and scope

| Item | Value |
| --- | --- |
| Platform | hosted Ubuntu 24.04.5 x86_64 container, non-root user (not a physical host, not WSL2) |
| Base | main `7c5cf90c` (PR branch rebased from `c92d62e0`) |
| Source | code commit of this change, tree `8529551517914f3771abf78b5d9982422631bc7e` (local commit `325f3a24`, after the review fixes), clean |
| Console `llm-firewall` | `a54e7cca1dd458e156fc16e313514756f8702eabeb158ca8191799446a16272f` (debug, local Rust 1.97.0, not the pinned 1.99.1) |
| Agent `agentfw` | `ced74fea88714e22b8de72a81ba8e61a1f491b7ddefd58febbcb9dd435fa3ad7` (same build) |
| Stores | disposable SQLite file; disposable PostgreSQL 16.15 cluster on 127.0.0.1 with TLS (owned CA, `sslmode=require` verified by the Console rustls connector) |
| Agent transport | existing HTTPS client through an owned private-CA edge on 127.0.0.1; credential from `SOUP_MANAGED_AGENT_TOKEN_FILE` |
| Browser | Chromium (Playwright) to the Console over loopback HTTP |

Synthetic tenants (`Enrollment Alpha`, `Enrollment Beta`) and Agent IDs only;
no provider or model call. Credentials existed only in the run's memory and
private temporary directory; the reports and real-service screenshots contain
none. The only credential visible in retained evidence is the fixture's
synthetic value in [synthetic-secret-view.png](console-agent-enrollment-2026-10-31/synthetic-secret-view.png).

## Result: `scripts/console-enrollment-acceptance.py` passed

SQLite: **29 checks**. PostgreSQL: **30 checks** (adds the TLS migration; the generated database password reaches `initdb` only on standard input).

| Step | Observed on both stores |
| --- | --- |
| Enroll | Owner typed the ID and pressed Enter; the one-time view showed the credential and install steps with the tenant, Agent ID and pinned issuer key; nothing in the URL or browser storage; clearing removed it from the page |
| Displayed installer | the exact command shown in the one-time view was run with `bash`: it refused an existing token-file link to an owned `0644` file and an existing public file (both unchanged), ignored a planted fixed-name `.next` link and installed the credential as a private `0600` file by rename; every later install in this run used the same displayed command |
| Fetch and acknowledge | the unchanged `agentfw serve`, reading the stored token file over the HTTPS edge, fetched `r1` and acknowledged it applied (sequence 1) |
| Rotate | typed confirmation; new credential shown once (generation 2); the old credential was refused on `whoami`, policy fetch and acknowledgement at once; after the documented rename the **same Agent process** fetched and applied `r2` (sequence 2) |
| Ambiguous rotation | the request reached the server but the browser lost the response: no credential shown, changes disabled; **Confirm with the same request** sent the byte-identical request; generation advanced once (3) and only then the credential appeared; generation 2 refused; Agent applied `r3` |
| Late response | an enrollment response delayed until after a switch to the other tenant was never shown; the Agent was recorded only in the submitted tenant |
| Negatives | Viewer browser without lifecycle controls; Viewer and Operator enroll/rotate/revoke refused **403**; cross-tenant rotate **409** and revoke **404**; an Agent credential cannot administer (**401**); nothing changed |
| Lost authorization | a second Owner's session was revoked while its panel was open; the next refresh reported it and disabled every change; nothing more was sent |
| Revoke | typed confirmation; credential refused; the Agent kept its last verified policy (`r3`) |
| Unavailable API | Console stopped: reads failed visibly, an enrollment attempt stayed "unknown" with changes disabled; after restart **Check again** reported it was not recorded; lifecycle state survived the restart |
| Layout | 390 px wide page without horizontal overflow |

Screenshots: [enrolled](console-agent-enrollment-2026-10-31/sqlite-enrolled.png),
[revoked](console-agent-enrollment-2026-10-31/postgres-revoked.png),
[unavailable](console-agent-enrollment-2026-10-31/sqlite-unavailable.png),
[Viewer](console-agent-enrollment-2026-10-31/postgres-viewer.png),
[narrow](console-agent-enrollment-2026-10-31/sqlite-narrow.png),
[synthetic one-time view](console-agent-enrollment-2026-10-31/synthetic-secret-view.png).

## Focused regressions

- `scripts/tests/test_console_enrollment_browser.py` (14, synthetic fixtures):
  Viewer/Operator read-only; one-time view, focus, clearing and no storage;
  late response after a tenant switch; duplicate and invalid IDs; ambiguous
  enrollment without resend; rotation request shape (current generation,
  32-hex operation ID, fresh `sw_agent_` credential); ambiguous rotation
  confirmed only with the identical body; refused and discarded rotations;
  revocation with Escape and typed confirmation; 401, 403 and unavailable API;
  Lock console; narrow layout; 401/403 on inventory reads lock every change;
  the displayed enrollment and rotation installers run under `bash` and `sh`:
  private `0600` install, refusal of linked, public, group-writable and linked
  directory targets, an unused planted `.next` link, invalid input leaving
  nothing, rotation requiring `SOUP_MANAGED_AGENT_TOKEN_FILE`.
- `scripts/tests/test_console_rollout_browser.py` (16) still passes with the
  enrollment module on the page.
- `crates/proxy/tests/proxy_tenants.rs`: the served page includes the panel
  without placeholders or browser storage.
- Existing backend role, rotation and revocation tests are reused unchanged.

## Not claimed

Agent TLS was terminated by an owned local edge, not a remote host. No exact-pin
toolchain, multi-host deployment, runtime attestation or production readiness.
