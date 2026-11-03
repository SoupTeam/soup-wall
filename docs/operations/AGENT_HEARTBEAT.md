# Managed Agent heartbeat (opt-in self-report)

An enrolled managed Agent can, when explicitly enabled, report a small
current observation to its existing Console. The Console admin page then shows
whether that Agent recently sent an **authenticated self-report**, an old one
(stale) or none.

A heartbeat is the Agent's own report, timed by the Console. It is **not**
runtime attestation, proof that a policy is enforced, a health check or an
execution grant. Agents that do not opt in keep the existing status:
liveness and protection unknown.

## Enable it on an Agent

The heartbeat runs inside the existing `agentfw serve` (no new process) over
the already configured managed Console origin, private CA and credential
(`SOUP_MANAGED_AGENT_CONSOLE`, `SOUP_MANAGED_AGENT_TLS_CA_FILE`,
`SOUP_MANAGED_AGENT_TOKEN_FILE`, tenant and Agent ID). Add:

| Variable | Values | Default |
| --- | --- | --- |
| `SOUP_MANAGED_AGENT_HEARTBEAT` | `1` on, `0` or unset off; anything else refuses startup | off |
| `SOUP_MANAGED_AGENT_HEARTBEAT_INTERVAL_SECONDS` | 5 to 60 | 30 |

`SOUP_MANAGED_AGENT_HEARTBEAT=1` without the managed Console configuration
refuses to start. The sender has no other destination, no TLS fallback and no
queue: each tick sends the current observation once. Failed or refused sends
back off up to five minutes. A Console outage, a refusal or a lost credential
never changes local enforcement; the last verified policy stays in force.

## Contract

`sw-agent-heartbeat/1`, Bearer Agent credential only (admin tokens get 401),
JSON bodies of at most 2 KiB with unknown fields refused.

1. `POST /agent/v1/heartbeat/registrations` with `tenant_id`, `agent_id`,
   `credential_generation` (the server-issued epoch, read from
   `/agent/v1/whoami`) and a random 32-hex `instance_id` chosen at process
   start. The Console returns a random `registration_id` and the timing
   (`interval_seconds` 30, `min_interval_seconds` 5,
   `expires_after_seconds` 90). A new registration replaces the previous one
   for that Agent.
2. `POST /agent/v1/heartbeats` with the same identity, `registration_id`, a
   `sequence` that must exceed the last accepted one, and `observed_policy`
   (the loaded managed policy's deployment sequence, revision and digest, or
   `null`). Returns 204.

Nothing else is accepted: no prompts, tool data, tokens or host paths.

| Refusal | HTTP | When |
| --- | --- | --- |
| `wrong_agent` | 403 | body names another tenant or Agent than the credential |
| `epoch_mismatch` | 409 | body names a credential generation other than the current one |
| `not_registered` | 409 | no registration (also after a SQLite Console restart) |
| `registration_superseded` | 409 | a newer registration, another instance or an older generation owns it |
| `sequence_replay` | 409 | sequence not greater than the last accepted (replay, out of order) |
| `too_frequent` | 429 | less than 5 s after the last accepted heartbeat |
| Agent authentication required | 401 | missing, revoked or rotated-away credential |

The Agent handles 409 by registering again: it reads its current generation
with its credential and receives a new `registration_id`, so a restarted
process or a rotated credential never continues an old counter, and replayed
old requests stay refused.

## Freshness

The Console records only its own receipt time. A report is **fresh** for 90
seconds after the Console received it, then **stale**. Agent clocks are never
used, and a restart, replay or re-registration cannot make an old report
fresh: a new registration starts with no report.

## Console status

The **Agent heartbeat (self-report)** section under the fleet shows the
selected Agent, re-read every 30 seconds, from
`GET /admin/v1/tenants/:t/agent-fleet/:a/heartbeat`
(`sw-agent-heartbeat-status/1`, same read authorization as the fleet):

| Status | Meaning |
| --- | --- |
| `fresh` | authenticated self-report received within 90 s |
| `stale` | last self-report older than 90 s |
| `registered_no_report` | registered, nothing reported yet |
| `credential_changed` | credential rotated after the last report; it no longer counts |
| `revoked` | credential revoked; reports are refused |
| `unsupported` | the Agent never opted in (liveness and protection unknown) |
| `unavailable` | the Console's observation store is not migrated (PostgreSQL) |

The self-reported loaded policy is shown separately from the server-recorded
delivery and acknowledgement in the fleet detail. Neither is presented as
proof of enforcement.

## Storage

One row per Agent, outside the recoverable control-plane schema:

- **SQLite**: a connection-scoped table. A Console restart forgets all
  observations; Agents re-register on their next heartbeat.
- **PostgreSQL**: table `agent_observations.heartbeats`, created by
  `llm-firewall migrate` (migration role) and deleted with its enrollment.
  The runtime role needs `USAGE` on the schema and `SELECT, INSERT, UPDATE`
  on the table. It is not part of the versioned Console recovery inventory
  (public schema, migrations 1 to 28), which is unchanged.

## Verification

```sh
cargo test --locked -p llm-firewall --test agent_heartbeat
cargo test --locked -p agentfw --lib managed_heartbeat
python3 -B -m unittest scripts/tests/test_console_heartbeat_browser.py
cargo build --locked -p llm-firewall -p agentfw
python3 -B scripts/console-agent-heartbeat-acceptance.py --no-build --backend sqlite --output /tmp/heartbeat
python3 -B scripts/console-agent-heartbeat-acceptance.py --no-build --backend postgres --output /tmp/heartbeat
```

Evidence: [2026-11-04](evidence/AGENT_HEARTBEAT_2026-11-04.md).
