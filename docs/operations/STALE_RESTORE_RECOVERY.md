# Stale-restore recovery for one Agent (SOU-242)

After a [Console restore](CONSOLE_RECOVERY.md), a running Agent may already
apply a deployment newer than the restored database. The Agent keeps that
durable active policy and refuses every lower or equal sequence, so the
restored Console cannot reach it: the baseline result is
`recovery_complete: false`. The first choice is still a newer backup.

When none exists, an Owner can use this bounded procedure for **one unchanged
enrolled Agent**: same tenant, same enrollment credential generation and the
same issuer key. It never rewinds the Agent, resets its counters or creates an
acknowledgement for it. Contract: `sw-console-stale-restore-recovery/1`.

## What it needs

- The restored Console started with the **unchanged** issuer settings
  (`SOUP_AGENT_POLICY_KEY_ID` and its seed). On PostgreSQL, run
  `llm-firewall migrate` (migration 33 adds the fence table and recreates the
  empty heartbeat store).
- The Agent running with the [heartbeat](AGENT_HEARTBEAT.md) enabled and its
  existing credential, so the Console receives a fresh authenticated report of
  its active policy (sequence, revision, digest) after the restore.
- The Agent's retained signed bundle: the file `managed-policy-active.json` in
  the Agent's `.agentfw` home. Copy it to the Owner's workstation over your
  normal admin channel. It holds the signed policy, not a credential.

## Procedure

1. In the Console, select the Agent. The **Stale-restore recovery** section
   shows `No stale-restore recovery recorded` and the latest restored sequence.
2. As an Owner, choose the evidence file and select **Preview recovery**. The
   Console checks, in one read:
   - the enrollment exists and is not revoked;
   - the evidence is signed by the current issuer key, and the newest restored
     deployment verifies with the same key;
   - tenant, Agent, digest and signature are exact, and the evidence sequence
     is above every restored deployment and every earlier fence;
   - a heartbeat received within 90 seconds, from the current credential
     generation, names exactly that sequence, revision and digest.

   The preview shows the restored sequence, the evidence, the observation age,
   the **unrecoverable history interval** (sequences between the restored one
   and the evidence, if any), the next issuance sequence, the remaining
   restrictions and an exact confirmation phrase such as
   `recover edge-1 from 2 to 4 9f2c41d07a3b`. A preview writes nothing.
3. Type the exact phrase and select **Confirm recovery fence**. Inside the
   fence transaction the Console first re-reads the confirming administrator:
   a stored administrator must still be active with the Owner role (SQLite
   write lock; PostgreSQL `FOR SHARE` on the admin row), so a revoke or
   demotion after the request was authenticated refuses with
   `owner_not_active`. The bootstrap Owner is the configured admin token
   itself and has no stored row. The Console then repeats every check under
   the same lock as issuance and compares a binding
   over the restored deployments, revisions, enrollment credential, issuer and
   earlier fences. Any change after the preview refuses with `state_changed`;
   preview again. On success it stores one fence row. The state is `fenced`.
4. Deploy an approved revision through the normal deployment path. It is
   signed with a sequence above the fence. The Agent verifies and applies it.
5. The state becomes `complete` only when that deployment has the Agent's
   authenticated `applied` acknowledgement. A delivered row is not completion.

## Refusals

Every refusal keeps recovery closed and changes nothing.

| Code | HTTP | Meaning |
| --- | --- | --- |
| `evidence_malformed` | 400 | not a bounded signed bundle, or an unknown field |
| `confirmation_mismatch` | 400 | the phrase is not the exact preview phrase |
| `owner_not_active` | 403 | the confirming administrator was revoked or demoted after authentication |
| `not_enrolled` | 404 | no such Agent in this tenant |
| `revoked` | 409 | the enrollment credential is revoked |
| `evidence_wrong_audience` | 409 | the bundle names another tenant or Agent |
| `evidence_digest_mismatch` | 409 | the policy does not match its digest |
| `issuer_changed` | 409 | evidence or restored deployments use another issuer key ID |
| `evidence_signature_invalid` | 409 | tampered bundle, or the issuer key material changed |
| `no_restored_deployment` | 409 | nothing restored to bind for this Agent |
| `evidence_not_ahead` | 409 | replayed or old evidence, or already fenced |
| `observation_unavailable` | 409 | no heartbeat report (not enabled, not yet sent, or not migrated) |
| `observation_not_fresh` | 409 | last report older than 90 seconds |
| `credential_changed` | 409 | the report uses another credential generation |
| `observation_mismatch` | 409 | the fresh report names another policy |
| `state_changed` | 409 | the restored state changed after the preview, or a concurrent confirmation won |

Preview and confirmation are Owner-only; Operators and Viewers get 403, and
an Agent credential gets 401.

If the confirmation gets no answer (lost response, timeout or a 5xx), the
outcome is unknown: the fence may be stored. The panel never repeats the
POST. It reads the recorded state once and shows it with "Confirmation
outcome was unknown". If that read also fails, it says the outcome is
unknown and asks you to select **Refresh recovery** before doing anything
else. A 4xx answer is shown as "Confirmation refused", followed by the
recorded state. Repeating a successful confirmation with the
same evidence and binding returns the same fence (`replayed: true`).
Concurrent confirmations create exactly one fence.

## API

| Method and path | Role |
| --- | --- |
| `GET /admin/v1/tenants/:t/agents/:a/stale-recovery` | Viewer |
| `POST /admin/v1/tenants/:t/agents/:a/stale-recovery/preview` `{evidence}` | Owner |
| `POST /admin/v1/tenants/:t/agents/:a/stale-recovery/confirm` `{evidence, state_binding, confirmation}` | Owner |

Bodies are at most 160 KiB. The status lists up to 20 fences, newest first,
each with its restored and fence sequences, evidence revision and digests,
issuer key ID, credential generation, unrecoverable interval, who confirmed
it and when, and the completing deployment once applied.

## What is stored

`managed_agent_recovery_fences` (SQLite on first use, PostgreSQL migration
33): identifiers, sequences, evidence and issuer digests, the binding, the
unrecoverable interval, the observation time and the confirming admin ID.
It is part of the [recovery inventory](CONSOLE_RECOVERY.md). The issuance path
reads the highest fence for the Agent, so every later deployment, including
group rollouts, is issued above it.

## Not covered

A changed issuer, a rotated or revoked credential, a different tenant or a new
trust epoch; reconstructing the deployments in the unrecoverable interval;
Agents without the heartbeat; the installed managed-Console connection (its
heartbeat is unsupported). These need a separate reviewed procedure.

## Acceptance

`scripts/console-stale-restore-acceptance.py --backend sqlite|postgres
--output DIR` uses the supported recovery tool to back up and restore a real
Console behind a deployment that a real `agentfw serve` applied, then drives
the refusals, an interrupted confirmation and retry, concurrent requests and
the completed recovery with the Agent's own `/health` and `/hook` as witnesses.
