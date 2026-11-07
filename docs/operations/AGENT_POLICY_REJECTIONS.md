# Agent policy rejections

When a managed Agent refuses a signed policy candidate, it already sends an
authenticated `rejected` acknowledgement to `POST /agent/v1/policy/ack`. Since
SOU-241 that acknowledgement can carry one finite, versioned reason, and the
Console records when it received the first one. Operators see the cause and a
safe next step in the history, fleet and policy panels. The rejected candidate
never becomes the active policy: the Agent keeps its previous one.

## What the Agent sends

```json
{"deployment_sequence": 3, "revision": "r2", "policy_sha256": "...", "status": "rejected",
 "rejection": {"version": 1, "code": "bundle_expired"}}
```

`rejection` is optional and allowed only with `status: "rejected"`. `version`
must be `1` and `code` must be one of the codes below (lowercase letters and
`_`, at most 48 bytes). Nothing free-form is accepted or stored: no message,
path, policy text or Agent clock value. The Agent derives the code at the
exact check that failed; its detailed local message stays in its own log.

| Category | Code | Failure boundary |
| --- | --- | --- |
| trust | `issuer_key_unknown` | signing key ID not in the pinned keyring |
| trust | `issuer_key_revoked` | signing key is revoked in the keyring |
| trust | `keyring_unavailable` | the Agent could not read its trusted keyring |
| signature | `signature_invalid` | Ed25519 signature malformed or not valid |
| signature | `digest_mismatch` | policy SHA-256 differs from the signed digest |
| signature | `audience_mismatch` | tenant or Agent ID is not this Agent's (or not pinned) |
| signature | `schema_unsupported` | bundle schema version not supported |
| signature | `bundle_malformed` | revision, key ID, audience length or transcript invalid |
| expiry | `bundle_expired` | Agent time is at or after `expires_at_unix` |
| expiry | `issued_in_future` | issued more than 60 s ahead of the Agent clock |
| expiry | `lifetime_invalid` | lifetime is not within 1 s to the maximum TTL |
| policy | `policy_invalid` | `AgentPolicySet` validation failed |
| policy | `policy_too_large` | policy is empty or over the size limit |
| activation | `sequence_stale` | the Agent already runs this or a newer sequence |
| activation | `activation_failed` | verified, but persisting or switching failed |

A **transient** native-boundary refusal (`activation_pending`, the Agent's
native-session boundary is busy) is not a rejection. The Agent sends nothing,
the deployment stays `delivered` and the Agent retries on its next poll.

## Compatibility

- **Older Agent, new Console**: the acknowledgement has no `rejection` field.
  It is recorded with its receipt time and no code; the panels say the Agent
  did not report a reason.
- **New Agent, older Console**: an older Console refuses the unknown field
  (HTTP 422, or 400). The Agent then retries once with the previous body, so
  the rejection is still recorded there without a code.
- The `applied` acknowledgement, authentication (401 for an unknown or revoked
  credential), the exact sequence/revision/digest match and the 409 conflict
  contract are unchanged.

## What the Console stores

The first authenticated rejection of an exact candidate (tenant, Agent,
deployment sequence, revision, policy digest) is stored in
`managed_agent_rejections` with its reason version and code (both null for an
older Agent) and the Console's own receipt time. SQLite creates the table on
first use; PostgreSQL adds it in migration 32.

- A retry with the same status and reason returns 204 and changes nothing.
- A retry with a different reason, a missing reason after one was stored, or
  `applied` after `rejected` returns 409; the first rejection stays.
- An unknown code or version returns 400; an unknown field or a malformed
  reason returns 422 (the strict JSON extractor). Nothing is stored.
- A credential from another tenant or for another Agent cannot address the
  candidate (409); an unknown or revoked credential gets 401.

Fleet detail (`GET .../agent-fleet/{agent}`) and the Agent deployment list
(`GET .../agents/{agent}/deployments`) add `rejected_at_unix` and
`rejection_code` (fleet detail also `rejection_reason_version`) only on
rejected records. The fields are additive; older readers ignore them.

## What operators see

The browser keeps a fixed table of labels and next steps for each code. It
never renders server text: an unknown code shows "Rejected with a reason this
Console does not recognise", and a missing one shows that the Agent did not
report a reason. A reason or time on a non-rejected record, or a code that is
not a short token, makes the panel drop the record (history) or refuse the
page (policy panel).

- **History**: the Rejected event shows the receipt time, the reason, the next
  step and that the Agent kept its previous policy. The incident snapshot adds
  `rejection_code`, `rejection_category` and `next_step` to the event.
- **Fleet detail**: a Rejection column, and the latest-rejected notice names
  the reason. The historical last applied identity is unchanged.
- **Policy panel**: each rejected deployment is labelled as a rejected
  candidate, apart from the active policy, with its reason and next step.

## Recovery

The table is part of the [recovery inventory](CONSOLE_RECOVERY.md): an
optional SQLite table and a PostgreSQL table at schema version 32. Its rows
hold only identifiers, the reason code and the receipt time.

## Acceptance

`scripts/console-agent-rejection-acceptance.py --backend sqlite|postgres
--output DIR` runs one disposable Console and the real `agentfw serve`. The
Agent rejects an untrusted issuer, an expired bundle (its clock moved ahead by
an owned `LD_PRELOAD` shim) and an invalid policy (an approved invalid revision
inserted into the owned disposable store, because the Console refuses one at
authoring). A busy native boundary keeps the next candidate pending, then the
same signed redeploy applies, witnessed by the Agent's `/health` and `/hook`.
It also checks an older Agent, an older Console, conflicts, foreign and revoked
credentials, Viewer limits, Console and Agent restarts, the recovery inventory
against the live store, the three browser panels and redaction of the
retained report, snapshot and screenshots.
