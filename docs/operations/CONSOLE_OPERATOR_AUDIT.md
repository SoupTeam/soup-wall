# Console operator audit

Open the tenant in the authenticated platform Console, then open **Operator
audit history** and select **Load latest operator events**. An existing Console
viewer can read and export history, while each mutation still requires its
existing Operator or Owner role. The workspace browser and Agent bearer
credentials cannot read this platform history.

Each event has a server receipt time, an event ID, a tenant, an actor kind
and ID, a finite operation, a stable target, and an outcome. A platform admin
is identified by the ID authenticated by Console. The configured bootstrap
credential has the shared identity `bootstrap_owner`. Use named
administrators when attribution to one person is required. An authorized
workspace model-policy change records its verified workspace principal ID.
A refused platform request without verified credentials has actor
`unavailable`. The Console never takes an actor ID from request content.

- **Committed** records a storage mutation. A policy deployment may still
  be waiting for an Agent, and a rollout transition may have recorded a
  failed plan. Check the policy or rollout view for its current state and
  Agent history for its authenticated application acknowledgement.
- **Denied** records an authentication or authorization refusal for a known
  tenant when the request can be assigned to a covered operation.
- **Failed** records a handled error for a covered request. An earlier
  transaction in a compound request can have committed its own fact.
  Refusals identify the tenant and operation. An unverified body, selector,
  target or error message never becomes an audit record.

The covered mutations are:

| Surface | Operations |
| --- | --- |
| Gateway policy | Create and approve an immutable version, activate a version, and roll back to a prior version. Replace or clear the model allowlist using the existing versioning flow. |
| Individual Agent | Enroll, rotate a credential, revoke, create and approve an immutable policy revision, deploy, and issue a rollback. |
| Managed group | Create or delete a group, add or remove a member, create or approve an immutable group revision, and start, advance, pause, resume or roll back a rollout. Use the existing rollout rollback action to cancel work still in flight. |

There is no in-place edit or delete operation for immutable policy revisions.
New revisions represent edits. Operator events exclude policy previews,
Agent fetch and application reports, and automatic rollout reconciliation.
The Operator or Owner's identical accepted deployment, rotation or guarded
rollout retry returns the original receipt. It creates no new committed fact.
A repeated state transition that changes no stored rollout state creates no
new fact either. A source reference can carry a version, issuance sequence,
credential generation, rollout ID or policy digest. The log stores no raw
policy, command, credential, request URL, retry key, arbitrary label or
error text.

Select **Older events** to read the next page or **Download displayed page**
to save its bounded JSON. The API is
`GET /admin/v1/tenants/{tenant}/operator-audit?limit=50`, authenticated the
same way as the rest of Console. The default is 50, with an allowed range of
1–100. Pass the returned `next_before` as `before` for older events.
`download=true` serves the same page as a JSON attachment. The cursor is
scoped to the selected tenant. Exports may contain operational identifiers
and should be stored as private operator material.

SQLite and PostgreSQL write a committed fact inside the same transaction as
the change. A missing or suppressed audit write fails that transaction.
There are at most 10,000 committed, 500 denied and 500 failed events per
tenant. Attempts cannot evict committed facts. Pages are live reads, so a row
can age out between requests. Tenant deletion removes its history. Events
before this migration, expired rows, requests without an established tenant
scope, and refusals during an unavailable audit store are history gaps.
Existing proxy request telemetry is a separate view.

For PostgreSQL, run the existing `llm-firewall migrate` with the approved
migration role before starting the new Console. Migration 31 preserves
existing policies and Agent data and starts an empty operator history.
SQLite creates the audit table and indexes when opening the store. The
[Console recovery inventory](CONSOLE_RECOVERY.md) includes these records and
their sequence state in the encrypted backup.
