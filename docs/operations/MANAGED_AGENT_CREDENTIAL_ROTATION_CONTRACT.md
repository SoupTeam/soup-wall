# SOU-55 — Managed Agent credential rotation contract (implementation checkpoint)

Status: design contract only; **not implemented or accepted**. Base: `b58153c84b7a9a1c8d4c093b277d0df83404ac2a`. No changes to production auth until code and both-backend tests are ready.

## Scope and authority

- Only an authenticated Console **administrator** can rotate a credential, through an admin-middleware-protected route bound to an exact tenant and Agent ID. Never accept an Agent bearer token as Console administrative authority.
- Verify tenant active and enrollment unrevoked under the same database transaction that changes authority. No endpoint may re-enroll a revoked identity.
- Preserve `tenant_id`, `agent_id`, `created_at_unix`, deployment history, applied acknowledgements and group membership.
- The credential-generation counter begins at 1 for existing enrollments (migration/backfill); a successful rotation increments it exactly once. Generation is **not** a policy sequence, signing-key ID or authorization scope.

## Proposed request and response

`POST /api/v1/tenants/{tenant}/managed-agents/{agent}/credential-rotations` (exact router prefix to be verified in code).

Request (JSON, reject unknown fields):
```json
{
  "expected_generation": 1,
  "operation_id": "operator-generated-random-id",
  "replacement_token": "sw_agent_<43 base64url characters>"
}
```

- The operator generates a new strong credential *locally* before the request and writes it to a private staging file. A lost response cannot strand the operator without the secret. Require high-entropy randomness and the existing strict token grammar.
- `operation_id` is a unique opaque replay identifier (minimum 128 bits of entropy); bind it to tenant, Agent, expected generation and replacement credential digest. The same ID with changed parameters is a conflict.
- Response only returns non-secret `tenant_id`, `agent_id`, `generation`, `operation_id` and `already_applied`. Never echo credential, token hash or request bodies in logs, audit or evidence.
- For lost responses, replay the *identical* request (same operation ID, expected generation and credential). Return already-applied without another rotation. A stale competing operation must return 409, including when the old generation is supplied. Never make retries reactivate any historical token.
- Consider avoiding caller-supplied secret over HTTP except on verified administrator-to-Console HTTPS; add configuration/operations checks so this endpoint cannot be used insecurely.

## Atomic database contract

- Add `credential_generation` and a persisted receipt of the **last successful** rotation operation, including operation ID, prior generation and digest of replacement token. Explicit migration/backfill on SQLite and PostgreSQL.
- Within one SQLite `BEGIN IMMEDIATE` transaction / PostgreSQL transaction with row lock: check active tenant, unrevoked identity and operation replay; compare expected generation; update token hash, generation and receipt in one committed transaction.
- Retain no plaintext credential in storage. A replay of the last operation is accepted only if its expected generation and candidate digest also match. Older operations are always rejected; do not restore prior credentials.
- Auth lookup after commit accepts only the new hash. Audit and tests must demonstrate fetch **and** ack reject the old token.
- Concurrent operations from the same generation: exactly one succeeds, all losers conflict. Transaction retry errors must not leak tokens.

## Agent credential source

- Existing `SOUP_MANAGED_AGENT_TOKEN` is retained when file mode is not configured.
- A new explicit absolute-path `SOUP_MANAGED_AGENT_TOKEN_FILE` takes precedence whenever configured, including when missing, invalid, deleted or unreadable. **No env fallback** after selecting file mode.
- Load the file afresh before each fetch/ack request, not only at daemon startup. A missing/invalid file blocks that request and changes transport state to authentication-unavailable; retain the last active signed policy.
- Unix read restrictions: no symlink, no FIFO/socket/device/directory, owned by expected daemon user, mode without group/other access; nonblocking, nofollow open and post-open fstat with bounded read; reject embedded NUL/newline (unless a single documented trailing newline is explicitly supported). Accept atomic replacement by same-directory rename with private permissions.
- Do not log credential values, child environment copies, headers, argv, raw request bodies or hashed token digests.

## Preservation and proof

- Keep SOU-30 policy signature/issuer/audience/sequence/ack and rollback invariants and SOU-43 fixed-origin verified HTTPS, no redirects, no inherited proxies.
- Before coding acceptance: map existing Console admin routing, tenant store migrations and `managed_sync.rs` fetch and ack paths.
- Focused SQLite and PostgreSQL tests: first rotation, duplicate replay, lost response, stale and concurrent requests, disabled tenant, revoked enrollment, wrong tenant, unauthorized bearer, restart persistence.
- Owned one-command Linux test with real running Console and same Agent process: signed deny/defer/deny before and after rotation, old token fetch/ack refusal, missing/invalid/deleted file gap retains policy, restore/restart, sanitized exact-source identities.
- Do not mark SOU-55 Done until reviewable code, both database backends, real-process evidence and independent review pass.

## Open decision before implementation

Check the actual admin endpoint mount and deployment security posture before finalizing URL and request-secret handling. The proposal is deliberately conservative and remains unapproved until implemented and verified.
