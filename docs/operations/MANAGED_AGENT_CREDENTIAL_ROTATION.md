# Managed Agent enrollment credential rotation (SOU-55)

This is an **internal** operator procedure. It rotates the enrollment bearer for one
managed Agent; it does **not** rotate policy-signing keys, change Agent identity,
alter permissions or implicitly authorize a policy deployment.

## Preconditions and scope

- Console administrative authorization is required. The Agent bearer cannot
  call the rotation API. Admin routes remain protected by the existing
  `/admin/v1` middleware.
- Use verified HTTPS between the operator and a remote Console. HTTP is only
  appropriate in an owned, disposable local loopback demonstration. Never pass
  bearer credentials in an unverified remote request.
- The Agent must be configured with an **explicit absolute path**
  `SOUP_MANAGED_AGENT_TOKEN_FILE`. Put a private regular file owned by the
  daemon user at that path (mode `0600`). It contains exactly 52 ASCII bytes:
  the `sw_agent_` prefix followed by 43 URL-safe characters; **no newline**.
  Provision files with secure temporary creation and atomic same-filesystem
  rename. Do not use a symlink, FIFO, shared group-readable directory entry,
  world-readable file or output the token in logs.
- Existing `SOUP_MANAGED_AGENT_TOKEN` configuration remains supported for
  initial/manual enrollments, but cannot hot-reload credentials. When
  `SOUP_MANAGED_AGENT_TOKEN_FILE` is configured, the environment value is
  **never** used as fallback, even if the selected file is missing or invalid.
  Restart the old env-only daemon with file-mode provisioning before relying
  on live rotation.
- Confirm the Agent has an accepted signed policy and an applied acknowledgement
  before rotating. Inventory `GET /admin/v1/tenants/{tenant}/agents`
  exposes the current non-secret `credential_generation` (initially 1).
  The inventory never returns bearer credentials or credential digests.

## Transaction and API contract

`POST /admin/v1/tenants/{tenant}/agents/{agent}/credential-rotations`

Request JSON:
```json
{
  "expected_generation": 1,
  "operation_id": "0123456789abcdef0123456789abcdef",
  "replacement_token": "sw_agent_<43 fresh URL-safe characters>"
}
```

The operation ID must consist of 32 lowercase hex characters drawn randomly.
The replacement token must be independently generated with 32 bytes of
cryptographic randomness (for example, Python `secrets.token_urlsafe(32)`),
then persisted in a private staging file **before** submitting the request.
Never include the raw token in argv, command history, CI artifacts, error
messages, example logs, or public evidence. Use a non-logging HTTPS client that
passes the request in memory.

The server atomically compares the expected generation against the current,
unrevoked enrollment for an active tenant, then replaces the credential hash and
increments the generation. A successful response returns only the tenant/Agent
identity, generation, operation ID and `already_applied`. Previous fetch/ack
credentials become invalid at the committed cutover; policy history and
acknowledgements are preserved.

For a lost response, **retry the exact same request**: operation ID, expected
generation, and replacement credential must all be unchanged. An exact duplicate
is acknowledged without another change; a different request from an older
generation conflicts. An operation ID reused with modified parameters also
conflicts. Stale attempts never reactivate a previous credential. Keep the
staging file and operation metadata until the result is confirmed.

After a successful or repeat-confirmed response, atomically replace the Agent
credential file with the staged secret. The running daemon reloads the file
before each fetch/ack request, without restart. During the cutover gap, keep
the last signed active policy; report authentication unavailable rather than
a false applied acknowledgement. A disconnected/revoked Agent must **not**
lose its last verified active policy.

## Operational sequence

1. Inspect admin Agent inventory and record tenant, Agent and expected
   credential generation (no bearer secret).
2. Generate a new random `sw_agent_` token into a private, owner-only
   staging file. Generate and durably record a random operation ID before
   sending the request.
3. Submit the admin rotation request over owned verified transport, from
   local protected memory without logging the JSON body.
4. If the response is lost, retry with identical inputs. If a competing
   request wins, stop and reconcile the new generation before proceeding.
5. Rename the staged file atomically over the existing Agent credential
   file. Do not change the running daemon or the issuer keyring.
6. Verify old-token `whoami`, policy fetch and acknowledgement are
   unauthorized, and verify a new signed deployment is applied and
   acknowledged by the **same Agent PID** using the new bearer.
7. Retain only sanitized source, binary and configuration identities and
   non-secret check outcomes for review.

## Reproducible acceptance

Run locally on owned Linux hosts or in CI with existing Rust toolchain:

```sh
python3 scripts/managed-credential-rotation-demo.py --backend sqlite
python3 scripts/managed-credential-rotation-demo.py --backend postgres
```

The PostgreSQL command needs the owned Python fixture dependency
`cryptography==50.0.2` and the disposable helper from
`scripts/keycloak-oidc-acceptance.py`. The acceptance command builds the
real Console and Agent unless `--no-build` is selected. It uses local
owned fixtures, no provider API, and writes sanitized evidence under
`target/`; it never connects to a customer installation.

Release certification, general-purpose remote multi-host deployment, and
service-management changes are not part of SOU-55.
