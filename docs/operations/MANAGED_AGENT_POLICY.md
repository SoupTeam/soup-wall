# Signed managed Agent-policy rollout (SOU-30)

> **Draft / review in progress.** This is a bounded **local SQLite Console + `agentfw serve`** integration. It is **not** general remote deployment, TLS/IdP certification or permission to publish a product release. Full current-head review remains required.

## Purpose and policy separation

Console manages immutable, approved **AgentPolicySet YAML** revisions. These are not Gateway `TenantPolicyDocument` model policies; the existing Gateway policy APIs remain unchanged. Agent enrollment credentials are entirely separate from admin, tenant proxy and workspace service tokens.

Rollout stages stored per enrolled Agent:

1. `issued`: an approved Agent revision is signed as a new deployment sequence;
2. `delivered`: Console returned the signed envelope to an authenticated Agent;
3. `applied`: the Agent authenticated to Console *after reading back* its running firewall's active revision, SHA-256 and sequence; Console checks they match the current deployment;
4. `rejected`: the authenticated Agent refused a candidate; its last active policy remains intact.

The Agent reports `online`, `offline`, `stale`, `rejected` (and `restored_offline` immediately after restoring a previously accepted signed bundle) separately from the last **active** policy through `GET /health`. A download, persisted envelope, or lack of errors is not `applied` evidence.

## v1 signing protocol

`crates/agentfw/src/managed_policy.rs` defines `SignedAgentPolicy`; Console serializes the same fields as `SignedManagedBundle`.

| Property | Meaning |
| --- | --- |
| `schema_version` | integer 1 |
| `tenant_id`, `agent_id` | exact enrolled audience |
| `revision` | immutable approved Agent policy revision |
| `deployment_sequence` | strictly increasing **per Agent** (rollback included) |
| `issued_at_unix`, `expires_at_unix` | seconds since epoch; maximum validity 86,400 seconds; current issuer produces one-hour bundles |
| `issuer_key_id` | exact identifier for independently pinned Ed25519 key |
| `policy_yaml` | UTF-8 `AgentPolicySet`, at most 64 KiB |
| `policy_sha256` | lowercase SHA-256 of exact YAML bytes |
| `signature_hex` | lowercase Ed25519 signature, 64 bytes |

Before JSON decoding, the Agent refuses bundles over 96 KiB. Both sides sign this transcript, not canonical JSON: UTF-8 `soup-wall-agent-policy-bundle-v1`, one NUL byte, then **each field except `signature_hex` in the order above**, encoded as a 4-byte unsigned big-endian byte length and the literal UTF-8 bytes. Numeric fields use ordinary base-10 ASCII. Operator-pinned public key material is never trusted from the received bundle.

Verify exact audience, key identity/revocation, signature, digest, issuance/expiry, strictly increasing deployment sequence and strict `AgentPolicySet::from_yaml` parser before changing state. No implicit changes to `enforce`, judge, native registry, MCP resource confinement or executor permissions.

## Local operation (no provider or IdP needed)

The quickest reproducible test builds real binaries and runs a disposable Console and Agent:

```bash
python3 scripts/managed-policy-demo.py
```

CI runs the same scenario with prebuilt binaries in `.github/workflows/managed-policy-demo.yml`. It verifies **deny → defer/no hook objection → deny** after new `v-deny` / `v-allow` / rollback-to-`v-deny` deployments, with exact active sequence 1/2/3 and `applied` acknowledgements. The test uses temporary home/SQLite folders and random loopback ports; it does not access external providers. The `defer` behavior is represented as an empty Claude Code hook response `{}` (not permission `allow`). The witness, when the run succeeds, is `target/sou30-managed-rollout-evidence.json`.

### Console operator settings

Enable SQLite `tenant_store` in `firewall.yaml` and bind Console to loopback. Set a **separate secret** `LLM_FW_ADMIN_TOKEN` for `/admin/v1`, and provide an Ed25519 signing seed from the local operator's protected environment:

- `SOUP_AGENT_POLICY_KEY_ID`: nonempty key identifier
- `SOUP_AGENT_POLICY_SEED_HEX`: 32 random signing seed bytes, as 64 lowercase hexadecimal characters

Never commit the seed or token. The admin endpoint `GET /admin/v1/managed-issuer` returns the public key hex for **out-of-band provisioning** to the Agent; it never returns the seed.

Admin routes (existing `x-llm-firewall-admin-token: Bearer …` header, **Owner** required for mutations):

| Method | Route under `/admin/v1/tenants/{tenant}/agents` | Purpose |
| --- | --- | --- |
| POST | `/` | enroll `{"agent_id":"a"}`; returns Agent Bearer token **once** |
| GET | `/` | inventory without credentials or hashes |
| POST | `/{agent}/revoke` | revoke Agent credential |
| POST | `/{agent}/revisions` | create `{"revision":"v1","policy_yaml":"default: deny\n"}` |
| POST | `/{agent}/revisions/{revision}/approve` | explicitly approve immutable revision |
| POST | `/{agent}/revisions/{revision}/deploy` | `{"rollback":false}` or `{"rollback":true}` |
| GET | `/{agent}/deployments` | current and previous issued/delivered/applied/rejected deployments |

Agent routes with **its own** `Authorization: Bearer sw_agent_…`:
`GET /agent/v1/whoami`, `GET /agent/v1/policy`, `POST /agent/v1/policy/ack`.

### Agent operator pinning

The daemon continues to start with the existing `agentfw serve` command. In its operator-controlled environment, set:

- `SOUP_MANAGED_AGENT_CONSOLE=http://127.0.0.1:8080/` (or correct private loopback port)
- `SOUP_MANAGED_AGENT_TOKEN`: once-issued Agent Bearer credential
- `SOUP_MANAGED_AGENT_TENANT`, `SOUP_MANAGED_AGENT_ID`: exact enrolled audience
- `SOUP_MANAGED_AGENT_KEY_ID`, `SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX`: independently provisioned and pinned Ed25519 issuer key

Omitting `SOUP_MANAGED_AGENT_CONSOLE` disables managed polling entirely. The current bounded integration refuses non-loopback and non-HTTP origins (the remote TLS deployment is a different task). The Agent periodically fetches at most 96 KiB, validates, invalidates prior pending grants **explicitly**, writes a private signed last-accepted envelope, and switches policy **inside the existing `AgentFirewall`**. This preserves in-process session taint, incomplete-history indicators and authority; it does not silently reset the Agent's enforcement mode. A previous accepted envelope is restored on restart, including during Console outage; a previously expired envelope can remain the last accepted state but cannot authorize a new deployment.

## Failure semantics and outstanding review boundaries

- **Replayed, cross-tenant/Agent, modified, expired, unknown/revoked-key or invalid YAML**: reject before activation and attempt an authenticated `rejected` acknowledgement; preserve the last active policy.
- **Console offline/unavailable**: retain the last accepted active policy, expose transport status separately, and retry. If an `applied` ack failed, the same signed pending deployment can be acknowledged again *without* a second application.
- **Rollback**: issue a **new** higher-sequence signed deployment of a previously approved payload; do not replay an old signed bundle.
- **Revoked enrollment**: server refuses all future fetches and acknowledgements using the old Agent token. Already active policy is not remotely erased.
- **Key rotation**: issuer seed/key ID and independently pinned Agent public key are operator-provisioned. Changing keys requires coordinated local reprovisioning/restart; an unexpected new key fails. There is no online trust-root update.
- **Approval-grant boundary**: pending files are removed and a durable policy epoch is advanced under a cross-process OS file lock shared with CLI issuance and authoritative ledger redemption. A grant carries its signed epoch, so an already-loaded stale grant must fail even when its file was deleted. The hook also rechecks the running deployment after asynchronous judging and refuses a pre-tool decision that spans activation. These changes address the P2 review witness but still require completed exact-head CI and independent concurrency/security review before merge.
- **Trust limits**: an authenticated Agent `applied` assertion is an observation of this software process, **not hardware remote attestation**. Local file/OS compromise is outside the bounded slice.

## PostgreSQL managed enrollment and rollout (SOU-42)

Managed routes use the configured tenant-store backend through async store methods.
With `tenant_store.backend: postgres`, explicitly run `llm-firewall migrate` with
the migration role before starting Console. Migration 26 adds enrollment,
immutable revision and deployment tables to an existing v25 database; ordinary
startup checks the schema and performs no DDL. Use the existing PostgreSQL TLS
configuration and database roles. SQLite remains supported with the same wire
format and issuer transcript.

Only the enrollment response returns the credential. Storage contains a
domain-separated SHA-256 hash, and inventory exposes neither token nor hash.
Revision approval is explicit. Revision payloads cannot be overwritten through
the API. Every deployment locks the active tenant and enrolled Agent, selects the
next sequence and stores the signed bundle in one transaction. Delivery and
acknowledgement serialize on the same Agent row; revocation's row update shares
that serialization boundary. Distinct tenants may use the same Agent ID without
sharing credentials, revisions or sequences.

Fetching a pending deployment again returns the identical signed bundle. An
exact retry of the latest terminal acknowledgement returns HTTP 204 without
changing its timestamp. Mismatched hashes/revisions, superseded sequences and
conflicting terminal statuses return HTTP 409. A rejected deployment remains
terminal. These retry semantics apply to SQLite too. An explicit deployment POST
still issues a new sequence: the existing API has no deployment idempotency key,
so clients must inspect deployment inventory after an ambiguous POST outcome.

The separate Linux/Docker witness uses a pinned disposable PostgreSQL container
with verified TLS, the actual Console, and the unchanged `agentfw serve` process
over the existing loopback transport. It upgrades a populated v25 database using
an unmodified base Console, tests concurrent deployment requests, retry/isolation
and revocation boundaries, restarts the database and Console, and observes
`deny -> defer -> deny` at the live hook with three matching applied records.
Offline operation must retain the last accepted policy.

```bash
# Build the v25 fixture once from the reviewed pre-change source.
git worktree add --detach target/managed-previous e6f6305
CARGO_TARGET_DIR="$PWD/target" cargo build --locked --manifest-path target/managed-previous/Cargo.toml -p llm-firewall --bin llm-firewall
cp target/debug/llm-firewall target/previous-console
cargo build --locked -p llm-firewall -p agentfw
python3 -m venv target/managed-driver
target/managed-driver/bin/python -m pip install cryptography==50.0.2
target/managed-driver/bin/python scripts/managed-policy-postgres-demo.py --no-build --previous-gateway target/previous-console
```

The witness accepts no operator database URL. Generated credentials stay in
memory/private process environments; temporary logs and keys are removed with
the fixture. Only sanitized checks, runtime observations, source/config/binary
hashes and the pinned database version are retained in
`target/sou42-managed-postgres-evidence.json`, after owned resources are cleaned
up. CI runs this in `.github/workflows/managed-policy-postgres.yml`; the separate
SQLite runtime demonstration remains enabled. Successful checks are evidence
for independent review, not permission to self-approve or mark the task Done.

SOU-15 retains responsibility for MCP/resource confinement; SOU-26 owns release publication. This PR must remain Draft until integration tests and security review pass for the exact final source.
