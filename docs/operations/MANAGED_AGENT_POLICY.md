# Managed Agent policy rollout (SOU-30)

> **Status: work in progress.** This document specifies the implemented signed-bundle verifier and the intended rollout contract. The Console API, live activation, acknowledgements and executable rollback demonstration are **not yet implemented**. Do not claim this branch as release-ready.

## Separation of policy types

Managed policy bundles carry the YAML `soup_wall_agent::AgentPolicySet`, not the Gateway's `TenantPolicyDocument`. They MUST NOT modify `agentfw::Config.enforce`, the operator-controlled native registry, local executor permissions, or judge configuration.

## v1 signed envelope

The Rust type is `agentfw::managed_policy::SignedAgentPolicy`. Required JSON properties:

| Property | Meaning |
| --- | --- |
| `schema_version` | Exact integer 1 |
| `tenant_id`, `agent_id` | Exact, operator-enrolled audience |
| `revision` | Approved immutable Agent policy revision |
| `deployment_sequence` | Strictly increasing per enrolled Agent, including rollback |
| `issued_at_unix`, `expires_at_unix` | Unix seconds; expiry exclusive, maximum 86,400-second lifetime |
| `issuer_key_id` | References an independently pinned Ed25519 public key |
| `policy_yaml` | Raw UTF-8 AgentPolicySet YAML; max 64 KiB |
| `policy_sha256` | Lowercase SHA-256 of the raw UTF-8 YAML bytes |
| `signature_hex` | Lowercase hex encoding of the Ed25519 signature (64 bytes) |

Unknown fields are rejected. Before parsing, cap the entire JSON body to **96 KiB**. Signing bytes are constructed without canonical JSON: begin with ASCII `soup-wall-agent-policy-bundle-v1` followed by one NUL byte, then each of the first ten properties above **except signature_hex**, in the declared order. Encode every property as its UTF-8 string (numeric values in plain base-10 ASCII) prefixed with a 4-byte unsigned **big-endian** length. Sign this transcript with Ed25519; hex-encode the signature. This binds exact audience, revision, deployment order, key ID and payload to one signature.

## Trust and verification

An Agent must obtain its issuer key ID/public key independently from its local operator-controlled configuration. **Never trust a signing key delivered alongside the policy.** Unknown, revoked, malformed or mismatched keys fail. Reject wrong audience, modified policy/digest, expired bundle, future issuance outside the 60-second clock-skew allowance, invalid AgentPolicySet, and a deployment sequence not strictly greater than the highest durable accepted sequence. New keys require local operator provisioning and revoked keys must not validate fresh deliveries.

SQLite enrollment is handled in `tenant_store::agent_enrollment`. One Agent credential is returned once and stored only as a domain-separated SHA-256 hash, entirely separate from admin, tenant and service tokens. A revoked enrollment fails subsequent credential authentication; caller code must not accept a cached claim.

## Safety invariant for the unfinished runtime slice

Only after signature verification **and** successful in-process policy installation may the Agent durably record the new accepted sequence and report `applied` with its actual exposed revision and SHA-256. Download receipts (`delivered`) are not application proofs. A failed attempt must retain the last accepted policy and all session taint, incomplete-history indicators and admission evidence. Grant invalidation must be explicitly handled; simply creating a fresh AgentFirewall discards security history and is forbidden. Offline, stale and rejected states need distinct evidence.

Rollback is a **new, higher-sequence signed deployment** of a previously approved payload, not a replay of an old envelope. Required demonstration: one disposable SQLite Console and existing local `agentfw serve` show a real changed verdict after activation and restored verdict after rollback. Add tamper, cross-tenant, replay, revocation, key-rotation and unavailable-Console tests before marking this PR ready for review.

## Current checkpoint and remaining work

- [x] Independently pinned Ed25519 candidate-bundle verifier with focused negative tests in `agentfw`.
- [x] SQLite-backed managed Agent enrollment/credential hash/revocation store with focused tests.
- [ ] Wire admin/operator enrollment endpoints; separate Agent fetch and acknowledgment routes.
- [ ] Implement approved policy revisions, issuer signing, immutable deployments and status persistence.
- [ ] Fetch, validate, safely activate and attest the running policy without clearing any session evidence.
- [ ] Authenticated applied/rejected acknowledgments, rotation/offline recovery and rollback sequencing.
- [ ] One-command E2E demonstration, integration testing and passing current-head CI.

The SOU-26 release-gate and SOU-15 MCP/resource isolation remain owned by their respective teams. This milestone is **not** deployment authorization.
