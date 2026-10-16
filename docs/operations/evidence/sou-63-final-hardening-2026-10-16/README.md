# SOU-63 final hardening and acceptance evidence

Implementation based on `36d02ae4eed49ed6fa9aa63524d3d9b4cfa182d4`; exact tested source is pinned in [source-manifest.json](source-manifest.json). This supersedes the findings in the 8dd0ee2 and 36d02ae re-reviews for the supported scope described below. Reviewer approval remains an external decision.

## Completed fixes

- Reject partial, unsigned, forged, mismatched and duplicate scoped identities before granting authority.
- Resolve a genuine live parent; require child tool/resource/destination containment. Missing parent/scope, expiry, idle eviction, end and replacement cannot widen authority. A signed parent binding in the grant nonce prevents an old child token from bootstrapping under a replacement parent's epoch, even when the agent name and scope are unchanged.
- Bind scoped grant nonces to a random daemon instance. After restart an old scoped grant is refused; legacy isolated HMAC encoding remains compatible.
- Authenticate scoped hooks with the exact active collector grant in `X-Agentfw-Child-Authority`, rather than trusting payload IDs or a shared bearer. Validate expiry and every ancestor. Support exact registry names and `mcp__SERVER__TOOL` only for the verified server; evaluate canonical tool names using immutable registry semantics without changing the wire-tool approval binding.
- Serialize session lifecycle and hook policy evaluation in native-session → firewall lock order, then recheck authority after any judge await before approval redemption/decision.
- Refused PostToolUse and other lost inspection paths preserve sticky incomplete host history, including shadow mode. Signed result provenance always remains untrusted and comes from the verified MCP server.
- Match canonical path components and typed URL/mailbox/domain narrowing. A missing parent resource scope never creates proven child destination authority.
- Remove completed per-agent authority without clearing other agents or host taint. Keep bounded scoped-host tombstones, refusing new hosts at capacity instead of silently reverting completed hosts to unsigned mode.
- Strip authority/session and native/hook bearer environment variables from child MCP servers. Retained audit and acceptance evidence contain no authority tokens, signing keys or raw private payloads.
- Fix CLI parsing for randomly generated instance IDs beginning with `-`, covered by a deterministic regression.

The seven reviewer witnesses are integrated. Older positive fixture setup now registers actual parents instead of assuming arbitrary parent strings are valid. Additional controls cover valid signed hooks, claim/server/tool swaps, duplicate-agent supersession, expiry of ancestors, both existing-child and unused/replayed-child behavior after parent replacement, restart, capacity, shadow history loss, credential inheritance and the CLI parser edge case.

## Verification

See [results.json](results.json) and [suite-results.json](suite-results.json) for the authoritative final counts. The full workspace passed 1244 tests with 0 failures and 10 explicit ignores. A final portable path-fixture adjustment was followed by all 281 library tests and clippy again; production behavior was unchanged. The full workspace was tested offline in an isolated source export, with writes restricted to `/private/tmp/sou63-review` and networking limited to owned loopback fixtures. Tested Rust source bytes were compared against the working tree. Clippy ran across all targets with `-D warnings`; formatting was checked with `cargo fmt --all --check`.

Focused targets: 109 native endpoint, 71 MCP admission, 13 hook endpoint, 19 protection status, 281 agentfw library tests. The workspace also exercises 21 managed-group rollout tests; no SQLite/PostgreSQL implementation changes were made. Explicitly ignored tests requiring external/live-model or environment-specific facilities remain ignored. Local macOS verification does not replace Linux/Windows PR CI.

## Real-process acceptance

[real-process.json](real-process.json) is parsed from the actual test-run witness output and pins policy, registry, executable and owned-server source digests plus hashed signed bindings and synthetic identity claims.

1. Server A emits untrusted content into a verified host. A distinct Server B has its own server ID and is registered as an actual child of A with a narrower tool grant. B's destructive call is refused by `fixture-mcp-reuse`; its backend execution ledger stays at **0**. A clean separate session executes **1** useful operation.
2. An authenticated HTTP hook uses the exact active collector proof. Its untrusted result taints the same host; the subsequent real stdio MCP call is refused before backend execution (**0** operations).

Every count is asserted against a backend execution ledger. These fixture-policy checks establish the integration boundary; they do not claim live-model efficacy or model-context consumption attestation.

## Operator migration and support boundary

Follow [MCP_STDIO_ADMISSION.md](../../MCP_STDIO_ADMISSION.md). Issuers obtain the current daemon instance and live parent binding from authenticated `GET /native/v1/instance`; scoped mint requires `--instance-id`, and `--parent-id` requires `--parent-binding`. Old scoped grants must be reissued. Hooks in scoped hosts require signed proof; the default installer stays in legacy mode and does not overwrite active host configuration.

Hooks lack native resource/executor receipts. Unverifiable builtin delegation and resource-policy operations are explicitly refused in scoped hook mode; use native admission with its existing confinement contracts. After a daemon restart, start fresh host conversations and issue new grants. There is no claim of durable model-context disposal, kernel process attestation, or hook enforcement during daemon outage.
