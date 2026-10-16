# SOU-63 Acceptance and Final Verification (2026-10-16)

This document records the full verification and evidence for closing Linear ticket **SOU-63**:
`feat/sou-63-mcp-hook-provenance-sessions` (PR #146).

## Deliverables Summary

1. **Authenticated Agent and Parent Identity Binding**:
   - `ChildAuthorityGrant` carries `agent_id`, `parent_id`, and `granted_resources` with domain-separated length-prefixed HMAC-SHA256 signing.
   - HTTP `/hook` payloads accept optional `parent_id` alongside `agent_id` and `session_id`.
   - Event mapping into `AgentEvent` preserves authentic `agent` and `parent` identities instead of hardcoded fallbacks.
   - Covered by `sou63_child_authority_binds_authenticated_agent_and_parent_identity`.

2. **Authority and Resource Narrowing with Explicit Refusal of Unprovable Delegations**:
   - `ChildAuthorityGrant` scopes `granted_tools` and `granted_resources`.
   - Session starts verify signature, issuer, expiration, host session, and server ID.
   - Resource policies (`read_document`, `create_file`, `send_http`) are checked against the child's `granted_resources`.
   - Any escalation attempt (unlisted tools, ungranted filesystem paths, unauthorized egress destinations) or unprovable delegation fails closed with `native_child_authority_escalation` or `native_child_authority_denied`.
   - Covered by `sou63_child_authority_narrows_resources_and_destinations_relative_to_parent`.

3. **Deterministic Real-Process Witnesses**:
   - `sou63_real_process_cross_collector_taint_server_a_to_server_b`:
     - Spawns real stdio child processes for Server A and Server B under separate daemon sessions bound to the same `host_session`.
     - Server A executes `read_document` and returns untrusted content (`Provenance::McpServer { name: "server_a" }`).
     - Server B attempts a destructive action reusing tainted content.
     - The daemon detects the shared host taint and withholds Server B's invocation before execution (`fixture-mcp-reuse`).
     - Server B's execution ledger remains completely empty (no effects).
     - An independent unbound session continues ordinary work without restriction.
   - `sou63_real_process_hook_to_mcp_taint_and_lifecycle`:
     - Injects untrusted data into `host_session` via HTTP `/hook`.
     - An actual stdio MCP child process bound to `host_session` attempts a destructive action reusing that taint.
     - The daemon withholds the MCP invocation before server execution.
     - Session termination cleans up active handles and resets sequence allocation without leaking cross-session state.

4. **Truthful Support Matrix and Boundaries Documentation**:
   - Reconciled [MCP_STDIO_ADMISSION.md](../MCP_STDIO_ADMISSION.md) with complete Identity & Transport Support Matrix, exact refusal reasons, authority delegation rules, and lifecycle boundaries.

## Verification Suite Results

| Test Target / Suite | Passed | Failed | Status |
| --- | --- | --- | --- |
| `cargo test --offline -p agentfw --test native_endpoint` | 86 | 0 | PASS |
| `cargo test --offline -p agentfw --test mcp_admission` | 69 | 0 | PASS |
| `cargo test --offline -p agentfw --test hook_endpoint` | 13 | 0 | PASS |
| `cargo test --offline -p agentfw --test protection_status` | 19 | 0 | PASS |
| `cargo test --offline -p agentfw --lib` | 280 | 0 | PASS |
| `cargo test --offline --workspace` | All suites | 0 | PASS |
| `cargo clippy --all-targets -- -D warnings` | Zero warnings | 0 | PASS |
| `cargo fmt --check` | Clean | 0 | PASS |
