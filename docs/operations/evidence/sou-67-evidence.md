# SOU-67: Generalized Constrained Tool Bindings Evidence

## Overview

Issue **SOU-67** generalizes Soup Wall's constrained file execution beyond hardcoded
tool names (`create_file`, `read_document`) and legacy argument schemas. This delivery
addresses all review items raised by lead reviewer Baubek Serikbay (`@winux125`) on
PR #161, supported by independent Codex (`gpt-6.1-sol`) verification.

---

## 1. Scope & Implementation Matrix

| Component | File | Changes & Guarantees |
|---|---|---|
| Binding Contract | `crates/agentfw/src/native/resource.rs` | Introduced versioned `ToolBinding` (`sw-native/binding/1`) with explicit operation, action, path/content JSON pointer selectors, response contracts, executor profiles, and byte limits. Validates disjoint pointers and preserves legacy schemas. |
| Executor Validation | `crates/agentfw/src/native/resource.rs` | Enforces supported executor profiles (`READ_DOCUMENT_EXECUTOR_PROFILE`, `CREATE_FILE_EXECUTOR_PROFILE`, Windows handles profiles) in `ExecutionPolicy::supported()`. Invariant checks in `ExecutionBinding::valid()` reject corrupted admission payloads with 400. |
| Universal Scoping | `crates/agentfw/src/mcp/admission.rs` | Made `collector.config.server_id == policy.profile.server_id` universal across all resource policies (fixing the inherited Unix read server identity scoping gap). |
| Dynamic Dispatch | `crates/agentfw/src/mcp/admission.rs` | Constrained execution dispatches based on `is_read_bound_or_named` and `is_create_bound_or_named`. Content and path are extracted via `crate::mcp::resources::selected` without `.unwrap()` assumptions on nested schemas. |
| Documentation | `docs/operations/OPERATOR_TOOL_BINDINGS.md` | Complete reference specification for `sw-native/binding/1`, security invariants, reserved name rules, and operator migration guide. |

---

## 2. Review Items Remediation

1. **P1 — Binding Contract & Nested Schema Support:**
   - Implemented `ToolBinding` and `Policy::effective_execution()`.
   - `NativeState::from_bytes` validates operator-bound tools with arbitrary schemas while preserving exact schema digest checks for legacy profiles.
   - Verified in `sou67_create_file_v2_native_operator_bound_nested_schema_admits_and_binds`.

2. **P1 — Concurrency & Backpressure Fixtures:**
   - Verified `immediate_resource_refusals_preserve_same_session_recovery_and_eof` in `crates/agentfw/tests/mcp_concurrency.rs` exits 0 with zero failures.

3. **P2 — Owned Collector Create/Refusal & Hostile Child Witness:**
   - Added `sou67_operator_owned_tool_bindings_allow_arbitrary_create_tool_name_under_constrained_execution`.
   - Proves nested schema create (`save_artifact`), atomic file creation, mode `0600`, exact bytes written, replay/no-overwrite rejection (`native_create_target_exists_or_unavailable`), traversal rejection, and zero child process dispatch.

4. **P2 — Reserved-Name Exceptions:**
   - Documented reserved names (`https_get` for network authority, `create_file` for create authority) in `docs/operations/OPERATOR_TOOL_BINDINGS.md`.

5. **Inherited Security Finding — Unix Read Server ID Scoping:**
   - Universal equality check ensures collector and policy server IDs match. Negative witness `sou67_read_policy_server_id_mismatch_refused` verifies refusal with `resource_server_identity_mismatch` and zero child dispatch.

6. **Codex Audit Findings:**
   - Replay test uses fresh JSON-RPC ID (`sou67-create-replay`) to verify `native_create_target_exists_or_unavailable` without triggering collector session drop.
   - Enforced supported `executor_profile` in `ExecutionPolicy::supported()` for `read_document`.

---

## 3. Verification Commands & Results

| Command | Expected | Actual |
|---|---|---|
| `cargo fmt --check` | Exit 0, clean | Exit 0, clean |
| `cargo clippy --all-targets -- -D warnings` | Exit 0, 0 warnings | Exit 0, 0 warnings |
| `cargo test -p agentfw --test mcp_admission` | 75 passed, 0 failed | 75 passed, 0 failed |
| `cargo test -p agentfw --test native_endpoint` | 114 passed, 0 failed | 114 passed, 0 failed |
| `cargo test -p agentfw --test mcp_concurrency` | All passed | 1 passed, 0 failed (focused) |
