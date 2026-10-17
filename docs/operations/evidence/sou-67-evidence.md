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
| Universal Scoping | `crates/agentfw/src/mcp/admission.rs` | Enforces matching `collector.config.server_id == policy.profile.server_id` across all versioned bindings (`policy.binding.is_some()`), create, https, and windows handles, while preserving backward compatibility for legacy unbound Unix read continuations. |
| Mutual Exclusivity | `crates/agentfw/src/native/resource.rs` | Separately counts all authority declarations (`execution`, `binding`, `network`, `windows_read`) in `Policy::validate`. Rejects dual specification with `conflicting operator execution policies`. `effective_execution()` uses exclusive match. |
| Dynamic Dispatch | `crates/agentfw/src/mcp/admission.rs` | Constrained execution dispatches based on `is_read_bound_or_named` and `is_create_bound_or_named`. Content and path are extracted via `crate::mcp::resources::selected` without `.unwrap()` assumptions on nested schemas. |
| Profile Authoring | `crates/agentfw/src/mcp/profile_author.rs` | Preserved profile authoring CLI constructors compatibly across `main` merge (`afa00125264b227cdc3e249c1cd010a9c59d65a3`). |
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

5. **Inherited Security Finding — Server ID Scoping & Continuation Compatibility:**
   - Scoped server identity check: enforces matching `collector.config.server_id == policy.profile.server_id` across all versioned bindings (`policy.binding.is_some()`), create, https, and windows handles, while preserving compatibility for legacy unbound Unix read continuations (tested in `verify-sou54-create-file.py`).
   - Negative witness `sou67_read_policy_server_id_mismatch_refused` verifies refusal with `resource_server_identity_mismatch` and zero child dispatch for versioned bindings.

6. **Cross-Platform & Result Firewall Verification:**
   - Direct Unix create test `sou67_operator_owned_tool_bindings_allow_arbitrary_create_tool_name_under_constrained_execution` is guarded with `#[cfg(unix)]`, preventing unsupported platform panic during registry loading on Windows.
   - Scoped fixture firewall policy (`CREATE_POLICY`) configures `min_severity: medium` on `fixture-result-injection`, ensuring 64-character SHA-256 digests in create receipts are released cleanly without false-positive injection withholding.

7. **P1 — Rejection of Simultaneous Dual Declarations (Binding & Execution):**
   - In `crates/agentfw/src/native/resource.rs`:
     - Updated `Policy::validate` to count `self.execution.is_some()` and `self.binding.is_some()` as distinct entries in the authority count `<= 1` check. Simultaneous dual specification is rejected with `"conflicting operator execution policies"`.
     - Replaced `effective_execution()` with an explicit exclusive match:
       ```rust
       pub fn effective_execution(&self) -> Option<ExecutionPolicy> {
           match (&self.binding, &self.execution) {
               (Some(binding), None) => Some(binding.to_execution_policy()),
               (None, Some(execution)) => Some(execution.clone()),
               _ => None,
           }
       }
       ```
   - Added production-parser regression test in `crates/agentfw/tests/native_endpoint.rs` (`sou67_native_parser_rejects_dual_binding_and_execution`):
     - Positive controls verify that `execution-only` and `binding-only` load successfully and preserve effective execution.
     - Negative controls verify rejection of dual specification across identical dual authority, conflicting operations, unsupported profiles, incompatible paths, undersized content, and the reviewer's witness.

8. **P2 — Compatible Integration with Accepted Main (SOU-65 Profile Authoring CLI):**
   - Clean merge with accepted `main` (`afa00125264b227cdc3e249c1cd010a9c59d65a3`).
   - In `crates/agentfw/src/mcp/profile_author.rs`: compatibly updated `Policy` initializers with `binding: None` and `ExecutionPolicy` with `path_selector: None`, `content_selector: None`, `response_contract: None`.
   - Verified with `cargo check --locked --offline -p agentfw --lib` (Exit 0) and `cargo test --locked -p agentfw mcp::profile_author` (Exit 0).

---

## 3. Verification Commands & Results

| Command | Expected | Actual |
|---|---|---|
| `cargo check --locked --offline -p agentfw --lib` | Exit 0, clean | Exit 0, clean |
| `cargo fmt --check` | Exit 0, clean | Exit 0, clean |
| `cargo clippy --all-targets -- -D warnings` | Exit 0, 0 warnings | Exit 0, 0 warnings |
| `cargo test --locked -p agentfw --test native_endpoint sou67_native_parser_rejects_dual_binding_and_execution` | 1 passed, 0 failed | 1 passed, 0 failed |
| `cargo test --locked -p agentfw mcp::profile_author` | 2 passed, 0 failed | 2 passed, 0 failed |
| `cargo test -p agentfw --test mcp_admission` | 75 passed, 0 failed | 75 passed, 0 failed |
| `cargo test -p agentfw --test native_endpoint` | 115 passed, 0 failed | 115 passed, 0 failed |
| `cargo test --workspace --locked` | All passed | All passed |
| `scripts/verify-sou54-create-file.py` | Exit 0 | Exit 0 (required_os: Linux) |
