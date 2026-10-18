# SOU-88 Linux Native Resource Ask Confirmation Evidence (2026-10-18)

Evidence record for single-use operator Ask confirmation of constrained Linux native resource executors (`read_document`, `create_file`, `https_get`) under the Codex methodology.

## 1. Scope & Security Invariants

- **Scope Boundary:** Constrained Linux native resource executors under direct/1, linux-root-child/1, and constrained network executor profiles, along with compatible SOU-67 operator bindings.
- **Refused Scope:** Windows and macOS resource approvals remain explicitly refused (`native_approval_resource_tool_unsupported`). Real-fs create (SOU-83) and HTTPS POST / network writes (SOU-73) are strictly refused.
- **Non-Escalation:** A hard Deny verdict from policy or classifier can never be approved (`native_approval_hard_deny`).
- **Single-Use Authorization:** Approval authorizes exactly one execution of the identical bound request. Provenance taint and incomplete history flags are preserved and never cleared by approval.
- **Zero Hostile Child Invocations:** Constrained execution dispatches directly via native executors; the child MCP server receives zero dispatches.

## 2. Key Modules & Implemented Architecture

| Module | Purpose |
|---|---|
| `crates/agentfw/src/native/resource_approval.rs` | Supported tool classification, frozen `resource_details` building, and execution revalidation. |
| `crates/agentfw/src/native/approval.rs` | State machine support for resource inspection details and binding verification. |
| `crates/agentfw/src/native.rs` | Execution gate revalidation during redemption (`revalidate_resource_execution`). |
| `crates/agentfw/src/mcp/admission.rs` | Gateway admission loop holding and resuming resource calls upon Ask approval. |
| `crates/agentfw/tests/resource_approval_witness.rs` | 6-part independent witness verification suite testing approvals, rejections, mutations, expirations, hard Deny, and taint confinement. |
| `crates/agentfw/tests/mcp_admission.rs` | End-to-end MCP admission gateway test (`sou88_resource_create_ask_operator_approval_runs_once_and_reject_zero_execution`). |

## 3. Independent Witness Test Results

Verification suite executed via `cargo test --test resource_approval_witness`:

```text
running 6 tests
test witness_hard_deny_cannot_be_approved ... ok
test witness_read_document_approved_executes_once ... ok
test witness_create_file_approved_executes_once ... ok
test witness_https_get_approved_executes_once_and_rejection_zero_execution ... ok
test witness_ask_after_provenance_loss_confinement ... ok
test witness_create_file_rejected_mutated_expired_zero_execution ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.21s
```

### Scenario Breakdown

1. `witness_create_file_approved_executes_once`:
   - Submits `create_file` call under `side_effecting` Ask policy.
   - Verifies daemon returns `verdict: ask`, `release: false`.
   - Inspects `resource_details` (operation, profile, canonical path, payload length).
   - Approves with exact binding digest; call resubmits with `approval_id`.
   - Verifies file created with exact payload and permissions 0600.
   - Verifies replay attempt fails with `native_approval_spent`.

2. `witness_create_file_rejected_mutated_expired_zero_execution`:
   - Rejection test: operator rejects pending approval; resubmission fails closed; 0 executions.
   - Expired test: pending approval expires past TTL; resubmission fails closed; 0 executions.
   - Mutated test: argument payload altered after approval; binding mismatch; 0 executions.

3. `witness_read_document_approved_executes_once`:
   - Submits `read_document` call under `read_only` Ask policy.
   - Inspects `resource_details` (operation, canonical path, allowed resources).
   - Operator approves; resubmitted call releases exact document content.
   - Replay attempt fails closed with `native_approval_spent`.

4. `witness_https_get_approved_executes_once_and_rejection_zero_execution`:
   - Submits `https_get` call under `network` Ask policy with allowlisted egress host.
   - Operator inspects `resource_details` (operation: https_get, URL, method: GET).
   - Operator approves; resubmitted call releases; replay rejected.
   - Argument mutation (altered URL) fails closed with `native_approval_binding_mismatch`.

5. `witness_hard_deny_cannot_be_approved`:
   - Submits `create_file` call under `action: deny` policy.
   - Daemon returns hard `verdict: deny`.
   - Approval attempt fails with HTTP 409 Conflict (`native_approval_hard_deny`).
   - Zero pending records; zero target creations.

6. `witness_ask_after_provenance_loss_confinement`:
   - Induces provenance context loss.
   - First call under taint triggers Ask; operator approves and call executes.
   - Invariant verified: `provenance_incomplete` remains `true`.
   - Subsequent call still requires Ask; no blanket authorization granted.

## 4. MCP Gateway Integration Test

End-to-end integration test executed via `cargo test --test mcp_admission sou88`:

```text
running 1 test
test sou88_resource_create_ask_operator_approval_runs_once_and_reject_zero_execution ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 77 filtered out; finished in 1.26s
```

Verifies:
- Gateway intercepts resource call and holds client frame.
- Rejection returns `native_approval_rejected` with 0 executions.
- Approval re-presents identical request and executes cleanly.
- Platform boundaries: non-Linux platforms refuse execution cleanly with `resource_create_platform_unsupported`.
- Child MCP server process receives zero tool call dispatches (`executed.len() == 0`).

## 5. Formatting & Linting Verification

Commands executed:
- `cargo fmt --check`: Clean exit code 0.
- `cargo clippy --all-targets -- -D warnings`: Clean exit code 0 (zero warnings across all targets).
