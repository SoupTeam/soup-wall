# SOU-88 Linux Native Resource Ask Confirmation Evidence (2026-10-18)

Evidence record for single-use operator Ask confirmation of constrained Linux native resource executors (`read_document`, `create_file`, `https_get`) under the Codex methodology.

## 1. Scope & Security Invariants

- **Scope Boundary:** Constrained Linux native resource executors under direct/1, linux-root-child/1, and constrained network executor profiles, along with compatible SOU-67 operator bindings.
- **Refused Scope:** Windows and macOS resource approvals remain explicitly refused (`native_approval_resource_tool_unsupported`). Real-fs create (SOU-83) and HTTPS POST / network writes (SOU-73) are strictly refused.
- **Non-Escalation & Hard Floor:** A hard Deny verdict from policy, lineage floor, egress allowlist, or classifier can never be approved or redeemed (`native_approval_hard_deny`). Egress denial checks compose before opening and redeeming approvals.
- **Classifier Ambiguity Ineligibility:** SOU-88 strictly excludes unknown or ambiguous classifications (`unknown == true` or `uncertainty >= 0.8`) on resource tool calls. Such calls are withheld immediately with `classifier_unknown_or_ambiguous` without opening approvals. Reclassification following operator confirmation cancels pending approvals on ambiguity.
- **Terminal Invalidation on Refusal:** Any presented approval that encounters validation, lineage, egress, binding, or early resource refusal is terminally closed (`State::Closed(reason)`), preventing replay or retrying under the original URL/payload.
- **Single-Use Authorization:** Approval authorizes exactly one execution of the identical bound request. Provenance taint and incomplete history flags are preserved and never cleared by approval.
- **Zero Hostile Child Invocations:** Constrained execution dispatches directly via native executors; the child MCP server receives zero dispatches.

## 2. Key Modules & Implemented Architecture

| Module | Purpose |
|---|---|
| `crates/agentfw/src/native/resource_approval.rs` | Supported tool classification with strict compile-time `cfg!(target_os = "linux")` gating (no environment or test bypasses), frozen `resource_details` building, and execution revalidation. |
| `crates/agentfw/src/native/approval.rs` | State machine support for resource inspection details, binding verification, lineage validation, egress checks, and session-ownership-validated terminal invalidation. |
| `crates/agentfw/src/native.rs` | Execution gate floor composition, redemption revalidation (`revalidate_resource_execution`), and terminal invalidation for early resource authorization and egress refusals. |
| `crates/agentfw/src/mcp/admission.rs` | Gateway admission loop holding and resuming resource calls upon Ask approval, pre-checking classifier ambiguity, and validating reclassification using identical authority context. |
| `crates/agentfw/tests/resource_approval_witness.rs` | 9-part independent witness verification suite testing approvals, rejections, mutations, expirations, hard Deny, taint confinement, egress denial, terminal invalidation, and platform refusal. |
| `crates/agentfw/tests/mcp_admission.rs` | End-to-end MCP admission gateway tests covering real executor dispatch, rejection, platform boundary refusal, and classifier ambiguity/reclassification cancellation. |

## 3. Independent Witness Test Results

Verification suite executed via `cargo test -p agentfw --test resource_approval_witness`:

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
   - Operator approves; resubmitted call releases authorization.
   - Replay attempt fails closed with `native_approval_spent`.

4. `witness_https_get_approved_executes_once_and_rejection_zero_execution`:
   - Submits `https_get` call under `network` Ask policy with allowlisted egress host.
   - Operator inspects `resource_details` (operation: https_get, URL, method: GET).
   - Operator approves; resubmitted call releases; replay rejected.
   - Argument mutation (altered URL) fails closed with `native_approval_binding_mismatch`.
   - Retrying original URL after mutation refusal fails closed with `native_approval_closed`.

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

7. `witness_https_egress_denial_cannot_open_or_redeem_approval`:
   - Submits `https_get` to non-allowlisted host; daemon returns `verdict: deny`, `native_https_egress_not_allowlisted`.
   - Approval opening fails with HTTP 409 Conflict (`native_approval_hard_deny`).
   - Redemption control: approval opened while egress was allowed, but egress permission revoked before redemption; redemption returns `verdict: deny`, `release: false`, and terminally invalidates approval. Retrying fails with `native_approval_closed`.

8. `witness_refused_mutation_terminally_invalidates_approval`:
   - Operator approves original URL.
   - Mutated URL submitted; refused with `native_https_url_not_allowed` or binding mismatch.
   - Early resource refusal routes to `approval.invalidate(...)`.
   - Retrying original URL with same `approval_id` returns `release: false` and `native_approval_closed`.

9. `witness_non_linux_platform_refusal`:
   - Verified on non-Linux platforms (macOS): resource approval opening is strictly refused with `native_approval_resource_tool_unsupported`.
   - Environment variables (`CARGO_MANIFEST_DIR`, `AGENTFW_TEST`) cannot bypass the `target_os = "linux"` compile-time boundary.

## 4. MCP Gateway Integration Tests

Integration suite executed via `cargo test -p agentfw --test mcp_admission sou88`:

1. `sou88_resource_create_ask_operator_approval_runs_once_and_reject_zero_execution`:
   - Gateway intercepts resource call and holds client frame.
   - Rejection returns `native_approval_rejected` with 0 executions.
   - Approval re-presents identical request and executes cleanly through native executor.
   - Platform boundaries: non-Linux platforms refuse execution cleanly with `resource_create_platform_unsupported`.
   - Child MCP server process receives zero tool call dispatches (`executed.len() == 0`).

2. `sou88_resource_classifier_unknown_ambiguous_ineligible`:
   - Tests high uncertainty (`uncertainty: 0.9 >= 0.8`): withheld immediately, 0 pending approvals.
   - Tests unknown classification (`unknown: true, uncertainty: 0.1`): withheld immediately, 0 pending approvals.
   - Tests exact boundary (`uncertainty: 0.8`): withheld immediately, 0 pending approvals.
   - Tests reclassification: eligible initial call (`uncertainty: 0.2`) approved by operator; reclassification returns `uncertainty: 0.9` -> approval canceled, call withheld with `native_approval_reclassify_refused`, target file never created.

## 5. Formatting & Linting Verification

Commands executed:
- `cargo fmt --check`: Clean exit code 0.
- `cargo clippy --locked -p agentfw --all-targets -- -D warnings`: Clean exit code 0.
