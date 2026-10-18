# Linux Native Resource Ask Operator Guide (SOU-88)

This guide documents the operator inspection and confirmation workflow for constrained Linux native resource executors when an MCP call evaluates to Ask.

## 1. Overview & Scope Boundaries

Under SOU-88, single-use operator Ask confirmation is supported for constrained Linux native resource tools:
- Linux `read_document` under the direct/1 profile (`sw-native/read-document/direct/1`).
- Linux `create_file` under the linux-root-child/1 profile (`sw-native/create-file/linux-root-child/1`).
- Linux `https_get` under the constrained network executor profile.
- Compatible operator-owned tool bindings under `sw-native/binding/1` (SOU-67).

### Explicit Refusals & Out-of-Scope Boundaries

The following operations are strictly refused and cannot be authorized by an operator approval:
- Windows and macOS resource tools: Windows handles and macOS native execution remain explicitly refused (`native_approval_resource_tool_unsupported`).
- Confined real-fs create profiles (SOU-83): real-fs create is out of scope.
- HTTPS POST and non-GET network mutations (SOU-73): network write operations are strictly refused.
- Hard Deny policies: if the policy or classifier evaluates to hard Deny, operator approval is rejected (`native_approval_hard_deny`). An approval cannot rescue a hard Deny.

## 2. Operator Inspection Workflow

When a constrained resource call evaluates to Ask (via daemon policy rule `action: ask` or classifier uncertainty), the MCP gateway stalls the original call frame and creates a pending approval record.

### Step 1: Listing Outstanding Approvals

The operator lists unexpired pending approvals:

```bash
agentfw native-approval list
```

This returns high-level metadata (pending id, tool name, binding digest, expiration time) without exposing raw argument bytes.

### Step 2: Inspecting Detailed Resource Attributes

The operator inspects the full record, including frozen resource details:

```bash
agentfw native-approval inspect <pending_id>
```

For resource tools, the returned JSON record includes the `resource_details` block:

```json
{
  "pending_id": "...",
  "tool": "save_artifact",
  "binding_sha256": "...",
  "resource_details": {
    "operation": "create_file",
    "executor_profile": "sw-native/create-file/linux-root-child/1",
    "canonical_path": "/workspace/target.txt",
    "target_destination": "target.txt",
    "payload_length_bytes": 1024,
    "max_content_bytes": 4096
  }
}
```

For `read_document`:
- `operation`: `"read_document"`
- `canonical_path`: canonical path of the target document within workspace bounds.
- `allowed_resources`: canonical paths permitted by policy.

For `https_get`:
- `operation`: `"https_get"`
- `url`: target URL string.
- `host`: destination hostname.
- `method`: `"GET"`.

## 3. Decision & Execution

### Approving an Operation

To approve the exact call:

```bash
agentfw native-approval approve <pending_id> --binding <binding_sha256>
```

Requirements for successful approval:
1. The `--binding` parameter must match the computed `binding_sha256` digest exactly.
2. The approval is signed with the native approval key and recorded in `<home>/native-grants/<id>.json`.
3. The gateway resumes the call and presents `approval_id` to the execution gate.
4. The execution gate revalidates workspace containment, path boundaries, target existence (for create), and checks that the grant has not been spent.
5. The grant is recorded in `<home>/native-grants-spent.json`. The action executes exactly once.

### Rejecting an Operation

To reject the pending call:

```bash
agentfw native-approval reject <pending_id>
```

Effects of rejection:
1. The pending record is atomically transitioned to `rejected`.
2. The gateway immediately returns an MCP error reply containing `native_approval_rejected`.
3. Zero native executions occur; the target resource is never touched; the child MCP server is never invoked.

## 4. Replay Prevention & Single-Use Ledger

Replay prevention operates across multiple independent layers:
1. **Grant Spend Ledger:** Once redeemed, the grant ID is marked spent in `native-grants-spent.json`. Subsequent resubmissions are rejected with `native_approval_spent`.
2. **Target File Existence (create_file):** For `create_file`, if the target file already exists, re-submission fails closed with `native_create_target_exists_or_unavailable`.
3. **Binding Immutability:** Any change to arguments, session epoch, destination, or payload invalidates the binding digest and fails redemption with `native_approval_binding_mismatch`.

## 5. Provenance Taint Preservation

Operator approval is scoped strictly to authorization of the single native execution.
- Single-use approval does **not** clear session taint.
- Single-use approval does **not** clear incomplete history flags (`provenance_incomplete`).
- Subsequent actions in the same session must continue to satisfy all security and taint policies independently.
