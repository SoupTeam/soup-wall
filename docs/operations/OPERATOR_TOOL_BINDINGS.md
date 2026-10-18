# Operator-Owned Constrained Tool Bindings (SOU-67)

Soup Wall supports **operator-owned constrained tool bindings** under the
`sw-native/binding/1` contract. This generalizes native resource confinement
beyond hardcoded tool names (`create_file`, `read_document`) and legacy argument
shapes, enabling operators to bind arbitrary tool names and custom (including
nested) argument schemas to reviewed native executors.

Host JSON-RPC frames, tool names, and original argument shapes are preserved
verbatim. The discovery child process starts to supply its manifest, but receives
**zero child invocation** when an admitted constrained call executes.

---

## 1. Specification & Binding Contract (`sw-native/binding/1`)

An operator specifies a tool binding in the native registry within the tool's
`resource_policy.binding` object:

```json
{
  "contract_version": "sw-native/binding/1",
  "operation": "create_file",
  "action": "write",
  "path_selector": "/spec/destination",
  "content_selector": "/spec/payload",
  "response_contract": "sw-native/response/text/1",
  "executor_profile": "sw-native/create-file/linux-root-child/1",
  "max_content_bytes": 4096
}
```

### Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `contract_version` | String | **Yes** | Must equal `"sw-native/binding/1"`. |
| `operation` | String | **Yes** | Target operation: `"create_file"` or `"read_document"`. |
| `action` | String | No | Target action class: `"write"` for create, `"read"` for read (inferred if omitted). |
| `path_selector` | String | **Yes** | RFC 6901 JSON pointer to target destination path string. |
| `content_selector` | String | For create | RFC 6901 JSON pointer to content string to be written. |
| `response_contract` | String | No | Supported format: `"sw-native/response/text/1"` or `"mcp/text_result/1"`. |
| `executor_profile` | String | No | Executor identity; defaults to standard operation profile if omitted. |
| `max_content_bytes` | Integer | No | Maximum UTF-8 content byte limit; defaults to 4,096 bytes for create. |

---

## 2. Validation & Security Controls

During registry ingestion and policy validation (`Policy::validate`):

1. **Pointer Validation:** Both `path_selector` and `content_selector` must be valid RFC 6901 JSON pointers (`valid_pointer`).
2. **Disjoint Selectors:** `path_selector` and `content_selector` must not be identical, and neither pointer may be a prefix of the other (preventing overlapping or ambiguous extraction).
3. **Profile Selector Alignment:** The profile's primary selector pointer must match `path_selector`.
4. **Action & Operation Invariants:** `create_file` requires `action: "write"` and action class `side_effecting`. `read_document` requires `action: "read"` and action class `read_only`. Corrupt or conflicting declarations are rejected with HTTP 400 `BAD_REQUEST`.
5. **Direct Workspace Child:** For `create_file`, the admitted destination must resolve to an immediate direct child of the approved `workspace` root (`workspace.join(leaf)`). Traversal (`..`), nested directories, and absolute paths escaping the workspace are refused.
6. **Server Identity Scoping:** Universal across Unix and Windows: the collector's configured `server_id` must match `policy.profile.server_id`. Mismatched identities fail closed with `resource_server_identity_mismatch`.
7. **Zero Child Execution:** When an invocation is admitted to a constrained executor, the call is serviced directly by native code. The child process receives zero tool call dispatches.

---

## 3. Name Reservations & Exceptions

- **`https_get`:** Reserved exclusively for HTTPS network authority. A tool named `https_get` without a valid network profile is refused with `resource_https_profile_required`.
- **`create_file`:** Reserved exclusively for file creation authority. A tool named `create_file` without a valid create execution profile is refused with `resource_create_profile_required`. It cannot be bound as a ReadDocument tool.
- **Custom Tool Names:** Any non-reserved tool name (e.g. `save_artifact`, `publish_blob`, `fetch_document`, `read_note`) may be bound to either read or create operations provided the required profile and action classes align.

---

## 4. Backward Compatibility & Migration

Existing configurations lacking an explicit `binding` object continue to operate under legacy profiles:
- Legacy `create_file`: Expects exact `create_file_schema()` digest and exact top-level keys `{"path": "...", "content": "..."}` with `path_selector = "/path"` and `content_selector = "/content"`.
- Legacy `read_document`: Expects top-level key `{"path": "..."}` with `path_selector = "/path"`.

To migrate an existing custom tool to SOU-67:
1. Add `"binding": { "contract_version": "sw-native/binding/1", ... }` to `resource_policy`.
2. Define `path_selector` (and `content_selector` if creating files) pointing to the path and content fields within the tool's schema.
3. Verify that `action_class` in tool registration matches the operation (`side_effecting` for create, `read_only` for read).
