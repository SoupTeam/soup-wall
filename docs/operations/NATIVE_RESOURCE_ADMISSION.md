# Native resource admission

The opt-in `sw-native/resources/1` contract at `/native/v1` checks permissions and one-shot correlation for an authenticated trusted collector. It does not attest an executor sandbox. The shipped generic stdio relay refuses resource-profiled calls except the reviewed operation executors below. [Constrained Linux file creation](MCP_CREATE_FILE.md) adds an explicitly installed `sw-native/resources/2` create-only profile; it does not enable arbitrary writes or server containment. See [MCP admission](MCP_STDIO_ADMISSION.md).

[Constrained Linux HTTPS GET](MCP_HTTPS_GET.md) adds `sw-native/resources/3`
with a separate, mutually exclusive `network` authority and binding. The earlier
read and create contracts remain compatible. The registry and session
start/end contract remain `sw-native/1`; earlier daemons refuse v3.

## Operator configuration

The registry remains `sw-native/1`. Each tool can optionally carry a closed `resource_policy` object with:

- `profile`: the existing typed ResourceProfile (server ID, tool, schema digest and 1–32 selectors).
- `workspace` and `cwd`: existing absolute directories, with canonical cwd inside workspace.
- `executor_sha256` and `classifier_sha256`: operator-reviewed revision digests.
- `allowed_resources`: 1–256 complete normalized Resource values.
- `execution` for the explicit v2 create profile, or `network` for the explicit
  v3 HTTPS GET profile; both are absent from legacy reads and cannot coexist.

Digests must be 64 lowercase hexadecimal characters. The profile must match the installed tool and schema. This policy is loaded from trusted operator configuration, never from a call or MCP annotations. Existing native policy and declared egress checks still apply after resource checks.

Allowed resources use the [existing extractor's typed shapes](../../crates/agentfw/src/mcp/resources.rs): a URL's canonical text, host and port; a canonical absolute path; a domain; or a mailbox address and domain. Membership is exact. A permitted host does not authorize another URL port/path, and a permitted mail domain does not authorize another mailbox. A domain-only selector expresses domain scope; use URL selectors for URL-level restrictions.

## Request and receipt

Start/end sessions with the existing `sw-native/1` events. A resource call uses `contract_version: "sw-native/resources/1"`, the usual registry hash, session, `event: "call"`, tool, args and schema digest. It also requires a closed `resource_admission` object:

| Field | Meaning |
| --- | --- |
| `server_id` | Operator-reviewed profile's server identity |
| `host_call_id` | Original bounded integer/string JSON-RPC ID |
| `profile_sha256` | Normalized operator profile digest |
| `executor_sha256`, `classifier_sha256` | Operator-reviewed revision digests |
| `snapshot_sha256`, `definition_sha256`, `input_sha256` | Admitted discovery/classification correlation digests |
| `resources` | Nonempty typed evidence array (pointer, source and resource), maximum 256 |

The daemon checks the pinned server/profile/executor/classifier identities, repeats extraction from the **actual args** using operator selectors, and requires complete derived evidence to equal supplied evidence. Every resource must be explicitly allowed. Missing policy, ambiguous extraction, forged evidence, untyped arrays and stale pinned revisions fail closed. A Deny gets no call ID or invocation grant. Metadata obeys both protocol and configured record byte limits.

The trusted collector remains responsible for validating discovery and classification before submission. Snapshot/definition/input hashes are bound correlation fields, not independent discovery or model attestations from this daemon. Changing any of them, the original host ID, resources, args or revisions changes the opaque invocation binding.

For hashing, deserialize profiles/evidence into typed Rust shapes, serialize them including selector defaults, recursively sort JSON object keys, serialize compact JSON and SHA-256 the UTF-8 bytes. Arrays retain order. `resources_sha256` covers the normalized evidence array. The collector must require exact equality, not just valid digest syntax. Missing/mismatched hashes and unsolicited hashes on legacy receipts fail closed.

Result/context events retain the call's contract version and ordinary grant fields. A `delivery: "mcp_host"` result must retain the bound original JSON-RPC ID. A wrong stage/version/ID spends the grant and refuses release. Legacy binding bytes remain unchanged without resource admission. An installed resource policy cannot be bypassed with a legacy call.

## Operation-level constrained executor (SOU-15)

The confined file-read executor is supported on Unix. Non-Unix platforms refuse resource-policy calls with `resource_executor_unsupported` before reserving native capacity; their zero-execution refusal is tested. Resource-aware execution enforces operation-level isolation within this declared scope. An unconfined server process cannot be trusted to self-enforce resource policies or confine file/network access. Therefore:

- For supported workspace file read operations (`read_document`), the proxy itself serves as the constrained operation executor:
  1. Validates the target canonical path strictly against the canonical workspace boundary (`AGENTFW_WORKSPACE` / `policy.workspace`). Unsupported tools, unreviewed action classes, invalid destinations, or invalid workspaces fail closed early before reserving native call capacity (`resource_executor_unsupported`, `resource_destination_invalid`, `resource_workspace_invalid`).
  2. Derives native resource evidence with `fixed_destinations: true` and requests admission under `sw-native/resources/1`.
  3. Pins the workspace directory descriptor before native admission and compares it with the initially observed root identity. Reads through `agentfw::sandbox::PinnedWorkspace` using component-by-component `openat` traversal with `O_NOFOLLOW` and `O_DIRECTORY`. A later root rename retains the originally pinned directory; intermediate and leaf symlinks are refused. Content is read from the opened file handle.
  4. Content reads are strictly bounded by `MAX_CONTENT` (256 KiB) and validated for valid UTF-8.
  5. Any post-admission failure (missing target, symlink refusal, invalid UTF-8, content size exceeded) immediately settles its call reservation via `collector.event("result", result_kind: "error")`, ensuring zero native session capacity leakage.
  6. On successful read, delivers the verified result through native result admission with bound host ID and release confirmation.
  7. Directly returns the result to the host, ensuring the unconfined server child process is **never invoked** for the operation.
- The separately configured [Linux `create_file` executor](MCP_CREATE_FILE.md) supports one new direct workspace child under `sw-native/resources/2`. Its explicit operation/action/content/workspace authority cannot be downgraded to the read contract.
- The separately configured [Linux `https_get` executor](MCP_HTTPS_GET.md) supports one exact HTTPS URL and reviewed socket address under `sw-native/resources/3`, with verified TLS and bounded reads. It requires actual native Allow and inspects the original response text before release.
- All other unsupported resource-policy operations remain refused with `resource_executor_unsupported`, preventing unconfined server execution.

## Verification and remaining work

```sh
cargo test --locked -p agentfw --test native_endpoint
cargo test --locked -p agentfw --test mcp_admission
cargo test --locked -p agentfw resource_receipt_tests
python3 scripts/verify-sou17.py --allow-dirty --offline
```

These exercise the real native router and stdio boundary, positive legacy execution, operation-level constrained file reads, and fail-closed unsupported/unauthorized boundaries. Arbitrary-server containment is not claimed; confinement is strictly guaranteed by the verified operation executor.

