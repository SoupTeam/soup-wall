# Constrained macOS ARM64 MCP file executors (SOU-94)

Soup Wall supports constrained, operator-owned native document reads and file creations on macOS ARM64 systems running local APFS filesystems.

Brokered calls execute directly within native Rust without child tool-call dispatch. The child discovery process starts only to provide its schema manifest during discovery (`tools/list`), receiving zero child execution for admitted operations.

---

## 1. Demonstrated Platform & Filesystem Scope

### Supported Platform Boundary
- **Operating System:** macOS (Darwin).
- **Architecture:** ARM64 (`aarch64`) only. Intel macOS (`x86_64`) is strictly unsupported and refused.
- **Filesystem:** Verified local APFS volumes only (`statfs` confirms `f_fstypename == "apfs"` and `f_flags & MNT_LOCAL`).
- **Path Confinement:** Reads pin every traversed ancestor inside the approved workspace; creates permit only an immediate root child.

### Explicitly Refused & Out of Scope
- Intel macOS (`x86_64`) architectures.
- Non-APFS filesystems (HFS+, FAT32, exFAT, SMB, NFS, remote or network mounts).
- Interactive operator Ask approval: the interactive Ask approval predicate (`native.approval`) remains strictly Linux-only. On macOS, any policy evaluating to `action: ask` fails closed.
- Real filesystem arbitrary-path confinement (SOU-83).
- Launchd lifecycle management (SOU-93).
- Overwrite of preexisting files: file creation is strictly atomic and non-overwriting.

---

## 2. macOS Document Read Executor (`sw-native/read-document/macos-descriptors/1`)

The `sw-native/read-document/macos-descriptors/1` executor implements descriptor-bound reading of regular files under admission contract `sw-native/resources/7`.

### Contracts & Limits
- **Admission Contract:** `sw-native/resources/7`.
- **Maximum Content Limit:** 40,960 bytes (40 KiB) raw document bound. Conservative limit on local APFS ARM64 to preserve encoded JSON-RPC transport wire budget (accounting for worst-case 6x JSON escaping expansion plus envelope). Files exceeding this limit are refused.
- **Payload Encoding:** Valid UTF-8 required. Binary files or invalid UTF-8 sequences are withheld.

### Security & Invariant Enforcement
1. **Descriptor Pinning:** Opens and pins the workspace root directory descriptor with `O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW`.
2. **Local APFS Verification:** Verifies volume local APFS characteristics via `fstatfs` on the open root descriptor.
3. **Descriptor-Relative Open:** Opens the target leaf relative to the pinned workspace descriptor using `openat` with flags `O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW_ANY | O_RESOLVE_BENEATH`.
4. **Physical Path Verification:** Resolves kernel canonical paths via `fcntl(F_GETPATH)` to verify physical containment and detect mount or directory redirection.
5. **File Attribute Validation:**
   - Must be a regular file (`S_ISREG`).
   - Sockets, FIFOs, character/block devices, and symlinks are refused. Nonblocking open ensures FIFOs fail immediately without stalling or blocking worker threads.
   - Hard links are refused (`st_nlink == 1` enforced).
6. **Double-fstat TOCTOU Drift Detection:** Captures device, inode, size, mtime, and ctime at preparation and re-verifies them after bounded reading to ensure the file was not modified or replaced in place.

---

## 3. macOS File Create Executor (`sw-native/create-file/macos-descriptors/1`)

The `sw-native/create-file/macos-descriptors/1` executor implements atomic, non-overwriting creation of direct workspace child files under admission contract `sw-native/resources/8`.

### Contracts & Limits
- **Admission Contract:** `sw-native/resources/8`.
- **Maximum Content Limit:** 4,096 bytes (4 KiB).
- **Target Boundary:** Immediate direct root child of the approved workspace (`allow_missing_leaf: true`). Subdirectories, traversal (`..`), and nested paths are refused.
- **Created Permissions:** Mode bits `0600` (`-rw-------`). Inherited workspace ACLs may extend effective access; reserve the workspace for the intended principal.

### Staging, Atomicity, and Collision Semantics
1. **Anonymous Staging:** Staging takes place outside the workspace directory in an isolated temporary staging directory on the same APFS volume.
2. **Immediate Unlink Transition:** The stage file is opened with `O_CREAT | O_EXCL | O_RDWR` (mode `0600`) and unlinked immediately after creation (`libc::unlink`), resulting in an anonymous file descriptor (`st_nlink == 0`).
3. **Zero Disk Residue on Drop or Failure:** After verified unlink, write failures and process interruption leave no named payload. Before unlink, uncertain metadata or a replaced stage name returns `stage_ownership_cleanup_unresolved` and preserves the uncertain empty entry rather than deleting foreign inventory. The private mode-0700, ACL-free staging directory is reserved for the trusted broker.
4. **ACL Inspection:** Checks descriptor ACLs using `acl_get_fd`, validates non-null ACLs with `acl_valid`, and rejects entries. Only `ENOENT` proves an absent ACL; query errors and ambiguous null results refuse execution.
5. **Atomic Publication via `fclonefileat`:**
   - The verified anonymous stage descriptor is cloned into the target workspace using `fclonefileat(stage_fd, root_dirfd, leaf_name, CLONE_NOFOLLOW_ANY | CLONE_RESOLVE_BENEATH)`.
   - `fclonefileat` performs an atomic catalog publication. If the destination leaf already exists or is created concurrently, `fclonefileat` fails with `EEXIST` (`destination_already_exists`). Preexisting files are never overwritten or modified.
6. **Full Durability Sync:** Synchronizes both file and parent directory using `fcntl(F_FULLFSYNC)`. A failure after publication reports `committed: true`; callers must inspect the destination instead of retrying as though no effect occurred.

---

## 4. Operator Tool Binding Configuration (SOU-67)

Operators configure constrained file execution in `registry.json` using either standard tool declarations or SOU-67 operator-owned bindings:

### Standard `create_file` Policy
```json
{
  "name": "create_file",
  "action_class": "side_effecting",
  "result_provenance": "untrusted",
  "egress": [],
  "resource_policy": {
    "profile": {
      "server_id": "sou94",
      "tool_name": "create_file",
      "schema_sha256": "<schema_digest>",
      "selectors": [{"pointer": "/path", "kind": "path", "allow_missing_leaf": true}]
    },
    "workspace": "/private/tmp/workspace",
    "cwd": "/private/tmp/workspace",
    "executor_sha256": "<sha256 of 'sw-native/create-file/macos-descriptors/1'>",
    "classifier_sha256": "<classifier_sha256>",
    "allowed_resources": [{"kind": "path", "canonical": "/private/tmp/workspace/new.txt"}],
    "execution": {
      "operation": "create_file",
      "action": "write",
      "max_content_bytes": 4096,
      "executor_profile": "sw-native/create-file/macos-descriptors/1"
    }
  }
}
```

### SOU-67 Custom Tool Binding Example
```json
{
  "name": "custom_create_file",
  "action_class": "side_effecting",
  "result_provenance": "untrusted",
  "egress": [],
  "resource_policy": {
    "profile": {
      "server_id": "sou94",
      "tool_name": "custom_create_file",
      "schema_sha256": "<custom_schema_digest>",
      "selectors": [{"pointer": "/spec/destination", "kind": "path", "allow_missing_leaf": true}]
    },
    "workspace": "/private/tmp/workspace",
    "cwd": "/private/tmp/workspace",
    "executor_sha256": "<sha256 of 'sw-native/create-file/macos-descriptors/1'>",
    "classifier_sha256": "<classifier_sha256>",
    "allowed_resources": [{"kind": "path", "canonical": "/private/tmp/workspace/created_alias.txt"}],
    "binding": {
      "contract_version": "sw-native/binding/1",
      "operation": "create_file",
      "action": "write",
      "path_selector": "/spec/destination",
      "content_selector": "/spec/payload",
      "executor_profile": "sw-native/create-file/macos-descriptors/1",
      "max_content_bytes": 4096
    }
  }
}
```

---

## 5. Verification & Acceptance

The installed runtime suite contains 41 process controls. It requires native ARM64 macOS, local APFS, the Command Line Tools SDK/clang, Python 3 and the actual built or installed `agentfw` executable:

```bash
python3 -I scripts/macos-file-acceptance.py --run --agentfw /absolute/path/to/agentfw --output /private/tmp/sou94-result.json
```

It uses disposable private home/workspace directories outside the checkout. An independent native probe records actual local APFS/device metadata and the executable architecture. Calibrated observer processes measure reads; successful creates are verified for exact bytes, digest and mode. The discovery-only MCP fixture must receive zero tool calls. Exit 0 means all selected runtime controls passed; 1 means failure; 2 means incomplete or unsupported. Failed iterations are retained. This is runtime qualification, not a claim that every project or CI check ran.

The anonymous-stage publication controls compile an acceptance-only Darwin interposer. It gates the actual collector immediately before the real `fclonefileat`, then forwards unchanged syscall arguments. An unchanged useful create calibrates the gate; a separate process races a foreign destination and must receive real `EEXIST`; terminating the collector before publication preserves foreign stage files and permits useful work from a fresh collector. Normal positive controls run without the interposer. Hardened-runtime rejection is an unsupported instrumented control; do not weaken signing or library validation. The product executor itself does not require the compiler or interposer.

Before-execution cancellation and after-staging process interruption are distinct controls. An absent reply after an attempted publication is not proof that no write happened. A live daemon refusal, exact spent-result replay, and genuine authority expiry are asserted separately from transport failure. Authenticated hook provenance is attributed to its bound MCP server; taint and incomplete-history floors use separate host sessions and a clean useful counterpart.

Managed-policy preservation is qualified separately by the v7/v8 native integration regression `macos_v7_v8_managed_transition_spends_old_receipts_and_recovers`, covering Deny/Ask activation, spent old receipts and rollback to useful work. Shared native policy regressions preserve existing taint/history. These in-process regressions are not counted as installed process controls. Read/create retain the collector policy boundary; macOS Ask continuation remains unsupported.

Executor/profile hashes identify semantic contracts, not executable attestation. Acceptance records the actual executable, classifier, fixture and observer digests; retained build manifests bind Cargo inputs and reviewed sources to the tested binaries. No arbitrary MCP-server OS confinement, Intel support, launchd lifecycle or release-publication claim is made.
