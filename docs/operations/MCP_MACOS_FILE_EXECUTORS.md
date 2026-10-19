# Constrained macOS ARM64 MCP file executors (SOU-94)

Soup Wall supports constrained, operator-owned native document reads and file creations on macOS ARM64 systems running local APFS filesystems.

Brokered calls execute directly within native Rust without child tool-call dispatch. The child discovery process starts only to provide its schema manifest during discovery (`tools/list`), receiving zero child execution for admitted operations.

---

## 1. Demonstrated Platform & Filesystem Scope

### Supported Platform Boundary
- **Operating System:** macOS (Darwin).
- **Architecture:** ARM64 (`aarch64`) only. Intel macOS (`x86_64`) is strictly unsupported and refused.
- **Filesystem:** Verified local APFS volumes only (`statfs` confirms `f_fstypename == "apfs"` and `f_flags & MNT_LOCAL`).
- **Path Confinement:** Direct children within an authorized local workspace directory.

### Explicitly Refused & Out of Scope
- Intel macOS (`x86_64`) architectures.
- Non-APFS filesystems (HFS+, FAT32, exFAT, SMB, NFS, remote or network mounts).
- Interactive operator Ask approval: the interactive Ask approval predicate (`native.approval`) remains strictly Linux-only. On macOS, any policy evaluating to `action: ask` fails closed.
- Real filesystem arbitrary-path confinement (SOU-83).
- Launchd lifecycle management (SOU-93).
- Overwrite of preexisting files: file creation is strictly atomic and non-overwriting.

---

## 2. macOS Document Read Executor (`sw-native/read-document/macos-descriptors/1`)

The `sw-native/read-document/macos-descriptors/1` executor implements constrained, race-free reading of regular files under admission contract `sw-native/resources/7`.

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
- **Created Permissions:** Strict mode `0600` (`-rw-------`).

### Staging, Atomicity, and Collision Semantics
1. **Anonymous Staging:** Staging takes place outside the workspace directory in an isolated temporary staging directory on the same APFS volume.
2. **Immediate Unlink Transition:** The stage file is opened with `O_CREAT | O_EXCL | O_RDWR` (mode `0600`) and unlinked immediately after creation (`libc::unlink`), resulting in an anonymous file descriptor (`st_nlink == 0`).
3. **Zero Disk Residue on Drop or Failure:** Any error, write failure, cancellation, or crash occurring during payload write or flush leaves zero named temporary files on disk.
4. **ACL Inspection:** Verifies via `fpathconf(fd, _PC_EXTENDED_SECURITY_NP)` and `acl_get_fd_np` that the staging file and directory carry no inherited or extended Access Control Lists.
5. **Atomic Publication via `fclonefileat`:**
   - The verified anonymous stage descriptor is cloned into the target workspace using `fclonefileat(stage_fd, root_dirfd, leaf_name, CLONE_NOFOLLOW_ANY | CLONE_RESOLVE_BENEATH)`.
   - `fclonefileat` performs an atomic catalog publication. If the destination leaf already exists or is created concurrently, `fclonefileat` fails with `EEXIST` (`destination_already_exists`). Preexisting files are never overwritten or modified.
6. **Full Durability Sync:** Synchronizes both file and parent directory using `fcntl(F_FULLFSYNC)` and `fsync`.

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

The complete 35-control acceptance suite can be run with:

```bash
python3 scripts/macos-file-acceptance.py --run --agentfw target/debug/agentfw
```

The test runner establishes an isolated mode-`0700` environment, verifies local APFS filesystem properties, starts the daemon and authentic collector proxy with the production classifier (`rule_baseline/rule_baseline.py`), and exercises all positive paths, negative controls, boundary conditions, and drift invariants with zero child MCP execution.
