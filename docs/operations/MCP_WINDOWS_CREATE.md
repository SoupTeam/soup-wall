# Constrained Windows MCP file creation

The explicitly installed `sw-native/create-file/windows-handles/1` executor
creates one new regular UTF-8 file directly inside its authorized Windows
workspace. It uses the additive `sw-native/resources/5` admission contract;
registry/session start/end remain `sw-native/1`. The broker performs the write.
Discovery MCP processes receive no `tools/call` and do not execute this operation.

Existing Unix reads, Linux create and HTTPS GET, and
[Windows handle-bound reads](MCP_WINDOWS_READ.md) retain their existing profiles.
Older daemons and unknown profiles refuse this authority. This profile does not
grant overwrite, arbitrary deletion or rename, recursive directory creation,
network access, shell execution or process sandboxing.

## Exact operator authority

Declare `create_file` with the existing closed schema returned by
`agentfw::native::resource::create_file_schema()`: required string `path`
(1–4,096 characters) and required string `content` (at most 4,096 characters),
with no additional properties. The executor additionally bounds the complete
UTF-8 encoding to **4,096 bytes**. Empty content is valid.

The trusted tool declaration has `action_class: side_effecting`,
`result_provenance: untrusted`, and empty `egress`. Its resource policy requires:

- One required `/path` selector of kind `path`, with `allow_missing_leaf: true`,
  without aliases or defaults.
- One exact allowed Windows canonical destination directly below the workspace.
  Granting a workspace directory does not authorize every child.
- Identical `workspace` and `cwd`; set `AGENTFW_WORKSPACE` to that same workspace.
- `executor_sha256` equal to SHA-256 of the UTF-8 executor profile string, and
  `classifier_sha256` equal to the selected classifier's source digest.
- This exact execution declaration, with `network` and `windows_read` absent:

```json
{
  "execution": {
    "operation": "create_file",
    "action": "write",
    "max_content_bytes": 4096,
    "executor_profile": "sw-native/create-file/windows-handles/1"
  }
}
```

The original arguments and exact content digest, operator policy, workspace
volume/file identity, schema/classifier revisions, host call ID, session and
single-use native receipt are bound together. The daemon independently derives
the parent identity and resource evidence. A tool description or a caller's
claimed digest does not grant authority.

## Windows filesystem boundary

Only local NTFS and a local drive workspace are supported. The accepted Windows
read traversal opens the validated local NT volume directly, opens each
component relative to its retained parent, refuses reparse processing, checks
exact handle-resolved spelling, and retains write/delete-excluding parent pins
through publication. Preparation inspects metadata and a missing leaf; it
creates no workspace object and opens no write-capable staging object.

Only an exact root child is accepted. Traversal, nested destinations, missing
parents, alternate streams, device/UNC/drive-relative/root-relative paths,
reserved names, trailing dot/space, ambiguous case and short-name spellings,
junctions, symlinks/reparse points and existing destinations fail closed. An
existing regular file or hard link is refused even when its bytes match.
The user needs ordinary workspace traverse and file-creation permissions.
A useful read declared alongside this create still has the read profile's
separate traverse/execute permission requirements.

After the correlated native Allow is delivered, the executor creates an
exclusive unpredictable temporary file relative to the same pinned parent,
using `FILE_DELETE_ON_CLOSE`. Its protected empty DACL is verified against the
actual kernel object and creator identity before any content write. Windows may
still permit metadata-only opens; the native tests separately exercise data
access and foreign-link refusal. It writes complete bounded content, flushes
file data, and rechecks the original file identity, single-link state and exact
length before installing a protected owner/SYSTEM DACL. No content write follows
that ACL change. The final file remains private to its owner and SYSTEM, rather
than inheriting broader workspace access. A deliberate file-owner permission
rewrite is outside the process-sandbox boundary of this executor.
Publication uses handle-relative
[`FileLinkInformation`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_link_information)
with `ReplaceIfExists = FALSE` and one same-parent leaf. Another creator winning
the destination race is preserved with its original identity and bytes.
The complete file becomes visible atomically. Closing the staging handle removes
only its original temporary link; cleanup never unlinks a guessed pathname.

## Effects, cancellation and durability

Success reports `success`, `created`, `committed`, the original `path`, exact
`bytes_written` and `content_sha256`, and `file_synced: true`. Windows reports
`directory_synced: false`: the implementation does not claim Linux directory
fsync or power-loss namespace durability. File flushing and namespace durability
are distinct; see
[`FlushFileBuffers`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).

Ordinary execution failures retain `committed`, `staged_bytes` and
`committed_bytes`. A failure before publication may have created and written its
own temporary object; no destination is published by this operation, and a
competing creator's file remains intact. A failure after publication reports
`committed: true` and preserves the complete published file. If closing the exact
owned staging handle does not establish that its temporary name is absent,
publication returns an explicit cleanup-unverified error with the committed
byte count. A retained metadata handle or a foreign recreation can make cleanup
unverified; the executor never falls back to deleting that pathname.
Withholding an untrusted result cannot undo a committed effect.

Cancellation before Allow performs no creation. During staging, dropping or
canceling the worker cannot publish: only the returned staged owner has the
separate publication capability. Process interruption closes the private
staging handle and removes its temporary link; any already published final link
survives. The collector records publication intent before its syscall and a
completion afterwards. A missing completion/reply means the publication result
is indeterminate until independent filesystem evidence resolves it. It must
never be presented as proof of rollback or zero writes.

The local NTFS scope excludes remote files and pipes. Neither this profile nor
its acceptance harness promises a hard deadline against an unresponsive kernel,
storage device or filesystem filter driver.

## Native acceptance and evidence

Build an exact clean candidate on Windows and run the owned driver from an
ordinary standard account:

```powershell
cargo build --locked -p agentfw --bin agentfw
$messages = cargo test --locked -p agentfw --lib --no-run --message-format=json
if ($LASTEXITCODE -ne 0) { throw 'Native test build failed' }
$tests = @($messages | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object {
  $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'agentfw' -and
  $_.profile.test -and $_.executable
})
if ($tests.Count -ne 1) { throw 'Unique native test binary required' }
python -B scripts/verify-sou60-windows-create.py --run --repo . `
  --agentfw target/debug/agentfw.exe --expected-commit (git rev-parse HEAD) `
  --native-test-binary $tests[0].executable `
  --output target/sou60-windows-create.json
```

The dedicated workflow builds that source, provisions an ephemeral genuine
standard-user account, and verifies both administrator privilege and
administrator-group membership are absent. Its kill-on-close process job bounds
owned descendants. The launcher removes only that account, profile and private
staging tree. It retains exact source/binary/helper digests, original stdio
frames, native receipts/audits, independent discovery-child traffic and OS
process-exit witnesses, and independent filesystem identity/content evidence.

The driver has 35 actual MCP cases. Positive cases hold an authentic native
Allow at the owned relay, verify no prior effects, then forward the same reply.
They cover exact useful creation followed by a useful `/4` read in the same
session; native/classifier Deny and Ask; path/type/existing-target refusals;
argument/content/session substitutions; competing creation; daemon loss,
cancellation and replay; and committed creation whose result is withheld.
Transport-fatal cases use a fresh session for their useful recovery read.

A native [`ReadDirectoryChangesW`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw)
observer is queued and calibrated with owned create/delete events before Agent
processes start. Raw notification bytes, delivery barriers and epoch ranges are
checked independently, alongside snapshots, so a transient staging name cannot
hide behind an unchanged final tree. Overflow or incomplete observation refuses
a passing grade. These witnesses establish observed effects in the owned
fixtures; they do not establish zero attempted calls or zero metadata access.

Fourteen separately mandatory native executor tests exercise the actual Windows
APIs: parent/ancestor exclusion, root identity, exact content/bounds, competing
and concurrent creators, real partial writes, flush/publication failures,
post-publication accounting, cancellation cleanup and real killed processes
before/after publication, metadata-only and true zero-access source handles,
and unverified cleanup after an actual committed link. Test-only fault points
exercise executor accounting;
synthetic discovery-child failures are not native write-fault evidence.

Portable negative grader controls are not Windows proof. WSL, Linux or mocked
Windows API passes cannot establish this profile's support. Check exact source,
all mandatory native tests, every case, zero failed/skipped cases and cleanup
before claiming acceptance. The same workflow separately runs the existing real
owned Linux read/create and offline HTTPS regressions without external provider
traffic. CI Summary exposes bounded curated diagnostics; complete original owned
reports remain in its evidence artifacts with normal retention.
