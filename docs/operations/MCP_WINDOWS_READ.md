# Constrained Windows MCP document reads

The explicitly installed `sw-native/read-document/windows-handles/1` profile
serves one reviewed `read_document` path through the native broker. It uses
`sw-native/resources/4`; the registry and session start/end remain `sw-native/1`.
Existing Unix reads (`resources/1`), Linux create (`resources/2`) and Linux HTTPS
GET (`resources/3`) retain their platform and execution boundaries. An earlier
daemon refuses v4. No arbitrary MCP server or shell performs the file read.

## Operator authority

Install a `read_document` tool with the exact schema returned by
`agentfw::native::resource::windows_read_schema()`: one required string `path`,
1–4,096 characters, with no additional arguments. Its trusted action is
`read_only`, result provenance is `untrusted`, and egress is empty.

The tool's resource policy has one required `/path` selector of kind `path`,
without aliases, defaults or a missing-leaf exception; one exact allowed
canonical path; and identical workspace/cwd directories. Add:

```json
{
  "windows_read": {
    "executor_profile": "sw-native/read-document/windows-handles/1",
    "max_content_bytes": 262144
  }
}
```

`execution` and `network` must be absent. `executor_sha256` is SHA-256 of the
UTF-8 profile string; `classifier_sha256` must match the selected classifier.
Set `AGENTFW_WORKSPACE` to the same workspace. The full registry remains trusted
operator configuration; tool descriptions and caller arguments grant nothing.

The v4 admission includes a separate `windows_read` binding. Its policy and
original argument digests, workspace identity and target identity join the
existing server, schema, classifier, host-call ID, session and single-use native
grant. The daemon independently derives metadata identity and resource evidence.
A syntactically valid digest cannot authorize another file or workspace.

## Supported filesystem and race boundary

Only a local NTFS regular file below a local drive workspace is supported.
The executor retains opened handles for the drive-to-workspace ancestors,
target ancestors and metadata-only leaf before requesting native Allow. Each
component below the volume is opened relative to its retained parent handle;
the volume itself is opened by its validated local NT device name, without
resolving the drive letter again. Reparse processing is refused. V4 resource
evidence comes from these retained handles instead of generic DOS path checks.
Volume/file identities and exact handle-resolved spelling are
checked. Retained handles deny write/delete sharing throughout the operation.
Content access is opened only after a matching actual Allow and must identify
the pinned leaf.

Traversal, junctions, symlinks and other reparse points, multiple hard links,
alternate streams, UNC/device paths, ambiguous case/short-name spellings,
non-regular objects and unsupported filesystems fail closed. This conservative
profile does not grant Windows create/write, network access or process sandboxing.
Filesystem metadata is inspected before admission; this is not a claim of zero
metadata access. Deny/Ask and transport/identity failures grant no content read
and never forward the call to the MCP child.

Content is limited to 262,144 bytes and complete valid UTF-8. The complete MCP
result must also fit existing native result-envelope limits; escaping and
envelope overhead may cause a near-limit document to be withheld. Results and
ordinary read failures use the same correlated inspection/release boundary.
An ordinary failure settles its reservation so another useful call can proceed.

Cancellation before Allow drops metadata authority without opening a data
handle. Cancellation during an issued read cannot undo bytes already read.
Overlapped reads request cancellation on cancellation/deadline and retain their
buffer and handles until the kernel reports completion. The local NTFS scope
excludes pipes and remote files; no hard deadline is promised for an unresponsive
kernel or filesystem driver.

These mechanics follow the documented
[handle-relative open and sharing rules](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile)
and [asynchronous cancellation lifetime requirements](https://learn.microsoft.com/en-us/windows/win32/fileio/canceling-pending-i-o-operations).

## Native acceptance

Build the exact candidate on Windows and run the owned fixture driver as a
standard user:

```powershell
cargo build --locked -p agentfw --bin agentfw
$messages = cargo test --locked -p agentfw --lib --no-run --message-format=json
if ($LASTEXITCODE -ne 0) { throw 'Native test build failed' }
$tests = @($messages | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object {
  $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'agentfw' -and
  $_.profile.test -and $_.executable
})
if ($tests.Count -ne 1) { throw 'Unique native test binary required' }
python -B scripts/verify-sou58-windows-read.py --run --repo . `
  --agentfw target/debug/agentfw.exe --expected-commit (git rev-parse HEAD) `
  --native-test-binary $tests[0].executable `
  --output target/sou58-windows-read.json
```

The dedicated Windows workflow runs the actual built Agent and executor tests
under a disposable nonadministrator identity. Reports retain source/binary
identities, identity/membership checks, original stdio replies, native receipts,
the server execution ledger, calibrated OS read-exclusion witnesses and
deterministic native replacement-race results. All twelve mandatory executor
tests must pass without ignored tests, including the real held-oplock and
validated NT volume-mapping regressions.
The file-symlink test runs separately with its required Windows privilege.
Cleanup is confined to its owned
account, processes and fixture directories. A mocked Windows API, WSL run or
Linux regression pass is not native Windows acceptance.

Check the report's completeness, failed/skipped cases and exact source identity
before claiming acceptance. Linux regression checks still cover the existing
read, create and HTTPS executors. No external provider traffic is required.
