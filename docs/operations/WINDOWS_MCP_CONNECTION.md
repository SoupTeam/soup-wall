# Native Windows MCP Connection

The Windows backend extends the existing selected-server connection commands.
Use an explicitly selected native Agent executable, its reviewed `.agentfw`
directory and an existing Claude-style JSON configuration. The command manages
one stdio entry.

## File Contract

Only exact local NTFS drive paths are supported. Files and the containing
directory must belong to the current user and have a protected DACL granting
access only to that user and LocalSystem. File hardlinks, reparse points,
junctions, network filesystems, alternate streams, case aliases, short names and
parent traversal are refused. The reviewed Windows traversal helpers retain
ancestor handles. Validation does not repair existing ACLs.

The original command must be a private, owned native `.exe`. Arguments retain
their values and order, including spaces and Unicode. No shell or WSL process
is used to run the collector. Nonempty selected environments remain unsupported.

## Runtime Selection

For the existing native read/create executors, supply an owned runtime file:

```json
{
  "workspace": "C:\\private\\workspace",
  "classifier_script": "C:\\private\\rule_baseline.py",
  "classifier_python": "C:\\private\\python\\python.exe"
}
```

This file selects existing components. It cannot grant tool authority. The
reviewed registry, enforcing daemon and classifier still decide admission.
The launcher clears inherited application variables and passes only the
selected profile, Windows runtime path and explicit classifier/workspace
settings. Runtime bytes, classifier source and Python executable digests are
pinned in the generated wrapper.

```powershell
agentfw mcp-connection preview --path C:\private\mcp.json --server notes `
  --agent C:\private\agentfw.exe --home C:\private\profile\.agentfw `
  --runtime C:\private\runtime.json
agentfw mcp-connection connect --path C:\private\mcp.json --server notes `
  --agent C:\private\agentfw.exe --home C:\private\profile\.agentfw `
  --runtime C:\private\runtime.json
agentfw mcp-connection inspect --path C:\private\mcp.json --server notes `
  --agent C:\private\agentfw.exe --home C:\private\profile\.agentfw `
  --runtime C:\private\runtime.json --probe-tool read_document `
  --probe-args '{"path":"inventory.txt"}'
agentfw mcp-connection disconnect --path C:\private\mcp.json --server notes `
  --agent C:\private\agentfw.exe --home C:\private\profile\.agentfw `
  --runtime C:\private\runtime.json
```

A successful connection means that the entry and enforcing daemon identities
match. Only an explicit successful probe reports `verified_for_this_probe`.
A missing or changed daemon, binary, registry, runtime or ownership record
causes refusal or an unavailable/unknown result.

## Publication and Recovery

Replacement uses [ReplaceFileW](https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-replacefilew)
with a mandatory backup of the actual displaced file. An owned private archive
retains the original snapshot, proposed bytes, staging file before replacement
and `displaced.json` afterward. A flushed publication journal binds both file
IDs and byte digests. First creation uses flushed staging followed by a native
rename that refuses an existing target.

The same publication rule applies to ownership metadata. The directory lock
serializes cooperating connect/disconnect commands. An ordinary editor does not
acquire that lock, so successful completion also checks the actual displaced
version. Conflicts retain all versions and return nonzero. The live file may
already contain the proposed version; no automatic overwrite restores an older
whole-file snapshot.

Repeat connect or disconnect after a process interruption. Only exact before
or after states may clear a journal. A partial native failure, edited snapshot
or changed file ID requires explicit reconciliation with all writers stopped.
Retain both versions, preserve unrelated settings in the chosen live config
and remove only its matching journal after reconciliation. Inspect and preview
refuse pending publication.

Archives are not automatically pruned. An editor retaining an old descriptor
may continue writing to the displaced inode. Those bytes remain in the archive
after the command returns. Keep archives private and remove them only after all
writers close and reconciliation is complete. File flushing is required;
namespace durability after power loss is not claimed.

## Native Evidence

```powershell
python -B scripts/test-windows-connection.py `
  --agentfw target/debug/agentfw.exe `
  --native-test-binary C:\private\agentfw-tests.exe `
  --claude C:\tools\claude.exe --claude-sha256 <sha256> `
  --out target/windows-connection-evidence
```

Run from a genuine standard-user account. The driver uses disposable profiles,
the production daemon and collector, independent file effects, and an explicitly
supplied pinned Claude Code executable with scripted local provider responses.
It exercises native read/create, outside-workspace refusal, daemon loss,
repeated operations, config conflicts and cleanup.

`--diagnostic` runs the same local controls under a filtered administrator
account and records incomplete acceptance. Missing actual-host evidence is
also incomplete. Cross-compilation and a passing diagnostic run do not replace
the required standard-user evidence. Scripted provider responses establish host
interoperability, not live-model efficacy. The driver neither installs nor
updates the host and does not use a real provider account.

The native Windows acceptance workflow performs both the transactions and the
actual-host procedure under one disposable standard account. CI unpacks the
official Windows x64 Claude Code 2.1.251 package into temporary runner storage;
it checks the pinned archive SHA-512 and executable SHA-256 before use. This is
not a host installation. The package and license remain outside the repository.
The launcher refuses incomplete host evidence, missing controls, account
membership in Administrators, source changes and failed cleanup. A local
diagnostic report does not establish that this workflow passed.
