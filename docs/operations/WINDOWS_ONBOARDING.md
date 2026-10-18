# Native Windows onboarding preview

The current local increment provides a read-only setup preview. Apply,
verification, recovery and removal are not yet available through this command.
Use the accepted [Windows connection procedure](WINDOWS_MCP_CONNECTION.md) and
[self-test procedure](WINDOWS_SELF_TEST.md) for the existing supported workflow.

## Prerequisites

Use a non-elevated native Windows terminal and local NTFS storage. Select an
installed Agent, local Python interpreter, reviewed classifier source, native
registry and policy. Supply the expected SHA-256 for each selected asset.
These digests must come from the versions that were reviewed for the setup.

The selected files and their immediate directories must have protected ACLs
that allow only the current user and SYSTEM. The command refuses unsafe owners,
broad permissions, hard links, junctions and path aliases. It does not tighten
the ACL of an existing directory.

Select an existing private host configuration and server entry. Use a fresh
`.agentfw` destination beneath a private owned parent. The state directory
must already exist and be private. Select a fresh report path outside the new
Agent home and an unused numeric-loopback port.

## Preview

The following example uses explicitly staged local assets. Replace the five
digest placeholders with the reviewed values before running it.

```powershell
& 'C:\SoupWall\agentfw.exe' onboard-windows preview `
  --agent 'C:\SoupWall\agentfw.exe' --agent-sha256 '<agent-sha256>' `
  --python 'C:\SoupWall\python\python.exe' --python-sha256 '<python-sha256>' `
  --classifier 'C:\SoupWall\rule_baseline.py' --classifier-sha256 '<classifier-sha256>' `
  --registry 'C:\SoupWall\registry.json' --registry-sha256 '<registry-sha256>' `
  --policy 'C:\SoupWall\policy.yaml' --policy-sha256 '<policy-sha256>' `
  --host-config 'C:\SoupWall\host\settings.json' --server 'notes' `
  --home 'C:\SoupWall\profile\.agentfw' `
  --state-directory 'C:\SoupWall\state' `
  --report 'C:\SoupWall\reports\setup.json' --port 8877
```

Preview writes its JSON result to standard output. It does not create the home,
journal or report, execute the selected server, or send traffic to an occupied
port. It checks the selected files again before returning.

The confirmation digest binds the selected paths, expected asset digests,
observed host file identity, complete host configuration and selected server
entry. Changing a destination or editing the host configuration produces a
different confirmation. The elapsed time is excluded from that digest.

`host_reload` remains `pending_explicit_host_reload`, and
`synthetic_protection` remains `not_witnessed`. A successful preview establishes
neither daemon health nor protection. Those require separate execution evidence.
