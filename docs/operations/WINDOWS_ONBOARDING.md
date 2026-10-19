# Native Windows Agent onboarding

Use `agentfw onboard-windows` to preview a new owned Agent setup, apply the
confirmed changes, verify the running daemon and run the installed self-test.
The workflow reuses the accepted [Windows connection](WINDOWS_MCP_CONNECTION.md),
[lifecycle](AGENT_LIFECYCLE.md) and [self-test](WINDOWS_SELF_TEST.md) procedures.
It requires explicit local assets and does not download dependencies.

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
  --workspace 'C:\SoupWall\notes' `
  --report 'C:\SoupWall\reports\setup.json' --port 8877
```

Preview writes its JSON result to standard output. It does not create the home,
journal or report, execute the selected server, or send traffic to an occupied
port. It checks the selected files again before returning.

The confirmation digest binds the selected paths, expected asset digests,
observed host file identity, complete host configuration and selected server
entry. Changing a destination or editing the host configuration produces a
different confirmation. The elapsed time is excluded from that digest.

## Apply and verify

Review the proposed changes. Repeat the same selection with `apply` instead of
`preview` and add `--confirm` followed by the returned confirmation digest.
Apply rechecks the selection, records recovery state, creates the new private
home, installs the Agent, verifies the daemon and wraps only the selected MCP
entry. Existing host settings and unrelated servers stay intact.

Then run:

```powershell
& 'C:\SoupWall\agentfw.exe' onboard-windows inspect --state-directory 'C:\SoupWall\state'
& 'C:\SoupWall\agentfw.exe' onboard-windows verify --state-directory 'C:\SoupWall\state'
```

Verification checks the managed process, binary, configuration, registry and
policy identities. The installed Windows self-test runs in a separate Job
Object with a deadline and a fresh evidence report. Its five scenarios use the
bundled synthetic fixture and shipped policy. They do not certify arbitrary
server implementations or the selected operator policy's effectiveness.

The report separates `configured`, `daemon_verified`, `synthetic_protection`
and `host_reload`. Reload the host explicitly before using the changed entry.
Configuration publication alone does not prove that an existing host process
loaded it.

## Recover or remove

```powershell
& 'C:\SoupWall\agentfw.exe' onboard-windows recover --state-directory 'C:\SoupWall\state'
& 'C:\SoupWall\agentfw.exe' onboard-windows remove --state-directory 'C:\SoupWall\state'
```

Recovery reconciles the lifecycle record and owned connection transaction.
When an operator edits an owned configuration file or the selected host entry,
the command refuses to replace the edit. Inspect the preserved files before
deciding which version to keep.

Removal restores the original selected MCP entry and removes the managed
binary and unchanged setup configuration. Audit data, evidence, recovery
records and unrelated operator files are retained. It does not recursively
delete the profile. A completed removal can be repeated.

The private recovery journal can contain local authentication tokens and
configuration snapshots. Do not upload the state directory, connection
archives or raw lifecycle files. Share only the sanitized acceptance and
self-test reports. Verification allows three fresh report attempts; previous
reports are never overwritten.

Preview reports `host_reload: pending_explicit_host_reload` and
`synthetic_protection: not_witnessed`. Only successful verification changes the
synthetic protection result to `witnessed`.

## Native acceptance

Run the acceptance driver from a non-elevated Windows terminal. It stages a
disposable installed copy and Python runtime outside the source checkout.

```powershell
python scripts/test-windows-onboarding.py --agent C:\SoupWall\agentfw.exe `
  --baseline rule_baseline/rule_baseline.py --out C:\SoupWall\evidence\onboarding
```

The output directory must be fresh. A local filtered administrator token does
not substitute for clean standard-account CI acceptance. Check the account
membership recorded in the report before interpreting the result.
