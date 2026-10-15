# Claude Code MCP connection

The connection commands manage one explicitly selected server in a Claude Code
JSON file. The supported transaction platform is Linux, including a Linux
profile inside WSL2. Native Windows, macOS, project aliases, remote transports
and nonempty server environments are refused.

## Operator flow

Use absolute paths to an existing Agent executable, its reviewed `.agentfw`
directory and a JSON file containing an `mcpServers` object. The Agent must be
running in enforcing mode with its pinned native registry. The selected server
must name an absolute executable and an array of string arguments.

The config must be a regular, single-link file owned by the operator, with mode
`0600`. Its directory must be owned by the operator and not writable by other
users. Paths containing symlinks or `..` are refused. Executables must not be
writable by other users. These checks never change existing permissions.

```sh
agentfw mcp-connection preview --path /private/mcp.json --server notes \
  --agent /private/bin/agentfw --home /private/profile/.agentfw
agentfw mcp-connection connect --path /private/mcp.json --server notes \
  --agent /private/bin/agentfw --home /private/profile/.agentfw
agentfw mcp-connection inspect --path /private/mcp.json --server notes \
  --agent /private/bin/agentfw --home /private/profile/.agentfw
```

Preview validates the selected entry and describes the bounded change without
writing files, starting servers or contacting a provider. Output contains
identities and digests, never original command arguments or environment values.
Connect queries the existing authenticated
[Agent status endpoint](AGENT_LIFECYCLE.md), matching the selected
binary, loaded native configuration and registry. It then installs the existing
`agentfw mcp --native-admission` collector with a stable per-file/server ID.

The wrapper uses `/usr/bin/env -i` with only a fixed system PATH and the explicit
Agent profile. The original command and argument values retain their order.
A nonempty selected `env` is outside this profile: move credentials to an
operator-reviewed mechanism before connecting. Unrelated server entries and
settings retain their JSON values. Formatting and object key order may change.

## Controlled verification

Inspect is read-only unless an operator explicitly supplies a probe. A probe
starts the configured path, discovers tools and sends the chosen call:

```sh
agentfw mcp-connection inspect --path /private/mcp.json --server notes \
  --agent /private/bin/agentfw --home /private/profile/.agentfw \
  --probe-tool read_document --probe-args '{"name":"inventory"}'
```

Choose a harmless read in an owned fixture. A probe is a real tool invocation.
Only the digest of its admitted result is printed.

| Status | Meaning |
| --- | --- |
| `preview` | Valid selected input; no change has been made |
| `configured` | Owned entry and current Agent identities match |
| `verified_for_this_probe` | The explicit controlled call returned an admitted result |
| `unavailable` | Preflight or the controlled request failed |
| `unknown` | Ownership, pending transaction or configuration identity is not verified |
| `disconnected` | No owned wrapper remains to restore |

Unknown and unavailable return nonzero. A successful status query alone never
proves execution protection. Verification describes that invocation only;
future calls still pass through native admission.

## Disconnect and recovery

```sh
agentfw mcp-connection disconnect --path /private/mcp.json --server notes \
  --agent /private/bin/agentfw --home /private/profile/.agentfw
```

Disconnect works while the daemon is stopped. It restores only the selected
entry recorded by this connection and preserves later unrelated edits. A
changed selected entry causes a conflict with no overwrite. Repeated connect
does not double-wrap; repeated disconnect is harmless.

Each config directory retains a private `.soup-wall-mcp.lock` file. The kernel
releases its advisory lock after process exit, including a crash. Do not delete
the lock while an operation is running.

A private `.soup-wall-<digest>.json` file stores ownership, exact original and
wrapped entries, native identities and transaction phase. It is written and
synced before the config changes. Both files use same-directory atomic rename
and directory sync. Original arguments may be sensitive; keep this record
private. A pending transaction is never reported as configured.

After interruption, repeat connect with the same pinned inputs to finish a
pending connection, or disconnect to restore the original entry. A changed
binary, registry, native config or selected entry causes refusal. Resolve that
change explicitly; do not copy an old whole-file backup over the current file.
Failed writes retain recovery metadata when necessary.

The lock coordinates these commands. The writer also rechecks the config inode,
bytes and directory identity before replacement to detect outside edits.
Editors that ignore advisory locks must not write the selected file during
the final replacement; ordinary filesystem rename has no compare-and-swap
operation for arbitrary non-cooperating writers.

## Reproduce acceptance

Build the current source, then provide an already installed Claude Code
executable. The runner does not install or update that client:

```sh
cargo build --locked -p agentfw
python3 scripts/test-mcp-connection.py --agentfw target/debug/agentfw \
  --claude /absolute/path/to/claude --out target/connection-evidence/new-run
```

Docker must provide Linux containers. The image is pinned by digest. The test
uses private disposable Agent and Claude profiles, an existing deterministic
local Messages API and the existing MCP fixture. No paid model is contacted.
The installed client reaches the unchanged generated Linux entry through an
explicit Docker stdio bridge; the report records the client and binary identity.
This bridge run does not establish native macOS or Windows transaction support.

The receiver and original server ledger independently prove the useful read,
the absence of a forbidden send and the refusal after daemon loss. The final
ledger is reconciled after both client sessions. The runner also checks
preview, repeated operations, conflict preservation, pending recovery,
malformed inputs, original arguments, unrelated entries and offline disconnect.

Reports retain timings, per-operation identities, client outcomes, source
hashes and cleanup. Native tokens remain in the temporary Linux profile.
The existing [legacy HTTP hook fails open](MCP_STDIO_ADMISSION.md); connecting
one selected MCP server neither changes that behavior nor protects every host
tool. The server still runs as the operator: this is no arbitrary-server OS
confinement claim.
