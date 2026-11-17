# Codex CLI MCP connection (Linux)

`agentfw mcp-connection <operation> --host codex` manages one existing stdio entry in
Codex `config.toml`. Use `--host codex` **after** `preview`, `connect`,
`inspect`, or `disconnect`, as shown below. Omitting the host retains the
existing Claude JSON behavior. This increment covers the selected stdio MCP
connection, not all tools of a Codex session.

## Connect and inspect

Use an enforcing daemon, its reviewed native registry and a private installed
Agent binary. The [shared connection requirements](CLAUDE_MCP_CONNECTION.md)
apply: absolute paths, an owned single-link `0600` configuration, no symlink
components, private ownership/recovery records, and an explicit `.agentfw` home.
The selected TOML entry must contain `command`, optional string-array `args`,
and optionally an empty `env`. Remote transports, credential environments,
unknown selected fields and relative executables are refused. Other entries
may contain arbitrary host settings; they are not enrolled by this command.

```toml
[mcp_servers.notes]
command = "/private/runtime/python3"
args = ["-I", "/private/server.py"]
```

```sh
agentfw mcp-connection preview --host codex --path /private/codex/config.toml \
  --server notes --agent /private/bin/agentfw --home /private/profile/.agentfw
agentfw mcp-connection connect --host codex --path /private/codex/config.toml \
  --server notes --agent /private/bin/agentfw --home /private/profile/.agentfw
agentfw mcp-connection inspect --host codex --path /private/codex/config.toml \
  --server notes --agent /private/bin/agentfw --home /private/profile/.agentfw
```

Restart the Codex process to load the new command. Connection does not alter
Codex permissions. A host refusal can precede Soup Wall admission. The owned
acceptance explicitly approves only its fixture MCP tools with the Codex
invocation override `-c 'mcp_servers.demo.default_tools_approval_mode="approve"'`.
This does not approve Soup Wall Ask decisions.

The wrapper clears inherited environment, retains the original argument values,
and invokes the existing guarded collector with a `codex-` connection ID.
TOML editing retains unrelated tables, comments and secrets without printing
them. Selected command/argument formatting may change. Ownership hashes bind
the host kind and exact original/wrapped values. Legacy Claude ownership files
retain their existing meaning.

`configured` confirms the configuration and daemon identities, not a host
execution. To issue a real controlled probe, append
`--probe-tool read_document --probe-args '{"name":"inventory"}'` to `inspect`
using a tool and arguments in your reviewed registry. Only a permitted result
produces `verified_for_this_probe` and its digest. Reports separately expose
`host` and `enforcement_coverage=selected_stdio_mcp_only`.

## Disconnect and recovery

```sh
agentfw mcp-connection disconnect --host codex --path /private/codex/config.toml \
  --server notes --agent /private/bin/agentfw --home /private/profile/.agentfw
```

Disconnect restores original selected values while preserving unrelated later
edits. Repeated connect/disconnect is safe. A changed selected entry is a
conflict, not permission to overwrite it. The same retained-version exchange,
private publication journal, crash recovery and concurrent-writer checks used
by the [Claude lifecycle](CLAUDE_MCP_CONNECTION.md#disconnect-and-recovery)
apply to TOML. Archive files named `snapshot.json`, `proposed.json` and
`exchanged.json` contain original format bytes, which are TOML for this host.
Retain them during operator reconciliation; they may contain secrets.

## Tested wire and coverage

The live acceptance pins **Codex CLI 0.169.0-alpha.11.1**. Its sanitized
[captured call](../../scripts/fixtures/codex-0.169.0-call.json) adds bounded
turn/session/window/item correlation and optional Git workspace metadata.
The parser accepts only the observed keys, types and version. Malformed,
partial, oversized or unknown metadata closes transport before forwarding.
The earlier 0.148.0 `threadId`/`progressToken` form remains covered by regression.

All metadata is untrusted correlation. Original frame bytes remain in the
collector's bindings and are forwarded only after native admission. Claimed
sandbox, approval flags, paths, remotes and session IDs confer no authority.
Native identity still comes from the authenticated collector/daemon protocol.

| Surface | This increment |
| --- | --- |
| Selected stdio MCP | Native call/result admission; permitted read and loopback delivery; Deny and unconfirmed Ask with no effect; rejected result withheld |
| Configuration | Preview, repeat connect, inspect/probe, disconnect, unrelated edits, selected conflicts; publication race/crash tests for both formats |
| Daemon outage | Fail closed at the selected MCP boundary; host sees transport failure |
| Built-in shell / `write_stdin` | Outside this MCP connection; acceptance deliberately demonstrates an interactive file write |
| Built-in file tools, subagents, hosted tools | Not enrolled; no cross-tool native session or inherited taint claim |
| Native Ask | Existing native grant machinery retained; this acceptance verifies unconfirmed Ask stays blocked, not a Codex approval UI integration |
| Selected filesystem/Git sandbox profiles | Existing explicit profile launch checks retained; Codex original-server qualification not established by the generic fixture |
| Profile transitions | Refused for Codex until an authenticated launcher lifecycle is implemented |
| Windows/macOS Codex lifecycle | Explicitly unsupported in this increment |

There is no Codex hook installation here. Hook errors, timeouts, built-in tool
admission and cross-subagent provenance require a separate host adapter. Do not
interpret the MCP status as whole-session protection or as proof of live-model
effectiveness. Gemini, Cursor Desktop, OpenCode and Copilot are not enabled by
this change.

## Reproduce (USD0)

```sh
cargo build --locked -p agentfw --bins
cargo test --locked -p agentfw --lib mcp::connection
cargo test --locked -p agentfw --test mcp_admission
python3 scripts/codex-mcp-acceptance.py --agentfw target/debug/agentfw \
  --codex "$(command -v codex)" --out target/codex-acceptance/report.json
```

The acceptance uses an isolated home, local scripted Responses provider,
synthetic secret, owned note server, independent execution ledger and loopback
receiver. No paid model or personal Codex credentials are used. It records the
source SHA, source-file and executable hashes, exact host version, checks and
coverage. Its companion `.host.json` contains only fixture transcripts. Keep
failed reports as failures; an unavailable host is not a passed integration.
