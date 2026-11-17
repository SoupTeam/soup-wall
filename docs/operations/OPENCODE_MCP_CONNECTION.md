# OpenCode MCP and scoped plugin (Linux, 1.19.6)

This increment is pinned to the published **opencode-ai 1.19.6** binary. Its
tested contract uses `mcp.<server>`, a command array, and
`tool.execute.before` / `tool.execute.after`. The current website also describes
V2 configuration and plugin APIs; those are not the contract qualified here.
See the [tagged plugin types](https://github.com/anomalyco/opencode/blob/v1.19.6/packages/plugin/src/index.ts)
and [actual MCP callback path](https://github.com/anomalyco/opencode/blob/v1.19.6/packages/opencode/src/session/tools.ts).

## Selected connection

The [shared private connection requirements](CLAUDE_MCP_CONNECTION.md) apply.
An existing owner-private JSONC file can contain:

```jsonc
{
  "mcp": {
    "notes": {"type": "local", "command": ["/private/python3", "/private/server.py"],},
  },
}
```

```sh
agentfw mcp-connection preview --host opencode --path /private/opencode.jsonc \
  --server notes --agent /private/agentfw --home /private/profile/.agentfw
agentfw mcp-connection connect --host opencode --path /private/opencode.jsonc \
  --server notes --agent /private/agentfw --home /private/profile/.agentfw
agentfw mcp-connection inspect --host opencode --path /private/opencode.jsonc \
  --server notes --agent /private/agentfw --home /private/profile/.agentfw
```

Only `type: local`, a nonempty command array with an absolute executable, and
an optional empty `environment` are supported in the selected entry. Remote
transport, environment credentials, `cwd`, enable/disable flags, timeouts and
other selected options are refused. Unrelated settings remain byte-for-byte
unchanged. JSONC comments/trailing commas are retained outside the selected
entry; duplicate keys are refused. Private publication, conflict and crash
recovery use the existing connection journal with canonical launch records.

Restart the host to load the wrapper. `configured` is not a successful probe.
Append `--probe-tool read_document --probe-args '{"name":"inventory"}'` to
`inspect` for a reviewed real probe. `disconnect` with the same connection
arguments restores the original entry. Use a private home and `umask 077`.
Original filesystem profiles use the same `--server-profile`, classifier and
runtime pins as the [Codex procedure](CODEX_MCP_CONNECTION.md#reproduce-usd0).

The [captured call](../../scripts/fixtures/opencode-1.19.6-call.json) carries a
safe nonnegative integer `progressToken`, treated only as correlation. The
real host also sends a late cancellation after a completed call. The generic
collector accepts one notification matching its latest finished call, without
forwarding or granting anything. The transport must be idle to consume this
no-op; unknown, repeated and stale IDs are refused. Existing in-flight cancellation semantics
remain unchanged: closing/withholding does not promise to undo an already
dispatched effect. The original-server relay retains its own cancellation path.

## Optional signed plugin binding

Configure the repository's [plugin](../../scripts/soup-wall-opencode.mjs) as an
absolute `file://` path in the pinned host's `plugin` array. A trusted launcher
supplies these absolute paths:

```sh
export SOUP_WALL_AGENTFW=/private/agentfw
export SOUP_WALL_HOME=/private/profile/.agentfw
export SOUP_WALL_BINDING=/private/run/opencode-binding.json
```

The owner-private binding has this shape:

```json
{
  "contract_version": "sw-opencode-plugin-binding/1",
  "host_session": "operator-issued-run-id",
  "host_server": "notes",
  "native_server": "opencode-connection-id-from-inspect",
  "child_authority": "signed-scoped-proof-from-the-trusted-issuer"
}
```

The native collector must use the same `AGENTFW_HOST_SESSION` and
`AGENTFW_CHILD_AUTHORITY`. The [scoped authority protocol](MCP_STDIO_ADMISSION.md)
binds the current daemon instance, server, agent, tools and resources. This
increment does not install a persistent trusted launcher or mint authority
from host callbacks. The disposable `--hooks` acceptance provisions the
complete signed sequence explicitly.

The plugin calls `agentfw opencode-hook`, which reads private files and uses the
authenticated `/hook/decision/v1` endpoint. Host `sessionID`, `callID`, directory
and tool labels are untrusted correlation. The daemon supplies native identity,
parent and result provenance from the active collector. Arguments and the
entire original result are preserved. The actual MCP `after` result contains
`content`, unlike the SDK type's built-in-tool `title/output` declaration.
OpenCode does not invoke `after` when MCP execution throws an error; native
admission already withholds rejected MCP results.

Defer leaves host permissions unchanged. Deny and Ask throw an explicit plugin
error, withholding the call or result; Ask is not an approval or native grant.
Bridge exit failure, malformed output, missing binary and the 2500 ms bridge
timeout block while the plugin is loaded. Plugin load/removal failures are
outside that guarantee: the pinned host ignored a missing plugin and the
owned positive-control calls executed. Native MCP remains the execution/result boundary.
Unsupported built-ins are refused while the plugin executes, but this is not
native enrollment of built-ins, subagents, hosted tools or background shell.
No interactive approval UI or combined single-use grant flow is qualified.

## Reproduce (owned fixtures, USD0)

Install the exact official `opencode-ai@1.19.6` package in an isolated prefix;
use its platform binary as `OPENCODE`. Keep user credentials out of its home.

```sh
cargo build --locked -p agentfw
cargo fmt --all -- --check
cargo test --locked -p agentfw --lib
cargo test --locked -p agentfw --test mcp_admission --test hook_endpoint
python3 scripts/opencode-mcp-acceptance.py --agentfw target/debug/agentfw \
  --opencode "$OPENCODE" --out target/opencode/mcp.json
python3 scripts/opencode-mcp-acceptance.py --agentfw target/debug/agentfw \
  --opencode "$OPENCODE" --hooks --out target/opencode/hooks.json
python3 scripts/opencode-plugin-fault-acceptance.py --opencode "$OPENCODE" \
  --out target/opencode/faults/report.json
python3 scripts/opencode-filesystem-acceptance.py --agentfw target/debug/agentfw \
  --opencode "$OPENCODE" --node "$NODE" --npm "$NPM" --bwrap "$BWRAP" \
  --npm-cache "$OFFLINE_NPM_CACHE" --out target/opencode/filesystem.json
```

The filesystem fixture requires the repository-pinned original server, Node,
bubblewrap and offline npm inputs. Providers and receivers are local scripted
fixtures, all files/credentials are synthetic, and no paid model is used.
Reports distinguish runtime/source identities, native enforcement checks and
host/plugin failure characterization. Linux only; Windows/macOS installation,
V2 APIs, multi-server launch provisioning and whole-session protection are not
qualified by this increment.
