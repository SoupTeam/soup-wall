# Copilot CLI MCP and scoped hooks (Linux, 1.0.112)

This increment qualifies the published **@github/copilot 1.0.112** Linux binary
against owned scripted providers. It covers selected local MCP connections and
an optional signed `preToolUse` / `postToolUse` binding. It does not qualify the
VS Code Copilot extension or expand the frozen Linux pilot's supported hosts.
See GitHub's [MCP configuration](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers),
[command hook reference](https://docs.github.com/en/copilot/reference/hooks-reference)
and [custom providers](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-llm-models).
The actual captured frames and executable behavior define the tested contract.

## Selected connection

The [shared private connection requirements](CLAUDE_MCP_CONNECTION.md) apply.
An existing owner-private `~/.copilot/mcp-config.json` can contain:

```json
{
  "mcpServers": {
    "notes": {
      "type": "local",
      "command": "/private/python3",
      "args": ["/private/server.py"],
      "tools": ["*"]
    }
  }
}
```

```sh
agentfw mcp-connection preview --host copilot --path /private/.copilot/mcp-config.json \
  --server notes --agent /private/agentfw --home /private/profile/.agentfw
agentfw mcp-connection connect --host copilot --path /private/.copilot/mcp-config.json \
  --server notes --agent /private/agentfw --home /private/profile/.agentfw
agentfw mcp-connection inspect --host copilot --path /private/.copilot/mcp-config.json \
  --server notes --agent /private/agentfw --home /private/profile/.agentfw
```

The selected entry accepts `type: local` or `stdio`, an absolute command,
bounded arguments, an optional empty `env`, and absent `tools` or exactly
`["*"]`. The actual-host evidence uses `local`; `stdio` preservation is covered
by connection tests. Selected remote transport, tool filters, credentials,
`${...}` interpolation and unknown options are refused. Strict JSON rejects
duplicate keys, comments and trailing commas. The type/tool selector and all
unrelated bytes remain unchanged. Connection journal publication, conflicts
and crash recovery retain their existing private-file checks.

Restart Copilot to load the wrapper. `configured` is distinct from a successful
probe. Append `--probe-tool read_document --probe-args '{"name":"inventory"}'`
to `inspect` for a reviewed real probe. `disconnect` with the same connection
arguments restores the original launch. Original filesystem profiles use the
same explicit profile/classifier/runtime pins as the
[Codex procedure](CODEX_MCP_CONNECTION.md#reproduce-usd0).

The [captured call](../../scripts/fixtures/copilot-1.0.112-call.json) contains
`com.github.copilot/toolCallId` and an integral safe `progressToken`. Both are
bounded untrusted correlation. Mixed identities, unknown metadata and partial
shapes are refused; neither field supplies native identity or authority.

## Optional signed callback binding

An operator-created private binding has this shape:

```json
{
  "contract_version": "sw-copilot-hook-binding/1",
  "host_session": "operator-issued-run-id",
  "host_server": "notes",
  "native_server": "copilot-connection-id-from-inspect",
  "child_authority": "signed-scoped-proof-from-the-trusted-issuer"
}
```

The native collector must use the same `AGENTFW_HOST_SESSION` and
`AGENTFW_CHILD_AUTHORITY`. The [authority protocol](MCP_STDIO_ADMISSION.md)
binds the active daemon instance, server, agent, tools and resources. This
increment does not provision a persistent trusted launcher. Its disposable
`--hooks` acceptance explicitly creates and verifies one complete binding.

Add command hooks to the private Copilot `settings.json`:

```json
{
  "hooks": {
    "preToolUse": [{
      "type": "command",
      "command": "/private/agentfw copilot-hook --home /private/profile/.agentfw --binding /private/run/copilot-binding.json --phase before",
      "timeoutSec": 5
    }],
    "postToolUse": [{
      "type": "command",
      "command": "/private/agentfw copilot-hook --home /private/profile/.agentfw --binding /private/run/copilot-binding.json --phase after",
      "timeoutSec": 5
    }]
  }
}
```

Quote paths appropriately if they contain spaces. The phase is selected by
trusted configuration. The [captured callback](../../scripts/fixtures/copilot-1.0.112-hooks.json)
includes `toolCallId` as well as `sessionId`, `timestamp`, `cwd`, `toolName`
and `toolArgs`. Tool labels use `server-tool`. These host fields are never
native authority. The adapter preserves arguments and the entire original
`toolResult`, including `textResultForLlm`, for the authenticated
`/hook/decision/v1` endpoint. The daemon derives identity and provenance from
the active native collector. Unexpected or incomplete shapes are refused.

Defer emits `{}` and leaves host permissions unchanged. Deny and Ask emit an
explicit permission denial before execution, or `modifiedResult` with
`resultType: failure` after execution. Ask remains a visible pending policy
decision; no host permission is treated as a native grant. Result withholding
does not undo an earlier side effect. Copilot does not invoke `postToolUse`
for failed MCP calls; native admission already withholds their rejected results.

Handled bridge errors emit an explicit refusal. Host behavior has limits:
pre-hook nonzero exits block, but timeouts and malformed JSON fail open;
post-hook crashes also fail open. These are measured runtime boundaries,
not guarantees supplied by the adapter. Removing hooks likewise removes
their coverage. The native MCP collector remains the execution/result
boundary. Unsupported built-ins are refused when the callback runs; built-in
tools, subagents, background tasks, HTTP hooks and whole-session protection
are not natively enrolled or qualified here. Interactive Ask/grant UI is not
qualified.

## Reproduce (owned fixtures, USD0)

Install exact official `@github/copilot@1.0.112` in an isolated prefix and use
its platform executable as `COPILOT`. The acceptance creates fresh private
homes, sets `COPILOT_OFFLINE=true`, disables updates and built-in MCPs, and
selects only `owned/fixture` from an explicit local providers file. Broad host
permissions apply only to these disposable synthetic fixtures. No user
credentials or paid provider requests are used.

```sh
cargo build --locked -p agentfw
cargo fmt --all -- --check
cargo test --locked --workspace
python3 scripts/copilot-mcp-acceptance.py --agentfw target/debug/agentfw \
  --copilot "$COPILOT" --out target/copilot/mcp.json
python3 scripts/copilot-mcp-acceptance.py --agentfw target/debug/agentfw \
  --copilot "$COPILOT" --hooks --out target/copilot/hooks.json
python3 scripts/copilot-hook-fault-acceptance.py --copilot "$COPILOT" \
  --out target/copilot/faults/report.json
python3 scripts/copilot-filesystem-acceptance.py --agentfw target/debug/agentfw \
  --copilot "$COPILOT" --node "$NODE" --npm "$NPM" --bwrap "$BWRAP" \
  --npm-cache "$OFFLINE_NPM_CACHE" --out target/copilot/filesystem.json
```

The filesystem check requires the pinned original server, Node, bubblewrap
and offline npm cache. Reports record exact runtime/source identities and
independent receiver/filesystem witnesses. Linux only; Windows/macOS runtime
installation, multi-server authority provisioning and live-model effectiveness
are outside this increment's evidence.
