# Gemini CLI MCP and scoped callbacks (Linux)

The tested host is **Gemini CLI 0.68.0**. `agentfw mcp-connection <operation>
--host gemini` manages one existing `mcpServers` entry in `settings.json`.
The optional `gemini-hook` bridge translates Gemini `BeforeTool`/`AfterTool`
for one signed, active native MCP binding. The native collector remains the
call/result enforcement boundary.

## Connection lifecycle

The [shared connection requirements](CLAUDE_MCP_CONNECTION.md) apply: absolute
executables, owned single-link `0600` configuration, no symlink components,
private ownership/recovery records and an explicit installed `.agentfw` home.
The selected entry supports `command`, optional string-array `args`, and an
empty optional `env`. Other selected fields, remote transports and credential
environments are refused. Unselected settings may contain arbitrary values.

```jsonc
{
  // Existing server; install its reviewed registry and policy separately.
  "mcpServers": {
    "notes": {"command": "/private/runtime/python3", "args": ["/private/server.py"],},
  },
}
```

```sh
agentfw mcp-connection preview --host gemini --path /private/home/.gemini/settings.json \
  --server notes --agent /private/bin/agentfw --home /private/profile/.agentfw
agentfw mcp-connection connect --host gemini --path /private/home/.gemini/settings.json \
  --server notes --agent /private/bin/agentfw --home /private/profile/.agentfw
agentfw mcp-connection inspect --host gemini --path /private/home/.gemini/settings.json \
  --server notes --agent /private/bin/agentfw --home /private/profile/.agentfw
```

Restart Gemini to load the wrapper. Start it with a private umask:

```sh
(umask 077; gemini)
```

The pinned host can replace its settings file. With umask `022`, the observed
replacement was `0644`; inspection/disconnect correctly refused that file.
For an owned ordinary file, restore `0600` before retrying. Keep the containing
home private as well. The acceptance launches the host with umask `077` and
verifies privacy. No connection checks were relaxed for Gemini.

`configured`, `verified_for_this_probe`, and
`enforcement_coverage=selected_stdio_mcp_only` have distinct meanings. To run a
real permitted probe, append `--probe-tool read_document --probe-args
'{"name":"inventory"}'` to `inspect`, using your reviewed tool and arguments.

Use the same command with `disconnect` to restore the original selected entry.
JSONC comments/trailing commas are accepted, duplicate keys are refused, and
all bytes outside the selected entry are retained. The selected object may be
reformatted. Repeat installation, unrelated edits, selected conflicts, atomic
publication races and crash recovery use the existing connection machinery.

For an installed original filesystem profile, pass `--server-profile`,
`--classifier-script` and `--classifier-python` as in the
[Codex original-server procedure](CODEX_MCP_CONNECTION.md#reproduce-usd0).
The runtime, schemas, registry, policy and Linux confinement pins remain required.

## Optional signed callback bridge

```sh
/private/bin/agentfw gemini-hook --home /private/profile/.agentfw \
  --binding /private/run/gemini-binding.json
```

Configure this command in both Gemini hook events with matcher `.*` and a
5000 ms host timeout. A trusted run owner must provision the private binding:

```json
{
  "contract_version": "sw-gemini-hook-binding/1",
  "host_session": "operator-issued-run-id",
  "host_server": "notes",
  "native_server": "gemini-connection-id-from-inspect",
  "child_authority": "signed-scoped-proof-from-the-trusted-issuer"
}
```

The collector must use the same `AGENTFW_HOST_SESSION` and
`AGENTFW_CHILD_AUTHORITY`. Use the existing
[scoped authority protocol](MCP_STDIO_ADMISSION.md); the proof must bind the
current daemon instance, server, agent, tools and allowed resources. The bridge
reads owner-private files and never mints a proof from callback data.
`mcp-connection` installs the MCP wrapper; it does **not** provision a persistent
Gemini run launcher or manage these expiring callback bindings. The `--hooks`
acceptance below demonstrates the complete disposable provisioning sequence.

The bridge preserves arguments and the entire result value. It maps the real
`mcp_context.server_name`/`tool_name` through the operator binding. Host session,
transcript, launch metadata and timestamps supply no authority. The daemon
authenticates the proof against an active collector and supplies agent/parent
identity and result provenance. The observed callback has no invocation ID;
exact original-frame call/result binding remains in native MCP admission.

The authenticated `/hook/decision/v1` endpoint reuses the existing policy,
taint, identity and grant handling. It returns explicit before/after receipts;
the existing Claude `/hook` wire behavior is unchanged. Allow/shadow maps to
an empty Gemini response, preserving host permissions. Deny maps to `deny`.
Ask is explicitly held with a `deny` response retaining its Ask reason: the
pinned headless MCP host waits without continuing on a literal `ask` callback.
No interactive Ask UI or combined single-use approval flow is qualified here.

Handled parse/authentication/daemon failures return an explicit blocking JSON
response. Gemini itself fails open when a callback exits 1 or exceeds its host
timeout. A killed or missing callback therefore cannot provide whole-session
protection. Unsupported built-in tools are refused while this bridge runs;
they are not enrolled native executors. Subagent lifecycle/taint propagation,
interactive/background shell coverage and multi-server launch provisioning
remain unqualified. Existing native grants and OS boundaries are unchanged.

## Reproduce with owned fixtures (USD0)

```sh
npm install --prefix target/gemini-host --ignore-scripts --no-audit --no-fund @google/gemini-cli@0.68.0
GEMINI="$PWD/target/gemini-host/node_modules/@google/gemini-cli/bundle/gemini.js"
NODE="/absolute/path/to/node"
cargo build --locked -p agentfw
cargo test --locked -p agentfw --lib mcp::connection
cargo test --locked -p agentfw --lib gemini_hook
cargo test --locked -p agentfw --test hook_endpoint --test mcp_admission
python3 scripts/gemini-mcp-acceptance.py --agentfw target/debug/agentfw \
  --node "$NODE" --gemini "$GEMINI" --out target/gemini-acceptance/mcp.json
python3 scripts/gemini-mcp-acceptance.py --agentfw target/debug/agentfw \
  --node "$NODE" --gemini "$GEMINI" --hooks --out target/gemini-acceptance/hooks.json
python3 scripts/gemini-hook-fault-acceptance.py --node "$NODE" --gemini "$GEMINI" \
  --out target/gemini-acceptance/faults/report.json
python3 scripts/gemini-filesystem-acceptance.py --agentfw target/debug/agentfw \
  --node "$NODE" --gemini "$GEMINI" --npm /absolute/path/to/npm \
  --bwrap /absolute/path/to/pinned/bwrap --npm-cache /absolute/path/to/offline/npm-cache \
  --out target/gemini-acceptance/filesystem.json
```

The original filesystem test requires the repository-pinned Node, bubblewrap
and offline package inputs. All hosts use isolated homes and local scripted
providers; receivers, files and credentials are synthetic. Reports distinguish
source/runtime identities, actual checks, failure characterization and coverage.
The [captured Gemini call](../../scripts/fixtures/gemini-0.68.0-call.json)
contains only a bounded UUID-v4 progress token, accepted solely as correlation.
Other Claude/Codex metadata shapes retain their previous validation.

| Surface | Verified scope |
| --- | --- |
| Selected stdio MCP | Allowed read/send; Deny/Ask have no effect; rejected result held; useful continuation; daemon outage closed |
| Original filesystem MCP | Pinned original runtime; read, write refusal, result withholding, continuation, disconnect; independent tree witness |
| Optional callbacks | One shared signed native session; wrong transport token/proof blocked; allowed read resumes |
| Callback faults | Actual exit 1/timeout fail open; exit 2/deny block; headless MCP Ask waits |
| Built-ins / subagents / hosted tools | Outside native MCP enforcement; no whole-session claim |
| Windows/macOS installation | Unsupported by this increment |

Upstream contracts: [MCP settings](https://geminicli.com/docs/tools/mcp-server/)
and [hooks reference](https://geminicli.com/docs/hooks/reference/). Qualification
is tied to the pinned actual runtime and witnesses above.

[Recorded acceptance evidence](evidence/gemini-mcp-2026-11-17.json) binds these checks to the implementation and runtime hashes.
