# Claude Code MCP connection

The connection commands manage one selected Claude Code stdio server. They use
the existing native-admission proxy and never change other servers in the file.

## Preview

```sh
agentfw mcp-connection preview --path /tmp/claude.json --server local
```

Preview reads the selected entry and prints only bounded, non-secret metadata.
It does not start the server or write the configuration.

## Connect

```sh
agentfw mcp-connection connect --path /tmp/claude.json --server local
```

Connect replaces only the selected stdio command with the installed
`agentfw mcp --native-admission` wrapper. The original entry is stored in a
sidecar ownership record. Repeating the command is safe and does not add a
second wrapper.

The first supported profile is a local Unix/Linux JSON file with an
`mcpServers` object and a selected `command` plus string `args`. URLs and other
transports are refused.

## Inspect and disconnect

```sh
agentfw mcp-connection inspect --path /tmp/claude.json --server local
agentfw mcp-connection disconnect --path /tmp/claude.json --server local
```

Disconnect restores only the exact entry owned by the sidecar. If the entry
was edited after connect, the command fails and leaves the edit untouched.

The configuration and ownership record are written with temporary files and an
atomic rename. A per-file lock rejects concurrent connect or disconnect
operations. The sidecar contains the original command and arguments, but no
tokens or environment values.

This feature does not modify a real user profile in its tests, approve Claude
Code permissions, discover every MCP server, or claim protection for legacy
HTTP hooks.
