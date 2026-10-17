# Versioned SOU-65 owned MCP demonstration profile

`discovery.json` is the bounded original-tool snapshot for the owned fixture
`scripts/fixtures/mcp_profile_author_server.py`, not a claim about a deployed
external server. `declarations.json` is a **reviewed declaration for that
fixture alone**, with an exact schema/snapshot pin. Operator review must
never be copied to an unrelated server or version.

```sh
agentfw mcp-profile validate --snapshot "$PWD/profiles/mcp/operator-authoring-v1/discovery.json" --declarations "$PWD/profiles/mcp/operator-authoring-v1/declarations.json"
agentfw mcp-profile compile --snapshot "$PWD/profiles/mcp/operator-authoring-v1/discovery.json" --declarations "$PWD/profiles/mcp/operator-authoring-v1/declarations.json" --out "/absolute/operator-owned/private/compiled-v1"
```

To author a **new** server, begin with `agentfw mcp-profile import`; never
change only the digest or preserve a prior review statement across drift.
The compile command publishes private inert files and does not install grants.
