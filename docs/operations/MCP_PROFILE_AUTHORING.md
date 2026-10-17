# SOU-65 — operator-reviewed MCP profiles (initial Linux scope)

The `agentfw mcp-profile` CLI stages an **inert, operator-owned profile**.
It never starts a daemon, connects to a provider/server, changes a host MCP
configuration, grants session authority or installs a registry.

## Trust boundaries

A saved, bounded original discovery snapshot has format
`sw-mcp/operator-discovery/1`, with explicit `server_id`,
`server_version` and a `tools` array of original MCP `tools/list`
definitions (name, description, inputSchema, optional annotations).
Preserve source frames separately if an upstream server requires extra
transport metadata. Every name, description, annotation and schema is
**untrusted evidence**, never a requested permission or behavior proof.

`import` produces a draft declaration with **every tool unreviewed**
(`reviewed: false`, `authority: null`, no operator attestation).
The operator must inspect the real server implementation, the actual arguments
and side effects, and separately edit each selected declaration:
`reviewed: true`, an explicit `authority.kind` and a bounded
`operator_review` statement. The snapshot and schema hashes are pinned; a
changed description, tool set or schema requires a new import/review.

**Runtime coverage limit:** the existing guarded stdio collector requires the
native registry to match the complete original `tools/list` inventory.
`validate` can inspect a partially reviewed declaration for planning, but
`compile` refuses to publish it while any original tool remains unreviewed.
The operator must either review **every** tool offered by that specific server
under supported enforcement or use a separate server offering a narrower
original tool inventory. The authoring CLI cannot hide undesired tools,
rename originals, or bypass the production manifest check.

The first Linux version deliberately admits only the current native:
- `read_only`: explicitly reviewed, zero egress. This is an *admission
  classification*, **not a sandbox** or proof the server cannot write; review
  the executor and constrain it separately. The dedicated real filesystem
  profile is its own selected execution contract.
- `create_file`: name **create_file**, the exact current native create-file
  schema, operator-chosen absolute existing workspace, direct missing
  destination child, and explicit reviewed classifier digest; generates the
  current typed root-child resource/execution policy.
- `https_get`: name **https_get**, the exact current native HTTPS GET schema,
  operator-chosen workspace, canonical exact URL, single verified approved
  address and classifier digest; generates the current typed network authority.

Other operations, including arbitrary send-to-recipient, mixed actions,
unsupported schema keywords, aliases, unconstrained paths and destinations,
are **not** silently translated to a weaker read permission. No synthetic
semantic declaration is attestation for an unrelated real server.

## Example workflow

Create an owned private directory and place the reviewed discovery snapshot
there, for example `/home/operator/private/mcp/discovery.json`.

```sh
agentfw mcp-profile import \
  --snapshot /home/operator/private/mcp/discovery.json \
  --server-id reviewed-server --server-version 1.0 \
  --out /home/operator/private/mcp/declarations.json

# Manually edit declarations.json: assert each selected tool's actual,
# independently reviewed behavior; unselected tools stay unreviewed.

agentfw mcp-profile validate \
  --snapshot /home/operator/private/mcp/discovery.json \
  --declarations /home/operator/private/mcp/declarations.json

agentfw mcp-profile explain \
  --snapshot /home/operator/private/mcp/discovery.json \
  --declarations /home/operator/private/mcp/declarations.json

agentfw mcp-profile compile \
  --snapshot /home/operator/private/mcp/discovery.json \
  --declarations /home/operator/private/mcp/declarations.json \
  --out /home/operator/private/mcp/compiled-v1

agentfw mcp-profile diff \
  --old /home/operator/private/mcp/compiled-v1/profile.json \
  --new /home/operator/private/mcp/compiled-v2/profile.json
```

The operator must create a *separate* `compiled-v2` for updates.
The CLI does **not** overwrite existing directories or publish into the active
Agent home. Output is privately staged, fsynced, and published without
replacing an existing directory. It contains:
`registry.json` (the actual native registry consumed by
`NativeState::from_bytes`), `resource-profiles.json`, `profile.json`,
`source-snapshot.json`, and `operator-declarations.json`.
The operator must explicitly configure the *actual* Agent's native registry
path and SHA-256 after reviewing the output; the profile generator cannot
prove that the selected external server's implementation honors any
description or that the collector is sandboxed.

For an individual invocation, pass
`--example /private/path/to/arguments.json` to `validate` with
`{"tool":"read_document","arguments":{"name":"inventory"}}` shape.
This reuses the production bounded schema and typed resource extraction;
it **does not execute the tool** or authorize arbitrary future arguments.

## Demonstration and limits

```sh
python3 scripts/mcp-profile-authoring-demo.py
```

The controlled smoke proof checks import denial-by-default, reviewed read
input, native registry hashing, source preservation, private files,
schema drift, forbidden arguments, no clobber and deterministic self-diff.
It does not claim a real remote server is safe or that arbitrary mixed
actions or egress destinations can be enforced.

A full independent SOU-65 acceptance still requires the production collector
under an owned test server, real read/write/network side effect and refusal
witnesses, and a reviewed stable ABI; this initial checkpoint is not a
completed SOU-65 delivery.
