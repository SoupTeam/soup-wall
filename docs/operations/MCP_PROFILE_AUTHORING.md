# SOU-65 — operator-owned MCP profile authoring (draft)

The `agentfw mcp-profile` tool is a **local offline preparation tool**. It does
not discover a running server, authorize a tool by its description, create an
Agent session, alter an active native registry or contact a provider. The
result must still be separately selected by an operator, and the server
implementation itself must be reviewed. Do not deploy unreviewed declarations.

## Initial Linux operator workflow

Obtain a bounded saved original `tools/list` result from an *owned* MCP
server, pinned to an explicit, exact server identity and version. Keep the
original descriptions and input schemas, even if their language claims access.

```sh
agentfw mcp-profile import \
  --discovery /private/input/tools-list.json \
  --server owned-server --version 1.0.0 \
  --output /private/review/snapshot.json
agentfw mcp-profile explain --snapshot /private/review/snapshot.json
```

**None** of the imported tools are admitted. Review the server's implementation
and actual supported executor, write a private operator declaration with
exact `discovery_sha256`, `schema_sha256`, semantic action class,
result provenance, destination extraction/allowances, and
`implementation_reviewed: true`. A non-read operation requires an enforced
`resource_policy`. An absent selector, unsupported schema, malformed or
unknown runtime policy **fails**, rather than guessing intent. Follow the
existing `native::resource::Policy` format and limits; no new policy
semantics are introduced.

```sh
agentfw mcp-profile validate \
  --snapshot /private/review/snapshot.json \
  --declaration /private/review/operator.json
agentfw mcp-profile diff \
  --before /private/review/operator-old.json \
  --after /private/review/operator.json
agentfw mcp-profile compile \
  --snapshot /private/review/snapshot.json \
  --declaration /private/review/operator.json \
  --output /private/review/compiled-v1
```

Compile creates a **new** private directory with `registry.json` and
`report.json`; it refuses overwriting an existing directory. It uses the
current `NativeState::from_bytes` validation path, rather than inventing an
incompatible policy grammar. The report contains non-secret digests of the
original snapshot, reviewed declaration and exactly compiled native registry.

For controlled deterministic exercises, build `agentfw` and run:

```sh
cargo build --locked -p agentfw
python3 scripts/verify-sou65-profile.py
```

The exercise validates the current native registry parser, an owned read-only
declaration, duplicate publication refusal, altered schema digest, revoked
review assertion, mismatched discovery, and a misleading imported description.

## Explicit limitations before release

- A compiled registry is **not** installed or active, and original server
  behavior is not attested by example input.
- Validation uses current native registry and input-schema checks. Additional
  nested/optional resource pointer coverage, concrete supported write/send
  profiles, egress authority diff granularity, and a live enforcing collector
  witness are still required before SOU-65 can be considered Done.
- Keep input/output paths absolute, private and controlled by the operator.
  A local validation example cannot establish sandbox isolation or protect
  against an external unreviewed server.

Review code, implementation provenance, configuration, examples, schema
retention and all runtime checks before approving a profile.
