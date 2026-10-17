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
  The supported, operator-explicit `private_endpoint` and
  `root_certificate_pem` fields are passed to the existing native
  `HttpsGetAuthority::validate` checks. They are not inferred from a tool
  description or a URL: a private address requires the exact reviewed
  exception; the TLS client still verifies hostname, CA and expiry.
  These fields are intended for deliberately owned endpoints or an
  independently approved deployment, **not a global private-network grant**.

Other operations, including arbitrary send-to-recipient, mixed actions,
unsupported schema keywords, aliases, unconstrained paths and destinations,
are **not** silently translated to a weaker read permission. No synthetic
semantic declaration is attestation for an unrelated real server.

Compilation now also emits `native-config.json`, a typed, inert
`NativeCfg` fragment containing the final registry path and exact digest.
The owned acceptance starts the Agent with this generated fragment, instead
of hand-assembling its registry identity; compiling still does **not** install
or modify the user's active configuration. Strict duplicate-key JSON and
schema-drift refusals are covered by the CLI acceptance.

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
replacing an existing directory. It contains **six files**: `registry.json` (the actual native registry
consumed by `NativeState::from_bytes`), `native-config.json` (typed,
inert `NativeCfg` fragment with final path and SHA-256),
`resource-profiles.json`, `profile.json`, `source-snapshot.json`,
and `operator-declarations.json`.
The operator must separately review and explicitly select the generated
`native-config.json` fragment when configuring the actual Agent.
Compilation itself never changes the active config and cannot prove the
selected external server honors a description or runs sandboxed.

For an individual invocation, pass
`--example /private/path/to/arguments.json` to `validate` with
`{"tool":"read_document","arguments":{"name":"inventory"}}` shape.
This reuses the production bounded schema and typed resource extraction;
it **does not execute the tool** or authorize arbitrary future arguments.

## Real production-collector acceptance and limits

Run on an owned Linux host with Rust, Python and OpenSSL installed:

```sh
python3 scripts/mcp-profile-authoring-demo.py
# For an already built exact Agent:
python3 scripts/mcp-profile-authoring-demo.py --no-build
```

The one-command acceptance creates fresh private temporary directories and
operates only on controlled local fixtures. The **real** Agent daemon and
production stdio MCP collector consume the compiled native registry and
the generated `native-config.json` fragment, not a hand-built replacement.
The demonstration checks:

- Import starts with every tool unreviewed and refuses partial reviews;
  original name/schema and declaration digests survive compilation.
- Reviewed `read_document` is useful, unreviewed send and unknown arguments
  do not reach the child, and a malicious description grants no authority.
- Native `create_file` creates one approved workspace child while rejecting
  an out-of-scope path with zero child writes.
- Native `https_get` uses an explicitly reviewed HTTPS URL, loopback
  fixture exception and disposable CA with normal TLS validation. A separate
  receiver process records the **one actual GET** and its exact Host/target;
  a second independently owned TLS receiver sees **zero connections** for
  the changed destination. A malformed scheme is rejected, and a useful
  original `read_document` invocation succeeds *after* the refusal.
  No HTTPS call is passed through to the child executor.
- The schema/description drift, changed certificate or private-endpoint
  mapping, duplicate JSON members, symlinks, unsafe authority diff, no-clobber
  publication and 0700/0600 private output behavior are checked.

A sanitized exact-source proof is written to
`target/sou65-profile-author-evidence.json`. It contains the source commit,
Agent binary digest, compiled registry digest and named check outcomes, not
operator tokens or private keys. The focused
`.github/workflows/mcp-profile-author.yml` job runs the same demonstration
on the PR head.

**Scope:** The TLS endpoint, CA and discovery are disposable owned fixtures.
The demonstration proves the compiled authority works with the selected
*current production collector* for these supported operations; it is not an
attestation of an unrelated MCP server, arbitrary behavior, all network
environments, generalized send-to-recipient semantics, or host sandboxing.
Operator implementation review is a separate manual prerequisite.
