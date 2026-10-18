# Owned Linux MCP profile transitions (SOU-78)

This workflow changes one existing **owned Claude Code stdio connection** between
two explicitly reviewed profiles. It reuses the accepted authoring compiler, owned
connection publication and Agent lifecycle manager. It does not discover or approve
new authority automatically. Development and acceptance use disposable homes.

The supported path is Linux. macOS and Windows reject the owned profile commands
before mutation. An enforcing, responding, owned Agent with a pinned native registry
and a supported lifecycle installation is required. The Agent binary and policy stay
pinned throughout a profile change. Upgrading binaries/services is a separate lifecycle
operation, not a profile transaction.

## Preview and apply

First author both inert bundles with `agentfw mcp-profile import`, review every
schema and authority declaration independently, and `validate`/`compile` them as
specified in [MCP_PROFILE_AUTHORING.md](MCP_PROFILE_AUTHORING.md). A tool description,
version number or discovery annotation does not grant authority.

The selected connection must already be owned by `mcp-connection connect` and must
still match its recorded wrapped entry, Agent binary, native configuration and
registry identities. Existing `connect`/`disconnect` refusals are preserved.

```bash
agentfw mcp-connection profile preview \
  --path /absolute/claude-mcp.json --server selected \
  --home /absolute/operator/.agentfw --agent /absolute/agentfw \
  --source-profile /absolute/reviewed-v1 --profile /absolute/reviewed-v2 \
  --host-session actual-host-session \
  --classifier-script /absolute/rule_baseline/rule_baseline.py
```

`--host-session` is the actual authenticated host context whose history must survive.
It is an identity, not a new bearer credential. Keep it identical on subsequent
transitions. Existing scoped hook authentication still applies: scoped hooks require
the signed proof of an active collector, as in SOU-63; a shared hook bearer alone
cannot impersonate an agent or erase its history. The operation does not install or
invent a replacement hook authentication transport.

`--classifier-script` selects reviewed rule-baseline source for native privileged
resource executors. It is optional for profiles containing only ordinary read-only
tools. Resource profiles must agree on workspace and classifier digest. The source
and `/usr/bin/python3` binary are hashed; source is staged privately by content
identity, and the launcher revalidates those pins. No new classifier is supplied.

Preview shows schema, action, resource/destination and provenance changes. Its
`approval` binds the exact source/target bundle, host file bytes, ownership record,
home/path/server, host session, next generation, classifier/interpreter, binary,
registry, config, policy and current native daemon instance. It stages nothing.

Pass the returned digest to the identical command with `apply`:

```bash
agentfw mcp-connection profile apply \
  --path /absolute/claude-mcp.json --server selected \
  --home /absolute/operator/.agentfw --agent /absolute/agentfw \
  --source-profile /absolute/reviewed-v1 --profile /absolute/reviewed-v2 \
  --host-session actual-host-session \
  --classifier-script /absolute/rule_baseline/rule_baseline.py \
  --approval EXACT_PREVIEW_DIGEST
```

Generic `yes` is refused. Changed inputs, a changed daemon instance or unrelated
host edit require a fresh preview. Another active daemon/profile/connection operation
is a conflict, not permission to overwrite its state.

## Durable transition and authority

1. The host publication lock and bounded outer journal reserve the selected connection.
   A home-wide reservation prevents another profile writer or launcher from proceeding.
2. Both reviewed bundles and any selected classifier are validated and staged privately
   before the continuity barrier or daemon switch. Revisions are content-addressed;
   all six authoring outputs must reconstruct the reviewed authority exactly.
3. An authenticated native barrier drains earlier authenticated POST handlers, checkpoints
   retained taint and scoped host identities, and imposes a sticky incomplete-history
   floor for deliveries that cannot be attested across the restart.
4. The existing profile/lifecycle manager atomically selects the candidate registry,
   retires the persistent approval epoch, restarts the owned daemon, and verifies its
   fresh process/config identity. It compensates startup failure through the same
   lifecycle APIs; it does not introduce another service manager.
5. The accepted retained-version publication primitive atomically exchanges only the
   selected host entry. Unrelated entries/settings are preserved. The selected entry
   always invokes a native collector wrapper; it never temporarily invokes the original
   server directly. Ownership and installed-generation metadata are then committed.
6. A private generation-checked launcher refuses pending or stale transactions, rechecks
   Agent/config/registry/policy identity, obtains the current authenticated daemon
   instance and mints narrowed session authority. Tokens stay out of host configuration,
   argv, audit and the original server's environment.

Already running collectors have the previous daemon's session/call state and cannot
release results or execute a new call after the restart. New launchers mint current
instance-bound authority. A byte-identical rollback advances generation again, so an
old launcher cannot revive. Outstanding result receipts and Ask records are not
restored; approval issuance/redemption is refused during the transition, and previous
policy epochs remain invalid after it.

## Risk continuity

Private `mcp-profiles/risk-checkpoint.json` authenticates provenance with HMAC-SHA256
and domain `agentfw/provenance-checkpoint/v1\0`. It contains taint fingerprints,
URL/path literals, incomplete-history flags and scoped-host tombstones. It deliberately
contains no active agent grants, calls, receipts or approvals. Restore requires a
pristine tracker and enforces current provenance budgets. A malformed, public,
symlinked, over-budget or invalid-MAC checkpoint refuses startup.

Once enabled, authenticated POST handlers first fsync `risk-inflight.json`, then fsync
the signed checkpoint before releasing their response. An interrupted handler restores
a global incomplete-history floor. On storage failure, native calls fail closed and
hooks return documented HTTP 200 `permissionDecision: deny`. Exact old span-cache
indices and ephemeral native sessions are not restored; the conservative floor accounts
for incomplete context. The floor is evidence of uncertainty, not a fabricated taint
source, and it does not silently expire or disappear on collector restart.

Checkpoint serialization and reads are capped at 16 MiB. Native scoped-host tombstones
are capped at the existing 64-host bound. Reaching a bound refuses the operation;
history is not silently evicted to claim a successful transition. Checkpoint contents
may contain sensitive provenance literals: keep them private and exclude them from
support bundles. Same-user operators who can read daemon keys remain outside the
credential boundary, as with the existing native protocol.

## Status, recovery and rollback

```bash
agentfw mcp-connection profile status \
  --path /absolute/claude-mcp.json --server selected \
  --home /absolute/operator/.agentfw --agent /absolute/agentfw

agentfw mcp-connection profile recover \
  --path /absolute/claude-mcp.json --server selected \
  --home /absolute/operator/.agentfw --agent /absolute/agentfw
```

Status separates `configured`, `not_configured`, `conflict` and `incomplete` from
`daemon: configuration_verified`, `identity_mismatch` or `unavailable`.
`runtime_execution: not_probed` and `host_reload: pending` are intentional. Atomic
publication and daemon health do not prove that a running Claude host reloaded it.
Reload/restart that host, then exercise the intended useful call through its actual
collector; configuration status alone is not execution attestation.

Recovery is idempotent. Before candidate activation it retains the verified baseline;
after activation it completes the retained owned publication. It recognizes crashes
immediately before and after the host exchange. A foreign daemon, ownership change,
modified selected entry or external publication edit retains journals and every
captured version and reports a conflict. Preserve those private files, inspect the
current and retained versions, and explicitly reconcile the intended configuration
before retrying recovery. Do not delete a journal or edit ownership metadata to force
success. Recovery does not guess which external edit to discard.

Rollback uses the same preview/apply commands, swaps `--source-profile` and `--profile`
and adds `--rollback` to **both**. Only the recorded previous reviewed snapshot is
eligible; it must still pass authoring, resource and runtime validation. Revoked review,
a changed workspace/classifier or a no-longer-valid create-file destination can make
an old snapshot ineligible. No arbitrary file is accepted as rollback authority.

Outer transaction records are limited to 1 MiB; daemon profile state to 10 MiB, Agent
config to 1 MiB and recent low-level operation history to 1024 records. Retained host
publication archives are deliberately preserved as private operator evidence; they
are not automatically garbage-collected. A home-wide native registry is shared: this
workflow serializes profile changes and does not promise independent live registries
for multiple selected connections in one Agent home.

The lower-level `mcp-profile install/preview/upgrade/rollback/status/recover` commands
remain available for daemon-profile maintenance. They do not publish an owned Claude
entry and cannot bypass a pending owned-connection transition. Use the owned workflow
above for an installed connection.

## Reproduction

`scripts/verify-sou78-linux.sh` exports the committed tree into a disposable ordinary-UID
container, disables external networking/capabilities and runs strict lint, affected test
suites and `scripts/verify-sou78-owned.py`. The latter uses a real managed Agent, real
stdio collectors and a scripted host; it makes no paid-model or installed-UI claim.
Its independent original-server execution ledger, profile/binary digests, explicit
crash-before/crash-after exits and sanitized check counts are retained in CI artifacts.
See [evidence/sou-78-evidence.md](evidence/sou-78-evidence.md) for exact-source results.
