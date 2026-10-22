# Claude Code MCP connection

The connection commands manage one explicitly selected server in a Claude Code
JSON file. The supported transaction platform is Linux, including a Linux
profile inside WSL2. The [native Windows backend](WINDOWS_MCP_CONNECTION.md)
has a separate NTFS, ownership and recovery contract. macOS, project aliases,
remote transports and nonempty server environments are refused.

## Operator flow

Use absolute paths to an existing Agent executable, its reviewed `.agentfw`
directory and a JSON file containing an `mcpServers` object. The Agent must be
running in enforcing mode with its pinned native registry. The selected server
must name an absolute executable and an array of string arguments.
The installed entry may contain at most 256 arguments. The generic collector adds 11,
so an original entry may contain at most 245. The complete proposed config
and recovery record must each fit within 1 MiB before any transaction is saved.

The config must be a regular, single-link file owned by the operator, with mode
`0600`. Its directory must be owned by the operator and not writable by other
users. Paths containing symlinks or `..` are refused. Executables must not be
writable by other users. These checks never change existing permissions.

```sh
agentfw mcp-connection preview --path /private/mcp.json --server notes \
  --agent /private/bin/agentfw --home /private/profile/.agentfw
agentfw mcp-connection connect --path /private/mcp.json --server notes \
  --agent /private/bin/agentfw --home /private/profile/.agentfw
agentfw mcp-connection inspect --path /private/mcp.json --server notes \
  --agent /private/bin/agentfw --home /private/profile/.agentfw
```

Preview validates the selected entry and describes the bounded change without
writing files, starting servers or contacting a provider. Output contains
identities and digests, never original command arguments or environment values.
Connect queries the existing authenticated
[Agent status endpoint](AGENT_LIFECYCLE.md), matching the selected
binary, loaded native configuration and registry. It then installs the existing
`agentfw mcp --native-admission` collector with a stable per-file/server ID.

The wrapper uses `/usr/bin/env -i` with only a fixed system PATH and the explicit
Agent profile. The original command and argument values retain their order.
A nonempty selected `env` is outside this profile: move credentials to an
operator-reviewed mechanism before connecting. Unrelated server entries and
settings retain their JSON values. Formatting and object key order may change.

### Selected original-server profiles (Linux)

`--server-profile <profile.json> --classifier-script <file> --classifier-python <python>`
connects the original [filesystem](MCP_REAL_FILESYSTEM.md) or
[Git](GIT_MCP_PROFILE.md) server under its accepted read-only profile. The selected
entry must be the profile's original command and arguments. Preview and connect
verify the profile, every installed runtime pin and the repository rules with the
collector's own sandbox code; connect also requires a registry whose result-profile
tools all belong to that profile and no resource executor. The wrapper then adds
exactly five settings to `env -i`: `AGENTFW_MCP_SERVER_PROFILE`, `AGENTFW_WORKSPACE`,
`AGENTFW_CLASSIFIER=rule-baseline`, `AGENTFW_RULE_BASELINE` and
`AGENTFW_CLASSIFIER_PYTHON` (normalized absolute paths only), so the collector adds
16 arguments and an original entry may contain at most 240. The ownership record
binds the profile, classifier and interpreter digests. `inspect` re-verifies them from
the recorded paths and reports `unknown` after any change; a retried `connect` with
different settings is refused. `disconnect` is unchanged. A connect without
`--server-profile` for a registry that belongs to an original-server profile is
refused, so an entry never appears protected while its server runs outside the profile.
Probes of profile connections negotiate the pinned protocol version with a 60-second
bound. [Onboarding](ONBOARDING.md#original-filesystem-and-git-profiles) uses this path.
Other platforms refuse `--server-profile`.

## Controlled verification

Inspect is read-only unless an operator explicitly supplies a probe. A probe
starts the configured path, discovers tools and sends the chosen call:

```sh
agentfw mcp-connection inspect --path /private/mcp.json --server notes \
  --agent /private/bin/agentfw --home /private/profile/.agentfw \
  --probe-tool read_document --probe-args '{"name":"inventory"}'
```

Choose a harmless read in an owned fixture. A probe is a real tool invocation.
Only the digest of its admitted result is printed.

| Status | Meaning |
| --- | --- |
| `preview` | Valid selected input; no change has been made |
| `configured` | Owned entry and current Agent identities match |
| `verified_for_this_probe` | The explicit controlled call returned an admitted result |
| `unavailable` | Preflight or the controlled request failed |
| `unknown` | Ownership, pending transaction or configuration identity is not verified |
| `disconnected` | No owned wrapper remains to restore |

Unknown and unavailable return nonzero. A successful status query alone never
proves execution protection. Verification describes that invocation only;
future calls still pass through native admission.
Inspect checks the config and ownership snapshot after preflight and again
after a probe. A changed snapshot returns `unknown`, without a probe digest;
printed config digests describe the inspected snapshot, not a later file.

## Disconnect and recovery

```sh
agentfw mcp-connection disconnect --path /private/mcp.json --server notes \
  --agent /private/bin/agentfw --home /private/profile/.agentfw
```

Disconnect works while the daemon is stopped. It restores only the selected
entry recorded by this connection and preserves later unrelated edits. A
changed selected entry causes a conflict with no overwrite. Repeated connect
does not double-wrap; repeated disconnect is harmless.

Each config directory retains a private `.soup-wall-mcp.lock` file. The kernel
releases its advisory lock after process exit, including a crash. Do not delete
the lock while an operation is running.

A private `.soup-wall-<digest>.json` file stores ownership, exact original and
wrapped entries, native identities and transaction phase. It is written and
synced before the config changes. Ownership updates use atomic rename and
directory sync; config publication retains the displaced file as described below.
Original arguments may be sensitive; keep this record
private. A pending transaction is never reported as configured.

After interruption, repeat connect with the same pinned inputs to finish a
pending connection, or disconnect to restore the original entry. A changed
binary, registry, native config or selected entry causes refusal. Resolve that
change explicitly; do not copy an old whole-file backup over the current file.
Failed writes retain recovery metadata when necessary.

The lock coordinates these commands. Every successful operation checks the
config inode, bytes, directory identity and ownership record. Repeated connect
also checks these after preflight, even when no config replacement is needed.

Config publication uses Linux `renameat2(RENAME_EXCHANGE)`. Before the exchange,
the command syncs a private `.soup-wall-version-<id>` directory containing the
original snapshot, proposed bytes and a manifest. A separate private
`.soup-wall-publication-<digest>.json` journal identifies the pending exchange.
The exchange moves the actual displaced inode into `exchanged.json` in that
directory. It never unlinks the displaced file, including after success.
The filesystem must support exchange; failure retains the journal and versions.

After exchange, the command compares the displaced inode and bytes with the
original snapshot. An external write or replacement at publication produces a
nonzero conflict instead of success. The live config may already contain the
proposed version. The command does not overwrite it again to roll back: that
would create another race. Both versions and the journal remain for recovery.
Further connect/disconnect attempts refuse an unresolved conflict; inspect and
preview refuse any unfinished publication.

After a process crash, connect/disconnect can clear the publication journal
only when the inode identities and complete bytes prove the exact pre-exchange
or post-exchange state. The normal pending connection/disconnection then resumes.
Any other state requires manual reconciliation. Stop writers, compare the live
config with `snapshot.json`, `proposed.json` and `exchanged.json`, and preserve
the unrelated settings in the chosen config. Keep the archive, remove only the
matching publication journal after reconciliation, then repeat the operation.
The selected entry must still match the owned original or wrapped entry.

These commands do not isolate arbitrary editors. A writer with an already open
descriptor can continue modifying the displaced inode after publication. Its
writes remain in `exchanged.json`, even after the command returns. Retained
versions can contain sensitive configuration; they use private permissions and
are not automatically pruned. Remove them only after all writers have closed
and the chosen live configuration has been checked.

## Reproduce acceptance

Build the current source, then provide an already installed Claude Code
executable. The runner does not install or update that client:

```sh
cargo build --locked -p agentfw
python3 scripts/test-mcp-connection.py --agentfw target/debug/agentfw \
  --claude /absolute/path/to/claude --out target/connection-evidence/new-run
```

Docker must provide Linux containers. The image is pinned by digest. The test
uses private disposable Agent and Claude profiles, an existing deterministic
local Messages API and the existing MCP fixture. No paid model is contacted.
The installed client reaches the unchanged generated Linux entry through an
explicit Docker stdio bridge; the report records the client and binary identity.
This bridge run does not establish native macOS or Windows transaction support.

The receiver and original server ledger independently prove the useful read,
the absence of a forbidden send and the refusal after daemon loss. The final
ledger is reconciled after both client sessions. The runner also checks
preview, repeated operations, conflict preservation, pending recovery,
malformed inputs, original arguments, unrelated entries and offline disconnect.
It pauses real CLI processes during preflight to exercise concurrent selected
edits, disconnect and ownership changes, and checks both sides of the argument
limit without invoking the boundary-test server.
An owned `LD_PRELOAD` scheduling fixture also writes and replaces the destination
at the actual exchange boundary, writes through a retained descriptor, and kills
the command immediately before and after exchange. Both connect and disconnect
must preserve the versions, refuse conflicts and recover exact interrupted states.
The fixture is compiled with the container's C compiler and is never installed
or loaded into the host client or daemon.

Reports retain timings, per-operation identities, client outcomes, source
hashes and cleanup. Native tokens remain in the temporary Linux profile.
The existing [legacy HTTP hook fails open](MCP_STDIO_ADMISSION.md); connecting
one selected MCP server neither changes that behavior nor protects every host
tool. The server still runs as the operator: this is no arbitrary-server OS
confinement claim.
