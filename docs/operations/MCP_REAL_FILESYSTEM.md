# Selected read-only filesystem MCP profile

SOU-62 adds one explicit Linux x86-64 process profile for the original
`@modelcontextprotocol/server-filesystem@2026.8.31` stdio server. The selected
server runs with a read-only workspace, exact read-only runtime/dependency files,
private namespaces and denied socket/network operations. Its nine selected
read-only tools retain their original schemas, arguments and original result
bytes. Every call and every result still needs independent native admission.

This profile is selected by `AGENTFW_MCP_SERVER_PROFILE`, in addition to
`agentfw mcp --native-admission`. Omitting it keeps the existing guarded MCP
contract. Built-in Linux/Windows file and HTTPS executors are separate profiles;
this increment does not certify arbitrary MCP commands or complete Phase 4.

Without an explicit budget this compatibility profile has no aggregate CPU,
memory or task limit. Select the separate versioned
[Linux resource budget](MCP_LINUX_RESOURCE_BUDGETS.md) with
`AGENTFW_MCP_LINUX_BUDGET` to require a prepared cgroup-v2 delegation. Missing
delegation or unsupported controls refuse startup before the server executes.

The selected Linux runtime also uses [owned crash supervision](MCP_LINUX_CRASH_SUPERVISION.md)
for collector loss, private PID 1 ownership and bounded recovery. Process cleanup
and native session retirement are reported separately.

## Exact upstream and runtime identities

The committed [upstream identity](../../profiles/mcp/filesystem-readonly-v1/upstream-identity.json)
pins the original package archive, entry point, SDK `1.32.1`, dependency lock,
all original tool definitions and input schemas. The original
[initialize result](../../profiles/mcp/filesystem-readonly-v1/upstream-initialize.json)
and [tools/list result](../../profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json)
are retained without rewriting their schemas. npm installs the
[committed lock](../../profiles/mcp/filesystem-readonly-v1/package-lock.json)
with lifecycle scripts disabled. It verifies the original entry point after
installation. The installed profile additionally hashes every file, directory
and contained symlink in the complete installed dependency tree.

The selected runtime is the official Linux x64 Node.js `v22.22.0` binary:

- Archive SHA-256: `9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37`.
- `bin/node` SHA-256: `1bec56ef7cfa9a76f3e0b7c0a87f220eb73f23102b9c0b4c7529a3f7c3ce7c31`.
- Official archive: [node-v22.22.0-linux-x64.tar.xz](https://nodejs.org/dist/v22.22.0/node-v22.22.0-linux-x64.tar.xz).

The required CI builds [bubblewrap v0.13.1](https://github.com/containers/bubblewrap/releases/tag/v0.13.1)
from archive SHA-256 `0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d`.
The operator profile pins the actual resulting executable, each ELF dependency
and the original ELF interpreter path. It requires `--ro-bind-fd`; older
bubblewrap versions have no unsafe path-based fallback. Unsupported namespaces,
seccomp, sealed memfd or descriptor-closing prerequisites refuse startup.

## Install and select the profile

The scenario-specific [installer](../../scripts/install-sou62-filesystem-profile.py)
requires Python 3.11+, the pinned Node binary, npm, `ldd`, `readelf`, a reviewed
workspace and a suitable bubblewrap binary. Python 3.12 is the CI interpreter.
It creates a **new** private directory and never edits an existing Agent home,
client configuration or policy. A failed partial installation is not selected;
inspect/remove that owned directory before retrying with a new destination.

```sh
python3 -B scripts/install-sou62-filesystem-profile.py --run \
  --workspace /absolute/reviewed-workspace \
  --destination /absolute/new-private-filesystem-profile \
  --node /absolute/node-v22.22.0/bin/node \
  --npm /absolute/node-v22.22.0/bin/npm \
  --bwrap /absolute/bubblewrap-0.13.1/bwrap
```

The output contains `profile.json`, `registry.json`, `policy.yaml` and
`installation.json`. Select these explicitly in a dedicated enforcing Agent
configuration; the native registry digest is the SHA-256 of its exact bytes:

```yaml
enforce: true
max_record_bytes: 1048576
policy: /absolute/new-private-filesystem-profile/policy.yaml
native:
  registry_path: /absolute/new-private-filesystem-profile/registry.json
  registry_sha256: '<exact registry SHA-256>'
```

Run that Agent daemon with the optional judge disabled, then launch the MCP
entry with the same Agent home and the reviewed workspace as working directory:

```sh
AGENTFW_MCP_SERVER_PROFILE=/absolute/new-private-filesystem-profile/profile.json \
AGENTFW_WORKSPACE=/absolute/reviewed-workspace \
AGENTFW_CLASSIFIER=rule-baseline \
AGENTFW_RULE_BASELINE=/absolute/soup-wall/rule_baseline/rule_baseline.py \
AGENTFW_CLASSIFIER_PYTHON=/absolute/python3 \
/absolute/agentfw mcp --native-admission --id filesystem-readonly-v1 -- \
  /absolute/node-v22.22.0/bin/node \
  /absolute/new-private-filesystem-profile/package/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js \
  /workspace
```

For a persistent Claude Code entry, prefer
[`agentfw onboard --server-profile`](ONBOARDING.md#original-filesystem-and-git-profiles):
it previews and pins these identities, persists only these launch settings,
verifies a useful read and a witnessed refusal through the entry, and can be undone.
Otherwise use this command and environment in the selected Claude Code `mcpServers`
entry. The server command, fixed entry point and `/workspace` argument must
match the installed profile exactly. No package is downloaded during collector
startup. Native receipts retain existing session, schema, original arguments,
policy, exact binding and single-use grant checks. This command uses an isolated
collector by default. The accepted [SOU-63 host binding](MCP_STDIO_ADMISSION.md#authenticated-child-authority-and-host-session-binding-sou-63)
adds shared cross-server/hook context only when a trusted launcher supplies both
the host session and current-instance scoped child authority.

The context-construction seam remains the common `Collector::new` and
`Collector::event` methods in
[`admission.rs`](../../crates/agentfw/src/mcp/admission.rs). Both transport loops
use those methods; the selected loop owns only discovery and per-call state.
The new `mcp_host_call_id` native field binds the original typed host ID to one
selected-profile call receipt; it is neither a shared-session credential nor a
source of provenance. Legacy registries refuse that field. The selected relay
[fault fixtures](../../crates/agentfw/src/mcp/admission/real_server/fault_tests.rs)
exercise the existing event boundary without introducing host context claims.
SOU-63 supplies authenticated host-session construction, hook sharing and context
serialization. The original SOU-62 acceptance below proves the isolated profile;
the separate combined procedure exercises that same selected server with scoped
host identities and hooks. Its report is an additional required gate and does
not replace the original transport, sandbox or actual-host acceptance.

The shipped [scenario policy](../../profiles/mcp/filesystem-readonly-v1/policy.yaml)
hard-denies destructive, side-effecting, network and privilege-changing actions,
including clean sessions without prior taint. It permits benign reads and
refuses detected result injection. This is an explicitly selected scenario
policy. The existing global `agent-default.yaml` has taint-conditioned
`deny-tainted-destructive`; it does **not** universally deny every destructive
operation without taint. Existing user policies, hard Deny/Ask and exact
single-use Ask grants are not replaced or weakened.

## Selected tool/support matrix

The full original schemas, descriptions, annotations, output schemas and
advertised `execution.taskSupport` remain in the pinned tools/list artifact.
Names/descriptions never supply trust or grant effects. The selected registry
adds `mcp_result_profile: sw-mcp/filesystem-readonly/1` only to the nine supported
read-only tools, with `untrusted` result provenance and no egress authority.

| Original advertised tool | Treatment | Original arguments / result |
| --- | --- | --- |
| `read_file` | Conditionally supported; upstream deprecated alias | `path`, optional numeric `head`/`tail`; original text and structured content |
| `read_text_file` | Conditionally supported | `path`, optional numeric `head`/`tail`; original text and structured content |
| `read_multiple_files` | Conditionally supported | `paths` array; original upstream formatted text and structured content |
| `list_directory` | Conditionally supported | `path`; original directory listing |
| `list_directory_with_sizes` | Conditionally supported | `path`, optional `sortBy` enum `name`/`size`; original listing |
| `directory_tree` | Schema supported; current rule baseline returns unknown/Ask, so execution is refused | `path`, optional `excludePatterns`; original tree text |
| `search_files` | Conditionally supported | `path`, `pattern`, optional `excludePatterns`; original upstream glob semantics |
| `get_file_info` | Conditionally supported | `path`; original metadata text |
| `list_allowed_directories` | Conditionally supported | Empty object; original allowed-directory text |
| `read_media_file` | Explicitly unsupported | Original multimedia/resource union is not a text release channel |
| `write_file` | Explicitly unsupported; policy also denies side effects | No child dispatch |
| `edit_file` | Explicitly unsupported; policy also denies side effects | No child dispatch |
| `create_directory` | Explicitly unsupported; policy also denies side effects | No child dispatch |
| `move_file` | Explicitly unsupported; policy also denies destructive actions | No child dispatch |

The current shipped rule baseline permits ordinary calls for eight of those
nine read-only tools. `directory_tree` has no recognized action verb, so its
unknown classification produces Ask and correlated refusal; this profile does
not bypass that decision. The real-server acceptance checks that refusal and a
useful read afterward. A future reviewed classifier may resolve it independently.

Every conditionally supported call must satisfy its pinned schema, workspace
path rules, bounded classification and native call/result admission. The
workspace is mounted read-only independently of those argument checks. Selected `head`/`tail` values must be positive integers from 1 to 65536, and both
cannot be supplied together. Caller arguments are not coerced, defaulted or stripped. Although the original SDK
schemas omit `additionalProperties`, this selected validator deliberately
refuses undeclared fields. Schema metadata (`title`, `description`, `default`,
recognized `$schema`) remains inert. Enum/const, scalar types, required fields,
string lengths and array bounds are enforced. Unsupported JSON Schema keywords,
including `pattern` and `format`, are refused rather than silently ignored;
this pinned tool inventory does not declare those constraints. Upstream
application glob arguments are ordinary inspected strings, not schema keywords.

An individual unsupported tool, invalid arguments or unsupported result gets a
correlated refusal and healthy unrelated calls remain usable. Original upstream
errors are inspected as errors, never mislabeled as useful successful reads.
Successful results require the original output schema and `structuredContent`;
all original text blocks and structured text are inspected before releasing the
entire unchanged original JSON-RPC result envelope.

## Transport and containment bounds

| Boundary | Selected contract |
| --- | --- |
| Pending calls | At most 8 active and 8 queued; independent receipts/result release per call |
| Physical server work | At most 16 outstanding requests including abandoned cancellations; at most 8 forwarded cancellation tombstones per session |
| Request IDs | Original bounded string or safe JSON integer; string `"1"` and integer `1` remain distinct; duplicate/replayed IDs refused |
| Session budget | 1024 request identifiers; 8192 total transport messages |
| Time | 30-second per-call/control bound; a cancellation withdraws delivery and does not attest kernel I/O stopped |
| Frames / discovery | 262144 bytes per client frame and aggregate tools/list; at most 4 distinct pages and 64 tools |
| Results | 262144 decoded UTF-8 bytes per result text; 1048576 bytes per server response frame; see [large results](LARGE_MCP_RESULTS.md) |
| Paths and errors | Exact names, no normalization; refusals name the boundary; see [paths and errors](FILESYSTEM_PATHS_AND_ERRORS.md) |
| Parsing | JSON depth 20 / 16384 nodes; schema depth 8 / 1024 nodes; arguments depth 8 / 4096 nodes |
| Values | At most 256 object properties/array elements; default per decoded argument string 16384 UTF-8 bytes |
| Progress | Correlated bounded token, nonnegative finite monotonic counters, at most 128 per call; content is withheld |
| Cleanup / stderr | Bounded 3-second process cleanup; server stderr is drained and suppressed with a 1 MiB quota |
| Other channels | Server stderr suppressed; logging notifications withheld; callbacks/server requests are not released as content |

Queued cancellation removes that call without execution. In-flight cancellation
returns correlated JSON-RPC `-32800` promptly, withdraws result delivery and
sends a best-effort cancellation while the bounded forwarding budget permits.
The pinned SDK can suppress a response even when `fs.readFile` finishes later;
a bounded abandoned slot accounts for that uncertainty. Later cancellations can
withdraw delivery without forwarding another abort, so a real completion can
reclaim the slot. Late/unknown cancellation does not create a grant, release
late data or kill unrelated useful calls. Cancellation cannot undo a committed
effect. Malformed/unknown responses, duplicate identifiers, daemon loss and
incomplete transport fail closed; overload gets a correlated refusal.

The server sees only `/workspace` read-only, `/mcp-server` read-only, the exact
Node runtime, individually pinned read-only ELF files and private ephemeral
runtime directories. User/PID/mount/network namespaces, no-new-privileges,
capability removal and socket-denying seccomp contain the selected process.
Network namespaces alone would not stop a host Unix socket in the workspace;
seccomp additionally refuses socket/connect/send operations and io_uring setup.
Read-only mounts do not themselves block FIFO/device IPC writes. The selected
filter also denies write-intent `open`/`openat`, `openat2`, `creat` and device
`ioctl` operations. Only `FIONBIO` on stdio descriptors 0–2 is allowed so the
pinned Node/libuv runtime can make its transport pipes nonblocking; this grants
no filesystem write access. Ordinary read-only directory and FIFO reads remain supported. The mandatory
probe calibrates a host FIFO receiver and verifies that the child cannot open
it for writing or deliver any extra bytes.
Unrelated inherited descriptors and environment variables are removed. The
fixed clean environment includes `UV_THREADPOOL_SIZE=16` for the selected
bounded eight-call server workload.

This boundary does not stop the host operator from editing their own reviewed
workspace/runtime files, provide a generic sandbox for arbitrary tools, or
make CPU/memory exhaustion impossible. The operator owns the profile, runtime,
registry and host keys. Resource/result size limits can refuse large useful
reads; a blocked filesystem call can last until session timeout/termination.

## Required acceptance and actual host

The [required workflow](../../.github/workflows/mcp-real-filesystem.yml) builds
the exact source with Rust `1.94.1`, pins the Node archive and bubblewrap source, installs the
original filesystem server from its lock and installs actual Claude Code
`2.1.251` from its separate [host lock](../../profiles/mcp/filesystem-readonly-v1/claude-host/package-lock.json).
The host's native Linux optional-package binary is launched directly; npm
lifecycle scripts are not needed. It does not relax host sysctl/AppArmor policy.

After building `agentfw` and the library test binary, run the original isolated
profile acceptance:

```sh
python3 -B scripts/verify-sou62-real-mcp.py --run \
  --agentfw /absolute/agentfw \
  --node /absolute/node-v22.22.0/bin/node \
  --npm /absolute/node-v22.22.0/bin/npm \
  --bwrap /absolute/bubblewrap-0.13.1/bwrap \
  --claude /absolute/claude-host/node_modules/@anthropic-ai/claude-code-linux-x64/claude \
  --sandbox-test-binary /absolute/agentfw-library-test-binary \
  --expected-commit '<exact clean source commit>' \
  --output /absolute/new-evidence-directory
```

Prerequisites missing, unsupported sandbox operation, zero matching native
tests or a missing actual Claude process are failures with zero skipped cases.
The positive native test is explicitly run even though ordinary cross-platform
unit runs mark it ignored; it must report one passed test and the
`SOU62_SANDBOX_POSITIVE` witness. It independently calibrates TCP, Unix socket and FIFO
receivers, then attempts allowed reads, outside reads/writes, workspace
creation/replacement, inherited-secret/environment/descriptor access and egress
from an adversarial Node program through the same sandbox construction.
That program is a test-only seam; production always launches the fixed original
filesystem entry point.

The real-server driver independently calibrates original reads and an owned
original mutator before protection. It then checks unchanged original discovery
and useful result bytes, all eight ordinary read-only tools, preserved
`directory_tree` classifier Ask, eight blocked real FIFO reads plus eight queued calls,
queued/in-flight/late/unknown cancellation, overload refusal, per-call ID/content correlation,
unsupported tools, invalid enum/type/missing/extra arguments, typed IDs and
useful same-session continuations and actual daemon-loss refusal before FIFO execution. Parent-side FIFO reader/writer handshakes,
workspace inode/content snapshots, client raw bytes and an owned receiver are
independent witnesses. It also checks the actual installed policy hard Denies a
declared destructive native operation, a file mutation and an owned HTTP POST
proposal in clean sessions with no prior taint. The POST proposal uses guarded
`curl --data`, which the existing classifier treats as outbound `network` data;
plain `WebFetch` is classified as read-only retrieval and is not mislabeled a
policy Network Deny. The independent receiver is calibrated before the denied
proposal, then must receive zero bytes from protected attempts. These are concrete synthetic files and local receivers only.

The actual Claude Code run connects to that installed server, receives a useful
read, observes a refused write and completes another useful read. An owned
scripted local Messages provider records the host's original tool proposals and
returned tool results. Pinned Claude Code 2.1.251 presents the original
`structuredContent` as a JSON string to the provider, rather than repeating the
plain MCP text block. The host check strictly parses that string as exactly
`{"content": <exact owned UTF-8 text>}`; it rejects duplicate/extra fields,
changed content and trailing instructions. It strips only the observed host
`total_tokens` reminder, preserves the full original provider result and records
`structured_json` plus exact content/rendering hashes. The MCP wire result
remains byte-for-byte unchanged and separately verified. This proves host
interoperability separately; no live
model efficacy, paid provider or held-out/private dataset is measured.

`report.json` records exact source/tree, Agent/test/Claude/runtime/package/profile
identities, pass/fail/skip counts, transport events, independent witnesses and
cleanup. Raw owned transcripts/logs accompany it. Failed/incomplete reports are
retained. Only accepted execution evidence supports support claims; the final
PR's required workflow and retained artifact identify the tested source.


## Combined SOU-62 and SOU-63 smoke

The [combined driver](../../scripts/verify-sou62-sou63-combined.py) is a separate
required step in the same Linux workflow. It reuses the exact pinned original
server, Node, bubblewrap, Agent and Claude Code host. The original SOU-62 driver
and its established checks still run unchanged.

```sh
python3 -B scripts/verify-sou62-sou63-combined.py --run \
  --agentfw /absolute/agentfw \
  --node /absolute/node-v22.22.0/bin/node \
  --npm /absolute/node-v22.22.0/bin/npm \
  --bwrap /absolute/bubblewrap-0.13.1/bwrap \
  --claude /absolute/claude-host/node_modules/@anthropic-ai/claude-code-linux-x64/claude \
  --sandbox-test-binary /absolute/agentfw-library-test-binary \
  --expected-commit '<exact clean source commit>' \
  --output /absolute/new-combined-evidence-directory
```

This procedure requires two original server instances with scoped grants tied
to the running daemon instance and the same host-session UUID. It checks a
clean useful read, shared MCP and authenticated-hook provenance, taint-conditioned
refusal with an independent absent FIFO-reader witness, and useful continuation.
The actual pinned Claude Code process connects both servers under that scoped
session using the owned scripted provider. It does not measure live-model
protection efficacy.

The combined proof uses a separate owned scenario policy to make the shared
taint disposition observable. A refusal from the profile's ordinary unsupported
write handling alone is not proof that provenance crossed a session boundary.
The driver retains source and binary identities, sanitized binding digests,
policy identity, exact owned call/result witnesses and cleanup outcomes. It
never publishes child-authority tokens. Missing prerequisites, missing proof,
failed cleanup or a missing actual host are failures; there is no skip or
unsandboxed fallback. The workflow retains incomplete reports as well as logs.
A support claim requires a passing combined report for the exact candidate;
adding the procedure is not itself runtime acceptance.

## Explicit multi-root profile

`filesystem-multi-root-readonly-v1` (`sw-mcp/filesystem-multi-root-readonly/1`)
is a separate opt-in profile for two to four existing directories. It uses the
same pinned original server, schemas, dependency lock, classifier and policy.
The single-root default remains a separate installation. Git linked worktrees
are not required.

Select stable lowercase IDs explicitly. Each ID maps to `/workspace/<ID>` inside
the original server; host paths and relative paths are refused by this profile.
The common parent and any unselected sibling are never mounted. IDs are sorted,
unique and case-sensitive, with syntax `[a-z][a-z0-9_-]{0,31}`. Every declared
scope is `read-only`; changing the set requires a new manifest and generation.

```sh
# The parent of this new manifest must already be private and owned (0700).
agentfw pilot --home /absolute/agent-home filesystem-roots \
  --root alpha=/absolute/project-alpha --root beta=/absolute/project-beta \
  --output /absolute/private/roots.json
# Preview above writes nothing. Repeat with --apply to create a fresh 0600 file.
agentfw pilot --home /absolute/agent-home filesystem-roots \
  --root alpha=/absolute/project-alpha --root beta=/absolute/project-beta \
  --output /absolute/private/roots.json --apply
```

Use the [installed front door](PILOT_INSTALLED_FRONT_DOOR.md) with its explicit
pinned runtime inputs. Add `--filesystem-roots-binding /absolute/private/roots.json`,
`--filesystem-workspace /absolute/project-alpha` (the first sorted ID), and the
separately selected ordinary `--git-workspace /absolute/reviewed-repository` to
`preview` and `prepare --apply`. Keep the prefix, manifest, caches, runtimes,
archives and run-state directory outside every selected root. Preparation is
configuration, not observed protection. `status` becomes `observed-live` only
when that exact selection's enforcing daemon and protected host are witnessed.

Each root's canonical path, device/inode/owner and declared scope are retained
in the manifest, profile, receipt and versioned prepared selection. Native
startup independently opens every component without following links, pins all
root descriptors and mounts each root read-only at its own ID. Before admission,
after approval and before result delivery, the adapter rechecks that same set.
Topology changes permanently withdraw the live set; restoring a directory does
not revive its authority. File contents remain mutable, untrusted input and
still pass existing result inspection.

| Original selected tools | Complete resource extraction |
| --- | --- |
| `read_file`, `read_text_file`, `get_file_info` | Required `path`, including its explicit root ID |
| `list_directory`, `list_directory_with_sizes` | Required `path`; `sortBy` defaults to `name` and grants no resource |
| `directory_tree` | Required `path`; default `excludePatterns: []` only filters that root |
| `search_files` | Required `path`; `pattern` and default `excludePatterns: []` are literal filters, never root selectors |
| `read_multiple_files` | Every member of required `paths`, at most 64; any invalid member refuses the entire call before execution |
| `list_allowed_directories` | Empty arguments bind the complete selected set; no ambient default directory |
| Writes, edits, directory creation, moves, media reads | Remain unsupported; neither `path` nor `source`/`destination` can grant execution |

Argument bytes are not rewritten. Existing input-schema and line/byte limits,
classification, independent admission and original result delivery remain in
force. Missing paths and ordinary file/directory type errors can reach the
original server and retain its errors. A native root/custody refusal is a
correlated `-32602`, with no partially released first resource; a later valid
call remains possible unless the root set itself was withdrawn. In particular,
`/workspace` is not a selected resource, and a symlink from one selected root
to another cannot silently change a call's root binding.

Support is native Ubuntu 24.04 x86-64 with the existing descriptor-consuming
bubblewrap boundary. Topology observation requires local ext4, XFS, Btrfs or tmpfs; remote, FUSE,
overlay and other filesystems refuse even if watch registration succeeds.
All entries must be owned, readable, regular files or
directories without shared write. Symlinks, hardlinked files, special files,
nested mounts, duplicate/aliased/overlapping roots, replacement, missing roots
and mutable topology refuse conservatively. The complete set is bounded to
32768 entries, 128 directories and depth 32. WSL, Windows and macOS execution
are not qualified by this opt-in profile. Existing classifier refusals (such
as `directory_tree`) and result false positives are unchanged and must be
reported separately from execution or root-binding failures.

To update, explicitly create a new manifest and use `prepare --apply --rebuild`
(or a new prefix). Retain the previous prefix and manifest for rollback; select
that prefix explicitly and verify `status` before starting a fresh run. A stale
manifest, changed scope, substituted profile or old single-root receipt cannot
adopt extra roots. Do not edit a selected profile or reuse a live withdrawn set.

Focused qualification uses `mcp-real-filesystem.yml` with exactly
`filesystem_roots_only=true`, `native_preparation_only=true`, stability off and
all other optional modes off/empty. It runs native binding regressions, builds
an exact-source installed component outside the checkout, and exercises owned
read/list/search, both-root arrays, whole-call refusals, an unselected canary,
single-root sibling behavior, unchanged sources and process cleanup through
the pinned original servers and genuine host with a local scripted provider.
The fixed case inventory retains failed attempts. It is not a shared Ready,
security or final admission cycle; those remain TL-owned.

The selected roots do not grant policy approval. Existing provenance rules still
apply: the installed pilot proof policy asks before reading a path learned from
an MCP result. The focused multi-root qualification keeps that explicit Ask
control, then checks healthy continuation with a separately supplied owned path.
It does not erase taint or weaken the installed policy to obtain a pass.
