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

Use this command and environment in the selected Claude Code `mcpServers`
entry. The server command, fixed entry point and `/workspace` argument must
match the installed profile exactly. No package is downloaded during collector
startup. Native receipts retain existing session, schema, original arguments,
policy, exact binding and single-use grant checks. This task does not install a
shared cross-server/hook context; that is SOU-63.

The context-construction seam remains the common `Collector::new` and
`Collector::event` methods in
[`admission.rs`](../../crates/agentfw/src/mcp/admission.rs). Both transport loops
use those methods; the selected loop owns only discovery and per-call state.
The new `mcp_host_call_id` native field binds the original typed host ID to one
selected-profile call receipt; it is neither a shared-session credential nor a
source of provenance. Legacy registries refuse that field. The selected relay
[fault fixtures](../../crates/agentfw/src/mcp/admission/real_server/fault_tests.rs)
exercise the existing event boundary without introducing host context claims.
SOU-63 owns authenticated host-session construction, hook sharing and context
serialization. A combined host smoke test must follow acceptance of both
increments; the current acceptance proves an isolated collector session.

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
| Frames / discovery | 262144 bytes per frame and aggregate tools/list; at most 4 distinct pages and 64 tools |
| Parsing | JSON depth 20 / 16384 nodes; schema depth 8 / 1024 nodes; arguments depth 8 / 4096 nodes |
| Values | At most 256 object properties/array elements; default per decoded string 16384 UTF-8 bytes |
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
filter also denies write-intent `open`/`openat`, `openat2`, `creat` and `ioctl`;
ordinary read-only directory and FIFO reads remain supported. The mandatory
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

After building `agentfw` and the library test binary, run one command:

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
destructive operation and network retrieval in clean sessions with no prior
taint. These are concrete synthetic files and local receivers only.

The actual Claude Code run connects to that installed server, receives a useful
read, observes a refused write and completes another useful read. An owned
scripted local Messages provider records the host's original tool proposals and
returned tool results. This proves host interoperability separately; no live
model efficacy, paid provider or held-out/private dataset is measured.

`report.json` records exact source/tree, Agent/test/Claude/runtime/package/profile
identities, pass/fail/skip counts, transport events, independent witnesses and
cleanup. Raw owned transcripts/logs accompany it. Failed/incomplete reports are
retained. Only accepted execution evidence supports support claims; the final
PR's required workflow and retained artifact identify the tested source.
