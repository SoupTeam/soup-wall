# Read-only Git MCP profile (SOU-68)

This opt-in Linux x86-64 profile runs the original `mcp-server-git` 2026.10.10
stdio package with MCP Python SDK 1.29.0. It extends the existing selected-server
relay and bubblewrap boundary. It does not replace the transport, classifier,
policy engine, original discovery, schemas, tool names or result/error frames.

Aggregate resource limits are a separate explicit opt-in. Without
`AGENTFW_MCP_LINUX_BUDGET` this compatibility profile is unbudgeted. See
[Linux MCP resource budgets](MCP_LINUX_RESOURCE_BUDGETS.md) for the versioned
configuration, delegated cgroup-v2 prerequisites and fail-closed launch.

[Owned Linux crash supervision](MCP_LINUX_CRASH_SUPERVISION.md) also covers this
selected launch. It preserves the original Git process and sandbox while adding
collector-loss ownership; process cleanup does not imply immediate native session
retirement.

**Acceptance gate:** full Linux acceptance and independent review are required.
Baubek agreed to the narrow Git rule on October 17.
The opt-in [Git classifier snapshot](../../rule_baseline/git_readonly_v1/rule_baseline.py)
adds only six exact original schemas and bounded argument forms below. It fixes
unknown status/log/diff and the generic rule's false write for `context_lines`.
The frozen research baseline and filesystem profile remain unchanged. No global
status/log/diff vocabulary is added. Unsupported Git forms retain unknown and
any recognized risky evidence; policy still determines Ask/refusal. Schema
recognition is semantic evidence, not authenticated server identity. Registry,
runtime pins, argument validation, policy and sandbox remain independent gates.
Select this snapshot with `AGENTFW_RULE_BASELINE` and `AGENTFW_CLASSIFIER=rule-baseline`;
the acceptance driver records its SHA-256 and selects it explicitly.

## Original discovery and bounded operations

The [identity](../../profiles/mcp/git-readonly-v1/upstream-identity.json),
[original initialization](../../profiles/mcp/git-readonly-v1/upstream-initialize.json),
[original tool discovery](../../profiles/mcp/git-readonly-v1/upstream-tools-list.json)
and [hash-locked dependencies](../../profiles/mcp/git-readonly-v1/requirements.lock)
are committed. Every advertised original tool remains visible. Protected calls
must use exactly `repo_path: "/workspace"`; extra fields are refused.

| Original tool | Selected-profile support and bounds |
| --- | --- |
| `git_status` | Conditional read; no other arguments |
| `git_log` | Conditional read; optional integer `max_count` 1-20; timestamp filters unsupported |
| `git_diff` | Conditional read; required `target` is `HEAD` or full 40-digit hexadecimal SHA-1; optional integer `context_lines` 0-20 |
| `git_diff_staged` | Conditional read; optional integer `context_lines` 0-20 |
| `git_diff_unstaged` | Conditional read; optional integer `context_lines` 0-20 |
| `git_show` | Conditional read; required `revision` is `HEAD` or full 40-digit hexadecimal SHA-1 |
| `git_commit` | Unsupported; refused before dispatch |
| `git_add` | Unsupported; refused before dispatch |
| `git_reset` | Unsupported; refused before dispatch |
| `git_create_branch` | Unsupported; refused before dispatch |
| `git_checkout` | Unsupported; refused before dispatch |
| `git_branch` | Unsupported in this bounded increment; refused before dispatch |

Conditional means that discovery, exact registry/schema, bounded arguments,
classification, policy and invocation authorization must all succeed. Unknown
tools, clean, remote and credential operations have no admitted execution path.
Native text-only Git results are inspected as untrusted content before release;
unexpected structured output, metadata, binary blocks or envelopes are rejected.
The private Git policy refuses Medium/High injection findings. A bare 40-digit
Git object ID triggers the detector's Low long-token heuristic and is not alone
an instruction. No result bytes are stripped or trusted to avoid inspection.
Instruction override and prompt-exfiltration controls remain refused, followed
by a useful hash-bearing read. The private policy preserves the shipped Agent
rules and strengthens inspected-result injection to Medium/Deny. Both policies
pass the unchanged 40-session general corpus (19 attacks and 21 benign sessions).
Read-only Git authority is independently bounded by profile/registry admission,
argument validation and the mandatory sandbox; the policy does not grant a
mutating, remote or unsupported tool an execution path. Installation never
replaces an existing user's policy.
The existing filesystem profile continues to require its original structured
result contract. Cancellation never claims to roll back dispatched work.

## Repository and runtime boundary

Use only an owned synthetic, standalone, non-bare SHA-1 repository. Startup
refuses worktrees, submodules, shallow metadata, alternates, config includes,
remote/helper/filter/diff settings, active hooks, symlinks and special files.
The small core configuration allowlist permits ordinary repository-format,
bare=false, file-mode and case settings. Inspection is bounded to 8 KiB of
configuration, 32 directory levels and 32,768 entries. Unsupported repositories
are not rewritten or normalized by Agent. Keep the source repository quiescent
while testing; the read-only mount does not freeze changes by its host owner.

The exact CPython archive, Git version/source, wheel graph, binary digests,
library files, installed package tree and bubblewrap executable are recorded.
The repository and runtime mounts are read-only. The child has no ambient home,
credentials, Git global/system config, inherited descriptors or network access.
The existing seccomp filter denies socket creation and unsafe device ioctls.
The Git branch permits generic nonblocking FIONBIO and destination-free sends
on anonymous socketpairs for Python's worker-thread wakeups. Addressed sends,
socket creation/connect, inherited sockets and device-specific ioctls remain
denied; kernel-backed positive and negative probes cover this distinction.
Git unconditionally opens `/dev/null` read/write at startup. Its separately
pinned `agentfw-git-sandbox` launcher therefore installs mandatory Landlock ABI
3 mutation restrictions inside the namespace before executing original Python:
only the verified `/dev/null` character device can be opened for writing.
File creation, truncation, removal, rename and all other writable opens remain
denied, including `/tmp` and named FIFOs. Missing Landlock fails closed. The
filesystem profile retains its original blanket seccomp writable-open denial.
Hooks, fsmonitor, external helper path, terminal prompting and optional index
locking are disabled explicitly. Git protocols are disabled. No shell or remote
helper is installed in the sandbox. Missing Linux/bubblewrap features fail
closed; Windows is not a positive isolation result.

## Prepare a private installation

Preparation downloads are opt-in; protected startup is offline. Supply a
separately verified Git 2.51.2 executable and bubblewrap 0.13.1 with
`--ro-bind-fd`, Linux Landlock ABI >= 3, and the `agentfw-git-sandbox` binary built
from the same reviewed source. The [Linux workflow](../../.github/workflows/mcp-real-git.yml)
builds these from pinned official sources without changing host security policy.

```sh
python3 -B scripts/install-sou68-git-profile.py --run \
  --destination /absolute/new-private-profile \
  --workspace /absolute/owned-synthetic-repository \
  --git /absolute/git --git-sha256 VERIFIED_GIT_BINARY_SHA256 \
  --bwrap /absolute/bwrap --git-launcher /absolute/agentfw-git-sandbox
```

The destination must be new and outside the repository. The installer creates
private profile/registry/policy files and an installation report. It never edits
an existing Agent home or client configuration. Failed partial installations
remain for diagnosis and must not be treated as usable profiles.

To connect the installed profile to a Claude Code entry persistently, use
[`agentfw onboard --server-profile`](ONBOARDING.md#original-filesystem-and-git-profiles)
with the Git classifier snapshot above. It verifies a `git_status` read, a refused
`git_create_branch` with an unchanged repository witness and a continuation through
the connected entry, and undo restores the original entry.

## Exact-source acceptance

Build the current Agent, its private Git launcher (`cargo build --locked -p
agentfw --bins`) and library-test executable, then run:

```sh
python3 -B scripts/verify-sou68-real-mcp.py --run \
  --agentfw /absolute/agentfw --git /absolute/git \
  --git-sha256 VERIFIED_GIT_BINARY_SHA256 --bwrap /absolute/bwrap \
  --git-launcher /absolute/agentfw-git-sandbox \
  --sandbox-test-binary /absolute/agentfw-library-test-binary \
  --expected-commit FULL_CLEAN_COMMIT --output /absolute/new-evidence-directory
```

The driver creates its own repository and Agent home. Unwrapped upstream reads
and a real index mutation calibrate behavior. Protected reads compare original
results; rejected operations have useful follow-ups and an unchanged repository
snapshot. A verified owned server PID is briefly stopped to make overlap and
queued/inflight cancellation deterministic, then resumed. Sixteen consecutive
rounds use fresh request IDs within the same original process/session, requiring
two correlated withdrawals and fourteen useful peer replies per round. The
inflight target must actually reach the child wire; a count of pending admission
work is insufficient. Git cancellations withdraw delivery locally and drain the
original response; no abort notification reaches this pinned server. Physical
slots remain occupied until a response arrives, with the original deadline and
sixteen-request limit unchanged. Partial replies and the failed round
remain in failed reports; a previous successful round cannot mask a later loss.
Daemon-loss admission
and process cleanup are checked. A separate real Python/Git sandbox probe checks
readability, denied writes, outside-file isolation, inherited descriptors,
environment, separate namespaces and a calibrated TCP receiver. That probe is
separate from policy refusal evidence.

Reports contain only synthetic data and exact source/runtime identities. A
failed prerequisite, missing marker or unknown classification fails acceptance;
it is never a successful skip. Full independent denied-execution/result-injection
witness coverage and the positive Linux run remain required before completion.
Existing filesystem acceptance runs alongside this profile in CI. Neither this
profile nor its synthetic fixture constitutes general Git repository support.

## Failed-run diagnostics

Selected-server stderr remains withheld from the MCP host and is not written as
a raw log. Operator diagnostics retain its byte count, streaming SHA-256, EOF
completeness and a finite set of exception markers. Markers are untrusted server
observations, not authenticated exception reports, policy inputs or permission
to release a result. Arbitrary exception text, paths and payloads never appear
in that summary. The existing 1 MiB stderr quota is unchanged.

The private owner retains the first observed sandbox-wrapper exit code or signal
and whether it preceded the quiesce acknowledgment. Cleanup cannot replace that
witness with its own termination status or erase an earlier failure. This is a
wrapper status, not the original Python process's exit code or exception. The
bounded acceptance summary also preserves fixed owner failure codes. The
relay-error summary is recorded before stdin shutdown, because an ensuing
wrapper failure can otherwise win the owner select while shutdown is pending.
Only fixed full-string error codes are retained; arbitrary contexts and suffixes
remain withheld. A later
successful run does not explain or relabel an earlier failed overlap/cancellation
run; preserve the original artifact and qualify the exact candidate separately.

## Pinned SDK cancellation compatibility

The original `mcp-server-git 2026.10.10` uses `mcp 1.29.0` and `anyio 4.15.1`
on pinned Python 3.11.14. These versions satisfy their declared dependency
constraints. Under response backpressure, however, `RequestResponder.__exit__`
discards the Boolean result of `CancelScope.__exit__`. Cancellation escapes the
request task, cancels sibling handlers and the session receive loop, and leaves
`stdio_server.stdin_reader` sending into a closed peer (`BrokenResourceError`
inside `ExceptionGroup`, exit 1). A controlled original-server reproduction also
fails on Python 3.14; this is not a Windows Job-budget or cleanup failure.

For this exact Git profile the relay therefore uses local withdrawal and bounded
draining from the first cancellation, including deadline withdrawal. It does not
patch the original package, suppress server exceptions, restart the session or
release a late cancelled result. Native grants are reclaimed immediately; the
physical request retains its slot and original deadline until it completes. A
nonresponding withdrawn request still terminates the transport at that deadline.
Filesystem's existing finite best-effort wire cancellation remains unchanged.
See the [upstream cancellation report](https://github.com/modelcontextprotocol/python-sdk/issues/2610).


## Opt-in strict shallow repositories (SOU-147)

`sw-mcp/git-readonly-shallow/1` is a separate Linux x86-64 profile for a prepared,
owned standalone repository that satisfies the existing strict repository
contract and has local shallow boundary metadata. The default v1 profile still
refuses `.git/shallow`. This selection does not enable named-reference or
per-file syntax. Unqualified combined identities and simultaneous installer
options refuse; none falls back to another profile.

```sh
python3 scripts/install-sou68-git-profile.py --run --shallow-repository \
  --destination /absolute/private/git-shallow \
  --workspace /absolute/owned/strict-shallow-project --git /absolute/pinned/git \
  --git-sha256 REVIEWED_GIT_SHA256 --bwrap /absolute/pinned/bwrap \
  --git-launcher /absolute/pinned/agentfw-git-sandbox
```

Use that installation's `profile.json` as `AGENTFW_MCP_SERVER_PROFILE`, and its
`registry.json` and digest in the enforcing daemon. Keep the accepted
`rule_baseline/git_readonly_v1/rule_baseline.py` classifier. The original tool
names, schemas and arguments remain unchanged. `git_show`/`git_diff` still accept
only HEAD or a full local SHA; status/log/staged/unstaged diff keep their accepted
bounds. No fetch, deepen, repair, helper or second Git executor is introduced.
A missing ancestor stays missing and yields an original error or correlated
explicit refusal; a later safe local read remains usable.

Existing strict **core-only configuration and heads/tags metadata** restrictions
remain. General clone remote/branch configuration, remote-reference layouts,
alternates, worktrees, submodules, attributes, active hooks and promisor/partial
clones are unsupported. A normal clone carrying those features is refused; the
installer never strips user configuration or changes source data. This task's
local clone fixtures normalize only their newly generated owned metadata to
that accepted strict layout. Do not mistake that fixture preparation for an
automatic conversion command for an existing project.

A present boundary file must contain 1–64 unique lowercase SHA-1 IDs, each an
exact 40-byte line ending in LF, within 2624 bytes. Every boundary must be an
available local commit. Blank/duplicate/CRLF/NUL/truncated/oversized records,
links, hard links, shared writable or unowned inputs and unsupported object
formats refuse before starting the original server. An ordinary repository with
no boundary file is also supported as a control; no boundary is synthesized.

The new view reuses same-FD read leases and sealed metadata images. It captures
at most 128 loose or packed objects, each bounded to 262144 bytes, within a
16 MiB total image and existing process/descriptor/resource limits. Pack v2,
index v2 and optional reverse-index v1 have checked count, SHA-1 identity,
checksums, offsets, fanout/order and CRC framing. Delta records, auxiliary pack
formats, large-offset indexes and duplicate loose/packed storage are explicitly
unsupported in this finite profile. The original pinned Git remains the only
executor. See [Git's pack specification](https://git-scm.com/docs/gitformat-pack).

Read leases reject existing writers/mappings and permanently withdraw a view on
a later write-open. Directory watches also cover replacement/removal. The
collector checks withdrawal before admission, before dispatch after Ask and
before result release. Restoring metadata bytes never reactivates a withdrawn
session. Current policy/classifier admission, exact single-use Ask, result
inspection, cancellation, isolation and cleanup remain mandatory; the accepted
five-second first-pending observation and broker/runtime budgets are unchanged.

The pinned upstream GitPython `git_show` implementation compares a commit with
its parent. In a depth-one clone it can therefore return its own `fatal: bad
object` error for HEAD, despite status/log/working-tree diff remaining useful.
The protected server preserves that original error and permits a later safe
read. It never fetches the parent or substitutes another implementation.
Qualification retains this depth-one case and separately checks successful
byte-identical show output from a shallow fixture with a local parent. Original
error strings can contain different executable paths outside/inside the fixed
namespace; both raw errors and hashes are retained without rewriting output.

Run **Real Git MCP profile** on the exact source branch and select **Run only
opt-in SOU-147 shallow Git acceptance**. The retained
`sou68-real-git-mcp-evidence` artifact includes ordinary/shallow original-server
byte comparisons, missing-ancestor calibration and continuation, malformed and
unsafe metadata refusals, boundary and pack mapped write/restore, in-flight
withdrawal, Ask/replay/cancel/Deny, calibrated helper/outside/receiver witnesses,
source identity and process cleanup. Missing native prerequisites fail rather
than becoming passing skips. Preserve failed/incomplete attempts.


## Opt-in per-file revision reads (SOU-146)

The default `sw-mcp/git-readonly/1` contract remains unchanged. An operator may
prepare a **separate installation** with `--file-revisions` to select
`sw-mcp/git-readonly-file-revisions/1`. Use the same pinned Linux x86-64 Git,
Python, bubblewrap and Agent launcher as above; `--ro-bind-data` support is
required. Preparation never changes the source repository.

```sh
python3 scripts/install-sou68-git-profile.py --run --file-revisions \
  --destination /absolute/private/git-file-revisions \
  --workspace /absolute/owned/project --git /absolute/pinned/git \
  --git-sha256 REVIEWED_GIT_SHA256 --bwrap /absolute/pinned/bwrap \
  --git-launcher /absolute/pinned/agentfw-git-sandbox
```

Install that directory's `registry.json` and its digest in the enforcing daemon,
and select its `profile.json` with `AGENTFW_MCP_SERVER_PROFILE`. Explicitly select
`rule_baseline/git_readonly_file_revisions_v1/rule_baseline.py` with
`AGENTFW_RULE_BASELINE` and `AGENTFW_CLASSIFIER=rule-baseline`. Do not reuse another
profile's registry or classifier as an implicit fallback. This development
extension is not a combined local-reference, shallow or installed-pilot preset.
Unknown combined profile identities refuse at startup; named refs and shallow
repositories remain unsupported by this selection.

To execute whole-commit and diff reads with daemon-owned formatter attribution,
explicitly configure `native.git_execution.profile_path` to this installation's
absolute `profile.json`, `profile_sha256` to its SHA-256, and `server_id` to the
collector's exact server ID. Keep its workspace identity pinned and use the
authenticated host/child-authority and liveness configuration documented for
daemon Git execution. Execution accepts exactly the BASE and file-revision
formats; it does not enable local-reference or shallow combinations. The worker
retains the same revision View for its sealed mount and typed object facts and
rechecks its path proof immediately before writing the original request. The
collector independently retains its original View throughout a pending Ask.
File payloads (`HEAD:path` or full-SHA plus path) receive full baseline result
inspection, including payloads that look like commit headers. No result text or
serialized receipt can manufacture formatter origin. Missing execution opt-in
preserves the original inspection route and may withhold a whole-commit result.

The original upstream `git_show` name, schema and arguments are preserved. Its
`revision` accepts `HEAD:notes.txt` or `FULL_40_HEX_COMMIT_SHA:docs/機能 notes.txt`.
The path is a literal UTF-8 relative path: at most 1024 bytes, 16 components and
255 bytes per component. ASCII letters, digits, dot, underscore, dash and spaces
plus bounded Unicode are supported. Empty components, dot/dot-dot, absolute
paths, option-like components, NUL/control/format characters, revision magic,
backslashes, colons, wildcards and Git metadata/attribute components refuse.
`git_diff` retains its original HEAD/full-SHA grammar. A per-file target must
resolve through a commit and trees to a regular blob; trees, tags, symlinks,
gitlinks, missing objects and missing paths receive a correlated refusal.

This profile captures at most 128 loose objects, each at most 262144 compressed
and inflated bytes, within a 16 MiB total image. Packed object stores refuse;
packed reference metadata may resolve HEAD but grants no named-reference
capability. Existing ownership, configuration, hook, alternate, submodule,
standalone-repository and resource constraints still apply. No helper, Git
revision expansion, fetch, repair or network operation is used to validate a
path. The original server executes the original request on sealed metadata and
object images and its result passes the existing inspection gate unchanged.

Retained same-FD read leases reject pre-existing writers/mappings and permanently
withdraw on a later writer. Directory watches cover replacement, creation and
removal. Source validity is checked before admission, after approval before
dispatch, and before result release. A write/restore does not revive a session;
start a new protected session after restoring the owned source. Each call still
requires current classifier/policy admission and a separate single-use Ask when
configured. The first-pending observation remains five seconds including cold
preparation; broker TTLs and resource budgets are unchanged.

The ordinary required Ready Git job runs this qualifier alongside the separately
selected local-reference and shallow qualifiers. For a focused reproduction, run
the **Real Git MCP profile** workflow on the exact branch and select
**Run only opt-in SOU-146 per-file revision acceptance**. Its retained
`sou68-real-git-mcp-evidence` artifact includes `sou146-acceptance/report.json`,
source identity, original/protected response hashes, grammar/type refusals,
source replacement and mapped write/restore, Ask/replay/cancel/Deny, actual
in-flight source withdrawal, calibrated helper/outside/receiver controls and
independent process cleanup. A missing Linux prerequisite is a failure, never a
passing skip. Preserve incomplete and failed reports alongside a later pass.
The report distinguishes collector and verified-worker confinement probes,
actual daemon-worker preparation/stop barriers, and a private libtest barrier
after the real original `tools/call` write. The latter proves source restoration
cannot create a Completion after withdrawal; it adds no production hook. A known
withdrawn collector View receives its correlated refusal before any worker error
propagates. Incomplete execution still retires the uncertain old session; a fresh
protected session must pass after restoring the owned source.
