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
