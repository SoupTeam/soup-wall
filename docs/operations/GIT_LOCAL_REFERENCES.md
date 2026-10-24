# Explicit local Git branch and tag reads

SOU-137 adds the opt-in `sw-mcp/git-readonly-local-refs/1` profile for the
original pinned Git MCP server. Select its matching
`git-readonly-local-refs-v1` registry and `git_readonly_local_refs_v1`
classifier together. The default `sw-mcp/git-readonly/1` profile and its
classifier retain their HEAD/full-SHA-only contract.

This increment covers Phase 1 invocation semantics, Phase 2 containment and
Phase 5 useful inspection of a prepared standalone repository. Its baseline is
reviewed main `a2fb3bf6ed95f126a6522ad569f34240fc0f226a`. It does not depend on
the unmerged ordinary-clone, result-attribution, cgroup-membership or terminal
Ask UI changes (SOU-107, SOU-109, SOU-136 and SOU-135).

## Invocation contract

The only newly supported arguments are `git_show.revision` and `git_diff.target`
containing a complete literal `refs/heads/...` or `refs/tags/...`. Requests keep
the original schemas and argument keys, with `repo_path` exactly `/workspace`.
Original MCP initialization, discovery and successful response bytes are retained;
there is no shell translation or substitution with another Git operation.

Examples:

```json
{"name":"git_show","arguments":{"repo_path":"/workspace","revision":"refs/heads/feature/nested"}}
{"name":"git_diff","arguments":{"repo_path":"/workspace","target":"refs/tags/releases/annotated","context_lines":3}}
{"name":"git_show","arguments":{"repo_path":"/workspace","revision":"refs/heads/機能/読み取り"}}
```

Names are case-sensitive, unchanged UTF-8, at most 255 bytes including the
prefix, with one to eight nonempty suffix components. ASCII letters, digits,
`-`, `_`, `.`, `@`, `+` and component separators are allowed. Non-ASCII scalar
values from U+00A1 are allowed except U+1680, U+180E, U+2000–200F,
U+2028–202F, U+205F–206F, U+3000, U+FEFF and U+E0000–E0FFF.
No component may start with `.` or `-`, end with `.` or `.lock`, or contain
`..` or `@{`. Names are not normalized; composed and decomposed Unicode remain
different names. The [reviewed fixture](../../profiles/mcp/git-readonly-local-refs-v1/contract.json)
is shared by Rust and classifier tests.

Refused examples include `main`, `refs/remotes/origin/main`, `--help`,
`HEAD~1`, `HEAD:file`, `refs/heads/main@{0}`, wildcards, whitespace, empty
components, option-like components and overlong/deep names. No fetch, clone,
push, checkout, ref mutation or helper is added. HEAD and complete 40-digit
SHA-1 arguments keep their existing behavior and result inspection.

## Repository and session protection

All existing [Git profile restrictions](GIT_MCP_PROFILE.md) still apply:
Linux x86-64, the pinned original server/runtime, supported core-only config,
one owned prepared standalone repository, no worktree indirection, submodules,
active hooks, attributes, alternates, external helpers or remotes. This profile
additionally requires an owned local ext4, XFS, Btrfs or tmpfs metadata filesystem
and no group/other writable metadata or hard-linked metadata files. Network,
FUSE and overlay metadata filesystems are unsupported.

Up to 64 local refs are captured. A supported branch resolves to a commit; a
tag resolves to a commit directly or through at most eight annotated tag objects.
The commit/tag target objects must be available as bounded loose SHA-1 objects
(at most 256 KiB each). Their hashes and object types are checked without invoking
Git. Packed ref names are supported with loose target objects; packed-only target
objects are unsupported. A usable commit HEAD is required at startup. Blob,
tree, symbolic, absent or otherwise unsupported named targets are refused before
original-server dispatch. A correlated JSON-RPC error identifies the local-ref
boundary, and subsequent supported calls remain useful.

The namespace receives sealed copies of config, HEAD, index and refs, plus the
verified target objects. Its `.git` image is read-only. Object alternates are
masked with an empty read-only directory. The original worktree remains bounded
to the selected read-only workspace. Capture is limited to 16 MiB, 128 target
objects, 128 metadata directories and 256 watches; index and packed-ref input
limits are 8 MiB and 64 KiB respectively. Unsupported or changing capture refuses
startup. The ordinary sandbox resource budgets are retained.

Every captured metadata/target-object file additionally requires a retained
kernel read lease on the same opened inode, using the accepted local-file proof
primitive. A pre-existing writable FD or shared writable mapping makes that
source unsupported before startup; missing lease support/capacity fails closed.
A later write-open breaks the proof permanently before its writer is promptly
released. The view never reacquires a broken lease. This covers mapped writes
that inotify does not report, including write/restore between validation calls.
Lease descriptors remain private to the collector and are never mounted or
inherited by the server. Existing per-owner/process proof budgets are unchanged.

Kernel directory watches also withdraw the session on writes, replacement or
rename in captured reference/config/index metadata directories and target-object
prefixes, and on watch loss or overflow. An empty inotify queue alone is never
content authority. The collector checks both proofs before admission,
immediately before dispatch and before releasing an inspected result. Restoring
the old bytes does not revive that session: close it and start a new protected
collector. This is a bounded metadata image with sticky withdrawal, not live
branch following or a complete immutable copy of the worktree/object graph.
The data image is not an authorization cache. Every invocation still needs native
admission and result inspection; classifier uncertainty, policy Deny/Ask and
single-use approvals continue to apply. A changed ref cannot use an approval
obtained for the earlier image.

## Installation and reproducible acceptance

Use the prerequisites and pinned build procedure in the
[original Git guide](GIT_MCP_PROFILE.md). The upstream identity remains
`mcp-server-git 2026.10.10`, SDK `1.29.0`, protocol `2025-11-25`, Python
`3.11.14` (standalone release `20251014`), and Git `2.51.2`.
The exact archive, wheel, discovery and initialization digests remain in
[`upstream-identity.json`](../../profiles/mcp/git-readonly-v1/upstream-identity.json)
and [`requirements.lock`](../../profiles/mcp/git-readonly-v1/requirements.lock).
The unchanged policy source is
[`git-readonly-v1/policy.yaml`](../../profiles/mcp/git-readonly-v1/policy.yaml).

Install to a new private destination outside the selected workspace:

```sh
python3 -B scripts/install-sou68-git-profile.py --run --local-references \
  --destination /owned/private/git-local-refs --workspace /owned/prepared-repo \
  --git /owned/runtime/git --git-sha256 "$GIT_SHA256" \
  --bwrap /owned/runtime/bwrap --git-launcher "$PWD/target/debug/agentfw-git-sandbox"
```

Configure the enforcing daemon with the installed `policy.yaml`, `registry.json`
and its exact SHA-256. Select the installed `profile.json` through
`AGENTFW_MCP_SERVER_PROFILE`, and set `AGENTFW_CLASSIFIER=rule-baseline`,
`AGENTFW_RULE_BASELINE=$PWD/rule_baseline/git_readonly_local_refs_v1/rule_baseline.py`
and `AGENTFW_CLASSIFIER_PYTHON` to the reviewed Python interpreter. Keep the
original server command from the Git guide. Installing the new format alone
does not change another daemon or classifier selection. Record installation,
registry, policy and classifier hashes before use.

On a clean exact source checkout with the pinned runtime binaries, run:

```sh
python3 -B scripts/verify-sou137-local-git-refs.py --run \
  --agentfw "$PWD/target/debug/agentfw" \
  --git /owned/runtime/git --git-sha256 "$GIT_SHA256" \
  --bwrap /owned/runtime/bwrap --git-launcher "$PWD/target/debug/agentfw-git-sandbox" \
  --sandbox-test-binary "$SANDBOX_TEST_BINARY" \
  --expected-commit "$(git rev-parse HEAD)" --output /owned/evidence/sou137-new-run
```

The driver uses synthetic owned fixtures and the existing original-server
acceptance client, enforcing daemon and independent Linux process/open witnesses.
It calibrates an external-helper effect against the direct original server,
checks a live receiver and FIFO through the existing OS-isolation probe, reproduces
default-v1 refusals, and tests both pre-dispatch and inflight reference substitution.
Native unit controls on the ordinary local filesystem and tmpfs reproduce the
inotify-only mapped-write gap and exercise mappings before/after capture,
unchanged useful calls and write/restore. Actual original-server controls keep
the writable mapping/FD open while testing pre-dispatch, pending-Ask and result
release, including restoration before the next boundary check.
An owned Ask policy exercises exact original CLI approval, single use and source
withdrawal while approval is pending; a Deny policy and an uncertain classifier
must independently refuse. These synthetic decisions do not establish physical
human presence or relax an installed operator's policy.
Evidence records exact source/tree, binaries, installed profile/registry/policy,
classifier and raw request/response transcript hashes. Missing enforcement or a
blocked original response fails acceptance; parser tests alone cannot pass it.
Retain and attribute unchanged detector or environmental failures instead of
weakening their gates.

The manual **Real Git MCP profile** workflow's `local_refs_only` input selects
this native acceptance. It has a separate concurrency group so an existing
default-profile regression run continues. Routine Ready CI retains its existing
default-profile, filesystem and platform gates; the additional expensive
local-reference acceptance is explicitly dispatched. Final qualification uses
the normal Ready PR and required CI admission workflow. Merging remains a TL
decision.
