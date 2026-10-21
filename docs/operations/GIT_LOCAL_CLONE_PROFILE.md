# Opt-in ordinary local Git clones (SOU-107)

This increment defines `sw-mcp/git-local-clone-readonly/1`, selected explicitly.
The original `git-readonly-v1` assets and repository validator remain unchanged.
It reuses the pinned original Git MCP server, six read operations, schemas,
classifier and `linux-readonly-v1` policy. Remote metadata never permits remote
contact. This is a bounded subset, not arbitrary repository compatibility.

## Supported subset, defined before implementation

One standalone non-bare SHA-1 repository with a real `.git` directory, regular
files/directories only, at most 32,768 entries and depth 32. Nested repositories,
submodules, worktrees, shallow repositories, alternate object stores, active hooks,
config indirection and unsupported metadata are refused. The operator must keep
the repository quiescent during a call; concurrent writers are not a snapshot
consistency guarantee. They must never gain helper, write or network authority.

Config is at most 8 KiB of ASCII. Empty lines and whole-line `#`/`;` comments are
accepted. Each value requires `key = value`; section/key case is insensitive.
Quoted values, escapes, continuations, inline comments, duplicate sections/keys
and implicit boolean values are outside this subset. Exact supported entries:

| Section | Keys and values |
| --- | --- |
| `[core]` | `repositoryformatversion = 0`, `bare = false`; optional `filemode`, `logallrefupdates`, `ignorecase`, `precomposeunicode` as `true`/`false` |
| `[user]` | `name` and `email`, bounded printable identity strings without Git quoting/comment syntax |
| `[remote "origin"]` | one inert `url`; `fetch = +refs/heads/*:refs/remotes/origin/*` |
| `[branch "NAME"]` | `remote = origin`; `merge = refs/heads/REF`; NAME and REF use bounded ASCII ref components without `..`, `@{`, leading/trailing dot, empty components or `.lock` |

Origin URLs are bounded ASCII HTTPS/SSH URLs or scp-style `git@HOST:PATH`, without
whitespace, quoting, backslash or helper syntax. They are retained as data.
No credential, alias, diff, filter, include/includeIf, extension, pager, fsmonitor,
hooksPath, URL rewriting, alternate or protocol setting is accepted.

Root/nested `.gitattributes` may contain whole-line comments and simple relative
patterns using ASCII letters/digits, `_`, `-`, `.`, `/`, `*`, `?`. No quoting,
backslash, negation, bracket patterns or macro definitions. Allowed tokens are
`text`, `-text`, `text=auto`, `eol=lf`, `eol=crlf`, `binary`, and `-diff`.
At most 64 attribute files, 8 KiB/file, 256 KiB total. Unsupported attributes,
including filter, textconv/diff drivers, encodings and custom macros, are refused.
Tracked attribute blobs and index file modes must be checked as well as the live
worktree, so removing a worktree file cannot expose an unchecked index fallback.

Reference syntax: [Git config](https://git-scm.com/docs/git-config) and
[Git attributes](https://git-scm.com/docs/gitattributes). This profile intentionally
implements a narrower grammar and does not rewrite files to fit it.

## Containment and validation boundary

Use the accepted fd-pinned read-only workspace/runtime mounts, no-network seccomp,
clean credential/environment boundary, Landlock mutation restrictions, owner
liveness, resource budgets and native result inspection. Add per-Git-invocation
inspection inside the actual mounted workspace and an execution restriction
permitting only the pinned Git image for its children. An external helper must
not run even if unsafe settings are introduced after inspection. The original
Python MCP server, Git arguments, results and errors are preserved for supported
repositories; wrapper refusals are explicitly profile errors.

Configuration selection is preparation, not authority for a later repository
state. Test valid startup followed by config include/helper insertion, attribute
replacement, symlink substitution and new metadata. Bind directory inspection
through no-follow descriptors; reject changed identities while inspecting.

## Required evidence before acceptance

The opt-in Linux command must compare all six original reads with the same
unwrapped server on an owned clone-shaped fixture with staged/unstaged data and
accepted attributes. Retain source/profile/runtime/policy hashes, original
outputs, repository/index/worktree state, useful continuation and cleanup.
Independently calibrate helper execution and network witnesses; a parser error
alone is not an OS-containment result. Preserve original v1 negative controls
and failed/incomplete attempts. No live providers, fetch/push/clone capability,
new Ask path, onboarding or shared host launcher is added here.

## Explicit isolated installation and selection

Use Linux x86-64 with the existing supported bubblewrap/seccomp/Landlock ABI 3
floor. Build `agentfw` and `agentfw-git-sandbox` from the reviewed source. Supply
the Git binary and its independently verified SHA-256. Installation downloads
the existing hash-pinned original Python/server assets; it does not contact the
repository remote. Both destination directories must be new, private paths.

```sh
python3 -B scripts/install-sou107-git-profile.py --run \
  --destination /private/local-clone-runtime --workspace /owned/local-clone \
  --git /verified/git --git-sha256 "$VERIFIED_GIT_SHA256" \
  --bwrap /verified/bwrap --git-launcher "$PWD/target/debug/agentfw-git-sandbox" \
  --selection /private/local-clone-selection --port 48001
```

The receipt says `prepared-not-active`. In a separate private Agent home, use
the generated `config.json` as `.agentfw/config.yaml` and the exact environment
entries from `selection.json`. Start `agentfw serve` with that same private home,
then start the collector with the installed `profile.json` and original command:

```sh
agentfw mcp --native-admission --id local-clone -- \
  /private/local-clone-runtime/package/python/bin/python3.11 \
  -I -B -m mcp_server_git --repository /workspace
```

Do not reuse a running daemon from another policy/registry selection. The
selector rechecks the installation, original discovery, classifier and shipped
pilot policy. It does not edit an existing v1 installation or operator repository.
The six operations remain `git_show`, `git_status`, `git_log`, `git_diff`,
`git_diff_unstaged`, `git_diff_staged`; existing HEAD/SHA-1 and count/context bounds
remain in force. No additional tool becomes executable.

## Refusal codes

Codes are profile diagnostics inside the original server's tool-error path;
they are not new MCP tools or execution approvals.

| Code suffix after `git_clone_` | Reason |
| --- | --- |
| `config_bounds`, `config_syntax`, `config_section`, `config_value`, `config_duplicate`, `config_required` | Config exceeds the documented grammar, allowlist or required standalone core settings |
| `attributes_bounds`, `attributes_pattern`, `attributes_syntax`, `attributes_token` | Worktree/index attributes exceed the bounded grammar |
| `index_bounds`, `index_encoding`, `index_mode`, `index_path`, `index_syntax`, `index_inspection_failed` | Oversized/unsupported index, nonregular entry, conflict stage, unsafe path or failed original Git inspection |
| `metadata_unsupported`, `standalone_required` | Unsupported metadata or missing real standalone repository |
| `file_type`, `identity_changed` | Symlink/special file, substitution or concurrent inspection change |
| `control_bounds`, `depth_limit`, `entry_limit`, `path_bounds`, `path_encoding`, `inspection_bounds` | Bounded traversal/control-file/output limit |
| `executable_type` | Mounted Git image is not a regular file |

Filesystem/kernel failures also fail closed and retain their underlying error.

## Reproduce and interpret acceptance

Run the existing **Real Git MCP profile** manual workflow on the exact candidate.
It retains the v1 and SOU-98 gates, then runs the SOU-107 gate using the same
pinned runtime provisioning. No additional per-push expensive workflow is added.
For an already provisioned Linux test machine:

```sh
python3 -B scripts/verify-sou107-real-git.py --run \
  --agentfw "$PWD/target/debug/agentfw" --git /verified/git \
  --git-sha256 "$VERIFIED_GIT_SHA256" --bwrap /verified/bwrap \
  --git-launcher "$PWD/target/debug/agentfw-git-sandbox" \
  --sandbox-test-binary "$AGENTFW_LIB_TEST_BINARY" \
  --expected-commit "$(git rev-parse HEAD)" --output /private/new-sou107-evidence
```

Only a complete `status: pass` report is acceptance evidence. The driver requires
clean exact source, a calibrated real helper-execution/network OS probe, six
late-change refusals with useful continuation, six byte-faithful original reads,
12 admission refusals with zero repository opens, 16 overlap/cancellation rounds,
result inspection, daemon-outage refusal, unchanged repository and owned-process
cleanup. Failed attempts retain logs and partial reports in the workflow artifact.
Windows unit tests and a parser refusal do not establish Linux containment.
