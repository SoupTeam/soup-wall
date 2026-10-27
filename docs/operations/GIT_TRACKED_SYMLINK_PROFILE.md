# Opt-in tracked symbolic links (SOU-150)

`sw-mcp/git-tracked-symlinks-readonly/1` is a separate, explicitly selected
profile. It starts from accepted main `49268d852a5af491c1145d627f1ab6e73593f5df`
and reuses the [ordinary-clone profile](GIT_LOCAL_CLONE_PROFILE.md), original
Git MCP server, six read operations, schemas, policy and classifier.

## Supported subset, frozen before implementation

Use an owned standalone non-bare SHA-1 repository with the ordinary-clone
config/attributes/metadata grammar and traversal limits. At most 64 tracked
links are supported. Each link has index mode `120000`, stage zero, and an
existing worktree symlink whose target bytes exactly match its indexed blob.
Staged link changes are supported when the worktree matches the new index;
unstaged link edits, missing links and regular-file replacements are refused.

Targets are nonempty relative ASCII paths, at most 256 bytes and 32 components.
Components use letters, digits, dot, underscore and hyphen. Relative `..` may
stay within the repository. The normalized target must name a regular file,
with no symlink component, in that same index/worktree or historical tree.
Intermediate components must be represented directories even when followed by
`..`; `missing/../file` and `regular-file/../file` are refused. Absolute,
outside-root, dangling, directory, cyclic and chained targets are refused.
Links to or through `.git`, `.gitmodules` and `.gitattributes` are unsupported;
those names cannot themselves be links. Untracked links and special files,
symlinked Git metadata, submodules and conflict stages remain refused.

Inspect the bounded stage inventory and every stored commit tree using the
same original Git inside the OS sandbox. At most 64 commits and 32,768 objects
are supported. Index and object inventories and each commit-tree listing are
at most 4 MiB; combined tree listings are at most 32 MiB per Git invocation.
At most 128 distinct link/attribute blobs are inspected, each at most 8 KiB;
link targets still have the smaller 256-byte bound. Attribute bytes inspected
across the index and all trees total at most 256 KiB. Each inventory has at most
32,768 entries. A link graph has at most 64 links. Limits are repeated per
invocation, with no cached result used as authority. Large histories can exceed
this deliberately bounded profile or its unchanged process/resource budgets. Historical link targets may
differ from the index, but must independently satisfy the same tree-relative
grammar and resolve to regular entries in their own commit tree. Raw blob
objects remain Git data; they are never dereferenced as filesystem paths.

The repository must remain quiescent for a successful read. Recheck link,
index, config and directory identities before each actual Git invocation.
A concurrent writer may cause refusal; this profile does not promise snapshot
consistency. Read-only mounts, the clean namespace/environment, no-network
seccomp, static-Git-only execution restriction, Landlock mutation restriction,
resource budgets and exact invocation/result receipts remain authoritative
even if a writer races the final validation/use interval. No repair, rewritten
link, sanitized repository copy or implicit combination with local-reference,
shallow or per-file capabilities is permitted.

## Optional daemon-owned execution

Whole-commit formatter attribution requires explicit `native.git_execution`
configuration. Create a separately reviewed copy of the tracked profile with
the owned workspace's observed `workspaceIdentity` (device, inode and uid).
Configure its absolute `profile_path`, exact file `profile_sha256`, and the
collector's `server_id`; use this same profile in the collector environment.
Authenticate the host/child authority and enable native liveness. The installer
and original selection metadata remain unchanged by this opt-in.

This execution route accepts exactly BASE and TRACKED profile identities. It
uses the existing private original-Git worker, with the tracked repository
validator before and after capture. The same retained sealed metadata/object
image supplies both its typed object facts and its mount. The tracked launcher
still checks inventory, index, historical targets and worktree state on every
actual Git invocation. Working-tree links retain their original names and
targets and confer no outside-file authority.

Only the TRACKED witness capture accepts the existing bounded ordinary-clone
core/user/origin/branch config grammar. It preserves those config bytes, loose
and packed `refs/remotes/origin/*`, and a bounded symbolic origin HEAD in the
same sealed image and digest. The symbolic target must be a present direct
same-origin reference. Other remotes, escaping/malformed names and symbolic
cycles refuse. These metadata do not enable named-remote request arguments;
actual HEAD remains a proved local branch or detached commit. BASE and selected
SHALLOW capture keep their existing config and namespace restrictions.

The optional witness supports at most 128 loose objects, each at most 262144
compressed/inflated bytes, within a 16 MiB image and 64 references in total.
Packed object witnesses or larger images refuse; bounded packed references
remain metadata within the same reference limit. The original tracked profile
retains its separately bounded packed/loose
behavior when this optional execution route is not selected. The five-second
worker deadline and existing scan/resource budgets remain unchanged. Only a
proved original formatter header receives the existing attribution; raw blobs,
body content and policy floors retain baseline inspection.

Healthy qualification sessions explicitly request and verify the production
default ten-second liveness lease. The shared fixture initially chose two
seconds; [SOU-146 run #185](https://github.com/SoupTeam/soup-wall/actions/runs/40355477933)
failed on liveness uncertainty after its first file read. It does not qualify
healthy two-second execution for either profile or establish a complete cause.
This qualifier retains that limitation and separately tests a granted two-second
lease: pause only the pinned owned collector, match its exact session/epoch
`native_session_expired` audit, require zero execution/new original results and
actual host EOF, and independently verify cleanup. Terminal grading accepts
confirmed owner cleanup with `native_liveness_uncertain`, or the exact combined
native-expiry/1500 ms namespace-owner guard with `pilot_cleanup_unconfirmed`.
The latter requires matching owner instance/process start identities, the exact
`mcp_owner_liveness_expired` reason and complete independent descendant
observation. Its production cleanup receipt remains unconfirmed; this branch
does not prove isolated native-denial behavior. Other errors refuse, and owner
termination alone is not native-expiry evidence. A new ten-second session must
return the original bytes. Production defaults, five-second calls, approval TTLs
and resource/policy guards remain unchanged.

[Run #187](https://github.com/SoupTeam/soup-wall/actions/runs/40364823623) remains
failed/incomplete: verified preparation rejected the fixture's permitted
origin/tracking config before starting the actual read scenarios. The fixture
and its metadata are retained for the new qualification; this failure provides
no runtime byte-equality or extended-profile SOU-109 acceptance evidence.

[Run #189](https://github.com/SoupTeam/soup-wall/actions/runs/40373408778) failed
in the new Linux snapshot test before the acceptance driver ran. Exact sealed
image export and HEAD-kind checks passed, but the test incorrectly constructed
the generic component Producer with TRACKED, which its existing profile boundary
refuses. The corrected test retains that refusal and checks Snapshot validation,
export, mount and sticky origin-ref withdrawal through existing APIs. It makes
no generic Producer completion claim; actual private-worker kind and original
read-byte qualification still require a new complete native run.

## Acceptance

The targeted native Linux command must retain exact source/profile/runtime/
policy identities, compare all six original read results byte-for-byte, verify
repository state and useful continuation after link/index/metadata refusals,
and independently calibrate an external read marker. Exercise link replacement
after sandbox preparation and concurrent replacements; a parser refusal is
not evidence of OS containment. Verify owned-process cleanup and unrelated
state preservation. Record shared detector false refusals without changing
policy or result bytes. macOS tests do not establish native Linux containment.

## Isolated installation and selection

Linux x86-64, working user namespaces, bubblewrap/seccomp and Landlock ABI 3 or
later are required. Reuse the pinned original-server provisioning and static
interpreter-free Git described in the [ordinary-clone guide](GIT_LOCAL_CLONE_PROFILE.md#explicit-isolated-installation-and-selection).
Build the Agent and Git sandbox launcher from the candidate source. Independently
verify the static Git digest; a dynamic Git/ELF loader is unsupported. The
installer downloads only the existing hash-pinned original runtime/server
assets. It requires fresh private installation and selection directories.

```sh
python3 -B scripts/install-sou150-git-profile.py --run \
  --destination /private/tracked-links-runtime --workspace /owned/repository \
  --git /verified/static-git --git-sha256 "$VERIFIED_GIT_SHA256" \
  --bwrap /verified/bwrap --git-launcher "$PWD/target/debug/agentfw-git-sandbox" \
  --selection /private/tracked-links-selection --port 48001
```

The receipt is `prepared-not-active`. Use the generated `config.json` as
`.agentfw/config.yaml` in a separate private Agent home and the exact environment
from `selection.json`; start the daemon in that same home. Follow the
[existing isolated activation procedure](GIT_LOCAL_CLONE_PROFILE.md#explicit-isolated-installation-and-selection)
using the new paths and registry `git-tracked-symlinks-readonly-v1`.
Neither an existing installation nor the operator repository is edited.

The original operations remain `git_show`, `git_status`, `git_log`, `git_diff`,
`git_diff_unstaged` and `git_diff_staged`, with the original HEAD/full-SHA-1,
count and context limits. This profile does not add `HEAD:path`, local-reference
selectors, shallow history, mutation, remote operations or implicit activation.

## Refusal diagnostics

The original server returns a tool error when the per-Git guard refuses.
These diagnostics grant no authority and do not replace MCP schemas/results.
The inherited [ordinary-clone diagnostics](GIT_LOCAL_CLONE_PROFILE.md#refusal-codes)
and filesystem/kernel errors also remain fail-closed.

| `git_links_` suffix | Meaning |
| --- | --- |
| `ownership` | Repository entry is not owned or a regular file/directory is shared writable |
| `metadata`, `control_path` | Link occupies or traverses an unsupported control/metadata path |
| `target_bounds`, `target_encoding`, `target_absolute_or_depth`, `target_component` | Target bytes exceed the relative ASCII grammar |
| `target_escape`, `target_directory`, `target_not_regular`, `target_component_not_directory`, `chain` | Target escapes, dangles, selects a directory, traverses a missing/non-directory component, or uses a link chain/cycle |
| `index_worktree_mismatch`, `index_record` | Index and worktree link inventories differ or index framing is malformed |
| `identity_changed` | Link/index/config/directory identity changed during inspection |
| `count`, `blob_count`, `commit_count`, `object_count`, `history_bounds`, `tree_bounds` | Declared count/output budget exceeded |
| `duplicate_path`, `tree_record`, `tree_mode`, `object_record` | Unsupported or malformed Git inventory |

## Targeted native reproduction

For hosted Linux acceptance, manually dispatch the existing **Real Git MCP
profile** workflow from the exact candidate branch with only
`tracked_symlinks_only=true`; keep `local_refs_only=false` and
`shallow_only=false`. Any pair or triple of selectors is refused. This opt-in
mode reuses the existing Ubuntu 22.04 job and pinned runtime provisioning,
runs only the tracked-symlink regressions/acceptance, and retains
`sou150-acceptance/` plus its log in the existing evidence artifact. Ordinary
qualification and previous manual selectors retain their behavior. The
workflow's source SHA must match the report; a later source change needs new
qualification. Required CI/admission/main integration remains TL work.

The default-profile negative control first proves an actual useful original
v1 read on a link-free, v1-compatible fixture with its own matching registry,
policy and daemon. It then adds an indexed link without changing those inputs
and requires the specific repository-link diagnostic before server startup;
a generic startup error is never accepted as this proof. Removing the owned
link restores a byte-identical useful default read.

This command is opt-in; CI/admission integration belongs to TL. Use a clean exact
candidate checkout and fresh evidence outside it. Provision the pinned static
Git and bubblewrap through the existing reviewed procedure. Then build the
candidate Agent/launcher and discover its matching Linux libtest binary:

```sh
EVIDENCE_PARENT="$(mktemp -d)"
cargo build --locked -p agentfw --bins
cargo test --locked -p agentfw --lib --no-run --message-format=json > "$EVIDENCE_PARENT/test-build.jsonl"
```

The single `compiler-artifact` entry with `target.name == "agentfw"`,
`profile.test == true` and a non-null `executable` names `$TEST_BINARY`.
Run using those exact candidates:

```sh
python3 -B scripts/verify-sou150-tracked-symlinks.py --run \
  --agentfw "$PWD/target/debug/agentfw" \
  --git /verified/static-git --git-sha256 "$VERIFIED_GIT_SHA256" \
  --bwrap /verified/bwrap --git-launcher "$PWD/target/debug/agentfw-git-sandbox" \
  --sandbox-test-binary "$TEST_BINARY" \
  --expected-commit "$(git rev-parse HEAD)" --output "$EVIDENCE_PARENT/acceptance"
```

Without `--run` the driver only prints a plan. A native pass requires all six
byte-identical original JSON-RPC read replies, unchanged repository state,
independent external-marker calibration followed by zero opens for late absolute,
relative and racing replacements, and useful real-server continuation after
late index/worktree/config refusals. The OS probe prepares the sandbox on a
valid tracked link and replaces it afterward; direct restricted Python reads
bypass the parser and Git guard deliberately. It also checks unrelated owned
state and finishes the existing budget/owner boundary. The real-server driver
checks default-profile refusal and descendant cleanup. Only synthetic owned
fixtures are mutated, then restored; no repair of an operator repository occurs.

`report.json` retains source/tree, runtime/profile/policy/classifier identities,
original transcripts, actual refusals, cleanup and the independent OS-test log.
Any required read refusal, including a shared SOU-109 detector false refusal,
keeps the report failed. No normalization, Ask override, changed label or policy
exception turns an incomplete native run into acceptance. macOS regressions and
a driver plan do not qualify Linux containment; missing runtime/kernel support
must remain an explicit acceptance gap.
