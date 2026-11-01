# Installed pilot Git capabilities

`agentfw pilot preview` and `prepare --apply` accept exactly one `--git-profile`
registry ID below. Omitting it retains `git-readonly-v1`. A later prepare under
the same prefix reuses its recorded explicit selection. Changing the selection
requires `--rebuild`; it retains the previous generation. Repeated flags, lists,
unknown IDs and combined capability strings refuse. Repository content never
selects a capability.

| Registry ID | Reviewed capability | Classifier | Required Git layout/runtime |
| --- | --- | --- | --- |
| `git-readonly-v1` | Original six bounded read operations | `git_readonly_v1` | Default standalone repository |
| `git-readonly-file-revisions-v1` | Default operations plus `git_show` with literal `HEAD:path` or full local SHA:path | `git_readonly_file_revisions_v1` | Regular tracked blob; no named-ref/file union |
| `git-readonly-local-refs-v1` | Reviewed bounded local branch/tag reference grammar | `git_readonly_local_refs_v1` | Local references only; no fetching |
| `git-linked-worktree-readonly-v1` | Original bounded read operations over an explicit linked worktree snapshot | `git_readonly_v1` | Explicit workspace, per-worktree gitdir and common Git directory; native Linux only |
| `git-readonly-shallow-v1` | Reviewed bounded local shallow repository reads | `git_readonly_v1` | Existing local shallow boundary; no deepening |
| `git-local-clone-readonly-v1` | Reviewed standalone local-clone metadata | `git_readonly_v1` | Explicit interpreter-free static pinned Git |
| `git-tracked-symlinks-readonly-v1` | Original six operations over the reviewed bounded tracked-link graph | `git_readonly_v1` | Relative tracked links confined to the declared graph; static pinned Git |

These are separate declarations. Selecting tracked links does not grant per-file
revision syntax or local-reference syntax. The upstream names, arguments,
schemas and response bytes remain original. Mutating Git, network, hooks,
helpers, unselected worktrees, submodules and unrelated link targets remain
unsupported. Preparation reuses production validators without running Git
against the selected existing projects or repairing them. Preview reports the
selected declaration and required inputs; compatibility validation occurs on
explicit preparation and again on launch.

## Operator examples

Use a verified installed front-door component and Agent binaries built from its
exact commit. Start with existing explicit runtime inputs as described in
[the installed front door](PILOT_INSTALLED_FRONT_DOOR.md). Both roots must be
canonical owned paths. The private prefix must be outside them.

```sh
agentfw pilot preview --prefix /home/operator/pilot-file \
  --filesystem-workspace /home/operator/project \
  --git-workspace /home/operator/repository \
  --git-profile git-readonly-file-revisions-v1 \
  --agentfw /home/operator/runtime/agentfw \
  --git-launcher /home/operator/runtime/agentfw-git-sandbox \
  --sandbox-tests /home/operator/runtime/sandbox_tests \
  --git /home/operator/runtime/git --bwrap /home/operator/runtime/bwrap \
  --node-archive /home/operator/inputs/node-v22.22.0-linux-x64.tar.xz \
  --claude /home/operator/runtime/claude --python /usr/bin/python3.12 \
  --python-archive /home/operator/inputs/python.tar.gz \
  --npm-cache /home/operator/inputs/npm-cache \
  --wheelhouse /home/operator/inputs/wheelhouse
```

Repeat those options with `prepare --apply`. After preparation:

```sh
agentfw pilot status --prefix /home/operator/pilot-file
agentfw pilot run --prefix /home/operator/pilot-file \
  --prompt 'Use the Git MCP git_show tool to inspect HEAD:src/app.py.'
```

For tracked links, choose `--git-profile git-tracked-symlinks-readonly-v1` and
supply the accepted static Git runtime. Ask the host to inspect Git status,
diff or history. To change a prepared selection, use `prepare --apply --rebuild`
with the new explicit ID and compatible runtime inputs. The existing generation
switch command verifies each generation with its own source and selection.

New selection/3 manifests bind the declaration, original schema/registry,
scenario policy, selected classifier and helper input hashes as `git_selection`.
They also pin installed profile, receipt, package and runtime bytes. Old
selection/2 manifests keep default-only meaning; adding an extension field to
one refuses. Old generations still require their own matching source component.
Mixed sources, changed helpers, altered profile bytes and changed registries
require fresh preparation, never a hand-edited manifest or updated digest.

## Qualification and limits

A configured profile is not observed successful use. `status` reports
`configured-not-running` until an exact current run answers the existing
authenticated status query. A successful preview is not sandbox enforcement.

`scripts/qualify-installed-git-profiles.py` exercises installed default, per-file
and tracked-link runs outside the checkout through the genuine pinned host and
the owned scripted provider. It retains exact source/component/input identities,
correlated useful results, refused controls, cancellation/restart and unchanged
workspace/index/HEAD and outside-sentinel witnesses. Run it on native Ubuntu
24.04 x86_64 as an ordinary user with explicit runtime inputs. Retain every
attempt's `report.json`; a failed or incomplete report is not qualification.
Dispatch `Real Git MCP profile` with `installed_profiles_only=true` to run this
focused scenario. It is excluded from automatic component matrices. Local unit
tests also cover all reviewed declaration bindings and component
closure. WSL2, macOS and Windows are unqualified for this installed workflow.
Live-model effectiveness is not measured by the scripted provider.

## Explicit linked worktrees

The separate `git-linked-worktree-readonly-v1` profile supports an ordinary owned
linked worktree with an absolute `.git` file, an explicitly selected
`COMMON/worktrees/NAME` admin directory, and `commondir` exactly `../..`.
These repository strings are only consistency checks. They never select another
root or cause traversal to a repository-chosen path. Choose all three canonical,
owned roots explicitly; roots with shared write access or aliases refuse.

The installed front door can construct the selection outside any checkout:

```sh
agentfw pilot worktree-selection \
  --workspace /home/operator/worktrees/feature \
  --git-dir /home/operator/repository/.git/worktrees/feature \
  --common-dir /home/operator/repository/.git \
  --output /home/operator/private/feature-binding.json
# Preview writes nothing. Repeat with --apply to create the new private file.
```

Use a new private prefix outside both worktree and common metadata, the same
explicit runtime inputs shown above, and add these options to `preview` then
`prepare --apply`:

```sh
--filesystem-workspace /home/operator/worktrees/feature \
--git-workspace /home/operator/worktrees/feature \
--git-profile git-linked-worktree-readonly-v1 \
--git-worktree-binding /home/operator/private/feature-binding.json
```

Preparation binds root device/inode/owner, exact HEAD/index, configuration,
local refs and bounded object inputs. It does not alter the selected sources.
Native startup independently repeats validation, leases the original selected
inodes and materializes sealed bounded metadata images. The original server sees
its usual `/workspace` repository and original schemas. Common-repository or
parent paths are never mounted. Each call revalidates source custody; a changed
source withdraws that session permanently. Restoring bytes cannot revive it.
Two worktrees require two explicit manifests and prefixes. A token, prepared
profile or similarly named directory from one cannot select the other.

This profile keeps the original HEAD/full-SHA-1 revision grammar, six read
operations, result inspection, read-only mounts, seccomp/Landlock, deadlines and
existing byte/object/reference bounds (16 MiB, 128 objects, 64 refs). It does not
combine file-revision, tracked-link, shallow or named-reference extensions.
Submodules, nested repositories, symlinks, alternates, partial/promisor or
unsupported pack formats, active hooks, configuration helpers, worktree-specific
config and indirect/foreign/missing roots refuse. Default profiles continue to
refuse linked layouts. Result-inspection refusals remain separate from source
or original-execution failures; this profile does not change SOU-177 diagnostics
or any result detector/policy.

After a legitimate source change, stop the old run and explicitly create a fresh
binding file; use `prepare --apply --rebuild` with that file. Do not repair a
binding by editing hashes. To roll back, choose the earlier verified prefix or
use the existing prepared-generation switch with matching source/component and
still-valid source inputs. A stale earlier generation refuses rather than
repreparing or adopting changed inputs.

Focused evidence runs through `mcp-real-filesystem.yml` with only
`linked_worktrees_only=true` and `native_preparation_only=true` (stability off).
It preserves failed/incomplete outcomes and uses two owned real worktrees,
pinned original servers, a genuine host and an owned scripted provider.
macOS, Windows, WSL2 and unsupported layouts remain unqualified; local selection
unit tests are not native protection or final Ready/security/admission evidence.

Ordinary selected-worktree commits may leave `COMMIT_EDITMSG` in the explicit
admin directory. The linked profile accepts only an owned regular non-shared
file with one link and at most 64 KiB. It never reads, copies or executes that
message and never treats it as snapshot authority. Other unselected admin
names remain a refusal; an empty owned per-worktree `refs` directory is allowed,
but nonempty private ref namespaces are unsupported. Native regression fixtures
perform a real commit inside the linked worktree before capturing its view.
