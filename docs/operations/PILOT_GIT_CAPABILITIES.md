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
| `git-readonly-shallow-v1` | Reviewed bounded local shallow repository reads | `git_readonly_v1` | Existing local shallow boundary; no deepening |
| `git-local-clone-readonly-v1` | Reviewed standalone local-clone metadata | `git_readonly_v1` | Explicit interpreter-free static pinned Git |
| `git-tracked-symlinks-readonly-v1` | Original six operations over the reviewed bounded tracked-link graph | `git_readonly_v1` | Relative tracked links confined to the declared graph; static pinned Git |

These are separate declarations. Selecting tracked links does not grant per-file
revision syntax or local-reference syntax. The upstream names, arguments,
schemas and response bytes remain original. Mutating Git, network, hooks,
helpers, arbitrary worktrees, submodules and unrelated link targets remain
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
tests also cover all six declaration bindings and component
closure. WSL2, macOS and Windows are unqualified for this installed workflow.
Live-model effectiveness is not measured by the scripted provider.
