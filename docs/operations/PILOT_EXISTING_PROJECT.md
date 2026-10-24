# Read-only pilot on an existing project

The prepared pilot can inspect explicitly selected, existing owned roots through
the pinned original filesystem and Git MCP servers. Omitting both workspace
options preserves the generated demo. This runtime supports ordinary users on
**native Ubuntu 24.04 x86-64**; arbitrary clones, WSL and other platforms are not
certified. Scripted development acceptance does not measure live-model effectiveness.

Start with the [development guide](../DEVELOPMENT.md) and the existing
`prepare-installed-pilot.py` inventory. Keep the reviewed source, selected runtimes,
policy, classifiers, preparation prefix and run state outside both selected roots.
Append **both** options to the preparation command with its normal runtime inputs:

```sh
--filesystem-workspace /absolute/canonical/owned/source-project \
--git-workspace /absolute/canonical/owned/supported-repository
```

First run without `--prepare`. The non-executing preview shows roots, directory
identities, source and supplied input hashes, pinned profiles, read-only capability,
scope limits and missing inputs. It does not execute selected binaries, install
packages, or change source data. Native repository validation runs only on opt-in;
preview alone is not runtime protection. Inspect it, then explicitly repeat the
command with `--prepare`. Downloads separately require `--allow-download`; existing
offline archives/cache options still work. No daemon starts during preparation.

Roots must be absolute and canonical, with no symlink components or `..`, owned by
the operator, and not group/other writable. Do not select your home directory.
The prefix must not contain either root or be inside either root. One directory
may serve both roles only if it satisfies the Git restrictions.

Git supports a standalone, non-bare repository with a bounded core-only
`.git/config`. Remotes, user sections, includes, linked worktrees, submodules,
attributes, active hooks, alternates, shallow repositories, symlinks, special files
and excessive entry count/depth are refused by the existing profile validator.
A typical clone with a remote configured is unsupported. Choose a supported
project; the pilot never edits settings, removes hooks, repairs a repository,
initializes Git, fetches, resets, or copies source data into the project.

The additive `prepared_workspaces` binding retains selection/2; optional
`workspaceIdentity` retains profile/1. Selection/profile hashes, read-only scope,
device, inode and owner are rechecked at launch. The original sandbox also checks
the opened root descriptor. A moved/missing/replaced root or stale selection fails
without a generated-directory fallback. Selecting different roots requires an
explicit `--rebuild` with the new options; the old generation is retained.

Use the returned selection with the regular entry point:

```sh
python3 -B scripts/pilot-run.py \
  --selection /private/preparation/generations/GENERATION/selection.json \
  --expected-commit FULL_REVIEWED_COMMIT
```

Inspect this plan, then add `--run` and a useful `--prompt`. Each server sees its
own selected root as `/workspace`. Supported Git inspection includes status, show
and diff; show/diff accept only `HEAD` or a full SHA-1 revision. Project contents
and results remain untrusted. Operator edits between separate runs are read as
current data with fresh authority; unchanged root identity needs no new selection.

The host starts outside the project with the existing restricted MCP configuration.
Project-local Claude settings, hooks, plugins, `.mcp.json`, and `CLAUDE.md` cannot
enable built-in tools or commands. Writes, outside-workspace symlink targets and
server network effects stay confined/refused. Policy Ask/Deny behavior is unchanged.
Cancel with Ctrl-C; daemon loss fails the owned run closed. The existing process
and private-state cleanup applies. The generated demo and fixture qualification
refuse external selections before writing fixtures. `pilot-cleanup.py` traverses
only private generations; external project roots are never deletion targets.

For targeted native acceptance, dispatch **Real filesystem MCP profile** on the
review branch with `existing_project_only=true`. Before the default branch UI
exposes that input, `native_preparation_only=true` also runs this slice after native
preparation qualification. `qualify-existing-pilot.py` creates owned ordinary
projects outside the prefix and uses the existing scripted loopback provider and
actual pinned host. It records original outcomes, failure/skip counts, source/input
hashes, operator edits, root/selection refusals, mutation/symlink refusal, hostile
project settings, cancellation, daemon loss and recovery. Independent syscall and
repository snapshots cover useful execution, forbidden effects, worktree/index/
HEAD/config and an untracked file. Raw traces/output remain private. This harness
is not permission to run acceptance against an operator's real project.
