# Native Linux pilot runtime preparation

`scripts/prepare-installed-pilot.py` prepares the accepted original filesystem
and Git server profiles and writes a `sw-installed-pilot-selection/2` manifest.
It does **not** start Agent, Claude or the enforcing daemon. To launch a completed
prepared selection with an owned enforcing daemon, use the explicit
[prepared pilot-run entry point](PREPARED_PILOT_RUN.md). Only a separate
successful [installed-pilot qualification](INSTALLED_PILOT_QUALIFICATION.md)
can establish the selected runtime's observed behavior.

For a verified non-root build of the Git and bubblewrap inputs, follow
[native prerequisite preparation](PILOT_NATIVE_PREREQUISITES.md) first and
pass its emitted absolute paths as `--git` and `--bwrap` below.
For the three caller-supplied Agent binaries, follow
[native Agent source build](PILOT_SOURCE_BUILD.md) and pass its emitted paths
as `--agentfw`, `--git-launcher`, and `--sandbox-tests`.

## Inputs

Use a clean, reviewed Git checkout on native Ubuntu 24.04 x86_64 as a non-root
operator. Supply the already built Agent, Git sandbox launcher and Agent library
test executable; the exact Claude Code host executable; both selected single-file
classifiers; the selected policy; Python, bubblewrap and Git executables. The
existing [real-filesystem workflow](../../.github/workflows/mcp-real-filesystem.yml)
shows how these selected binaries are built. Preparation does not build Agent,
Claude, classifiers or the policy, and it never reads provider credentials.

The accepted Node archive is
`node-v22.22.0-linux-x64.tar.xz` from
`https://nodejs.org/dist/v22.22.0/`, SHA-256
`9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37`.
Provide it locally with `--node-archive`. Alternatively provide an already
extracted exact Node and npm with `--node` and `--npm`. The Node executable
digest must match the reviewed filesystem installer. The selected Git must
report 2.51.2; its source archive and SHA-256 are in the checked-in
`git-readonly-v1/upstream-identity.json`. Bubblewrap must support
`--ro-bind-fd`. Missing native libraries fail preparation.

Default invocation lists missing inputs without creating directories. Add
`--prepare` only when the inventory is complete:

```sh
python3 -B scripts/prepare-installed-pilot.py \
  --output "$HOME/private-pilot-preparation" --expected-commit "$(git rev-parse HEAD)" \
  --agentfw "$PWD/target/debug/agentfw" \
  --git-launcher "$PWD/target/debug/agentfw-git-sandbox" \
  --sandbox-tests /absolute/agentfw-library-test-executable \
  --node-archive /absolute/node-v22.22.0-linux-x64.tar.xz \
  --bwrap /absolute/bwrap --git /absolute/git-2.51.2/git \
  --claude /absolute/claude --python /absolute/python3 \
  --filesystem-classifier "$PWD/rule_baseline/rule_baseline.py" \
  --git-classifier "$PWD/rule_baseline/git_readonly_v1/rule_baseline.py" \
  --policy /absolute/selected-pilot-policy.yaml
```

For the fully local path, also supply `--python-archive` with the exact pinned
Python 3.11.14 archive, a private `0700` `--npm-cache` containing the locked npm
packages and a private `0700` `--wheelhouse` containing all hashed Git server
wheels. Their names, versions and hashes are in the accepted installers and
`profiles/mcp/git-readonly-v1/requirements.lock`. A missing local package fails
closed. Add `--allow-download` to the same command when those package caches are
unavailable. This explicitly permits only the accepted installers' pinned
Python archive download and locked npm/pip resolution during preparation;
the original server entrypoints, profile registry, package trees and runtime
dependencies are verified afterwards. No protected launch downloads anything.
The supplied local Python archive takes precedence over its download. No sudo,
global install or host security setting change is part of this command.

After reviewing the plan, repeat the command with `--prepare`. The JSON result
contains `selection`, an absolute private path. A second identical `--prepare`
returns `reused` only after revalidating the exact selected files, profile
receipts, registry, package trees, libraries and source. Then qualify separately:

```sh
python3 -B scripts/qualify-installed-pilot.py --run \
  --selection /absolute/private-pilot-preparation/generations/GENERATION/selection.json \
  --expected-commit "$(git rev-parse HEAD)" \
  --output /absolute/private/new-qualification-run
```

The manifest is the qualifier's normal caller-attested selection, not a signed
publisher attestation. Its additional `prepared_profiles` field binds the two
prepared profile receipts; the qualifier still independently validates its
normal source and file identities, and runs its accepted original-server
exercise. Preparation is not persistent onboarding or a launcher.

## Recovery and support boundary

The output must be outside the checkout, owned by the current user and `0700`.
Each attempt uses a new private generation. A failed or interrupted generation
has no completion marker; the previous `current.json` remains selected. A wrong
digest, changed cached package, symlink escape or missing native dependency
fails closed. Keep the first failure for diagnosis. Fix the input or cache,
then rerun with `--prepare --rebuild`; the previous generation and unrelated
files remain. Do not edit a prepared generation to repair it. Reuse checks the
completion marker and all selected assets again. If the source commit changes,
build and select that exact candidate and use a new qualification output.

Only native Ubuntu 24.04 x86_64 is supported here. WSL, macOS and Windows are
not qualified by a native Ubuntu run. The registered
[real-filesystem workflow](../../.github/workflows/mcp-real-filesystem.yml)
retains the initial digest failure, clean/repeated preparation evidence and
the exact installed-pilot qualification report. A green preparation result by
itself is not a green enforcing-daemon result.

The selected bubblewrap also needs permission to create its isolated network
namespace. On the tested GitHub Ubuntu 24.04 runner, the native qualification's
positive sandbox control failed before the server started: both direct and
descriptor-pinned bubblewrap reported `loopback: Failed RTM_NEWADDR: Operation
not permitted` with the runner's AppArmor unprivileged-user-namespace
restriction enabled. The original failure remains retained. For this disposable
GitHub-hosted job, CI now provisions a root-owned copy of the exact hashed
bubblewrap and an AppArmor `userns` profile attached only to that job's copy.
This is runner administration, separate from the unprivileged product preparation
command. It follows Ubuntu's application-specific profile mechanism:
[Ubuntu 24.04 user namespace restrictions](https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions).

The host restriction stays enabled. The helper requires native Ubuntu 24.04,
an explicit GitHub-hosted job identity and a non-root qualifier. Before the
original-server qualification, both direct and descriptor-pinned execution must
prove separate user/network/mount/PID namespaces, read-only bindings, refusal of
nested user namespaces, zero effective capabilities and no connection to an
independent host listener. The unapproved original path must remain refused.
The owned profile and binary are removed in an `always()` cleanup step; foreign
files or operator edits cause refusal rather than deletion. No shared VPS, local
machine, global sysctl, AppArmor service or runtime enforcement policy is changed.

For a focused CI environment check, dispatch `mcp-real-filesystem.yml` on the
candidate branch with `native_preparation_only: true`. This omits the duplicate
Ubuntu 22.04 lane only for that explicit manual run; normal Ready CI still
requires every selected job. A passing provisioning probe is not pilot
qualification: the full enforcing-daemon/original-server qualifier must also pass.
Do not disable AppArmor, remove network isolation, or treat prepared assets as an
active pilot when either control fails.
