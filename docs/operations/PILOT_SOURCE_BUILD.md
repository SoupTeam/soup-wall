# Native Linux pilot Agent source build

`scripts/build-native-pilot-inputs.py` builds the three caller-supplied Agent
executables required by [pilot runtime preparation](PILOT_RUNTIME_PREPARATION.md):
`agentfw`, `agentfw-git-sandbox`, and the Agent library test executable that
runs the positive filesystem and Git sandbox controls. It does not prepare
profiles, start an enforcing daemon, or establish active protection.

## Plan and build

Use a clean, reviewed checkout on native Ubuntu 24.04 x86_64 as a non-root
operator. Select an absolute private output directory outside the checkout.
The default invocation is a read-only inventory: it reports missing native
compiler inputs and does not create an output directory, install software, or
build anything. Arrange for any missing inputs through the host's approved
process before continuing. The script requires the exact Rust 1.94.1 toolchain
used by the [native CI workflow](../../.github/workflows/mcp-real-filesystem.yml)
and the repository's `Cargo.lock`; it does not select an ambient floating
`stable` toolchain. The root `rust-toolchain.toml` currently names `stable`,
so that file alone is not an exact build identity. There is no automatic
`rustup`, package manager, or system installation step.
An explicit `--build` fetches dependencies pinned by `Cargo.lock` into a
generation-private Cargo home; `--locked` rejects lockfile changes. That cache
and the Cargo target tree are removed after the build. The read-only plan
does not fetch dependencies or inspect any global Cargo configuration.

```sh
commit="$(git rev-parse HEAD)"
source_args=(--output "$HOME/private-pilot-agent-build" --expected-commit "$commit")
python3 -B scripts/build-native-pilot-inputs.py "${source_args[@]}"
```

Review the JSON plan and resolve every missing input before adding `--build`.
The source build uses the checked-in lockfile and exact source tree; it places
Cargo outputs in an owned, bounded external generation, leaving the checkout
and unrelated files alone. Build logs and the versioned receipt stay private.
The build enforces a 20-minute limit per Cargo phase, monitors the temporary
generation against an 8 GiB / 200,000-entry limit every two seconds, caps each
phase log at 1 MiB, and checks the 512 MiB completed-generation limit before
publishing.
Cargo may remove temporary files or child directories during a quota scan.
Entries that disappear after enumeration are treated as removed. A missing
generation root, unreadable entries or other inventory errors still fail closed;
the byte, entry and time limits are unchanged.

```sh
build_result="$(python3 -B scripts/build-native-pilot-inputs.py --build "${source_args[@]}")"
printf '%s\n' "$build_result"
agentfw="$(printf '%s\n' "$build_result" | python3 -c 'import json,sys; print(json.load(sys.stdin)["agentfw"])')"
git_launcher="$(printf '%s\n' "$build_result" | python3 -c 'import json,sys; print(json.load(sys.stdin)["git_launcher"])')"
sandbox_tests="$(printf '%s\n' "$build_result" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sandbox_tests"])')"
```

The JSON result includes `status`, the three absolute executable paths,
`receipt`, and `build_seconds`. The private receipt binds the clean commit and
tree, lockfile, exact compiler and build options, and output hashes. A repeated
`--build` returns `reused` only after revalidating the completed generation;
`--build --rebuild` creates a fresh generation. Changed source, modified or
non-executable output, a wrong digest, or an interrupted build must fail
closed. An unsuccessful attempt must leave the last selected generation and
unrelated files intact. Keep its first bounded failure record and private
logs for diagnosis; do not publish raw build logs as evidence.
Unexpected errors include the source function and line, without exporting private paths.

## Use with the accepted preparation and qualification

[Native prerequisite preparation](PILOT_NATIVE_PREREQUISITES.md) separately
builds the pinned Git and bubblewrap inputs. It does not build these Agent
binaries. Obtain its emitted `git` and `bwrap` paths, then supply all other
reviewed inputs to the existing SOU-111 command. For example:

```sh
python3 -B scripts/prepare-installed-pilot.py \
  --output "$HOME/private-pilot-preparation" --expected-commit "$commit" \
  --agentfw "$agentfw" --git-launcher "$git_launcher" \
  --sandbox-tests "$sandbox_tests" \
  --node-archive /absolute/node-v22.22.0-linux-x64.tar.xz \
  --bwrap "$bwrap_path" --git "$git_path" \
  --claude /absolute/claude --python /absolute/python3 \
  --filesystem-classifier "$PWD/rule_baseline/rule_baseline.py" \
  --git-classifier "$PWD/rule_baseline/git_readonly_v1/rule_baseline.py" \
  --policy /absolute/selected-pilot-policy.yaml \
  --python-archive /absolute/pinned-python.tar.gz \
  --npm-cache /absolute/private-npm-cache --wheelhouse /absolute/private-wheelhouse
```

That first invocation is the read-only SOU-111 plan. Repeat the same command
with `--prepare` only after reviewing it. Its JSON result gives an absolute
`selection` path. Qualify that exact selection separately through the accepted
original-server driver:

```sh
python3 -B scripts/qualify-installed-pilot.py --run \
  --selection /absolute/private-pilot-preparation/generations/GENERATION/selection.json \
  --expected-commit "$commit" --output /absolute/private/new-qualification-run
```

Record clean build and original-server runtime durations separately from the
same native candidate. A successful build or preparation result is not an
active-protection claim; only the separate qualification can report observed
runtime behavior. Do not replace its positive sandbox controls with an
unqualified host or relaxed namespace settings.
