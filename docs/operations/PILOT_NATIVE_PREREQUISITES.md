# Native pilot Git and bubblewrap prerequisites

`scripts/prepare-native-pilot-prerequisites.py` replaces the two manual source
builds needed before [pilot runtime preparation](PILOT_RUNTIME_PREPARATION.md).
It builds only Git 2.51.2 and bubblewrap 0.13.1 for native Ubuntu 24.04 x86_64.
It does not install packages, alter the host, grant user namespace permission,
start the daemon, or claim active protection.

## Inputs and inventory

Use a clean reviewed checkout as a non-root operator. The output prefix must be
an absolute, private `0700` directory outside the checkout. The default plan
does not create it. Supply local archives for a fully offline prerequisite
build, or explicitly add `--allow-download`. The only download targets are:

| Input | Exact URL | SHA-256 |
| --- | --- | --- |
| Git 2.51.2 | `https://www.kernel.org/pub/software/scm/git/git-2.51.2.tar.xz` | `233d7143a2d58e60755eee9b76f559ec73ea2b3c297f5b503162ace95966b4e3` |
| bubblewrap 0.13.1 | `https://github.com/containers/bubblewrap/releases/download/v0.13.1/bubblewrap-0.13.1.tar.xz` | `0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d` |

The plan inventories `cc`, `make`, Meson, Ninja, `pkg-config`, `ar`, `ranlib`,
`ldd`, `readelf`, and the `libcap` and `zlib` development packages. On Ubuntu,
the corresponding packages are `build-essential`, `meson`, `ninja-build`,
`pkg-config`, `binutils`, `libcap-dev`, and `zlib1g-dev`. Have the host owner
provide missing dependencies through the approved host process; this command
never invokes `sudo` or a package manager. A private Meson Python path and a
private `libcap.pc` directory can instead be supplied with
`--meson-pythonpath`, `--pkg-config-libdir`, and `--pkg-config-sysroot`, as in
the [native CI lane](../../.github/workflows/mcp-real-filesystem.yml).

```sh
commit="$(git rev-parse HEAD)"
archive_args=(
  --git-archive /absolute/git-2.51.2.tar.xz
  --bwrap-archive /absolute/bubblewrap-0.13.1.tar.xz
)
args=(--output "$HOME/private-native-prerequisites" --expected-commit "$commit" "${archive_args[@]}")
python3 -B scripts/prepare-native-pilot-prerequisites.py "${args[@]}"
```

An incomplete plan lists exact missing prerequisites. It does not count as a
successful preparation. Add `--allow-download` only when the selected local
archive is unavailable; a failed download or wrong digest never selects an
ambient binary, alternate mirror, version, or hash. Both archives are fully
checked before extraction. The archive and build bounds are 64 MiB for Git,
16 MiB for bubblewrap, 12,000 entries, 512 MiB total expanded bytes, 64 MiB
per member, 1 MiB per private build log, 10 minutes for Git and 7 minutes
for bubblewrap setup/compile. The build environment passes only selected tool
paths and a small fixed set of variables. On timeout or cancellation it stops
the owned process group.

## Prepare, reuse, and select for the accepted runtime

```sh
result="$(python3 -B scripts/prepare-native-pilot-prerequisites.py --prepare "${args[@]}")"
printf '%s\n' "$result"
git_path="$(printf '%s\n' "$result" | python3 -c 'import json,sys; print(json.load(sys.stdin)["git"])')"
bwrap_path="$(printf '%s\n' "$result" | python3 -c 'import json,sys; print(json.load(sys.stdin)["bwrap"])')"
```

The result reports `prepared-not-qualified`, absolute Git/bubblewrap paths,
and the private receipt. That receipt binds the reviewed source commit,
archive digests, compiler/tool hashes, fixed flags, output hashes and native
library hashes. A repeated `--prepare` returns `reused` only after checking
the completed generation again. `--prepare --rebuild` creates another private
generation; a failure leaves `current.json`, the last valid generation, and
unrelated files intact. The first bounded failure record stays in
`first-failure.json`; raw build logs stay private in the incomplete generation.
Do not copy those logs into a public issue or PR.

Pass the two emitted paths directly to the existing SOU-111 interface. Supply
the remaining reviewed inputs described in
[pilot runtime preparation](PILOT_RUNTIME_PREPARATION.md):

```sh
python3 -B scripts/prepare-installed-pilot.py --prepare \
  --output "$HOME/private-pilot-preparation" --expected-commit "$commit" \
  --agentfw "$PWD/target/debug/agentfw" \
  --git-launcher "$PWD/target/debug/agentfw-git-sandbox" \
  --sandbox-tests /absolute/agentfw-library-test-executable \
  --node-archive /absolute/node-v22.22.0-linux-x64.tar.xz \
  --bwrap "$bwrap_path" --git "$git_path" \
  --claude /absolute/claude --python /absolute/python3 \
  --filesystem-classifier "$PWD/rule_baseline/rule_baseline.py" \
  --git-classifier "$PWD/rule_baseline/git_readonly_v1/rule_baseline.py" \
  --policy /absolute/selected-pilot-policy.yaml \
  --python-archive /absolute/pinned-python.tar.gz \
  --npm-cache /absolute/private-npm-cache --wheelhouse /absolute/private-wheelhouse
```

The SOU-111 result emits its own `selection` path. Qualify that selection in
a separate invocation of the original enforcing-daemon and two-server driver:

```sh
python3 -B scripts/qualify-installed-pilot.py --run \
  --selection /absolute/private-pilot-preparation/generations/GENERATION/selection.json \
  --expected-commit "$commit" --output /absolute/private/new-qualification-run
```

The [native CI lane](../../.github/workflows/mcp-real-filesystem.yml) tests
real namespace, read-only mount, network and positive sandbox controls before
the original two-server qualification. Its disposable runner has a separate,
job-scoped AppArmor permission for an exact copy of the prepared bubblewrap.
The local non-root bootstrap does not grant that permission. If a host refuses
the sandbox, report it as unavailable; never disable AppArmor, use setuid or
share the host network to turn preparation into a claimed qualification.
This run does not qualify WSL, Windows, macOS or live-model attack effectiveness.

## Native timing evidence

The native workflow publishes `native-timing.json` with the measured clean
Git/bubblewrap build duration, alongside a bounded summary of source and
binary hashes. Record the measured value from the exact reviewed run before
claiming a setup-time result. Archive acquisition and SOU-111 runtime/profile
preparation are separate intervals; the clean build time is not a full pilot
setup time.

On source `c8b9bd520b8345794254ac80e3b4f9d0e2f23753`, the [native Ubuntu
24.04 qualification run](https://github.com/SoupTeam/soup-wall/actions/runs/39759708725)
recorded **41 seconds** in `native-timing.json` for the clean Git and
bubblewrap build. The same run verified reuse, refused a wrong archive digest
without changing the selected generation, and completed the existing
installed-pilot qualification with 12 passed cases, no failed or incomplete
cases, and no remaining blockers. This timing excludes archive acquisition,
other prerequisite installation, Rust builds, SOU-111 preparation and the
two-server run. It is one hosted-run observation, not a setup-time guarantee.
