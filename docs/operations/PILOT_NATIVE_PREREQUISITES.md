# Native pilot Git and bubblewrap prerequisites

`scripts/prepare-native-pilot-prerequisites.py` replaces the two manual source
builds needed before [pilot runtime preparation](PILOT_RUNTIME_PREPARATION.md).
Concurrent calls use the [owned preparation protocol](PILOT_PREPARATION_COORDINATION.md).
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

### Private offline download exchange (SOU-194)

An explicit exchange moves only the two exact source archives above. The
uncompressed `sw-pilot-prerequisite-download-exchange/1` tar contains exactly
`manifest.json`, `git.tar.xz` and `bwrap.tar.xz`. The manifest binds each
version, accepted URL, SHA-256 and byte count. The importer checks the complete
inventory, member types, sizes, digest and the *current* repository pins before
publishing a selected cache. This is a source cache, not a built binary, sandbox
permission, selected runtime or active-protection claim. Compiler, Meson,
libcap and other native build dependencies remain separate host inputs.

Run these commands as a non-root operator from the same clean, reviewed source
commit on native Ubuntu 24.04 x86_64. Replace paths with owned private `0700`
directories outside the checkout. The online preparation uses the existing
download/build verifier; all other exchange operations require explicit flags.

```sh
commit="$(git rev-parse HEAD)"
online="$HOME/private-online-prerequisites"
fresh="$HOME/private-offline-prerequisites"
bundle_dir="$HOME/private-transfer"
mkdir -m 700 "$bundle_dir"
python3 -B scripts/prepare-native-pilot-prerequisites.py --cache-preview \
  --output "$online" --expected-commit "$commit"
python3 -B scripts/prepare-native-pilot-prerequisites.py --prepare --allow-download \
  --output "$online" --expected-commit "$commit"
python3 -B scripts/prepare-native-pilot-prerequisites.py --cache-export "$bundle_dir/pinned.tar" \
  --output "$online" --expected-commit "$commit"
# Transfer pinned.tar through the approved private channel; keep it owner-only.
python3 -B scripts/prepare-native-pilot-prerequisites.py --cache-import "$bundle_dir/pinned.tar" \
  --output "$fresh" --expected-commit "$commit"
python3 -B scripts/prepare-native-pilot-prerequisites.py --cache-preview \
  --output "$fresh" --expected-commit "$commit"
python3 -B scripts/prepare-native-pilot-prerequisites.py --prepare --offline-import-cache \
  --output "$fresh" --expected-commit "$commit"
```

Supply any required `--pkg-config-libdir`, `--pkg-config-sysroot` and
`--meson-pythonpath` arguments to both preparation calls; the archive exchange
does not supply them. The export destination must be absent, owner-private and
outside the cache root. A previous valid import is never overwritten. An owner
private filesystem must support unnamed `O_TMPFILE` creation and descriptor
linking: export, direct-cache seed and import selection publish the verified
inode through a pinned directory descriptor, without a replaceable named
temporary. An unsupported filesystem refuses the operation. Import rechecks
all staged member hashes after selecting the cache, and every later consumer
checks them again. An owner
interrupted before selection may retry the import: only known, private files
from its unselected stage are removed under the existing same-root lock;
unknown or unsafe entries cause refusal. A complete selected import is checked
again before each offline archive copy. The offline consumer never invokes the
download path, and a fresh root is required to demonstrate that it consumed
the import instead of reusing an already prepared generation. Import refuses a
root with an existing selected preparation. Keep the bundle
private; it contains source bytes and is not a release artifact.

The focused `cache_exchange_only` manual job in
[`mcp-real-filesystem.yml`](../../.github/workflows/mcp-real-filesystem.yml)
uses two private roots outside the checkout, records separate online/exchange/
offline timings, and executes the offline preparation in a disposable network
namespace. It retains finite JSON diagnostics for incomplete attempts. The
normal required CI, CodeQL and trusted admission remain separate gates.

### Resumable bubblewrap download (SOU-173)

The pinned bubblewrap 0.13.1 archive has an exact 129,472-byte length and the
SHA-256 above. With explicit `--prepare --allow-download`, the preparer keeps
its incomplete transfer in the owner's `0700` output root under
`download-cache/`. The SOU-139 preparation claim serializes same-root callers.
The `0600` versioned resume record binds the canonical URL, expected bytes,
full digest, partial inode, offset and a bounded history of failed attempts.
It is evidence, not authority: the complete archive is hashed against the
repository pin before reuse, extraction or selection. HTTP validators and
Content-Length are never accepted as a substitute for that digest.

Each explicit invocation makes at most one HTTP request. A matching strong
ETag permits a `Range` request; a valid `206` appends, and an ignored Range
(`200`) starts over from byte zero within the same request. Missing validators
start fresh. Changed validators, incorrect Content-Range, premature EOF,
unexpected `416`, over-limit data and digest mismatches refuse publication.
The transfer chain permits at most three attempts and at most twice the
existing 16 MiB compressed bound of transferred data, with the existing
120-second request budget, including connection, response headers, HTTPS
redirects and redirect bodies, and 25-second socket timeout. A cancellation or
disconnect retains only the recorded private prefix; an uncommitted tail is
discarded after the next identity and prefix check. No ambient proxy,
credentials or caller headers enter the download helper.

The JSON result includes finite `download_progress` counts for the selected
archive. A failed attempt reports its reason and retained/transferred bytes
without URLs, headers or private paths. Keep this evidence private; do not
publish the cache or a generation from a failed attempt. The existing
`first-failure.json` remains the first failure, while the resume record retains
up to three later transfer failures. On verified transfer, the bounded private
`bwrap.transfer-evidence.json` keeps those counts and failures after the resume
record is removed; this evidence is never archive authority. A completed cache
entry is rehashed on every use. An offline rebuild can use it with the exact
local Git archive:

```sh
python3 -B scripts/prepare-native-pilot-prerequisites.py --prepare --rebuild \
  --offline-bwrap-cache --output "$HOME/private-native-prerequisites" \
  --expected-commit "$commit" --git-archive /absolute/git-2.51.2.tar.xz
```

For an invalid or exhausted partial, inspect the bounded failure reason and
run a fresh explicit transfer with `--prepare --rebuild --allow-download
--clear-bwrap-cache` plus the other required inputs. That flag deletes only
the four identity-checked private bubblewrap cache names while holding the
same-root claim; it does not remove an installed generation or unrelated
files. The default inventory and ordinary pilot run/status/preview never
contact the network.

The native Ubuntu 24.04 job runs the local Range/disconnect/ownership controls
and `qualify-pilot-resumable-download.py --run` against the exact public pin.
Its accepted Git/bubblewrap preparation also selects the bwrap archive through
this explicitly consented transfer path, then builds, verifies and uses the
resulting binary in the existing original-server qualification.
Its `sou173-download.json` artifact records the complete transfer and offline
reuse byte counts, durations and extraction result. A failed job retains a
bounded failure report rather than treating a fixture or WSL result as native
qualification. Record the exact job SHA and artifact digest before citing it
as acceptance evidence.

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

### Explicit retry after a completed Git stage

If Git finished and its private stage checkpoint was published before a later
bubblewrap failure or cancellation, retry with the same output root and input
arguments, adding `--resume`:

```sh
python3 -B scripts/prepare-native-pilot-prerequisites.py --prepare --resume "${args[@]}"
```

The retry acquires the normal per-output preparation lock and verifies the
complete frozen Git stage before copying its verified binary into a new
generation. The checkpoint binds the clean source, pinned Git archive, build
recipe and flags, compiler/interpreter and native inputs, runtime libraries,
file modes, and bounded stage-tree digests. Bubblewrap is built normally, and
the final Git+bubblewrap receipt, hashes and runtime checks still run before
`current.json` changes. The result distinguishes built and reused stages and
reports their actual timings; preview/status commands do not build or select.

`--resume` refuses an absent, incomplete, mutable, unsafe or identity-mismatched
checkpoint. It never resumes compiler scratch or trusts a partial executable.
Inspect the bounded failure reason, then run `--prepare` without `--resume` to
start a fresh build after correcting the input or environment; use `--rebuild`
when a complete generation is already selected and a new one is intended.
Failed attempts remain private for diagnosis, and no failed or incomplete
generation becomes the selected runtime. Existing local archive arguments
keep this retry offline; network access still requires explicit
`--allow-download` under the same pins and bounds.

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
