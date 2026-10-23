# Linux pilot toolchain pins (SOU-122)

This guide lets a second operator identify and select the same compiler and interpreter
inputs as the internal Linux pilot candidate, and see a clear refusal when anything drifts.

## What is pinned

The single source of truth is `profiles/toolchain/linux-pilot-toolchain.json`.

| Input | Pin | Declared in |
| --- | --- | --- |
| Rust compiler | `1.99.1` (commit prefix `58cf8f9c3`, host `x86_64-unknown-linux-gnu`) | `rust-toolchain.toml`, `dtolnay/rust-toolchain@1.99.1` in workflows |
| Cargo dependencies | `Cargo.lock`, built with `--locked` | `Cargo.lock` |
| Classifier Python | CPython >= 3.9, supplied explicitly | pins file |
| Git runtime Python | CPython 3.11.14, pinned archive digest | `profiles/mcp/git-readonly-v1/upstream-identity.json` |
| Git runtime packages | `requirements.lock` digest | same identity file |
| Filesystem server packages | `package-lock.json` digest | `profiles/mcp/filesystem-readonly-v1/upstream-identity.json` |
| Build scripts | digests recorded in every report | pins file `build_scripts` |

`rust-toolchain.toml` and the workflows previously used the floating `stable` channel.
They now name `1.99.1`. A version-shaped action ref (for example `@1.99.1`) is a movable
branch, not proof that a release exists; the report therefore checks the real `rustc -Vv`
output (release, commit hash, host) instead of trusting the ref.

## Native Ubuntu lane (stays on 1.94.1)

The `native-ubuntu-2404` job in `mcp-real-filesystem.yml` and the source-build entry point
(`scripts/build-native-pilot-inputs.py`) deliberately keep Rust **1.94.1**, selected by an explicit
`RUSTUP_TOOLCHAIN=1.94.1` override that wins over `rust-toolchain.toml`. That job runs

```
python3 scripts/verify-pilot-toolchain.py --lane native --python "$(command -v python3)" --expected-commit "$(git rev-parse HEAD)" --output "$RUNNER_TEMP/sou122-toolchain/native-attestation.json"
```

before building and uploads the report with the job artifacts. In this lane the compiler must be 1.94.1
(release, host, cargo), `RUSTUP_TOOLCHAIN` must be set to it, and the checked-in file must name 1.99.1.
The 1.94.1 commit hash is recorded in the report but is only enforced once pinned in the pins file.

## Separate older lane

Some existing acceptance workflows stay on `1.94.1` because their recorded results were produced
there. They are listed under `legacy_lane` in the pins file and are not silently upgraded. A
workflow using any other ref (including `stable`) is refused by the verifier.

Not covered by this command: Docker builder images (`deploy/Dockerfile*`, digest-pinned separately)
and the self-hosted Windows lane in `vps-ci.yml`, which still calls `rustup run stable`.
The report lists the declared Docker images but does not verify them.

## Verify

Run from a clean checkout of the exact commit, with the pinned toolchain installed beforehand
(the command never downloads or installs anything):

```
python3 scripts/verify-pilot-toolchain.py --python /absolute/path/to/python3 --expected-commit <40-hex-sha> --output /absolute/new/report.json
```

Options:

- `--lane native` attests the native 1.94.1 lane instead of the 1.99.1 pin.
- `--python-role git_runtime` attests the Git runtime interpreter (must be exactly 3.11.14).
- `--git-archive` and `--python-archive` digest-check locally supplied archives against their pins.
- `--allow-dirty` is for development only.

Exit code `0` means `verified`; `2` means `refused`. Each check in the report names what was
declared and what was resolved, including the real paths and SHA-256 of the selected `rustc` and `cargo`
executables (resolved through the compiler's sysroot) and of the interpreter executable. Every external command has a 20 second deadline.

Refusals include: floating or unrecorded compiler refs, `rustc`/`cargo` release, commit or host
differing from the pin, a missing toolchain, a missing or untracked `Cargo.lock`, a missing or
wrong interpreter, a digest differing from the profile identity, a missing build script, a dirty
tree, or a checkout that is not the expected commit.

## What "reproducible" means here

A `verified` report means a second operator selected the same source, compiler, lockfile,
interpreter and package inputs. It is reproducibility by source identity. Byte-for-byte identical
binaries are **not** claimed; compare the SHA-256 of two builds before saying so.

## Building and running the pilot

This command does not build anything. Use the existing flow:

1. `python3 scripts/prepare-installed-pilot.py` (plan) and then `--prepare` on native Ubuntu 24.04 x86_64.
2. `python3 scripts/qualify-installed-pilot.py` for the useful and refused-effect controls.

The one-command binary build entry point is owned by SOU-119; this guide does not replace it.
