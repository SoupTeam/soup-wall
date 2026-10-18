#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Exact-source Linux profile, owned connection, and real-process verification.
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo 'SOU-78 Linux checks require Linux' >&2
  exit 2
fi

if [[ ${1:-} == --isolated ]]; then
  rustc --version > "$SOU78_EVIDENCE/toolchain.txt"
  cargo --version > "$SOU78_EVIDENCE/cargo-version.txt"
  run_check() {
    local label=$1
    shift
    set +e
    "$@" > "$SOU78_EVIDENCE/$label.log" 2>&1
    local result=$?
    set -e
    printf '%s\n' "$result" > "$SOU78_EVIDENCE/$label.exit"
    # Retain complete logs as artifacts; console only gives bounded diagnostics.
    tail -n 24 "$SOU78_EVIDENCE/$label.log"
    return "$result"
  }
  run_check fmt cargo fmt --all -- --check
  run_check clippy cargo clippy --offline --locked -p agentfw --all-targets -- -D warnings
  run_check provenance cargo test --offline --locked -p soup-wall-agent
  run_check library cargo test --offline --locked -p agentfw --lib
  run_check native cargo test --offline --locked -p agentfw --test native_endpoint
  run_check hooks cargo test --offline --locked -p agentfw --test hook_endpoint
  run_check protection cargo test --offline --locked -p agentfw --test protection_status
  run_check owned python3 -I scripts/verify-sou78-owned.py --agentfw "$CARGO_TARGET_DIR/debug/agentfw" --out "$SOU78_EVIDENCE/owned-process.json"
  run_check profiles cargo test --offline --locked -p agentfw --test mcp_profile_lifecycle
  run_check daemon cargo test --offline --locked -p agentfw --test lifecycle
  run_check admission cargo test --offline --locked -p agentfw --test mcp_admission
  exit 0
fi

command -v docker >/dev/null
: "${RUNNER_TEMP:?an owned disposable runner directory is required}"
proof="$RUNNER_TEMP/sou78-linux"
mkdir "$proof"
mkdir "$proof/source" "$proof/target" "$proof/tmp" "$proof/evidence" "$proof/cargo-home"
# Export the committed tree, never the runner's authentication/checkout metadata.
git archive HEAD | tar -x -C "$proof/source"
git rev-parse HEAD > "$proof/evidence/source-commit.txt"
(
  cd "$proof/source"
  find . -type f -print0 | sort -z | xargs -0 sha256sum
) > "$proof/evidence/source-sha256.txt"
rustc --version > "$proof/evidence/toolchain.txt"
# Build only a standard toolchain image here; no target source is copied into it.
# No host kernel/AppArmor setting is changed. Compilation/tests run as the runner
# UID in a read-only container with no external network and no capabilities.
cat > "$proof/Dockerfile" <<'DOCKERFILE'
FROM rust:1-bookworm
RUN apt-get update && apt-get install --no-install-recommends -y python3 cmake bubblewrap && rm -rf /var/lib/apt/lists/*
RUN rustup component add clippy rustfmt
# The repository asks for stable. Link the image's installed toolchain under a
# custom name so rustup never tries to refresh it inside the read-only container.
RUN rustup toolchain link sou78 "$(rustc --print sysroot)"
ENV RUSTUP_TOOLCHAIN=sou78
DOCKERFILE
printf '*\n!Dockerfile\n' > "$proof/.dockerignore"
image="sou78-linux:$(git rev-parse --short=12 HEAD)"
docker build --tag "$image" "$proof" > "$proof/evidence/image-build.log" 2>&1
docker image inspect "$image" --format '{{.Id}}' > "$proof/evidence/image-id.txt"
# Dependency retrieval does not run target package build scripts. The source is
# read-only during retrieval. Cargo's package cache is the only writable input.
docker run --rm --read-only --user "$(id -u):$(id -g)" \
  --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,src=$proof/source,dst=/source,readonly" \
  --mount "type=bind,src=$proof/cargo-home,dst=/cargo-home" \
  --env CARGO_HOME=/cargo-home --workdir /source \
  "$image" cargo fetch --locked > "$proof/evidence/fetch.log" 2>&1
docker run --rm --read-only --network none --user "$(id -u):$(id -g)" \
  --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,src=$proof,dst=$proof" \
  --env "CARGO_HOME=$proof/cargo-home" \
  --env "CARGO_TARGET_DIR=$proof/target" \
  --env "TMPDIR=$proof/tmp" \
  --env "SOU78_EVIDENCE=$proof/evidence" \
  --workdir "$proof/source" \
  "$image" /bin/bash scripts/verify-sou78-linux.sh --isolated
