#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Linux foundation verification. Full SOU-78 production acceptance is separate.
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo 'SOU-78 Linux checks require Linux' >&2
  exit 2
fi

if [[ ${1:-} == --isolated ]]; then
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
  run_check library cargo test --offline --locked -p agentfw --lib
  run_check profiles cargo test --offline --locked -p agentfw --test mcp_profile_lifecycle
  run_check daemon cargo test --offline --locked -p agentfw --test lifecycle
  run_check admission cargo test --offline --locked -p agentfw --test mcp_admission
  exit 0
fi

command -v bwrap >/dev/null
: "${RUNNER_TEMP:?an owned disposable runner directory is required}"
proof="$RUNNER_TEMP/sou78-linux"
mkdir "$proof"
mkdir "$proof/source" "$proof/target" "$proof/tmp" "$proof/evidence" "$proof/cargo-home"
# Export the committed tree, never the runner's authentication/checkout metadata.
git archive HEAD | tar -x -C "$proof/source"
git rev-parse HEAD > "$proof/evidence/source-commit.txt"
(
  cd "$proof/source"
  find crates scripts -type f -print0 | sort -z | xargs -0 sha256sum
) > "$proof/evidence/source-sha256.txt"
rustc --version > "$proof/evidence/toolchain.txt"
# Dependency retrieval does not execute package build scripts. Execution below is
# offline, with a writable disposable copy and a read-only original checkout.
CARGO_HOME="$proof/cargo-home" cargo fetch --locked --manifest-path "$proof/source/Cargo.toml"
bwrap --die-with-parent --unshare-net \
  --ro-bind / / --bind "$proof" "$proof" --dev /dev --proc /proc \
  --chdir "$proof/source" \
  --setenv CARGO_HOME "$proof/cargo-home" \
  --setenv CARGO_TARGET_DIR "$proof/target" \
  --setenv TMPDIR "$proof/tmp" \
  --setenv SOU78_EVIDENCE "$proof/evidence" \
  /bin/bash scripts/verify-sou78-linux.sh --isolated
