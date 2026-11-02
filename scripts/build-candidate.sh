#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 077
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"
[[ "$(uname -s)-$(uname -m)" == Linux-x86_64 ]] || { echo 'Linux x86-64 required' >&2; exit 1; }
# Matches the accepted native pilot build entry point, independently of rustup defaults.
export RUSTUP_TOOLCHAIN=1.94.1 RUSTUP_AUTO_INSTALL=0
[[ "$(rustc --version)" == 'rustc 1.94.1 '* ]] || { echo 'Exact native Rust 1.94.1 required' >&2; exit 1; }
[[ -z "$(git status --porcelain --untracked-files=all)" ]] || { echo 'Clean committed source required' >&2; exit 1; }
export CANDIDATE_EXPECTED_COMMIT="$(git rev-parse HEAD)"
: "${CANDIDATE_BWRAP:?Supply the reviewed bubblewrap 0.13.1 binary}"
: "${CANDIDATE_BWRAP_SHA256:?Supply its independently recorded SHA-256}"
echo "$CANDIDATE_BWRAP_SHA256  $CANDIDATE_BWRAP" | sha256sum --check --status
[[ "$("$CANDIDATE_BWRAP" --version)" == 'bubblewrap 0.13.1' ]] || exit 1
"$CANDIDATE_BWRAP" --help | grep -q -- --ro-bind-fd
NODE_TAR=node-v22.23.4-linux-x64.tar.xz
TARGET_DIR="$ROOT/target/soup-wall-linux-amd64"
[[ ! -e "$TARGET_DIR" && ! -e "$TARGET_DIR.tar.gz" ]] || { echo 'Candidate output already exists; retain it and choose a fresh checkout' >&2; exit 1; }
mkdir -p "$TARGET_DIR/bin" "$TARGET_DIR/assets" "$TARGET_DIR/scripts" "$TARGET_DIR/profiles/mcp" "$TARGET_DIR/npm-cache" "$TARGET_DIR/upstream-notices"
# One affected binary, no all-platform matrix or release publication.
cargo build --locked -p agentfw --bin agentfw
cp "${CARGO_TARGET_DIR:-$ROOT/target}/debug/agentfw" "$TARGET_DIR/bin/"
cp "$CANDIDATE_BWRAP" "$TARGET_DIR/bin/bwrap"
"$TARGET_DIR/bin/agentfw" classifier-package build --classifier rev2 --source "$ROOT" --out "$TARGET_DIR/assets/baseline.classifier"
while IFS= read -r -d '' path; do
    mkdir -p "$TARGET_DIR/$(dirname "$path")"
    cp "$path" "$TARGET_DIR/$path"
done < <(git ls-files -z rule_baseline)
for file in install-sou62-filesystem-profile.py pilot_provider.py pilot_filesystem_roots.py; do
    cp "scripts/$file" "$TARGET_DIR/scripts/"
done
cp -R profiles/mcp/filesystem-readonly-v1 "$TARGET_DIR/profiles/mcp/"
cp Cargo.lock rust-toolchain.toml LICENSE NOTICE "$TARGET_DIR/"
if [[ -n "${CANDIDATE_NODE_ARCHIVE:-}" ]]; then
    cp "$CANDIDATE_NODE_ARCHIVE" "$TARGET_DIR/$NODE_TAR"
else
    curl --fail --location --max-time 300 "https://nodejs.org/dist/v22.23.4/$NODE_TAR" --output "$TARGET_DIR/$NODE_TAR"
fi
echo "1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce  $TARGET_DIR/$NODE_TAR" | sha256sum --check --status
# Retain the exact redistributed sandbox license from the pinned source archive.
if [[ -n "${CANDIDATE_BWRAP_ARCHIVE:-}" ]]; then
    cp "$CANDIDATE_BWRAP_ARCHIVE" "$TARGET_DIR/assets/bubblewrap-0.13.1.tar.xz"
else
    curl --fail --location --max-time 120 https://github.com/containers/bubblewrap/releases/download/v0.13.1/bubblewrap-0.13.1.tar.xz --output "$TARGET_DIR/assets/bubblewrap-0.13.1.tar.xz"
fi
echo "0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d  $TARGET_DIR/assets/bubblewrap-0.13.1.tar.xz" | sha256sum --check --status
tar -xOf "$TARGET_DIR/assets/bubblewrap-0.13.1.tar.xz" bubblewrap-0.13.1/COPYING > "$TARGET_DIR/upstream-notices/bubblewrap-COPYING"
NODE_STAGE=$(mktemp -d -t candidate-node-XXXXXX)
trap 'rm -rf "$NODE_STAGE"' EXIT
tar -xf "$TARGET_DIR/$NODE_TAR" -C "$NODE_STAGE"
export PATH="$NODE_STAGE/node-v22.23.4-linux-x64/bin:$PATH"
# npm lifecycle scripts and mutable registry audit are never run here.
(cd "$TARGET_DIR/profiles/mcp/filesystem-readonly-v1" && npm ci --ignore-scripts --no-audit --no-fund --logs-max=0 --cache "$TARGET_DIR/npm-cache")
# npm diagnostic logs contain the preparation checkout's absolute path.
rm -rf "$TARGET_DIR/npm-cache/_logs"
# Include transitive notices with the exact lock graph before removing installed packages.
python3 scripts/candidate_manifest.py "$TARGET_DIR"
rm -rf "$TARGET_DIR/profiles/mcp/filesystem-readonly-v1/node_modules"
[[ "$(git rev-parse HEAD)" == "$CANDIDATE_EXPECTED_COMMIT" && -z "$(git status --porcelain --untracked-files=all)" ]] || {
    echo 'Source changed during candidate preparation; output is not accepted' >&2; exit 1;
}
python3 scripts/candidate_manifest.py "$TARGET_DIR" --finalize
tar -czf "$TARGET_DIR.tar.gz" -C "$ROOT/target" soup-wall-linux-amd64
sha256sum "$TARGET_DIR.tar.gz"
