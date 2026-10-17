#!/usr/bin/env bash
# SOU-64: clean-directory lifecycle of the installable classifier package (Linux).
# Usage: scripts/classifier-runtime-demo.sh [path-to-agentfw] [path-to-python3]
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
bin="${1:-$repo/target/debug/agentfw}"
py="${2:-/usr/bin/python3}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export HOME="$work/home"; mkdir -m 700 "$HOME"
unset AGENTFW_RULE_BASELINE AGENTFW_CLASSIFIER
run() { echo "\$ agentfw $*"; "$bin" "$@"; echo; }
# Build is the only step that reads the repository; everything after runs from an empty directory.
run classifier-package build --classifier frozen --source "$repo" --out "$work/frozen.tar"
run classifier-package build --classifier rev2   --source "$repo" --out "$work/rev2.tar"
cd "$work"
run classifier-package preview frozen.tar --python "$py"
run classifier-package install frozen.tar --python "$py"
run classifier-package verify
run classifier-package install rev2.tar --python "$py"
run classifier-package rollback
run classifier-package inspect
echo "# repository path appears nowhere in the installed profile:"
if grep -rl "$repo" "$HOME" >/dev/null 2>&1; then echo "FOUND"; exit 1; else echo "none"; fi
run classifier-package remove --all
ls -A "$HOME"
