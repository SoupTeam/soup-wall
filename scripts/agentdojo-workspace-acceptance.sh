#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
# Fresh owned inputs; do not consume an arbitrary checkout or ambient provider.
# CI supplies RUNNER_TEMP so Rust target caches cannot restore stale inputs.
base="${1:-target/sou85-acceptance}"
mkdir -p target
mkdir "$base"
git -c core.autocrlf=false clone --filter=blob:none --no-checkout \
  https://github.com/ethz-spylab/agentdojo.git "$base/upstream"
git -C "$base/upstream" config core.autocrlf false
git -C "$base/upstream" sparse-checkout set src
git -C "$base/upstream" checkout 089ed468cf3ed0322acc66b0211f26d9d90dbf60
python3 -m venv "$base/driver"
"$base/driver/bin/python" -m pip install --disable-pip-version-check -r scripts/benchmarks/agentdojo-live.requirements.txt
cargo build --locked -p agentfw --bin agentfw
"$base/driver/bin/python" -B -m unittest discover -s scripts/benchmarks -p test_agentdojo_workspace.py -v
"$base/driver/bin/python" -B scripts/agentdojo-live.py --mode workspace-fixture \
  --upstream-checkout "$base/upstream" --agent-binary target/debug/agentfw \
  --report-out "$base/offline"
"$base/driver/bin/python" -B scripts/agentdojo-live.py --mode native-fixture \
  --upstream-checkout "$base/upstream" --agent-binary target/debug/agentfw \
  --evidence "$base/offline/legacy-native.json"
