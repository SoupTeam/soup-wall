#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
# Fresh owned inputs; do not consume an arbitrary checkout or ambient provider.
test ! -e target/sou85-upstream
test ! -e target/sou85-driver
test ! -e target/sou85-offline
git -c core.autocrlf=false clone --filter=blob:none --no-checkout \
  https://github.com/ethz-spylab/agentdojo.git target/sou85-upstream
git -C target/sou85-upstream config core.autocrlf false
git -C target/sou85-upstream sparse-checkout set src
git -C target/sou85-upstream checkout 089ed468cf3ed0322acc66b0211f26d9d90dbf60
python3 -m venv target/sou85-driver
target/sou85-driver/bin/python -m pip install --disable-pip-version-check -r scripts/benchmarks/agentdojo-live.requirements.txt
cargo build --locked -p agentfw --bin agentfw
target/sou85-driver/bin/python -B -m unittest discover -s scripts/benchmarks -p test_agentdojo_workspace.py -v
target/sou85-driver/bin/python -B scripts/agentdojo-live.py --mode workspace-fixture \
  --upstream-checkout target/sou85-upstream --agent-binary target/debug/agentfw \
  --report-out target/sou85-offline
