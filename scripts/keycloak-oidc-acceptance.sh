#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null
command -v certutil >/dev/null
cargo build --locked -p llm-firewall --bin llm-firewall --example keycloak-oidc-bootstrap
mkdir -p target/oidc-evidence
python3 scripts/keycloak-oidc-acceptance.py --docker \
  --gateway target/debug/llm-firewall \
  --bootstrap-helper target/debug/examples/keycloak-oidc-bootstrap \
  --artifact-label "$(git rev-parse HEAD)" \
  --out "target/oidc-evidence/acceptance-$(date -u +%Y%m%dT%H%M%SZ).json"
