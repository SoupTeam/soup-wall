#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null
command -v certutil >/dev/null
backend="${1:-sqlite}"
case "$backend" in sqlite|postgres) ;; *) echo 'usage: keycloak-oidc-acceptance.sh [sqlite|postgres]' >&2; exit 2;; esac
cargo build --locked -p llm-firewall --bin llm-firewall --example keycloak-oidc-bootstrap
mkdir -p target/oidc-evidence
python3 scripts/keycloak-oidc-acceptance.py --docker --backend "$backend" \
  --gateway target/debug/llm-firewall \
  --bootstrap-helper target/debug/examples/keycloak-oidc-bootstrap \
  --artifact-label "$(git rev-parse HEAD)" \
  --out "target/oidc-evidence/acceptance-$backend-$(date -u +%Y%m%dT%H%M%SZ).json"
