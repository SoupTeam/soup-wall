#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
command -v docker >/dev/null
command -v certutil >/dev/null
backend="${1:-sqlite}"
case "$backend" in sqlite|postgres) ;; *) echo 'usage: keycloak-saml-linux.sh [sqlite|postgres]' >&2; exit 2;; esac
cargo build --locked -p llm-firewall --bin llm-firewall --example keycloak-saml-bootstrap
out="${SAML_EVIDENCE_DIR:-target/saml-evidence}"
mkdir -p "$out"
python3 scripts/sso_acceptance_batch.py --protocol saml --backend "$backend" --runs "${SSO_RUNS:-1}" \
  --gateway target/debug/llm-firewall \
  --bootstrap-helper target/debug/examples/keycloak-saml-bootstrap \
  --artifact-label "$(git rev-parse HEAD)" \
  --out "$out/batch-$backend-$(date -u +%Y%m%dT%H%M%SZ)-$$"
