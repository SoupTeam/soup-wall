#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# One focused command from a fresh checkout; system prerequisites are documented.
set -euo pipefail
cd "$(dirname "$0")/.."
protocol="${1:-oidc}"
backend="${2:-sqlite}"
runs="${3:-1}"
case "$protocol/$backend/$runs" in
  oidc/sqlite/[12]|oidc/postgres/[12]|saml/sqlite/[12]|saml/postgres/[12]) ;;
  *) echo 'usage: sso-acceptance.sh [oidc|saml] [sqlite|postgres] [1|2]' >&2; exit 2 ;;
esac
command -v docker >/dev/null
command -v certutil >/dev/null
command -v cargo >/dev/null
mkdir -p target
driver="$(mktemp -d "$PWD/target/sso-driver-XXXXXXXX")"
python3 -m venv "$driver"
"$driver/bin/python" -m pip install requests==2.34.2 cryptography==50.0.2 psutil==7.2.2 playwright==1.63.0
"$driver/bin/python" -m playwright install chromium
export PATH="$driver/bin:$PATH"
export SSO_RUNS="$runs"
if [[ "$protocol" == oidc ]]; then
  bash scripts/keycloak-oidc-acceptance.sh "$backend"
else
  bash scripts/keycloak-saml-linux.sh "$backend"
fi
