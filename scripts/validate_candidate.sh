#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Preserve the existing entry point; strict JSON/custody/readiness share one gate.
set -euo pipefail
exec python3 "$(dirname -- "${BASH_SOURCE[0]}")/validate_candidate.py" "$@"