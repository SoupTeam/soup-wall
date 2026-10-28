set -euo pipefail
cd "$SOU145_SOURCE"
python3 - <<'PY'
from pathlib import Path
import importlib.util,os
spec=importlib.util.spec_from_file_location('pilot','scripts/qualify-installed-pilot.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=Path(os.environ['SOU145_SCRATCH'])/'policy.yaml';m.owned_bytes(p,m.PILOT_POLICY.encode())
PY
mkdir -m 700 "$SOU145_SCRATCH/preparation"
status=0
python3 -B scripts/prepare-installed-pilot.py --prepare \
  --output "$SOU145_SCRATCH/preparation" --expected-commit dfa5366aba631cb8e79d831c3a69946fbdcf26ca \
  --agentfw "$SOU145_SCRATCH/target/debug/agentfw" --git-launcher "$SOU145_SCRATCH/target/debug/agentfw-git-sandbox" \
  --sandbox-tests "$(cat "$SOU145_SCRATCH/library-path.txt")" \
  --node "$SOU145_SCRATCH/node/bin/node" --npm "$SOU145_SCRATCH/node/bin/npm" \
  --bwrap "$SOU145_SELECTED_BWRAP" --git "$SOU145_SCRATCH/git-source/git" \
  --claude "$SOU145_SCRATCH/host/node_modules/@anthropic-ai/claude-code-linux-x64/claude" --python /usr/bin/python3 \
  --filesystem-classifier "$SOU145_SOURCE/rule_baseline/rule_baseline.py" --git-classifier "$SOU145_SOURCE/rule_baseline/git_readonly_v1/rule_baseline.py" \
  --policy "$SOU145_SCRATCH/policy.yaml" --npm-cache "$SOU145_SCRATCH/offline/npm-cache" \
  --python-archive "$SOU145_SCRATCH/offline/python.tar.gz" --wheelhouse "$SOU145_SCRATCH/offline/wheelhouse" > "$SOU145_SCRATCH/seed.json" || status=$?
if [ "$status" != 0 ]; then
  python3 -c 'import json,os,pathlib; r=json.loads((pathlib.Path(os.environ["SOU145_SCRATCH"])/"seed.json").read_text()); print({"status":r.get("status"),"reason":r.get("reason"),"stage":r.get("stage")})'
  exit "$status"
fi
selection="$(python3 -c 'import json,os,pathlib;print(json.loads((pathlib.Path(os.environ["SOU145_SCRATCH"])/"seed.json").read_text())["selection"])')"
python3 -B scripts/qualify-sou145-readiness.py --selection "$selection" \
  --expected-commit dfa5366aba631cb8e79d831c3a69946fbdcf26ca --strace /usr/bin/strace \
  --offline-inputs "$SOU145_SCRATCH/offline" --output "$SOU145_SCRATCH/results" --owned-pid-namespace
