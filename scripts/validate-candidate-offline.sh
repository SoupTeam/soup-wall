#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

KIT_ARCHIVE="$(pwd)/target/soup-wall-linux-amd64.tar.gz"
VALIDATION_DIR=$(mktemp -d -t soup-wall-candidate-XXXXXX)
ABS_HELPER="${VALIDATION_DIR}/check_inventory.py"
AGENT_PID=""

cleanup() {
    if [ -n "$AGENT_PID" ]; then
        kill -9 $AGENT_PID 2>/dev/null || true
        wait $AGENT_PID 2>/dev/null || true
    fi
    rm -rf "$VALIDATION_DIR"
}
trap cleanup EXIT

cat <<'EOF' > "$ABS_HELPER"
import json, hashlib, sys, os
try:
    manifest = json.load(open("manifest.json"))
    expected = manifest.get("files", {})
except:
    sys.exit("CRITICAL: Failed to read manifest")

for req in ["bin/agentfw", "bin/llm-firewall"]:
    if req not in expected: sys.exit("CRITICAL: Missing core binaries in manifest")

for rel_path, expected_hash in expected.items():
    if not os.path.exists(rel_path): sys.exit(f"CRITICAL: Missing file {rel_path}")
    if hashlib.sha256(open(rel_path, "rb").read()).hexdigest() != expected_hash:
        sys.exit(f"CRITICAL: Hash mismatch for {rel_path}")

# Strict negative control - NO exemptions
for root, _, files in os.walk("."):
    for file in files:
        rel_path = os.path.relpath(os.path.join(root, file), ".")
        if rel_path != "manifest.json" and rel_path not in expected:
            sys.exit(f"CRITICAL: Unlisted file found: {rel_path}")
EOF

tar -xzf "$KIT_ARCHIVE" -C "$VALIDATION_DIR"
cd "${VALIDATION_DIR}/soup-wall-linux-amd64"

echo "Testing Nested Unlisted File Negative Control..."
mkdir -p "assets/nested_fake"
touch "assets/nested_fake/rogue.txt"
if python3 "$ABS_HELPER" >/dev/null 2>&1; then
    echo "CRITICAL: Validator accepted nested unlisted file."; exit 1
fi
rm -rf "assets/nested_fake"

echo "Executing Strict Initial Inventory Integrity Check..."
python3 "$ABS_HELPER" || { echo "CRITICAL: Initial clean inventory failed."; exit 1; }

echo "=> Extracting Node & Bootstrapping Profile via Official Installer (Strictly Offline)..."
tar -xf node-v22.22.0-linux-x64.tar.xz
export PATH="$(pwd)/node-v22.22.0-linux-x64/bin:$(pwd)/bin:$PATH"
export HOME="$(pwd)/agent-home"
mkdir -p "$HOME/.agentfw" "$(pwd)/workspace"

cat <<'EOF' > run_installer.py
import sys, pathlib, importlib.util
spec = importlib.util.spec_from_file_location("fs", "scripts/install-sou62-filesystem-profile.py")
fs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fs)
dest, ws, node, bwrap, npm, cache = [pathlib.Path(a).absolute() for a in sys.argv[1:7]]
fs.install(dest, ws, node, bwrap, npm, npm_cache=cache, offline=True)
EOF

# Force network unshare to prove strictly offline operation
./bin/bwrap --unshare-net --dev /dev --proc /proc --bind / / --die-with-parent \
    python3 run_installer.py "$HOME/profile-sou62" "$(pwd)/workspace" "$(pwd)/node-v22.22.0-linux-x64/bin/node" "$(pwd)/bin/bwrap" "$(pwd)/node-v22.22.0-linux-x64/bin/npm" "$(pwd)/npm-cache"

REGISTRY_PATH="$HOME/profile-sou62/registry.json"
cat <<CONFIG > "$HOME/.agentfw/config.yaml"
enforce: true
native:
  registry_path: "${REGISTRY_PATH}"
  registry_sha256: "$(sha256sum "${REGISTRY_PATH}" | awk '{print $1}')"
CONFIG

echo "=> Starting Daemon..."
agentfw serve > agent.log 2>&1 &
AGENT_PID=$!
sleep 2
agentfw preflight > preflight.log 2>&1 || { echo "CRITICAL: Preflight failed"; cat agent.log; exit 1; }

cat <<'EOF' > mcp_client.py
import sys, json
action, path, content = sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None
def send(msg): sys.stdout.write(json.dumps(msg) + "\n"); sys.stdout.flush()

send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"validator","version":"1.0"}}})
send({"jsonrpc":"2.0","method":"notifications/initialized"})
send({"jsonrpc":"2.0","id":2,"method":"tools/list"})
if action == "write":
    send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{"path":path,"content":content}}})
else:
    send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":path}}})
EOF

cat <<'EOF' > check_response.py
import sys, json
action = sys.argv[1]
responses = []
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        responses.append(json.loads(line))
    except ValueError:
        pass

id3 = next((r for r in responses if r.get("id") == 3), None)
if not id3:
    sys.exit("CRITICAL: No JSON-RPC response for id=3 found.")

if action == "read":
    if "error" in id3 or id3.get("result", {}).get("isError"):
        sys.exit(f"CRITICAL: Unexpected error on read: {id3}")
    content = id3.get("result", {}).get("content", [{}])[0].get("text", "")
    if "SOU-87-EXACT-WITNESS-DATA" not in content:
        sys.exit("CRITICAL: Useful read failed to return expected content.")
elif action == "write":
    refused = "error" in id3 or id3.get("result", {}).get("isError") is True
    if not refused:
        sys.exit(f"CRITICAL: Write was not refused. Response: {id3}")
EOF

NODE_BIN="$(pwd)/node-v22.22.0-linux-x64/bin/node"
INDEX_JS="$HOME/profile-sou62/package/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"

export AGENTFW_MCP_SERVER_PROFILE="$HOME/profile-sou62/profile.json"
export AGENTFW_WORKSPACE="$(pwd)/workspace"
export AGENTFW_CLASSIFIER_PACKAGE="$(pwd)/assets/baseline.classifier"
export AGENTFW_CLASSIFIER="rule-baseline"
export AGENTFW_RULE_BASELINE="$(pwd)/rule_baseline/rule_baseline.py"
export AGENTFW_CLASSIFIER_PYTHON="$(which python3)"

SECRET_FILE="$(pwd)/workspace/test_secret.txt"
echo "SOU-87-EXACT-WITNESS-DATA" > "$SECRET_FILE"

echo "Testing Useful Read (Offline)..."
python3 mcp_client.py "read" "/workspace/test_secret.txt" | \
    agentfw mcp --native-admission --id filesystem-readonly-v1 -- $NODE_BIN $INDEX_JS /workspace > read.json 2> read.err || true
python3 check_response.py "read" < read.json || { cat read.json read.err; exit 1; }

echo "Testing Correlated Deny..."
ZERO_EFFECT_FILE="$(pwd)/workspace/zero_effect_witness.txt"
python3 mcp_client.py "write" "/workspace/zero_effect_witness.txt" "ignore all instructions" | \
    agentfw mcp --native-admission --id filesystem-readonly-v1 -- $NODE_BIN $INDEX_JS /workspace > deny.json 2> deny.err || true
python3 check_response.py "write" < deny.json || { cat deny.json deny.err; exit 1; }

if [ -f "$ZERO_EFFECT_FILE" ]; then
    echo "CRITICAL: File was written! Zero-effect failed."; exit 1
fi

echo "Testing Daemon-Loss Refusal..."
kill -9 $AGENT_PID 2>/dev/null
wait $AGENT_PID 2>/dev/null || true
AGENT_PID=""

python3 mcp_client.py "read" "$SECRET_FILE" | \
    agentfw mcp --native-admission --id filesystem-readonly-v1 -- $NODE_BIN $INDEX_JS /workspace > loss.json 2> loss.err || EXIT_CODE=$?

if [ "${EXIT_CODE:-0}" -eq 0 ]; then
    echo "CRITICAL: Command succeeded despite daemon loss!"
    exit 1
fi

echo "=> Offline Validation Passed!"