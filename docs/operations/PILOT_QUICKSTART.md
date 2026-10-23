# First Linux pilot run

Use native Ubuntu 24.04 x86_64 as an ordinary user. Run the shell blocks in
Bash. Keep the checkout clean and use the same reviewed commit for every step.
The real Claude Code host talks to an owned local scripted provider; no model
account, API key or real credentials are needed. Do not export personal provider
credentials for this walkthrough.

## Prerequisites

An administrator supplies Python 3.11+, Git, a C/C++ compiler, make, meson,
ninja-build, pkg-config, binutils, libcap-dev, zlib1g-dev, curl, xz-utils, strace,
and Rust **1.94.1** with its compiler and Cargo. The preparation scripts report
missing inputs without installing system software. Bubblewrap must pass the
accepted sandbox positive controls on this host. An AppArmor/user-namespace
refusal requires administrator review using the
[native preparation guide](PILOT_RUNTIME_PREPARATION.md); leave the host's
security settings enabled.

Clone the reviewed source, then run from your home directory:

```bash
set -euo pipefail
git clone https://github.com/SoupTeam/soup-wall.git "$HOME/soup-wall"
repo="$(realpath "$HOME/soup-wall")"
commit="$(git -C "$repo" rev-parse HEAD)"
test -z "$(git -C "$repo" status --porcelain)"
cd "$HOME"
umask 077
assets="$(mktemp -d "$HOME/pilot-inputs.XXXXXXXX")"
python3 -B "$repo/scripts/pilot-demo.py"
```

Record the reviewed `$commit` and retain each command's first failure. A later
commit needs new preparation and qualification. Plans do not establish active
protection. The demo's default plan does not create output or start subprocesses.

## Build and select inputs

The following explicit steps download pinned public dependencies into private
directories. A disconnected setup can instead supply the archives and caches
described in the [runtime preparation guide](PILOT_RUNTIME_PREPARATION.md).

```bash
native_args=(--output "$assets/native" --expected-commit "$commit" --allow-download)
python3 -B "$repo/scripts/prepare-native-pilot-prerequisites.py" "${native_args[@]}"
{ time python3 -B "$repo/scripts/prepare-native-pilot-prerequisites.py" --prepare \
  "${native_args[@]}" > "$assets/native-result.json"; } 2> "$assets/native-timing.log"
source_args=(--output "$assets/agent" --expected-commit "$commit")
python3 -B "$repo/scripts/build-native-pilot-inputs.py" "${source_args[@]}"
{ time python3 -B "$repo/scripts/build-native-pilot-inputs.py" --build \
  "${source_args[@]}" > "$assets/agent-result.json"; } 2> "$assets/agent-timing.log"
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }
git_path="$(field "$assets/native-result.json" git)"
bwrap_path="$(field "$assets/native-result.json" bwrap)"
agentfw="$(field "$assets/agent-result.json" agentfw)"
git_launcher="$(field "$assets/agent-result.json" git_launcher)"
sandbox_tests="$(field "$assets/agent-result.json" sandbox_tests)"
```

Obtain the reviewed Node archive and locked Claude Code **2.1.251** package.
The archive digest is checked before extraction. `npm ci` verifies the checked-in
lockfile integrity and disables install scripts:

```bash
curl --fail --location --proto '=https' --tlsv1.2 \
  https://nodejs.org/dist/v22.22.0/node-v22.22.0-linux-x64.tar.xz \
  --output "$assets/node.tar.xz"
printf '%s  %s\n' 9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37 \
  "$assets/node.tar.xz" | sha256sum --check
tar -xJf "$assets/node.tar.xz" -C "$assets"
export PATH="$assets/node-v22.22.0-linux-x64/bin:/usr/bin:/bin"
mkdir -m 700 "$assets/claude"
cp "$repo"/profiles/mcp/filesystem-readonly-v1/claude-host/package*.json "$assets/claude/"
npm ci --ignore-scripts --no-audit --no-fund --prefix "$assets/claude"
claude="$assets/claude/node_modules/@anthropic-ai/claude-code-linux-x64/claude"
"$claude" --version
python3 -B - "$repo" "$assets/policy.yaml" <<'PY'
import importlib.util
from pathlib import Path
import sys
repo, output = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(repo / 'scripts'))
spec = importlib.util.spec_from_file_location('pilot', repo / 'scripts/qualify-installed-pilot.py')
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)
pilot.owned_bytes(output, pilot.PILOT_POLICY.encode('utf-8'))
PY
prep_args=(--output "$assets/prepared" --expected-commit "$commit"
  --agentfw "$agentfw" --git-launcher "$git_launcher" --sandbox-tests "$sandbox_tests"
  --node-archive "$assets/node.tar.xz" --bwrap "$bwrap_path" --git "$git_path"
  --claude "$claude" --python "$(realpath "$(command -v python3)")"
  --filesystem-classifier "$repo/rule_baseline/rule_baseline.py"
  --git-classifier "$repo/rule_baseline/git_readonly_v1/rule_baseline.py"
  --policy "$assets/policy.yaml" --allow-download)
python3 -B "$repo/scripts/prepare-installed-pilot.py" "${prep_args[@]}"
{ time python3 -B "$repo/scripts/prepare-installed-pilot.py" --prepare \
  "${prep_args[@]}" > "$assets/prepared-result.json"; } 2> "$assets/prepared-timing.log"
selection="$(field "$assets/prepared-result.json" selection)"
```

This prepares original filesystem and Git MCP packages, Python 3.11.14 and
separate private workspaces. It writes receipts and a selection manifest with
source and input hashes. Nothing is enforcing yet. Repeating `--prepare` verifies
and reuses the selected generation; changed bytes fail closed.

## Run and inspect

Use a fresh result directory and an unused prepared generation. The four fixture
names listed in the demo script must be absent. Existing files cause a refusal.

```bash
{ time python3 -B "$repo/scripts/pilot-demo.py" --run \
  --selection "$selection" --expected-commit "$commit" \
  --output "$HOME/pilot-demo-result-1" > "$assets/demo-result.json"; } 2> "$assets/demo-timing.log"
python3 -m json.tool "$HOME/pilot-demo-result-1/report.json"
```

A passing report requires useful filesystem and Git replies, independently
observed non-execution of a refused Git mutation, exact-call Ask controls,
continuation, timeout, cancellation, daemon-loss recovery and owned process
cleanup. The accepted driver inspects each pending call before issuing an exact
scripted approval. This controlled test approval is not operator consent for
future calls. For interactive approvals, use the second-terminal commands in
[the Ask guide](PILOT_ASK_WORKFLOW.md).

The wrapper removes only its unchanged synthetic files. Operator edits are
retained and make cleanup incomplete. The prepared generation, external input
builds, global Claude settings and unrelated files remain. Reports contain
source/input identities, case results and elapsed runtime; private raw traces
are temporary. Keep setup timings separately from the demo runtime.
The demo allows 120 seconds for each traced input-validation control. This
bounded observation budget covers source/package hashing; host execution, Ask,
cancellation and daemon-loss deadlines retain their accepted values.

## Troubleshooting and limits

| Result | Next step |
| --- | --- |
| Missing prerequisites | Resolve the plan's exact missing inputs before repeating the explicit command. |
| Unsupported platform | Use native Ubuntu 24.04 x86_64; WSL is a separate environment. |
| Sandbox positive fails | Retain the first failure and ask the host administrator to inspect the supported namespace/AppArmor setup. |
| Source or asset digest changed | Build and prepare the reviewed source again; retain the earlier result. |
| `demo_fixture_name_occupied` | Use a fresh generation; leave the existing files alone. |
| Failed demo | Keep `report.json`, including its first failing case; retry with a new output directory after correcting the cause. |
| Changed files retained during cleanup | Inspect them manually; no automatic force-removal is provided. |

This procedure qualifies the two pinned original servers and single-file rule
baselines in the synthetic workload. It does not measure live-model accuracy,
support arbitrary MCP servers, install a persistent service or qualify macOS,
WSL or Windows for this Linux flow. Ordinary Claude hooks retain their documented
fail-open boundary; this pilot uses the explicit protected launcher.
