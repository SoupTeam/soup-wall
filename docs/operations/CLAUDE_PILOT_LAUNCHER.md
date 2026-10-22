# Claude Code Pilot Launcher

For explicit run-scoped operator Ask decisions from a second terminal, see
[the opt-in Ask workflow](PILOT_ASK_WORKFLOW.md). Default launcher behavior is unchanged.

The `agentfw pilot-launch` command delivers a trusted, per-run launcher for Claude Code paired with two pinned Model Context Protocol (MCP) servers (`filesystem` and `git`). It replaces error-prone manual authority minting, ad-hoc environment variables, and manual configuration editing with a single validated entry point.

## Overview

When operating Claude Code with scoped MCP tools, an operator must guarantee that:
1. Tools are constrained to an explicit, non-overlapping allowed set.
2. Authority is scoped strictly to the current session and server via HMAC-signed child grants.
3. Host boundaries prevent unmediated execution routes (such as built-in shell commands or arbitrary transports).
4. All per-run configuration and child authority tokens are stored in private state outside the workspace and erased immediately upon exit or failure.

## Command Reference

```sh
agentfw pilot-launch \
  --claude /path/to/claude \
  --workspace /path/to/workspace \
  --fs-profile /path/to/filesystem-readonly-v1 \
  --git-profile /path/to/git-readonly-v1 \
  [--home /path/to/.agentfw] \
  [--session-id <uuid>] \
  [--timeout-seconds 180] \
  [--dry-run] \
  [--json]
```

### Options

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--claude <PATH>` | Absolute path to the verified Claude Code executable. Must exist and be executable. | Required |
| `--workspace <PATH>` | Target directory exposed to the pilot conversation. Must be a directory. | Required |
| `--fs-profile <PATH>` | Pinned filesystem profile JSON or directory containing upstream tool metadata. | Required |
| `--git-profile <PATH>` | Pinned Git profile JSON or directory containing upstream tool metadata. | Required |
| `--home <PATH>` | Explicit daemon home directory containing `native-token` and `config.yaml`. | `~/.agentfw` |
| `--classifier <PATH>` | Optional path to verified rule-baseline classifier package or script. | None |
| `--policy <PATH>` | Optional path to pilot policy YAML. | Default policy |
| `--session-id <UUID>` | Optional explicit host session identifier. Generated if omitted. | Random UUID v4 |
| `--agent-bin <PATH>` | Path to `agentfw` binary to run MCP collectors. | Current executable |
| `--timeout-seconds <N>` | Maximum seconds allowed for the host conversation before termination. | `180` |
| `--dry-run` | Validates configuration, constructs execution plan, and exits without launching host. | `false` |
| `--json` | Outputs versioned machine-readable JSON report (`sw-pilot-launcher/1`). | `false` |

## Security Guarantees

### 1. Private Per-Run Isolation
The launcher creates a fresh temporary directory with mode `0700` strictly outside the workspace:
- Generated `mcp.json` is written with mode `0600`.
- Environment variable `CLAUDE_CONFIG_DIR` points to this private directory, ensuring operator global configurations (`~/.claude.json`) are neither read nor modified.
- Upon process exit, SIGINT, SIGTERM, or abnormal failure, an RAII cleanup guard automatically removes the private directory and all contained state.

### 2. Scoped Child Authority Minting
Child authority grants are minted using the authenticated daemon's native token (`child_authority::derive_key`):
- Each server (`filesystem` and `git`) receives a distinct, HMAC-SHA256 signed grant bounded by session ID, server ID, allowed tool list, and lease TTL.
- Raw bearer tokens and signatures are never printed to stdout, stderr, or operator logs. In structured reports, authority arguments are strictly `[REDACTED]`.

### 3. Strict Host Boundary Enforcement
Claude Code is invoked with strict arguments to prevent prompt-based tool bypass:
- `--restricted`: Restricts built-in host capabilities.
- `--strict-mcp-config`: Rejects servers not defined in the specified configuration.
- `--mcp-config <PATH>`: Pins server definitions to the private per-run configuration.
- `--tools ""`: Disables built-in default tools (e.g. unmediated `Bash`).
- `--allowedTools <LIST>`: Constrains admitted tool calls strictly to the union of tools declared in the pinned profiles.
- `--no-session-persistence`: Disallows persistent state accumulation across conversations.
- `--permission-mode dontAsk`: Enforces deterministic non-interactive policy verdicts.

### 4. Fail-Closed Recovery
- **Daemon restart / Token rotation:** Stale grants minted under a previous daemon authority are rejected by child authority verification, requiring a fresh launch.
- **Ambiguous tool declarations:** Tool name collisions between server profiles cause immediate validation failure before any process is spawned.

## Verification

### Unit Tests

```sh
# Run Rust unit tests for pilot launcher
cargo test -p agentfw --lib pilot_launcher

# Run Python CLI contract tests
python3 -m unittest scripts/tests/test_pilot_launch.py
```

### End-to-End Acceptance

The portable driver checks the four-phase sequence against Python fixture servers, plus stub-profile previews and cleanup controls. It does not qualify the installed original servers:

```sh
python3 scripts/claude_pilot_acceptance.py --binary target/debug/agentfw
```

Evidence is published to `docs/operations/evidence/sou-99-pilot-launcher/qualification.json`.

`scripts/qualify-pilot-launcher.py` is the separate required Linux x86-64 full-launch check. It reuses the original locked filesystem/Git installers, pinned Node/Git/bubblewrap and genuine Claude Code. It invokes `pilot-launch` without mock, fixture or dry-run flags against the selected enforcing policy and an owned loopback provider. The sequence includes useful filesystem and Git calls, untrusted input, an actual correlated destructive refusal and useful continuation. A syscall observer calibrates original-server dispatch and verifies no forbidden dispatch; independent workspace/index/HEAD snapshots and process identities verify effects and cleanup. Raw syscall traces remain private because they can contain authority.

The real-filesystem CI lane supplies those assets and retains a separate `sou99-original-launcher/qualification.json`, including executable/profile/package identities and failure status. Missing assets or an unexecuted host cannot produce a passing original-server report. Its owned provider makes no paid model calls; it measures host wiring, not live-model efficacy.

## Related Documents

- [MCP Stdio Admission](MCP_STDIO_ADMISSION.md)
- [MCP Real Filesystem Profile](MCP_REAL_FILESYSTEM.md)
- [Claude MCP Connection](CLAUDE_MCP_CONNECTION.md)
- [Agent Lifecycle](AGENT_LIFECYCLE.md)

For the pinned Linux host configuration boundary and hostile-project witnesses,
see [Project configuration isolation](PILOT_PROJECT_ISOLATION.md).
