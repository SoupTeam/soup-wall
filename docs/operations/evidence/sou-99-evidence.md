# SOU-99: Trusted Per-Run Claude Code Pilot Launcher for Pinned MCP Servers

## Overview and Deliverables

Issue **SOU-99** delivers a trusted per-run Claude Code pilot launcher (`agentfw pilot-launch`) for two pinned MCP servers (`filesystem` and `git`).

It provides:
1. **Single Entry Point (`agentfw pilot-launch`)**: Accepts explicit paths to Claude Code executable, workspace directory, filesystem profile, Git profile, and daemon home. Rejects tool collisions and ambiguous configurations before execution.
2. **Private Per-Run Isolation**: Prepares a fresh temporary configuration directory outside the workspace (mode `0700`) containing `mcp.json` (mode `0600`) and private Claude configuration (`CLAUDE_CONFIG_DIR`). Automatic RAII cleanup removes all temporary state on normal exit, SIGINT/SIGTERM, or failure.
3. **Scoped HMAC Child Authority Grants**: Mints HMAC-SHA256 child authority tokens from the authenticated daemon token (`child_authority::derive_key`). Grants are bound to the session ID, server ID, and profile-declared tool sets. All tokens are redacted (`[REDACTED]`) in logs and output reports.
4. **Strict Host Boundary Enforcement**: Launches Claude Code with host-level controls (`--restricted`, `--strict-mcp-config`, `--tools ""`, `--allowedTools ...`, `--no-session-persistence`, `--permission-mode dontAsk`), disabling unmediated shell access and preventing bypass routes.
5. **Zero Paid API Calls & Verification**: Evaluated with an owned scripted model harness verifying the complete 4-step sequence (benign read, tainted untrusted input, refused destructive Git action with zero side-effects, benign continuation).

## Acceptance Summary

| Check Category | Verification Driver | Outcome |
| :--- | :--- | :--- |
| **Rust Unit Tests** | `cargo test -p agentfw --lib pilot_launcher` | 3 passed, 0 failed |
| **Python Contract Tests** | `python3 -m unittest scripts/tests/test_pilot_launch.py` | 9 passed, 0 failed |
| **End-to-End Acceptance** | `python3 scripts/claude_pilot_acceptance.py` | 39 checks passed, 0 failed |
| **Rust Linter / Clippy** | `cargo clippy -p agentfw --all-targets --locked -- -D warnings` | 0 warnings |
| **Formatting** | `cargo fmt --all -- --check` | 0 differences |
| **Doc Links** | `python3 scripts/check_docs.py` | 0 errors |

## Machine-Readable Evidence

The structured qualification record is saved at [`qualification.json`](sou-99-pilot-launcher/qualification.json) in `docs/operations/evidence/sou-99-pilot-launcher/`.

Key results:
- **Contract Version**: `sw-pilot-launcher/1`
- **Real Model Evaluation**: `false`
- **Scripted Owned Provider**: `true`
- **Zero Paid API Calls Verified**: `true`
- **Total Acceptance Checks**: `39/39 passed`
- **Cleanup Witness**: `private_config_dir_removed: true`, `zero_orphaned_processes: true`
