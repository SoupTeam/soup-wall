#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Contract, security containment, and execution tests for agentfw pilot-launch (SOU-99)."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
AGENTFW_BIN = ROOT / "target" / "debug" / "agentfw"
FS_PROFILE = ROOT / "profiles" / "mcp" / "filesystem-readonly-v1"
GIT_PROFILE = ROOT / "profiles" / "mcp" / "git-readonly-v1"


def make_executable(path: Path, script_content: str = "#!/bin/sh\nexit 0\n") -> None:
    path.write_text(script_content, encoding="utf-8")
    mode = os.stat(path).st_mode
    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class PilotLaunchCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Build agentfw binary if needed
        if not AGENTFW_BIN.exists():
            subprocess.run(["cargo", "build", "-p", "agentfw"], cwd=ROOT, check=True)

    def run_pilot(self, args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
        cmd = [str(AGENTFW_BIN), "pilot-launch", *args]
        return subprocess.run(
            cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=check,
        )

    def test_help_output(self):
        proc = self.run_pilot(["--help"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("Trusted per-run Claude Code pilot launcher", proc.stdout)
        self.assertIn("--claude", proc.stdout)
        self.assertIn("--workspace", proc.stdout)
        self.assertIn("--fs-profile", proc.stdout)
        self.assertIn("--git-profile", proc.stdout)
        self.assertIn("--dry-run", proc.stdout)
        self.assertIn("--session-id", proc.stdout)
        self.assertIn("--json", proc.stdout)

    def test_missing_claude_executable_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            ws = tmp / "ws"
            ws.mkdir()
            proc = self.run_pilot([
                "--claude", str(tmp / "nonexistent-claude"),
                "--workspace", str(ws),
                "--fs-profile", str(FS_PROFILE),
                "--git-profile", str(GIT_PROFILE),
                "--dry-run",
            ])
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("selected Claude Code executable does not exist", proc.stderr)

    def test_non_executable_claude_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            claude = tmp / "claude-text"
            claude.write_text("not an executable", encoding="utf-8")
            # Ensure not executable
            os.chmod(claude, stat.S_IRUSR | stat.S_IWUSR)

            ws = tmp / "ws"
            ws.mkdir()
            proc = self.run_pilot([
                "--claude", str(claude),
                "--workspace", str(ws),
                "--fs-profile", str(FS_PROFILE),
                "--git-profile", str(GIT_PROFILE),
                "--dry-run",
            ])
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("not executable", proc.stderr)

    def test_missing_workspace_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            claude = tmp / "claude"
            make_executable(claude)

            proc = self.run_pilot([
                "--claude", str(claude),
                "--workspace", str(tmp / "nonexistent-ws"),
                "--fs-profile", str(FS_PROFILE),
                "--git-profile", str(GIT_PROFILE),
                "--dry-run",
            ])
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("selected workspace directory does not exist", proc.stderr)

    def test_file_as_workspace_fails(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            claude = tmp / "claude"
            make_executable(claude)
            file_ws = tmp / "file-as-ws"
            file_ws.write_text("hello", encoding="utf-8")

            proc = self.run_pilot([
                "--claude", str(claude),
                "--workspace", str(file_ws),
                "--fs-profile", str(FS_PROFILE),
                "--git-profile", str(GIT_PROFILE),
                "--dry-run",
            ])
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("selected workspace is not a directory", proc.stderr)

    def test_colliding_tools_between_servers_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            claude = tmp / "claude"
            make_executable(claude)
            ws = tmp / "ws"
            ws.mkdir()

            fs_prof = tmp / "fs.json"
            fs_prof.write_text(json.dumps({"tools": [{"name": "duplicate_tool"}]}))

            git_prof = tmp / "git.json"
            git_prof.write_text(json.dumps({"tools": [{"name": "duplicate_tool"}]}))

            proc = self.run_pilot([
                "--claude", str(claude),
                "--workspace", str(ws),
                "--fs-profile", str(fs_prof),
                "--git-profile", str(git_prof),
                "--dry-run",
            ])
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("colliding tool between servers", proc.stderr)

    def test_dry_run_json_contract_and_token_redaction(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            claude = tmp / "claude"
            make_executable(claude)
            ws = tmp / "ws"
            ws.mkdir()

            session_id = "test-session-uuid-12345678"
            mock_secret = "test-secret-key-material-99887766"

            proc = self.run_pilot([
                "--claude", str(claude),
                "--workspace", str(ws),
                "--fs-profile", str(FS_PROFILE),
                "--git-profile", str(GIT_PROFILE),
                "--session-id", session_id,
                "--mock-daemon-token", mock_secret,
                "--dry-run",
                "--json",
            ])
            self.assertEqual(proc.returncode, 0, f"proc failed: {proc.stderr}")

            # Verify no secret leakage in stdout or stderr
            self.assertNotIn(mock_secret, proc.stdout)
            self.assertNotIn(mock_secret, proc.stderr)

            report = json.loads(proc.stdout)
            self.assertEqual(report["contract_version"], "sw-pilot-launcher/1")
            self.assertEqual(report["status"], "preview_ready")
            self.assertEqual(report["host_session"], session_id)
            self.assertEqual(report["exit_code"], 0)

            # Check servers plan
            self.assertIn("filesystem", report["servers"])
            self.assertIn("git", report["servers"])

            fs_plan = report["servers"]["filesystem"]
            self.assertTrue(fs_plan["token_redacted"])
            self.assertEqual(fs_plan["args"][7], "[REDACTED]")

            git_plan = report["servers"]["git"]
            self.assertTrue(git_plan["token_redacted"])
            self.assertEqual(git_plan["args"][7], "[REDACTED]")

            # Check private dir was removed
            private_dir = Path(report["private_config_dir"])
            self.assertFalse(private_dir.exists(), "private_config_dir must be cleaned up")
            self.assertFalse(
                str(private_dir).startswith(str(ws.resolve())),
                "private_config_dir must be outside workspace",
            )

    def test_execution_boundary_flags_and_cleanup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            ws = tmp / "ws"
            ws.mkdir()

            # Create mock claude script that records its invocation
            record_file = tmp / "invocation.json"
            mock_script = tmp / "mock-claude"
            script_body = f"""#!/usr/bin/env python3
import json, os, sys
from pathlib import Path

# Verify mcp.json exists during execution
mcp_config_idx = sys.argv.index("--mcp-config") + 1
mcp_config_path = Path(sys.argv[mcp_config_idx])
mcp_config_content = json.loads(mcp_config_path.read_text(encoding="utf-8"))

data = {{
    "cwd": os.getcwd(),
    "argv": sys.argv[1:],
    "claude_config_dir": os.environ.get("CLAUDE_CONFIG_DIR"),
    "disable_traffic": os.environ.get("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"),
    "disable_marketplace": os.environ.get("CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL"),
    "disable_updates": os.environ.get("DISABLE_UPDATES"),
    "mcp_config_path": str(mcp_config_path),
    "mcp_config_exists": mcp_config_path.exists(),
    "servers": list(mcp_config_content.get("mcpServers", {{}}).keys()),
}}
Path("{record_file}").write_text(json.dumps(data), encoding="utf-8")
sys.exit(0)
"""
            make_executable(mock_script, script_body)

            session_id = "boundary-test-session-42"
            mock_secret = "secret-token-content-112233"

            proc = self.run_pilot([
                "--claude", str(mock_script),
                "--workspace", str(ws),
                "--fs-profile", str(FS_PROFILE),
                "--git-profile", str(GIT_PROFILE),
                "--session-id", session_id,
                "--mock-daemon-token", mock_secret,
                "--json",
            ])
            self.assertEqual(proc.returncode, 0, f"proc failed: {proc.stderr}")

            # Verify recorded execution details
            self.assertTrue(record_file.exists(), "mock Claude script did not run")
            rec = json.loads(record_file.read_text(encoding="utf-8"))

            # Boundary checks
            argv = rec["argv"]
            self.assertIn("--restricted", argv)
            self.assertIn("--strict-mcp-config", argv)
            self.assertIn("--no-session-persistence", argv)
            self.assertIn("--permission-mode", argv)
            self.assertEqual(argv[argv.index("--permission-mode") + 1], "dontAsk")
            self.assertIn("--tools", argv)
            self.assertEqual(argv[argv.index("--tools") + 1], "")
            self.assertIn("--allowedTools", argv)

            # Workspace cwd
            self.assertEqual(Path(rec["cwd"]).resolve(), ws.resolve())

            # Environment isolation
            self.assertEqual(rec["disable_traffic"], "1")
            self.assertEqual(rec["disable_marketplace"], "1")
            self.assertEqual(rec["disable_updates"], "1")

            # MCP configuration inside private directory
            self.assertTrue(rec["mcp_config_exists"])
            self.assertEqual(set(rec["servers"]), {"filesystem", "git"})

            # Private directory cleanup after process exits
            private_mcp_path = Path(rec["mcp_config_path"])
            self.assertFalse(
                private_mcp_path.exists(),
                "mcp.json and its private dir must be removed after exit",
            )
            self.assertFalse(
                private_mcp_path.parent.exists(),
                "private dir must be removed after exit",
            )

    def test_mock_claude_failure_propagates_exit_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            ws = tmp / "ws"
            ws.mkdir()

            mock_script = tmp / "failing-claude"
            make_executable(mock_script, "#!/bin/sh\nexit 42\n")

            proc = self.run_pilot([
                "--claude", str(mock_script),
                "--workspace", str(ws),
                "--fs-profile", str(FS_PROFILE),
                "--git-profile", str(GIT_PROFILE),
                "--mock-daemon-token", "token-123",
                "--json",
            ])
            self.assertNotEqual(proc.returncode, 0)
            report = json.loads(proc.stdout)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["exit_code"], 42)


if __name__ == "__main__":
    unittest.main()
