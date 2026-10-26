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
        self.assertIn("--ask-wait-seconds", proc.stdout)

    def test_run_operator_requires_a_run_and_exact_binding(self):
        for words in (["pilot-approval", "list"],
                      ["pilot-approval", "--run", "a" * 32, "approve", "pending"],
                      ["pilot-approval", "--run", "a" * 32, "reject", "pending"]):
            proc = subprocess.run([str(AGENTFW_BIN), *words], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("required", proc.stderr)

    def test_base64url_pending_id_is_not_an_option(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            for action in ("inspect", "approve", "reject"):
                words = ["pilot-approval", "--home", tmpdir, "--run", "a" * 32, action, "--owned-pending-id"]
                if action != "inspect":
                    words += ["--binding", "b" * 64]
                proc = subprocess.run([str(AGENTFW_BIN), *words], cwd=ROOT, capture_output=True, text=True)
                self.assertNotEqual(proc.returncode, 0)  # No live run in this owned empty home.
                self.assertNotIn("unexpected argument", proc.stderr)
                self.assertNotIn("Usage:", proc.stderr)

    def test_ask_opt_in_never_executes_a_fixture_host(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir); workspace = tmp / "workspace"; workspace.mkdir()
            marker = tmp / "executed"
            host = tmp / "claude"
            make_executable(host, '#!/bin/sh\nprintf executed > "' + str(marker) + '"\n')
            fs = tmp / "fs.json"; git = tmp / "git.json"
            fs.write_text(json.dumps({"command":"echo","tools":["read_text_file"]}))
            git.write_text(json.dumps({"command":"echo","tools":["git_status"]}))
            proc = self.run_pilot(["--claude",str(host),"--workspace",str(workspace),
                "--fs-profile",str(fs),"--git-profile",str(git),"--mock-daemon-token","owned-test",
                "--allow-command-fixtures","--ask-wait-seconds","25"])
            self.assertNotEqual(proc.returncode,0)
            self.assertIn("original installed profiles on qualified Linux",proc.stderr)
            self.assertFalse(marker.exists())

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
                "--mock-instance-id", "mock-instance-test",
                "--json",
            ])
            self.assertNotEqual(proc.returncode, 0)
            report = json.loads(proc.stdout)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["exit_code"], 42)

    def test_collector_command_and_env_construction(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            ws = tmp / "ws"
            ws.mkdir()

            fs_prof = tmp / "profile.json"
            fs_prof.write_text(json.dumps({
                "runtimePath": "/usr/bin/node",
                "packageRoot": "/pkg/fs",
                "tools": [{"name": "read_text_file"}]
            }))

            git_prof = tmp / "git-profile.json"
            git_prof.write_text(json.dumps({
                "runtimePath": "/usr/bin/python3",
                "tools": [{"name": "git_status"}]
            }))

            claude = tmp / "claude"
            make_executable(claude)

            proc = self.run_pilot([
                "--claude", str(claude),
                "--workspace", str(ws),
                "--fs-profile", str(fs_prof),
                "--git-profile", str(git_prof),
                "--mock-daemon-token", "test-token",
                "--mock-instance-id", "inst-42",
                "--dry-run",
                "--json",
            ])
            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(proc.stdout)
            fs_server = report["servers"]["filesystem"]
            self.assertIn("--", fs_server["args"])
            idx = fs_server["args"].index("--")
            self.assertEqual(fs_server["args"][idx + 1], "/usr/bin/node")

            git_server = report["servers"]["git"]
            self.assertIn("--", git_server["args"])
            g_idx = git_server["args"].index("--")
            self.assertEqual(git_server["args"][g_idx + 1], "/usr/bin/python3")

    def test_timeout_enforcement_and_process_cleanup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            ws = tmp / "ws"
            ws.mkdir()

            # Host script sleeps longer than declared timeout
            sleep_script = tmp / "sleep-claude"
            make_executable(sleep_script, "#!/bin/sh\nsleep 30\n")

            proc = self.run_pilot([
                "--claude", str(sleep_script),
                "--workspace", str(ws),
                "--fs-profile", str(FS_PROFILE),
                "--git-profile", str(GIT_PROFILE),
                "--mock-daemon-token", "token-timeout",
                "--mock-instance-id", "inst-timeout",
                "--timeout-seconds", "2",
                "--json",
            ])
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("exceeded declared timeout", proc.stderr)

    def test_descendants_reaped_on_normal_host_exit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            ws = tmp / "ws"
            ws.mkdir()

            pid_file = tmp / "descendant.pid"
            mock_claude = tmp / "claude-with-descendant"
            script = f"""#!/bin/sh
sleep 60 >/dev/null 2>&1 &
echo $! > "{pid_file}"
exit 0
"""
            make_executable(mock_claude, script)

            proc = self.run_pilot([
                "--claude", str(mock_claude),
                "--workspace", str(ws),
                "--fs-profile", str(FS_PROFILE),
                "--git-profile", str(GIT_PROFILE),
                "--mock-daemon-token", "token-reap",
                "--mock-instance-id", "inst-reap",
                "--json",
            ])
            self.assertEqual(proc.returncode, 0, f"pilot-launch failed: {proc.stderr}")
            self.assertTrue(pid_file.exists(), "mock claude did not write descendant pid")
            descendant_pid = int(pid_file.read_text().strip())

            import time
            time.sleep(0.1)
            is_alive = True
            try:
                os.kill(descendant_pid, 0)
            except OSError:
                is_alive = False
            self.assertFalse(is_alive, f"descendant PID {descendant_pid} survived normal host exit")

    def test_invalid_mcp_server_profile_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            ws = tmp / "ws"
            ws.mkdir()

            invalid_fs = tmp / "invalid_fs.json"
            invalid_fs.write_text(json.dumps({
                "format": "sw-mcp/filesystem-readonly/1",
                "workspace": "/tmp",
                "corrupted": True,
            }), encoding="utf-8")

            claude = tmp / "claude"
            make_executable(claude)

            proc = self.run_pilot([
                "--claude", str(claude),
                "--workspace", str(ws),
                "--fs-profile", str(invalid_fs),
                "--git-profile", str(GIT_PROFILE),
                "--mock-daemon-token", "token-inv",
                "--mock-instance-id", "inst-inv",
                "--dry-run",
            ])
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("failed ProfileConfig validation", proc.stderr)

    def test_daemon_policy_verification_and_negative_control(self):
        import hashlib, socket, time, urllib.request

        def free_port() -> int:
            with socket.socket() as s:
                s.bind(("127.0.0.1", 0))
                return s.getsockname()[1]

        def sha256_bytes(b: bytes) -> str:
            return hashlib.sha256(b).hexdigest()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir).resolve()
            home = tmp / "home"
            home.mkdir()
            agentfw_dir = home / ".agentfw"
            agentfw_dir.mkdir()
            ws = tmp / "ws"
            ws.mkdir()

            policy_a = tmp / "policy_allow.yaml"
            policy_a.write_text("agent_policies: []\ndefault: allow\n", encoding="utf-8")

            policy_b = tmp / "policy_deny.yaml"
            policy_b.write_text("agent_policies: []\ndefault: deny\n", encoding="utf-8")

            reg_schema = {"type": "object", "additionalProperties": False}
            reg_bytes = json.dumps({
                "contract_version": "sw-native/1",
                "registry_id": "sou99-test-reg",
                "tools": [
                    {
                        "name": "read_text_file",
                        "schema_sha256": sha256_bytes(json.dumps(reg_schema).encode()),
                        "action_class": "read_only",
                        "result_provenance": "untrusted",
                        "egress": [],
                    }
                ],
            }).encode()
            reg_path = tmp / "registry.json"
            reg_path.write_bytes(reg_bytes)

            daemon_port = free_port()
            (agentfw_dir / "config.yaml").write_text(f"""port: {daemon_port}
enforce: true
policy: {policy_a}
native:
  registry_path: {reg_path}
  registry_sha256: {sha256_bytes(reg_bytes)}
""", encoding="utf-8")

            daemon_env = dict(
                HOME=str(home),
                PATH=os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin"),
            )
            daemon = subprocess.Popen(
                [str(AGENTFW_BIN), "serve"],
                env=daemon_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            claude = tmp / "claude"
            make_executable(claude)

            try:
                deadline = time.monotonic() + 10
                healthy = False
                while time.monotonic() < deadline:
                    if daemon.poll() is not None:
                        break
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{daemon_port}/health", timeout=1) as resp:
                            if resp.status == 200:
                                healthy = True
                                break
                    except Exception:
                        time.sleep(0.1)

                self.assertTrue(healthy, "daemon failed to become healthy")

                # Prepare valid installed ProfileConfig profiles for real pilot execution
                fs_installed = tmp / "fs_installed"
                fs_installed.mkdir()
                pkg_fs = tmp / "pkg_fs"
                pkg_fs.mkdir()
                (pkg_fs / "node_modules/@modelcontextprotocol/server-filesystem/dist").mkdir(parents=True)
                (pkg_fs / "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js").write_text("// entrypoint")
                node_dummy = tmp / "node"
                make_executable(node_dummy)
                bwrap_dummy = tmp / "bwrap"
                make_executable(bwrap_dummy)

                d64 = "0" * 64
                canonical_ws = str(ws.resolve())
                fs_prof = {
                    "format": "sw-mcp/filesystem-readonly/1",
                    "workspace": canonical_ws,
                    "runtimePath": str(node_dummy),
                    "runtimeSha256": d64,
                    "packageRoot": str(pkg_fs),
                    "packageTreeSha256": d64,
                    "bwrapPath": str(bwrap_dummy),
                    "bwrapSha256": d64,
                    "libraries": [],
                }
                (fs_installed / "profile.json").write_text(json.dumps(fs_prof), encoding="utf-8")

                git_installed = tmp / "git_installed"
                git_installed.mkdir()
                pkg_git = tmp / "pkg_git"
                pkg_git.mkdir()
                py_dummy = tmp / "python3"
                make_executable(py_dummy)
                git_dummy = tmp / "git"
                make_executable(git_dummy)
                launcher_dummy = tmp / "launcher"
                make_executable(launcher_dummy)

                git_prof = {
                    "format": "sw-mcp/git-readonly/1",
                    "workspace": canonical_ws,
                    "runtimePath": str(py_dummy),
                    "runtimeSha256": d64,
                    "packageRoot": str(pkg_git),
                    "packageTreeSha256": d64,
                    "bwrapPath": str(bwrap_dummy),
                    "bwrapSha256": d64,
                    "libraries": [],
                    "git": {"path": str(git_dummy), "sha256": d64},
                    "gitLauncher": {"path": str(launcher_dummy), "sha256": d64},
                }
                (git_installed / "profile.json").write_text(json.dumps(git_prof), encoding="utf-8")

                # 1. Negative control: operator selects policy_b but daemon enforces policy_a
                proc_mismatch = self.run_pilot([
                    "--claude", str(claude),
                    "--allow-command-fixtures",  # Explicit synthetic executables; policy checks remain real.
                    "--workspace", str(ws),
                    "--fs-profile", str(fs_installed),
                    "--git-profile", str(git_installed),
                    "--home", str(agentfw_dir),
                    "--policy", str(policy_b),
                    "--dry-run",
                ])
                self.assertNotEqual(proc_mismatch.returncode, 0)
                self.assertTrue(
                    "policy mismatch" in proc_mismatch.stderr or "policy digest mismatch" in proc_mismatch.stderr,
                    f"expected policy mismatch error, got: {proc_mismatch.stderr}",
                )

                # 2. Positive control: operator selects policy_a matching daemon
                proc_match = self.run_pilot([
                    "--claude", str(claude),
                    "--allow-command-fixtures",  # Explicit synthetic executables; policy checks remain real.
                    "--workspace", str(ws),
                    "--fs-profile", str(fs_installed),
                    "--git-profile", str(git_installed),
                    "--home", str(agentfw_dir),
                    "--policy", str(policy_a),
                    "--dry-run",
                    "--json",
                ])
                self.assertEqual(proc_match.returncode, 0, f"matching policy failed: {proc_match.stderr}")
                report = json.loads(proc_match.stdout)
                self.assertEqual(report["status"], "preview_ready")

            finally:
                daemon.terminate()
                try:
                    daemon.wait(timeout=3)
                except Exception:
                    daemon.kill()
                if daemon.stdout:
                    daemon.stdout.close()
                if daemon.stderr:
                    daemon.stderr.close()

    def test_unverified_command_json_rejected_outside_mock_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            claude = tmp / "claude"
            make_executable(claude)
            ws = tmp / "ws"
            ws.mkdir()

            fs_prof = tmp / "fs.json"
            fs_prof.write_text(json.dumps({"command": "/bin/echo", "args": ["hello"]}))
            git_prof = tmp / "git.json"
            git_prof.write_text(json.dumps({"command": "/bin/echo", "args": ["world"]}))

            # 1. Outside mock mode: rejected with failure
            proc = self.run_pilot([
                "--claude", str(claude),
                "--workspace", str(ws),
                "--fs-profile", str(fs_prof),
                "--git-profile", str(git_prof),
                "--dry-run",
            ])
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("real pilot requires validated ProfileConfig", proc.stderr)

            # 2. Inside mock mode: command fixtures accepted
            proc_mock = self.run_pilot([
                "--claude", str(claude),
                "--workspace", str(ws),
                "--fs-profile", str(fs_prof),
                "--git-profile", str(git_prof),
                "--mock-daemon-token", "test-token",
                "--dry-run",
            ])
            self.assertEqual(proc_mock.returncode, 0)

    def test_missing_profile_rejected_outside_mock_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            claude = tmp / "claude"
            make_executable(claude)
            ws = tmp / "ws"
            ws.mkdir()
            fs_empty = tmp / "fs_empty"
            fs_empty.mkdir()
            git_empty = tmp / "git_empty"
            git_empty.mkdir()

            proc = self.run_pilot([
                "--claude", str(claude),
                "--workspace", str(ws),
                "--fs-profile", str(fs_empty),
                "--git-profile", str(git_empty),
                "--dry-run",
            ])
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("installed MCP server profile not found", proc.stderr)


if __name__ == "__main__":
    unittest.main()


