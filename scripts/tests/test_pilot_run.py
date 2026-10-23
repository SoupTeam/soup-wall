# SPDX-License-Identifier: Apache-2.0
"""Prepared launch refusal and ownership controls (SOU-116)."""
import importlib.util
import errno
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sou116_run", ROOT / "scripts/pilot-run.py")
RUN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN)


class PreparedRunBoundary(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "Linux owned file-descriptor fault control")
    def test_authority_sync_storage_failure_refuses_before_daemon_and_cleans_only_owned_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, selection, paths, profiles = self.fixture(root)
            paths.update(agentfw=Path("/trusted/agentfw"), claude=Path("/trusted/claude"),
                         node=Path("/trusted/node"), python=Path("/trusted/python"), policy=Path("/trusted/policy"))
            (root / "registry.json").write_text('{"tools": []}')
            sentinel = root / "foreign.txt"
            sentinel.write_bytes(b"preserve")
            sync = RUN.os.fsync
            faults = []
            def fail_authority(fd):
                if Path(os.readlink(f"/proc/self/fd/{fd}")).name == "native-token":
                    faults.append("authority_sync")
                    raise OSError(errno.ENOSPC, "owned storage fault")
                return sync(fd)
            report = {}
            with patch.object(RUN.PREP, "supported_platform"), \
                 patch.object(RUN, "selected", return_value=(selection, paths, profiles)), \
                 patch.object(RUN.os, "fsync", side_effect=fail_authority), \
                 patch.object(RUN.subprocess, "Popen") as spawn:
                with self.assertRaises(OSError):
                    RUN.run(args, report)
                spawn.assert_not_called()
            self.assertEqual(faults, ["authority_sync"])
            self.assertEqual(report["storage_failure"], "storage_full")
            self.assertFalse(report["host_started"])
            self.assertEqual(report["cleanup"], "owned_state_removed")
            self.assertFalse(list(root.glob("soup-wall-run-*")))
            self.assertEqual(sentinel.read_bytes(), b"preserve")

    def test_storage_diagnostics_are_finite_and_never_echo_paths(self):
        for number, reason in ((errno.ENOSPC, "storage_full"), (errno.EROFS, "storage_read_only"),
                               (errno.EACCES, "storage_permission_denied"), (errno.EIO, "storage_io_failed")):
            with self.subTest(errno=number), \
                 patch.object(RUN, "selected", side_effect=OSError(number, "Bearer private-secret", "/private/path")), \
                 patch.object(sys, "argv", ["pilot-run", "--selection", "/unused", "--expected-commit", "b" * 40]), \
                 patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(RUN.main(), 1)
                value = json.loads(output.getvalue())
                self.assertEqual(value["storage_failure"], reason)
                self.assertFalse(value["executed"])
                self.assertEqual(value["effects"], "Protected host was not started.")
                self.assertNotIn("private-secret", output.getvalue())
                self.assertNotIn("/private/path", output.getvalue())

    def test_cleanup_failure_preserves_original_storage_failure_and_effect_uncertainty(self):
        def failed_run(_args, report):
            report.update(executed=True, host_started=True, stage="run_publication",
                          storage_failure="storage_full", cleanup="failed",
                          cleanup_storage_failure="storage_permission_denied")
            raise RUN.Failure("owned_process_cleanup_failed")
        with patch.object(RUN, "selected", return_value=({"source": {}}, {}, {})), \
             patch.object(RUN.PREP.FS, "sha", return_value="a" * 64), \
             patch.object(RUN, "run", side_effect=failed_run), \
             patch.object(sys, "argv", ["pilot-run", "--run", "--selection", "/unused", "--expected-commit", "b" * 40]), \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(RUN.main(), 1)
            value = json.loads(output.getvalue())
            self.assertEqual(value["reason"], "owned_process_cleanup_failed")
            self.assertEqual(value["storage_failure"], "storage_full")
            self.assertEqual(value["cleanup_storage_failure"], "storage_permission_denied")
            self.assertIn("may have occurred", value["effects"])
            self.assertEqual(value["stage"], "run_publication")

    def args(self, root):
        return SimpleNamespace(selection=root / "generations" / ("a" * 32) / "selection.json",
            expected_commit="b" * 40, run=False, state_root=root, port=0,
            timeout_seconds=30, ask_wait_seconds=0, prompt="owned control")

    def fixture(self, root):
        args = self.args(root)
        args.selection.parent.mkdir(parents=True, mode=0o700)
        args.selection.parent.parent.chmod(0o700)
        selection = {"source": {"commit": args.expected_commit}, "files": {}}
        args.selection.write_text(json.dumps(selection))
        marker = {"format": "sw-pilot-preparation/1", "generation": "a" * 32,
                  "selection_sha256": RUN.PREP.FS.sha(args.selection), "status": "prepared-not-active"}
        (root / "current.json").write_text(json.dumps(marker))
        profiles = {kind: {"profile": {"path": str(root / (kind + ".json"))}}
                    for kind in ("filesystem", "git")}
        for kind in profiles:
            (root / (kind + ".json")).write_text(json.dumps({"workspace": str(root / kind)}))
        paths = {"git_classifier": ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py"}
        return args, selection, paths, profiles

    def test_default_command_does_not_spawn_or_create_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, selection, paths, profiles = self.fixture(root)
            before = sorted(str(p) for p in root.rglob("*"))
            with patch.object(RUN, "selected", return_value=(selection, paths, profiles)), \
                 patch.object(sys, "argv", ["pilot-run", "--selection", str(args.selection),
                                            "--expected-commit", args.expected_commit]), \
                 patch.object(RUN.subprocess, "Popen") as spawn, patch.object(RUN, "run") as execute, \
                 patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(RUN.main(), 0)
                self.assertEqual(json.loads(output.getvalue())["status"], "plan")
                self.assertFalse(json.loads(output.getvalue())["executed"])
                spawn.assert_not_called()
                execute.assert_not_called()
            self.assertEqual(before, sorted(str(p) for p in root.rglob("*")))

    def test_unsupported_platform_reports_a_finite_actionable_reason_without_spawn(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, selection, paths, profiles = self.fixture(Path(temporary))
            with patch.object(RUN, "selected", return_value=(selection, paths, profiles)), \
                 patch.object(RUN.PREP, "supported_platform", side_effect=ValueError("native_linux_x86_64_required")), \
                 patch.object(RUN.subprocess, "Popen") as spawn, \
                 patch.object(sys, "argv", ["pilot-run", "--run", "--selection", str(args.selection),
                                            "--expected-commit", args.expected_commit]), \
                 patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(RUN.main(), 1)
                self.assertEqual(json.loads(output.getvalue())["reason"], "native_linux_x86_64_required")
                self.assertFalse(json.loads(output.getvalue())["executed"])
                spawn.assert_not_called()

    def test_marker_and_generation_must_be_completed_selected_and_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, selection, paths, profiles = self.fixture(root)
            with patch.object(RUN.PREP, "verify_generation", return_value=(args.selection, profiles)) as verify, \
                 patch.object(RUN.PREP.PILOT, "validate_selection", return_value=({}, paths)):
                RUN.selected(args)
                self.assertFalse(verify.call_args.kwargs["probe_native"])
                marker = root / "current.json"
                original = marker.read_text()
                for update in ({"generation": "c" * 32}, {"selection_sha256": "0" * 64},
                               {"status": "interrupted"}):
                    marker.write_text(json.dumps({**json.loads(original), **update}))
                    with self.assertRaisesRegex(RUN.Failure, "preparation_marker_mismatch"):
                        RUN.selected(args)
                marker.write_text(original)
                args.selection.write_text(json.dumps({**selection, "changed": True}))
                with self.assertRaisesRegex(RUN.Failure, "preparation_marker_mismatch"):
                    RUN.selected(args)

    def test_marker_duplicate_json_is_never_trusted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, _, _, profiles = self.fixture(root)
            (root / "current.json").write_text('{"generation":"a","generation":"b"}')
            with patch.object(RUN.PREP, "verify_generation", return_value=(args.selection, profiles)):
                with self.assertRaises(Exception):
                    RUN.selected(args)

    def test_plan_validation_never_probes_native_executables(self):
        # Exercise the accepted generation validator, rather than mocking its probe switch.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "selection.json").write_text(json.dumps({"prepared_profiles": {"filesystem": {}, "git": {}}}))
            with patch.object(RUN.PREP.PILOT, "validate_selection", return_value=({}, {"node": Path(sys.executable)})), \
                 patch.object(RUN.PREP, "verify_profile", return_value={}), \
                 patch.object(RUN.PREP.FS, "NODE_SHA256", RUN.PREP.FS.sha(sys.executable)), \
                 patch.object(RUN.PREP, "check_native") as probe:
                RUN.PREP.verify_generation(root, "b" * 40, probe_native=False)
                probe.assert_not_called()

    def test_occupied_foreign_port_refuses_before_spawn_and_preserves_owner(self):
        with tempfile.TemporaryDirectory() as temporary, socket.socket() as owner:
            root = Path(temporary)
            args, selection, paths, profiles = self.fixture(root)
            owner.bind(("127.0.0.1", 0)); owner.listen()
            args.port = owner.getsockname()[1]
            before = sorted(str(p) for p in root.rglob("*"))
            with patch.object(RUN.PREP, "supported_platform"), \
                 patch.object(RUN, "selected", return_value=(selection, paths, profiles)), \
                 patch.object(RUN.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(RUN.Failure, "occupied_port_refused"):
                    RUN.run(args, {})
                spawn.assert_not_called()
            self.assertEqual(owner.getsockname()[1], args.port)
            self.assertEqual(before, sorted(str(p) for p in root.rglob("*")))

    def test_state_inside_project_or_checkout_refuses_before_spawn(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, selection, paths, profiles = self.fixture(root)
            for state in (ROOT, root):
                (root / "filesystem.json").write_text(json.dumps({"workspace": str(root)}))
                args.state_root = state
                with patch.object(RUN.PREP, "supported_platform"), \
                     patch.object(RUN, "selected", return_value=(selection, paths, profiles)), \
                     patch.object(RUN.subprocess, "Popen") as spawn:
                    with self.assertRaisesRegex(RUN.Failure, "state_inside_"):
                        RUN.run(args, {})
                    spawn.assert_not_called()

    def test_cancellation_during_last_validation_never_starts_host(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, selection, paths, profiles = self.fixture(root)
            paths.update(agentfw=Path("/trusted/agentfw"), claude=Path("/trusted/claude"),
                         node=Path("/trusted/node"), python=Path("/trusted/python"), policy=Path("/trusted/policy"))
            (root / "registry.json").write_text('{"tools": []}')
            read_fd, write_fd = os.pipe()
            os.close(write_fd)
            daemon = MagicMock(pid=12345, stdout=os.fdopen(read_fd, "rb"))
            count = 0
            def validate(_args):
                nonlocal count
                count += 1
                if count == 3:
                    os.kill(os.getpid(), RUN.signal.SIGTERM)
                return selection, paths, profiles
            with patch.object(RUN.PREP, "supported_platform"), \
                 patch.object(RUN, "selected", side_effect=validate), \
                 patch.object(RUN, "readiness", return_value={}), \
                 patch.object(RUN.GROUPS, "leader_finished", return_value=False), \
                 patch.object(RUN.GROUPS, "stop_group"), \
                 patch.object(RUN.subprocess, "Popen", return_value=daemon) as spawn:
                with self.assertRaisesRegex(RUN.Failure, "pilot_cancelled_before_host"):
                    RUN.run(args, {})
            self.assertEqual(count, 3)
            self.assertEqual(spawn.call_count, 1)  # Only the owned daemon, never a host.
            self.assertFalse(list(root.glob("soup-wall-run-*")))

    def test_correlated_dispatch_without_useful_result_cannot_pass_qualification(self):
        spec = importlib.util.spec_from_file_location("sou116_acceptance", ROOT / "scripts/qualify-prepared-pilot-run.py")
        acceptance = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(acceptance)
        for value in ({}, {"is_error": True, "content": "Owned prepared continuation."},
                      {"is_error": False, "content": []}, {"is_error": False, "content": "withheld"}):
            with self.assertRaisesRegex(ValueError, "prepared_useful_result_missing"):
                acceptance.useful_result({"followup": value}, "followup", "Owned prepared continuation.")
        acceptance.useful_result({"followup": {"is_error": False, "content": [
            {"type": "text", "text": "Owned prepared continuation."}]}}, "followup", "Owned prepared continuation.")

    def test_failure_during_private_setup_removes_partial_state_without_spawn(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, selection, paths, profiles = self.fixture(root)
            previous = RUN.signal.getsignal(RUN.signal.SIGTERM)
            report = {}
            with patch.object(RUN.PREP, "supported_platform"), \
                 patch.object(RUN, "selected", return_value=(selection, paths, profiles)), \
                 patch.object(RUN, "environment", side_effect=RuntimeError("owned setup failure")), \
                 patch.object(RUN.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(RuntimeError, "owned setup failure"):
                    RUN.run(args, report)
                spawn.assert_not_called()
            self.assertEqual(report["cleanup"], "owned_state_removed")
            self.assertFalse(list(root.glob("soup-wall-run-*")))
            self.assertEqual(RUN.signal.getsignal(RUN.signal.SIGTERM), previous)

    def test_provider_is_explicit_but_project_environment_is_not_inherited(self):
        with patch.dict(os.environ, {"PATH": "/untrusted", "PYTHONPATH": "/untrusted",
             "LD_PRELOAD": "/untrusted", "CLAUDE_CONFIG_DIR": "/untrusted", "AGENTFW_TOKEN": "secret",
             "ANTHROPIC_API_KEY": "owned-provider", "ANTHROPIC_BASE_URL": "http://127.0.0.1:1234"}):
            env = RUN.environment({"node": Path("/trusted/bin/node"), "python": Path("/trusted/python")}, Path("/private/run"))
        for key in ("PYTHONPATH", "LD_PRELOAD", "CLAUDE_CONFIG_DIR", "AGENTFW_TOKEN"):
            self.assertNotIn(key, env)
        self.assertNotIn("untrusted", env["PATH"])
        self.assertEqual(env["ANTHROPIC_API_KEY"], "owned-provider")
        # serve resolves HOME/.agentfw; AGENTFW_HOME alone is not its interface.
        self.assertEqual(env["AGENTFW_HOME"], str(Path(env["HOME"]) / ".agentfw"))

    def test_unexpected_error_never_exports_secret_or_raw_subprocess_output(self):
        for secret in ("Bearer owned-secret\nprivate args", "0123456789abcdef" * 4):
            with self.subTest(secret_shape="hex" if secret.isalnum() else "message"), \
                 patch.object(RUN, "selected", side_effect=RuntimeError(secret)), \
                 patch.object(sys, "argv", ["pilot-run", "--selection", "/unused/selection.json", "--expected-commit", "b" * 40]), \
                 patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(RUN.main(), 1)
                self.assertNotIn(secret, output.getvalue())
                self.assertEqual(json.loads(output.getvalue())["reason"], "pilot_input_or_runtime_failure")


if __name__ == "__main__":
    unittest.main()
