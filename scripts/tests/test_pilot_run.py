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


@patch.dict(os.environ, {"ANTHROPIC_API_KEY": "owned-provider-fixture"})
class PreparedRunBoundary(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "linux", "Linux owned file-descriptor fault control")
    def test_authority_sync_storage_failure_refuses_before_daemon_and_cleans_only_owned_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, selection, paths, profiles = self.fixture(root)
            paths.update(agentfw=Path("/trusted/agentfw"), claude=Path("/trusted/claude"),
                         node=Path("/trusted/node"), python=Path("/trusted/python"), policy=Path("/trusted/policy"))
            for role in ("agentfw", "policy"):
                paths[role] = root / (role + ".fixture")
                paths[role].write_bytes(b"owned selected input")
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
            self.assertEqual(report["cleanup"], "owned_processes_stopped_audit_retained")
            retained = list(root.glob("soup-wall-run-*"))
            self.assertEqual(len(retained), 1)
            RUN.AUDIT.verify_cleanup(retained[0])
            self.assertEqual(report["audit"]["snapshot"]["state"], "unavailable")
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
        with patch.object(RUN.PREP, "supported_platform"), \
             patch.object(RUN.SELECTION_LOCK, "hold"), \
             patch.object(RUN, "selected", return_value=({"source": {}}, {}, {})), \
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
            self.assertEqual(value["audit_retention"], RUN.AUDIT.LIMITS)

    def args(self, root):
        return SimpleNamespace(selection=root / "generations" / ("a" * 32) / "selection.json",
            expected_commit="b" * 40, run=False, state_root=root, port=0,
            timeout_seconds=30, ask_wait_seconds=0, prompt="owned control")

    def fixture(self, root):
        args = self.args(root)
        args.selection.parent.mkdir(parents=True, mode=0o700)
        args.selection.parent.parent.chmod(0o700)
        selection = {"format": "sw-installed-pilot-selection/2",
                     "source": {"commit": args.expected_commit}, "files": {}}
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

    def test_explicit_budget_plan_reads_only_owned_bytes_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args, selection, paths, profiles = self.fixture(root)
            budget = root / "budget.json"
            budget.write_bytes(b'{"operator":"selection-only"}')
            budget.chmod(0o600)
            before = sorted(str(p) for p in root.rglob("*"))
            with patch.object(RUN, "selected", return_value=(selection, paths, profiles)), \
                 patch.object(sys, "argv", ["pilot-run", "--selection", str(args.selection),
                     "--expected-commit", args.expected_commit, "--linux-budget", str(budget)]), \
                 patch.object(RUN.subprocess, "run") as utility, \
                 patch.object(RUN.subprocess, "Popen") as spawn, \
                 patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(RUN.main(), 0)
                report = json.loads(output.getvalue())
                self.assertEqual(report["resource_budget"]["status"], "selected-not-validated")
                self.assertFalse(report["executed"])
                utility.assert_not_called()
                spawn.assert_not_called()
            self.assertEqual(before, sorted(str(p) for p in root.rglob("*")))

    def test_budget_input_rejects_symlink_shared_write_and_overflow(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            budget = root / "budget"
            budget.write_bytes(b'{}')
            budget.chmod(0o600)
            self.assertEqual(RUN.budget_input(budget), b'{}')
            link = root / "link"
            link.symlink_to(budget)
            with self.assertRaises(RUN.Failure):
                RUN.budget_input(link)
            budget.chmod(0o622)
            with self.assertRaises(RUN.Failure):
                RUN.budget_input(budget)
            budget.chmod(0o600)
            budget.write_bytes(b'x' * 16385)
            with self.assertRaises(RUN.Failure):
                RUN.budget_input(budget)

    def test_budget_probe_has_no_provider_environment_and_refusal_never_starts_daemon(self):
        provider = {key: "distinct-owned-canary" for key in ("ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE")}
        with patch.object(RUN.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout=b'')) as call:
            with self.assertRaisesRegex(RUN.Failure, "linux_budget_preflight_refused"):
                RUN.budget_cli({"agentfw": Path("/trusted/agentfw")}, Path("/owned"),
                    {"PATH": "/usr/bin:/bin", **provider}, "--config", Path("/owned/budget"), True)
            self.assertEqual(call.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin"})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args, selection, paths, profiles = self.fixture(root)
            args.linux_budget = root / "budget.json"
            args.linux_budget.write_bytes(b'{}')
            args.linux_budget.chmod(0o600)
            with patch.object(RUN.PREP, "supported_platform"), \
                 patch.object(RUN, "selected", return_value=(selection, paths, profiles)), \
                 patch.object(RUN, "environment", return_value={}), \
                 patch.object(RUN, "budget_cli", side_effect=RUN.Failure("linux_budget_preflight_refused")), \
                 patch.object(RUN.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(RUN.Failure, "linux_budget_preflight_refused"):
                    RUN.run(args, {})
                spawn.assert_not_called()
            self.assertFalse(list(root.glob("soup-wall-run-*")))

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
                self.assertEqual(json.loads(output.getvalue())["audit_retention"], RUN.AUDIT.LIMITS)
                spawn.assert_not_called()
                execute.assert_not_called()
            self.assertEqual(before, sorted(str(p) for p in root.rglob("*")))

    @unittest.skipUnless(os.name == "posix", "lifetime lock requires POSIX")
    def test_active_transition_refuses_run_before_selection_or_spawn(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args, _, _, _ = self.fixture(root)
            with patch.object(RUN.PREP, "supported_platform"), \
                 RUN.SELECTION_LOCK.hold(root, exclusive=True), \
                 patch.object(RUN, "selected") as selected, patch.object(RUN, "run") as launch, \
                 patch.object(sys, "argv", ["pilot-run", "--run", "--selection", str(args.selection),
                                            "--expected-commit", args.expected_commit]), \
                 patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(RUN.main(), 1)
                self.assertEqual(json.loads(output.getvalue())["reason"],
                                 "selected_generation_in_use_or_transitioning")
                selected.assert_not_called()
                launch.assert_not_called()

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
            (root / "selection.json").write_text(json.dumps({"format": "sw-installed-pilot-selection/2",
                "prepared_profiles": {"filesystem": {}, "git": {}}}))
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
                 patch.object(RUN, "selected", side_effect=AssertionError("slow generation recheck reached")) as recheck, \
                 patch.object(RUN.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(RUN.Failure, "occupied_port_refused"):
                    RUN.run(args, {})
                recheck.assert_not_called()
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
            for role in ("agentfw", "claude", "node", "python", "policy"):
                paths[role] = root / ("trusted-" + role)
                paths[role].write_text("owned selected " + role)
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
            retained = list(root.glob("soup-wall-run-*"))
            self.assertEqual(len(retained), 1)
            self.assertEqual({p.name for p in retained[0].iterdir()},
                             {"audit", "audit-run.json", "audit-finished.json"})

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
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertNotIn("ANTHROPIC_BASE_URL", env)
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


    def test_interrupted_stop_retains_private_state_instead_of_erasing_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args, selection, paths, profiles = self.fixture(root)
            report = {}
            def interrupted(_paths, private):
                stop_dir = private / ".agentfw" / "pilot-runs" / ("a" * 32)
                stop_dir.mkdir(parents=True, mode=0o700)
                (stop_dir / "stop.json").write_text("synthetic retained intent")
                raise RuntimeError("owned interrupted stop fixture")
            with patch.object(RUN.PREP, "supported_platform"), \
                 patch.object(RUN, "selected", return_value=(selection, paths, profiles)), \
                 patch.object(RUN, "environment", side_effect=interrupted), \
                 patch.object(RUN.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(RuntimeError, "owned interrupted stop fixture"):
                    RUN.run(args, report)
                spawn.assert_not_called()
            retained = Path(report["retained_stop_state"])
            self.assertTrue((retained / ".agentfw" / "pilot-runs" / ("a" * 32) / "stop.json").is_file())
            self.assertEqual(report["cleanup"], "owned_processes_stopped_state_retained")
            self.assertNotEqual(report.get("status"), "stopped")

    def stop_fixture(self, root):
        home = root / ".agentfw"
        record = home / "pilot-runs" / ("a" * 32) / "run.json"
        record.parent.mkdir(parents=True, mode=0o700)
        value = {"contract": "sw-pilot-run/1", "home": str(home),
                 "run_id": record.parent.name, "launcher_pid": 1234}
        record.write_text(json.dumps(value))
        (record.parent / "stop.json").write_text('{"status":"stopped"}')
        response = {"run": value["run_id"], "status": "already_stopped",
                    "running_effects_rolled_back": False}
        return home, record, value, response

    def test_terminal_stop_uses_authenticated_exact_run_confirmation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, _, _, response = self.stop_fixture(root)
            with patch.object(RUN.subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout=json.dumps(response).encode())) as operator:
                RUN.confirmed_stop(home, 1234, Path("/trusted/agentfw"), {}, root)
            words = operator.call_args.args[0]
            self.assertEqual(words, ["/trusted/agentfw", "pilot-approval", "--home",
                str(home), "--run", "a" * 32, "stop"])

    def test_stop_intent_status_or_failed_authentication_cannot_report_stopped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, _, _, response = self.stop_fixture(root)
            for status in ("requested", "revoked", "stopped", "completed"):
                with self.subTest(status=status), patch.object(RUN.subprocess, "run", return_value=SimpleNamespace(
                        returncode=0, stdout=json.dumps({**response, "status": status}).encode())):
                    with self.assertRaisesRegex(RUN.Failure, "owned_stop_unconfirmed"):
                        RUN.confirmed_stop(home, 1234, Path("/trusted/agentfw"), {}, root)
            with patch.object(RUN.subprocess, "run", return_value=SimpleNamespace(
                    returncode=1, stdout=json.dumps(response).encode())):
                with self.assertRaisesRegex(RUN.Failure, "owned_stop_unconfirmed"):
                    RUN.confirmed_stop(home, 1234, Path("/trusted/agentfw"), {}, root)

    def test_foreign_stop_record_cannot_select_another_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home, record, value, _ = self.stop_fixture(root)
            for changes in ({"launcher_pid": 5678}, {"home": "/foreign"},
                            {"run_id": "b" * 32}, {"contract": "other"}):
                record.write_text(json.dumps({**value, **changes}))
                with patch.object(RUN.subprocess, "run") as operator:
                    with self.assertRaisesRegex(RUN.Failure, "owned_stop_unconfirmed"):
                        RUN.confirmed_stop(home, 1234, Path("/trusted/agentfw"), {}, root)
                    operator.assert_not_called()


if __name__ == "__main__":
    unittest.main()
