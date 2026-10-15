# SPDX-License-Identifier: Apache-2.0
"""Safety and evidence-boundary controls for the opt-in recovery driver."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


FILE = Path(__file__).resolve().parents[1] / "console-recovery-acceptance.py"
SPEC = importlib.util.spec_from_file_location("console_recovery_acceptance", FILE)
DRIVER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DRIVER
SPEC.loader.exec_module(DRIVER)


class OptInAndPrivateArtifacts(unittest.TestCase):
    def test_default_command_never_runs_tools_or_creates_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "must-not-exist.json"
            with patch.object(DRIVER.subprocess, "run") as tool, \
                    patch.object(DRIVER.subprocess, "Popen") as process, \
                    patch.object(DRIVER, "private_directory") as private, \
                    contextlib.redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(DRIVER.main(["--output", str(output)]), 0)
            tool.assert_not_called()
            process.assert_not_called()
            private.assert_not_called()
            self.assertFalse(output.exists())
            self.assertIn("predeclared_objective", stream.getvalue())

    @unittest.skipUnless(os.name == "posix", "Unix permission contract")
    def test_private_file_is_exclusive_and_existing_secret_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            os.chmod(directory, 0o700)
            path = directory / "secret.json"
            DRIVER.private_write(path, "original-private-value")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                DRIVER.private_write(path, "replacement")
            self.assertEqual(path.read_text(), "original-private-value")

    @unittest.skipUnless(os.name == "posix", "Unix permission contract")
    def test_redirected_or_nonprivate_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            os.chmod(directory, 0o755)
            with self.assertRaises(DRIVER.AcceptanceError):
                DRIVER.private_directory(directory)
            os.chmod(directory, 0o700)
            link = directory / "alias"
            link.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(DRIVER.AcceptanceError):
                DRIVER.private_directory(link)

    def test_no_operator_credentials_or_proxy_settings_are_inherited(self):
        with patch.dict(os.environ, {"LLM_FW_ADMIN_TOKEN": "private-admin",
                "SOUP_AGENT_POLICY_SEED_HEX": "private-key", "OPENAI_API_KEY": "private-provider",
                "HTTPS_PROXY": "http://private-proxy", "PGOPTIONS": "private-db-option"}):
            environment = DRIVER.child_environment()
        for name in ("LLM_FW_ADMIN_TOKEN", "SOUP_AGENT_POLICY_SEED_HEX", "OPENAI_API_KEY",
                     "HTTPS_PROXY", "PGOPTIONS"):
            self.assertNotIn(name, environment)


class RuntimeBoundaries(unittest.TestCase):
    def test_external_or_confused_http_authority_is_refused_before_network(self):
        for url in ("https://127.0.0.1:443/", "http://127.0.0.1:80@evil.example/",
                    "http://localhost:80/", "http://example.test/", "http://127.0.0.1/"):
            with self.subTest(url=url), patch.object(DRIVER.urllib.request, "build_opener") as network:
                with self.assertRaises(DRIVER.AcceptanceError):
                    DRIVER.request("GET", url)
                network.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "Unix permission contract")
    def test_running_source_console_prevents_backup_invocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            os.chmod(directory, 0o700)
            with patch.object(DRIVER, "free_port", return_value=12345):
                run = DRIVER.Run(SimpleNamespace(backend="sqlite"), directory)
            run.console = SimpleNamespace(poll=lambda: None)
            run.backup_module = Mock()
            with self.assertRaises(DRIVER.AcceptanceError):
                run.backup("source-still-running")
            run.backup_module.backup_sqlite.assert_not_called()
            self.assertFalse(run.checks[-1]["passed"])

    def test_hook_allow_is_defer_and_cannot_manufacture_an_allow_grant(self):
        run = object.__new__(DRIVER.Run)
        item = {"url": "http://127.0.0.1:12345", "hook_token": "private-token"}
        with patch.object(DRIVER, "request", return_value=(200, {})):
            self.assertEqual(run.hook(item), "defer")
        with patch.object(DRIVER, "request", return_value=(200, {
                "hookSpecificOutput": {"permissionDecision": "deny"}})):
            self.assertEqual(run.hook(item), "deny")

    def test_cleanup_kills_only_the_owned_child_after_termination_timeout(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [DRIVER.subprocess.TimeoutExpired("owned", 10), 0]
        DRIVER.stop_child(process)
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 2)

    def test_cached_policy_does_not_count_as_recovered_transport_until_online(self):
        run = object.__new__(DRIVER.Run)
        run.checks = []
        run.health = Mock(side_effect=[
            {"managed_policy": {"deployment_sequence": 3}, "managed_transport": {"state": "stale"}},
            {"managed_policy": {"deployment_sequence": 3}, "managed_transport": {"state": "offline"}},
            {"managed_policy": {"deployment_sequence": 3}, "managed_transport": {"state": "online"}},
        ])
        with patch.object(DRIVER.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            observed = run.online({"number": 0}, "restored")
        self.assertEqual(run.health.call_count, 3)
        self.assertEqual(observed["state"], "online")
        self.assertTrue(run.checks[-1]["passed"])

    @unittest.skipUnless(os.name == "posix", "Unix permission contract")
    def test_existing_but_modified_operator_settings_cannot_prove_retained_trust(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            os.chmod(directory, 0o700)
            path = directory / "operator-settings.json"
            DRIVER.private_write(path, "original signing settings")
            run = object.__new__(DRIVER.Run)
            run.directory, run.checks = directory, []
            run.operator_settings_sha256 = DRIVER.sha256(path)
            run.issuer_seed = "private-fixture-seed"
            run.environment = {"SOUP_AGENT_POLICY_SEED_HEX": run.issuer_seed,
                               "SOUP_AGENT_POLICY_KEY_ID": "pinned"}
            run.initial_issuer = {"key_id": "pinned", "public_key_hex": "ab" * 32}
            run.api = Mock()
            path.write_text("different signing settings")
            self.assertTrue(path.is_file())
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(DRIVER.AcceptanceError):
                run.verify_operator_trust()
            run.api.assert_not_called()
            self.assertFalse(run.checks[-1]["passed"])


@unittest.skipUnless(os.name == "posix", "Unix permission contract")
class OwnedCleanup(unittest.TestCase):
    def invoke(self, directory, *, retain=False, fail=False):
        binary = directory / "fixture-binary"
        binary.write_bytes(b"synthetic executable selected only by mocked runtime")
        selected = directory / "owned-run"
        output = directory / "public-result.json"
        def runtime(run, resources):
            DRIVER.private_write(run.directory / "private-secret", "must-be-cleaned")
            if fail:
                raise DRIVER.AcceptanceError("Synthetic bounded failure.")
            return {"status": "passed"}
        arguments = ["--run", "--private-dir", str(selected), "--output", str(output)]
        for option in ("--console-binary", "--agent-binary", "--fixture-helper"):
            arguments.extend((option, str(binary)))
        if retain:
            arguments.append("--retain-private-fixture")
        with patch.object(DRIVER, "free_port", return_value=12345), \
                patch.object(DRIVER, "source_metadata", return_value={}), \
                patch.object(DRIVER.Run, "run", runtime), contextlib.redirect_stdout(io.StringIO()):
            result = DRIVER.main(arguments)
        return result, selected, json.loads(output.read_text())

    def test_default_success_removes_private_plaintext_and_retains_sanitized_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, selected, report = self.invoke(Path(temporary).resolve())
            self.assertEqual(result, 0)
            self.assertFalse(selected.exists())
            self.assertTrue(report["cleanup"]["complete"])
            self.assertNotIn("must-be-cleaned", json.dumps(report))

    def test_default_failure_still_removes_private_plaintext(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, selected, report = self.invoke(Path(temporary).resolve(), fail=True)
            self.assertEqual(result, 1)
            self.assertFalse(selected.exists())
            self.assertEqual(report["status"], "failed")
            self.assertTrue(report["cleanup"]["complete"])

    def test_explicit_debug_retention_is_incomplete_not_successful_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, selected, report = self.invoke(Path(temporary).resolve(), retain=True)
            self.assertEqual(result, 1)
            self.assertTrue((selected / "private-secret").is_file())
            self.assertEqual(report["status"], "incomplete")
            self.assertTrue(report["cleanup"]["private_fixture_retained"])
            self.assertFalse(report["cleanup"]["complete"])

    def test_replaced_directory_is_not_mistaken_for_owned_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            owned = directory / "owned"
            DRIVER.private_directory(owned, create=True)
            original = owned.stat()
            owned.rename(directory / "original-owned")
            DRIVER.private_directory(owned, create=True)
            (owned / "foreign-file").write_text("leave intact")
            with self.assertRaises(DRIVER.AcceptanceError):
                DRIVER.cleanup_owned_tree(owned, (original.st_dev, original.st_ino))
            self.assertEqual((owned / "foreign-file").read_text(), "leave intact")

    def test_nested_symlink_never_removes_its_external_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            sentinel = directory / "outside-file"
            sentinel.write_text("leave intact")
            owned = DRIVER.private_directory(directory / "owned", create=True)
            (owned / "link").symlink_to(sentinel)
            original = owned.stat()
            DRIVER.cleanup_owned_tree(owned, (original.st_dev, original.st_ino))
            self.assertFalse(owned.exists())
            self.assertEqual(sentinel.read_text(), "leave intact")


if __name__ == "__main__":
    unittest.main()
