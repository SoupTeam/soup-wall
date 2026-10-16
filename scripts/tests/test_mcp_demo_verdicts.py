# SPDX-License-Identifier: Apache-2.0
"""Recognize composed refusals without weakening unknown-error grading."""
import importlib.util
from pathlib import Path
import unittest
import tempfile
import json
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location(
    "mcp_demo_verdicts", Path(__file__).resolve().parents[1] / "mcp-admission-demo.py")
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)


class DemoVerdicts(unittest.TestCase):
    def test_startup_wait_accepts_slow_live_daemon_only_after_real_health(self):
        opener = Mock()
        healthy = unittest.mock.MagicMock()
        opener.open.side_effect = [OSError("not listening"), healthy]
        with patch.object(DEMO.urllib.request, "build_opener", return_value=opener), \
                patch.object(DEMO.time, "monotonic", side_effect=[0, 1, 20]), \
                patch.object(DEMO.time, "sleep"):
            self.assertTrue(DEMO.wait_healthy(12345, Mock(poll=lambda: None)))
        self.assertEqual(opener.open.call_count, 2)
        opener.open.assert_called_with("http://127.0.0.1:12345/health", timeout=1)

    def test_startup_wait_still_refuses_exit_and_bounded_timeout(self):
        for process, clock in [(Mock(poll=lambda: 1), [0, 1]),
                               (Mock(poll=lambda: None), [0, 61])]:
            with self.subTest(clock=clock), \
                    patch.object(DEMO.urllib.request, "build_opener") as opener, \
                    patch.object(DEMO.time, "monotonic", side_effect=clock):
                self.assertFalse(DEMO.wait_healthy(12345, process))
                opener.return_value.open.assert_not_called()

    def test_startup_failure_retains_bounded_escaped_redacted_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / ".agentfw").mkdir()
            (workspace / ".agentfw" / "token").write_text("fixture-private-token")
            (workspace / "daemon.log").write_bytes(
                b"x" * 9000 + b"\n::error::untrusted\nfixture-private-token\nstartup failed")
            message = DEMO.startup_failure(workspace, Mock(poll=lambda: 1))
            self.assertNotIn("fixture-private-token", message)
            self.assertNotIn("\n", message)
            diagnostic = json.loads(message.split(": ", 1)[1])
            self.assertEqual(diagnostic["exit_code"], 1)
            self.assertIn("startup failed", diagnostic["daemon_log_tail"])
            self.assertIn("[REDACTED]", diagnostic["daemon_log_tail"])
            self.assertLessEqual(len(diagnostic["daemon_log_tail"]), 8192)

    def test_composed_policy_refusals_are_distinct(self):
        for reason, verdict in [("policy_denied", "deny"), ("policy_unconfirmed_ask", "ask")]:
            with self.subTest(reason=reason):
                self.assertEqual(DEMO.outcome_of(
                    f"Soup Wall withheld MCP invocation ({reason})", True), verdict)

    def test_unsupported_executor_does_not_count_as_policy_deny(self):
        self.assertEqual(DEMO.outcome_of(
            "Soup Wall withheld MCP invocation (resource_executor_unsupported)", True),
            "refused:resource_executor_unsupported")
