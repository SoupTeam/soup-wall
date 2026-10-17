# SPDX-License-Identifier: Apache-2.0
"""Driver controls only; these never stand in for genuine Keycloak acceptance."""
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "sso_diagnostics.py"
spec = importlib.util.spec_from_file_location("sso_diagnostics", SCRIPT)
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)


class BrowserOutcomes(unittest.TestCase):
    def test_success_requires_observed_readiness(self):
        page = Mock()
        ready = Mock(side_effect=[False, False, True])
        D.wait_for_browser(page, ready, {}, 1000)
        self.assertEqual(page.wait_for_timeout.call_count, 2)

    def test_navigation_failure_does_not_wait_for_selector_timeout_or_accept_stale_ui(self):
        page, ready = Mock(), Mock(return_value=True)
        with self.assertRaises(D.BrowserTransportFailure):
            D.wait_for_browser(page, ready, {"network_failures": ["net::ERR_NETWORK_CHANGED"]}, 90000)
        ready.assert_not_called()
        page.wait_for_timeout.assert_not_called()

    def test_failure_during_event_pump_is_retained(self):
        observation = {"network_failures": []}
        page = Mock()
        page.wait_for_timeout.side_effect = lambda _: observation["network_failures"].append("other")
        with self.assertRaises(D.BrowserTransportFailure):
            D.wait_for_browser(page, lambda: False, observation, 1000)
        self.assertEqual(observation["network_failures"], ["other"])
        page.wait_for_timeout.assert_called_once()

    def test_timeout_is_bounded_and_never_success(self):
        with patch.object(D.time, "monotonic", side_effect=[0, 1]):
            with self.assertRaises(TimeoutError):
                D.wait_for_browser(Mock(), lambda: False, {}, 1000)


class PrivacyTests(unittest.TestCase):
    def test_navigation_and_failures_are_allowlisted(self):
        gateway, vendor = "https://127.0.0.1:444", "https://localhost:8443"
        for secret in ("token=password", "code=authorization-code", "SAMLResponse=assertion"):
            self.assertEqual(D.location(gateway + "/auth/oidc/callback?" + secret,
                                        gateway, vendor), "gateway_callback")
            self.assertTrue(D.same_endpoint(gateway + "/auth/oidc/callback?" + secret,
                                            gateway + "/auth/oidc/callback"))
            self.assertEqual(D.network_category(secret), "other")
        self.assertFalse(D.same_endpoint("https://other.test/auth/oidc/callback", gateway + "/auth/oidc/callback"))
        self.assertEqual(D.location("https://[invalid", gateway, vendor), "other")

    def test_log_offset_excludes_previous_expected_refusals_and_raw_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.log"
            previous = b"SAML response validation failed: replay secret-old\n"
            path.write_bytes(previous + b"OIDC authorization-code exchange failed: code=secret-new\n")
            result = D.log_categories(path, len(previous))
            self.assertEqual(result["categories"], ["oidc authorization-code exchange failed"])
            self.assertEqual(result["validation"], [])
            self.assertNotIn("secret", json.dumps(result))

    def test_large_log_is_bounded_and_unavailable_log_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.log"
            path.write_bytes(b"x" * 100000 + b"saml response validation failed: signature token=secret")
            result = D.log_categories(path)
            self.assertTrue(result["truncated"])
            self.assertEqual(result["validation"], ["signature"])
            self.assertLess(len(json.dumps(result)), 300)
            self.assertFalse(D.log_categories(Path(directory) / "absent")["available"])


class LifecycleTests(unittest.TestCase):
    def evidence(self):
        report = {"checks": [], "cleanup_passed": False}
        output = Mock()
        with patch.object(D.platform, "system", return_value="Linux"), \
                patch.object(D.platform, "machine", return_value="x86_64"), \
                patch.object(D.platform, "release", return_value="test-kernel"), \
                patch.object(D.subprocess, "check_output", side_effect=["a" * 40, b""]):
            diag = D.Diagnostics(report, output, SCRIPT.parent)
        return diag

    def test_failure_collects_health_before_cleanup_and_preserves_failure(self):
        diag = self.evidence()
        sequence = []
        with patch.object(diag, "health", side_effect=lambda: sequence.append("health")):
            with self.assertRaisesRegex(RuntimeError, "original assertion"):
                with D.RunResources(diag) as resources:
                    resources.callback(sequence.append, "cleanup")
                    raise RuntimeError("original assertion")
        self.assertEqual(sequence, ["health", "cleanup"])
        self.assertTrue(diag.report["cleanup_passed"])
        self.assertEqual(diag.report["outcome"], "incomplete")

    def test_cleanup_failure_remains_failure(self):
        diag = self.evidence()
        with self.assertRaises(OSError):
            with D.RunResources(diag) as resources:
                resources.callback(Mock(side_effect=OSError("private error")))
        self.assertFalse(diag.report["cleanup_passed"])

    def test_diagnostic_failure_cannot_skip_cleanup(self):
        diag, cleaned = self.evidence(), Mock()
        with patch.object(diag, "health", side_effect=OSError("private error")):
            with self.assertRaises(OSError):
                with D.RunResources(diag) as resources:
                    resources.callback(cleaned)
        cleaned.assert_called_once()

    def test_timeline_has_durations_and_bounded_entries(self):
        diag = self.evidence()
        diag.phase("credentials-owner")
        diag.phase("callback-owner")
        self.assertIn("duration_ms", diag.report["timeline"][1])
        self.assertIn("source_commit", diag.report)
        for _ in range(253):
            diag.phase("bounded")
        with self.assertRaises(RuntimeError):
            diag.phase("overflow")

    def test_container_health_cannot_export_untrusted_inspect_output(self):
        diag = self.evidence()
        diag.container("keycloak", "docker", "a" * 64)
        for output in ("token=secret", "running 0 false sha256:" + "b" * 64):
            with patch.object(D.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output)):
                diag.health()
            self.assertNotIn("secret", json.dumps(diag.report))
        self.assertTrue(diag.report["owned_health_before_cleanup"]["containers"][0]["inspect_available"])

    def test_network_cleanup_is_owned_even_on_failure(self):
        with patch.object(D.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "c" * 64)) as run:
            with self.assertRaises(RuntimeError):
                with ExitStack() as resources:
                    D.owned_network("docker", resources)
                    raise RuntimeError("failed")
            self.assertEqual(run.call_args.args[0], ["docker", "network", "rm", "c" * 64])

    @unittest.skipUnless(os.name == "posix", "real signal/child cleanup requires Linux")
    def test_sigterm_and_deadline_clean_real_owned_child_and_directory(self):
        # Independent OS witness: exercise signals against a real sleeping child,
        # not a mocked callback. The parent test always reaps its own launcher.
        for number in (signal.SIGTERM, signal.SIGALRM):
            with self.subTest(number=number), tempfile.TemporaryDirectory() as temporary:
                program = r'''
import importlib.util, json, pathlib, shutil, subprocess, sys, time
spec = importlib.util.spec_from_file_location('d', sys.argv[1])
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
root = pathlib.Path(sys.argv[2]); owned = root / 'owned'; owned.mkdir()
class Output:
    def publish(self, report): (root / 'result.json').write_text(json.dumps(report))
diag = d.Diagnostics({'cleanup_passed': False}, Output(), pathlib.Path(sys.argv[1]).parent)
try:
    with d.RunResources(diag) as resources:
        resources.callback(shutil.rmtree, owned)
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])
        def stop():
            child.terminate(); child.wait(timeout=5)
            (root / 'reaped').write_text(str(child.returncode))
        resources.callback(stop)
        print('READY', flush=True)
        time.sleep(120)
except (d.RunCancelled, d.RunBudgetExceeded):
    sys.exit(3)
'''
                child = subprocess.Popen([sys.executable, "-c", program, str(SCRIPT), temporary],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    # communicate has a hard timeout; signal only after ownership is established.
                    import select
                    self.assertTrue(select.select([child.stdout], [], [], 15)[0])
                    self.assertEqual(child.stdout.readline().strip(), "READY")
                    os.kill(child.pid, number)
                    child.communicate(timeout=15)
                    self.assertEqual(child.returncode, 3)
                    root = Path(temporary)
                    self.assertFalse((root / "owned").exists())
                    self.assertTrue((root / "reaped").exists())
                    self.assertTrue(json.loads((root / "result.json").read_text())["cleanup_passed"])
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
