# SPDX-License-Identifier: Apache-2.0
import contextlib
import copy
import io
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("agent_service_acceptance", Path(__file__).resolve().parents[1] / "test-agent-service.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ServiceAcceptanceGraderTests(unittest.TestCase):
    def complete(self):
        return {"suite": "core", "manager_verified": True, "cases": [{"name": name, "status": "passed"} for name in MODULE.CORE_CASES]}

    def test_only_complete_executed_success_passes(self):
        self.assertTrue(MODULE.grade(self.complete()))
        for status in ("failed", "not_run", "skipped", "unknown", True, None):
            report = self.complete()
            report["cases"][0]["status"] = status
            self.assertFalse(MODULE.grade(report))

    def test_missing_duplicate_and_unverified_cases_do_not_pass(self):
        for change in (lambda r: r["cases"].pop(), lambda r: r["cases"].append(copy.deepcopy(r["cases"][0])),
                       lambda r: r.update(manager_verified=False), lambda r: r.update(manager_verified="true"), lambda r: r.update(error="failed"),
                       lambda r: r.update(cleanup_error="incomplete")):
            report = self.complete()
            change(report)
            self.assertFalse(MODULE.grade(report))

    def test_full_acceptance_requires_every_failure_scenario(self):
        report = self.complete()
        report["suite"] = "full"
        self.assertFalse(MODULE.grade(report))
        report["cases"] = [{"name": name, "status": "passed"} for name in MODULE.FULL_CASES]
        self.assertTrue(MODULE.grade(report))
        for status in ("not_run", "skipped", "failed"):
            changed = copy.deepcopy(report)
            changed["cases"][-1]["status"] = status
            self.assertFalse(MODULE.grade(changed))
        for suite in (None, "unknown", "FULL"):
            report["suite"] = suite
            self.assertFalse(MODULE.grade(report))

    def test_outage_fixture_cannot_pass_when_manager_is_still_accessible(self):
        runner = MODULE.Acceptance.__new__(MODULE.Acceptance)
        runner.root = Path("/tmp/synthetic-service-outage")
        runner.env = {}
        runner.service = mock.Mock()
        with mock.patch.object(MODULE.subprocess, "run", return_value=mock.Mock(returncode=0)):
            with self.assertRaisesRegex(AssertionError, "did not isolate the real manager"):
                runner.unavailable_manager()
        runner.service.assert_not_called()

    def test_opt_in_is_required_before_creating_output(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "report.json"
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                MODULE.main(["--agentfw", "missing", "--output", str(output)])
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
