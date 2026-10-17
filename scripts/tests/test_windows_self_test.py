# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / "test-windows-self-test.py"
SPEC = importlib.util.spec_from_file_location("self_test_acceptance", PATH)
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class ReportChecks(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.probe = DRIVER.Acceptance.__new__(DRIVER.Acceptance)
        self.probe.agent = self.root / "agent"
        self.probe.baseline = self.root / "baseline"
        self.probe.agent.write_bytes(b"binary")
        self.probe.baseline.write_bytes(b"classifier")
        self.probe.stage = self.root
        self.probe.python = self.root / "python"
        ids = ["allowed_read", "adversarial_result", "protected_send_refused",
               "useful_read_after_refusal", "daemon_loss"]
        self.report = {
            "schema_version": "sw-self-test/1", "exit_code": 0,
            "profile": {"id": "windows-stdio-mcp-admission-v1"}, "result": "passed",
            "identities": {
                "agent": {"sha256": DRIVER.digest(self.probe.agent)},
                "classifier": {"source_sha256": DRIVER.digest(self.probe.baseline)},
                **{name: {"sha256": "a" * 64} for name in ("policy", "registry", "fixtures")},
            },
            "scenarios": [{"id": name, "status": "passed", "observed": {}, "receipts": {
                "classification": {"classifier_sha256_matches": True, "policy": "reached"},
                "native_audit": []}} for name in ids],
            "cleanup": {"workspace": "removed", "receiver": {"socket_closed": True},
                        "collector": {"job_empty": True}, "daemon": {"job_empty": True},
                        "final_effects": {"exact_execution_ledger": True, "no_unexpected_effects": True}},
        }
        self.report["scenarios"][0]["observed"]["checks"] = {"exact_expected_bytes": True}
        self.report["scenarios"][1]["observed"] = {"outcome": "result_withheld", "marker_reached_client": False}
        self.report["scenarios"][1]["receipts"]["native_audit"] = [{"verdict": "ask", "released": False}]
        self.report["scenarios"][2]["observed"] = {"mcp_child_executions": 0, "receiver_connections": 0}
        self.report["scenarios"][2]["receipts"]["native_audit"] = [{"verdict": "deny"}]
        self.report["scenarios"][4]["observed"] = {"daemon_killed": True, "collector_exited": True}
        self.result = subprocess.CompletedProcess([], 0, stdout=b"", stderr=b"")

    def test_complete_independent_report_is_accepted(self):
        self.probe.complete(self.result, self.report)

    def test_late_execution_cannot_hide_behind_passing_scenarios(self):
        for key in ("exact_execution_ledger", "no_unexpected_effects"):
            with self.subTest(key=key):
                report = copy.deepcopy(self.report)
                report["cleanup"]["final_effects"][key] = False
                with self.assertRaises(AssertionError):
                    self.probe.complete(self.result, report)

    def test_missing_receipt_or_wrong_binary_cannot_pass(self):
        for mutate in (
            lambda report: report["identities"]["agent"].update(sha256="0" * 64),
            lambda report: report["scenarios"][0]["receipts"]["classification"].update(policy="not_reached"),
            lambda report: report["scenarios"][1]["receipts"].update(native_audit=[]),
        ):
            report = copy.deepcopy(self.report)
            mutate(report)
            with self.assertRaises(AssertionError):
                self.probe.complete(self.result, report)

    def test_unavailable_cleanup_failure_and_release_are_rejected(self):
        for mutate in (
            lambda report: report["scenarios"][0].update(status="unavailable"),
            lambda report: report["cleanup"]["daemon"].update(job_empty=False),
            lambda report: report["cleanup"].update(workspace="workspace_removal_failed"),
            lambda report: report["scenarios"][1]["observed"].update(marker_reached_client=True),
            lambda report: report.update(exit_code=4),
        ):
            report = copy.deepcopy(self.report)
            mutate(report)
            with self.assertRaises(AssertionError):
                self.probe.complete(self.result, report)


if __name__ == "__main__":
    unittest.main()
