# SPDX-License-Identifier: Apache-2.0
"""Adversarial measurement controls, not installed-host acceptance evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_qualification as CONTRACT

SPEC = importlib.util.spec_from_file_location("installed_pilot", ROOT / "scripts/qualify-installed-pilot.py")
PILOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PILOT)


class OutcomeControls(unittest.TestCase):
    def test_unstarted_cases_keep_original_denominators(self):
        report = CONTRACT.finish(CONTRACT.new_report())
        self.assertEqual(report["required"], 12)
        self.assertEqual(report["counts"], {"passed": 0, "failed": 0, "incomplete": 12, "unsupported": 0})
        self.assertEqual(report["benign_workflows"]["incomplete"], 2)
        self.assertEqual(report["status"], "incomplete")

    def test_partial_run_cannot_become_green_by_editing_summary(self):
        report = CONTRACT.new_report()
        CONTRACT.measure(report, CONTRACT.CASES[0], lambda: {"observation": "owned"})
        report.update(status="passed", counts={"passed": 12})
        self.assertEqual(CONTRACT.finish(report)["status"], "incomplete")
        self.assertEqual(report["counts"]["passed"], 1)

    def test_removed_duplicated_or_reordered_case_is_rejected(self):
        for mutation in (lambda rows: rows.pop(), lambda rows: rows.append(copy.deepcopy(rows[0])), lambda rows: rows.reverse()):
            report = CONTRACT.new_report()
            mutation(report["cases"])
            with self.assertRaises(CONTRACT.Failure):
                CONTRACT.finish(report)

    def test_exceptions_keep_the_failure_and_all_unrun_cases(self):
        report = CONTRACT.new_report()
        def broken():
            raise ValueError("owned-token-MUST-NOT-LEAK")
        self.assertFalse(CONTRACT.measure(report, CONTRACT.CASES[0], broken))
        CONTRACT.finish(report)
        self.assertEqual(report["counts"]["failed"], 1)
        self.assertEqual(report["counts"]["incomplete"], 11)
        self.assertNotIn("MUST-NOT-LEAK", json.dumps(report))

    def test_late_success_is_failure_with_evidence_retained(self):
        report = CONTRACT.new_report()
        with patch.object(CONTRACT.time, "monotonic", side_effect=[1, 182, 183]):
            self.assertFalse(CONTRACT.measure(report, CONTRACT.CASES[0], lambda: {"original_result_hash": "a" * 64}))
        row = report["cases"][0]
        self.assertEqual(row["reason"], "case_deadline_exceeded")
        self.assertEqual(row["evidence"]["original_result_hash"], "a" * 64)
        self.assertEqual(CONTRACT.finish(report)["status"], "failed")

    def test_second_execution_cannot_overwrite_failed_case(self):
        report = CONTRACT.new_report()
        CONTRACT.measure(report, CONTRACT.CASES[0], lambda: None)
        with self.assertRaises(CONTRACT.Failure):
            CONTRACT.measure(report, CONTRACT.CASES[0], lambda: {"replacement": True})

    def test_false_interruptions_do_not_reduce_benign_denominator(self):
        report = CONTRACT.new_report()
        report["benign_workflows"].update(completed=1, false_interruptions=1, incomplete=0)
        CONTRACT.finish(report)
        report["benign_workflows"]["required"] = 1
        with self.assertRaises(CONTRACT.Failure):
            CONTRACT.finish(report)

    def test_unknown_states_nonfinite_duration_and_unbounded_report_fail(self):
        for change in ({"status": "skipped"}, {"elapsed_ms": float("nan")}, {"status": "passed", "reason": None}):
            report = CONTRACT.new_report()
            report["cases"][0].update(change)
            with self.assertRaises(CONTRACT.Failure):
                CONTRACT.finish(report)
        report = CONTRACT.new_report()
        report["remaining_blockers"] = ["x" * (CONTRACT.LIMITS["report_bytes"] + 1)]
        with self.assertRaises(CONTRACT.Failure):
            CONTRACT.finish(report)


class RuntimeBoundaryControls(unittest.TestCase):
    def selection(self, executable):
        before = {"commit": "a" * 40, "tree": "b" * 40, "dirty": False, "files_sha256": "c" * 64}
        return {"format": "sw-installed-pilot-selection/1", "source": before,
                "files": {role: {"path": str(executable), "sha256": CONTRACT.sha(executable)} for role in PILOT.ROLES}}

    def test_changed_binary_wrong_candidate_and_missing_sandbox_are_actual_input_failures(self):
        selection = self.selection(Path(sys.executable).resolve())
        before = copy.deepcopy(selection["source"])
        with patch.object(PILOT, "source", return_value=before):
            PILOT.validate_selection(selection, "a" * 40)
            for mutation, reason in (
                (lambda s: s["files"]["agentfw"].update(sha256="0" * 64), "selected_executable_changed"),
                (lambda s: s["source"].update(commit="0" * 40), "candidate_source_mismatch"),
                (lambda s: s["files"]["bwrap"].update(path="/missing-owned-sandbox"), "selected_executable_unavailable"),
            ):
                item = copy.deepcopy(selection)
                mutation(item)
                with self.assertRaisesRegex(CONTRACT.Failure, "^" + reason + "$"):
                    PILOT.validate_selection(item, "a" * 40)

    def test_structured_useful_content_requires_exact_shape_and_no_duplicate_keys(self):
        self.assertEqual(PILOT.host_text({"is_error": False, "content": '{"content":"useful"}'}, "filesystem"), "useful")
        for value in ({"is_error": True, "content": '{"content":"useful"}'},
                      {"is_error": False, "content": '{"content":"bad","content":"useful"}'},
                      {"is_error": False, "content": '{"content":"useful","other":true}'},
                      {"is_error": False, "content": '{"content":NaN}'},
                      {"is_error": False, "content": "prefix useful suffix"}):
            with self.assertRaises(ValueError):
                PILOT.host_text(value, "filesystem")

    def test_stream_overflow_drains_real_child_but_cannot_be_accepted(self):
        process = subprocess.Popen([sys.executable, "-I", "-c", "import os; os.write(1,b'x'*4096)"], stdout=subprocess.PIPE)
        with patch.dict(CONTRACT.LIMITS, host_bytes=128):
            capture = PILOT.BoundedStream(process.stdout)
            process.wait(timeout=5)
            with self.assertRaisesRegex(CONTRACT.Failure, "host_output_limit"):
                capture.finish()
        self.assertEqual(capture.total, 4096)
        self.assertEqual(len(capture.data), 128)
        self.assertFalse(capture.thread.is_alive())

    def test_bad_selection_command_exits_nonzero_and_retains_failed_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection = root / "selection.json"
            selection.write_text('{"format":"wrong"}')
            result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/qualify-installed-pilot.py"), "--run",
                "--selection", str(selection), "--expected-commit", "a" * 40, "--output", str(root / "run")],
                capture_output=True, timeout=10)
            report = json.loads((root / "run/report.json").read_text())
            self.assertEqual(result.returncode, 1)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["counts"]["failed"], 1)
            self.assertEqual(report["counts"]["incomplete"], 11)
            self.assertEqual(report["cases"][0]["reason"], "selection_version")
            again = subprocess.run(result.args, capture_output=True, timeout=10)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(json.loads((root / "run/report.json").read_text()), report)

    def test_changed_staged_classifier_hits_production_check_before_any_server(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private, output = root / "private", root / "output"
            private.mkdir()
            output.mkdir()
            paths = {role: Path(sys.executable).resolve() for role in PILOT.ROLES}
            pilot = PILOT.Pilot(private, output, paths, CONTRACT.new_report())
            try:
                with self.assertRaisesRegex(CONTRACT.Failure, "^staged_classifier_changed$"):
                    pilot.prepare("changed-asset")
                self.assertIsNone(pilot.daemon)
                self.assertEqual(pilot.hosts, [])
                self.assertEqual(pilot.bindings, [])
                self.assertEqual(pilot.clients, [])
            finally:
                pilot.cleanup()

    def test_evidence_retention_redacts_credentials_and_excludes_host_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private, output = root / "private", root / "output"
            private.mkdir()
            output.mkdir()
            pilot = PILOT.Pilot(private, output, {role: Path(sys.executable).resolve() for role in PILOT.ROLES}, CONTRACT.new_report())
            try:
                pilot.secrets = ["owned-private-token", "owned-signed-proof"]
                (private / "probe.log").write_text("owned-private-token owned-signed-proof useful diagnostic\n")
                host = private / "host-probe"
                host.mkdir()
                (host / "mcp.json").write_text("MUST-NOT-BE-RETAINED")
                rows = pilot.retain()
                self.assertEqual(len(rows), 1)
                payload = (output / rows[0]["file"]).read_text()
                self.assertIn("useful diagnostic", payload)
                self.assertNotIn("owned-private-token", payload)
                self.assertNotIn("owned-signed-proof", payload)
                self.assertFalse(any(path.suffix == ".json" for path in output.iterdir()))
                self.assertEqual((output / rows[0]["file"]).stat().st_mode & 0o777, 0o600)
            finally:
                pilot.receiver.close()


if __name__ == "__main__":
    unittest.main()
