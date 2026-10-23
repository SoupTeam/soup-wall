# SPDX-License-Identifier: Apache-2.0
"""Fail-closed controls for the long-session experiment and its observations."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_stability as S
from ci_components import blocks, generated
from ci_impact import WORKFLOW_JOBS


def complete():
    idle = {"processes": 5, "fds": 80, "threads": 16, "rss_bytes": 32000000}
    return {"workload": S.plan(), "workload_sha256": S.digest(S.plan()), "elapsed_seconds": 3601,
        "source_before": {"commit": "a" * 40, "dirty": False},
        "source_after": {"commit": "a" * 40, "dirty": False}, "selected_unchanged": True, "skipped": 0,
        "iterations": [{"index": i, "status": "pass", "completed_workflows": 20,
                        "false_interruptions": 0, "elapsed_seconds": 20, "started_seconds": i * 300,
                        "idle": idle.copy()} for i in range(12)],
        **{key: {"passed": True} for key in ("sandbox", "calibration", "final_follow_up", "cleanup", "observer_calibration")},
        "faults": {key: {"passed": True} for key in S.FAULTS.values()},
        "observer": {"samples": 3600, "max_gap_seconds": 1.1, "errors": [], "stopped": True, "peaks": idle.copy()},
        "native_samples": [{"seconds": i * 5} for i in range(720)]}


class StabilityControls(unittest.TestCase):
    def rejects(self, mutation):
        report = complete()
        mutation(report)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            S.grade(report)

    def test_hour_and_original_denominator_are_mandatory(self):
        self.assertEqual(S.grade(complete())["completed_workflows"], 240)
        for mutation in (lambda r: r.update(elapsed_seconds=3599), lambda r: r["iterations"].pop(),
                         lambda r: r["iterations"][0].update(completed_workflows=19),
                         lambda r: r.update(workload=S.plan("smoke")),
                         lambda r: r["iterations"][4].update(started_seconds=0)):
            with self.subTest(mutation=mutation):
                self.rejects(mutation)

    def test_frozen_bounds_cannot_be_raised_after_execution(self):
        self.rejects(lambda r: r["workload"]["resource_bounds"].update(fds=99999))
        self.rejects(lambda r: r.update(workload_sha256="0" * 64))

    def test_missing_faults_source_and_cleanup_fail(self):
        for mutation in (lambda r: r["faults"].pop("server-death"), lambda r: r["faults"]["daemon-outage"].update(passed=False),
                         lambda r: r["source_after"].update(commit="b" * 40), lambda r: r.update(selected_unchanged=False),
                         lambda r: r["cleanup"].update(passed=False), lambda r: r.update(skipped=1),
                         lambda r: r["iterations"][2].update(false_interruptions=1)):
            with self.subTest(mutation=mutation):
                self.rejects(mutation)

    def test_empty_stale_unsupported_observers_are_not_safe(self):
        for mutation in (lambda r: r["observer"].update(samples=0), lambda r: r["observer"].update(errors=["PermissionError"]),
                         lambda r: r["observer"].update(max_gap_seconds=6), lambda r: r["observer"]["peaks"].update(fds=0),
                         lambda r: r["observer"]["peaks"].update(rss_bytes=S.BOUNDS["rss_bytes"] + 1),
                         lambda r: r.update(native_samples=[])):
            with self.subTest(mutation=mutation):
                self.rejects(mutation)

    def test_idle_leaks_are_not_hidden_by_absolute_resource_ceiling(self):
        self.rejects(lambda r: r["iterations"][7]["idle"].update(fds=500))
        self.rejects(lambda r: r["iterations"][7]["idle"].update(processes=6))

    def test_native_limits_and_counters_must_be_explicit(self):
        instance = {"instance_id": "owned", "pilot_collectors": [], "provenance": {
            "accounting_revision": "sw-provenance-storage/1", "limits": S.DEFAULT_PROVENANCE.copy(),
            "usage": {"sessions": 0, "retained_bytes": 0, "max_session_retained_bytes": 0}}}
        self.assertEqual(S.native_sample(instance)["active_collectors"], 0)
        for mutation in (lambda r: r["provenance"]["usage"].pop("sessions"),
                         lambda r: r["provenance"]["limits"].update(max_sessions=1024),
                         lambda r: r["provenance"]["usage"].update(retained_bytes=67108865)):
            changed = copy.deepcopy(instance)
            mutation(changed)
            with self.assertRaises((ValueError, KeyError)):
                S.native_sample(changed)

    def test_proc_missing_root_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                S.snapshot(4242, 1, proc=Path(directory))

    def test_unreadable_proc_metadata_never_becomes_empty_safe_list(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "4242"
            root.mkdir()
            fields = ["S", *(["0"] * 18), "123", "0", "0"]
            (root / "stat").write_text("4242 (owned) " + " ".join(fields))
            with self.assertRaises((ValueError, KeyError)):
                S.process_row(4242, Path(directory))

    def test_long_job_is_manual_only_and_absent_from_pr_components(self):
        workflow = (ROOT / ".github/workflows/mcp-real-filesystem.yml").read_text()
        jobs = blocks(workflow)
        manual = jobs["manual-long-session"]
        self.assertIn("if: github.event_name == 'workflow_dispatch' && contains(fromJSON('[\"smoke\",\"soak\"]'), github.event.inputs.stability_mode)", manual)
        self.assertNotIn("manual-long-session", WORKFLOW_JOBS["mcp-real-filesystem.yml"])
        self.assertNotIn("manual-long-session:", generated())
        self.assertIn("default: off", workflow)
        self.assertIn("--property=KillMode=control-group", manual)
        self.assertIn("if: always()", manual)

    def test_plan_without_run_starts_no_process(self):
        spec = importlib.util.spec_from_file_location("stability_driver", ROOT / "scripts/qualify-pilot-stability.py")
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        from unittest.mock import patch
        from contextlib import redirect_stdout
        import io
        output = io.StringIO()
        with patch.object(sys, "argv", ["qualify-pilot-stability.py"]), patch.object(driver.subprocess, "Popen", side_effect=AssertionError), redirect_stdout(output):
            self.assertEqual(driver.main(), 0)
        self.assertFalse(json.loads(output.getvalue())["executed"])


if __name__ == "__main__":
    unittest.main()
