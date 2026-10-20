"""Exact-source, copied-rerun and missing-data controls for SOU-91 metrics."""

from __future__ import annotations

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ci_impact import plan
from ci_runner_metrics import measure, measure_full_dispatch, seconds


HEAD = "a" * 40


def job(job_id, name, start=None, end=None, conclusion="success", runner=1):
    return {
        "id": job_id, "name": name, "runner_id": runner,
        "started_at": start, "completed_at": end,
        "status": "completed", "conclusion": conclusion, "head_sha": HEAD,
    }


class FakeAPI:
    def __init__(self):
        self.pr = {"head": {"sha": HEAD}, "changed_files": 1}
        self.ci = {
            "id": 10, "path": ".github/workflows/ci.yml@refs/pull/1/merge",
            "head_sha": HEAD, "event": "pull_request", "run_attempt": 2,
            "status": "completed", "conclusion": "success",
            "created_at": "2026-10-18T23:55:00Z",
            "run_started_at": "2026-10-19T00:00:00Z",
            "updated_at": "2026-10-19T00:15:00Z",
        }
        self.codeql = {
            "id": 20, "path": "dynamic/github-code-scanning/codeql",
            "head_sha": HEAD, "event": "dynamic", "run_attempt": 1,
            "status": "completed", "conclusion": "success",
            "run_started_at": "2026-10-19T00:01:00Z",
            "updated_at": "2026-10-19T00:07:00Z",
        }
        self.dispatch = {
            **self.ci, "id": 99, "event": "workflow_dispatch", "run_attempt": 1,
        }
        self.docs = job(1, "Documentation links",
                        "2026-10-19T00:00:00Z", "2026-10-19T00:01:00Z")
        self.first = [
            self.docs,
            job(2, "test", "2026-10-19T00:01:00Z",
                "2026-10-19T00:03:00Z", "failure"),
        ]
        self.second = [
            self.docs,  # GitHub copied a successful job from the first attempt.
            job(3, "test", "2026-10-19T00:04:00Z",
                "2026-10-19T00:05:30Z"),
            job(4, "Components / example / unused",
                "2026-10-19T00:06:00Z", "2026-10-19T00:07:00Z",
                conclusion="skipped", runner=None),
        ]
        self.dispatch_jobs = [
            self.docs,
            job(99, "test", "2026-10-19T00:04:00Z", "2026-10-19T00:05:30Z"),
        ]
        self.analyses = [
            job(30 + i, name, f"2026-10-19T00:0{i}:00Z",
                f"2026-10-19T00:0{i + 1}:00Z", runner=30 + i)
            for i, name in enumerate(plan(["README.md"])["codeql"])
        ]

    def get(self, suffix):
        if suffix == "/pulls/1":
            return self.pr
        if suffix == "/actions/runs/99":
            return self.dispatch
        raise AssertionError(suffix)

    def pages(self, suffix, key):
        if suffix.startswith("/pulls/1/files"):
            return [{"filename": "README.md"}]
        if suffix.startswith("/actions/runs?head_sha="):
            return [self.codeql] if "event=dynamic" in suffix else [self.ci]
        if "/actions/runs/10/attempts/1/jobs" in suffix:
            return self.first
        if "/actions/runs/10/attempts/2/jobs" in suffix:
            return self.second
        if "/actions/runs/20/attempts/1/jobs" in suffix:
            return self.analyses
        if "/actions/runs/99/attempts/1/jobs" in suffix:
            return self.dispatch_jobs
        raise AssertionError(suffix)


class RunnerMetricsTests(unittest.TestCase):
    def test_counts_actual_retries_once_and_keeps_codeql_separate(self):
        result = measure(FakeAPI(), 1, run_id=10)
        self.assertEqual(result["schema"], "sou91-runner-observation/2")
        self.assertEqual(result["path_source"], "actual-pr-files")
        self.assertEqual(result["modeled_selective_job_ids"], 1)
        self.assertEqual(result["ci"]["runner_minutes"], 4.5)
        self.assertEqual(result["ci"]["executed_jobs"], 3)
        self.assertEqual(result["ci"]["copied_forward_job_records"], 1)
        self.assertEqual(result["ci"]["wall_minutes"], 20)
        self.assertEqual(result["ci"]["latest_attempt_wall_minutes"], 15)
        self.assertEqual(result["ci"]["latest_attempt_skipped_job_names"],
                         ["Components / example / unused"])
        self.assertEqual(result["ci"]["modeled_required_checks_missing_or_unsuccessful"], [])
        self.assertEqual(result["codeql"]["runner_minutes"], 5)
        self.assertEqual(result["codeql"]["required_analyses_missing_or_unsuccessful"], [])
        self.assertEqual(result["observed_runner_minutes_including_codeql"], 9.5)
        self.assertEqual(result["observed_wall_minutes_including_codeql"], 20)
        self.assertIsNone(result["cache_misses"])
        self.assertIsNone(result["organization_billed_minutes"])

    def test_refuses_a_nonmatching_run_or_incomplete_file_listing(self):
        api = FakeAPI()
        with self.assertRaisesRegex(ValueError, "exact-head"):
            measure(api, 1, run_id=99)
        api.pr["changed_files"] = 2
        with self.assertRaisesRegex(ValueError, "file list incomplete"):
            measure(api, 1)

    def test_modeled_override_is_labeled_and_missing_check_visible(self):
        api = FakeAPI()
        api.second = [entry for entry in api.second if entry["name"] != "Documentation links"]
        result = measure(api, 1, sample_paths=["README.md"], run_id=10)
        self.assertEqual(result["path_source"], "modeled-path-override")
        self.assertEqual(result["ci"]["modeled_required_checks_missing_or_unsuccessful"],
                         ["Documentation links"])

    def test_absent_codeql_is_not_counted_as_zero_minute_complete_evidence(self):
        api = FakeAPI()
        api.codeql = None
        original_pages = api.pages

        def without_codeql(suffix, key):
            if "event=dynamic" in suffix:
                return []
            return original_pages(suffix, key)

        api.pages = without_codeql
        result = measure(api, 1, run_id=10)
        self.assertIsNone(result["codeql"])
        self.assertIsNone(result["observed_runner_minutes_including_codeql"])

    def test_invalid_timing_is_unavailable_not_zero(self):
        self.assertIsNone(seconds("2026-10-19T00:02:00Z", "2026-10-19T00:01:00Z"))

    def test_full_dispatch_is_measured_but_never_accepted_as_pr_evidence(self):
        result = measure_full_dispatch(FakeAPI(), 99, HEAD)
        self.assertEqual(result["schema"], "sou91-full-dispatch-observation/1")
        self.assertEqual(result["source_event"], "workflow_dispatch")
        self.assertFalse(result["admission_eligible"])
        self.assertEqual(result["ci"]["runner_minutes"], 2.5)
        self.assertIn("all-features", result["ci"]["modeled_required_checks_missing_or_unsuccessful"])
        self.assertIsNone(result["organization_billed_minutes"])

    def test_full_dispatch_refuses_stale_event_or_incomplete_run(self):
        api = FakeAPI()
        with self.assertRaisesRegex(ValueError, "requested source/event"):
            measure_full_dispatch(api, 99, "b" * 40)
        api.dispatch["event"] = "pull_request"
        with self.assertRaisesRegex(ValueError, "requested source/event"):
            measure_full_dispatch(api, 99, HEAD)
        api.dispatch["event"] = "workflow_dispatch"
        api.dispatch["status"] = "in_progress"
        with self.assertRaisesRegex(ValueError, "unfinished"):
            measure_full_dispatch(api, 99, HEAD)


if __name__ == "__main__":
    unittest.main()
