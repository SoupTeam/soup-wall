"""Centralization must preserve exact-source and complete matrix qualification."""
from copy import deepcopy
from itertools import count
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import ci_admission as gate

BASE, HEAD, MERGE = "a" * 40, "b" * 40, "c" * 40
SELECTION = {"workflows": {"ci.yml": ["documentation"],
                          "scim-directory.yml": ["interoperability"]},
             "codeql": ["Analyze (rust)", "Analyze (python)", "Analyze (actions)",
                        "Analyze (c-cpp)", "Analyze (javascript-typescript)"]}


JOB_IDS = count(100)


def job(name, conclusion="success", run_id=1, attempt=1):
    return {"id": next(JOB_IDS), "name": name, "status": "completed",
            "conclusion": conclusion, "head_sha": HEAD, "run_id": run_id,
            "run_attempt": attempt}


class API:
    def __init__(self):
        self.pr = {"state": "open", "draft": False, "base": {"sha": BASE},
                   "head": {"sha": HEAD}, "merge_commit_sha": MERGE, "changed_files": 1}
        self.parents = [BASE, HEAD]
        self.pr_reads = 0
        self.next_pr_after_first = None
        self.runs = [{"id": 1, "path": ".github/workflows/ci.yml", "head_sha": HEAD,
                      "event": "pull_request", "created_at": "2026-10-19", "run_attempt": 1,
                      "status": "completed", "conclusion": "success"}]
        self.codeql = [dict(self.runs[0], id=2, event="dynamic",
                            path="dynamic/github-code-scanning/codeql")]
        self.jobs = {1: [job("impact / Candidate " + MERGE), job("Documentation links"),
                         *[job(n) for n in gate.component_names("scim-directory.yml", ["interoperability"])]],
                     2: [job(n, run_id=2) for n in SELECTION["codeql"]]}
        self.attempt_jobs = {}
        self.direct_jobs = {}
        self.job_reads = []
        self.job_paths = []
        self.run_list_reads = 0
        self.new_run_on_second_list = None
        self.second_runs_override = None
        self.codeql_list_reads = 0
        self.new_codeql_on_second_list = None
        self.second_codeql_override = None

    def get(self, suffix):
        if suffix == "/pulls/1":
            self.pr_reads += 1
            if self.pr_reads > 1 and self.next_pr_after_first is not None:
                return self.next_pr_after_first
            return self.pr
        if suffix == "/git/commits/" + MERGE:
            return {"parents": [{"sha": sha} for sha in self.parents]}
        if suffix.startswith("/actions/runs/"):
            return next(run for run in self.runs + self.codeql
                        if run["id"] == int(suffix.rsplit("/", 1)[1]))
        if suffix.startswith("/actions/jobs/"):
            job_id = int(suffix.rsplit("/", 1)[1])
            if job_id in self.direct_jobs:
                return self.direct_jobs[job_id]
            for entries in list(self.attempt_jobs.values()) + list(self.jobs.values()):
                for entry in entries:
                    if entry["id"] == job_id:
                        return entry
            raise AssertionError("unknown job ID " + str(job_id))
        raise AssertionError(suffix)

    def pages(self, suffix, key):
        if suffix.startswith("/pulls/1/files"):
            return [{"filename": "README.md"}]
        if suffix.startswith("/actions/runs?"):
            if "event=dynamic" in suffix:
                self.codeql_list_reads += 1
                if self.codeql_list_reads > 1 and self.second_codeql_override is not None:
                    return self.second_codeql_override
                if self.codeql_list_reads > 1 and self.new_codeql_on_second_list is not None:
                    return self.codeql + [self.new_codeql_on_second_list]
                return self.codeql
            self.run_list_reads += 1
            if self.run_list_reads > 1 and self.second_runs_override is not None:
                return self.second_runs_override
            if self.run_list_reads > 1 and self.new_run_on_second_list is not None:
                return self.runs + [self.new_run_on_second_list]
            return self.runs
        if suffix.startswith("/actions/runs/"):
            parts = suffix.split("/")
            n = int(parts[3])
            attempt = int(parts[5])
            self.job_reads.append(n)
            self.job_paths.append(suffix)
            return self.attempt_jobs.get((n, attempt), self.jobs[n])
        raise AssertionError(suffix)


class CentralAdmission(unittest.TestCase):
    def assess(self, api):
        with patch.object(gate, "plan", return_value=SELECTION), patch.dict(os.environ, {"SOU91_SELECTIVE_CI": ""}):
            return gate.inspect(api, 1, BASE, HEAD)[1]

    def test_central_run_qualifies_all_members_and_is_fetched_once(self):
        api = API()
        self.assertEqual(self.assess(api).state, "success")
        self.assertEqual(api.job_reads.count(1), 1)

    def test_missing_member_waits_for_api_snapshot_to_complete(self):
        api = API()
        missing = api.jobs[1].pop()
        self.assertEqual(self.assess(api).state, "pending")
        api.jobs[1].append(missing)
        self.assertEqual(self.assess(api).state, "success")

    def test_explicit_failed_skipped_cancelled_or_duplicate_member_blocks(self):
        for mode in ("failure", "skipped", "cancelled", "neutral", "duplicate"):
            with self.subTest(mode=mode):
                api = API()
                if mode == "duplicate": api.jobs[1].append(dict(api.jobs[1][-1]))
                else: api.jobs[1][-1]["conclusion"] = mode
                self.assertEqual(self.assess(api).state, "failure")

    def test_incomplete_job_and_planner_remain_pending_until_current_snapshot_is_final(self):
        for index in (0, -1):
            with self.subTest(index=index):
                api = API()
                target = api.jobs[1][index]
                target.update(status="in_progress", conclusion=None)
                self.assertEqual(self.assess(api).state, "pending")
                target.update(status="completed", conclusion="success")
                self.assertEqual(self.assess(api).state, "success")

    def test_conflicting_list_and_direct_job_evidence_waits_for_reconciliation(self):
        api = API()
        listed = api.jobs[1][-1]
        api.direct_jobs[listed["id"]] = dict(listed)
        listed["conclusion"] = "failure"
        inconsistent = self.assess(api)
        self.assertEqual(inconsistent.state, "pending")
        self.assertIn("job " + str(listed["id"]) + " attempt 1", inconsistent.reason)
        self.assertIn("list=completed/failure detail=completed/success", inconsistent.reason)
        listed["conclusion"] = "success"
        self.assertEqual(self.assess(api).state, "success")

        # A direct failed job is also not hidden behind an earlier green list.
        api.direct_jobs[listed["id"]]["conclusion"] = "failure"
        self.assertEqual(self.assess(api).state, "pending")
        listed["conclusion"] = "failure"
        self.assertEqual(self.assess(api).state, "failure")

    def test_stale_attempt_or_head_on_named_job_never_qualifies(self):
        for field, stale in (("run_attempt", 2), ("head_sha", "d" * 40)):
            with self.subTest(field=field):
                api = API()
                api.jobs[1][-1][field] = stale
                self.assertEqual(self.assess(api).state, "failure")

    def test_newer_attempt_never_falls_back_to_successful_old_attempt(self):
        api = API()
        old_jobs = list(api.jobs[1])
        api.runs[0]["run_attempt"] = 2
        api.attempt_jobs[(1, 1)] = old_jobs
        api.attempt_jobs[(1, 2)] = [job(entry["name"], attempt=2) for entry in old_jobs[:-1]]
        self.assertEqual(self.assess(api).state, "pending")
        api.attempt_jobs[(1, 2)] = [job(entry["name"], attempt=2) for entry in old_jobs]
        self.assertEqual(self.assess(api).state, "success")
        api.attempt_jobs[(1, 2)][-1]["conclusion"] = "failure"
        self.assertEqual(self.assess(api).state, "failure")
        self.assertTrue(any("/attempts/2/jobs" in path for path in api.job_paths))

    def test_newer_run_at_same_head_never_falls_back_to_older_green_run(self):
        api = API()
        api.runs.append(dict(api.runs[0], id=3, created_at="2026-10-20"))
        api.jobs[3] = [job(entry["name"], run_id=3) for entry in api.jobs[1][:-1]]
        self.assertEqual(self.assess(api).state, "pending")
        api.jobs[3] = [job(entry["name"], run_id=3) for entry in api.jobs[1]]
        self.assertEqual(self.assess(api).state, "success")
        api.jobs[3][-1]["conclusion"] = "failure"
        self.assertEqual(self.assess(api).state, "failure")

    def test_rerun_of_older_run_supersedes_newer_created_green_run(self):
        api = API()
        api.runs.append(dict(api.runs[0], id=3, created_at="2026-10-20",
                             run_started_at="2026-10-20T10:00:00Z"))
        api.jobs[3] = [job(entry["name"], run_id=3) for entry in api.jobs[1]]
        api.runs[0].update(run_attempt=2, run_started_at="2026-10-21T10:00:00Z",
                           status="in_progress", conclusion=None)
        self.assertEqual(self.assess(api).state, "pending")
        api.runs[0].update(status="completed", conclusion="failure")
        self.assertEqual(self.assess(api).state, "failure")

    def test_completed_run_without_conclusion_remains_pending(self):
        for source in ("ci", "codeql"):
            with self.subTest(source=source):
                api = API()
                target = api.runs[0] if source == "ci" else api.codeql[0]
                target["conclusion"] = None
                self.assertEqual(self.assess(api).state, "pending")
                target["conclusion"] = "failure"
                self.assertEqual(self.assess(api).state, "failure")

    def test_new_same_head_run_appearing_during_inspection_prevents_old_success(self):
        api = API()
        api.new_run_on_second_list = dict(api.runs[0], id=3, created_at="2026-10-20",
                                          status="in_progress", conclusion=None)
        self.assertNotEqual(self.assess(api).state, "success")

    def test_new_same_head_codeql_run_during_inspection_prevents_old_success(self):
        api = API()
        api.new_codeql_on_second_list = dict(api.codeql[0], id=4, created_at="2026-10-20",
                                             status="in_progress", conclusion=None)
        self.assertNotEqual(self.assess(api).state, "success")

    def test_same_attempt_changed_outcome_on_final_listing_never_qualifies(self):
        for source in ("ci", "codeql"):
            for status, conclusion in (("in_progress", None),
                                       ("completed", "failure")):
                with self.subTest(source=source, status=status):
                    api = API()
                    original = api.runs[0] if source == "ci" else api.codeql[0]
                    changed = dict(original, run_started_at="2026-10-22T10:00:00Z",
                                   status=status, conclusion=conclusion)
                    if source == "ci":
                        api.second_runs_override = [changed]
                    else:
                        api.second_codeql_override = [changed]
                    self.assertEqual(self.assess(api).state, "pending")

    def test_old_names_and_wrong_merge_planner_do_not_qualify_central_run(self):
        for mode in ("old-name", "wrong-merge", "no-components"):
            with self.subTest(mode=mode):
                api = API()
                if mode == "old-name": api.jobs[1][-1]["name"] = "interoperability (postgres)"
                elif mode == "wrong-merge": api.jobs[1][0]["name"] = "impact / Candidate " + "d" * 40
                else: api.jobs[1] = api.jobs[1][:2]
                self.assertNotEqual(self.assess(api).state, "success")

    def test_legacy_failed_run_cannot_be_hidden_by_a_green_central_run(self):
        api = API()
        api.runs.append(dict(api.runs[0], id=3, path=".github/workflows/scim-directory.yml", conclusion="failure"))
        self.assertEqual(self.assess(api).state, "failure")

    def test_codeql_is_still_required_and_exact_head_bound(self):
        for mode in ("missing", "stale", "neutral"):
            with self.subTest(mode=mode):
                api = API()
                if mode == "missing": api.codeql = []
                elif mode == "stale": api.jobs[2][0]["head_sha"] = "d" * 40
                else: api.jobs[2][0]["conclusion"] = "neutral"
                self.assertNotEqual(self.assess(api).state, "success")

    def test_every_codeql_language_must_be_present_in_current_attempt(self):
        for missing_name in SELECTION["codeql"]:
            with self.subTest(missing_name=missing_name):
                api = API()
                api.codeql[0]["run_attempt"] = 2
                api.attempt_jobs[(2, 1)] = list(api.jobs[2])
                api.attempt_jobs[(2, 2)] = [job(n, run_id=2, attempt=2)
                                            for n in SELECTION["codeql"] if n != missing_name]
                self.assertEqual(self.assess(api).state, "pending")
                api.attempt_jobs[(2, 2)].append(job(missing_name, run_id=2, attempt=2))
                self.assertEqual(self.assess(api).state, "success")
                api.attempt_jobs[(2, 2)][-1]["conclusion"] = "failure"
                self.assertEqual(self.assess(api).state, "failure")

    def test_draft_or_changed_merge_parents_cannot_qualify_evidence(self):
        api = API()
        api.pr["draft"] = True
        self.assertEqual(self.assess(api).state, "failure")
        api.pr["draft"] = False
        api.parents = [BASE, "d" * 40]
        self.assertEqual(self.assess(api).state, "failure")

    def test_draft_or_source_transition_during_snapshot_cannot_turn_green(self):
        for change in ("draft", "head", "base"):
            with self.subTest(change=change):
                api = API()
                newer = deepcopy(api.pr)
                if change == "draft":
                    newer["draft"] = True
                else:
                    newer[change]["sha"] = "d" * 40
                api.next_pr_after_first = newer
                self.assertNotEqual(self.assess(api).state, "success")
