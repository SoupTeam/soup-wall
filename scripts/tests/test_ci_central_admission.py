"""Centralization must preserve exact-source and complete matrix qualification."""
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


def job(name, conclusion="success"):
    return {"name": name, "status": "completed", "conclusion": conclusion, "head_sha": HEAD}


class API:
    def __init__(self):
        self.pr = {"state": "open", "draft": False, "base": {"sha": BASE},
                   "head": {"sha": HEAD}, "merge_commit_sha": MERGE, "changed_files": 1}
        self.runs = [{"id": 1, "path": ".github/workflows/ci.yml", "head_sha": HEAD,
                      "event": "pull_request", "created_at": "2026-10-19", "run_attempt": 1,
                      "status": "completed", "conclusion": "success"}]
        self.codeql = [dict(self.runs[0], id=2, event="dynamic",
                            path="dynamic/github-code-scanning/codeql")]
        self.jobs = {1: [job("impact / Candidate " + MERGE), job("Documentation links"),
                         *[job(n) for n in gate.component_names("scim-directory.yml", ["interoperability"])]],
                     2: [job(n) for n in SELECTION["codeql"]]}
        self.job_reads = []

    def get(self, suffix):
        if suffix == "/pulls/1":
            return self.pr
        if suffix == "/git/commits/" + MERGE:
            return {"parents": [{"sha": BASE}, {"sha": HEAD}]}
        raise AssertionError(suffix)

    def pages(self, suffix, key):
        if suffix.startswith("/pulls/1/files"):
            return [{"filename": "README.md"}]
        if suffix.startswith("/actions/runs?"):
            return self.codeql if "event=dynamic" in suffix else self.runs
        if suffix.startswith("/actions/runs/"):
            n = int(suffix.split("/")[3])
            self.job_reads.append(n)
            return self.jobs[n]
        raise AssertionError(suffix)


class CentralAdmission(unittest.TestCase):
    def assess(self, api):
        with patch.object(gate, "plan", return_value=SELECTION), patch.dict(os.environ, {"SOU91_SELECTIVE_CI": ""}):
            return gate.inspect(api, 1, BASE, HEAD)[1]

    def test_central_run_qualifies_all_members_and_is_fetched_once(self):
        api = API()
        self.assertEqual(self.assess(api).state, "success")
        self.assertEqual(api.job_reads.count(1), 1)

    def test_each_missing_failed_skipped_cancelled_or_duplicate_member_blocks(self):
        for mode in ("missing", "failure", "skipped", "cancelled", "duplicate"):
            with self.subTest(mode=mode):
                api = API()
                if mode == "missing": api.jobs[1].pop()
                elif mode == "duplicate": api.jobs[1].append(dict(api.jobs[1][-1]))
                else: api.jobs[1][-1]["conclusion"] = mode
                self.assertEqual(self.assess(api).state, "failure")

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
