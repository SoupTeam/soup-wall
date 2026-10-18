"""Completion events cannot authorize stale sources or consume PR artifacts."""
import argparse
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import ci_admission as gate

HEAD, BASE, MERGE = "a" * 40, "b" * 40, "c" * 40


class API:
    def __init__(self):
        self.run = {"id": 7, "event": "dynamic", "path": "dynamic/github-code-scanning/codeql",
                    "head_sha": HEAD, "status": "completed", "pull_requests": []}
        self.pr = {"number": 1, "state": "open", "draft": False,
                   "head": {"sha": HEAD}, "base": {"sha": BASE}, "merge_commit_sha": MERGE}
        self.posts = []

    def get(self, path):
        if path == "/actions/runs/7": return self.run
        if path == "/pulls/1": return self.pr
        raise AssertionError(path)

    def pages(self, path, key):
        if path == "/pulls?state=open": return [{"number": 1}]
        raise AssertionError("No artifacts or untrusted contents may be fetched: " + path)

    def post(self, path, body): self.posts.append((path, body))


class Completion(unittest.TestCase):
    def test_codeql_without_pr_association_is_routed_by_current_head(self):
        api = API()
        self.assertEqual(gate.completion_targets(api, {"workflow_run": {"id": 7}}), [api.pr])
        api.pr["head"]["sha"] = "d" * 40
        self.assertEqual(gate.completion_targets(api, {"workflow_run": {"id": 7}}), [])

    def test_untrusted_name_event_path_and_stale_completion_do_not_route(self):
        for field, value in (("event", "pull_request_target"), ("path", ".github/workflows/evil.yml"),
                             ("status", "in_progress"), ("head_sha", "main")):
            with self.subTest(field=field):
                api = API(); api.run[field] = value
                self.assertEqual(gate.completion_targets(api, {"workflow_run": {"id": 7}}), [])

    def test_ci_completion_and_duplicate_associations_route_once(self):
        api = API()
        api.run.update(event="pull_request", path=".github/workflows/ci.yml",
                       pull_requests=[{"number": 1}, {"number": 1}])
        self.assertEqual(len(gate.completion_targets(api, {"workflow_run": {"id": 7}})), 1)

    def test_incomplete_evidence_stays_pending_without_polling_or_green(self):
        api = API()
        args = argparse.Namespace(pr=1, wait_seconds=0, dry_run=False)
        with patch.object(gate, "inspect", return_value=(MERGE, gate.Verdict("pending", "CodeQL missing"))), \
             patch.object(gate.time, "sleep", side_effect=AssertionError("idle polling")):
            self.assertEqual(gate.admit(api, args, api.pr), 0)
        self.assertEqual(len(api.posts), 2)
        self.assertTrue(all(body["state"] == "pending" for _, body in api.posts))

    def test_completed_failure_is_not_hidden_by_zero_wait(self):
        api = API()
        args = argparse.Namespace(pr=1, wait_seconds=0, dry_run=False)
        with patch.object(gate, "inspect", return_value=(MERGE, gate.Verdict("failure", "required job failed"))):
            self.assertEqual(gate.admit(api, args, api.pr), 1)
        self.assertEqual(api.posts[-1][1]["state"], "failure")

    def test_readonly_pending_probe_returns_pending_exit_not_success(self):
        api = API()
        args = argparse.Namespace(pr=1, wait_seconds=0, dry_run=True)
        with patch.object(gate, "inspect", return_value=(MERGE, gate.Verdict("pending", "CI unfinished"))):
            self.assertEqual(gate.admit(api, args, api.pr), 2)
        self.assertEqual(api.posts, [])
