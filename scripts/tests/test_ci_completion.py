"""Completion events cannot authorize stale sources or consume PR artifacts."""
import argparse
import fnmatch
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile
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
    def test_default_codeql_workflow_name_is_subscribed_not_only_run_title(self):
        # Live regression: workflow 351475764 is named CodeQL, whereas run
        # 39380135694 is titled PR #201. workflow_run filters the former.
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/ci-admission.yml").read_text(encoding="utf-8")
        trigger = workflow.split("  workflow_run:\n", 1)[1].split("\npermissions:", 1)[0]
        match = re.search(r"(?m)^    workflows: \[(.+)\]$", trigger)
        self.assertIsNotNone(match)
        subscriptions = [value.strip().strip("\"'") for value in match.group(1).split(",")]
        for name in ("ci", "CodeQL"):
            with self.subTest(workflow_name=name):
                self.assertTrue(any(fnmatch.fnmatchcase(name, pattern)
                                    for pattern in subscriptions))
        # A PR-style run title alone must not stand in for its workflow name.
        self.assertFalse(fnmatch.fnmatchcase("CodeQL", "PR #*"))

    def run_workflow_command(self, api, payload):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/ci-admission.yml").read_text(encoding="utf-8")
        command = re.search(r"(?m)^        run: (python3 scripts/ci_admission.py .+)$", workflow)
        self.assertIsNotNone(command)
        argv = shlex.split(command.group(1))[1:]
        self.assertNotIn("--pr", argv)
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(json.dumps(payload), encoding="utf-8")
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": "SoupTeam/soup-wall",
                                         "GITHUB_TOKEN": "test-only",
                                         "GITHUB_EVENT_PATH": str(event)}), \
                 patch.object(sys, "argv", argv), \
                 patch.object(gate, "GitHub", return_value=api), \
                 patch.object(gate.time, "sleep", side_effect=AssertionError("idle polling")):
                return gate.main()

    def test_workflow_command_routes_completion_using_current_repository_metadata(self):
        # The event snapshot can be stale; only the run ID identifies what to
        # re-read. The workflow command must not need a manually supplied PR.
        payload = {"workflow_run": {"id": 7, "head_sha": "d" * 40,
                                    "pull_requests": [{"number": 99}]}}
        for state, exit_code in (("success", 0), ("pending", 0), ("failure", 1)):
            with self.subTest(state=state):
                api = API()
                with patch.object(gate, "inspect", return_value=(MERGE, gate.Verdict(state, "fixture verdict"))) as inspect:
                    self.assertEqual(self.run_workflow_command(api, payload), exit_code)
                inspect.assert_called_once_with(api, 1, BASE, HEAD)
                self.assertEqual([body["state"] for _, body in api.posts], ["pending", state])
                self.assertTrue(all(path == "/statuses/" + MERGE for path, _ in api.posts))

    def test_workflow_command_cannot_qualify_a_draft_on_completion(self):
        api = API()
        api.pr["draft"] = True
        with patch.object(gate, "inspect", side_effect=AssertionError("draft evidence must not be polled")):
            self.assertEqual(self.run_workflow_command(api, {"workflow_run": {"id": 7}}), 0)
        self.assertEqual(len(api.posts), 1)
        self.assertEqual(api.posts[0][0], "/statuses/" + MERGE)
        self.assertEqual(api.posts[0][1]["state"], "pending")

    def test_workflow_command_cannot_publish_a_status_for_a_stale_completed_head(self):
        api = API()
        api.run["head_sha"] = "d" * 40
        with patch.object(gate, "inspect", side_effect=AssertionError("stale head must not be qualified")):
            self.assertEqual(self.run_workflow_command(api, {"workflow_run": {"id": 7}}), 0)
        self.assertEqual(api.posts, [])

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
