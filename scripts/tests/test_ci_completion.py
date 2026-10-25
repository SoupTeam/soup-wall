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
        self.assertIn("types: [in_progress, completed]", trigger)
        # Status writers at the same head must serialize without dropping a
        # queued completion/in-progress event that could revoke old success.
        self.assertIn("group: sou91-admission-${{ github.event_name == 'workflow_run' && github.event.workflow_run.head_sha || github.event.pull_request.head.sha }}", workflow)
        self.assertIn("  cancel-in-progress: false\n  queue: max\n", workflow)

    def run_workflow_command(self, api, payload):
        workflow = (Path(__file__).resolve().parents[2] /
                    ".github/workflows/ci-admission.yml").read_text(encoding="utf-8")
        command = re.search(r"(?m)^        run: (python3 scripts/ci_admission.py .+)$", workflow)
        self.assertIsNotNone(command)
        argv = shlex.split(command.group(1))[1:]
        self.assertNotIn("--pr", argv)
        self.assertEqual(argv[-2:], ["--wait-seconds", "12"])
        # Event-routing tests exercise one decision; the bounded retry has its
        # own clock-controlled test below.
        argv[-1] = "0"
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

    def test_readonly_draft_probe_reports_pending_exit(self):
        api = API()
        api.pr["draft"] = True
        args = argparse.Namespace(pr=1, wait_seconds=0, dry_run=True)
        self.assertEqual(gate.admit(api, args, api.pr), 2)
        self.assertEqual(api.posts, [])

    def test_workflow_command_cannot_publish_a_status_for_a_stale_completed_head(self):
        api = API()
        api.run["head_sha"] = "d" * 40
        with patch.object(gate, "inspect", side_effect=AssertionError("stale head must not be qualified")):
            self.assertEqual(self.run_workflow_command(api, {"workflow_run": {"id": 7}}), 0)
        self.assertEqual(api.posts, [])

    def test_old_pull_request_event_cannot_overwrite_current_candidate(self):
        # A delayed synchronize or ready_for_review event can arrive after a
        # newer head/base has already been evaluated. It has no authority to
        # write even a pending status for the new merge candidate.
        for field in ("head", "base"):
            with self.subTest(field=field):
                api = API()
                event = {"base": {"sha": BASE}, "head": {"sha": HEAD}}
                event[field]["sha"] = "d" * 40
                args = argparse.Namespace(pr=1, wait_seconds=0, dry_run=False)
                with patch.object(gate, "inspect", side_effect=AssertionError("stale event must not inspect")):
                    self.assertEqual(gate.admit(api, args, event), 0)
                self.assertEqual(api.posts, [])

    def test_completion_uses_current_base_after_old_base_event(self):
        api = API()
        new_base = "d" * 40
        api.pr["base"]["sha"] = new_base
        with patch.object(gate, "inspect", return_value=(MERGE, gate.Verdict("pending", "new base needs CI"))) as inspect:
            self.assertEqual(self.run_workflow_command(api, {"workflow_run": {"id": 7}}), 0)
        inspect.assert_called_once_with(api, 1, new_base, HEAD)
        self.assertNotIn("success", [body["state"] for _, body in api.posts])

    def test_codeql_without_pr_association_is_routed_by_current_head(self):
        api = API()
        self.assertEqual(gate.completion_targets(api, {"workflow_run": {"id": 7}}), [api.pr])
        api.pr["head"]["sha"] = "d" * 40
        self.assertEqual(gate.completion_targets(api, {"workflow_run": {"id": 7}}), [])

    def test_untrusted_name_event_path_and_stale_completion_do_not_route(self):
        for field, value in (("event", "pull_request_target"), ("path", ".github/workflows/evil.yml"),
                             ("status", "unknown"), ("head_sha", "main")):
            with self.subTest(field=field):
                api = API(); api.run[field] = value
                self.assertEqual(gate.completion_targets(api, {"workflow_run": {"id": 7}}), [])

    def test_ci_completion_and_duplicate_associations_route_once(self):
        api = API()
        api.run.update(event="pull_request", path=".github/workflows/ci.yml",
                       pull_requests=[{"number": 1}, {"number": 1}])
        self.assertEqual(len(gate.completion_targets(api, {"workflow_run": {"id": 7}})), 1)

    def test_in_progress_rerun_routes_to_clear_old_success(self):
        api = API()
        api.run.update(event="pull_request", path=".github/workflows/ci.yml",
                       status="in_progress", run_attempt=2, pull_requests=[{"number": 1}])
        payload = {"action": "in_progress", "workflow_run": {"id": 7, "run_attempt": 2}}
        with patch.object(gate, "inspect", side_effect=AssertionError("active run cannot qualify")):
            self.assertEqual(self.run_workflow_command(api, payload), 0)
        self.assertEqual([body["state"] for _, body in api.posts], ["pending"])

    def test_late_in_progress_event_rechecks_completed_attempt(self):
        api = API()
        api.run.update(event="pull_request", path=".github/workflows/ci.yml",
                       status="completed", run_attempt=2, pull_requests=[{"number": 1}])
        payload = {"action": "in_progress", "workflow_run": {"id": 7, "run_attempt": 2}}
        with patch.object(gate, "inspect", return_value=(MERGE, gate.Verdict("success", "qualified"))):
            self.assertEqual(self.run_workflow_command(api, payload), 0)
        self.assertEqual([body["state"] for _, body in api.posts], ["pending", "success"])

    def test_old_completion_event_suspends_newer_active_attempt(self):
        api = API()
        api.run.update(event="pull_request", path=".github/workflows/ci.yml",
                       status="in_progress", run_attempt=2, pull_requests=[{"number": 1}])
        payload = {"action": "completed", "workflow_run": {"id": 7, "run_attempt": 1}}
        with patch.object(gate, "inspect", side_effect=AssertionError("new attempt is unfinished")):
            self.assertEqual(self.run_workflow_command(api, payload), 0)
        self.assertEqual([body["state"] for _, body in api.posts], ["pending"])

    def test_incomplete_evidence_stays_pending_without_polling_or_green(self):
        api = API()
        args = argparse.Namespace(pr=1, wait_seconds=0, dry_run=False)
        with patch.object(gate, "inspect", return_value=(MERGE, gate.Verdict("pending", "CodeQL missing"))), \
             patch.object(gate.time, "sleep", side_effect=AssertionError("idle polling")):
            self.assertEqual(gate.admit(api, args, api.pr), 0)
        self.assertEqual(len(api.posts), 2)
        self.assertTrue(all(body["state"] == "pending" for _, body in api.posts))

    def test_bounded_rechecks_never_convert_missing_evidence_into_failure(self):
        api = API()
        args = argparse.Namespace(pr=1, wait_seconds=7, dry_run=False)
        now = [0.0]
        def clock(): return now[0]
        def advance(seconds):
            self.assertLessEqual(seconds, 3)
            now[0] += seconds
        with patch.object(gate, "inspect", return_value=(MERGE, gate.Verdict("pending", "job snapshot incomplete"))) as inspect, \
             patch.object(gate.time, "monotonic", side_effect=clock), \
             patch.object(gate.time, "sleep", side_effect=advance):
            self.assertEqual(gate.admit(api, args, api.pr), 0)
        self.assertGreaterEqual(inspect.call_count, 2)
        self.assertEqual([body["state"] for _, body in api.posts], ["pending", "pending"])

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
