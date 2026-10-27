"""Completion bursts must save work without preserving stale green authority."""
from copy import deepcopy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_admission as gate
from test_ci_central_admission import API, BASE, HEAD, MERGE, SELECTION, job


REVISION = "e" * 40
ENV = {"SOU91_SELECTIVE_CI": "", "SOU160_ADMISSION_REUSE": gate.REUSE_SWITCH,
       "SOU160_VERIFIER_SHA": REVISION, "GITHUB_RUN_ID": "77",
       "GITHUB_RUN_ATTEMPT": "1"}


class ReuseAPI(API):
    repo = "SoupTeam/soup-wall"

    def __init__(self):
        super().__init__()
        self.pr["number"] = 1
        self.pr["updated_at"] = "2026-10-27T00:00:00Z"
        self.statuses = []
        self.posts = []
        self.requests = []
        self.status_error = False
        self.run_api_error = False
        self.verifier = {"id": 77, "workflow_id": gate.ADMISSION_WORKFLOW_ID,
                         "path": ".github/workflows/ci-admission.yml",
                         "event": "workflow_run", "head_sha": REVISION,
                         "run_attempt": 1, "status": "completed", "conclusion": "success"}

    def get(self, suffix):
        self.requests.append(("get", suffix))
        if suffix == "/commits/" + MERGE + "/statuses?per_page=100":
            if self.status_error:
                raise RuntimeError("synthetic API outage")
            return deepcopy(self.statuses)
        if suffix == "/actions/runs/77":
            return deepcopy(self.verifier)
        if suffix == "/git/commits/" + "f" * 40:
            return {"parents": [{"sha": BASE}, {"sha": HEAD}]}
        return super().get(suffix)

    def pages(self, suffix, key):
        self.requests.append(("pages", suffix))
        if self.run_api_error and suffix.startswith("/actions/runs?"):
            raise RuntimeError("synthetic run API outage")
        if suffix == "/pulls?state=open":
            return [deepcopy(self.pr)]
        return super().pages(suffix, key)

    def post(self, suffix, body):
        self.requests.append(("post", suffix))
        self.posts.append((suffix, deepcopy(body)))
        if suffix == "/statuses/" + MERGE:
            self.statuses.insert(0, {"id": len(self.posts), "context": gate.CONTEXT,
                                     "state": body["state"],
                                     "target_url": body.get("target_url"),
                                     "creator": {"id": gate.GITHUB_ACTIONS_BOT_ID}})
        return {}


class DuplicateAdmission(unittest.TestCase):
    def admit(self, api, event=None):
        from argparse import Namespace
        event = event or {"number": 1, "base": {"sha": BASE}, "head": {"sha": HEAD}}
        with patch.object(gate, "plan", return_value=SELECTION), patch.dict(os.environ, ENV):
            return gate.admit(api, Namespace(pr=1, wait_seconds=0, dry_run=False), event)

    def qualified(self):
        api = ReuseAPI()
        self.assertEqual(self.admit(api), 0)
        self.assertEqual([body["state"] for _, body in api.posts], ["pending", "success"])
        self.assertIn("#sou160-v1.1.", api.posts[-1][1]["target_url"])
        return api

    def test_unchanged_duplicate_confirms_job_details_without_status_flicker(self):
        api = self.qualified()
        before_calls, before_posts = len(api.requests), len(api.posts)
        before_direct = sum(path.startswith("/actions/jobs/") for method, path in api.requests
                            if method == "get")
        self.assertEqual(self.admit(api), 0)
        self.assertEqual(len(api.posts), before_posts)
        duplicate_calls = api.requests[before_calls:]
        self.assertEqual(sum(path.startswith("/actions/jobs/") for method, path in duplicate_calls
                             if method == "get"), 9)
        self.assertEqual(before_direct, 9)
        self.assertGreater(sum(path.startswith("/actions/runs?") for method, path in duplicate_calls
                               if method == "pages"), 1)
        self.assertGreater(sum(path == "/pulls/1" for method, path in duplicate_calls
                               if method == "get"), 1)

    def test_switch_absent_restores_full_job_confirmation_and_status_writes(self):
        from argparse import Namespace
        api = self.qualified()
        before_direct = sum(path.startswith("/actions/jobs/") for method, path in api.requests
                            if method == "get")
        with patch.object(gate, "plan", return_value=SELECTION), \
                patch.dict(os.environ, dict(ENV, SOU160_ADMISSION_REUSE="")):
            self.assertEqual(gate.admit(
                api, Namespace(pr=1, wait_seconds=0, dry_run=False),
                {"number": 1, "base": {"sha": BASE}, "head": {"sha": HEAD}}), 0)
        after_direct = sum(path.startswith("/actions/jobs/") for method, path in api.requests
                           if method == "get")
        self.assertEqual(after_direct - before_direct, 9)
        self.assertEqual([body["state"] for _, body in api.posts[-2:]],
                         ["pending", "success"])

    def test_late_duplicate_cannot_reuse_after_selected_rerun_starts_or_fails(self):
        for state, conclusion in (("in_progress", None), ("completed", "failure")):
            with self.subTest(state=state):
                api = self.qualified()
                api.runs[0].update(run_attempt=2, status=state, conclusion=conclusion,
                                   run_started_at="2026-10-27T00:00:00Z")
                self.assertEqual(self.admit(api), 0 if state == "in_progress" else 1)
                self.assertEqual(api.posts[-1][1]["state"],
                                 "pending" if state == "in_progress" else "failure")

    def test_new_run_appearing_during_duplicate_recheck_invalidates_green(self):
        api = self.qualified()
        api.run_list_reads = 0
        api.new_run_on_second_list = dict(api.runs[0], id=3,
                                          created_at="2026-10-27T01:00:00Z",
                                          run_started_at="2026-10-27T01:00:00Z",
                                          status="in_progress", conclusion=None)
        self.assertEqual(self.admit(api), 0)
        self.assertEqual(api.posts[-1][1]["state"], "pending")

    def test_ci_codeql_completion_interleaving_suspends_then_reuses_only_new_attempt(self):
        api = self.qualified()
        api.codeql[0].update(run_attempt=2, status="in_progress", conclusion=None,
                             run_started_at="2026-10-27T00:00:00Z")
        event = {"workflow_run": {"id": 2, "run_attempt": 2}}
        targets = gate.completion_targets(api, event)
        self.assertEqual([pr["number"] for pr in targets], [1])
        gate.suspend_candidate(api, targets[0], 2)
        self.assertEqual(api.posts[-1][1]["state"], "pending")
        # A late CI completion cannot reuse the old CodeQL attempt or make
        # the pending candidate green while the replacement is unfinished.
        self.admit(api)
        self.assertEqual(api.posts[-1][1]["state"], "pending")
        api.codeql[0].update(status="completed", conclusion="success")
        api.attempt_jobs[(2, 2)] = [job(name, run_id=2, attempt=2)
                                    for name in SELECTION["codeql"]]
        self.assertEqual(self.admit(api), 0)
        self.assertEqual(api.posts[-1][1]["state"], "success")
        before = len(api.posts)
        self.assertEqual(self.admit(api), 0)
        self.assertEqual(len(api.posts), before)

    def test_codeql_new_attempt_missing_analysis_or_failed_member_blocks(self):
        for mode in ("attempt", "missing", "no-codeql", "failed"):
            with self.subTest(mode=mode):
                api = self.qualified()
                if mode == "attempt":
                    api.codeql[0].update(run_attempt=2, status="in_progress", conclusion=None)
                elif mode == "missing":
                    api.jobs[2].pop()
                elif mode == "no-codeql":
                    api.codeql.clear()
                else:
                    api.jobs[2][-1]["conclusion"] = "failure"
                    api.direct_jobs[api.jobs[2][-1]["id"]] = deepcopy(api.jobs[2][-1])
                self.assertNotEqual(api.posts[-1][1]["state"], "pending")
                self.admit(api)
                self.assertIn(api.posts[-1][1]["state"], {"pending", "failure"})

    def test_direct_job_disagreement_after_old_success_must_not_be_reused(self):
        api = self.qualified()
        listed = api.jobs[1][-1]
        api.direct_jobs[listed["id"]] = dict(listed, conclusion="failure")
        before = len(api.posts)
        self.assertEqual(self.admit(api), 0)
        self.assertGreater(len(api.posts), before)
        self.assertEqual(api.posts[-1][1]["state"], "pending")

    def test_source_replacement_draft_and_old_writer_never_retain_green(self):
        for change in ("head", "base", "merge", "draft"):
            with self.subTest(change=change):
                api = self.qualified()
                newer = deepcopy(api.pr)
                if change == "draft":
                    newer["draft"] = True
                elif change == "merge":
                    newer["merge_commit_sha"] = "f" * 40
                else:
                    newer[change]["sha"] = "f" * 40
                api.pr_reads = 0
                api.next_pr_after_first = newer
                before = len(api.posts)
                self.assertEqual(self.admit(api), 0)
                if change == "draft":
                    self.assertEqual([body["state"] for _, body in api.posts[before:]],
                                     ["pending"])
                else:
                    self.assertEqual(len(api.posts), before)

    def test_cancelled_prior_verifier_or_api_failure_cannot_authorize_reuse(self):
        for mode in ("cancelled", "api", "revision", "receipt"):
            with self.subTest(mode=mode):
                api = self.qualified()
                if mode == "cancelled":
                    api.verifier["conclusion"] = "cancelled"
                elif mode == "api":
                    api.status_error = True
                elif mode == "revision":
                    api.verifier["head_sha"] = "f" * 40
                else:
                    api.statuses[0]["target_url"] = "https://example.invalid/forged"
                before = len(api.posts)
                self.assertEqual(self.admit(api), 0)
                self.assertEqual(len(api.posts), before + 2)
                self.assertEqual([body["state"] for _, body in api.posts[-2:]],
                                 ["pending", "success"])

    def test_persistent_api_outage_keeps_required_context_pending(self):
        api = self.qualified()
        api.run_api_error = True
        self.assertEqual(self.admit(api), 0)
        self.assertEqual(api.posts[-1][1]["state"], "pending")

    def test_support_selection_change_cannot_reuse_previous_success(self):
        from argparse import Namespace
        api = self.qualified()
        changed = deepcopy(SELECTION)
        changed["workflows"]["ci.yml"].append("python-classifier")
        before = len(api.posts)
        with patch.object(gate, "plan", return_value=changed), patch.dict(os.environ, ENV):
            self.assertEqual(gate.admit(
                api, Namespace(pr=1, wait_seconds=0, dry_run=False),
                {"number": 1, "base": {"sha": BASE}, "head": {"sha": HEAD}}), 0)
        self.assertEqual(api.posts[before][1]["state"], "pending")
        self.assertEqual(api.posts[-1][1]["state"], "pending")

    def test_ready_again_after_draft_transition_cannot_reuse_old_receipt(self):
        api = self.qualified()
        # Even if a Draft event's writer was lost, the issue/PR update epoch
        # changes across Draft -> Ready and requires full qualification.
        api.pr["updated_at"] = "2026-10-27T01:00:00Z"
        before = len(api.posts)
        self.assertEqual(self.admit(api), 0)
        self.assertEqual([body["state"] for _, body in api.posts[before:]],
                         ["pending", "success"])

    def test_epoch_changes_at_final_pr_read_cannot_reuse_old_receipt(self):
        api = self.qualified()
        api.pr_reads = 0
        original_get = api.get

        def get_with_ready_draft_ready_transition(suffix):
            # admit's initial PR read and inspect's first PR read still see
            # the old Ready epoch. At inspect's final read the PR has become
            # Ready again, with identical source but a newer update epoch.
            if suffix == "/pulls/1" and api.pr_reads == 2:
                api.pr["updated_at"] = "2026-10-27T01:00:00Z"
            return original_get(suffix)

        before = len(api.posts)
        with patch.object(api, "get", side_effect=get_with_ready_draft_ready_transition):
            self.assertEqual(self.admit(api), 0)
        self.assertEqual([body["state"] for _, body in api.posts[before:]],
                         ["pending", "success"])
        self.assertEqual(api.posts[-1][1]["state"], "success")

    def test_concurrent_pending_writer_blocks_reuse_and_different_selection_rechecks(self):
        api = self.qualified()
        api.statuses.insert(0, {"id": 100, "context": gate.CONTEXT, "state": "pending",
                                "creator": {"id": gate.GITHUB_ACTIONS_BOT_ID}})
        before = len(api.posts)
        self.assertEqual(self.admit(api), 0)
        self.assertEqual(len(api.posts), before + 2)
        api = self.qualified()
        api.jobs[1][-1]["id"] = 9999
        api.direct_jobs[9999] = deepcopy(api.jobs[1][-1])
        before = len(api.posts)
        self.assertEqual(self.admit(api), 0)
        self.assertEqual(len(api.posts), before + 2)


if __name__ == "__main__":
    unittest.main()
