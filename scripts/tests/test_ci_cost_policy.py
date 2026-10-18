"""Draft/ready transition and post-merge cost controls must not qualify drafts."""

import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import ci_admission
from ci_impact import WORKFLOW_JOBS


class DraftAPI:
    def __init__(self):
        self.posts = []
        self.current = {"state": "open", "draft": True,
                        "base": {"sha": "a" * 40}, "head": {"sha": "b" * 40},
                        "merge_commit_sha": "c" * 40}

    def get(self, suffix):
        if suffix != "/pulls/1":
            raise AssertionError("Draft admission must not fetch or poll job evidence")
        return self.current

    def post(self, suffix, body):
        self.posts.append((suffix, body))


class CostPolicyTests(unittest.TestCase):
    def test_draft_cannot_receive_a_success_verdict(self):
        api = DraftAPI()
        sha, verdict = ci_admission.inspect(api, 1, "a" * 40, "b" * 40)
        self.assertEqual(sha, "c" * 40)
        self.assertEqual(verdict.state, "failure")
        self.assertIn("draft", verdict.reason)

    def test_draft_cli_leaves_pending_without_sleep_or_job_polling(self):
        for dry_run in (False, True):
            with self.subTest(dry_run=dry_run), tempfile.TemporaryDirectory() as directory:
                api = DraftAPI()
                event = Path(directory) / "event.json"
                event.write_text(json.dumps({"pull_request": {
                    "number": 1, "base": {"repo": {"full_name": "SoupTeam/soup-wall"}},
                }}), encoding="utf-8")
                args = ["ci_admission.py", "--pr", "1"] + (["--dry-run"] if dry_run else [])
                with patch.dict(os.environ, {"GITHUB_REPOSITORY": "SoupTeam/soup-wall",
                                             "GITHUB_TOKEN": "test-only",
                                             "GITHUB_EVENT_PATH": str(event)}), \
                     patch.object(sys, "argv", args), \
                     patch.object(ci_admission, "GitHub", return_value=api), \
                     patch.object(ci_admission.time, "sleep", side_effect=AssertionError("idle runner")):
                    self.assertEqual(ci_admission.main(), 0)
                self.assertEqual(len(api.posts), 0 if dry_run else 1)
                for suffix, body in api.posts:
                    self.assertEqual(suffix, "/statuses/" + "c" * 40)
                    self.assertEqual(body["state"], "pending")
                    self.assertEqual(body["context"], ci_admission.CONTEXT)

    def test_every_runtime_workflow_restarts_on_ready_and_cancels_on_draft(self):
        for name in WORKFLOW_JOBS:
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            match = re.search(r"(?m)^  pull_request:\n    types: \[([^]]+)\]", text)
            self.assertIsNotNone(match, name)
            self.assertEqual({x.strip() for x in match.group(1).split(",")},
                             {"opened", "synchronize", "reopened", "ready_for_review", "converted_to_draft"}, name)
            self.assertIn("cancel-in-progress: true", text, name)
            self.assertIn("github.event.pull_request.number || github.ref", text, name)
            if name != "ci.yml":
                self.assertNotRegex(text, r"(?m)^  push:", name)
            # Empty outputs from a skipped reusable planner must parse safely.
            self.assertNotIn("fromJSON(needs.impact.outputs.jobs)", text, name)

    def test_admission_also_handles_draft_transitions(self):
        text = (ROOT / ".github/workflows/ci-admission.yml").read_text(encoding="utf-8")
        self.assertIn("ready_for_review, converted_to_draft", text)
        self.assertIn("ref: ${{ github.event.pull_request.base.sha }}", text)
        self.assertNotIn("pull_request.head.sha", text)

    def test_skipped_drafts_cannot_satisfy_existing_required_contexts(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        for name in ("Documentation links", "test", "all-features", "agent-windows-security"):
            self.assertIn("github.event.pull_request.draft && 'Deferred - " + name + "' || '" + name + "'", text)

    def test_manual_full_qualification_is_preserved(self):
        for name in WORKFLOW_JOBS:
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            self.assertRegex(text, r"(?m)^  workflow_dispatch:", name)
        text = (ROOT / ".github/workflows/ci-impact-plan.yml").read_text(encoding="utf-8")
        self.assertIn("github.event_name != 'push'", text)
        self.assertIn("github.event_name != 'pull_request' || !github.event.pull_request.draft", text)


if __name__ == "__main__":
    unittest.main()
