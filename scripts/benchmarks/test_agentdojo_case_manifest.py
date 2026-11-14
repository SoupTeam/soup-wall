"""Explicit producer-owned case binding and negative controls."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import agentdojo_case_manifest as manifest


class CaseManifestTest(unittest.TestCase):
    def setUp(self):
        self.case = {"case_id": "public/benign", "user_task_id": "public", "injection_task_id": None}
        self.plan = {"upstream": {"suite": "fixture"}, "sets": {"development": {"cases": [self.case]}}}
        self.row = {**self.case, "expected_label": "benign", "semantic_family": "owner-fixture-family",
                    "user_task_file": "src/task", "environment_file": "src/env"}
        self.data = {"schema": manifest.SCHEMA, "suite": "fixture", "cases": [self.row]}
        self.files = {"src/cases.json", "src/task", "src/env"}

    def encode(self):
        return json.dumps(self.data).encode()

    def test_frozen_inventory_accepts_declared_family(self):
        self.assertEqual(manifest.validate(self.encode(), self.plan, self.files), 1)

    def test_duplicate_missing_and_changed_cases_reject(self):
        for other in ([self.row, self.row], [], [{**self.row, "expected_label": "attack"}],
                      [{**self.row, "case_id": "other"}], [{**self.row, "semantic_family": ""}]):
            with self.subTest(other=other), self.assertRaises(manifest.Invalid):
                data = {**self.data, "cases": other}
                manifest.validate(json.dumps(data).encode(), self.plan, self.files)

    def test_duplicate_key_and_oversize_reject(self):
        for raw in (b'{"suite":"fixture","suite":"fixture"}', b"x" * (manifest.MANIFEST_LIMIT + 1)):
            with self.assertRaises(manifest.Invalid):
                manifest.validate(raw, self.plan, self.files)

    def test_untracked_source_and_traversing_manifest_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            for name in ("src/task", "src/env"):
                (root / name).write_bytes(b"owned fixture input")
            (root / "src/cases.json").write_bytes(self.encode())
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "src/task", "src/env", "src/cases.json"], check=True)
            result = manifest.verify(root, "src/cases.json", self.plan)
            self.assertEqual(result["case_count"], 1)
            for name in ("src/../cases.json", "src/untracked.json", "other.json"):
                with self.assertRaises(manifest.Invalid):
                    manifest.verify(root, name, self.plan)

    def test_manifest_can_cover_development_without_fresh_evaluation(self):
        self.plan["sets"]["fresh_evaluation"] = {"cases": [{**self.case, "case_id": "fresh/benign"}]}
        self.assertEqual(manifest.validate(self.encode(), self.plan, self.files, "development"), 1)
        for plan_set in (None, "fresh_evaluation"):
            with self.subTest(plan_set=plan_set), self.assertRaises(manifest.Invalid):
                manifest.validate(self.encode(), self.plan, self.files, plan_set)

    def test_source_record_outside_bound_inventory_rejects(self):
        changed = copy.deepcopy(self.data)
        changed["cases"][0]["environment_file"] = "src/untracked"
        with self.assertRaises(manifest.Invalid):
            manifest.validate(json.dumps(changed).encode(), self.plan, self.files)
