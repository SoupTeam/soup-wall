# SPDX-License-Identifier: Apache-2.0
"""Negative controls for the separately pinned public development manifest."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import agentdojo_protocol as protocol
import paired_regression as compare
import paired_regression_controls as fixture
import paired_regression_project_cases as cases


class ProjectCases(unittest.TestCase):
    def setUp(self):
        self.bundle = fixture.bundle()
        self.bundle["case_manifest"] = None
        self.input_sha = protocol.digest(fixture.encode(self.bundle))
        plans = {role: fixture.plan(role) for role in ("baseline", "candidate")}
        self.sides = []
        self.paths = []
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.inputs = root / "inputs.json"
        self.inputs.write_bytes(fixture.encode(self.bundle))
        self.manifest = {"schema": cases.SCHEMA, "plan_set": "development",
                         "provenance": {"kind": "project-development-ai-assisted", "basis": "synthetic control"},
                         "inputs_sha256": self.input_sha, "upstream": plans["baseline"]["upstream"],
                         "sides": {}, "cases": []}
        for role, plan in plans.items():
            run = fixture.run(role, plan, fixture.baseline_outcome)
            path = root / f"{role}-plan.json"
            path.write_bytes(fixture.encode(plan))
            run_path = root / f"{role}-run.json"
            run_path.write_bytes(fixture.encode(run))
            self.paths.extend((path, run_path))
            self.sides.append({"role": role, "set": "development", "plan": plan, "run": run,
                               "plan_sha256": protocol.digest(path.read_bytes()),
                               "run_sha256": protocol.digest(run_path.read_bytes())})
            self.manifest["sides"][role] = {
                "plan_sha256": self.sides[-1]["plan_sha256"], "run_sha256": self.sides[-1]["run_sha256"],
                "source_revision": plan["identities"]["candidate"]["source_revision"],
                "producer_sha256": run["cli_source_sha256"]}
        case_sources = json.loads(self.bundle["files"][fixture.MANIFEST])["cases"]
        source = {c["case_id"]: c for c in case_sources}
        for item in plans["baseline"]["sets"]["development"]["cases"]:
            row = source[item["case_id"]]
            refs = {"user_task": row["user_task_file"], "environment": row["environment_file"]}
            if item["injection_task_id"]:
                refs["injection_task"] = row["environment_file"]
            self.manifest["cases"].append({
                **{key: item[key] for key in ("case_id", "user_task_id", "injection_task_id", "injections_sha256")},
                "expected_label": row["expected_label"], "semantic_family": row["semantic_family"],
                "sources": {role: {"path": path, "sha256": protocol.digest(self.bundle["files"][path].encode())}
                            for role, path in refs.items()}})

    def verify(self, manifest, sides=None):
        return cases.verify(manifest, "f" * 64, self.bundle, self.input_sha,
                            sides or self.sides, 512)

    def test_exact_pair_binds_under_separate_project_provenance(self):
        path = self.inputs.with_name("project-cases.json")
        path.write_bytes(fixture.encode(self.manifest))
        with patch.object(compare, "PROJECT_CASES_SHA256", {protocol.digest(path.read_bytes())}):
            result, code = compare.compare(*self.paths, self.inputs, project_cases_path=path)
        self.assertEqual(code, compare.EXIT_COMPARABLE)
        self.assertEqual(result["comparability"]["status"], "verified_comparable")
        self.assertEqual(result["grouping"]["semantic_families"]["status"], "bound_by_project_manifest")
        self.assertEqual(len(self.verify(self.manifest)[0]), len(self.manifest["cases"]))

    def test_unpinned_or_edited_manifest_refuses(self):
        path = self.inputs.with_name("project-cases.json")
        path.write_bytes(fixture.encode(self.manifest))
        original_sha = protocol.digest(path.read_bytes())
        path.write_bytes(path.read_bytes() + b"\n")
        with patch.object(compare, "PROJECT_CASES_SHA256", {original_sha}):
            with self.assertRaisesRegex(compare.Rejected, "not pinned"):
                compare.load_project_cases(path, compare.DEFAULT_LIMITS)

    def test_missing_duplicate_foreign_labels_and_hash_drift_refuse(self):
        for field, value in (("case_id", "foreign"), ("case_id", self.manifest["cases"][1]["case_id"]),
                             ("expected_label", "changed"), ("injections_sha256", "1" * 64),
                             ("sources", {"user_task": {"path": "src/foreign", "sha256": "1" * 64}})):
            with self.subTest(field=field, value=value), self.assertRaises(cases.Invalid):
                changed = deepcopy(self.manifest)
                changed["cases"][0][field] = value
                self.verify(changed)
        changed = deepcopy(self.manifest)
        changed["cases"].pop()
        with self.assertRaisesRegex(cases.Invalid, "omits"):
            self.verify(changed)
        changed = deepcopy(self.manifest)
        changed["cases"][0]["sources"]["environment"]["sha256"] = "1" * 64
        with self.assertRaisesRegex(cases.Invalid, "path or digest"):
            self.verify(changed)

    def test_substituted_report_producer_and_fresh_set_refuse(self):
        for key in ("run_sha256", "plan_sha256", "source_revision", "producer_sha256"):
            with self.subTest(key=key), self.assertRaisesRegex(cases.Invalid, "identity differs"):
                manifest = deepcopy(self.manifest)
                manifest["sides"]["baseline"][key] = "1" * 64
                self.verify(manifest)
        changed = deepcopy(self.sides)
        changed[0]["set"] = "fresh_evaluation"
        with self.assertRaisesRegex(cases.Invalid, "development plan differ"):
            self.verify(self.manifest, changed)
