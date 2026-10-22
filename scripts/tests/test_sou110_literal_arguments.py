# SPDX-License-Identifier: Apache-2.0
"""SOU-110 public classifier and evidence-failure controls, not Linux coverage."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sou110", ROOT / "scripts/verify-sou110-literal-arguments.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class EvidenceControls(unittest.TestCase):
    def fixture(self):
        source = {"commit": "a" * 40, "tree": "b" * 40, "dirty": False}
        rows = []
        for index, (label, tool, arguments, fragment, _) in enumerate(M.POSITIVES, 100):
            rows.append({"case": label, "id": index, "passed": True, "classifier": {"actions": ["read"], "unknown": False},
                         "response": {"id": index, "result": {"content": [{"type": "text", "text": fragment}], "structuredContent": {"content": fragment}}},
                         "target_reads_before": 0, "target_reads_after": 1, "dispatch_events": [{"execution_dispatched": True}],
                         "native_invocation": [{"tool":tool, "verdict":"allow", "released":True, "registry_sha256":"e" * 64}]})
        for index, (label, _, _) in enumerate(M.NEGATIVES, 200):
            rows.append({"case": label, "id": index, "passed": True, "response": {"id": index, "error": {"code": -1}},
                         "target_reads_before": 0, "target_reads_after": 0, "dispatch_events": []})
        return {"source_before": source, "source_after": source.copy(), "source_files_before": {"owned": "c" * 64},
                "source_files_after": {"owned": "c" * 64}, "skipped": 0, "cases": rows, "registry_sha256":"e" * 64,
                "workspace_before": {"owned": "d" * 64}, "workspace_after": {"owned": "d" * 64}, "receiver_bodies": [],
                "receiver_calibration": {"passed": True}, "policy_controls": [{"passed": True, "verdict": "deny"}],
                "classifier_limit": {"preserved": True, "response": {"error": {"code": -1}}},
                "client": {"exit_code": 0, "forced_cleanup": False, "process_cleanup": {"all_stopped": True, "descendant_count": 1}},
                "daemon_cleanup": {"all_stopped": True}, "daemon_exit_code": -15, "cleanup_audit": {"cleanup_verified": True}}

    def test_rejects_missing_useful_execution_failed_process_and_forged_results(self):
        valid = self.fixture()
        M.grade(valid)
        mutations = [
            lambda r: r["cases"][0].update(target_reads_after=0),
            lambda r: r["cases"][0].update(dispatch_events=[]),
            lambda r: r["cases"][0].update(native_invocation=[]),
            lambda r: r["cases"][0]["native_invocation"][0].update(verdict="ask"),
            lambda r: r["cases"][0]["response"].update(id="100"),
            lambda r: r["cases"][0]["response"]["result"].update(structuredContent={"content": "forged"}),
            lambda r: r["cases"][0]["classifier"].update(unknown=True),
            lambda r: r["client"].update(exit_code=1),
            lambda r: r["client"].update(forced_cleanup=True),
            lambda r: r["daemon_cleanup"].update(all_stopped=False),
        ]
        for mutation in mutations:
            changed = copy.deepcopy(valid)
            mutation(changed)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                M.grade(changed)

    def test_rejects_missing_negative_cases_and_any_forbidden_effect(self):
        valid = self.fixture()
        mutations = [
            lambda r: r["cases"].pop(),
            lambda r: r["cases"][-1].update(target_reads_after=1),
            lambda r: r["cases"][-1].update(dispatch_events=[{"execution_dispatched": True}]),
            lambda r: r["workspace_after"].update(forbidden="new"),
            lambda r: r["receiver_bodies"].append("forbidden"),
            lambda r: r.update(skipped=1),
            lambda r: r["source_after"].update(dirty=True),
            lambda r: r["source_files_after"].update(owned="changed"),
        ]
        for mutation in mutations:
            changed = copy.deepcopy(valid)
            mutation(changed)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                M.grade(changed)


class AcceptedClassifier(unittest.TestCase):
    def test_public_positive_literals_use_the_unchanged_classifier_and_original_schemas(self):
        manifest = json.loads((ROOT / "profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json").read_text())["result"]
        definitions = {tool["name"]: tool for tool in manifest["tools"]}
        for label, tool, arguments, _, _ in M.POSITIVES:
            definition = definitions[tool]
            prediction = M.CLASSIFIER.classify({"tool_name": tool, "raw_arguments": arguments,
                                                "tool_description": definition["description"], "tool_schema": definition["inputSchema"],
                                                "pinned_schema": definition["inputSchema"]})
            with self.subTest(case=label):
                self.assertEqual(prediction["actions"], ["read"])
                self.assertFalse(prediction["unknown"])
                self.assertEqual(prediction["status"], "ok")


if __name__ == "__main__":
    unittest.main()
