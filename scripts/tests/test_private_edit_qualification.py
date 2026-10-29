# SPDX-License-Identifier: Apache-2.0
"""The native qualification cannot substitute missing or simulated evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("private_edit_qualification", ROOT / "scripts/qualify-private-edit-self-test.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class QualificationControls(unittest.TestCase):
    def seed(self):
        expected = {"source_commit": "a" * 40, "source_tree": "b" * 40,
                    "component_sha256": "c" * 64, "selection_sha256": "d" * 64,
                    "agentfw_sha256": "e" * 64}
        value = {"format": PROBE.SELF_TEST, "status": "passed", "executed": True,
            "paid_inference": False, "expected": list(PROBE.CASES),
            "cases": [{"id": name, "attempted": True, "status": "passed"} for name in PROBE.CASES],
            "cleanup": {"all_owned_processes_stopped": True, "workspace_removed": True, "workspace_retained": False},
            "preservation": {"installed_state_unchanged": True, "original_projects_unchanged": True,
                             "unrelated_sentinel_unchanged": True},
            "identities": {key: val for key, val in expected.items() if key != "agentfw_sha256"},
            "inventory": {"expected": 8, "attempted": 8, "passed": 8, "failed": 0, "incomplete": 0, "unsupported": 0},
            "platform": {"id": "native-linux-x86_64"}}
        value["identities"]["installed_sha256"] = {"agentfw": expected["agentfw_sha256"]}
        return value, expected

    def test_missing_failed_unattempted_or_reordered_native_cases_cannot_pass(self):
        value, expected = self.seed()
        self.assertTrue(PROBE.positive_report(value, expected))
        for index in range(len(PROBE.CASES)):
            for field, bad in (("status", "incomplete"), ("status", "failed"), ("attempted", False)):
                changed = copy.deepcopy(value)
                changed["cases"][index][field] = bad
                self.assertFalse(PROBE.positive_report(changed, expected))
            changed = copy.deepcopy(value)
            changed["cases"].pop(index)
            self.assertFalse(PROBE.positive_report(changed, expected))
        changed = copy.deepcopy(value)
        changed["cases"].reverse()
        self.assertFalse(PROBE.positive_report(changed, expected))

    def test_cleanup_preservation_platform_and_exact_identity_are_required(self):
        value, expected = self.seed()
        for section in ("cleanup", "preservation"):
            for key in value[section]:
                changed = copy.deepcopy(value)
                changed[section][key] = not changed[section][key]
                self.assertFalse(PROBE.positive_report(changed, expected))
        for key in expected:
            changed_expected = dict(expected, **{key: "0" * len(expected[key])})
            self.assertFalse(PROBE.positive_report(value, changed_expected))
        changed = copy.deepcopy(value)
        changed["platform"]["id"] = "wsl2-linux-x86_64"
        self.assertFalse(PROBE.positive_report(changed, expected))
        changed = copy.deepcopy(value)
        changed["inventory"]["attempted"] -= 1
        self.assertFalse(PROBE.positive_report(changed, expected))
        for section in ("cleanup", "preservation", "identities", "inventory", "platform"):
            changed = copy.deepcopy(value)
            changed[section] = "malformed"
            self.assertFalse(PROBE.positive_report(changed, expected))

    def test_default_is_inert_without_paths_or_permission(self):
        result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/qualify-private-edit-self-test.py")],
            capture_output=True, check=True, timeout=10)
        value = json.loads(result.stdout)
        self.assertFalse(value["executed"])
        self.assertEqual(value["checks"], list(PROBE.CHECKS))
        self.assertNotIn("status", value)

    def test_summary_requires_all_controls_and_unchanged_selected_inputs(self):
        value = {"format": PROBE.FORMAT, "status": "passed", "selected_inputs_unchanged": True,
                 "checks": [{"id": name, "attempted": True, "status": "passed"} for name in PROBE.CHECKS]}
        self.assertTrue(PROBE.passed(value))
        for index in range(len(PROBE.CHECKS)):
            changed = copy.deepcopy(value)
            changed["checks"][index]["attempted"] = False
            self.assertFalse(PROBE.passed(changed))
        value["selected_inputs_unchanged"] = False
        self.assertFalse(PROBE.passed(value))


if __name__ == "__main__":
    unittest.main()
