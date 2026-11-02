#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Acceptance-shape controls for the installed SOU-200 maintenance qualifier."""
import copy
import importlib.util
from pathlib import Path
import unittest


SCRIPTS = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


QUAL = load("maintenance_qualification_test", "pilot_maintenance_qualification.py")


def complete():
    return {
        "format": "sw-pilot-maintenance-qualification/1", "platform": "native-linux",
        "executed": True, "expected": list(QUAL.CASES), "source": "a" * 40,
        "binary_sha256": "b" * 64, "source_unchanged": True, "project_unchanged": True,
        "receiver_requests": 0,
        "cases": [{"id": case, "attempted": True, "passed": True} for case in QUAL.CASES],
    }


class MaintenanceQualificationShape(unittest.TestCase):
    def test_complete_report_is_accepted(self):
        self.assertTrue(QUAL.passed(complete()))

    def test_every_required_case_is_load_bearing(self):
        for index in range(len(QUAL.CASES)):
            value = complete()
            del value["cases"][index]
            self.assertFalse(QUAL.passed(value), QUAL.CASES[index])

    def test_unattempted_failed_or_reordered_case_is_refused(self):
        for field in ("attempted", "passed"):
            value = complete()
            value["cases"][0][field] = False
            self.assertFalse(QUAL.passed(value), field)
        value = complete()
        value["cases"].reverse()
        self.assertFalse(QUAL.passed(value))

    def test_unobserved_platform_source_or_effect_is_refused(self):
        for field, bad in (("platform", "macos"), ("executed", False), ("source", "a" * 39),
                           ("binary_sha256", "B" * 64), ("source_unchanged", False),
                           ("project_unchanged", False), ("receiver_requests", 1),
                           ("receiver_requests", True)):
            value = copy.deepcopy(complete())
            value[field] = bad
            self.assertFalse(QUAL.passed(value), field)

    def test_required_races_and_controls_are_named(self):
        for case in ("entered-new-run-refused", "existing-run-draining", "sibling-independent",
                     "same-bytes-marker-replaced", "partial-transition-refused",
                     "dead-owner-uncertain", "new-useful-after-leave"):
            self.assertIn(case, QUAL.CASES)


if __name__ == "__main__":
    unittest.main()
