# SPDX-License-Identifier: Apache-2.0
"""SOU-31: runner behaviour for cases that expect a D06 technical failure."""
import copy
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import eval_runner as r  # noqa: E402

CASE = {
    "id": "T1", "group": "input_validation", "origin": "test", "expectation_status": "provisional",
    "requires": [], "contract_assumptions": ["D06"],
    "input": {"tool_name": "t", "tool_schema": {"type": "object"}, "raw_arguments": None},
    "expected": {"actions": None, "unknown": None, "status": None, "technical_failure": "classifier_invalid"},
    "evaluator_only": {},
}


def case(**expected):
    c = copy.deepcopy(CASE)
    c["expected"].update(expected)
    return c


def raises(_):
    raise ValueError("bad input")


class FailureChannel(unittest.TestCase):
    def test_masked_unknown_fails(self):
        rec = r.evaluate_case(case(), lambda _: {"actions": [], "unknown": True}, "s")
        self.assertEqual((rec["outcome"], rec["masked_failure"]), ("fail", True))

    def test_error_status_with_matching_code_passes(self):
        out = {"status": "error", "actions": [], "unknown": True, "failure": {"code": "classifier_invalid"}}
        rec = r.evaluate_case(case(), lambda _: out, "s")
        self.assertEqual((rec["outcome"], rec["reported_failure_code"]), ("pass", "classifier_invalid"))

    def test_error_status_with_other_code_fails(self):
        out = {"status": "error", "actions": [], "unknown": True, "failure": {"code": "classifier_timeout"}}
        self.assertEqual(r.evaluate_case(case(), lambda _: out, "s")["outcome"], "fail")

    def test_exception_without_code_passes(self):
        self.assertEqual(r.evaluate_case(case(), raises, "s")["outcome"], "pass")

    def test_expected_failure_is_not_counted_as_unexpected_technical_error(self):
        recs = [r.evaluate_case(case(), raises, "s")]
        s = r.summarize(recs)
        self.assertEqual(s["technical_errors"], [])
        self.assertEqual(len(s["expected_technical_failures"]), 1)
        self.assertEqual(r.exit_code(s), 0)
        self.assertEqual(s["per_label"]["read"]["expected_present"], 0)

    def test_masked_failure_sets_exit_code_one(self):
        s = r.summarize([r.evaluate_case(case(), lambda _: {"actions": [], "unknown": True}, "s")])
        self.assertEqual(r.exit_code(s), 1)

    def test_unexpected_error_on_normal_case_still_technical(self):
        normal = copy.deepcopy(CASE)
        normal["expected"] = {"actions": ["read"], "unknown": False, "status": None}
        s = r.summarize([r.evaluate_case(normal, raises, "s")])
        self.assertEqual(r.exit_code(s), 2)

    def test_validation(self):
        self.assertEqual(r.validate_fixture({"fixture_version": "x", "cases": [case()]}), [])
        bad_code = r.validate_fixture({"fixture_version": "x", "cases": [case(technical_failure="nope")]})
        self.assertTrue(any("technical_failure must be one of" in e for e in bad_code))
        with_labels = r.validate_fixture({"fixture_version": "x", "cases": [case(actions=[], unknown=True)]})
        self.assertTrue(any("must have expected.actions and expected.unknown = null" in e for e in with_labels))

    def test_markdown_and_csv_render(self):
        recs = [r.evaluate_case(case(), lambda _: {"actions": [], "unknown": True}, "s")]
        md = r.render_markdown(r.summarize(recs), recs, {})
        self.assertIn("Expected technical failures (D06)", md)
        self.assertIn("technical_failure=classifier_invalid", md)
        self.assertIn("classifier_invalid", r.render_csv(recs))

    def test_committed_v05_fixtures_validate(self):
        for name in ("soup_task1_evaluation_cases_v0.5.json", "soup_task1_challenge_cases_v0.2.json"):
            data = json.loads((HERE / "fixtures" / name).read_text(encoding="utf-8"))
            self.assertEqual(r.validate_fixture(data, name), [])


if __name__ == "__main__":
    unittest.main()
