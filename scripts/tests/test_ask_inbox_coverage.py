# SPDX-License-Identifier: Apache-2.0
"""Exercise the qualification coverage guard without launching external runtimes."""
import ast
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "qualify-ask-inbox.py"
MODULE = ast.parse(SOURCE.read_text(encoding="utf-8"))
FUNCTION = next(node for node in MODULE.body
                if isinstance(node, ast.FunctionDef) and node.name == "verify_original_cases")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


namespace = {"require": require}
exec(compile(ast.Module(body=[FUNCTION], type_ignores=[]), str(SOURCE), "exec"), namespace)
verify = namespace["verify_original_cases"]


class OriginalCaseCoverageTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{"profile": profile, "case": case, "passed": True}
                     for profile in ("git", "filesystem")
                     for case in ("expire", "restart", "approve", "reject", "cancel",
                                  "approved_cancel", "default")]
        self.rows.append({"profile": "git", "case": "collector_term", "passed": True})

    def test_all_fifteen_current_original_controls_are_required(self):
        verify({"cases": self.rows})
        with self.assertRaisesRegex(ValueError, "incomplete_original_cases"):
            verify({"cases": self.rows[:-1]})

    def test_duplicate_cannot_replace_missing_control(self):
        self.rows[-1] = dict(self.rows[0])
        with self.assertRaisesRegex(ValueError, "incomplete_original_cases"):
            verify({"cases": self.rows})

    def test_failed_or_truthy_non_boolean_control_is_not_success(self):
        for value in (False, 1, "passed", None):
            self.rows[-1]["passed"] = value
            with self.assertRaisesRegex(ValueError, "incomplete_original_cases"):
                verify({"cases": self.rows})

    def test_unknown_control_cannot_replace_expected_control(self):
        self.rows[-1]["case"] = "unexpected"
        with self.assertRaisesRegex(ValueError, "incomplete_original_cases"):
            verify({"cases": self.rows})


if __name__ == "__main__":
    unittest.main()
