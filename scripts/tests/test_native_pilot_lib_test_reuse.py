# SPDX-License-Identifier: Apache-2.0
"""SOU-217 comparison must reject incomplete or non-equivalent evidence."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "ci/compare-native-pilot-lib-tests.py"
spec = importlib.util.spec_from_file_location("sou217_compare", SCRIPT)
compare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compare)


class Comparison(unittest.TestCase):
    def fixture(self, root: Path) -> None:
        receipt = root / "receipt.json"
        receipt.write_text(json.dumps({"source": {"commit": "a" * 40}}))
        (root / "verified-source-build.json").write_text(json.dumps({
            "status": "verified-reuse", "receipt": str(receipt),
            "receipt_sha256": "b" * 64}))
        for name, seconds in (("cold", "120 95 18"), ("verify", "2 1 0"),
                              ("reused", "1 0.2 0.1")):
            (root / f"{name}.time").write_text(seconds)
        for name in ("cold", "reused"):
            (root / f"{name}.log").write_text(
                "running 3 tests\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured\n")

    def test_exact_source_equal_cases_and_cpu_elapsed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            report = compare.compare(root, "a" * 40)
            self.assertEqual(report["selected_test_cases"], 3)
            self.assertEqual(report["verified_reuse_and_test"]["elapsed_seconds"], 3)
            self.assertEqual(report["repeated_segment_elapsed_reduction_percent"], 97.5)
            self.assertFalse(report["runtime_qualification_inferred"])

    def test_missing_failed_stale_and_incompatible_are_blocked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.fixture(root)
            with self.assertRaisesRegex(ValueError, "source_identity_mismatch"):
                compare.compare(root, "c" * 40)
            (root / "reused.log").write_text(
                "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured\n")
            with self.assertRaisesRegex(ValueError, "acceptance_coverage_mismatch"):
                compare.compare(root, "a" * 40)
            (root / "reused.log").write_text(
                "test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured\n")
            with self.assertRaisesRegex(ValueError, "test_result_missing_or_ambiguous"):
                compare.compare(root, "a" * 40)
            (root / "reused.log").unlink()
            with self.assertRaises(FileNotFoundError):
                compare.compare(root, "a" * 40)


if __name__ == "__main__":
    unittest.main()
