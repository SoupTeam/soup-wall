# SPDX-License-Identifier: Apache-2.0
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("sso_batch", Path(__file__).resolve().parents[1] / "sso_acceptance_batch.py")
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


class BatchTests(unittest.TestCase):
    def test_only_complete_genuine_driver_with_cleanup_can_pass(self):
        good = {"passed": True, "cleanup_passed": True, "outcome": "completed"}
        self.assertEqual(B.classify(0, good), "completed")
        for report in ({}, dict(good, cleanup_passed=False), dict(good, passed=False),
                       dict(good, outcome="incomplete")):
            self.assertEqual(B.classify(0, report), "incomplete")
        self.assertEqual(B.classify(1, good), "incomplete")
        self.assertEqual(B.classify(1, {"outcome": "failed"}), "failed")

    def test_failed_first_run_is_retained_and_cannot_be_erased_by_second_success(self):
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(out=Path(directory) / "batch", protocol="saml", backend="postgres",
                runs=2, gateway=Path("gateway"), bootstrap_helper=Path("bootstrap"), artifact_label="unit-only")
            def launch(command, **_):
                path = Path(command[command.index("--out") + 1])
                passed = path.name == "run-2.json"
                path.write_text(json.dumps({"passed": passed, "cleanup_passed": True,
                                            "outcome": "completed" if passed else "failed"}))
                return Mock(wait=Mock(return_value=0 if passed else 1), poll=Mock(return_value=0))
            with patch.object(B.subprocess, "Popen", side_effect=launch) as popen:
                self.assertEqual(B.run(args), 1)
            self.assertEqual(popen.call_count, 2)
            summary = json.loads((args.out / "batch.json").read_text())
            self.assertEqual(summary["counts"], {"completed": 1, "failed": 1, "incomplete": 0, "skipped": 0})
            self.assertFalse(summary["passed"])

    def test_missing_runtime_marks_remaining_runs_skipped_without_false_success(self):
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(out=Path(directory) / "batch", protocol="oidc", backend="sqlite",
                runs=2, gateway=Path("gateway"), bootstrap_helper=Path("bootstrap"), artifact_label="unit-only")
            with patch.object(B.subprocess, "Popen", side_effect=OSError("secret")):
                self.assertEqual(B.run(args), 1)
            text = (args.out / "batch.json").read_text()
            self.assertNotIn("secret", text)
            self.assertEqual(json.loads(text)["counts"], {"completed": 0, "failed": 0, "incomplete": 1, "skipped": 1})
            with self.assertRaises(FileExistsError):
                B.run(args)


if __name__ == "__main__":
    unittest.main()
