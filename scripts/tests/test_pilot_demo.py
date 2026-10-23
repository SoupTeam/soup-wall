import importlib.util
import argparse
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "pilot-demo.py"


class PilotDemoTests(unittest.TestCase):
    def load(self):
        self.assertTrue(SCRIPT.is_file(), "the executable demo wrapper is missing")
        spec = importlib.util.spec_from_file_location("pilot_demo", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_plan_has_no_process_or_filesystem_effects(self):
        demo = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "output"
            with patch.object(sys, "argv", [str(SCRIPT), "--output", str(output)]), \
                 patch("subprocess.Popen", side_effect=AssertionError("plan spawned a process")), \
                 patch("sys.stdout", new_callable=io.StringIO) as stdout:
                self.assertEqual(demo.main(), 0)
            self.assertEqual(json.loads(stdout.getvalue())["status"], "plan")
            self.assertFalse(output.exists())

    def test_existing_fixture_and_symlink_are_refused(self):
        demo = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("filesystem-workspace", "git-workspace"):
                (root / name).mkdir()
            occupied = root / "filesystem-workspace/notes.txt"
            occupied.write_text("operator data")
            with self.assertRaisesRegex(ValueError, "demo_fixture_name_occupied"):
                demo.fixture_paths(root)
            self.assertEqual(occupied.read_text(), "operator data")

    def test_cleanup_preserves_operator_edits_and_unrelated_files(self):
        demo = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, changed, other = (root / name for name in ("first", "changed", "other"))
            first.write_bytes(b"owned")
            changed.write_bytes(b"operator edit")
            other.write_bytes(b"keep")
            retained = demo.cleanup_fixtures({first: b"owned", changed: b"original"})
            self.assertFalse(first.exists())
            self.assertEqual(changed.read_bytes(), b"operator edit")
            self.assertEqual(other.read_bytes(), b"keep")
            self.assertEqual(retained, ["changed"])

    def test_failure_reason_does_not_export_credentials(self):
        demo = self.load()
        self.assertEqual(demo.reason(ValueError("secret Bearer xyz")), "demo_failed")
        self.assertEqual(demo.reason(ValueError("demo_fixture_name_occupied")), "demo_fixture_name_occupied")

    def test_demo_uses_original_host_qualifier_without_transition(self):
        demo = self.load()
        options = demo.qualification_args(argparse.Namespace(
            selection=Path("/owned/selection.json"), expected_commit="a" * 40,
            strace=Path("/usr/bin/strace"), validation_timeout_seconds=120))
        self.assertIsNone(options.transition_target)
        self.assertEqual(options.selection, Path("/owned/selection.json"))
        self.assertEqual(options.expected_commit, "a" * 40)
        self.assertEqual(options.strace, Path("/usr/bin/strace"))
        self.assertEqual(options.validation_timeout_seconds, 120)


if __name__ == "__main__":
    unittest.main()
