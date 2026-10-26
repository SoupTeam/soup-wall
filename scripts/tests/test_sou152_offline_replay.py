# SPDX-License-Identifier: Apache-2.0
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("sou152", Path(__file__).resolve().parents[1] / "verify-sou152-offline-replay.py")
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


class OfflineQualificationSafety(unittest.TestCase):
    def test_plan_never_builds_or_creates_output(self):
        import argparse
        with patch.object(H, "source_identity", return_value={"commit": "a" * 40}), patch.object(H, "bounded_run") as run, patch.object(H, "fresh_output") as output:
            result = H.qualify(argparse.Namespace(expected_commit="a" * 40, run=False))
        self.assertEqual(result["status"], "plan")
        run.assert_not_called()
        output.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "Unix descriptor paths")
    def test_output_refuses_source_overwrite_and_symlink_ancestors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "source"
            source.mkdir()
            with self.assertRaises(H.Refusal):
                H.fresh_output(source / "output", source)
            output = H.fresh_output(root / "new", source)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(H.Refusal):
                H.fresh_output(output, source)
            (root / "link").symlink_to(output)
            with self.assertRaises(H.Refusal):
                H.fresh_output(root / "link" / "escape", source)
            self.assertFalse((output / "escape").exists())

    def test_source_binding_refuses_dirty_or_wrong_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()
            git("init", "-q")
            git("config", "user.email", "owned@example.invalid")
            git("config", "user.name", "Owned fixture")
            (root / "owned").write_text("initial")
            git("add", "owned")
            git("commit", "-qm", "owned fixture")
            commit = git("rev-parse", "HEAD")
            self.assertTrue(H.source_identity(root, commit)["clean"])
            with self.assertRaises(H.Refusal):
                H.source_identity(root, "0" * 40)
            (root / "owned").write_text("changed")
            with self.assertRaises(H.Refusal):
                H.source_identity(root, commit)

    def test_subprocess_stream_budget_is_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(H.Refusal):
                H.bounded_run([__import__("sys").executable, "-c", "print('x'*100000)"], temporary, os.environ.copy(), 5, 100)


if __name__ == "__main__":
    unittest.main()
