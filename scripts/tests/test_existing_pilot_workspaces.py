# SPDX-License-Identifier: Apache-2.0
"""Existing-project selection is explicit, pinned, and never a cleanup target."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("existing_prep", ROOT / "scripts/prepare-installed-pilot.py")
PREP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PREP)


class ExistingWorkspaceBoundary(unittest.TestCase):
    def fixture(self, temporary):
        root = Path(temporary).resolve()
        fs, git = root / "project", root / "repository"
        fs.mkdir(mode=0o700); git.mkdir(mode=0o700)
        args = SimpleNamespace(filesystem_workspace=fs, git_workspace=git)
        return root, args, PREP.requested_workspaces(args)

    def test_default_existing_preview_never_executes_selected_programs_or_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, args, binding = self.fixture(temporary)
            executable = root / "do-not-execute"
            executable.write_text("raise SystemExit('must not execute')")
            before = sorted(root.rglob("*"))
            with patch.object(sys, "argv", ["prepare", "--filesystem-workspace", str(args.filesystem_workspace),
                "--git-workspace", str(args.git_workspace), "--agentfw", str(executable)]), \
                patch.object(PREP.PILOT, "source", return_value={"commit": "a" * 40}), \
                patch.object(PREP.subprocess, "run") as run, \
                patch.object(PREP.subprocess, "check_output") as execute, \
                patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(PREP.main(), 0)
                plan = json.loads(output.getvalue())
                self.assertFalse(plan["executed"])
                self.assertEqual(plan["workspaces"], binding)
                self.assertEqual(plan["inputs"]["agentfw"]["sha256"], PREP.FS.sha(executable))
                self.assertIn("read-only", plan["capability"])
                run.assert_not_called(); execute.assert_not_called()
            self.assertEqual(before, sorted(root.rglob("*")))

    def test_same_supported_root_can_fill_both_roles_and_contents_can_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, args, _ = self.fixture(temporary)
            args.git_workspace = args.filesystem_workspace
            binding = PREP.requested_workspaces(args)
            (args.filesystem_workspace / "operator-edit").write_text("current untrusted data")
            self.assertEqual(PREP.workspace_paths({"prepared_workspaces": binding}, root / "generation"),
                             {"filesystem": args.filesystem_workspace, "git": args.git_workspace})

    def test_missing_moved_and_replaced_root_refuse_without_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, args, binding = self.fixture(temporary)
            args.filesystem_workspace.rename(root / "moved")
            with self.assertRaisesRegex(ValueError, "missing_or_moved"):
                PREP.workspace_paths({"prepared_workspaces": binding}, root / "generation")
            args.filesystem_workspace.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "selected_workspace_changed"):
                PREP.workspace_paths({"prepared_workspaces": binding}, root / "generation")
            # Removing a generation never requires following an external root.
            self.assertEqual(PREP.workspace_paths({"prepared_workspaces": binding}, root / "generation",
                revalidate=False)["filesystem"], args.filesystem_workspace)

    def test_alias_traversal_shared_or_unowned_root_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, args, _ = self.fixture(temporary)
            alias = root / "alias"; alias.symlink_to(args.filesystem_workspace, target_is_directory=True)
            for path in (alias, root / "repository" / ".." / "project", Path("/")):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    PREP.root_identity(path)
            args.filesystem_workspace.chmod(0o777)
            with self.assertRaisesRegex(ValueError, "owned_workspace"):
                PREP.root_identity(args.filesystem_workspace)
            args.filesystem_workspace.chmod(0o700)
            with patch.object(PREP.os, "getuid", return_value=os.getuid() + 1):
                with self.assertRaisesRegex(ValueError, "owned_workspace"):
                    PREP.root_identity(args.filesystem_workspace)

    def test_partial_scope_and_changed_scope_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, args, binding = self.fixture(temporary)
            args.git_workspace = None
            with self.assertRaisesRegex(ValueError, "supply_both"):
                PREP.requested_workspaces(args)
            for update in ({"capability": "write"}, {"result_provenance": "trusted"}, {"format": "unknown"}):
                with self.subTest(update=update), self.assertRaisesRegex(ValueError, "workspace_binding_invalid"):
                    PREP.workspace_paths({"prepared_workspaces": {**binding, **update}}, root / "generation")
            with self.assertRaisesRegex(ValueError, "preparation_overlaps_workspace"):
                PREP.workspace_paths({"prepared_workspaces": binding}, args.filesystem_workspace / "generation")
            with self.assertRaisesRegex(ValueError, "private_assets_inside_workspace"):
                PREP.outside_workspaces([args.filesystem_workspace / "config"],
                                       {"filesystem": args.filesystem_workspace})

    def test_native_profile_validator_refusal_is_not_repaired_or_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, args, _ = self.fixture(temporary)
            with patch.object(PREP.subprocess, "run") as run:
                run.return_value.returncode = 1
                with self.assertRaisesRegex(ValueError, "unsupported_existing_git_layout"):
                    PREP.validate_existing_workspaces({"agentfw": root / "agentfw"},
                        {"filesystem": args.filesystem_workspace, "git": args.git_workspace})
                self.assertEqual(run.call_args.args[0][1], "pilot-workspaces")
                self.assertNotIn("git", run.call_args.args[0])

    def test_legacy_selection_keeps_generated_roots(self):
        generation = Path("/private/generation")
        self.assertEqual(PREP.workspace_paths({}, generation), {
            "filesystem": generation / "filesystem-workspace", "git": generation / "git-workspace"})


if __name__ == "__main__":
    unittest.main()
