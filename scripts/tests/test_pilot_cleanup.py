import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "pilot-cleanup.py"


@unittest.skipUnless(sys.platform == "linux", "Linux descriptor and process controls")
class PilotCleanupTests(unittest.TestCase):
    def load(self):
        self.assertTrue(SCRIPT.is_file(), "receipt-aware cleanup is missing")
        spec = importlib.util.spec_from_file_location("pilot_cleanup", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def fixture(self, root, cleanup):
        root.chmod(0o700)
        generations = root / "generations"
        generations.mkdir(mode=0o700)
        target = generations / ("a" * 32)
        target.mkdir(mode=0o700)
        for directory in ("git-src", "bwrap-build"):
            (target / directory).mkdir(mode=0o700)
        binaries = {}
        for kind, relative in (("git", "git-src/git"), ("bwrap", "bwrap-build/bwrap")):
            path = target / relative
            path.write_bytes(b"synthetic control")
            path.chmod(0o700)
            binaries[kind] = {"path": str(path), "sha256": cleanup.sha(path),
                              "version": cleanup.NATIVE.SOURCES[kind][0], "libraries": {}}
        receipt = {"format": "sw-native-pilot-prerequisites/1", "source_commit": "b" * 40,
                   "archives": {kind: {"url": row[2], "sha256": row[3]}
                                for kind, row in cleanup.NATIVE.SOURCES.items()},
                   "tools": {}, "binaries": binaries, "status": "built-not-qualified",
                   "flags": {"git": list(cleanup.NATIVE.GIT_FLAGS), "bwrap": list(cleanup.NATIVE.BWRAP_FLAGS)},
                   "generation_tree_sha256": cleanup.NATIVE.tree_digest(target)}
        (target / "receipt.json").write_text(json.dumps(receipt))
        cleanup.NATIVE.freeze(target)
        (root / "current.json").write_text(json.dumps({"format": "sw-native-pilot-current/1",
                "generation": "c" * 32, "receipt_sha256": "d" * 64}))
        current = generations / ("c" * 32)
        current.mkdir(mode=0o700)
        return target

    def test_inactive_plan_and_confirmed_remove_preserve_unrelated_state(self):
        cleanup = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = self.fixture(root, cleanup)
            sentinel = root / "operator.txt"
            sentinel.write_text("keep")
            with patch.object(cleanup, "active_use", return_value=False):
                plan = cleanup.inspect(root, target.name)
                self.assertEqual(plan["classification"], "inactive")
                self.assertTrue(target.exists())
                result = cleanup.apply(root, target.name, plan["confirmation"])
            self.assertEqual(result["status"], "removed")
            self.assertFalse(target.exists())
            self.assertEqual(sentinel.read_text(), "keep")
            self.assertTrue((root / "generations" / ("c" * 32)).is_dir())

    def test_selected_and_incomplete_generation_cannot_be_removed(self):
        cleanup = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = self.fixture(root, cleanup)
            incomplete = "e" * 32
            (root / "generations" / incomplete).mkdir(mode=0o700)
            for name, classification in (("c" * 32, "current"), (incomplete, "incomplete")):
                plan = cleanup.inspect(root, name)
                self.assertEqual(plan["classification"], classification)
                self.assertIsNone(plan["confirmation"])
                with self.assertRaises(ValueError):
                    cleanup.apply(root, name, "0" * 64)

    def test_active_process_refusal(self):
        cleanup = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = self.fixture(root, cleanup)
            process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"], cwd=target)
            try:
                plan = cleanup.inspect(root, target.name)
                self.assertEqual(plan["classification"], "active-or-uncertain")
                self.assertIsNone(plan["confirmation"])
                self.assertIsNone(process.poll())
            finally:
                process.terminate()
                process.wait(timeout=5)

    def test_traversal_and_symlink_escape_preserve_destination(self):
        cleanup = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = self.fixture(root, cleanup)
            for name in ("../", str(target), "a" * 31):
                with self.assertRaises(ValueError):
                    cleanup.inspect(root, name)
            target.chmod(0o700)
            (target / "escape").symlink_to(root)
            with self.assertRaises(ValueError):
                cleanup.inspect(root, target.name)
            self.assertTrue((root / "current.json").exists())

    def test_tampered_receipt_and_stale_confirmation_are_refused(self):
        cleanup = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = self.fixture(root, cleanup)
            with patch.object(cleanup, "active_use", return_value=False):
                plan = cleanup.inspect(root, target.name)
            receipt = target / "receipt.json"
            receipt.chmod(0o600)
            value = json.loads(receipt.read_text())
            value["generation_tree_sha256"] = "0" * 64
            receipt.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                cleanup.apply(root, target.name, plan["confirmation"])
            self.assertTrue(target.is_dir())

    def test_unreadable_process_is_uncertain(self):
        cleanup = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(cleanup.os, "readlink", side_effect=PermissionError):
                child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
                try:
                    self.assertTrue(cleanup.active_use(Path(temporary)))
                finally:
                    child.terminate()
                    child.wait(timeout=5)

    def test_runtime_workspace_is_preserved_by_asset_prune(self):
        cleanup = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            workspace = root / "filesystem-workspace"
            workspace.mkdir(mode=0o700)
            (workspace / "notes.txt").write_text("operator notes")
            (root / "asset").write_text("owned asset")
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                cleanup.erase(descriptor, root.stat().st_dev, preserve={"filesystem-workspace"})
            finally:
                os.close(descriptor)
            self.assertEqual((workspace / "notes.txt").read_text(), "operator notes")
            self.assertFalse((root / "asset").exists())

    def test_runtime_receipts_prune_assets_but_keep_both_workspaces(self):
        cleanup = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            (root / "generations").mkdir(mode=0o700)
            target = root / "generations" / ("a" * 32)
            target.mkdir(mode=0o700)
            executable = str(Path(sys.executable).resolve())
            paths = {role: {"path": executable, "sha256": cleanup.sha(executable)}
                     for role in cleanup.PREP.PILOT.ROLES}
            profiles = {}
            for kind, number in (("filesystem", 62), ("git", 68)):
                installer = cleanup.PREP.FS if kind == "filesystem" else cleanup.PREP.GIT
                workspace = target / (kind + "-workspace")
                workspace.mkdir(mode=0o700)
                (workspace / "operator.txt").write_text("keep " + kind)
                directory = target / (kind + "-profile")
                directory.mkdir(mode=0o700)
                package = directory / "package"
                package.mkdir(mode=0o700)
                runtime = executable
                if kind == "git":
                    python = package / "python/bin"
                    python.mkdir(parents=True, mode=0o700)
                    runtime = str(python / "python3.11")
                    Path(runtime).write_bytes(b"synthetic Python runtime")
                profile = {"format": installer.FORMAT, "workspace": str(workspace),
                           "packageRoot": str(package), "packageTreeSha256": cleanup.PREP.FS.tree_sha(package),
                           "bwrapPath": executable, "bwrapSha256": paths["bwrap"]["sha256"],
                           "runtimePath": runtime, "runtimeSha256": cleanup.sha(runtime), "libraries": []}
                if kind == "git":
                    profile.update(git=paths["git"], gitLauncher=paths["git_launcher"])
                registry = installer.registry(json.loads((installer.ASSETS / "upstream-tools-list.json").read_bytes()))
                (directory / "profile.json").write_text(json.dumps(profile))
                (directory / "registry.json").write_text(json.dumps(registry))
                (directory / "policy.yaml").write_bytes((installer.ASSETS / "policy.yaml").read_bytes())
                receipt = {"format": f"sou{number}-profile-installation/1", "profile": profile,
                           **{label + "_sha256": cleanup.sha(directory / (label + suffix))
                              for label, suffix in (("profile", ".json"), ("registry", ".json"), ("policy", ".yaml"))}}
                (directory / "installation.json").write_text(json.dumps(receipt))
                profiles[kind] = {"profile": {"path": str(directory / "profile.json"), "sha256": receipt["profile_sha256"]},
                                  "registry_sha256": receipt["registry_sha256"], "package_tree_sha256": profile["packageTreeSha256"]}
            selection = {"format": "sw-installed-pilot-selection/2", "source": {"commit": "b" * 40},
                         "files": paths, "prepared_profiles": profiles}
            (target / "selection.json").write_text(json.dumps(selection))
            (root / "current.json").write_text(json.dumps({"format": "sw-pilot-preparation/1",
                    "generation": "c" * 32, "selection_sha256": "d" * 64, "status": "prepared-not-active"}))
            with patch.object(cleanup, "active_use", return_value=False):
                plan = cleanup.inspect(root, target.name)
                self.assertEqual(plan["classification"], "inactive")
                result = cleanup.apply(root, target.name, plan["confirmation"])
            self.assertEqual(result["status"], "assets-removed-workspaces-retained")
            for kind in ("filesystem", "git"):
                self.assertEqual((target / (kind + "-workspace/operator.txt")).read_text(), "keep " + kind)
                self.assertFalse((target / (kind + "-profile")).exists())

    def test_confirmation_changes_when_selected_generation_changes(self):
        cleanup = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = self.fixture(root, cleanup)
            with patch.object(cleanup, "active_use", return_value=False):
                before = cleanup.inspect(root, target.name)
                marker = root / "current.json"
                value = json.loads(marker.read_text())
                value["receipt_sha256"] = "e" * 64
                marker.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, "confirmation"):
                    cleanup.apply(root, target.name, before["confirmation"])
            self.assertTrue(target.is_dir())

    def test_hardlink_refusal_preserves_external_file(self):
        cleanup = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = self.fixture(root, cleanup)
            outside = root / "unrelated.txt"
            outside.write_text("keep")
            target.chmod(0o700)
            os.link(outside, target / "alias")
            with self.assertRaisesRegex(ValueError, "hardlinked"):
                cleanup.inspect(root, target.name)
            self.assertEqual(outside.read_text(), "keep")

    def test_descriptor_descent_refuses_bound_mount(self):
        self.load()
        program = '''import importlib.util, os, pathlib, subprocess, sys, tempfile
spec = importlib.util.spec_from_file_location("cleanup", sys.argv[1])
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)
with tempfile.TemporaryDirectory() as temporary:
    root = pathlib.Path(temporary)
    target, outside = root / "target", root / "outside"
    target.mkdir(mode=0o700)
    outside.mkdir(mode=0o700)
    (outside / "keep.txt").write_text("keep")
    subprocess.run(["mount", "--bind", str(outside), str(target)], check=True, capture_output=True)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        try:
            child = cleanup.open_child(descriptor, "target")
        except ValueError as error:
            assert str(error) == "directory_mount_or_link_refused"
        else:
            os.close(child)
            raise AssertionError("descriptor crossed a bind mount")
        assert (outside / "keep.txt").read_text() == "keep"
    finally:
        os.close(descriptor)
        subprocess.run(["umount", str(target)], check=True, capture_output=True)
'''
        result = subprocess.run(["unshare", "--user", "--map-root-user", "--mount", "--fork",
                                 sys.executable, "-B", "-c", program, str(SCRIPT)],
                                capture_output=True, text=True, timeout=20)
        if "unshare failed: Operation not permitted" in result.stderr:
            self.skipTest("host does not permit an isolated test mount namespace")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_unused_generation_without_process_mock(self):
        cleanup = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = self.fixture(root, cleanup)
            plan = cleanup.inspect(root, target.name)
            if plan["classification"] == "active-or-uncertain":
                self.skipTest("positive acceptance requires an inspectable native host account")
            result = cleanup.apply(root, target.name, plan["confirmation"])
            self.assertEqual(result["status"], "removed")
            self.assertFalse(target.exists())

    def test_nested_user_namespace_refuses_before_inspection(self):
        cleanup = self.load()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = self.fixture(root, cleanup)
            original = Path.read_text
            def nested_mapping(path, *args, **kwargs):
                if str(path) == "/proc/self/uid_map":
                    return "1000 1000 1\n"
                return original(path, *args, **kwargs)
            with patch("pathlib.Path.read_text", autospec=True, side_effect=nested_mapping):
                with self.assertRaisesRegex(ValueError, "host_user_namespace_required"):
                    cleanup.inspect(root, target.name)
            self.assertTrue(target.exists())


if __name__ == "__main__":
    unittest.main()
