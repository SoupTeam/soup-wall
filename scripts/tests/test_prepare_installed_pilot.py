# SPDX-License-Identifier: Apache-2.0
"""Failure boundaries for the SOU-111 preparation transaction."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sou111_preparation", ROOT / "scripts/prepare-installed-pilot.py")
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)


class PreparationBoundary(unittest.TestCase):
    def test_default_plan_is_non_mutating_and_inventories_missing_inputs(self):
        import subprocess
        result = subprocess.run([os.sys.executable, "-B", str(ROOT / "scripts/prepare-installed-pilot.py"),
                                 "--output", "/tmp/sou111-plan-does-not-create"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["status"], "plan")
        self.assertFalse(plan["executed"])
        self.assertIn("--agentfw PATH", plan["missing"])
        self.assertFalse(Path("/tmp/sou111-plan-does-not-create").exists())

    def test_wrong_digest_and_corrupt_archive_do_not_extract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive, destination = root / "node.tar.xz", root / "runtime"
            destination.mkdir()
            archive.write_bytes(b"not the pinned runtime")
            with self.assertRaisesRegex(ValueError, "input_digest_mismatch"):
                PREP.extract_node(archive, destination)
            self.assertEqual(list(destination.iterdir()), [])
            with patch.object(PREP, "NODE_ARCHIVE_SHA256", PREP.FS.sha(archive)):
                with self.assertRaises(tarfile.TarError):
                    PREP.extract_node(archive, destination)
            self.assertEqual(list(destination.iterdir()), [])

    def test_archive_rejects_traversal_external_symlink_and_link_parent(self):
        for name, kind, link in (("node-v22.22.0-linux-x64/../escape", tarfile.REGTYPE, ""),
                                 ("node-v22.22.0-linux-x64/bin/npm", tarfile.SYMTYPE, "/etc/passwd"),
                                 ("node-v22.22.0-linux-x64/bin/npm/x", tarfile.REGTYPE, "")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive, destination = root / "node.tar.xz", root / "runtime"
                destination.mkdir()
                with tarfile.open(archive, "w:xz") as bundle:
                    if name.endswith("/x"):
                        parent = tarfile.TarInfo("node-v22.22.0-linux-x64/bin/npm")
                        parent.type, parent.linkname = tarfile.SYMTYPE, "../lib"
                        bundle.addfile(parent)
                    entry = tarfile.TarInfo(name)
                    entry.type, entry.linkname = kind, link
                    if kind == tarfile.REGTYPE:
                        entry.size = 1
                        bundle.addfile(entry, io.BytesIO(b"x"))
                    else:
                        bundle.addfile(entry)
                with patch.object(PREP, "NODE_ARCHIVE_SHA256", PREP.FS.sha(archive)):
                    with self.assertRaises(ValueError):
                        PREP.extract_node(archive, destination)
                self.assertFalse((root / "escape").exists())

    @unittest.skipUnless(os.name == "posix", "owned POSIX mode and ldd checks require Linux")
    def test_private_path_and_native_dependency_reject(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private"
            private.mkdir(mode=0o700)
            private.chmod(0o700)
            PREP.private_dir(private)
            private.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "private_owned_0700"):
                PREP.private_dir(private)
            private.chmod(0o700)
            (root / "link").symlink_to(private)
            with self.assertRaisesRegex(ValueError, "private_directory_required"):
                PREP.private_dir(root / "link")
            with patch.object(PREP.subprocess, "run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = "libmissing.so => not found"
                run.return_value.stderr = ""
                with self.assertRaisesRegex(ValueError, "native_dependency_missing"):
                    PREP.check_native(Path(os.sys.executable))

    @unittest.skipUnless(os.name == "posix", "profile ownership requires Linux")
    def test_changed_package_and_runtime_fail_revalidation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            package.mkdir()
            (package / "entry.js").write_text("original")
            profile = {"format": PREP.FS.FORMAT, "packageRoot": str(package),
                       "packageTreeSha256": PREP.FS.tree_sha(package), "runtimePath": os.sys.executable,
                       "runtimeSha256": PREP.FS.sha(os.sys.executable), "libraries": [],
                       "workspace": str(root / "workspace"), "bwrapPath": os.sys.executable,
                       "bwrapSha256": PREP.FS.sha(os.sys.executable)}
            (root / "workspace").mkdir()
            assets = PREP.FS.ASSETS
            registry = PREP.FS.registry(json.loads((assets / "upstream-tools-list.json").read_text()))
            for name, value in (("profile.json", profile), ("registry.json", registry)):
                (root / name).write_text(json.dumps(value))
            (root / "policy.yaml").write_bytes((assets / "policy.yaml").read_bytes())
            receipt = {"format": "sou62-profile-installation/1", "profile": profile,
                       **{name + "_sha256": PREP.FS.sha(root / (name + (".yaml" if name == "policy" else ".json")))
                          for name in ("profile", "registry", "policy")}}
            (root / "installation.json").write_text(json.dumps(receipt))
            paths = {"bwrap": Path(os.sys.executable), "node": Path(os.sys.executable)}
            PREP.verify_profile("filesystem", root, paths, root / "workspace")
            (package / "entry.js").write_text("changed")
            with self.assertRaisesRegex(ValueError, "profile_package_changed"):
                PREP.verify_profile("filesystem", root, paths, root / "workspace")
            (package / "entry.js").write_text("original")
            profile["runtimeSha256"] = "0" * 64
            (root / "profile.json").write_text(json.dumps(profile))
            receipt["profile"] = profile
            receipt["profile_sha256"] = PREP.FS.sha(root / "profile.json")
            (root / "installation.json").write_text(json.dumps(receipt))
            with self.assertRaisesRegex(ValueError, "profile_runtime_changed"):
                PREP.verify_profile("filesystem", root, paths, root / "workspace")

    @unittest.skipUnless(os.name == "posix", "private generation ownership requires Linux")
    def test_marker_is_atomic_and_old_or_unrelated_files_survive_failed_rebuild(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unrelated = root / "unrelated.txt"
            unrelated.write_text("keep")
            output = root / "output"
            before = {"commit": "a" * 40, "tree": "b" * 40, "dirty": False, "files_sha256": "c" * 64}
            args = SimpleNamespace(output=output, expected_commit="a" * 40, rebuild=False,
                                   npm_cache=None, wheelhouse=None, python_archive=None, node_archive=None,
                                   allow_download=True, refusal_verdict="ask", refusal_rule="exact-rule")
            paths = {role: Path(os.sys.executable) for role in PREP.PILOT.ROLES}
            profiles = {kind: {"profile": {"path": str(root / kind), "sha256": "d" * 64},
                               "registry_sha256": "e" * 64, "package_tree_sha256": "f" * 64}
                        for kind in ("filesystem", "git")}

            def init_git(command, **_):
                (Path(command[-1]) / ".git").mkdir()

            with patch.object(PREP, "supported_platform"), patch.object(PREP.PILOT, "source", return_value=before), \
                 patch.object(PREP, "selected_paths", return_value=paths), \
                 patch.object(PREP, "verify_profile", side_effect=lambda kind, *_: profiles[kind]), \
                 patch.object(PREP, "verify_generation", side_effect=lambda gen, *_: (gen / "selection.json", profiles)), \
                 patch.object(PREP.subprocess, "run", side_effect=init_git), \
                 patch.object(PREP.FS, "install") as fs_install, patch.object(PREP.GIT, "install"):
                first = PREP.prepare(args)
                marker = json.loads((output / "current.json").read_text())
                self.assertEqual(first["status"], "prepared-not-active")
                self.assertIsNotNone(fs_install.call_args_list[0].kwargs["log"])
                self.assertEqual(stat.S_IMODE((output / "generations" / first["generation"] /
                                               "filesystem-install.log").stat().st_mode), 0o600)
                self.assertEqual(PREP.prepare(args)["status"], "reused")
                fs_install.side_effect = ValueError("interrupted_install")
                args.rebuild = True
                with self.assertRaisesRegex(ValueError, "interrupted_install"):
                    PREP.prepare(args)
                self.assertEqual(json.loads((output / "current.json").read_text()), marker)
                self.assertEqual(unrelated.read_text(), "keep")
                self.assertEqual(len(list((output / "generations").iterdir())), 2)


if __name__ == "__main__":
    unittest.main()
