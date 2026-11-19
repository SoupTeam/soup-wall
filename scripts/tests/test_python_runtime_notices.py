# SPDX-License-Identifier: Apache-2.0
"""Local Python notice custody controls; no runtime programs are executed."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("python_notice_installer", ROOT / "scripts/install-sou68-git-profile.py")
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)


class PythonRuntimeNotices(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.identity = json.loads((INSTALL.ASSETS / "upstream-identity.json").read_bytes())
        self.prefix = "upstream-notices/python-" + self.identity["python"]["version"]
        shutil.copytree(INSTALL.ASSETS / self.prefix, self.assets / self.prefix)
        shutil.copytree(INSTALL.ASSETS / "upstream-notices/runtime-licenses",
                        self.assets / "upstream-notices/runtime-licenses")
        (self.assets / "upstream-identity.json").write_text(json.dumps(self.identity))
        self.asset_patch = patch.object(INSTALL, "ASSETS", self.assets)
        self.asset_patch.start()
        self.addCleanup(self.asset_patch.stop)

    def verify(self, identity=None):
        INSTALL.verify_python_notices(self.identity if identity is None else identity)

    def test_runtime_supplemental_bundle_is_verified_and_every_member_is_required(self):
        INSTALL.verify_runtime_license_notices(self.identity)
        folder = self.assets / "upstream-notices/runtime-licenses"
        for path in folder.iterdir():
            raw = path.read_bytes()
            with self.subTest(path=path.name, mutation="corrupt"):
                path.write_bytes(b"changed" + raw[7:])
                with self.assertRaisesRegex(ValueError, "identity mismatch"):
                    INSTALL.verify_runtime_license_notices(self.identity)
            path.write_bytes(raw)
            with self.subTest(path=path.name, mutation="missing"):
                path.unlink()
                with self.assertRaises(ValueError):
                    INSTALL.verify_runtime_license_notices(self.identity)
            path.write_bytes(raw)
        (folder / "unbound.txt").write_bytes(b"unbound")
        with self.assertRaisesRegex(ValueError, "differs from declaration"):
            INSTALL.verify_runtime_license_notices(self.identity)

    def test_runtime_provenance_refuses_absent_or_unsafe_binding(self):
        for value in (None, {}, {"path": "../escape", "sha256": "a" * 64}):
            identity = copy.deepcopy(self.identity)
            identity["runtime_license_provenance"] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "identity required"):
                INSTALL.verify_runtime_license_notices(identity)

    def test_complete_declared_bundle_is_verified_and_retained_by_profile_copy(self):
        self.verify()
        installed = self.root / "installed-notices"
        shutil.copytree(self.assets / "upstream-notices", installed)
        for name in self.identity["python"]["upstream_notices"]:
            self.assertEqual((installed / Path(name).relative_to("upstream-notices")).read_bytes(),
                             (self.assets / name).read_bytes())

    def test_every_notice_and_provenance_refuses_corruption_or_removal(self):
        for name in self.identity["python"]["upstream_notices"]:
            path = self.assets / name
            original = path.read_bytes()
            with self.subTest(path=name, mutation="corrupt"):
                path.write_bytes(b"changed" + original[7:])
                with self.assertRaisesRegex(ValueError, "identity mismatch"):
                    self.verify()
            with self.subTest(path=name, mutation="missing"):
                path.unlink()
                with self.assertRaisesRegex(ValueError, "differs from declaration"):
                    self.verify()
            path.write_bytes(original)

    def test_missing_declaration_provenance_or_extra_file_is_refused(self):
        for value in (None, {}, []):
            identity = copy.deepcopy(self.identity)
            identity["python"]["upstream_notices"] = value
            with self.subTest(declaration=value), self.assertRaises(ValueError):
                self.verify(identity)
        identity = copy.deepcopy(self.identity)
        del identity["python"]["upstream_notices"][self.prefix + "/provenance.json"]
        with self.assertRaisesRegex(ValueError, "provenance is required"):
            self.verify(identity)
        (self.assets / self.prefix / "unbound.txt").write_bytes(b"unbound")
        with self.assertRaisesRegex(ValueError, "differs from declaration"):
            self.verify()

    def test_unsafe_paths_and_invalid_digests_are_refused(self):
        original = next(iter(self.identity["python"]["upstream_notices"]))
        unsafe = ("../escape", "/absolute", original.replace("/", "//", 1),
                  original.replace("/", "/./", 1), original.replace("/", "\\"),
                  self.prefix + "/../LICENSE.escape.txt", self.prefix + "/LICENSE.txt:stream")
        for name in unsafe:
            identity = copy.deepcopy(self.identity)
            value = identity["python"]["upstream_notices"].pop(original)
            identity["python"]["upstream_notices"][name] = value
            with self.subTest(path=name), self.assertRaisesRegex(ValueError, "unsafe.*path"):
                self.verify(identity)
        for digest in (None, "bad", "F" * 64):
            identity = copy.deepcopy(self.identity)
            identity["python"]["upstream_notices"][original] = digest
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, "invalid.*identity"):
                self.verify(identity)

    def test_file_and_parent_directory_symlinks_are_refused(self):
        name = next(iter(self.identity["python"]["upstream_notices"]))
        path = self.assets / name
        original = path.read_bytes()
        target = self.root / "external.txt"
        target.write_bytes(original)
        path.unlink()
        try:
            path.symlink_to(target)
        except OSError as error:
            self.skipTest("symlink fixture unavailable: " + str(error))
        with self.assertRaisesRegex(ValueError, "unsafe.*file"):
            self.verify()
        other_assets = self.root / "linked-assets"
        other_assets.mkdir()
        (other_assets / "upstream-notices").symlink_to(self.assets / "upstream-notices", target_is_directory=True)
        with patch.object(INSTALL, "ASSETS", other_assets), self.assertRaisesRegex(ValueError, "unsafe.*directory"):
            self.verify()

    def test_install_refuses_changed_notices_before_programs_or_destination_writes(self):
        workspace = self.root / "workspace"
        (workspace / ".git").mkdir(parents=True)
        program = self.root / "unused-program"
        program.write_bytes(b"never executed")
        name = next(iter(self.identity["python"]["upstream_notices"]))
        (self.assets / name).write_bytes(b"changed")
        destination = self.root / "destination"
        with patch.object(INSTALL.platform, "system", return_value="Linux"), \
             patch.object(INSTALL.platform, "machine", return_value="x86_64"), \
             patch.object(INSTALL.subprocess, "check_output") as probe, \
             patch.object(INSTALL.urllib.request, "urlopen") as download:
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                INSTALL.install(destination, workspace, program, INSTALL.sha(program), program, program)
        probe.assert_not_called()
        download.assert_not_called()
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
