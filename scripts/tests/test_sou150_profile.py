# SPDX-License-Identifier: Apache-2.0
"""Explicit identity/selection controls. Native containment is tested separately."""
import importlib.util
import json
from pathlib import Path
import os
import subprocess
import sys
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sou150_installer_tests", ROOT / "scripts/install-sou150-git-profile.py")
PROFILE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PROFILE)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.install = self.root / "installed"
        self.install.mkdir()
        workspace = self.root / "workspace"
        workspace.mkdir()
        self.profile = {"format": PROFILE.FORMAT, "workspace": str(workspace)}
        (self.install / "profile.json").write_text(json.dumps(self.profile))
        manifest = json.loads((PROFILE.SHARED.V1.ASSETS / "upstream-tools-list.json").read_text())
        (self.install / "registry.json").write_text(json.dumps(PROFILE.registry(manifest)))
        shutil.copyfile(ROOT / "profiles/pilot/linux-readonly-v1/policy.yaml", self.install / "policy.yaml")
        self.receipt()

    def receipt(self):
        receipt = {"format": "sou150-profile-installation/1", "selection_identity": PROFILE.identity(),
                   "profile": json.loads((self.install / "profile.json").read_text())}
        for name, suffix in (("profile", ".json"), ("registry", ".json"), ("policy", ".yaml")):
            receipt[name + "_sha256"] = PROFILE.sha(self.install / (name + suffix))
        (self.install / "installation.json").write_text(json.dumps(receipt))

    def prepare(self):
        with patch.object(PROFILE.SHARED.platform, "system", return_value="Linux"), patch.object(PROFILE.SHARED.platform, "machine", return_value="x86_64"):
            return PROFILE.prepare(self.install, self.root / "selection", 48001)

    def test_explicit_profile_preserves_installation_and_separate_default(self):
        before = {p.name: p.read_bytes() for p in self.install.iterdir()}
        config, receipt = self.prepare()
        self.assertTrue(config["enforce"])
        self.assertEqual(receipt["status"], "prepared-not-active")
        self.assertEqual(receipt["format"], PROFILE.FORMAT)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.install.iterdir()})
        self.assertEqual(PROFILE.SHARED.selection_parameters()["format"], PROFILE.SHARED.FORMAT)
        self.assertNotEqual(PROFILE.SHARED.identity(), PROFILE.identity())
        self.assertEqual(receipt["identity_sha256"], PROFILE.sha(ROOT / PROFILE.SELECTION["identity"]))

    def test_rehashed_wrong_profile_is_not_combined_or_selected(self):
        self.profile["format"] = PROFILE.SHARED.FORMAT
        (self.install / "profile.json").write_text(json.dumps(self.profile))
        self.receipt()
        with self.assertRaisesRegex(ValueError, "profile mismatch"):
            self.prepare()

    def test_policy_or_registry_rehash_does_not_widen_authority(self):
        registry = json.loads((self.install / "registry.json").read_text())
        registry["tools"][0]["result_provenance"] = "trusted"
        (self.install / "registry.json").write_text(json.dumps(registry))
        self.receipt()
        with self.assertRaisesRegex(ValueError, "authority"):
            self.prepare()

    def test_default_installation_cannot_be_reused_as_link_selection(self):
        receipt = json.loads((self.install / "installation.json").read_text())
        receipt["format"] = "sou107-profile-installation/1"
        (self.install / "installation.json").write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self.prepare()

    def test_changed_installed_bytes_refuse_before_selection_is_created(self):
        (self.install / "policy.yaml").write_text("default: allow\n")
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            self.prepare()
        self.assertFalse((self.root / "selection").exists())


spec = importlib.util.spec_from_file_location("sou150_native_driver_tests", ROOT / "scripts/verify-sou150-tracked-symlinks.py")
NATIVE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(NATIVE)


class NativeDriverTests(unittest.TestCase):
    def test_plan_does_not_execute_or_create_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "absent-output"
            command = [sys.executable, "-B", str(ROOT / "scripts/verify-sou150-tracked-symlinks.py")]
            for option in ("agentfw", "git", "bwrap", "git-launcher", "sandbox-test-binary"):
                command.extend(["--" + option, "/absent-executable"])
            command.extend(["--output", str(output), "--git-sha256", "0" * 64, "--expected-commit", "0" * 40])
            result = subprocess.run(command, capture_output=True, timeout=10, check=True)
            self.assertEqual(json.loads(result.stdout)["executed"], False)
            self.assertFalse(output.exists())

    def test_non_linux_run_refuses_before_provisioning(self):
        with patch.object(NATIVE.platform, "system", return_value="Darwin"), patch.object(NATIVE.INSTALL, "install") as install:
            with self.assertRaisesRegex(ValueError, "Linux x86-64"):
                NATIVE.run(None)
            install.assert_not_called()

    @unittest.skipUnless(os.name == "posix" and shutil.which("git"), "owned Git symlink fixture requires POSIX Git")
    def test_fixture_retains_git_link_objects_and_all_three_deltas(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir()
            env = NATIVE.BASE.environment(home)
            env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_OPTIONAL_LOCKS="0")
            workspace = root / "workspace"
            binary = Path(shutil.which("git"))
            NATIVE.fixture(workspace, binary, env)
            def git(*args):
                return subprocess.check_output([str(binary), *args], cwd=workspace, env=env, stderr=subprocess.PIPE, timeout=10)
            self.assertTrue((workspace / "tracked-link").is_symlink())
            self.assertEqual(git("show", "HEAD:tracked-link"), b"notes.txt")
            self.assertEqual(git("show", "HEAD:nested/relative-link"), b"../notes.txt")
            self.assertIn(b"synthetic staged text", git("diff", "--cached"))
            self.assertIn(b"synthetic changed text", git("diff"))
            self.assertIn(b"120000", git("show", "HEAD"))


if __name__ == "__main__":
    unittest.main()
