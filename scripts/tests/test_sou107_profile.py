# SPDX-License-Identifier: Apache-2.0
"""Authority/selection negative controls, not a substitute for Linux proof."""
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("sou107", ROOT / "scripts/install-sou107-git-profile.py")
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
        self.destination = self.root / "selection"
        self.profile = {"format": PROFILE.FORMAT, "workspace": str(workspace)}
        (self.install / "profile.json").write_text(json.dumps(self.profile))
        manifest = json.loads((PROFILE.V1.ASSETS / "upstream-tools-list.json").read_text())
        (self.install / "registry.json").write_text(json.dumps(PROFILE.registry(manifest)))
        shutil.copyfile(ROOT / "profiles/pilot/linux-readonly-v1/policy.yaml", self.install / "policy.yaml")
        self.receipt()

    def receipt(self):
        receipt = {"format": "sou107-profile-installation/1", "selection_identity": PROFILE.identity(),
                   "profile": json.loads((self.install / "profile.json").read_text())}
        for kind in ("profile", "registry", "policy"):
            receipt[kind + "_sha256"] = PROFILE.sha(self.install / (kind + (".yaml" if kind == "policy" else ".json")))
        (self.install / "installation.json").write_text(json.dumps(receipt))

    def prepare(self):
        with patch.object(PROFILE.platform, "system", return_value="Linux"), patch.object(PROFILE.platform, "machine", return_value="x86_64"):
            return PROFILE.prepare(self.install, self.destination, 48001)

    def test_explicit_selection_keeps_original_bytes_and_is_not_activation(self):
        before = {p.name: p.read_bytes() for p in self.install.iterdir()}
        config, receipt = self.prepare()
        self.assertTrue(config["enforce"])
        self.assertEqual(receipt["status"], "prepared-not-active")
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.install.iterdir()})
        self.assertEqual(receipt["environment"]["AGENTFW_CLASSIFIER"], "rule-baseline")
        self.assertEqual(receipt["python_sha256"], PROFILE.sha(receipt["environment"]["AGENTFW_CLASSIFIER_PYTHON"]))
        self.assertEqual(receipt["identity_sha256"], PROFILE.sha(ROOT / "profiles/mcp/git-local-clone-readonly-v1/identity.json"))
        with self.assertRaises(ValueError):
            self.prepare()

    def test_changed_installed_bytes_refused(self):
        with (self.install / "policy.yaml").open("a") as stream:
            stream.write("\n# changed\n")
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_rehashed_weakened_registry_refused(self):
        path = self.install / "registry.json"
        registry = json.loads(path.read_text())
        registry["tools"][0]["result_provenance"] = "trusted"
        path.write_text(json.dumps(registry))
        self.receipt()
        with self.assertRaisesRegex(ValueError, "authority"):
            self.prepare()

    def test_rehashed_weakened_policy_refused(self):
        (self.install / "policy.yaml").write_text("default: allow\n")
        self.receipt()
        with self.assertRaisesRegex(ValueError, "policy changed"):
            self.prepare()

    def test_v1_cannot_be_silently_selected(self):
        self.profile["format"] = "sw-mcp/git-readonly/1"
        (self.install / "profile.json").write_text(json.dumps(self.profile))
        self.receipt()
        with self.assertRaisesRegex(ValueError, "profile mismatch"):
            self.prepare()

    def test_changed_classifier_dependency_refused(self):
        original = PROFILE.sha
        with patch.object(PROFILE, "sha", side_effect=lambda p: "0" * 64 if Path(p).name == "rule_baseline.py" else original(p)):
            with self.assertRaisesRegex(ValueError, "dependency mismatch"):
                self.prepare()

    def test_fresh_v1_installation_is_converted_without_exclusive_write_collision(self):
        destination = self.root / "fresh"
        def upstream(target, *_args, **kwargs):
            self.assertEqual(kwargs, {"static_git": True})
            target.mkdir()
            for source in self.install.iterdir():
                shutil.copyfile(source, target / source.name)
        with patch.object(PROFILE.V1, "install", side_effect=upstream), patch.object(PROFILE, "require_static_git"):
            result = PROFILE.install(destination, self.profile["workspace"], "git", "a" * 64, "bwrap", "launcher")
        self.assertEqual(result["status"], "prepared-not-active")
        self.assertEqual(json.loads((destination / "profile.json").read_text())["format"], PROFILE.FORMAT)
        self.assertFalse(list(destination.glob("*.sou107-new")))
        self.assertEqual(json.loads((destination / "installation.json").read_text())["profile_sha256"], PROFILE.sha(destination / "profile.json"))

    def test_dynamic_git_is_rejected_without_allowing_the_loader(self):
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", header, 18, 62)
        struct.pack_into("<Q", header, 32, 64)
        struct.pack_into("<HH", header, 54, 56, 2)
        table = bytearray(112)
        struct.pack_into("<I", table, 0, 1)
        struct.pack_into("<I", table, 56, 3)
        path = self.root / "owned-elf"
        path.write_bytes(header + table)
        with self.assertRaisesRegex(ValueError, "no ELF interpreter"):
            PROFILE.require_static_git(path)
        struct.pack_into("<I", table, 56, 4)
        path.write_bytes(header + table)
        PROFILE.require_static_git(path)
        path.write_bytes(header + table[:20])
        with self.assertRaisesRegex(ValueError, "truncated"):
            PROFILE.require_static_git(path)


@unittest.skipUnless(sys.platform == "linux", "independent inotify witness requires Linux")
class ContinuousWitnessTests(unittest.TestCase):
    def test_real_open_burst_empty_interval_and_latched_failure(self):
        spec = importlib.util.spec_from_file_location("sou107_verify", ROOT / "scripts/verify-sou107-real-git.py")
        verify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = [root / "one", root / "two"]
            for path in paths:
                path.write_bytes(b"owned control")
            witness = verify.ContinuousRepositoryWitness(root)
            try:
                for n in range(1024):
                    paths[n % 2].read_bytes()
                self.assertEqual(witness.drain(), 1024)
                self.assertEqual(witness.drain(), 0)
                with witness._lock:
                    witness._failure = ValueError("injected queue overflow")
                for _ in range(2):
                    with self.assertRaisesRegex(ValueError, "witness failed"):
                        witness.drain()
            finally:
                if witness._failure is None:
                    witness.close()
                else:
                    with self.assertRaisesRegex(ValueError, "witness failed"):
                        witness.close()
            self.assertEqual(witness.fd, -1)
            self.assertFalse(witness._thread.is_alive())


if __name__ == "__main__":
    unittest.main()
