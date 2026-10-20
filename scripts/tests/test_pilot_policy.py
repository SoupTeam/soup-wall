# SPDX-License-Identifier: Apache-2.0
"""Selector negative controls; these do not substitute for Linux execution."""
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("pilot", ROOT / "scripts/pilot_policy.py")
PILOT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PILOT)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.install = self.root / "installation"
        self.install.mkdir()
        self.destination = self.root / "selection"
        workspace = self.root / "workspace"
        workspace.mkdir()
        self.profile = {"format": "sw-mcp/filesystem-readonly/1", "workspace": str(workspace)}
        (self.install / "profile.json").write_text(json.dumps(self.profile))
        upstream = PILOT.read(ROOT / "profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json")
        spec = importlib.util.spec_from_file_location("install", ROOT / "scripts/install-sou62-filesystem-profile.py")
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        (self.install / "registry.json").write_text(json.dumps(installer.registry(upstream)))
        shutil.copyfile(ROOT / "profiles/mcp/filesystem-readonly-v1/policy.yaml", self.install / "policy.yaml")
        self.receipt()

    def receipt(self):
        data = {"profile": PILOT.read(self.install / "profile.json")}
        for kind in ("profile", "registry", "policy"):
            data[kind + "_sha256"] = PILOT.sha(self.install / (kind + (".yaml" if kind == "policy" else ".json")))
        (self.install / "installation.json").write_text(json.dumps(data))

    def prepare(self):
        with patch.object(PILOT.platform, "system", return_value="Linux"), \
                patch.object(PILOT.platform, "machine", return_value="x86_64"):
            return PILOT.prepare("filesystem", self.install, self.destination, 48001)

    def test_selection_preserves_original_policy_and_never_claims_active(self):
        original = PILOT.sha(self.install / "policy.yaml")
        config, receipt = self.prepare()
        self.assertTrue(config["enforce"])
        self.assertEqual(receipt["status"], "prepared-not-active")
        self.assertEqual(receipt["policy_sha256"], PILOT.sha(PILOT.ASSETS / "policy.yaml"))
        self.assertEqual(original, PILOT.sha(self.install / "policy.yaml"))
        self.assertEqual(config["native"]["registry_sha256"], PILOT.sha(self.install / "registry.json"))
        with self.assertRaises(ValueError):
            self.prepare()

    def test_changed_profile_receipt_refused(self):
        (self.install / "profile.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "identity"):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_rehashed_weakened_registry_refused(self):
        registry = PILOT.read(self.install / "registry.json")
        registry["tools"][0]["result_provenance"] = "trusted"
        (self.install / "registry.json").write_text(json.dumps(registry))
        self.receipt()
        with self.assertRaisesRegex(ValueError, "authority"):
            self.prepare()

    def test_rehashed_weakened_scenario_policy_refused(self):
        (self.install / "policy.yaml").write_text("default: allow\n")
        self.receipt()
        with self.assertRaisesRegex(ValueError, "accepted version"):
            self.prepare()

    def test_unsupported_profile_even_with_new_receipt_refused(self):
        (self.install / "profile.json").write_text('{"format": "anything"}')
        self.receipt()
        with self.assertRaisesRegex(ValueError, "format"):
            self.prepare()

    def test_modified_preset_dependency_refused(self):
        original = PILOT.sha
        def tampered(path):
            return "0" * 64 if Path(path).name == "rule_baseline.py" else original(path)
        with patch.object(PILOT, "sha", side_effect=tampered):
            with self.assertRaisesRegex(ValueError, "dependency changed"):
                self.prepare()

    def test_platform_failure_does_not_create_selection(self):
        with patch.object(PILOT.platform, "system", return_value="Windows"):
            with self.assertRaisesRegex(ValueError, "Linux"):
                PILOT.prepare("filesystem", self.install, self.destination, 48001)
        self.assertFalse(self.destination.exists())

    def test_missing_workspace_never_produces_selection(self):
        profile = dict(self.profile, workspace=str(self.root / "absent"))
        (self.install / "profile.json").write_text(json.dumps(profile))
        self.receipt()
        with self.assertRaises(OSError):
            self.prepare()
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
