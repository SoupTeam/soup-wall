"""SOU-83 separate profile selection never mutates the default readonly profile."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "scripts/install-sou83-filesystem-create-profile.py"
SPEC = importlib.util.spec_from_file_location("sou83_install", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OriginalCreateProfileTests(unittest.TestCase):
    def originals(self):
        manifest = json.loads((MODULE.readonly.ASSETS / "upstream-tools-list.json").read_text(encoding="utf-8"))
        profile = {"format": MODULE.READONLY_FORMAT, "workspace": "/tmp/private"}
        registry = MODULE.readonly.registry(manifest)
        policy = (MODULE.readonly.ASSETS / "policy.yaml").read_text(encoding="utf-8")
        return profile, registry, policy

    def test_only_one_selected_original_mutation_and_readonly_identity_unchanged(self):
        profile, registry, policy = self.originals()
        before = json.dumps([profile, registry, policy], sort_keys=True)
        selected_profile, selected_registry, selected_policy = MODULE.select_documents(profile, registry, policy)
        self.assertEqual(selected_profile["format"], MODULE.FORMAT)
        self.assertEqual(selected_registry["registry_id"], MODULE.REGISTRY_ID)
        self.assertNotIn(MODULE.DENY_WRITE, selected_policy)
        self.assertIn("filesystem-profile-deny-destructive", selected_policy)
        self.assertIn("filesystem-profile-deny-network", selected_policy)
        self.assertIn("filesystem-profile-refuse-result-injection", selected_policy)
        for tool in selected_registry["tools"]:
            if tool["name"] == "write_file":
                self.assertEqual(tool["mcp_result_profile"], MODULE.FORMAT)
                self.assertEqual(tool["action_class"], "side_effecting")
            elif tool["name"] in {*MODULE.readonly.MUTATORS, "read_media_file"}:
                self.assertNotIn("mcp_result_profile", tool)
            else:
                self.assertEqual(tool["mcp_result_profile"], MODULE.FORMAT)
                self.assertEqual(tool["action_class"], "read_only")
            self.assertEqual(tool["egress"], [])
        self.assertEqual(json.dumps([profile, registry, policy], sort_keys=True), before)

    def test_drift_or_broader_authority_is_refused(self):
        for change in ["missing_tool", "extra_egress", "wrong_schema", "selected_edit", "wrong_policy"]:
            profile, registry, policy = self.originals()
            if change == "missing_tool":
                registry["tools"].pop()
            if change == "extra_egress":
                registry["tools"][0]["egress"] = ["https://example.invalid"]
            if change == "wrong_schema":
                registry["tools"][0]["schema_sha256"] = "0"*64
            if change == "selected_edit":
                next(t for t in registry["tools"] if t["name"] == "edit_file")["mcp_result_profile"] = MODULE.READONLY_FORMAT
            if change == "wrong_policy":
                policy = policy.replace(MODULE.DENY_WRITE, "")
            with self.subTest(change=change), self.assertRaises(ValueError):
                MODULE.select_documents(profile, registry, policy)


if __name__ == "__main__":
    unittest.main()
