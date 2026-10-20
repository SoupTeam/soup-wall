# SPDX-License-Identifier: Apache-2.0
"""Dependency-free profile/identity regressions; real runtime is an explicit CLI mode."""
import copy
import json
from types import SimpleNamespace
import unittest

import agentdojo_live as adapter
import agentdojo_native as native
import agentdojo_workspace as workspace


class WorkspaceProfileTests(unittest.TestCase):
    def setUp(self):
        self.profile, self.hash = workspace.snapshot()
        self.functions = [SimpleNamespace(name=r["name"], parameters=SimpleNamespace(
            model_json_schema=lambda s=r["schema"]: copy.deepcopy(s))) for r in self.profile["tools"]]

    def test_exact_inventory_and_semantics(self):
        self.assertEqual(len(self.functions), 24)
        registry = native.Registry(workspace.registry_bytes(self.functions))
        for function in self.functions:
            registry.schema(function)
        rows = {r["name"]: r for r in self.profile["tools"]}
        self.assertEqual(rows["get_unread_emails"]["action_class"], "side_effecting")
        self.assertTrue(all(r["result_provenance"] == "untrusted" for r in rows.values()))
        self.assertEqual([r["pointer"] for r in rows["send_email"]["egress"]], ["/recipients","/cc","/bcc"])
        self.assertEqual(sum(not r["supported"] for r in rows.values()), 3)

    def test_schema_and_inventory_drift_refuse(self):
        with self.assertRaises(adapter.AdapterError):
            workspace.registry_bytes(self.functions[:-1])
        self.functions[0].parameters.model_json_schema = lambda: {"type":"object"}
        with self.assertRaises(adapter.AdapterError):
            workspace.registry_bytes(self.functions)

    def test_misdeclared_authority_and_unknown_profile_refuse(self):
        data = json.loads(workspace.registry_bytes(self.functions))
        for field, value in [("result_provenance","local_system"),("action_class","read_only"),
                             ("schema_sha256","0"*64),("egress",[]),("workspace_profile","unreviewed/1")]:
            changed = copy.deepcopy(data)
            changed["tools"][0][field] = value
            with self.subTest(field=field), self.assertRaises(adapter.AdapterError):
                native.Registry(adapter.encoded(changed))

    def test_schema_one_registry_is_unchanged(self):
        row = {k: v for k, v in workspace.declaration(self.profile["tools"][0]).items()
               if k != "workspace_profile"}
        native.Registry(adapter.encoded({"contract_version":"sw-native/1","registry_id":"legacy","tools":[row]}))


if __name__ == "__main__":
    unittest.main()
