# SPDX-License-Identifier: Apache-2.0
"""Shallow profile selection, upstream schema identity and owned fixture checks."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
INSTALL=load("sou147_installer","scripts/install-sou68-git-profile.py")
VERIFY=load("sou147_driver","scripts/verify-sou147-shallow-git.py")

class ShallowProfile(unittest.TestCase):
    def test_separately_selected_identity_keeps_original_upstream_schemas(self):
        manifest=json.loads((INSTALL.ASSETS/"upstream-tools-list.json").read_text())
        default=INSTALL.registry(manifest);selected=INSTALL.registry(manifest,shallow_repository=True)
        self.assertEqual(default["registry_id"],"git-readonly-v1")
        self.assertEqual(selected["registry_id"],"git-readonly-shallow-v1")
        for a,b in zip(default["tools"],selected["tools"]):
            if a["name"] in INSTALL.READS:
                self.assertEqual(b["mcp_result_profile"],INSTALL.SHALLOW_FORMAT)
                b["mcp_result_profile"]=INSTALL.FORMAT
            self.assertEqual(a,b)

    def test_owned_fixture_is_shallow_local_and_missing_the_original_parent(self):
        git=shutil.which("git")
        self.assertIsNotNone(git,"local Git is a required test prerequisite")
        with tempfile.TemporaryDirectory(prefix="sou147-fixture-test-") as temporary:
            root=Path(temporary);workspace=root/"workspace"
            env=dict(os.environ,GIT_CONFIG_GLOBAL="/dev/null",GIT_CONFIG_NOSYSTEM="1",GIT_TERMINAL_PROMPT="0")
            first,second,poison=VERIFY.prepare_repo(workspace,Path(git),env)
            self.assertEqual((workspace/".git/shallow").read_text(),second+"\n")
            self.assertNotEqual(first,second)
            self.assertEqual(len(poison),40)
            self.assertTrue(any((workspace/".git/objects/pack").glob("*.pack")))
            self.assertFalse((workspace/".git/refs/remotes").exists())
            self.assertNotIn("[remote",(workspace/".git/config").read_text())
