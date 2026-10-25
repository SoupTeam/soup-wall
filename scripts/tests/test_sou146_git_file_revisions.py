# SPDX-License-Identifier: Apache-2.0
"""Independent original-schema and per-file grammar boundary regressions."""
import importlib.util
import json
import itertools
import subprocess
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
INSTALL = load("sou146_install", "scripts/install-sou68-git-profile.py")
CLASSIFIER = load("sou146_classifier", "rule_baseline/git_readonly_file_revisions_v1/rule_baseline.py")
LEGACY = load("sou146_legacy", "rule_baseline/git_readonly_v1/rule_baseline.py")
VERIFY = load("sou146_verify", "scripts/verify-sou146-git-file-revisions.py")

class PerFileRevisions(unittest.TestCase):
    def test_separate_identity_original_manifest_schema_and_default(self):
        manifest = json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text())
        legacy = INSTALL.registry(manifest)
        selected = INSTALL.registry(manifest, file_revisions=True)
        self.assertEqual(selected["registry_id"], "git-readonly-file-revisions-v1")
        self.assertEqual(legacy["registry_id"], "git-readonly-v1")
        for old, new in zip(legacy["tools"], selected["tools"]):
            if old["name"] in INSTALL.READS:
                self.assertEqual(new["mcp_result_profile"], INSTALL.FILE_READS_FORMAT)
                new["mcp_result_profile"] = INSTALL.FORMAT
            self.assertEqual(old, new)

    def test_classifier_selects_only_exact_upstream_schema_and_file_grammar(self):
        tools = json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text())["result"]["tools"]
        schema = next(t["inputSchema"] for t in tools if t["name"] == "git_show")
        for value in ("HEAD:notes.txt", "HEAD:docs/機能 notes.txt", "a" * 40 + ":café.txt"):
            event = {"tool_schema": schema, "pinned_schema": schema}
            args = {"repo_path": "/workspace", "revision": value}
            self.assertIs(CLASSIFIER._bounded_git_read("git_show", args, event), True)
            self.assertIs(LEGACY._bounded_git_read("git_show", args, event), False)
            self.assertIs(CLASSIFIER._bounded_git_read("git_show", args, {"tool_schema": {}}), False)
        for value in VERIFY.INVALID:
            self.assertFalse(CLASSIFIER._file_revision(value), repr(value))

    def test_file_capability_does_not_extend_diff_or_named_references(self):
        tools = json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text())["result"]["tools"]
        schema = next(t["inputSchema"] for t in tools if t["name"] == "git_diff")
        for value in ("HEAD:notes.txt", "refs/heads/main", "refs/heads/main:notes.txt"):
            self.assertIs(CLASSIFIER._bounded_git_read("git_diff", {"repo_path": "/workspace", "target": value}, {"tool_schema": schema}), False)

    def test_combined_registry_capabilities_refuse_before_any_installation(self):
        manifest = json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text())
        names = ("local_references", "file_revisions", "shallow_repository")
        for count in (2, 3):
            for selected in itertools.combinations(names, count):
                options = dict.fromkeys(selected, True)
                with self.subTest(selected=selected):
                    with self.assertRaisesRegex(ValueError, "not qualified"):
                        INSTALL.registry(manifest, **options)
                    with self.assertRaisesRegex(ValueError, "not qualified"):
                        INSTALL.install(Path("unused"), Path("unused"), Path("unused"), "a" * 64,
                                        Path("unused"), Path("unused"), **options)

    def test_cli_refuses_every_combined_selector_before_installation(self):
        flags = ("--local-references", "--file-revisions", "--shallow-repository")
        required = [value for name in ("destination", "workspace", "git", "bwrap", "git-launcher")
                    for value in ("--" + name, "/unused")]
        required += ["--git-sha256", "a" * 64]
        for count in (2, 3):
            for selected in itertools.combinations(flags, count):
                with self.subTest(selected=selected):
                    result = subprocess.run([sys.executable, str(ROOT / "scripts/install-sou68-git-profile.py"),
                                             "--run", *required, *selected], capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("not allowed with argument", result.stderr)
