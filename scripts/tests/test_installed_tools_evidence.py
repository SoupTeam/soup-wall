# SPDX-License-Identifier: Apache-2.0
"""Retention controls for installed-tool qualification reports."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InstalledToolsEvidence(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "output"
        self.output.mkdir()
        self.args = SimpleNamespace(output=self.output, agentfw=Path("/owned/agentfw"),
                                    expected_commit="a" * 40, strace=Path("/usr/bin/strace"))
        self.report = {"source_before": {"commit": "a" * 40, "tree": "b" * 40, "dirty": False},
                       "pilot_scope": {"demo_selection": "/owned/selection.json"}}
        self.qualifier = load("installed_tools_evidence_control", "qualify-installed-tools.py")
        self.engine = load("installed_tools_report_control", "roadmap_support.py")
        self.demo_status = "passed"

    def call(self, words, **kwargs):
        if words[4] == "demo":
            executed = "--run" in words
            report = {"status": self.demo_status if executed else "plan", "executed": executed,
                      "fixture_cleanup": {"complete": True}}
            if report["executed"]:
                output = Path(words[words.index("--output") + 1])
                output.mkdir()
                (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            return subprocess.CompletedProcess(words, int(executed and self.demo_status != "passed"),
                                               json.dumps(report).encode(), b"")
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()):
            code = self.engine.main(words[5:], installed=True)
        return subprocess.CompletedProcess(words, code, stdout.getvalue().encode(), b"")

    def qualify(self):
        with patch.object(self.qualifier.subprocess, "run", side_effect=self.call):
            self.qualifier.qualify(self.args, SimpleNamespace(cwd=self.root), self.root, {}, self.report,
                                   load=load, require=lambda ok, code: self.assertTrue(ok, code))

    def test_saved_reports_are_bounded_hash_references_in_the_native_artifact(self):
        self.qualify()
        evidence = self.report["installed_tools"]
        self.assertEqual(evidence["status"], "passed")
        expected = {"installed-tools/demo/report.json", "installed-tools/support/report.json",
                    "installed-tools/support/index.html"}
        self.assertEqual({row["path"] for row in evidence["reports"]}, expected)
        for row in evidence["reports"]:
            raw = (self.output / row["path"]).read_bytes()
            self.assertEqual(row["bytes"], len(raw))
            self.assertEqual(row["sha256"], hashlib.sha256(raw).hexdigest())
        for workflow in ("mcp-real-filesystem.yml", "ci-components.yml"):
            text = (ROOT / ".github/workflows" / workflow).read_text()
            for path in expected:
                self.assertIn("${{ runner.temp }}/sou215-pilot-scope/" + path, text)

    def test_candidate_lane_retains_complete_installed_tool_reports(self):
        text = (ROOT / ".github/workflows/mcp-real-filesystem.yml").read_text()
        with patch.object(sys, "path", [str(ROOT / "scripts"), *sys.path]):
            parser = load("installed_tools_workflow_parser", "ci_components.py")
        candidate = parser.blocks(text)["manual-linux-candidate"]
        for name in ("demo/report.json", "support/report.json", "support/index.html"):
            self.assertIn("${{ runner.temp }}/linux-candidate/installed/installed-tools/" + name,
                          candidate)

    def test_failed_demo_report_is_preserved_and_bound_before_failure(self):
        self.demo_status = "failed"
        with self.assertRaisesRegex(AssertionError, "installed_demo_failed"):
            self.qualify()
        evidence = self.report["installed_tools"]
        self.assertEqual(evidence["status"], "incomplete")
        self.assertEqual(len(evidence["reports"]), 1)
        row = evidence["reports"][0]
        raw = (self.output / row["path"]).read_bytes()
        self.assertEqual(json.loads(raw)["status"], "failed")
        self.assertEqual(row["sha256"], hashlib.sha256(raw).hexdigest())
