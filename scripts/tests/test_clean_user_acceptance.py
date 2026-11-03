# SPDX-License-Identifier: Apache-2.0
"""The new workload must not grade missing/error/partial original replies as useful."""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "pilot_clean_user_acceptance.py"
spec = importlib.util.spec_from_file_location("clean_user_workload_tests", SCRIPT)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class UtilityEvidence(unittest.TestCase):
    def row(self):
        return dict(exit=0, status="completed", live_status={"protection": "observed-live"},
                    process_cleanup={"all_stopped": True})

    def decode(self, value, kind):
        return value["text"]

    def test_exact_file_bytes_and_complete_history_have_independent_expectations(self):
        expected = {"text": "The exact owned contract.\n"}
        result = dict(is_error=False, text=expected["text"])
        m.verify_utility(self.row(), result, expected, "filesystem", self.decode)
        for text in ("The exact owned contract.", "prefix\n"+expected["text"], "wrong\n"):
            with self.assertRaisesRegex(ValueError, "exact_bytes"):
                m.verify_utility(self.row(), dict(is_error=False, text=text), expected, "filesystem", self.decode)
        expected = {"parts": ["a"*40, "b"*40, "Changed retention", "Create owned ledger"]}
        m.verify_utility(self.row(), dict(is_error=False, text="\n".join(expected["parts"])), expected, "git", self.decode)
        with self.assertRaisesRegex(ValueError, "history_or_diff"):
            m.verify_utility(self.row(), dict(is_error=False, text="\n".join(expected["parts"][:-1])),
                             expected, "git", self.decode)

    def test_exit_success_does_not_hide_original_error_missing_result_or_unconfirmed_cleanup(self):
        expected = {"text": "owned\n"}
        for value in (None, dict(is_error=True, text=expected["text"])):
            with self.assertRaisesRegex(ValueError, "original_error"):
                m.verify_utility(self.row(), value, expected, "filesystem", self.decode)
        for field, altered in (("exit", 1), ("live_status", {}), ("process_cleanup", {"all_stopped":False})):
            row = self.row(); row[field] = altered
            with self.assertRaises(ValueError):
                m.verify_utility(row, dict(is_error=False, text=expected["text"]), expected, "filesystem", self.decode)

    def test_runtime_source_refuses_another_commit_or_dirty_checkout_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            def git(*words):
                return subprocess.check_output(["git", "-C", str(root), *words], stderr=subprocess.DEVNULL).decode().strip()
            git("init", "-q")
            (root/"input").write_text("owned\n")
            git("add", ".")
            git("-c", "user.name=Owned", "-c", "user.email=owned@example.invalid", "commit", "-qm", "Owned")
            head = git("rev-parse", "HEAD")
            self.assertEqual(m.source(root, head)["commit"], head)
            with self.assertRaisesRegex(ValueError, "commit_mismatch"): m.source(root, "0"*40)
            (root/"input").write_text("changed\n")
            with self.assertRaisesRegex(ValueError, "not_clean"): m.source(root, head)

    def test_new_project_inputs_and_expectations_are_frozen_separately_from_old_fixtures(self):
        self.assertEqual(set(m.PROJECTS), {"catalog-service", "release-ledger"})
        self.assertEqual(len(m.TASKS), 4)
        before = m.digest(m.PROJECTS)
        for project in m.PROJECTS.values():
            self.assertIn(project["read"], project["files"])
            self.assertIn(project["change"], project["files"])
        self.assertEqual(m.digest(m.PROJECTS), before)


class DispatchCapture(unittest.TestCase):
    def test_long_installed_collector_argument_needs_complete_capture(self):
        witness = m.load(SCRIPT.parents[1], "clean_user_dispatch_test", "qualify-pilot-launcher.py")
        binary = Path("/owned/agentfw")
        rows = []
        for pid, server in ((101, "filesystem"), (102, "git")):
            # Real installed paths and MCP configuration can exceed a small
            # diagnostic string cap. Never grade an abbreviated exec/write.
            argv = [str(binary), "mcp", "--id", server, "--owned-configuration", "x" * 4096]
            rows.append(f'{pid} execve("{binary}", {json.dumps(argv)}, 0x0) = 0')
            frame = json.dumps({"jsonrpc": "2.0", "id": pid, "method": "tools/list"}) + "\n"
            rows.append(f'{pid} write(9, {json.dumps(frame)}, {len(frame)}) = {len(frame)}')
        observed = witness.collector_dispatches("\n".join(rows), binary, strict=False)
        self.assertEqual(observed["discoveries"], 2)
        incomplete = rows.copy()
        incomplete[0] = incomplete[0].replace(json.dumps("x" * 4096), '"xxx"...')
        with self.assertRaises((ValueError, SyntaxError)):
            witness.collector_dispatches("\n".join(incomplete), binary, strict=False)
