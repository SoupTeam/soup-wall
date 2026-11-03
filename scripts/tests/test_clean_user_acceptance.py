# SPDX-License-Identifier: Apache-2.0
"""The new workload must not grade missing/error/partial original replies as useful."""
import importlib.util
import json
import subprocess
import sys
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


class PrivateArguments(unittest.TestCase):
    def probe(self, root, hold=False):
        path = root / "probe.py"
        path.write_text("import importlib.util,json,os,sys\n"
            + "s=importlib.util.spec_from_file_location('entry'," + repr(str(SCRIPT)) + ");m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n"
            + "fd=int(sys.argv[2]);value=m.transferred_arguments(fd)\n"
            + "try: os.fstat(fd);closed=False\nexcept OSError: closed=True\n"
            + "print(json.dumps({'original':value,'visible':sys.argv[1:],'descriptor_closed':closed}),flush=True)\n"
            + ("sys.stdin.readline()\n" if hold else ""))
        return path

    def command(self, probe, arguments):
        program = ("import importlib.util;"
            + "s=importlib.util.spec_from_file_location('entry'," + repr(str(SCRIPT)) + ");"
            + "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
            + "m.replace_process(" + repr(arguments) + "," + repr(str(probe)) + ")")
        return [sys.executable, "-I", "-B", "-S", "-c", program]

    def test_exec_preserves_all_inputs_and_closes_private_descriptor(self):
        arguments = ["--agentfw", "/owned/selected runtime/agentfw", "--claude", "/owned/host", "unicode-ұ"]
        with tempfile.TemporaryDirectory() as directory:
            value = json.loads(subprocess.check_output(self.command(self.probe(Path(directory)), arguments)))
        self.assertEqual(value["original"], arguments)
        self.assertTrue(value["descriptor_closed"])
        self.assertEqual(value["visible"][0], "--arguments-fd")
        self.assertTrue(set(arguments).isdisjoint(value["visible"]))

    @unittest.skipUnless(sys.platform == "linux", "real accepted guard requires Linux /proc")
    def test_unchanged_inactivity_guard_still_refuses_selected_argv_but_accepts_exec_handoff(self):
        guard = m.load(SCRIPT.parents[1], "clean_user_process_guard", "switch-prepared-pilot.py")
        summary = {"agent_path": "/owned/selected-agent", "claude_path": "/owned/selected-host"}
        with tempfile.TemporaryDirectory() as directory:
            arguments = ["--agentfw", summary["agent_path"], "--claude", summary["claude_path"]]
            process = subprocess.Popen(self.command(self.probe(Path(directory), hold=True), arguments),
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            try:
                self.assertEqual(json.loads(process.stdout.readline())["original"], arguments)
                guard.require_inactive(summary)
                busy = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)", summary["agent_path"]])
                try:
                    with self.assertRaisesRegex(ValueError, "active_or_uncertain_pilot_run"):
                        guard.require_inactive(summary)
                finally:
                    busy.terminate(); busy.wait(timeout=5)
            finally:
                process.communicate("done\n", timeout=5)
            self.assertEqual(process.returncode, 0)


class ProcessProvenance(unittest.TestCase):
    def process(self, root, pid, parent, start, comm, uids):
        path = root / str(pid); path.mkdir()
        fields = ["S", str(parent)] + ["0"] * 17 + [str(start)]
        (path / "stat").write_text(f"{pid} ({comm}) " + " ".join(fields))
        (path / "comm").write_text(comm + "\n")
        (path / "status").write_text("Uid:\t" + "\t".join(map(str, uids)) + "\nCapEff:\t0000000000000000\n")
        (path / "cmdline").write_bytes(b"private-argument-canary\0")
        (path / "environ").write_bytes(b"PRIVATE=private-environment-canary\0")
        return path

    def fixture(self, root, comm="(sd-pam)"):
        path = self.process(root, 123, 1, 100, comm, (1001, 0, 0, 0))
        self.process(root, 1, 0, 1, "systemd", (0, 0, 0, 0))
        driver = root / "self"; driver.mkdir()
        (driver / "stat").write_text("456 (python3) " + " ".join(["R", "123"] + ["0"] * 17 + ["300"]))
        return path

    def test_real_uid_is_not_assumed_effective_and_diagnostic_never_authorizes(self):
        with tempfile.TemporaryDirectory() as directory:
            value = m.process_provenance(self.fixture(Path(directory)))
        self.assertFalse(value["authorization"])
        self.assertTrue(value["predates_driver"])
        self.assertEqual(value["ancestry"][0]["role"], "(sd-pam)")
        self.assertEqual(value["ancestry"][0]["uids"], dict(real=1001, effective=0, saved=0, filesystem=0))
        self.assertEqual(value["ancestry"][1]["role"], "systemd")
        encoded = json.dumps(value)
        self.assertNotIn("private-argument-canary", encoded)
        self.assertNotIn("private-environment-canary", encoded)
        self.assertNotIn("pid", value["ancestry"][0])

    def test_unknown_names_are_hashed_and_missing_credentials_cannot_be_complete_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.fixture(Path(directory), comm="private-name-canary")
            value = m.process_provenance(path)
            self.assertEqual(value["ancestry"][0]["role"], "other")
            self.assertNotIn("private-name-canary", json.dumps(value))
            (path / "status").write_text("Uid:\t1001\t1001\t1001\nCapEff:\t0\n")
            with self.assertRaisesRegex(ValueError, "process_provenance_uid"):
                m.process_provenance(path)
