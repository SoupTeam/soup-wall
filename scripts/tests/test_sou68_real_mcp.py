# SPDX-License-Identifier: Apache-2.0
"""Git runtime identity and archive boundary regressions."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sou68_install_tests", ROOT / "scripts/install-sou68-git-profile.py")
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)
VERIFY_SPEC = importlib.util.spec_from_file_location("sou68_diagnostics_tests", ROOT / "scripts/verify-sou68-real-mcp.py")
VERIFY = importlib.util.module_from_spec(VERIFY_SPEC)
VERIFY_SPEC.loader.exec_module(VERIFY)


class GitProfile(unittest.TestCase):
    def test_original_discovery_lock_and_registry_are_bound(self):
        identity = json.loads((INSTALL.ASSETS / "upstream-identity.json").read_text())
        self.assertEqual(len(identity["python"]["sha256"]), 64)
        for name, digest in identity["files"].items():
            self.assertEqual(INSTALL.sha(INSTALL.ASSETS / name), digest)
        manifest = json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text())
        registry = INSTALL.registry(manifest)
        self.assertEqual(len(registry["tools"]), 12)
        original = {tool["name"]: tool for tool in manifest["result"]["tools"]}
        for tool in registry["tools"]:
            self.assertEqual(tool["schema_sha256"], hashlib.sha256(INSTALL.filesystem.canonical(original[tool["name"]]["inputSchema"])).hexdigest())
            self.assertEqual(tool.get("mcp_result_profile") == INSTALL.FORMAT, tool["name"] in INSTALL.READS)
            self.assertEqual(tool["egress"], [])
            self.assertEqual(tool["result_provenance"], "untrusted")

    def test_archive_refuses_escape_special_files_and_external_links(self):
        for name, kind, target in [("../escape", tarfile.REGTYPE, ""), ("/python/escape", tarfile.REGTYPE, ""),
                                  ("python/socket", tarfile.FIFOTYPE, ""), ("python/bin/link", tarfile.SYMTYPE, "/etc/passwd"),
                                  ("python/bin/link", tarfile.SYMTYPE, "../../../escape")]:
            with self.subTest(name=name, target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "runtime.tar.gz"
                with tarfile.open(archive, "w:gz") as bundle:
                    entry = tarfile.TarInfo(name)
                    entry.type, entry.linkname = kind, target
                    bundle.addfile(entry)
                destination = root / "package"
                destination.mkdir()
                with self.assertRaises(ValueError):
                    INSTALL.extract_python(archive, destination)
                self.assertEqual(list(destination.iterdir()), [])

    def test_archive_keeps_original_regular_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "runtime.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                entry = tarfile.TarInfo("python/bin/python3.11")
                entry.size = 4
                bundle.addfile(entry, io.BytesIO(b"ELF!"))
            destination = root / "package"
            destination.mkdir()
            INSTALL.extract_python(archive, destination)
            self.assertEqual((destination / "python/bin/python3.11").read_bytes(), b"ELF!")

    def test_missing_linux_never_installs_or_passes(self):
        with patch.object(INSTALL.platform, "system", return_value="Windows"), patch.object(INSTALL.urllib.request, "urlopen") as download:
            with self.assertRaisesRegex(ValueError, "no isolation fallback"):
                INSTALL.install(Path("unused"), Path("unused"), Path("unused"), "a" * 64, Path("unused"), Path("unused"))
            download.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux", "independent inotify witness requires Linux")
    def test_repository_witness_calibrates_actual_open_and_empty_interval(self):
        spec = importlib.util.spec_from_file_location("sou68_witness_tests", ROOT / "scripts/verify-sou68-real-mcp.py")
        verify = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verify)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "index"
            target.write_bytes(b"synthetic index")
            witness = verify.RepositoryWitness(root)
            try:
                self.assertEqual(witness.drain(), 0)
                descriptor = os.open(target, os.O_RDONLY)
                os.close(descriptor)
                self.assertGreater(witness.drain(), 0)
                self.assertEqual(witness.drain(), 0)
            finally:
                witness.close()


class ProtectedDiagnostics(unittest.TestCase):
    def test_owner_first_failure_and_wrapper_status_survive_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "collector.log").write_text("\n".join([
                json.dumps({"event": "mcp_real_stderr", "received_bytes": 3113,
                            "sha256": "a" * 64, "markers": ["exception_group", "request_already_responded"],
                            "complete": True, "released": False, "origin": "untrusted_server_stderr"}),
                json.dumps({"event": "mcp_real_owner_end", "cleanup_verified": True, "observed_failure": True,
                            "owner": {"reason": "mcp_owner_sandbox_failed", "secret": "never publish",
                                      "sandbox_exit": {"code": 1, "signal": None, "before_quiesce": True}}}),
                "Error: mcp_owner_sandbox_failed"]))
            summary = VERIFY.protected_diagnostics({}, root)
            self.assertEqual(summary["unknown_terminal_rows"], 0)
            self.assertEqual(summary["terminal_codes"], ["mcp_owner_sandbox_failed"])
            self.assertEqual(summary["events"][0]["markers"], ["exception_group", "request_already_responded"])
            self.assertEqual(summary["events"][0]["sha256"], "a" * 64)
            owner = summary["events"][1]
            self.assertEqual(owner["owner_failure_code"], "mcp_owner_sandbox_failed")
            self.assertEqual(owner["sandbox_exit"], {"code": 1, "signal": None, "before_quiesce": True})
            self.assertNotIn("never publish", json.dumps(summary))

    def test_malformed_exit_and_untrusted_markers_never_leave_summary(self):
        valid = {"code": 1, "signal": None, "before_quiesce": True}
        mutations = [{"code": True}, {"code": 256}, {"code": -1}, {"code": "private"},
                     {"signal": 9}, {"code": None}, {"before_quiesce": 1}, {"path": "private"},
                     {"code": None, "signal": 0}, {"code": None, "signal": 65}]
        for change in mutations:
            self.assertIsNone(VERIFY.safe_sandbox_exit(dict(valid, **change)))
        self.assertEqual(VERIFY.safe_sandbox_exit({"code": None, "signal": 9, "before_quiesce": False}),
                         {"code": None, "signal": 9, "before_quiesce": False})
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for markers in (["private"], [False], [["private"]], ["runtime_error"] * (len(VERIFY.STDERR_MARKERS) + 1), "private"):
                (root / "collector.log").write_text(json.dumps({"event": "mcp_real_stderr", "markers": markers,
                    "sha256": "PRIVATE" * 11, "origin": "private", "complete": "private",
                    "owner": {"reason": ["private"], "sandbox_exit": dict(valid, path="private")}}))
                event = VERIFY.protected_diagnostics({}, root)["events"][0]
                self.assertEqual(event, {"event": "mcp_real_stderr"})

    def test_correlates_bounded_numeric_ids_and_static_lifecycle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "collector.log").write_text("\n".join([
                json.dumps({"event": "mcp_real_server_start", "sandbox_pid": 123}),
                json.dumps({"event": "mcp_real_call", "host_call_id": 115, "active": 8, "state": "queued"}),
                json.dumps({"event": "mcp_real_server_end", "cleanup_verified": True, "transport_complete": False}),
                "Error: selected MCP server closed with incomplete state"]))
            report = {"protected_client": {"sent": [json.dumps({"id": value}) for value in range(20)],
                      "received": [json.dumps({"id": 9})], "exit_code": 1, "forced_cleanup": True},
                      "reads": [{}, {}], "refusals": [{}], "sandbox_positive": True}
            summary = VERIFY.protected_diagnostics(report, root)
            self.assertEqual(summary["last_sent_ids"], list(range(12, 20)))
            self.assertEqual(summary["last_received_ids"], [9])
            self.assertEqual((summary["reads_completed"], summary["refusals_completed"]), (2, 1))
            self.assertEqual(summary["terminal_codes"], ["server_closed_incomplete"])
            self.assertTrue(summary["server_started"] and summary["server_ended"] and summary["forced_cleanup"])
            self.assertEqual(summary["events"][1], {"event": "mcp_real_call", "host_call_id": 115, "active": 8, "state_queued": True})
            self.assertEqual(summary["exit_code"], 1)

    def test_never_releases_payloads_arbitrary_errors_or_unsafe_ids(self):
        marker = "synthetic-private-payload"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "collector.log").write_text("\n".join([
                json.dumps({"event": "mcp_real_call", "source": marker, "error": marker,
                            "state": marker, "host_call_id": marker, "active": True, "path": marker}),
                json.dumps({"event": marker, "sandbox_pid": 123}),
                json.dumps({"event": [], "source": marker}),
                "Error: MCP control request timed out " + marker,
                "Error: " + marker,
                "Error: MCP control request timed out"]))
            frames = [json.dumps({"id": value, "result": marker}) for value in
                      (True, 1.5, -1, 9007199254740992, marker, 17)]
            frames.extend(["malformed " + marker, "[]", "null"])
            summary = VERIFY.protected_diagnostics({"protected_client": {"sent": frames, "exit_code": marker}}, root)
            self.assertNotIn(marker, json.dumps(summary))
            self.assertEqual(summary["last_sent_ids"], [17])
            self.assertEqual(summary["terminal_codes"], ["control_timeout"])
            self.assertEqual(summary["unknown_terminal_rows"], 2)
            self.assertEqual(summary["events"], [{"event": "mcp_real_call"}])
            self.assertNotIn("exit_code", summary)

    def test_log_bytes_rows_events_and_line_sizes_are_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertFalse(VERIFY.protected_diagnostics({}, root)["collector_log_available"])
            log = root / "collector.log"
            log.write_bytes(b"x" * (VERIFY.DIAGNOSTIC_LOG_BYTES + 1))
            summary = VERIFY.protected_diagnostics({}, root)
            self.assertTrue(summary["log_input_limited"])
            self.assertEqual(summary["events"], [])
            log.write_bytes(b"x" * (VERIFY.DIAGNOSTIC_ROW_BYTES + 1) + b"\n" + b"{}\n" * VERIFY.DIAGNOSTIC_LOG_ROWS)
            summary = VERIFY.protected_diagnostics({}, root)
            self.assertEqual(summary["oversized_rows"], 1)
            self.assertTrue(summary["log_row_limit"])
            log.write_text("\n".join(json.dumps({"event": "mcp_real_call", "host_call_id": value}) for value in range(40)))
            summary = VERIFY.protected_diagnostics({}, root)
            self.assertEqual(len(summary["events"]), 16)
            self.assertEqual(summary["events"][0]["host_call_id"], 24)


if __name__ == "__main__":
    unittest.main()
