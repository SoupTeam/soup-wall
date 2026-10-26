# SPDX-License-Identifier: Apache-2.0
"""Synthetic local Linux controls. These do not establish native pilot acceptance."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_run_state as S


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ARCHIVE = load("run_archive_test", "pilot-run-archive.py")
DISCOVERY = load("run_discovery_test", "pilot-runs.py") if sys.platform.startswith("linux") else None


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux descriptor and retention controls")
class RunOperations(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pilot-run-controls-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.state = self.root / "state"
        self.output = self.root / "archives"
        self.state.mkdir(mode=0o700)
        self.output.mkdir(mode=0o700)
        self.marker = "PRIVATE_SECRET_PROMPT_RESULT_NEVER_PUBLIC"
        self.run, self.receipt = self.completed("one")
        self.unrelated = self.state / "unrelated.txt"
        self.unrelated.write_text(self.marker)

    def write(self, path, value):
        body = value if type(value) is bytes else S.encoded(value)
        path.write_bytes(body)
        path.chmod(0o600)

    def completed(self, identity):
        run = self.state / ("soup-wall-run-" + identity)
        run.mkdir(mode=0o700)
        _, receipt = S.AUDIT.selection(run, "a" * 40, *("b" * 64 for _ in range(4)))
        self.write(run / "audit-run.json", receipt)
        self.write(run / "audit-finished.json", {"format": S.AUDIT.FORMAT,
                   "run_id": identity, "owned_processes_stopped": True})
        raw = S.encoded({"at_ms": 1760000000000, "event": "native_call", "tool": self.marker,
                         "verdict": "deny", "raw": self.marker}) + b"\n"
        self.write(run / "audit/segment-00000000000000000001.jsonl", raw)
        self.write(run / "audit/writer.lock", b"")
        self.write(run / "audit/manifest.json", {"version": 1,
                   "limits": {k: v for k, v in S.AUDIT.LIMITS.items() if k != "version"},
                   "generation": 1, "next_id": 2, "pruned_through": 0, "pending_prune": None,
                   "segments": [{"id": 1, "closed": False, "bytes": 0, "sha256": None, "partial_tail": False}]})
        return run, receipt

    def snapshot(self, path=None):
        root = path or self.state
        return {str(p.relative_to(root)): (p.lstat().st_mode, p.lstat().st_mtime_ns,
                p.read_bytes() if p.is_file() and not p.is_symlink() else None)
                for p in root.rglob("*")}

    def plan(self, ids=None):
        return ARCHIVE.preview(self.state, ids or ["one"])

    def archive(self, plan=None):
        plan = plan or self.plan()
        rows = ARCHIVE.build_archives(plan, self.output)
        self.assertEqual(rows[0]["outcome"], "archived_source_retained")
        return plan

    def active(self):
        (self.run / "audit-finished.json").unlink()
        home = self.run / ".agentfw"
        home.mkdir(mode=0o700)
        (home / "pilot-runs").mkdir(mode=0o700)
        native = home / "pilot-runs" / ("c" * 32)
        native.mkdir(mode=0o700)
        registry = S.encoded({"contract_version": "sw-native/1", "tools": []})
        self.write(home / "registry.json", registry)
        self.receipt["registry_sha256"] = S.sha(registry)
        self.write(self.run / "audit-run.json", self.receipt)
        manifest = {"contract": "sw-pilot-run/1", "run_id": native.name, "home": str(home),
                    "launcher_pid": 2**30, "launcher_start": 1, "manifest_fd": 3,
                    "registry_sha256": self.receipt["registry_sha256"], "instance_id": "owned-instance",
                    "expires_at_ms": int(time.time() * 1000) + 10000, "files": []}
        self.write(native / "run.json", manifest)
        return home, native, manifest

    def test_preview_and_multirun_listing_have_no_writes_or_process_effects(self):
        self.completed("two")
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.addCleanup(lambda: (process.terminate(), process.wait(timeout=5)))
        before = self.snapshot()
        with patch.object(DISCOVERY, "request", side_effect=AssertionError("default cannot probe")):
            result = DISCOVERY.discover(self.state)
        plan = self.plan(["one", "two"])
        self.assertEqual(len(result["runs"]), 2)
        self.assertTrue(result["complete"])
        self.assertTrue(all(row["lifecycle"] == "completed_audit_only" and row["protection"] == "unknown" for row in result["runs"]))
        self.assertEqual(len(plan["runs"]), 2)
        self.assertEqual(before, self.snapshot())
        self.assertIsNone(process.poll())
        self.assertNotIn(self.marker, json.dumps(result) + json.dumps(plan))

    def test_private_archive_verified_before_exact_removal_and_repeat_is_not_success(self):
        before = self.snapshot()
        plan = self.archive()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(ARCHIVE.build_archives(plan, self.output)[0]["outcome"], "archived_source_retained")
        path = self.output / ARCHIVE.archive_name(plan, plan["runs"][0])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        meta = ARCHIVE.verify_archive(path.read_bytes(), plan, plan["runs"][0])
        self.assertFalse(meta["execution_proven"])
        self.assertEqual(ARCHIVE.apply(plan, self.output)[0]["outcome"], "archived_and_removed")
        self.assertFalse(self.run.exists())
        self.assertEqual(self.unrelated.read_text(), self.marker)
        with self.assertRaises(FileNotFoundError):
            ARCHIVE.apply(plan, self.output)

    def test_active_stop_receipt_and_unknown_member_are_excluded(self):
        home, native, _ = self.active()
        self.write(native / "stop.json", {"contract": "sw-pilot-stop/1", "run_sha256": S.sha((native / "run.json").read_bytes()),
                   "status": "stopped", "signature": "s" * 43})
        before = self.snapshot()
        plan = self.plan()
        self.assertEqual(plan["runs"], [])
        self.assertEqual(plan["excluded"][0]["reason"], "active_or_retained_state")
        found = DISCOVERY.discover(self.state, probing=True)
        self.assertEqual(found["runs"][0]["lifecycle"], "retained_stop_state")
        self.assertNotIn(self.marker, json.dumps(found))
        self.assertEqual(before, self.snapshot())
        other, _ = self.completed("foreign")
        self.write(other / "unrelated.private", self.marker.encode())
        self.assertEqual(self.plan(["foreign"])["runs"], [])

    def test_stale_launcher_is_refused_before_any_network(self):
        home, native, manifest = self.active()
        record = {"format": "sw-prepared-pilot-run/1", "home": str(home), "supervisor_pid": 1,
                  "launcher_pid": manifest["launcher_pid"], "daemon_pid": manifest["launcher_pid"], "port": 12345}
        self.write(self.run / "run.json", record)
        policy = self.root / "policy.yaml"
        self.write(policy, b"agent_policies: []\ndefault: allow\n")
        trusted_binary = self.root / "trusted-agent"
        self.write(trusted_binary, Path(sys.executable).resolve().read_bytes())
        trusted_binary.chmod(0o700)
        binary_sha = S.sha(trusted_binary.read_bytes())
        self.receipt.update(binary_sha256=binary_sha, policy_sha256=S.sha(policy.read_bytes()))
        self.write(self.run / "audit-run.json", self.receipt)
        config = {"bind": "127.0.0.1", "port": 12345, "enforce": True,
            "policy": str(policy), "native": {"registry_sha256": self.receipt["registry_sha256"],
            "registry_path": str(home / "registry.json")}, "audit_retention": {}}
        self.write(home / "config.yaml", config)
        manifest["files"] = [{"path": str(home / "config.yaml"), "sha256": S.sha(S.encoded(config))},
                             {"path": str(policy), "sha256": S.sha(policy.read_bytes())}] + [{}] * 3
        self.write(native / "run.json", manifest)
        before = self.snapshot()
        with patch.object(DISCOVERY, "request", side_effect=AssertionError("stale state cannot query")), \
             patch.object(DISCOVERY, "sealed_launcher", wraps=DISCOVERY.sealed_launcher) as sealed:
            result = DISCOVERY.discover(self.state, probing=True, agentfw=trusted_binary, agentfw_sha256=binary_sha)
        sealed.assert_called_once()
        self.assertFalse(result["complete"])
        self.assertEqual(result["runs"][0]["observation"]["state"], "unavailable")
        self.assertEqual(before, self.snapshot())

    def test_run_receipt_cannot_select_an_executable_or_contact_an_endpoint(self):
        home, _, manifest = self.active()
        self.write(self.run / "run.json", {"format": "sw-prepared-pilot-run/1", "home": str(home),
            "supervisor_pid": 10, "launcher_pid": manifest["launcher_pid"], "daemon_pid": 42, "port": 12345})
        before = self.snapshot()
        with patch.object(DISCOVERY.subprocess, "Popen", side_effect=AssertionError("receipt cannot authorize execution")), \
             patch.object(DISCOVERY, "request", side_effect=AssertionError("unverified state cannot query")):
            result = DISCOVERY.discover(self.state, probing=True)
        self.assertEqual(result["runs"][0]["reason"], "explicit_agent_pin_required")
        self.assertEqual(before, self.snapshot())

    def test_explicit_binary_pin_is_read_only_and_rejects_wrong_digest_or_link(self):
        binary = self.root / "agent"
        self.write(binary, b"owned selected bytes")
        with patch.object(DISCOVERY.subprocess, "Popen", side_effect=AssertionError("pin validation is read-only")):
            self.assertEqual(DISCOVERY.verified_agent(binary, S.sha(binary.read_bytes()), time.monotonic() + 10),
                             S.sha(binary.read_bytes()))
            with self.assertRaises(S.Refusal):
                DISCOVERY.verified_agent(binary, "0" * 64, time.monotonic() + 10)
            link = self.root / "agent-link"
            link.symlink_to(binary)
            with self.assertRaises((OSError, S.Refusal)):
                DISCOVERY.verified_agent(link, S.sha(binary.read_bytes()), time.monotonic() + 10)

    def test_symlink_hardlink_fifo_modes_and_foreign_owner_refuse(self):
        path = self.run / "audit-run.json"
        original = path.read_bytes()
        for kind in ("symlink", "hardlink", "fifo", "mode", "oversized", "foreign-owner"):
            if path.exists() or path.is_symlink():
                path.unlink()
            self.write(path, original)
            extra = self.root / "linked"
            if extra.exists():
                extra.unlink()
            if kind == "symlink":
                path.unlink(); path.symlink_to(self.unrelated)
            elif kind == "hardlink":
                os.link(path, extra)
            elif kind == "fifo":
                path.unlink(); os.mkfifo(path, 0o600)
            elif kind == "mode":
                path.chmod(0o644)
            elif kind == "oversized":
                self.write(path, b" " * 65537)
            if kind == "foreign-owner":
                # Parser fixture only: emulate a different uid without chown privileges.
                with patch.object(S.os, "getuid", return_value=os.getuid() + 1), self.assertRaises(S.Refusal):
                    self.plan()
            else:
                self.assertEqual(self.plan()["runs"], [], kind)
                self.assertFalse(DISCOVERY.discover(self.state)["complete"], kind)
            self.assertEqual(self.unrelated.read_text(), self.marker)

    def test_scan_candidate_limits_and_missing_selection_are_explicit(self):
        self.completed("two")
        result = DISCOVERY.discover(self.state, scan_limit=1)
        self.assertFalse(result["complete"])
        self.assertIn("enumeration_limit", result["reasons"])
        result = DISCOVERY.discover(self.state, candidate_limit=1)
        self.assertIn("candidate_limit", result["reasons"])
        result = DISCOVERY.discover(self.state, selected_ids=["missing"])
        self.assertIn("selected_run_unavailable", result["reasons"])

    def test_changed_plan_corruption_and_failed_archive_write_preserve_source(self):
        plan = self.plan()
        path = self.run / "audit/segment-00000000000000000001.jsonl"
        original_body = path.read_bytes()
        self.write(path, b"changed\n")
        before = self.snapshot()
        with self.assertRaises(S.Refusal):
            ARCHIVE.build_archives(plan, self.output)
        self.assertEqual(before, self.snapshot())
        self.write(path, original_body)
        plan, before = self.plan(), self.snapshot()
        with patch.object(ARCHIVE, "publish", side_effect=OSError("private failure")) as publish, self.assertRaises(OSError):
            ARCHIVE.build_archives(plan, self.output)
        publish.assert_called_once()
        self.assertEqual(before, self.snapshot())
        with self.assertRaises((OSError, S.Refusal)):
            ARCHIVE.apply(plan, self.output)
        self.assertEqual(before, self.snapshot())

    def test_archive_corruption_or_link_replacement_never_removes_source(self):
        plan = self.archive()
        filename = self.output / ARCHIVE.archive_name(plan, plan["runs"][0])
        before = self.snapshot()
        self.write(filename, b"invalid archive")
        with self.assertRaises(S.Refusal):
            ARCHIVE.apply(plan, self.output)
        self.assertEqual(before, self.snapshot())
        filename.unlink()
        filename.symlink_to(self.unrelated)
        with self.assertRaises((OSError, S.Refusal)):
            ARCHIVE.apply(plan, self.output)
        self.assertEqual(before, self.snapshot())

    def test_rename_replacement_and_unexpected_member_refuse_and_keep_unrelated(self):
        plan = self.archive()
        old = self.state / "old-owned"
        self.run.rename(old)
        self.run.symlink_to(old, target_is_directory=True)
        with self.assertRaises(OSError):
            ARCHIVE.apply(plan, self.output)
        self.assertTrue((old / "audit-run.json").exists())
        self.run.unlink(); old.rename(self.run)
        self.write(self.run / "unexpected", self.marker.encode())
        with self.assertRaises(S.Refusal):
            ARCHIVE.apply(plan, self.output)
        self.assertEqual((self.run / "unexpected").read_text(), self.marker)

    def test_interrupted_deletion_reports_partial_and_keeps_verified_archive(self):
        plan = self.archive()
        original = ARCHIVE.os.unlink
        calls = 0
        def fail_after_one(name, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("controlled interruption")
            return original(name, *args, **kwargs)
        with patch.object(ARCHIVE.os, "unlink", side_effect=fail_after_one):
            result = ARCHIVE.apply(plan, self.output)[0]
        self.assertEqual(result["outcome"], "partial")
        self.assertTrue((self.state / result["quarantine"] / "run").is_dir())
        filename = self.output / ARCHIVE.archive_name(plan, plan["runs"][0])
        ARCHIVE.verify_archive(filename.read_bytes(), plan, plan["runs"][0])
        self.assertEqual(self.unrelated.read_text(), self.marker)

    def test_changed_generation_after_detach_is_retained_in_quarantine(self):
        plan = self.archive()
        original = ARCHIVE.rename_exclusive
        def changed(*args):
            original(*args)
            quarantine = next(self.state.glob(".soup-wall-cleanup-*"))
            self.write(quarantine / "run" / "new-activity", self.marker.encode())
        with patch.object(ARCHIVE, "rename_exclusive", side_effect=changed):
            result = ARCHIVE.apply(plan, self.output)[0]
        self.assertEqual(result["outcome"], "partial")
        self.assertEqual((self.state / result["quarantine"] / "run/new-activity").read_text(), self.marker)

    def test_file_replacement_after_last_source_check_is_preserved_before_unlink(self):
        plan = self.archive()
        original = ARCHIVE.validate_remaining
        raced = False
        def replace(run, audit, files, audit_present=True):
            nonlocal raced
            original(run, audit, files, audit_present)
            if not raced and audit is not None:
                raced = True
                first = sorted(key for key in files if key.startswith("audit/"))[0].split("/", 1)[1]
                os.unlink(first, dir_fd=audit.fd)
                fd = os.open(first, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=audit.fd)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(self.marker.encode())
        with patch.object(ARCHIVE, "validate_remaining", side_effect=replace):
            result = ARCHIVE.apply(plan, self.output)[0]
        self.assertEqual(result["outcome"], "partial")
        self.assertIn(result["reason"], ("removal_state_changed", "staged_member_changed"))
        staged = list((self.state / result["quarantine"]).glob("member-*"))
        candidate = self.state / result["quarantine"] / "run/audit/manifest.json"
        if candidate.exists() and candidate.read_text() == self.marker:
            staged.append(candidate)
        self.assertEqual(len(staged), 1)
        self.assertEqual(staged[0].read_text(), self.marker)

    def test_plan_cannot_archive_closed_corruption_or_partial_manifest(self):
        manifest_path = self.run / "audit/manifest.json"
        manifest = S.strict(manifest_path.read_bytes())
        manifest["segments"][0].update(closed=True, bytes=4, sha256="0" * 64)
        self.write(manifest_path, manifest)
        self.assertEqual(self.plan()["runs"], [])
        manifest["segments"][0].update(closed=False, bytes=0, sha256=None)
        manifest["pending_prune"] = 1
        self.write(manifest_path, manifest)
        self.assertEqual(self.plan()["runs"], [])

    def test_duplicate_json_deep_records_and_canonical_parent_links_refuse(self):
        self.write(self.run / "audit-run.json", b'{"run_id":"one","run_id":"other"}')
        self.assertEqual(self.plan()["runs"], [])
        self.write(self.run / "audit-run.json", b'[' * 100 + b']' * 100)
        self.assertEqual(self.plan()["runs"], [])
        link = self.root / "linked-state"
        link.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            ARCHIVE.preview(link, ["one"])

    def test_cli_preview_archive_apply_and_failure_outputs_are_private(self):
        def command(filename, args):
            value = subprocess.run([sys.executable, "-B", str(ROOT / "scripts" / filename), *args],
                                   capture_output=True, timeout=10)
            self.assertFalse(value.stderr, value.stderr.decode(errors="replace"))
            self.assertNotIn(self.marker.encode(), value.stdout)
            return value.returncode, json.loads(value.stdout)
        code, plan = command("pilot-run-archive.py", ["preview", "--state-parent", str(self.state), "--run-id", "one"])
        self.assertEqual(code, 0)
        path = self.output / "plan.json"
        self.write(path, plan)
        common = ["--plan", str(path), "--confirm", plan["plan_sha256"], "--archive-directory", str(self.output)]
        self.assertEqual(command("pilot-run-archive.py", ["archive", *common])[0], 0)
        code, result = command("pilot-run-archive.py", ["apply", *common])
        self.assertEqual(code, 0)
        self.assertTrue(result["complete"])
        code, result = command("pilot-run-archive.py", ["apply", *common])
        self.assertEqual(code, 1)
        self.assertFalse(result["complete"])
        self.assertEqual(self.unrelated.read_text(), self.marker)

    def test_confirmation_expiry_private_plan_and_retention_age(self):
        plan = self.plan()
        path = self.output / "plan.json"
        self.write(path, plan)
        self.assertEqual(ARCHIVE.load_plan(path, plan["plan_sha256"]), plan)
        with self.assertRaises(S.Refusal):
            ARCHIVE.load_plan(path, "0" * 64)
        with patch.object(ARCHIVE.time, "time", return_value=time.time() + 901), self.assertRaises(S.Refusal):
            ARCHIVE.load_plan(path, plan["plan_sha256"])
        path.chmod(0o644)
        with self.assertRaises(S.Refusal):
            ARCHIVE.load_plan(path, plan["plan_sha256"])
        self.assertEqual(ARCHIVE.preview(self.state, ["one"], 86400)["runs"], [])

    def test_read_only_recovery_verifies_journal_archive_and_remaining_members(self):
        plan = self.archive()
        original = ARCHIVE.remove_member
        def interrupt(*args):
            original(*args)
            raise InterruptedError("controlled interruption")
        with patch.object(ARCHIVE, "remove_member", side_effect=interrupt):
            result = ARCHIVE.apply(plan, self.output)[0]
        before = self.snapshot()
        inspection = ARCHIVE.inspect_quarantine(plan, self.output, result["quarantine"])
        self.assertEqual(inspection["outcome"], "partial")
        self.assertTrue(inspection["archive_verified"])
        self.assertGreater(inspection["remaining_files"], 0)
        self.assertEqual(before, self.snapshot())
        archive_path = self.output / ARCHIVE.archive_name(plan, plan["runs"][0])
        self.write(archive_path, b"corrupt archive")
        with self.assertRaises(S.Refusal):
            ARCHIVE.inspect_quarantine(plan, self.output, result["quarantine"])
        self.assertEqual(before, self.snapshot())

    def test_writer_lock_and_changed_directory_generation_prevent_cleanup(self):
        import fcntl
        with (self.run / "audit/writer.lock").open("rb") as holder:
            fcntl.flock(holder.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.plan()
            self.assertEqual(result["runs"], [])
            self.assertEqual(result["excluded"][0]["reason"], "active_audit_writer")
        plan = self.archive()
        saved = self.state / "original-run"
        self.run.rename(saved); saved.rename(self.run)
        with self.assertRaises(S.Refusal):
            ARCHIVE.apply(plan, self.output)
        self.assertTrue((self.run / "audit-run.json").exists())

    def test_archive_batch_retains_completed_results_and_reports_unattempted_runs(self):
        self.completed("two"); self.completed("three")
        plan = self.plan(["one", "two", "three"])
        original = ARCHIVE.build_archives
        calls = 0
        def fail_second(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("controlled archive failure")
            return original(*args)
        before = self.snapshot()
        with patch.object(ARCHIVE, "build_archives", side_effect=fail_second):
            rows = ARCHIVE.archive_batch(plan, self.output)
        self.assertEqual([row["outcome"] for row in rows], ["archived_source_retained", "retained", "not_attempted"])
        self.assertEqual(before, self.snapshot())

    def test_false_stop_record_is_unknown_and_proof_bytes_are_never_printed(self):
        _, native, _ = self.active()
        self.write(native / "stop.json", {"contract": "sw-pilot-stop/1", "run_sha256": "0" * 64,
                   "status": "stopped", "signature": "s" * 43})
        result = DISCOVERY.discover(self.state)
        self.assertFalse(result["complete"])
        self.assertEqual(result["runs"][0]["reason"], "stop_record_invalid")
        self.assertNotIn("s" * 43, json.dumps(result))

    def test_loopback_probe_fixtures_bind_instance_nonce_and_disable_proxy(self):
        home, native, manifest = self.active()
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass
            def do_GET(self):
                if self.path == "/native/v1/instance":
                    body = {"instance_id": owner.instance, "registry_sha256": owner.receipt["registry_sha256"]}
                else:
                    body = {"contract_version": "sw-protection-status/1", "nonce": self.headers.get("x-agentfw-status-nonce"),
                            "captured_at_ms": int(time.time() * 1000), "mode": "enforcing",
                            "runtime": {"pid": os.getpid(), "binary_sha256": owner.receipt["binary_sha256"]},
                            "registry": {"sha256": owner.receipt["registry_sha256"]}, "policy": {"sha256": "f" * 64}}
                payload = S.encoded(body)
                self.send_response(200); self.send_header("Content-Length", str(len(payload))); self.end_headers()
                self.wfile.write(payload)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join(timeout=2)))
        port = server.server_port
        self.write(self.run / "run.json", {"format": "sw-prepared-pilot-run/1", "home": str(home),
            "supervisor_pid": 10, "launcher_pid": manifest["launcher_pid"], "daemon_pid": os.getpid(), "port": port})
        policy = self.root / "policy.yaml"
        self.write(policy, b"agent_policies: []\ndefault: allow\n")
        self.receipt["policy_sha256"] = S.sha(policy.read_bytes())
        self.write(self.run / "audit-run.json", self.receipt)
        config = {"bind": "127.0.0.1", "port": port, "enforce": True, "policy": str(policy),
            "native": {"registry_sha256": self.receipt["registry_sha256"], "registry_path": str(home / "registry.json")},
            "audit_retention": {}}
        self.write(home / "config.yaml", config)
        manifest["files"] = [{"path": str(home / "config.yaml"), "sha256": S.sha(S.encoded(config))},
                             {"path": str(policy), "sha256": S.sha(policy.read_bytes())}] + [{}] * 3
        self.write(native / "run.json", manifest)
        self.write(home / "native-token", b"native_private_key_12345678")
        self.write(home / "token", b"status_private_key_12345678")
        before = self.snapshot()
        # The launcher proof and offline Rust projection are mocked here. Native
        # qualification and Rust regressions separately exercise those contracts.
        def sealed(*_args, pin=False):
            return os.open(sys.executable, os.O_RDONLY) if pin else None
        projection = {"state": "authenticated_daemon_observed", "protection": "unknown"}
        with patch.object(DISCOVERY, "sealed_launcher", side_effect=sealed), \
             patch.object(DISCOVERY, "diagnostic_projection", return_value=projection), \
             patch.object(DISCOVERY, "verified_agent", return_value=self.receipt["binary_sha256"]), \
             patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1"}):
            self.instance = "owned-instance"
            result = DISCOVERY.discover(self.state, probing=True, agentfw=Path(sys.executable), agentfw_sha256="b" * 64)
            observed = result["runs"][0]["observation"]
            self.assertEqual(observed["state"], "authenticated_daemon_observed")
            self.assertEqual(observed["protection"], "unknown")
            self.instance = "restarted-daemon"
            result = DISCOVERY.discover(self.state, probing=True, agentfw=Path(sys.executable), agentfw_sha256="b" * 64)
            self.assertEqual(result["runs"][0]["reason"], "stale_daemon_instance")
            config["bind"] = "remote.invalid"
            self.write(home / "config.yaml", config)
            with patch.object(DISCOVERY, "request", side_effect=AssertionError("untrusted endpoint")):
                result = DISCOVERY.discover(self.state, probing=True, agentfw=Path(sys.executable), agentfw_sha256="b" * 64)
            self.assertEqual(result["runs"][0]["reason"], "untrusted_endpoint")
        self.write(home / "config.yaml", {**config, "bind": "127.0.0.1"})
        # Restore metadata differs, so compare private bytes instead of mtimes.
        self.assertEqual({k:v[2] for k,v in before.items()}, {k:v[2] for k,v in self.snapshot().items()})
        self.assertNotIn(self.marker, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
