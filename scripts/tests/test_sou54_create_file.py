# SPDX-License-Identifier: Apache-2.0
"""Evidence controls: missing/refused output must not masquerade as confinement."""
from __future__ import annotations
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sou54_probe", SCRIPTS / "verify-sou54-create-file.py")
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def raw(value):
    return PROBE.canonical(value).decode() + "\n"


def observation(name="utf8-relative"):
    args = {"path": "created.txt", "content": PROBE.UTF8}
    repeated = PROBE.REPEATED if name == "repeated-failures" else 1
    attempts, responses, predictions = [], [], []
    for index in range(repeated):
        request = PROBE.frame("create-" + str(index + 1), "create_file", args)
        receipt = {"success": True, "created": True, "committed": True, "path": args["path"],
                   "bytes_written": len(args["content"].encode()), "content_sha256": PROBE.sha(args["content"].encode()),
                   "file_synced": True, "directory_synced": True}
        result = {"content": [{"type": "text", "text": PROBE.canonical(receipt).decode()}]}
        if name not in PROBE.SUCCESS or name == "result-withheld":
            text = {"classifier-ask": "policy_unconfirmed_ask", "classifier-deny": "policy_denied",
                    "native-ask": "sou54-explicit-ask", "native-deny": "sou54-explicit-deny",
                    "result-withheld": "Soup Wall withheld MCP result"}.get(name, "resource_create_failed")
            result = {"isError": True, "content": [{"type": "text", "text": text}]}
        response = {"jsonrpc": "2.0", "id": request["id"], "result": result}
        attempts.append({"request": request, "reply_raw": raw(response), "latency_ms": 1.25})
        responses.append(response)
        predictions.append({"host_call_id": request["id"], "args_sha256": PROBE.sha(PROBE.canonical(args)),
            "classifier_sha256": "c" * 64, "classification": {"actions": ["write"]},
            "authoritative_verdict": "ask" if name == "classifier-ask" else "deny" if name == "classifier-deny" else "allow"})
    predictions.append({"host_call_id": "useful-followup", "classifier_sha256": "c" * 64})
    initial = {"jsonrpc": "2.0", "id": "init", "result": {"protocolVersion": "2024-11-05"}}
    listing = {"jsonrpc": "2.0", "id": "list", "result": {"tools": PROBE.load_tools()}}
    useful = {"jsonrpc": "2.0", "id": "useful-followup", "result": {"content": [{"type": "text", "text": PROBE.READ_TEXT}]}}
    opened = {"event": "native_session_start", "session": "same-session"}
    ended = {"event": "native_session_end", "session": "same-session"}
    native = [opened]
    if name in PROBE.SUCCESS:
        native.extend([{"event": "native_call", "tool": "create_file", "session": "same-session", "verdict": "allow",
                        "released": True, "shadow": False, "call_id": "native-create", "binding_sha256": "b" * 64},
                       {"event": "native_result", "tool": "create_file", "session": "same-session", "verdict": "deny" if name == "result-withheld" else "allow",
                        "released": name != "result-withheld", "shadow": False, "call_id": "native-create", "binding_sha256": "b" * 64}])
    for event in ("native_call", "native_result"):
        native.append({"event": event, "tool": "read_document", "session": "same-session", "released": True,
                       "shadow": False, "verdict": "allow"})
    native.append(ended)
    before = {".": {"kind": stat.S_IFDIR, "mode": 0o700, "inode": 1, "device": 1, "links": 2}}
    created = {"kind": stat.S_IFREG, "mode": 0o600, "inode": 2, "device": 1, "links": 1,
               "bytes": len(PROBE.UTF8.encode()), "sha256": PROBE.sha(PROBE.UTF8.encode())}
    after = dict(before)
    if name in PROBE.SUCCESS:
        after["created.txt"] = created
    return {"case": name, "attempts": attempts, "child_ledger_present": True, "child_ledger_raw": "",
        "child_started_raw": "started\n", "child_closed_raw": "closed\n", "outside_before": {}, "outside_after": {},
        "collector_closure": {"exit_code": 0, "stdout_eof": True, "reader_joined": True, "forced_cleanup": False},
        "client_raw": "".join(raw(item) for item in [initial, listing, *responses, useful]),
        "child_input_raw": "".join(raw(item) for item in [{"method": "initialize"}, {"method": "notifications/initialized"}, {"method": "tools/list"}]),
        "child_output_raw": raw(initial) + raw(listing), "workspace_before": before, "workspace_after": after,
        "created_witness": created if name in PROBE.SUCCESS else None, "expected_content_bytes": created["bytes"],
        "expected_content_sha256": created["sha256"], "target_name": "created.txt", "classifications": predictions,
        "collector_raw": raw({"event": "mcp_create_file_execution", "host_call_id": "create-1", "committed": True,
                              "committed_bytes": len(PROBE.UTF8.encode()), "result_kind": "value", "error": None}) if name in PROBE.SUCCESS else "",
        "classifier_sha256": "c" * 64, "native_audit_raw": "".join(raw(item) for item in native)}


class EvidenceTests(unittest.TestCase):
    def test_zero_selected_tests_cannot_be_a_successful_native_boundary_check(self):
        self.assertFalse(PROBE.native_test_passed({"exit_code": 0, "stdout": "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 10 filtered out\n"}))
        self.assertFalse(PROBE.native_test_passed({"exit_code": 0, "stdout": "running 3 tests\n\ntest result: ok. 0 passed; 0 failed; 3 ignored\n"}))
        self.assertFalse(PROBE.native_test_passed({"exit_code": 1, "stdout": "running 2 tests\n\ntest result: ok. 2 passed; 0 failed;\n"}))
        self.assertTrue(PROBE.native_test_passed({"exit_code": 0, "stdout": "running 2 tests\n\ntest result: ok. 2 passed; 0 failed; 0 ignored;\n"}))

    def test_default_does_not_start_a_process(self):
        result = subprocess.run([sys.executable, str(SCRIPTS / "verify-sou54-create-file.py")],
                                capture_output=True, check=True, text=True)
        value = json.loads(result.stdout)
        self.assertEqual(value["processes_started"], 0)
        self.assertFalse(value["acceptance_passed"])

    def test_usable_create_and_result_withhold_have_honest_effect_witnesses(self):
        for name in ("utf8-relative", "result-withheld", "native-deny", "native-ask", "classifier-ask", "classifier-deny", "repeated-failures"):
            self.assertEqual(PROBE.grade(observation(name))["status"], "pass", name)

    def test_zero_child_calls_is_not_proof_of_successful_create(self):
        for change in (lambda r: r.update(created_witness=None), lambda r: r.update(workspace_after=r["workspace_before"]),
                       lambda r: r["created_witness"].update(sha256="a" * 64),
                       lambda r: r["created_witness"].update(mode=0o644), lambda r: r["created_witness"].update(links=2)):
            row = observation()
            change(row)
            self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_refusal_requires_unchanged_independent_workspace_and_outside(self):
        for change in (lambda r: r["workspace_after"].update(leaked={}), lambda r: r["outside_after"].update(leaked={}),
                       lambda r: r.update(child_ledger_raw=raw({"method": "tools/call"})),
                       lambda r: r.update(collector_raw=raw({"event": "mcp_create_file_execution"})),
                       lambda r: r.update(child_ledger_present=False), lambda r: r.update(child_started_raw=""), lambda r: r.update(child_closed_raw="")):
            row = observation("native-deny")
            change(row)
            self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_result_refusal_does_not_erase_committed_side_effect(self):
        row = observation("result-withheld")
        row["workspace_after"] = row["workspace_before"]
        self.assertEqual(PROBE.grade(row)["status"], "fail")
        row = observation("result-withheld")
        row["attempts"][0]["reply_raw"] = row["attempts"][0]["reply_raw"].replace("Soup Wall withheld MCP result", "unrelated failure")
        row["client_raw"] = row["client_raw"].replace("Soup Wall withheld MCP result", "unrelated failure")
        self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_timeout_eof_kill_or_missing_reply_is_not_a_clean_pass(self):
        for key, value in (("exit_code", 1), ("stdout_eof", False), ("reader_joined", False), ("forced_cleanup", True)):
            row = observation()
            row["collector_closure"][key] = value
            self.assertEqual(PROBE.grade(row)["status"], "fail", key)
        row = observation()
        row["client_raw"] = "\n".join(row["client_raw"].splitlines()[:-1]) + "\n"
        self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_same_session_continuation_and_revision_must_be_bound(self):
        for change in (lambda r: r.update(native_audit_raw=r["native_audit_raw"].replace('"tool":"read_document"', '"session":"other","tool":"read_document"')),
                       lambda r: r["classifications"][0].update(args_sha256="a" * 64),
                       lambda r: r["classifications"][0].update(classifier_sha256="a" * 64),
                       lambda r: r["classifications"][0].update(authoritative_verdict="ask")):
            row = observation()
            change(row)
            self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_missing_or_duplicate_json_is_not_evidence(self):
        self.assertEqual(PROBE.grade({})["status"], "fail")
        for key in ("client_raw", "native_audit_raw", "child_input_raw"):
            row = observation()
            row[key] = row[key].replace('{', '{"duplicate":1,"duplicate":2,', 1)
            self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_private_environment_does_not_inherit_user_secrets_or_redirects(self):
        with patch.dict(os.environ, {"AGENTFW_TOKEN": "secret", "HTTP_PROXY": "secret", "OPENAI_API_KEY": "secret", "PYTHONPATH": "secret"}):
            env = PROBE.private_environment(Path("owned-home"))
        for name in ("AGENTFW_TOKEN", "HTTP_PROXY", "OPENAI_API_KEY", "PYTHONPATH"):
            self.assertNotIn(name, env)
        self.assertEqual(env["HOME"], "owned-home")

    def test_tree_witness_does_not_follow_symlinks_or_block_on_fifo(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "file").write_bytes(b"exact")
            (root / "link").symlink_to(root / "file")
            if hasattr(os, "mkfifo"):
                os.mkfifo(root / "fifo")
            rows = PROBE.tree_snapshot(root)
            self.assertEqual(rows["file"]["sha256"], PROBE.sha(b"exact"))
            self.assertNotIn("sha256", rows["link"])
            if "fifo" in rows:
                self.assertEqual(rows["fifo"]["kind"], stat.S_IFIFO)
                self.assertNotIn("sha256", rows["fifo"])

    def test_discovery_fixture_never_executes_requested_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "must-not-exist.txt"
            ledger = root / "ledger.jsonl"
            original = raw(PROBE.frame("original-host-id", "create_file", {"path": str(target), "content": "MUST-NOT-WRITE"}))
            result = subprocess.run([sys.executable, str(PROBE.FIXTURE), "--ledger", str(ledger)],
                                    input=original, text=True, capture_output=True, check=True)
            self.assertFalse(target.exists())
            self.assertEqual(ledger.read_text(), original)
            self.assertEqual(json.loads(result.stdout)["id"], "original-host-id")
            self.assertIn("UNEXPECTED-CHILD-EXECUTION", result.stdout)

    def test_registry_scope_is_explicit_operator_execution_and_exact_target(self):
        value = PROBE.registry(PROBE.load_tools(), Path("/fixture/workspace"), Path("/fixture/workspace/new.txt"), "e" * 64, "c" * 64)
        create, read = value["tools"]
        self.assertEqual(create["action_class"], "side_effecting")
        self.assertEqual(create["resource_policy"]["execution"], {"operation": "create_file", "action": "write", "max_content_bytes": 65536,
                                                                  "executor_profile": PROBE.PROFILE})
        self.assertEqual(create["resource_policy"]["allowed_resources"], [{"kind": "path", "canonical": "/fixture/workspace/new.txt"}])
        self.assertNotIn("execution", read["resource_policy"])


if __name__ == "__main__":
    unittest.main()
