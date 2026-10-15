# SPDX-License-Identifier: Apache-2.0
"""Adversarial evidence-grading controls, separate from native Windows acceptance."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "verify-sou58-windows-read.py"
spec = importlib.util.spec_from_file_location("sou58_windows_acceptance_under_test", SCRIPT)
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)
DIAGNOSTICS = D.load(SCRIPT.with_name("print-sou58-ci-diagnostics.py"), "sou58_ci_diagnostics_under_test")


def line(value):
    return D.canonical(value).decode() + "\n"


def reply(identity, text, error=False):
    return line({"jsonrpc": "2.0", "id": identity,
                 "result": {"isError": error, "content": [{"type": "text", "text": text}]}})


def relay_row(request, response=None, forwarded=None, **extra):
    original = line(request).rstrip("\n")
    forwarded = original if forwarded is None else line(forwarded).rstrip("\n")
    row = {"path": "/native/v1", "original_raw": original, "forwarded_raw": forwarded,
           "original_sha256": D.sha(original.encode()), "forwarded_sha256": D.sha(forwarded.encode())}
    if response is not None:
        raw = line(response).rstrip("\n")
        row.update(status=200, reply_raw=raw, reply_sha256=D.sha(raw.encode()))
    row.update(extra)
    return row


def passing_row(name="post-allow-share-denial"):
    """Hand-built evidence oracle: no runner or grader manufactures these facts."""
    classifier = "c" * 64
    config = {"registry": {"tools": [{"resource_policy": {"classifier_sha256": classifier}}]},
              "policy": "agent_policies: []\ndefault: allow\n"}
    config.update(registry_sha256=D.sha(D.canonical(config["registry"])), policy_sha256=D.sha(config["policy"].encode()))
    abnormal = name in D.ABNORMAL
    sid = "session-2" if abnormal else "session-1"
    follow = reply("useful-followup", D.TEXT)
    reason = ("sou58-explicit-" + name[7:] if name in {"native-deny", "native-ask"} else
              "policy_denied" if name == "classifier-deny" else "policy_unconfirmed_ask" if name == "classifier-ask"
              else "Soup Wall withheld MCP result" if name == "result-withheld" else "resource_read_failed")
    attack = "" if abnormal else reply("probe", D.TEXT if name in D.SUCCESS else reason, name not in D.SUCCESS)
    attack_request = D.H.frame("probe", "read_document", {"path": "C:\\assigned\\document.txt"})
    row = {"case": name, "owned_fixture_removed": True, "configuration": config, "sessions": [],
           "attack": {"request": attack_request, "reply_raw": attack, "latency_ms": 2.0}, "followup_raw": follow, "relay": [],
           "classifier_sha256": classifier}
    def prediction(identity, arguments, verdict="allow"):
        return {"event": "mcp_classification", "host_call_id": identity, "source": "rule-baseline/python",
                "classifier_sha256": classifier, "args_sha256": D.sha(D.canonical(arguments)),
                "schema_sha256": D.sha(D.canonical(D.F.SCHEMA)), "registry_sha256": config["registry_sha256"],
                "server_id": "sou58", "tool": "read_document", "authoritative_verdict": verdict,
                "classification": {"actions": ["delete"] if verdict == "deny" else ["read"]}}
    row["collector_raw"] = ("" if name in D.EARLY_REFUSALS else
                            line(prediction("probe", attack_request["params"]["arguments"],
                                            "deny" if name == "classifier-deny" else "ask" if name == "classifier-ask" else "allow")))
    row["collector_raw"] += line(prediction("useful-followup", {"path": "document.txt"}))
    init = line({"jsonrpc": "2.0", "id": "init", "result": {"protocolVersion": "2024-11-05"}})
    listing = line({"jsonrpc": "2.0", "id": "list", "result": {"tools": D.F.TOOLS}})
    def session(label, output, exit_code):
        return {"label": label, "client_raw": init + listing + output, "child_ledger_present": True,
                "child_process": {"pid": 1234, "handle_bound_before_invocation": True, "exit_observed": True, "exit_code": 0},
                "child_ledger_raw": "", "child_started_raw": "started\n", "child_closed_raw": "closed\n",
                "child_output_raw": init + listing,
                "child_input_raw": "".join(line({"method": method}) for method in
                    ("initialize", "notifications/initialized", "tools/list")),
                "closure": {"exit_code": exit_code, "stdout_eof": True, "reader_joined": True, "forced_cleanup": False}}
    row["sessions"] = ([session("primary", "", 1), session("fresh-after-refusal", follow, 0)] if abnormal else
                       [session("primary", attack + follow, 1 if name == "replayed-id" else 0)])
    native = [{"event": "native_session_start", "session": "session-1"}]
    if abnormal:
        native.append({"event": "native_session_start", "session": sid})
    def call(host_id, session_id, arguments, call_id, allowed=True):
        request = {"contract_version": D.CONTRACT, "registry_sha256": config["registry_sha256"],
                   "session_id": session_id, "event": "call", "tool": "read_document", "args": arguments,
                   "resource_admission": {"host_call_id": host_id}}
        grant = {"contract_version": D.CONTRACT, "registry_sha256": config["registry_sha256"],
                 "session_id": session_id, "event": "call", "call_id": call_id, "binding_sha256": "b" * 64,
                 "release": allowed, "enforced": True, "verdict": "allow" if allowed else "deny"}
        return request, grant
    def audit(event, call_id, session_id, content=None, released=True):
        result = {"event": event, "session": session_id, "call_id": call_id, "binding_sha256": "b" * 64,
                  "released": released, "shadow": False, "verdict": "allow" if released else "deny"}
        if content is not None:
            result["content_sha256"] = D.sha(content.encode())
        native.append(result)
    def complete(request, grant, content, allowed=True):
        result = {"contract_version": D.CONTRACT, "registry_sha256": config["registry_sha256"],
                  "session_id": request["session_id"], "event": "result", "tool": "read_document", "args": request["args"],
                  "call_id": grant["call_id"], "content": content}
        receipt = dict(grant, event="result", release=allowed, content_sha256=D.sha(content.encode()))
        row["relay"].append(relay_row(result, receipt))
        audit("native_result", grant["call_id"], request["session_id"], content, allowed)
    executed = D.SUCCESS | {"post-allow-share-denial", "invalid-utf8", "oversize", "result-withheld"}
    if name in executed | {"native-deny", "native-ask", "native-args-mismatch"} | D.ABNORMAL:
        request, grant = call("probe", "session-1", attack_request["params"]["arguments"], "attack", name not in {"native-deny", "native-ask", "native-args-mismatch"})
        forwarded = copy.deepcopy(request)
        if name == "native-args-mismatch":
            forwarded["args"]["path"] += ".substituted"
        if name == "native-session-mismatch":
            forwarded["session_id"] = "wrong-session"
        row["relay"].append(relay_row(request, grant, forwarded,
            **({"held_allow": True, "released_unchanged": True} if name in D.HELD else {}),
            **({"owned_daemon_stopped": True} if name == "daemon-loss" else {})))
        audit("native_call", "attack", "session-1", released=name not in {"native-deny", "native-ask", "native-args-mismatch"})
        if name in executed:
            complete(request, grant, reply("probe", D.INJECTION) if name == "result-withheld" else attack,
                     name != "result-withheld")
    useful_request, grant = call("useful-followup", sid, {"path": "document.txt"}, "useful")
    row["relay"].append(relay_row(useful_request, grant))
    audit("native_call", "useful", sid)
    complete(useful_request, grant, follow)
    native.append({"event": "native_session_end", "session": "session-1"})
    if abnormal:
        native.append({"event": "native_session_end", "session": sid})
    row["native_audit_raw"] = "".join(line(item) for item in native)
    if name in D.GUARDED:
        labels = ["authorized-object"] + (["outside-junction-target"] if name == "junction" else ["unlisted-object"] if name == "unlisted" else [])
        row["read_exclusions"] = []
        for label in labels:
            data = D.TEXT if label == "authorized-object" else D.OUTSIDE
            row["read_exclusions"].append({"object": label, "held": True, "file_read_data_denied": True,
                "calibration_error": 32, "share_mode": 6, "guard_access": 128, "released_before_useful_followup": True,
                "released_bytes": len(data.encode()), "released_sha256": D.sha(data.encode())})
    if name == "replayed-id":
        row.update(replayed_reply_raw="", replay_terminated=True)
    return row


class WindowsReadGradingControls(unittest.TestCase):
    def assertFails(self, row):
        self.assertEqual(D.grade(row)["status"], "fail", D.grade(row))

    def test_reviewed_all_case_controls_pass(self):
        for name in D.CASES:
            with self.subTest(case=name):
                self.assertEqual(D.grade(passing_row(name))["status"], "pass", D.grade(passing_row(name)))

    def test_child_zero_calls_without_read_exclusion_is_not_pass(self):
        row = passing_row()
        del row["read_exclusions"]
        self.assertFails(row)

    def test_missing_calibration_or_released_guard_is_not_zero_read(self):
        for field, value in (("file_read_data_denied", False), ("calibration_error", 0),
                             ("released_before_useful_followup", False), ("released_sha256", "0" * 64)):
            with self.subTest(field=field):
                row = passing_row()
                row["read_exclusions"][0][field] = value
                self.assertFails(row)

    def test_outside_and_unlisted_objects_need_their_own_witness(self):
        for name in ("junction", "unlisted"):
            row = passing_row(name)
            row["read_exclusions"].pop()
            self.assertFails(row)

    def test_child_forwarding_missing_start_or_missing_close_is_not_pass(self):
        for field, value in (("child_ledger_raw", line({"method": "tools/call"})),
                             ("child_started_raw", ""), ("child_closed_raw", ""), ("child_ledger_present", False)):
            row = passing_row()
            row["sessions"][0][field] = value
            self.assertFails(row)

    def test_unauthorized_success_is_not_pass(self):
        row = passing_row("native-deny")
        row["attack"]["reply_raw"] = reply("probe", D.TEXT)
        self.assertFails(row)

    def test_allowed_read_interrupted_or_changed_is_not_pass(self):
        for actual in (reply("probe", "blocked", True), reply("probe", "different")):
            row = passing_row("allow-relative")
            row["attack"]["reply_raw"] = actual
            self.assertFails(row)

    def test_useful_reply_requires_exact_inspected_client_bytes(self):
        row = passing_row()
        row["followup_raw"] = row["followup_raw"].replace("7 red", "8 red")
        self.assertFails(row)

    def test_extra_response_or_reordered_original_id_is_not_pass(self):
        for suffix in (reply("extra", "extra"), reply("probe", D.TEXT)):
            row = passing_row()
            row["sessions"][0]["client_raw"] += suffix
            self.assertFails(row)

    def test_native_binding_or_content_hash_substitution_is_not_pass(self):
        for field in ("binding_sha256", "content_sha256"):
            row = passing_row()
            item = row["relay"][-1]
            receipt = D.strict_json(item["reply_raw"])
            receipt[field] = "f" * 64
            item["reply_raw"] = D.canonical(receipt).decode()
            item["reply_sha256"] = D.sha(item["reply_raw"].encode())
            self.assertFails(row)

    def test_unenforced_native_allow_is_not_pass(self):
        row = passing_row()
        useful = row["relay"][-2]
        grant = D.strict_json(useful["reply_raw"])
        grant["enforced"] = False
        useful["reply_raw"] = D.canonical(grant).decode()
        useful["reply_sha256"] = D.sha(useful["reply_raw"].encode())
        self.assertFails(row)

    def test_any_allow_audit_does_not_replace_exact_correlated_native_audit(self):
        for field, value in (("call_id", "other"), ("session", "other"), ("released", False), ("shadow", True)):
            row = passing_row()
            records = D.json_lines(row["native_audit_raw"].encode())
            record = next(item for item in records if item.get("event") == "native_result" and item.get("call_id") == "useful")
            record[field] = value
            row["native_audit_raw"] = "".join(line(item) for item in records)
            self.assertFails(row)

    def test_missing_or_forged_genuine_held_allow_is_not_pass(self):
        for field, value in (("held_allow", False), ("released_unchanged", False)):
            row = passing_row()
            row["relay"][0][field] = value
            self.assertFails(row)

    def test_configuration_substitution_and_extra_execution_are_not_pass(self):
        row = passing_row()
        row["configuration"]["policy"] += "# changed\n"
        self.assertFails(row)
        row = passing_row()
        row["relay"].append(copy.deepcopy(row["relay"][-2]))
        self.assertFails(row)

    def test_missing_fresh_useful_session_after_transport_failure_is_not_pass(self):
        row = passing_row("daemon-loss")
        row["sessions"].pop()
        self.assertFails(row)

    def test_invalid_utf8_and_oversize_make_no_zero_read_claim(self):
        for name in ("invalid-utf8", "oversize"):
            self.assertNotIn("read_exclusions", passing_row(name))
            self.assertEqual(D.grade(passing_row(name))["status"], "pass")

    def test_withheld_injection_must_have_been_inspected_and_not_released(self):
        row = passing_row("result-withheld")
        row["attack"]["reply_raw"] = reply("probe", D.INJECTION)
        self.assertFails(row)

    def test_fixture_operates_real_stdio_and_records_forwarded_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "child.jsonl"
            requests = [{"jsonrpc": "2.0", "id": "init", "method": "initialize"},
                        {"jsonrpc": "2.0", "method": "notifications/initialized"},
                        {"jsonrpc": "2.0", "id": "list", "method": "tools/list"},
                        D.H.frame("must-record", "read_document", {"path": "unused"})]
            result = subprocess.run([sys.executable, "-I", "-u", str(D.FIXTURE), "--ledger", str(ledger)],
                                    input="".join(line(item) for item in requests).encode(), capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(D.json_lines(ledger.read_bytes()), [requests[-1]])
            output = D.json_lines(result.stdout)
            self.assertEqual(output[1]["result"]["tools"], D.F.TOOLS)
            self.assertIn("UNEXPECTED-SERVER-READ", result.stdout.decode())
            self.assertEqual(ledger.with_suffix(".closed").read_text(), "closed\n")

    def test_dry_run_starts_no_processes(self):
        with patch.object(D.subprocess, "Popen", side_effect=AssertionError("process started")), patch.object(sys, "argv", [str(SCRIPT)]):
            self.assertEqual(D.main(), 0)

    def test_native_filter_cannot_pass_with_zero_tests(self):
        for raw in ("running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored;\n", ""):
            self.assertFalse(D.H.native_test_passed({"exit_code": 0, "stdout": raw}))

    def test_exact_native_boundary_tests_must_all_execute_without_ignores(self):
        output = ("running 12 tests\n" + "".join("test windows_read::tests::" + name + " ... ok\n" for name in D.NATIVE_TESTS)
                  + "test result: ok. 12 passed; 0 failed; 0 ignored; 1 filtered out;\n")
        self.assertTrue(D.native_tests_passed({"exit_code": 0, "stdout": output}))
        for broken in (output.replace(D.NATIVE_TESTS[0], "unrelated_test"), output.replace("0 ignored", "1 ignored"),
                       output.replace("12 passed", "11 passed"), output.replace(" ... ok", " ... ignored", 1)):
            self.assertFalse(D.native_tests_passed({"exit_code": 0, "stdout": broken}))

    def test_metadata_refusals_precede_classifier_and_still_allow_useful_read(self):
        for name in D.EARLY_REFUSALS:
            with self.subTest(case=name):
                row = passing_row(name)
                predictions = D.json_lines(row["collector_raw"].encode())
                self.assertEqual([item["host_call_id"] for item in predictions], ["useful-followup"])
                self.assertEqual(D.grade(row)["status"], "pass")
                forged = dict(predictions[0], host_call_id="probe",
                              args_sha256=D.sha(D.canonical(row["attack"]["request"]["params"]["arguments"])))
                row["collector_raw"] = line(forged) + row["collector_raw"]
                self.assertFails(row)

    def test_classifier_revision_args_registry_and_schema_must_correlate(self):
        for field, value in (("classifier_sha256", "f" * 64), ("args_sha256", "f" * 64),
                             ("registry_sha256", "f" * 64), ("schema_sha256", "f" * 64),
                             ("source", "test-double/read-v1"), ("tool", "different")):
            with self.subTest(field=field):
                row = passing_row("classifier-deny")
                predictions = D.json_lines(row["collector_raw"].encode())
                predictions[0][field] = value
                row["collector_raw"] = "".join(line(item) for item in predictions)
                self.assertFails(row)

    def test_classifier_deny_or_ask_cannot_be_an_ordinary_allow(self):
        for name in ("classifier-deny", "classifier-ask"):
            row = passing_row(name)
            predictions = D.json_lines(row["collector_raw"].encode())
            predictions[0]["authoritative_verdict"] = "allow"
            row["collector_raw"] = "".join(line(item) for item in predictions)
            self.assertFails(row)

    def test_useful_read_requires_real_classifier_composition(self):
        row = passing_row()
        predictions = D.json_lines(row["collector_raw"].encode())
        predictions.pop()
        row["collector_raw"] = "".join(line(item) for item in predictions)
        self.assertFails(row)

    def test_fatal_session_requires_os_exit_witness_even_without_closed_marker(self):
        row = passing_row("queued-cancellation")
        row["sessions"][0]["child_closed_raw"] = ""
        self.assertEqual(D.grade(row)["status"], "pass")
        row["sessions"][0]["child_process"]["exit_observed"] = False
        self.assertFails(row)

    def test_ci_diagnostics_keep_failures_visible_without_altering_raw_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sou58-router.log").write_text("router FAILED\n", encoding="utf-8")
            output = root / "sou58-standard-user"
            output.mkdir()
            report = {"status": "incomplete", "error": "native tests failed", "native_tests": {
                "stdout": "test failing ... FAILED", "stderr": "owned panic"},
                "cases": [{"case": "allow-relative", "error": "bad", "grade": {"status": "fail"}}]}
            raw = json.dumps(report)
            (output / "acceptance.json").write_text(raw, encoding="utf-8")
            (output / "launcher.json").write_text(json.dumps({"status": "incomplete", "error": "child failed"}), encoding="utf-8")
            text = DIAGNOSTICS.diagnostics(root)
            for expected in ("router FAILED", "failing ... FAILED", "owned panic", "allow-relative", "child failed"):
                self.assertIn(expected, text)
            self.assertEqual((output / "acceptance.json").read_text(encoding="utf-8"), raw)
            self.assertIn("~~~text", text)

    def test_ci_diagnostics_redact_authentication_and_cap_unicode_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sou58-router.log").write_text('Bearer fixture-secret\n{"password":"private"}\n~~~\n' + "🥣" * 100000, encoding="utf-8")
            text = DIAGNOSTICS.diagnostics(root)
            self.assertNotIn("fixture-secret", text)
            self.assertNotIn('"private"', text)
            self.assertIn("[REDACTED]", text)
            self.assertIn("[TRUNCATED:", text)
            self.assertLess(len(text.encode()), 150000)


if __name__ == "__main__":
    unittest.main()
