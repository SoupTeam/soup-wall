# SPDX-License-Identifier: Apache-2.0
"""Prevent missing, reordered or contradictory resource witnesses from passing."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-sou18-resources.py"
SPEC = importlib.util.spec_from_file_location("sou18_resources_test", SCRIPT)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def observation(case="absolute-read"):
    expected = PROBE.CASES[case]
    if expected == "recovery":
        row = observation()
        row["case"] = case
        row["submitted_frame"] = row["submitted_frame"].replace("absolute-read", case)
        row["client_output_raw"] = row["client_output_raw"].replace("absolute-read", case)
        final = row["classifications"][0]
        final["host_call_id"] = case
        response = json.loads(row["client_output_raw"].splitlines()[-1])
        row["native_decisions"][-1]["content_sha256"] = PROBE.sha(raw(response).encode())
        row.update(invalid_file="/owned/invalid.txt", read_errors=[])
        emitted = []
        predictions = []
        for index in range(PROBE.RECOVERY_ERRORS):
            call_id = f"read-error-{index}"
            request = {"id": call_id, "params": {"name": "read_document", "arguments": {"path": row["invalid_file"]}}}
            refusal = {"jsonrpc": "2.0", "id": call_id, "result": {"isError": True,
                "content": [{"text": "Soup Wall withheld MCP invocation (resource_read_failed)", "type": "text"}]}}
            row["read_errors"].append({"submitted_frame": raw(request), "released_raw": raw(refusal)})
            emitted.append(raw(refusal))
            predictions.append(dict(final, host_call_id=call_id))
        row["client_output_raw"] = row["server_output_raw"] + "".join(emitted) + raw(response)
        row["classifications"] = predictions + [final]
        return row
    tool = "read_note" if case == "unsupported-tool" else "read_document"
    request = {"jsonrpc": "2.0", "id": case, "method": "tools/call",
               "params": {"name": tool, "arguments": {"path": "/owned/file"}}}
    handshake = [{"id": "init", "method": "initialize"}, {"method": "notifications/initialized"},
                 {"id": "list", "method": "tools/list"}]
    discovery = [{"jsonrpc": "2.0", "id": "init", "result": {}}, {"jsonrpc": "2.0", "id": "list", "result": {}}]
    file_content = "Synthetic inventory. PRIVATE-MARKER" if case == "result-withheld" else "Synthetic inventory."
    produced = {"jsonrpc": "2.0", "id": case, "result": {"content": [{"type": "text", "text": file_content}]}}
    call = {"event": "native_call", "call_id": "grant", "session": "session", "binding_sha256": "a" * 64,
            "released": True, "verdict": "allow", "shadow": False}
    completion = dict(call, event="native_result", content_sha256=PROBE.sha(raw(produced).encode()), delivery="mcp_host")
    classifier = {"host_call_id": case, "source": "rule-baseline/python", "classifier_sha256": "c" * 64,
                  "args_sha256": PROBE.sha(raw(request["params"]["arguments"]).rstrip().encode()), "tool": tool,
                  "classification": {"actions": ["read"]}, "policy": "reached", "failure": None}
    row = {"case": case, "child_ledger_raw": "", "ledger_present": True, "server_started": "started\n",
           "collector_exit": 0, "stdout_complete": True, "receiver_count": 0, "files_unchanged": True,
           "call_submitted": True, "submitted_frame": raw(request), "handshake_frames": handshake,
           "server_input_raw": "".join(map(raw, handshake)), "server_output_raw": "".join(map(raw, discovery)),
           "native_decisions": [], "classifications": [], "classifier_sha256": "c" * 64,
           "file_content": file_content, "private_marker": "PRIVATE-MARKER", "collector_raw": ""}
    response = copy.deepcopy(produced)
    if expected in {"allow", "result_withheld", "resource_executor_unsupported", "native_resource_not_allowed"}:
        row["classifications"] = [classifier]
        if expected != "resource_executor_unsupported":
            row["native_decisions"] = [call]
    if expected in {"allow", "result_withheld"}:
        row["native_decisions"].append(completion)
    if expected != "allow":
        text = "Soup Wall withheld MCP invocation (" + expected + ")"
        if expected == "result_withheld":
            text = "Soup Wall withheld MCP result (demo-result-injection)"
            completion.update(released=False, verdict="ask")
        if expected == "native_resource_not_allowed":
            call.update(released=False, verdict="deny")
        response["result"] = {"isError": True, "content": [{"type": "text", "text": text}]}
    row["client_output_raw"] = row["server_output_raw"] + raw(response)
    if expected == "startup_refused":
        row.update(call_submitted=False, ledger_present=False, server_started="", collector_exit=1,
                   client_output_raw="", server_input_raw="", server_output_raw="",
                   collector_raw="Error: No such file or directory (os error 2)\n")
    return row


class ResourceEvidenceTests(unittest.TestCase):
    def test_default_starts_nothing(self):
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout), {"status": "not_run", "processes_started": 0, "acceptance_passed": False})

    def test_all_cases_require_their_distinct_outcomes(self):
        for case in PROBE.CASES:
            with self.subTest(case=case):
                self.assertEqual(PROBE.grade(observation(case))["status"], "pass")

    def test_forwarded_call_or_late_traffic_never_passes(self):
        for case in PROBE.CASES:
            for key in ("child_ledger_raw", "server_input_raw", "client_output_raw"):
                row = observation(case)
                row[key] += raw({"id": "late", "method": "tools/call"})
                self.assertEqual(PROBE.grade(row)["status"], "fail", (case, key))

    def test_zero_execution_needs_an_existing_independent_ledger(self):
        for key, value in (("ledger_present", False), ("server_started", ""), ("stdout_complete", False),
                           ("files_unchanged", False), ("collector_exit", None), ("collector_exit", False),
                           ("receiver_count", 1), ("receiver_count", False), ("call_submitted", False)):
            row = observation()
            row[key] = value
            self.assertEqual(PROBE.grade(row)["status"], "fail", key)

    def test_changed_id_arguments_classifier_or_native_binding_fails(self):
        mutations = [lambda r: r.update(client_output_raw=r["client_output_raw"].replace("absolute-read", "other")),
                     lambda r: r.update(submitted_frame=r["submitted_frame"].replace("/owned/file", "/other")),
                     lambda r: r["classifications"][0].update(classifier_sha256="d" * 64),
                     lambda r: r["native_decisions"][1].update(binding_sha256="b" * 64),
                     lambda r: r["native_decisions"][1].update(content_sha256="f" * 64),
                     lambda r: r["native_decisions"][0].update(shadow=True),
                     lambda r: r.update(error="incomplete observation")]
        for mutate in mutations:
            row = observation()
            mutate(row)
            self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_empty_wrong_or_duplicate_result_does_not_prove_a_useful_read(self):
        for text in ("", "UNEXPECTED-CHILD-EXECUTION", "other inventory"):
            row = observation()
            row["client_output_raw"] = row["client_output_raw"].replace("Synthetic inventory.", text)
            self.assertEqual(PROBE.grade(row)["status"], "fail")
        row = observation()
        row["client_output_raw"] += row["client_output_raw"].splitlines()[-1] + "\n"
        self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_withheld_result_needs_a_produced_result_and_no_marker_leak(self):
        for mutate in (lambda r: r.update(native_decisions=r["native_decisions"][:1]),
                       lambda r: r["native_decisions"][1].update(released=True),
                       lambda r: r.update(client_output_raw=r["client_output_raw"].replace("demo-result-injection", "PRIVATE-MARKER"))):
            row = observation("result-withheld")
            mutate(row)
            self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_policy_refusal_and_unsupported_execution_have_different_native_evidence(self):
        row = observation("unlisted-file")
        row["native_decisions"][0]["released"] = True
        self.assertEqual(PROBE.grade(row)["status"], "fail")
        for released in (True, False):
            row = observation("unsupported-tool")
            row["native_decisions"] = [dict(observation()["native_decisions"][0], released=released)]
            self.assertEqual(PROBE.grade(row)["status"], "fail")
        row = observation("unsupported-tool")
        row["classifications"] = []
        self.assertEqual(PROBE.grade(row)["status"], "fail")
        row = observation("traversal")
        row["classifications"] = observation()["classifications"]
        self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_startup_failure_is_not_a_policy_refusal_or_missing_evidence_pass(self):
        for key, value in (("collector_raw", "unrelated error"), ("collector_exit", 0),
                           ("ledger_present", True), ("call_submitted", True), ("stdout_complete", False),
                           ("server_started", "started\n")):
            row = observation("workspace-missing")
            row[key] = value
            self.assertEqual(PROBE.grade(row)["status"], "fail", key)

    def test_malformed_and_incomplete_json_are_not_success(self):
        self.assertEqual(PROBE.grade({})["status"], "fail")
        for key in ("client_output_raw", "server_input_raw", "server_output_raw"):
            for change in (lambda s: s.rstrip(), lambda s: s.replace('"id":', '"id":"duplicate","id":', 1)):
                row = observation()
                row[key] = change(row[key])
                self.assertEqual(PROBE.grade(row)["status"], "fail", key)

    def test_repeated_failures_require_useful_followup_in_same_session(self):
        for mutate in (lambda r: r.update(client_output_raw="\n".join(r["client_output_raw"].splitlines()[:-1]) + "\n"),
                       lambda r: r.update(read_errors=r["read_errors"][:64]),
                       lambda r: r["native_decisions"][-1].update(session="new-session"),
                       lambda r: r["read_errors"][0].update(released_raw=raw({"id": "wrong"})),
                       lambda r: r.update(collector_exit=1)):
            row = observation("read-error-recovery")
            mutate(row)
            self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_fixture_records_original_call_and_never_reads_requested_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = root / "input.txt"
            secret.write_text("MUST-NOT-RETURN")
            frame = raw({"jsonrpc": "2.0", "id": "original-id", "method": "tools/call",
                         "params": {"name": "read_document", "arguments": {"path": str(secret)}}})
            ledger = root / "ledger.jsonl"
            result = subprocess.run([sys.executable, str(PROBE.FIXTURE), "--notes", str(root),
                "--ledger", str(ledger), "--recipient", "unused"], input=frame, text=True, capture_output=True, check=True)
            self.assertEqual(ledger.read_text(), frame)
            self.assertEqual(ledger.with_suffix(".started").read_text(), "started\n")
            self.assertEqual(json.loads(result.stdout)["id"], "original-id")
            self.assertIn("UNEXPECTED-CHILD-EXECUTION", result.stdout)
            self.assertNotIn("MUST-NOT-RETURN", result.stdout)


if __name__ == "__main__":
    unittest.main()
