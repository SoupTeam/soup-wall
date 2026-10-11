# SPDX-License-Identifier: Apache-2.0
"""Regressions for status evidence that must not invent execution or protection."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-sou18-status.py"
SPEC = importlib.util.spec_from_file_location("sou18_status_test", SCRIPT)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


def observation(expected):
    call_id = "test-call"
    frame = PROBE.call_frame(call_id, "read_document", {"name": "inventory"}, 1)
    reply = {"jsonrpc": "2.0", "id": call_id,
             "result": {"content": [{"type": "text", "text": "Inventory: 7 red widgets."}]}}
    response = json.dumps(reply) + "\n"
    row = {"call_id": call_id, "submitted_frame": frame, "expected": expected, "actual": expected,
           "preflight_exit": {"unavailable": 2, "shadow": 4}.get(expected, 0),
           "executor_raw": "", "server_result_raw": "", "released_raw": "", "receiver_count": 0,
           "collector_exit": None, "classifier_matches_revision": True}
    if expected == "allow":
        row.update(executor_raw=frame + "\n", server_result_raw=response, released_raw=response)
    elif expected == "result_withheld":
        reply["result"]["content"][0]["text"] = "MARKER-PRIVATE-FIXTURE"
        row.update(executor_raw=frame + "\n", server_result_raw=json.dumps(reply) + "\n")
        reply["result"] = {"content": [{"type": "text", "text": "Soup Wall withheld MCP result (demo-result-injection)"}], "isError": True}
        row["released_raw"] = json.dumps(reply) + "\n"
    elif expected in {"deny", "ask"}:
        reason = "policy_denied" if expected == "deny" else "policy_unconfirmed_ask"
        reply["result"] = {"isError": True, "content": [{"type": "text", "text": f"Soup Wall withheld MCP invocation ({reason})"}]}
        row["released_raw"] = json.dumps(reply) + "\n"
    else:
        row["collector_exit"] = 1
    return row


class StatusEvidenceTests(unittest.TestCase):
    def test_default_starts_nothing(self):
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout)["processes_started"], 0)

    def test_original_frame_keeps_native_id_arguments_and_numeric_progress(self):
        args = {"name": "inventory"}
        frame = json.loads(PROBE.call_frame("string-id", "read_document", args, 3))
        self.assertEqual(frame["id"], "string-id")
        self.assertEqual(frame["params"]["arguments"], args)
        self.assertIs(type(frame["params"]["_meta"]["progressToken"]), int)
        self.assertEqual(args, {"name": "inventory"})

    def test_each_expected_state_requires_its_independent_witnesses(self):
        for expected in ("allow", "deny", "ask", "result_withheld", "unavailable", "shadow"):
            with self.subTest(expected=expected):
                self.assertEqual(PROBE.grade(observation(expected))["status"], "pass")

    def test_healthy_preflight_without_actual_execution_or_original_result_fails(self):
        for field in ("executor_raw", "server_result_raw", "released_raw"):
            row = observation("allow")
            row[field] = ""
            self.assertEqual(PROBE.grade(row)["status"], "fail")
        row = observation("allow")
        row["executor_raw"] *= 2
        self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_denied_asked_outage_and_shadow_cannot_hide_an_execution(self):
        for expected in ("deny", "ask", "unavailable", "shadow"):
            row = observation(expected)
            row["executor_raw"] = row["submitted_frame"] + "\n"
            self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_mismatched_status_identity_arguments_and_classifier_fail(self):
        for mutation in (
            lambda row: row.update(preflight_exit=4),
            lambda row: row.update(classifier_matches_revision=False),
            lambda row: row.update(released_raw=row["released_raw"].replace("test-call", "other")),
            lambda row: row.update(executor_raw=row["executor_raw"].replace("inventory", "different")),
            lambda row: row.update(receiver_count=1),
            lambda row: row.update(receiver_count=False),
        ):
            row = observation("allow")
            mutation(row)
            self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_result_blocking_requires_a_real_produced_result_and_no_marker_release(self):
        for mutation in (
            lambda row: row.update(server_result_raw=""),
            lambda row: row.update(server_result_raw=row["server_result_raw"].replace("test-call", "other")),
            lambda row: row.update(released_raw=row["server_result_raw"]),
            lambda row: row.update(executor_raw=""),
        ):
            row = observation("result_withheld")
            mutation(row)
            self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_unrelated_errors_are_not_policy_refusals(self):
        for expected in ("deny", "ask", "result_withheld"):
            row = observation(expected)
            row["released_raw"] = json.dumps({"jsonrpc": "2.0", "id": "test-call", "error": {"message": "unrelated error"}})
            self.assertEqual(PROBE.grade(row)["status"], "fail")

    def test_missing_response_or_unterminated_collector_never_proves_loss_protection(self):
        for value in (None, 0, False):
            row = observation("unavailable")
            row["collector_exit"] = value
            self.assertEqual(PROBE.grade(row)["status"], "fail")
        self.assertEqual(PROBE.grade({})["status"], "fail")

    def test_environment_is_restored_on_failure_and_credentials_are_not_inherited(self):
        original = dict(os.environ)
        with self.assertRaises(RuntimeError):
            with PROBE.private_environment({"HOME": "temporary-profile"}):
                self.assertEqual(dict(os.environ), {"HOME": "temporary-profile"})
                raise RuntimeError("owned fixture failed")
        self.assertEqual(dict(os.environ), original)

    def test_complete_case_set_stability_cleanup_and_final_witnesses_are_required(self):
        report = {"rows": [{"call_id": name, "status": "pass"} for name in PROBE.CASE_IDS],
                  "final_ledger_matches": True, "inventory_preserved": True, "receiver_final_count": 0,
                  "source_binary_stable": True, "owned_profile_removed": True}
        self.assertTrue(PROBE.verified(report))
        for name in ("final_ledger_matches", "inventory_preserved", "source_binary_stable", "owned_profile_removed"):
            broken = copy.deepcopy(report)
            broken[name] = False
            self.assertFalse(PROBE.verified(broken))
        broken = copy.deepcopy(report)
        broken["rows"][0] = broken["rows"][1]
        self.assertFalse(PROBE.verified(broken))
        broken = copy.deepcopy(report)
        broken["error"] = "late observation failure"
        self.assertFalse(PROBE.verified(broken))


if __name__ == "__main__":
    unittest.main()
