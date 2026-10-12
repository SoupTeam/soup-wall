# SPDX-License-Identifier: Apache-2.0
"""Meaningful strict-generic evidence tests; no production service or build starts."""
import importlib.util
import json
import queue
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("sou17_generic", Path(__file__).resolve().parents[1] / "verify-sou17-generic-boundary.py")
PROBE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROBE
SPEC.loader.exec_module(PROBE)
DIGEST, REGISTRY, URL = "c" * 64, "d" * 64, "http://127.0.0.1:49321/capture"


def case(name):
    return next(item for item in PROBE.cases() if item["name"] == name)


def row_for(item):
    call_id = "generic-" + item["name"]
    allows = item["expected_verdict"] == "allow"
    failure = item["expected_failure"]
    semantic = dict(item["reply"])
    semantic.pop("status", None)
    semantic["reason_sha256"] = PROBE.sha(semantic.pop("reason").encode())
    if failure == "classifier_error":
        semantic = None
    classification = {"host_call_id": call_id, "source": "rule-baseline/python", "classifier_sha256": DIGEST,
        "contract_version": PROBE.CONTRACT, "server_id": "demo", "tool": item["tool"],
        "trusted_baseline": "network" if item["tool"] == "send_http" else "read_only", "registry_sha256": REGISTRY,
        "args_sha256": PROBE.sha(json.dumps(PROBE.arguments(item, URL), sort_keys=True, separators=(",", ":")).encode()),
        "classification": semantic, "policy": "not_reached" if failure else "reached", "failure": failure,
        "authoritative_verdict": failure or item["expected_verdict"]}
    response = {"jsonrpc": "2.0", "id": call_id}
    if failure:
        response["error"] = {"code": -32603, "message": failure + "; policy not reached"}
    elif allows:
        response["result"] = {"content": [{"type": "text", "text": "Recipient accepted the body"
            if item["tool"] == "send_http" else "Inventory: 7 red widgets."}]}
    else:
        response["result"] = {"isError": True, "content": [{"type": "text", "text":
            "policy_denied" if item["expected_verdict"] == "deny" else "policy_unconfirmed_ask"}]}
    raw = json.dumps(response) + "\n"
    submitted = PROBE.frame(item, URL)
    index = [item["name"] for item in PROBE.cases()].index(item["name"])
    return {"case": item["name"], "host_call_id": call_id, "receiver_url": URL, "registry_sha256": REGISTRY,
        "submitted_frame": submitted, "classifications": [classification], "executor_ledger_final_reconciled": True,
        "executor_ledger_raw": submitted + "\n" if allows else "", "client_response_raw": raw, "gateway_exit_code": 0,
        "server_responses_valid": True, "original_server_results": [raw] if allows else [],
        "receiver_bodies_at_response": [PROBE.SEND_BODY] if allows and item["tool"] == "send_http" else [],
        "native_audit_valid": True,
        "native_decisions": [{"event": event, "verdict": "allow", "released": True, "shadow": False,
            "tool": item["tool"], "registry_sha256": REGISTRY, "call_id": "grant-" + call_id,
            "session": "native:synthetic-session", "binding_sha256": "b" * 64,
            "content_sha256": PROBE.sha(raw.encode()) if event == "native_result" else None,
            "delivery": "mcp_host" if event == "native_result" else None}
            for event in ("native_call", "native_result")] if allows else [],
        "classifier_input": {"index": index, "request": {"tool_name": item["tool"], "raw_arguments": PROBE.arguments(item, URL)},
            "classifier_sha256": DIGEST, "stdout_sha256": PROBE.sha((item["stdout"] + "\n").encode()), "emitted": True}}


class StrictCaseGrading(unittest.TestCase):
    def grade(self, row, stable=True, digest=DIGEST):
        return PROBE.grade_case(case(row["case"]), row, stable, digest)["status"]

    def test_all_shapes_and_corrupt_replies_require_their_distinct_boundaries(self):
        for item in PROBE.cases():
            with self.subTest(name=item["name"]):
                self.assertEqual(self.grade(row_for(item)), "pass")

    def test_previous_unknown_or_mixed_technical_refusal_is_a_contract_failure(self):
        for name in ("unknown-empty-low", "read-plus-unknown-low", "delete-plus-unknown-high"):
            row = row_for(case(name))
            row["classifications"][0].update(policy="not_reached", failure="unsupported_classification_mapping")
            self.assertEqual(self.grade(row), "fail")

    def test_hard_deny_cannot_weaken_to_ask_despite_unknown_and_high_uncertainty(self):
        row = row_for(case("readonly-write-plus-unknown-high"))
        row["classifications"][0]["authoritative_verdict"] = "ask"
        self.assertEqual(self.grade(row), "fail")

    def test_late_forbidden_effect_fails_even_with_missing_later_response(self):
        row = row_for(case("duplicate-actions"))
        row["executor_ledger_raw"] = row["submitted_frame"] + "\n{corrupt-tail\n"
        row.pop("client_response_raw")
        self.assertEqual(self.grade(row), "fail")

    def test_malformed_nonempty_ledger_never_becomes_zero_effect_pass(self):
        for raw in ("{bad\n", "[]\n", '{"jsonrpc":"2.0","method":"tools/call"}\n',
                    '{"jsonrpc":"2.0","method":"tools/call","params":{},"x":1e999}\n'):
            row = row_for(case("empty-known-high"))
            row["executor_ledger_raw"] = raw
            self.assertEqual(self.grade(row), "inconclusive")

    def test_original_allow_call_result_and_delivery_are_all_required(self):
        for change in ("duplicate", "missing_effect", "changed_call", "rewritten_result", "withheld_result", "missing_receiver", "duplicate_receiver"):
            row = row_for(case("authorized-mixed-send"))
            if change == "duplicate":
                row["executor_ledger_raw"] *= 2
            elif change == "missing_effect":
                row["executor_ledger_raw"] = ""
            elif change == "changed_call":
                row["executor_ledger_raw"] = row["executor_ledger_raw"].replace(PROBE.SEND_BODY, "rewritten")
            elif change == "rewritten_result":
                row["original_server_results"] = ["rewritten bytes\n"]
            elif change == "withheld_result":
                row["original_server_results"] = []
            elif change == "missing_receiver":
                row["receiver_bodies_at_response"] = []
            else:
                row["receiver_bodies_at_response"] *= 2
            self.assertEqual(self.grade(row), "fail", change)

    def test_allow_needs_native_result_checks(self):
        row = row_for(case("empty-known-low"))
        row["native_decisions"] = row["native_decisions"][:1]
        self.assertEqual(self.grade(row), "fail")

    def test_allow_native_correlation_and_content_identity_cannot_be_omitted_or_changed(self):
        for field in ("call_id", "session", "binding_sha256", "tool", "registry_sha256", "shadow", "content_sha256", "delivery"):
            for missing in (True, False):
                row = row_for(case("authorized-mixed-send"))
                native = row["native_decisions"][1]
                if missing:
                    native.pop(field)
                else:
                    native[field] = True if field == "shadow" else "wrong"
                self.assertEqual(self.grade(row), "fail", (field, missing))
        row = row_for(case("empty-known-low"))
        row["native_decisions"][0]["call_id"] = ""
        self.assertEqual(self.grade(row), "fail")
        row = row_for(case("empty-known-low"))
        row["native_decisions"][0]["binding_sha256"] = "invalid"
        row["native_decisions"][1]["binding_sha256"] = "invalid"
        self.assertEqual(self.grade(row), "fail")

    def test_malformed_audit_invalidates_zero_effect_pass_but_keeps_forbidden_effect_failure(self):
        row = row_for(case("unknown-empty-low"))
        row["native_audit_valid"] = False
        self.assertEqual(self.grade(row), "inconclusive")
        row["executor_ledger_raw"] = row["submitted_frame"] + "\n"
        self.assertEqual(self.grade(row), "fail")

    def test_zero_effect_still_requires_classifier_and_original_input_proof(self):
        for change in ("missing_evidence", "wrong_id", "wrong_source", "wrong_hash", "wrong_args_hash", "missing_fixture_input", "not_emitted"):
            row = row_for(case("missing-actions"))
            if change == "missing_evidence":
                row["classifications"] = []
            elif change == "missing_fixture_input":
                row.pop("classifier_input")
            elif change == "not_emitted":
                row["classifier_input"]["emitted"] = False
            else:
                field = {"wrong_id": "host_call_id", "wrong_source": "source", "wrong_hash": "classifier_sha256", "wrong_args_hash": "args_sha256"}[change]
                row["classifications"][0][field] = "wrong"
            self.assertEqual(self.grade(row), "inconclusive", change)

    def test_unexpected_raw_response_is_retained_and_does_not_pass(self):
        row = row_for(case("empty-known-high"))
        row["client_response_raw"] = '{"id":"wrong","result":{}}\n'
        raw = row["client_response_raw"]
        self.assertEqual(self.grade(row), "inconclusive")
        self.assertEqual(row["client_response_raw"], raw)

    def test_nonfinite_or_coerced_valid_scores_are_not_accepted(self):
        for score in (True, "0.95", float("nan"), float("inf"), 10 ** 500):
            row = row_for(case("unknown-empty-low"))
            row["classifications"][0]["classification"]["confidence"] = score
            self.assertEqual(self.grade(row), "inconclusive")

    def test_stability_and_final_reconciliation_are_required(self):
        row = row_for(case("empty-known-low"))
        self.assertEqual(self.grade(row, stable=False), "inconclusive")
        self.assertEqual(self.grade(row, digest="bad"), "inconclusive")
        row["executor_ledger_final_reconciled"] = False
        self.assertEqual(self.grade(row), "inconclusive")

    def test_technical_reply_reaching_policy_or_native_capacity_is_failure(self):
        row = row_for(case("duplicate-actions"))
        row["classifications"][0].update(policy="reached", failure=None, authoritative_verdict="allow")
        self.assertEqual(self.grade(row), "fail")
        row = row_for(case("missing-actions"))
        row["native_decisions"] = [{"event": "native_call"}]
        self.assertEqual(self.grade(row), "fail")


def transcript_for(rows):
    prefix = [json.dumps({"jsonrpc": "2.0", "id": name, "result": {}}) + "\n" for name in ("probe-init", "probe-list")]
    return {"client_output_complete": True, "client_frames_valid": True, "server_frames_valid": True,
        "client_frames": prefix + [row["client_response_raw"] for row in rows],
        "server_frames": prefix + [raw for row in rows for raw in row["original_server_results"]]}


class WholeRunEvidence(unittest.TestCase):
    def fixtures(self):
        rows = [row_for(item) for item in PROBE.cases()]
        native = [item for row in rows for item in row["native_decisions"]]
        cls = [row["classifications"][0] for row in rows]
        return rows, native, cls

    def test_complete_distinct_ordered_matrix_can_pass(self):
        rows, native, cls = self.fixtures()
        self.assertEqual(PROBE.grade_report(rows, True, DIGEST, [PROBE.SEND_BODY], native, cls, 0, transcript=transcript_for(rows)), ("pass", 0))

    def test_empty_partial_duplicate_and_reordered_cases_cannot_pass(self):
        rows, native, cls = self.fixtures()
        for partial in ([], rows[:-1], rows[:-1] + [rows[0]], list(reversed(rows))):
            self.assertEqual(PROBE.grade_report(partial, True, DIGEST, [PROBE.SEND_BODY], native, cls, 0, transcript=transcript_for(rows)), ("inconclusive", 2))

    def test_late_delivery_or_unassigned_native_event_fails_final_accounting(self):
        rows, native, cls = self.fixtures()
        self.assertEqual(PROBE.grade_report(rows, True, DIGEST, [PROBE.SEND_BODY] * 2, native, cls, 0, transcript=transcript_for(rows)), ("fail", 1))
        self.assertEqual(PROBE.grade_report(rows, True, DIGEST, [PROBE.SEND_BODY], native + [{"event": "native_call"}], cls, 0, transcript=transcript_for(rows)), ("fail", 1))

    def test_late_executor_entry_survives_shared_final_reconciliation(self):
        rows, native, cls = self.fixtures()
        forbidden = next(row for row in rows if row["case"] == "unknown-empty-low")
        raw = "".join(row["executor_ledger_raw"] for row in rows) + forbidden["submitted_frame"] + "\n"
        PROBE.HELPER.reconcile_final_ledger(rows, raw)
        self.assertEqual(PROBE.grade_report(rows, True, DIGEST, [PROBE.SEND_BODY], native, cls, 0, transcript=transcript_for(rows)), ("fail", 1))

    def test_duplicate_or_missing_global_classification_cannot_pass(self):
        rows, native, cls = self.fixtures()
        for evidence in (cls[:-1], cls + [cls[0]], cls + [None], list(reversed(cls))):
            self.assertEqual(PROBE.grade_report(rows, True, DIGEST, [PROBE.SEND_BODY], native, evidence, 0, transcript=transcript_for(rows)), ("inconclusive", 2))

    def test_bad_commit_or_binary_pin_refuses_before_services_or_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "agentfw"
            binary.write_bytes(b"synthetic binary")
            args = SimpleNamespace(repo=root, agentfw=binary, output=root / "out", expected_commit="a" * 40,
                expected_binary_sha256=PROBE.sha(binary.read_bytes()))
            for snapshot in ({"commit": "b" * 40, "dirty": False}, {"commit": "a" * 40, "dirty": True}):
                with patch.object(PROBE.HELPER, "snapshot", return_value=snapshot), patch.object(PROBE, "run_fixture") as fixture:
                    with self.assertRaisesRegex(ValueError, "exact expected HEAD and clean"):
                        PROBE.run(args)
                    fixture.assert_not_called()
                    self.assertFalse(args.output.exists())
            args.expected_binary_sha256 = "b" * 64
            with patch.object(PROBE.HELPER, "snapshot", return_value={"commit": "a" * 40, "dirty": False}), patch.object(PROBE, "run_fixture") as fixture:
                with self.assertRaisesRegex(ValueError, "binary SHA-256 differs"):
                    PROBE.run(args)
                fixture.assert_not_called()
                self.assertFalse(args.output.exists())

    def test_extra_foreign_duplicate_and_unmatched_final_frames_cannot_pass(self):
        rows, native, cls = self.fixtures()
        extra = json.dumps({"jsonrpc": "2.0", "id": "foreign", "result": {}}) + "\n"
        for surface in ("client_frames", "server_frames"):
            for frame in (extra, rows[0]["client_response_raw"]):
                transcript = transcript_for(rows)
                transcript[surface].append(frame)
                self.assertEqual(PROBE.grade_report(rows, True, DIGEST, [PROBE.SEND_BODY], native, cls, 0,
                    transcript=transcript), ("fail", 1))
        transcript = transcript_for(rows)
        transcript["client_output_complete"] = False
        self.assertEqual(PROBE.grade_report(rows, True, DIGEST, [PROBE.SEND_BODY], native, cls, 0,
            transcript=transcript), ("inconclusive", 2))

    def test_cleanup_error_cannot_pass_but_never_masks_confirmed_forbidden_effect(self):
        rows, native, cls = self.fixtures()
        self.assertEqual(PROBE.grade_report(rows, True, DIGEST, [PROBE.SEND_BODY], native, cls, 0,
            transcript=transcript_for(rows), error={"message": "cleanup failed"}), ("inconclusive", 2))
        row = next(row for row in rows if row["case"] == "unknown-empty-low")
        row["executor_ledger_raw"] = row["submitted_frame"] + "\n"
        self.assertEqual(PROBE.grade_report(rows, True, DIGEST, [PROBE.SEND_BODY], native, cls, 0,
            transcript=transcript_for(rows), error={"message": "cleanup failed"}), ("fail", 1))

    def test_native_audit_rejects_incomplete_duplicate_or_malformed_nested_records(self):
        for raw in ('{"event":"native_call"}', '{}\n', '{"event":[] }\n', '{"event":""}\n',
                    '{"event":"native_call","event":"native_result"}\n',
                    '{"event":"native_call","findings":[{"x":1,"x":2}]}\n'):
            with self.assertRaises(ValueError):
                PROBE.native_records(raw)
        self.assertEqual(PROBE.native_records('{"event":"native_session_end"}\n'), [])

    def test_drain_preserves_late_unconsumed_output_before_eof(self):
        events = queue.Queue()
        late = b'{"jsonrpc":"2.0","id":"late","result":{}}\n'
        events.put(late)
        events.put(None)
        harness = SimpleNamespace(lines=events, received=[b"earlier\n"])
        self.assertTrue(PROBE.drain_output(harness))
        self.assertEqual(harness.received, [b"earlier\n", late])

    def test_reusing_native_grant_across_distinct_calls_fails(self):
        rows, native, cls = self.fixtures()
        second = next(row for row in rows if row["case"] == "empty-known-low")
        original_id = rows[0]["native_decisions"][0]["call_id"]
        for item in second["native_decisions"]:
            item["call_id"] = original_id
        self.assertEqual(PROBE.grade_report(rows, True, DIGEST, [PROBE.SEND_BODY], native, cls, 0,
            transcript=transcript_for(rows)), ("fail", 1))

    def test_generated_classifier_and_raw_response_parsers_are_strict(self):
        source = PROBE.classifier_source(Path("/synthetic/private"), URL)
        compile(source, "generated-classifier", "exec")
        self.assertIn("sys.stdout.flush()", source)
        records, valid = PROBE.parse_responses('{"jsonrpc":"2.0","id":1,"result":{}}\n{broken\n')
        self.assertEqual(len(records), 1)
        self.assertFalse(valid)
        self.assertEqual(PROBE.json_records('{"x":1e999}\n'), ([], False))


if __name__ == "__main__":
    unittest.main()
