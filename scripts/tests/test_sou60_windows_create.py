#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Portable grader controls, explicitly not native Windows execution evidence."""
from __future__ import annotations
import copy
import importlib.util
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify-sou60-windows-create.py"
spec = importlib.util.spec_from_file_location("sou60_grader_controls", SCRIPT)
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)
spec = importlib.util.spec_from_file_location("sou60_ci_diagnostics", ROOT / "scripts/print-sou60-ci-diagnostics.py")
DIAGNOSTICS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DIAGNOSTICS)


def line(value):
    return D.canonical(value).decode() + "\n"


def reply(identifier, text, error=False):
    return line({"jsonrpc": "2.0", "id": identifier, "result": {"isError": error, "content": [{"type": "text", "text": text}]}})


def notification_batch(records):
    parts = []
    for index, item in enumerate(records):
        text = item["name"].encode("utf-16-le")
        size = 12 + len(text)
        padded = (size + 3) & ~3
        parts.append(struct.pack("<III", padded if index + 1 < len(records) else 0, item["action"], len(text))
                     + text + b"\x00" * (padded - size))
    raw = b"".join(parts)
    return {"raw_hex": raw.hex(), "sha256": D.sha(raw), "records": records}


def passing_row(name="native-deny"):
    content = "" if name == "empty-content" else "x" * D.MAX_BYTES if name == "byte-limit" else (
        "🥣" * (D.MAX_BYTES // 4 + 1) if name == "utf8-over-byte-limit" else D.TEXT)
    target = D.INJECTION + ".txt" if name == "result-withheld" else "created.txt"
    args = {"path": ("C:\\Owned\\Workspace\\" + target if name == "utf8-absolute" else target), "content": content}
    configuration = D.registry(Path("C:/Owned/Workspace"), Path("C:/Owned/Workspace") / target, "c" * 64)
    row = {"case": name, "error": None, "owned_fixture_removed": True, "sessions": [],
           "standard_user_sid": "S-1-5-21-1-2-3-1001", "target_relative": target,
           "expected_content_bytes": len(content.encode()), "expected_content_sha256": D.sha(content.encode()),
           "classifier_sha256": "c" * 64, "workspace_identity": {"volume_serial": 7, "file_id": [1] * 16}, "relay": [], "collector_raw": "", "native_audit_raw": "",
           "configuration": {"registry": configuration, "registry_sha256": D.sha(D.canonical(configuration)),
                             "policy": D.policy_for(name), "policy_sha256": D.sha(D.policy_for(name).encode())}}
    file = {"kind": stat.S_IFREG, "attributes": 32, "inode": 12, "device": 7, "links": 1,
            "bytes": len(D.READ_TEXT.encode()), "sha256": D.sha(D.READ_TEXT.encode())}
    before = {".": {"kind": stat.S_IFDIR, "attributes": 16, "inode": 11, "device": 7, "links": 1}, "inventory.txt": file}
    if name in {"existing-file", "hard-link", "directory"}:
        before[target] = dict(file, inode=14)
    row["workspace_before"] = before
    row["workspace_after"] = copy.deepcopy(before)
    row["outside_before"] = {"canary.txt": copy.deepcopy(file)}
    row["outside_after"] = copy.deepcopy(row["outside_before"])
    if name in D.SUCCESS:
        row["workspace_after"][target] = dict(file, inode=13, bytes=len(content.encode()), sha256=D.sha(content.encode()))
    if name == "competing-creator":
        row["workspace_after"][target] = dict(file, inode=14, bytes=len(D.COMPETITOR), sha256=D.sha(D.COMPETITOR))
        row["workspace_before_release"] = copy.deepcopy(row["workspace_after"])
        row["competing_creator"] = {"after_authentic_allow": True, "bytes": len(D.COMPETITOR), "sha256": D.sha(D.COMPETITOR)}
    # Controls contain plausible retained OS bytes; only the real driver can
    # acquire them. A synthetic control passing is never native acceptance.
    records, batches, barriers = [], [], []
    def barrier(label, effects=()):
        barrier_name = ".sou60-" + label + "-controlled"
        start = len(records)
        batch = list(effects) + [{"action": 1, "name": barrier_name}, {"action": 2, "name": barrier_name}]
        records.extend(batch)
        batches.append(notification_batch(batch))
        item = {"label": label, "name": barrier_name, "start": start, "end": len(records), "events": batch}
        barriers.append(item)
        return item
    calibration = barrier("calibration")
    if name in D.HELD:
        barrier("heldallow")
        row["pre_allow_events"] = []
        row["workspace_at_held_allow"] = copy.deepcopy(before)
    if name == "competing-creator":
        row["owned_actor_events"] = [{"action": 1, "name": target}]
        barrier("ownedactor", row["owned_actor_events"])
    row["attempt_events"] = ([{"action": 1, "name": ".soup-wall-create-owned.tmp"}, {"action": 1, "name": target},
                              {"action": 2, "name": ".soup-wall-create-owned.tmp"}] if name in D.SUCCESS else [])
    barrier("attemptdone", row["attempt_events"])
    row["write_watch"] = {"method": "ReadDirectoryChangesW/1", "queued_before_agent": True, "complete": True,
                          "calibration": calibration, "barriers": barriers, "batches": batches,
                          "cancellation_drained": True, "error": None}
    create_receipt = {"success": True, "created": True, "committed": True, "path": args["path"],
                      "bytes_written": len(content.encode()), "content_sha256": D.sha(content.encode()),
                      "file_synced": True, "directory_synced": False}
    if name in D.SUCCESS:
        inspected = reply("probe", D.canonical(create_receipt).decode())
        actual = reply("probe", "Soup Wall withheld MCP result", True) if name == "result-withheld" else inspected
    else:
        reason = ("sou60-explicit-" + name[7:] if name in {"native-deny", "native-ask"} else
                  "policy_denied" if name == "classifier-deny" else "policy_unconfirmed_ask" if name == "classifier-ask" else "refused")
        inspected = actual = reply("probe", reason, True)
    if name == "competing-creator":
        failure = {"success": False, "created": False, "committed": False, "staged_bytes": 0,
                   "committed_bytes": 0, "error": "target_exists"}
        inspected = actual = reply("probe", D.canonical(failure).decode(), True)
    if name in D.ABNORMAL:
        actual = ""
    row["attack"] = {"request": D.H.frame("probe", "create_file", args), "reply_raw": actual, "latency_ms": 1.2}
    row["followup_raw"] = reply("useful-followup", D.READ_TEXT)
    initialization = line({"jsonrpc": "2.0", "id": "init", "result": {}})
    listing = line({"jsonrpc": "2.0", "id": "list", "result": {"tools": D.F.TOOLS}})
    labels = ["primary", "fresh-after-refusal"] if name in D.ABNORMAL else ["primary"]
    native = []
    epoch_for = {"session-" + label: "native:controlled-epoch-" + label for label in labels}
    next_sequence = {epoch: 1 for epoch in epoch_for.values()}
    for index, label in enumerate(labels):
        session_id = "session-" + label
        primary_abnormal = name in D.ABNORMAL and label == "primary"
        fatal = primary_abnormal or name == "replayed-id"
        client = initialization + listing
        if not primary_abnormal:
            if name not in D.ABNORMAL:
                client += actual
            client += row["followup_raw"]
        row["sessions"].append({"label": label, "client_raw": client,
            "closure": {"exit_code": 1 if fatal else 0, "stdout_eof": True, "reader_joined": True, "forced_cleanup": False},
            "child_process": {"pid": 100 + index, "handle_bound_before_invocation": True, "exit_observed": True, "exit_code": 0},
            "child_ledger_present": True, "child_ledger_raw": "", "child_started_raw": "started\n", "child_closed_raw": "closed\n",
            "child_input_raw": line({"method": "initialize"}) + line({"method": "notifications/initialized"}) + line({"method": "tools/list"}),
            "child_output_raw": initialization + listing})
        native.append({"event": "native_session_start", "session": epoch_for[session_id], "seq": 1,
                       "registry_sha256": row["configuration"]["registry_sha256"], "released": True, "shadow": False})
    def relay(original, forwarded=None, response=None, **extra):
        raw, forwarded_raw = D.canonical(original).decode(), D.canonical(forwarded or original).decode()
        row["relay"].append(dict(original_raw=raw, forwarded_raw=forwarded_raw,
            original_sha256=D.sha(raw.encode()), forwarded_sha256=D.sha(forwarded_raw.encode()), **extra))
        if response is not None:
            raw_reply = D.canonical(response).decode()
            row["relay"][-1].update(reply_raw=raw_reply, reply_sha256=D.sha(raw_reply.encode()))
        return row["relay"][-1]
    for label in labels:
        client_session = "session-" + label
        relay({"event": "session_start", "contract_version": "sw-native/1", "session_id": client_session}, response={
            "event": "session_start", "contract_version": "sw-native/1", "session_id": client_session,
            "registry_sha256": row["configuration"]["registry_sha256"], "release": True, "enforced": True, "verdict": "allow"})
    def boundary(host, arguments, contract, content_raw, released=True, grant=True):
        session = "session-" + ("fresh-after-refusal" if host == "useful-followup" and name in D.ABNORMAL else "primary")
        request = {"event": "call", "contract_version": contract, "args": arguments, "session_id": session,
                   "tool": "read_document" if host == "useful-followup" else "create_file",
                   "schema_sha256": D.sha(D.canonical(D.F.READ_SCHEMA if host == "useful-followup" else D.F.CREATE_SCHEMA)),
                   "resource_admission": {"host_call_id": host}}
        policy = configuration["tools"][1 if host == "useful-followup" else 0]["resource_policy"]
        resources = [{"pointer": "/path", "source": "argument", "resource": policy["allowed_resources"][0]}]
        request["resource_admission"].update(server_id="sou60", resources=resources, executor_sha256=policy["executor_sha256"],
            classifier_sha256=row["classifier_sha256"], profile_sha256=D.sha(D.canonical(policy["profile"])))
        if host == "probe":
            request["resource_admission"]["execution"] = dict(policy["execution"], policy_sha256=D.sha(D.canonical(policy)),
                args_sha256=D.sha(D.canonical(arguments)), content_sha256=D.sha(arguments["content"].encode()),
                workspace_sha256=D.sha(D.canonical(dict(workspace=policy["workspace"], cwd=policy["cwd"], **row["workspace_identity"]))))
        grant_value = {"session_id": session, "contract_version": contract, "event": "call", "resources_sha256": D.sha(D.canonical(resources)), "call_id": host + "-native", "enforced": True, "release": grant,
                       "verdict": "allow" if grant else "deny", "registry_sha256": row["configuration"]["registry_sha256"],
                       "binding_sha256": D.native_binding(row["configuration"]["registry_sha256"], epoch_for[session], request)}
        forwarded = copy.deepcopy(request)
        if host == "probe":
            if name == "native-args-mismatch":
                forwarded["args"]["path"] += ".substituted"
            if name == "native-content-mismatch":
                forwarded["args"]["content"] += "SUBSTITUTED"
            if name == "native-session-mismatch":
                forwarded["session_id"] = "other-session"
        call = relay(request, forwarded, grant_value)
        if host == "probe" and name in D.HELD:
            call.update(held_allow=True, released_unchanged=True)
        if host == "probe" and name == "daemon-loss":
            call["owned_daemon_stopped"] = True
        next_sequence[epoch_for[session]] += 1
        native.append({"event": "native_call", "call_id": grant_value["call_id"], "session": epoch_for[session],
                       "seq": next_sequence[epoch_for[session]], "registry_sha256": row["configuration"]["registry_sha256"],
                       "binding_sha256": grant_value["binding_sha256"], "released": grant, "shadow": False,
                       "verdict": "allow" if grant else "deny"})
        if grant and content_raw is not None:
            completion = {"event": "result", "contract_version": contract, "args": arguments, "session_id": session,
                          "call_id": grant_value["call_id"], "content": content_raw}
            completion_reply = dict(grant_value, event="result", release=released, content_sha256=D.sha(content_raw.encode()))
            relay(completion, response=completion_reply)
            next_sequence[epoch_for[session]] += 1
            native.append({"event": "native_result", "call_id": grant_value["call_id"], "session": epoch_for[session],
                           "seq": next_sequence[epoch_for[session]], "registry_sha256": row["configuration"]["registry_sha256"],
                           "released": released, "shadow": False, "verdict": "allow" if released else "deny",
                           "binding_sha256": grant_value["binding_sha256"], "content_sha256": D.sha(content_raw.encode())})
    if name in D.SUCCESS | {"competing-creator"}:
        boundary("probe", args, D.CONTRACT, inspected, released=name != "result-withheld")
    elif name in {"native-deny", "native-ask", "native-args-mismatch", "native-content-mismatch"} | D.ABNORMAL:
        boundary("probe", args, D.CONTRACT, None, grant=name == "queued-cancellation")
    boundary("useful-followup", {"path": "inventory.txt"}, D.READ_CONTRACT, row["followup_raw"])
    for label in labels:
        if name != "daemon-loss" or label != "primary":
            epoch = epoch_for["session-" + label]
            native.append({"event": "native_session_end", "session": epoch, "seq": next_sequence[epoch] + 1})
    row["native_audit_raw"] = "".join(line(item) for item in native)
    for host in (["probe"] if name not in D.EARLY_REFUSALS else []) + ["useful-followup"]:
        useful = host == "useful-followup"
        verdict = "deny" if not useful and name == "classifier-deny" else "ask" if not useful and name == "classifier-ask" else "allow"
        row["collector_raw"] += line({"event": "mcp_classification", "host_call_id": host, "source": "rule-baseline/python",
            "classifier_sha256": row["classifier_sha256"], "registry_sha256": row["configuration"]["registry_sha256"],
            "schema_sha256": D.sha(D.canonical(D.F.READ_SCHEMA if useful else D.F.CREATE_SCHEMA)),
            "args_sha256": D.sha(D.canonical({"path": "inventory.txt"} if useful else args)),
            "server_id": "sou60", "tool": "read_document" if useful else "create_file", "authoritative_verdict": verdict,
            "operator_execution_profile": None if useful else D.PROFILE,
            "classification": {"actions": ["read"] if useful else ["delete"] if name == "classifier-deny" else ["write"]}})
    if name in D.SUCCESS | {"competing-creator"}:
        if name in D.SUCCESS:
            row["collector_raw"] += line({"event": "mcp_create_file_publication_intent", "host_call_id": "probe",
                "publication_attempted": True, "staged_bytes": len(content.encode()), "outcome": "indeterminate_until_completion"})
        row["collector_raw"] += line({"event": "mcp_create_file_execution", "host_call_id": "probe",
            "committed": name in D.SUCCESS, "committed_bytes": len(content.encode()) if name in D.SUCCESS else 0,
            "staged_bytes": None if name in D.SUCCESS else 0, "result_kind": "value" if name in D.SUCCESS else "error",
            "error": None if name in D.SUCCESS else "target_exists"})
    if name == "replayed-id":
        row.update(replayed_reply_raw="", replay_terminated=True)
    return row


class WindowsCreateGradingControls(unittest.TestCase):
    def assertFails(self, row):
        self.assertEqual(D.grade(row)["status"], "fail", D.grade(row))

    def test_all_reviewed_control_shapes_pass(self):
        for name in D.CASES:
            with self.subTest(case=name):
                self.assertEqual(D.grade(passing_row(name))["status"], "pass", D.grade(passing_row(name)))

    def test_allowed_create_requires_exact_receipt_durability_and_bytes(self):
        for field, value in (("directory_synced", True), ("file_synced", False), ("committed", False),
                             ("bytes_written", 1), ("path", "other.txt"), ("content_sha256", "f" * 64)):
            row = passing_row("utf8-relative")
            reply = D.strict_json(row["attack"]["reply_raw"])
            receipt = D.strict_json(reply["result"]["content"][0]["text"])
            receipt[field] = value
            reply["result"]["content"][0]["text"] = D.canonical(receipt).decode()
            row["attack"]["reply_raw"] = line(reply)
            self.assertFails(row)

    def test_missing_original_content_identity_fails(self):
        for field, value in (("expected_content_bytes", 1), ("expected_content_sha256", "f" * 64)):
            row = passing_row()
            row[field] = value
            self.assertFails(row)

    def test_wrong_published_bytes_identity_links_or_surviving_temp_fails(self):
        for field, value in (("bytes", 1), ("sha256", "f" * 64), ("links", 2), ("attributes", 0x420), ("kind", stat.S_IFDIR)):
            row = passing_row("utf8-relative")
            row["workspace_after"][row["target_relative"]][field] = value
            self.assertFails(row)
        row = passing_row("utf8-relative")
        row["workspace_after"]["foreign-temp"] = copy.deepcopy(row["workspace_after"][row["target_relative"]])
        self.assertFails(row)

    def test_refusal_mutation_fails_even_with_no_child_call(self):
        row = passing_row("native-deny")
        row["workspace_after"]["unexpected.txt"] = copy.deepcopy(row["workspace_before"]["inventory.txt"])
        self.assertFails(row)

    def test_refusal_transient_effect_cannot_be_hidden_by_final_snapshot(self):
        row = passing_row("native-ask")
        row["attempt_events"] = [{"action": 1, "name": "unexpected-temp"}]
        self.assertFails(row)

    def test_pre_allow_mutation_fails(self):
        row = passing_row("utf8-relative")
        row["workspace_at_held_allow"]["unexpected-temp"] = {}
        self.assertFails(row)

    def test_competing_creator_must_keep_same_identity_and_bytes(self):
        for field, value in (("inode", 999), ("sha256", "f" * 64)):
            row = passing_row("competing-creator")
            row["workspace_after"][row["target_relative"]][field] = value
            self.assertFails(row)

    def test_competing_creator_requires_structured_honest_failure_accounting(self):
        for field, value in (("committed", True), ("committed_bytes", 1), ("staged_bytes", -1), ("staged_bytes", True)):
            row = passing_row("competing-creator")
            response = D.strict_json(row["attack"]["reply_raw"])
            receipt = D.strict_json(response["result"]["content"][0]["text"])
            receipt[field] = value
            response["result"]["content"][0]["text"] = D.canonical(receipt).decode()
            row["attack"]["reply_raw"] = line(response)
            self.assertFails(row)

    def test_completed_audit_cannot_hide_or_invent_committed_effect(self):
        for name in ("utf8-relative", "result-withheld", "competing-creator"):
            row = passing_row(name)
            records = D.json_lines(row["collector_raw"].encode())
            completion = next(item for item in records if item["event"] == "mcp_create_file_execution")
            completion["committed"] = name not in D.SUCCESS
            row["collector_raw"] = "".join(line(item) for item in records)
            self.assertFails(row)

    def test_missing_or_fake_publication_intent_cannot_claim_known_rollback(self):
        row = passing_row("utf8-relative")
        records = D.json_lines(row["collector_raw"].encode())
        intent = next(item for item in records if item["event"] == "mcp_create_file_publication_intent")
        intent["outcome"] = "no_effect_guaranteed"
        row["collector_raw"] = "".join(line(item) for item in records)
        self.assertFails(row)

    def test_outside_change_fails(self):
        row = passing_row()
        row["outside_after"]["canary.txt"]["sha256"] = "f" * 64
        self.assertFails(row)

    def test_notification_bytes_are_independently_decoded(self):
        for field, value in (("raw_hex", "00000000"), ("sha256", "f" * 64), ("records", [])):
            row = passing_row()
            row["write_watch"]["batches"][0][field] = value
            self.assertFails(row)

    def test_notification_overflow_invalid_utf16_and_offsets_refuse(self):
        for raw in (b"", struct.pack("<III", 0, 1, 0), struct.pack("<III", 3, 1, 2) + b"a\0",
                    struct.pack("<III", 0, 1, 2) + b"\x00\xd8"):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                D.notify_records(raw)

    def test_notification_completeness_calibration_and_drain_required(self):
        for field, value in (("queued_before_agent", False), ("complete", False), ("cancellation_drained", False), ("error", "overflow")):
            row = passing_row()
            row["write_watch"][field] = value
            self.assertFails(row)
        row = passing_row()
        row["write_watch"]["barriers"].pop()
        self.assertFails(row)

    def test_empty_effect_claim_must_match_raw_notification_epoch(self):
        row = passing_row("utf8-relative")
        row["attempt_events"] = []
        self.assertFails(row)

    def test_no_effect_cannot_be_inferred_from_missing_client_response(self):
        row = passing_row("queued-cancellation")
        row["workspace_after"]["created.txt"] = copy.deepcopy(row["workspace_before"]["inventory.txt"])
        self.assertFails(row)

    def test_policy_schema_action_and_profile_identity_required(self):
        row = passing_row()
        row["configuration"]["policy"] += "# changed\n"
        self.assertFails(row)
        for field, value in (("action_class", "read_only"), ("schema_sha256", "f" * 64), ("egress", ["external"])):
            row = passing_row()
            row["configuration"]["registry"]["tools"][0][field] = value
            self.assertFails(row)

    def test_unknown_case_cannot_pass(self):
        row = passing_row()
        row["case"] = "unknown"
        self.assertFails(row)

    def test_child_call_missing_start_close_or_exit_fails(self):
        for field, value in (("child_ledger_raw", line({"method": "tools/call"})), ("child_started_raw", ""),
                             ("child_closed_raw", ""), ("child_ledger_present", False)):
            row = passing_row()
            row["sessions"][0][field] = value
            self.assertFails(row)
        row = passing_row("queued-cancellation")
        row["sessions"][0]["child_process"]["exit_observed"] = False
        self.assertFails(row)

    def test_extra_or_reordered_client_response_fails(self):
        row = passing_row()
        row["sessions"][0]["client_raw"] += reply("extra", "extra")
        self.assertFails(row)

    def test_changed_original_native_request_reply_binding_and_result_digest_fail(self):
        for field in ("binding_sha256", "content_sha256"):
            row = passing_row()
            item = row["relay"][-1]
            value = D.strict_json(item["reply_raw"])
            value[field] = "f" * 64
            item.update(reply_raw=D.canonical(value).decode(), reply_sha256=D.sha(D.canonical(value)))
            self.assertFails(row)

    def test_correlated_audit_requires_actual_session_and_release(self):
        for field, value in (("session", "other"), ("released", False), ("shadow", True)):
            row = passing_row()
            records = D.json_lines(row["native_audit_raw"].encode())
            result = next(item for item in records if item.get("event") == "native_result")
            result[field] = value
            row["native_audit_raw"] = "".join(line(item) for item in records)
            self.assertFails(row)

    def test_real_server_epoch_differs_from_client_id_and_is_bound_by_receipt(self):
        row = passing_row("utf8-relative")
        audits = D.json_lines(row["native_audit_raw"].encode())
        call = next(D.strict_json(item["original_raw"]) for item in row["relay"]
                    if D.strict_json(item["original_raw"]).get("event") == "call")
        self.assertNotEqual(audits[0]["session"], call["session_id"])
        self.assertEqual(D.grade(row)["status"], "pass", D.grade(row))

    def test_rewriting_complete_audit_epoch_still_fails_original_receipt_binding(self):
        row = passing_row("utf8-relative")
        records = D.json_lines(row["native_audit_raw"].encode())
        old_epoch = records[0]["session"]
        for item in records:
            if item.get("session") == old_epoch:
                item["session"] = "native:substituted-valid-looking-epoch"
        row["native_audit_raw"] = "".join(line(item) for item in records)
        result = D.grade(row)
        self.assertEqual(result["status"], "fail")
        self.assertIn("native receipt does not bind server epoch and exact original call", result["check_failures"])

    def test_authenticated_native_epoch_start_is_required(self):
        for field, value in (("enforced", False), ("contract_version", "sw-native/resources/5")):
            with self.subTest(field=field):
                row = passing_row("utf8-relative")
                item = next(item for item in row["relay"] if D.strict_json(item["original_raw"]).get("event") == "session_start")
                receipt = D.strict_json(item["reply_raw"])
                receipt[field] = value
                item.update(reply_raw=D.canonical(receipt).decode(), reply_sha256=D.sha(D.canonical(receipt)))
                self.assertFails(row)

    def test_native_epoch_sequence_cannot_repeat_or_reorder(self):
        row = passing_row("utf8-relative")
        records = D.json_lines(row["native_audit_raw"].encode())
        calls = [item for item in records if item.get("event") == "native_call"]
        calls[-1]["seq"] = calls[0]["seq"]
        row["native_audit_raw"] = "".join(line(item) for item in records)
        self.assertFails(row)

    def test_actual_publication_intent_event_is_required(self):
        row = passing_row("utf8-relative")
        records = D.json_lines(row["collector_raw"].encode())
        intent = next(item for item in records if item["event"] == "mcp_create_file_publication_intent")
        intent["event"] = "mcp_create_file_publication"
        row["collector_raw"] = "".join(line(item) for item in records)
        self.assertFails(row)

    def test_allow_must_be_genuinely_held_and_enforced(self):
        for field, value in (("held_allow", False), ("released_unchanged", False)):
            row = passing_row("utf8-relative")
            next(item for item in row["relay"] if item.get("held_allow"))[field] = value
            self.assertFails(row)

    def test_result_withholding_does_not_undo_committed_file(self):
        row = passing_row("result-withheld")
        row["workspace_after"] = copy.deepcopy(row["workspace_before"])
        self.assertFails(row)
        row = passing_row("result-withheld")
        row["attack"]["reply_raw"] = reply("probe", D.INJECTION)
        self.assertFails(row)

    def test_classifier_revision_arguments_contract_and_verdict_required(self):
        for field, value in (("classifier_sha256", "f" * 64), ("schema_sha256", "f" * 64), ("args_sha256", "f" * 64),
                             ("registry_sha256", "f" * 64), ("authoritative_verdict", "allow")):
            row = passing_row("classifier-deny")
            records = D.json_lines(row["collector_raw"].encode())
            records[0][field] = value
            row["collector_raw"] = "".join(line(item) for item in records)
            self.assertFails(row)

    def test_single_use_replay_must_terminate_without_second_reply(self):
        row = passing_row("replayed-id")
        row["replay_terminated"] = False
        self.assertFails(row)

    def test_native_filter_requires_all_exact_real_tests_no_ignored(self):
        raw = ("running 14 tests\n" + "".join("test windows_create::tests::" + name + " ... ok\n" for name in D.NATIVE_TESTS)
               + "test result: ok. 14 passed; 0 failed; 0 ignored; 77 filtered out;\n")
        self.assertTrue(D.native_tests_passed({"exit_code": 0, "stdout": raw}))
        for broken in ("running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored;", raw.replace("14 passed", "13 passed"),
                       raw.replace(D.NATIVE_TESTS[0], "unknown"), raw.replace("0 ignored", "1 ignored")):
            self.assertFalse(D.native_tests_passed({"exit_code": 0, "stdout": broken}))

    def test_fixture_records_real_forwarding_without_performing_file_operation(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = Path(temporary) / "child.jsonl"
            request = D.H.frame("forwarded", "create_file", {"path": "no-create.txt", "content": "fixture must not write"})
            result = subprocess.run([sys.executable, "-I", "-u", str(D.FIXTURE), "--ledger", str(ledger)],
                input=(line({"method": "initialize", "id": "init"}) + line({"method": "tools/list", "id": "list"}) + line(request)).encode(),
                capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(D.json_lines(ledger.read_bytes()), [request])
            self.assertEqual(D.json_lines(result.stdout)[1]["result"]["tools"], D.F.TOOLS)
            self.assertFalse((Path(temporary) / "no-create.txt").exists())
            self.assertIn("UNEXPECTED-CHILD-EXECUTION", result.stdout.decode())
            self.assertEqual(ledger.with_suffix(".started").read_bytes(), b"started\n")
            self.assertEqual(ledger.with_suffix(".closed").read_bytes(), b"closed\n")

    def test_dry_run_has_no_process_effect(self):
        with patch.object(D.subprocess, "Popen", side_effect=AssertionError("started")), patch.object(sys, "argv", [str(SCRIPT)]):
            self.assertEqual(D.main(), 0)

    def test_diagnostics_publish_only_curated_provenance_and_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "sou60-standard-user"
            output.mkdir()
            report = {"status": "incomplete", "source_before": {"commit": "a" * 40},
                "environment": {"os": "Windows", "architecture": "AMD64", "private": "DO-NOT-PUBLISH"},
                "standard_user": {"sid": "DO-NOT-PUBLISH", "is_administrator": False},
                "binary_sha256": "b" * 64, "collector_raw": "DO-NOT-PUBLISH", "cases": []}
            original = json.dumps(report)
            (output / "acceptance.json").write_text(original, encoding="utf-8")
            text = DIAGNOSTICS.diagnostics(root)
            self.assertIn("a" * 40, text)
            self.assertIn("b" * 64, text)
            self.assertNotIn("DO-NOT-PUBLISH", text)
            self.assertEqual((output / "acceptance.json").read_text(encoding="utf-8"), original)
            (root / "sou60-router.log").write_text('Bearer private-secret\n~~~\n' + "🥣" * 100000, encoding="utf-8")
            text = DIAGNOSTICS.diagnostics(root)
            self.assertNotIn("private-secret", text)
            self.assertIn("[REDACTED]", text)
            self.assertLess(len(text.encode()), 150000)


if __name__ == "__main__":
    unittest.main()
