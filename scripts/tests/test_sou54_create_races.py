# SPDX-License-Identifier: Apache-2.0
"""Pure race-evidence grader controls; these do not fake runtime acceptance."""
from __future__ import annotations
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sou54_race_probe", SCRIPTS / "verify-sou54-create-races.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
H = P.H


def raw(value):
    return H.canonical(value).decode() + "\n"


def exchange(original, forwarded=None, reply=None):
    forwarded = copy.deepcopy(original) if forwarded is None else forwarded
    reply = {"verdict": "allow", "release": True, "call_id": "native-read"} if reply is None else reply
    row = {"original": original, "forwarded": forwarded, "reply": reply,
           "authorization_header_retained": False, "upstream_status": 200, "upstream_completed_at": 1.0}
    for name in ("original", "forwarded", "reply"):
        row[name + "_raw"] = raw(row[name])
        row[name + "_sha256"] = H.sha(row[name + "_raw"].encode())
    return row


def observation(root_race=False):
    args = {"path": "created.txt", "content": H.UTF8}
    request = H.frame("create-primary", "create_file", args)
    original = {"event": "call", "tool": "create_file", "args": args, "session_id": "session-primary",
                "resource_admission": {"host_call_id": request["id"], "execution": {"original_binding": "pinned"}}}
    forwarded = copy.deepcopy(original)
    forwarded["args"]["path"] = "substituted.txt"
    reply = {"verdict": "deny", "release": False}
    create_response = {"jsonrpc": "2.0", "id": request["id"], "result": {"isError": True,
                       "content": [{"type": "text", "text": "Soup Wall withheld MCP invocation"}]}}
    log = ""
    if root_race:
        forwarded = copy.deepcopy(original)
        reply = {"verdict": "allow", "release": True}
        payload = {"success": False, "committed": False, "created": False, "error": "workspace_root_substituted"}
        create_response["result"]["content"][0]["text"] = H.canonical(payload).decode()
        log = raw({"event": "mcp_create_file_execution", "host_call_id": request["id"], "committed": False,
                   "committed_bytes": 0, "staged_bytes": 0, "result_kind": "error", "error": "workspace_root_substituted"})
    native_create = exchange(original, forwarded, reply)
    if root_race:
        native_create.update(held=True, released_at=3.0)
    useful_request = H.frame("useful-primary", "read_document", {"path": "/fixture/inventory.txt"})
    useful_reply = {"jsonrpc": "2.0", "id": useful_request["id"], "result": {"content": [{"type": "text", "text": H.READ_TEXT}]}}
    init = {"id": "init", "result": {"protocolVersion": "2024-11-05"}}
    listing = {"id": "list", "result": {"tools": H.load_tools()}}
    native_read = exchange({"event": "call", "tool": "read_document", "session_id": "session-primary"})
    native_result = exchange({"event": "result", "call_id": "native-read", "session_id": "session-primary"})
    tree = {".": {"kind": 16384, "mode": 448, "inode": 1, "device": 1, "links": 2}}
    session = {"label": "primary", "child_ledger_present": True, "child_started_raw": "started\n", "child_closed_raw": "closed\n",
        "child_ledger_raw": "", "child_input_raw": "".join(raw({"method": method}) for method in ("initialize", "notifications/initialized", "tools/list")),
        "child_output_raw": raw(init) + raw(listing), "client_raw": "".join(raw(item) for item in (init, listing, create_response, useful_reply)),
        "collector_raw": log, "closure": {"exit_code": 0, "stdout_eof": True, "reader_joined": True, "forced_cleanup": False},
        "create_reply_raw": raw(create_response), "useful": {"request": useful_request, "reply_raw": raw(useful_reply)}}
    row = {"case": "root-replacement-after-allow" if root_race else "destination-substitution", "sessions": [session],
        "submitted_creates": [request], "proxy_closed_cleanly": True, "proxy_exchanges": [native_create, native_read, native_result],
        "outside_before": {}, "outside_after": {}, "workspace_before": tree, "workspace_after": copy.deepcopy(tree), "target_final": None,
        "native_audit_raw": raw({"event": "native_session_start", "session": "primary-epoch"}) + raw({"event": "native_session_end", "session": "primary-epoch"})}
    if root_race:
        row.update(fixture_mutations=["explicit fixture root rename/replacement"], root_replaced_at=2.0, release_at=3.0,
                   parked_before=tree, parked_after=copy.deepcopy(tree), replacement_before={"canary": {}}, replacement_after={"canary": {}})
    return row


class RaceEvidenceTests(unittest.TestCase):
    def test_default_starts_no_process(self):
        result = subprocess.run([sys.executable, str(SCRIPTS / "verify-sou54-create-races.py")], capture_output=True, text=True, check=True)
        value = json.loads(result.stdout)
        self.assertEqual(value["processes_started"], 0)
        self.assertFalse(value["acceptance_passed"])
        self.assertEqual(len(value["cases"]), 8)

    def test_reference_substitution_and_root_race_evidence_pass(self):
        for root_race in (False, True):
            self.assertEqual(P.grade(observation(root_race))["status"], "pass")

    def test_substitution_requires_actual_deny_with_unchanged_original_binding(self):
        for change in (
            lambda r: r["proxy_exchanges"][0]["reply"].update(verdict="allow", release=True),
            lambda r: r["proxy_exchanges"][0]["forwarded"]["resource_admission"]["execution"].update(original_binding="recomputed"),
            lambda r: r["proxy_exchanges"][0]["forwarded"]["args"].update(content="another unauthorized change"),
            lambda r: r["proxy_exchanges"][0].update(upstream_status=401),
            lambda r: r["proxy_exchanges"][0].update(authorization_header_retained=True),
        ):
            row = observation()
            change(row)
            # Keep transcript encodings coherent so semantic controls, rather
            # than an incidental stale digest, reject the forged witness.
            for item in row["proxy_exchanges"]:
                for name in ("original", "forwarded", "reply"):
                    item[name + "_raw"] = raw(item[name])
                    item[name + "_sha256"] = H.sha(item[name + "_raw"].encode())
            self.assertEqual(P.grade(row)["status"], "fail")

    def test_zero_child_calls_does_not_hide_changed_files_or_broker_entry(self):
        for change in (lambda r: r["workspace_after"].update(leak={}), lambda r: r["outside_after"].update(leak={}),
                       lambda r: r["sessions"][0].update(collector_raw=raw({"event": "mcp_create_file_execution", "committed": False})),
                       lambda r: r["sessions"][0].update(child_ledger_present=False)):
            row = observation()
            change(row)
            self.assertEqual(P.grade(row)["status"], "fail")

    def test_root_fixture_changes_must_have_independent_unchanged_witnesses_and_order(self):
        for change in (lambda r: r.update(root_replaced_at=0.5), lambda r: r.update(release_at=1.5),
                       lambda r: r["replacement_after"].update(created={}), lambda r: r["parked_after"].update(created={}),
                       lambda r: r.update(fixture_mutations=[])):
            row = observation(True)
            change(row)
            self.assertEqual(P.grade(row)["status"], "fail")

    def test_useful_continuation_and_clean_eof_are_required(self):
        for change in (lambda r: r["sessions"][0]["closure"].update(exit_code=1),
                       lambda r: r["sessions"][0].update(child_closed_raw=""),
                       lambda r: r["sessions"][0].update(client_raw=""),
                       lambda r: r.update(native_audit_raw="")):
            row = observation()
            change(row)
            self.assertEqual(P.grade(row)["status"], "fail")

    def test_raw_proxy_byte_witnesses_cannot_be_missing_or_replaced(self):
        for name in ("original_raw", "forwarded_raw", "reply_raw", "reply_sha256"):
            row = observation()
            row["proxy_exchanges"][0][name] = "changed"
            self.assertEqual(P.grade(row)["status"], "fail")
        self.assertEqual(P.grade({})["status"], "fail")


if __name__ == "__main__":
    unittest.main()
