# SPDX-License-Identifier: Apache-2.0
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from candidate_evidence import AuditWindow, FRAME, RULE, policy_evidence


def records():
    common = {"tool": "read_file", "session": "fresh-session", "call_id": "fresh-call",
              "binding_sha256": "b" * 64, "registry_sha256": "a" * 64, "shadow": False}
    return [{**common, "event": "native_call", "seq": 1, "verdict": "allow", "released": True},
            {**common, "event": "native_result", "seq": 2, "verdict": "deny", "released": False,
             "rule": RULE, "reason_codes": [RULE], "delivery": "mcp_host", "content_sha256": "c" * 64}]


def frame():
    return {"jsonrpc": "2.0", "id": 3, "result": {
        "isError": True, "content": [{"type": "text", "text": FRAME}]}}


class CandidateEvidenceTests(unittest.TestCase):
    def test_matching_call_and_daemon_result(self):
        self.assertEqual(policy_evidence(frame(), records(), "a" * 64)["rule"], RULE)

    def test_changed_binding_phase_verdict_or_reason_is_refused(self):
        for field, value in [("event", "native_context"), ("verdict", "allow"), ("released", True),
                             ("reason_codes", ["different"]), ("rule", "different"), ("shadow", True),
                             ("session", "different"), ("call_id", "different"), ("seq", 0),
                             ("binding_sha256", "other"), ("delivery", "model")]:
            with self.subTest(field=field):
                rows = records()
                rows[1][field] = value
                with self.assertRaises(ValueError):
                    policy_evidence(frame(), rows, "a" * 64)

    def test_stale_audit_does_not_qualify_fresh_invocation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.jsonl"
            path.write_text("".join(json.dumps(row) + "\n" for row in records()))
            window = AuditWindow(path)
            try:
                self.assertEqual(window.records(), [])
                with self.assertRaisesRegex(ValueError, "fresh_daemon"):
                    policy_evidence(frame(), window.records(), "a" * 64)
                with path.open("a") as stream:
                    stream.write("".join(json.dumps(row) + "\n" for row in records()))
                self.assertEqual(len(window.records()), 2)
            finally:
                window.close()

    def test_truncated_audit_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "audit.jsonl"
            path.write_text("old-record\n")
            window = AuditWindow(path)
            try:
                path.write_text("")
                with self.assertRaisesRegex(ValueError, "audit_size_changed"):
                    window.records()
            finally:
                window.close()

    def test_fabricated_collector_marker_cannot_qualify_without_daemon(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            audit = path / "audit.jsonl"
            audit.write_text("")
            fake = path / "fake.py"
            fake.write_text("import sys,json\nfor line in sys.stdin:\n"
                " r=json.loads(line)\n if 'id' not in r: continue\n"
                " print('mcp_classification',file=sys.stderr,flush=True)\n"
                " result=" + repr(frame()["result"]) + " if r['id']==3 else {}\n"
                " print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':result}),flush=True)\n")
            command = [sys.executable, str(Path(__file__).resolve().parents[1] / "candidate_mcp_driver.py"),
                       "verify_policy", "", "", sys.executable, str(fake)]
            result = subprocess.run(command, capture_output=True, text=True, timeout=15,
                env={**os.environ, "CANDIDATE_AUDIT_PATH": str(audit), "CANDIDATE_REGISTRY_SHA256": "a" * 64})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("fresh_daemon_call_result_required", result.stderr)

    def test_setup_errors_and_incidental_refusal_text_are_refused(self):
        for change in ["Cannot open " + FRAME, FRAME + " trailing", "classifier_deny withheld"]:
            response = frame()
            response["result"]["content"][0]["text"] = change
            with self.assertRaisesRegex(ValueError, "policy_frame"):
                policy_evidence(response, records(), "a" * 64)


if __name__ == "__main__":
    unittest.main()
