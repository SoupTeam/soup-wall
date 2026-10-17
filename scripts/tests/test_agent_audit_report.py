# SPDX-License-Identifier: Apache-2.0
"""Focused safety and semantics checks for the offline audit projection."""

import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "agent-audit-report.py"
SPEC = importlib.util.spec_from_file_location("agent_audit_report", SCRIPT)
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux permission scope")
class AuditReportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.input = self.base / "audit.jsonl"
        self.output = self.base / "report.html"
        self.template = self.base / "template.html"
        self.template.write_text('<script id="audit-data" type="application/json">__AUDIT_DATA__</script>', encoding="utf-8")

    def write(self, *rows):
        self.input.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows))

    def hook(self, **more):
        row = dict(at_ms=1_760_000_000_000, session="real-session-secret", seq=1,
                   event="pre_tool_use", tool="Bash", verdict="allow", shadow=False,
                   rule="ask-unknown-host", risk_score=0, findings=[], taint=None,
                   latency_us=1299, truncated=False)
        row.update(more)
        return row

    def native(self, event, **more):
        row = self.hook(event=event, call_id="opaque-call-secret", released=True)
        row.update(more)
        return row

    def read_data(self):
        text = self.output.read_text(encoding="utf-8")
        return json.loads(text.split('type="application/json">', 1)[1].split("</script>", 1)[0])

    def generate(self):
        return REPORT.generate(self.input, self.output, self.template)

    def test_real_formats_and_link_only_present_native_identifiers(self):
        self.write(self.hook(), self.native("native_call"), self.native("native_result", verdict="deny", released=False),
                   self.native("native_result", call_id=None, verdict="deny", released=False))
        self.generate()
        rows = self.read_data()["events"]
        self.assertEqual([r["stage"] for r in rows], ["decision", "admission", "result", "result"])
        self.assertIn("Host execution is not proven", " ".join(rows[0]["evidence_missing"]))
        self.assertEqual(rows[1]["correlation"], rows[2]["correlation"])
        self.assertIsNone(rows[3]["correlation"])
        self.assertEqual(rows[2]["reason"], "Result withheld; prior side effects may remain")
        self.assertEqual(rows[0]["session_alias"], "Session 1")
        self.assertNotIn("real-session-secret", self.output.read_text())
        self.assertNotIn("opaque-call-secret", self.output.read_text())

    def test_unknown_native_identity_does_not_invent_link(self):
        self.write(self.native("native_result", call_id="orphan", released=False))
        self.generate()
        self.assertIn("No linked admission record in this report", self.read_data()["events"][0]["evidence_missing"])

    def test_source_truncation_and_missing_result_are_visible(self):
        self.write(self.native("native_call", truncated=True))
        self.generate()
        missing = self.read_data()["events"][0]["evidence_missing"]
        self.assertIn("Source event was truncated", missing)
        self.assertIn("No linked result record in this report", missing)

    def test_omitted_findings_are_disclosed(self):
        self.write(self.hook(findings=[{"detector": "injection", "severity": "high"}] *
                             (REPORT.MAX_FINDINGS + 1)))
        self.generate()
        row = self.read_data()["events"][0]
        self.assertEqual(row["detectors"], ["injection"])
        self.assertTrue(any("omitted" in note for note in row["evidence_missing"]))

    def test_projection_removes_secret_and_script_sequences(self):
        self.write(self.hook(tool="Bash</script><script>alert(1)</script>",
                             rule="secret-password-sentinel", agent_id="real-agent-secret",
                             parent_id="real-parent-secret", raw="SENTINEL_SECRET",
                             approval="SENTINEL_NONCE", egress_hosts=["internal.example"],
                             args={"path": "/home/alice/secret"},
                             reason_codes=["native_approval_redeemed:SENTINEL_NONCE"],
                             taint={"source": "network:internal.example", "source_name": "internal.example", "origin": "network", "trust": "untrusted", "seq": 1},
                             findings=[{"detector": "<img onerror=alert(1)>", "severity": "high"}]))
        self.generate()
        text = self.output.read_text()
        for secret in ("SENTINEL_SECRET", "SENTINEL_NONCE", "internal.example", "/home/alice", "real-agent-secret", "real-parent-secret", "onerror", "</script><script>"):
            self.assertNotIn(secret, text)
        row = self.read_data()["events"][0]
        self.assertEqual(row["tool"], "Tool 1")
        self.assertEqual(row["rule"], "Rule 1")
        self.assertEqual(row["taint_origin"], "network")
        self.assertEqual(row["severity"], ["high"])
        self.assertEqual(row["detectors"], ["Detector 1"])

    def test_malformed_partial_and_unsupported_are_honest(self):
        self.input.write_bytes(json.dumps(self.hook()).encode() + b"\n" + b'{"event":' + b"\n" +
                               json.dumps({**self.hook(), "format_version": 2}).encode())
        self.generate()
        meta = self.read_data()["meta"]
        self.assertEqual(meta["totals"], {"lines": 3, "accepted": 1, "malformed": 1, "unsupported": 1, "skipped": 0})
        self.assertEqual(meta["source_status"], "partial")
        self.assertTrue(any("newline" in notice for notice in meta["notices"]))

    def test_deep_duplicate_and_oversized_line(self):
        self.input.write_bytes(b'{' + b'"x":[' * 20 + b'0' + b']' * 20 + b'}\n' +
                               b'{"event":"pre_tool_use","event":"post_tool_use"}\n' +
                               b' ' * (REPORT.MAX_LINE_BYTES + 1))
        self.generate()
        meta = self.read_data()["meta"]
        self.assertEqual(meta["totals"]["malformed"], 2)
        self.assertEqual(meta["totals"]["skipped"], 1)
        self.assertEqual(meta["source_status"], "partial")

    def test_private_no_clobber_and_refuse_links(self):
        self.write(self.hook())
        self.generate()
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            self.generate()
        self.output.unlink()
        link = self.base / "linked.jsonl"
        link.symlink_to(self.input)
        with self.assertRaises(REPORT.ReportError):
            REPORT.generate(link, self.output, self.template)

    def test_input_size_and_output_parent_permissions(self):
        self.input.write_bytes(b"x" * (REPORT.MAX_INPUT_BYTES + 1))
        self.generate()
        self.assertEqual(self.read_data()["meta"]["source_status"], "partial")
        self.output.unlink()
        self.write(self.hook())
        os.chmod(self.base, 0o755)
        with self.assertRaises(REPORT.ReportError):
            self.generate()

    def test_total_line_limit_includes_unsupported_records(self):
        self.input.write_bytes(b'{}\n' * (REPORT.MAX_RECORDS + 1))
        self.generate()
        meta = self.read_data()["meta"]
        self.assertEqual(meta["totals"]["lines"], REPORT.MAX_RECORDS)
        self.assertEqual(meta["totals"]["unsupported"], REPORT.MAX_RECORDS)
        self.assertEqual(meta["totals"]["skipped"], 1)
        self.assertEqual(meta["source_status"], "partial")

    def test_benign_looking_values_are_pseudonyms(self):
        self.write(self.hook(tool="CANARY123", rule="canary123", findings=[{"detector": "canary123", "severity": "critical"}],
                             reason_codes=["native_approval_redeemed:nonce123"]),
                   self.hook(tool="CANARY123", rule="canary123", findings=[{"detector": "canary123", "severity": "low"}]))
        self.generate()
        text = self.output.read_text()
        self.assertNotIn("CANARY123", text)
        self.assertNotIn("canary123", text)
        self.assertNotIn("nonce123", text)
        rows = self.read_data()["events"]
        self.assertEqual([r["tool"] for r in rows], ["Tool 1", "Tool 1"])
        self.assertEqual([r["rule"] for r in rows], ["Rule 1", "Rule 1"])
        self.assertEqual(rows[0]["details"][0], {"label": "Finding 1", "value": "Detector 1 · critical"})

    def test_post_hook_observation_and_handshake_server_alias(self):
        self.write(self.hook(event="post_tool_use"), self.hook(event="mcp_handshake", session="server-secret", tool=None))
        self.generate()
        first, second = self.read_data()["events"]
        self.assertEqual(first["stage"], "observation")
        self.assertEqual(second["session_alias"], "Server 1")
        self.assertTrue(any("MCP server" in message for message in second["evidence_missing"]))

    def test_agent_and_parent_share_identity_namespace(self):
        self.write(self.hook(agent_id="same-hidden-id"), self.hook(parent_id="same-hidden-id"))
        self.generate()
        first, second = self.read_data()["events"]
        self.assertEqual(first["details"][0], {"label": "Agent alias", "value": "Agent 1"})
        self.assertEqual(second["details"][0], {"label": "Parent alias", "value": "Agent 1"})

    def test_conflicting_native_link_is_marked_ambiguous(self):
        self.write(self.native("native_call", binding_sha256="binding-a"),
                   self.native("native_result", binding_sha256="binding-b"))
        self.generate()
        for row in self.read_data()["events"]:
            self.assertIsNone(row["correlation"])
            self.assertIn("Call/result linkage ambiguous in this report", row["evidence_missing"])


if __name__ == "__main__":
    unittest.main()
