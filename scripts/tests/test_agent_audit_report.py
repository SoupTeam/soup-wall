# SPDX-License-Identifier: Apache-2.0
"""Focused safety and semantics checks for the offline audit projection."""

import importlib.util
import hashlib
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

    def retained(self, segments, pruned=0):
        directory = self.base / "retained"
        directory.mkdir(mode=0o700)
        metadata = []
        for index, body in enumerate(segments, pruned + 1):
            name = directory / f"segment-{index:020}.jsonl"
            name.write_bytes(body)
            name.chmod(0o600)
            metadata.append(dict(id=index, closed=index != pruned + len(segments),
                                 bytes=len(body) if index != pruned + len(segments) else 0,
                                 sha256=hashlib.sha256(body).hexdigest() if index != pruned + len(segments) else None,
                                 partial_tail=False))
        manifest = dict(version=1, limits=dict(segment_size_bytes=65536, segment_count=4,
                                              total_disk_bytes=512000, max_record_bytes=4096),
                        generation=2, next_id=pruned + len(segments) + 1,
                        pruned_through=pruned, pending_prune=None, segments=metadata)
        path = directory / "manifest.json"
        path.write_text(json.dumps(manifest))
        path.chmod(0o600)
        return directory

    def test_retained_export_projects_real_segments_and_explains_pruning(self):
        first = json.dumps(self.native("native_call", raw="SENTINEL_SECRET")).encode() + b"\n"
        second = json.dumps(self.native("native_result", released=False)).encode() + b"\n"
        directory = self.retained([first, second], pruned=3)
        exported = self.base / "export.jsonl"
        result = REPORT.export_retained(directory, exported)
        self.assertEqual(result["records"], 2)
        self.assertEqual(stat.S_IMODE(exported.stat().st_mode), 0o600)
        self.input = exported
        self.generate()
        report = self.read_data()
        self.assertEqual(report["meta"]["gaps"]["intentional"], 3)
        self.assertEqual(report["meta"]["source_status"], "partial")
        self.assertEqual(report["events"][0]["correlation"], report["events"][1]["correlation"])
        self.assertNotIn("SENTINEL_SECRET", self.output.read_text())
        self.assertNotIn("real-session-secret", self.output.read_text())

    def test_retained_export_distinguishes_missing_corrupt_and_partial(self):
        row = json.dumps(self.hook()).encode() + b"\n"
        directory = self.retained([row, row, row + b'{"incomplete"'])
        (directory / "segment-00000000000000000001.jsonl").unlink()
        (directory / "segment-00000000000000000002.jsonl").write_bytes(b"changed\n")
        exported = self.base / "export.jsonl"
        result = REPORT.export_retained(directory, exported)
        self.assertEqual(result["gaps"], {"intentional": 0, "unexplained": 1, "corrupt": 1})
        self.assertIn("partial_tail", result["notices"])
        self.input = exported
        self.generate()
        report = self.read_data()
        self.assertEqual(len(report["events"]), 1)
        self.assertTrue(any("incomplete final record" in note for note in report["meta"]["notices"]))
        self.assertTrue(any("unexplained gap" in note for note in report["meta"]["notices"]))

    def test_retained_segment_and_time_selection_keeps_linkage_honest(self):
        call = json.dumps(self.native("native_call", at_ms=100)).encode() + b"\n"
        result = json.dumps(self.native("native_result", at_ms=200)).encode() + b"\n"
        directory = self.retained([call, result])
        exported = self.base / "selected.jsonl"
        metadata = REPORT.export_retained(directory, exported, from_segment=2, to_segment=2,
                                          from_ms=150, to_ms=250)
        self.assertEqual(metadata["records"], 1)
        self.assertIn("selected_range", metadata["notices"])
        self.input = exported
        self.generate()
        row = self.read_data()["events"][0]
        self.assertEqual(row["stage"], "result")
        self.assertIn("No linked admission record in this report", row["evidence_missing"])

    def test_retained_export_rejects_symlink_and_refuses_overwrite(self):
        directory = self.retained([json.dumps(self.hook()).encode() + b"\n"])
        segment = directory / "segment-00000000000000000001.jsonl"
        moved = self.base / "other.jsonl"
        segment.rename(moved)
        segment.symlink_to(moved)
        with self.assertRaises(REPORT.ReportError):
            REPORT.export_retained(directory, self.base / "export.jsonl")
        segment.unlink()
        segment.write_bytes(moved.read_bytes())
        segment.chmod(0o600)
        output = self.base / "export.jsonl"
        REPORT.export_retained(directory, output)
        with self.assertRaises(FileExistsError):
            REPORT.export_retained(directory, output)

    def test_reordered_manifest_is_unknown_schema_and_fifo_is_refused(self):
        row = json.dumps(self.hook()).encode() + b"\n"
        directory = self.retained([row, row])
        manifest_path = directory / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["segments"] = list(reversed(manifest["segments"]))
        manifest_path.write_text(json.dumps(manifest))
        export = self.base / "reordered.jsonl"
        result = REPORT.export_retained(directory, export)
        self.assertIn("unknown_schema", result["notices"])
        self.assertEqual(result["gaps"]["corrupt"], 1)
        self.assertEqual(result["records"], 0)
        manifest["segments"].reverse()
        manifest_path.write_text(json.dumps(manifest))
        fifo = directory / "segment-00000000000000000001.jsonl"
        fifo.unlink()
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(REPORT.ReportError):
            REPORT.export_retained(directory, self.base / "fifo.jsonl")

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
