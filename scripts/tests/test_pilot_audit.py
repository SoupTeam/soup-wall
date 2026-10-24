# SPDX-License-Identifier: Apache-2.0
"""Run selection, private export and loss controls; synthetic POSIX file fixtures."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sou132_audit", ROOT / "scripts/pilot_audit.py")
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)


@unittest.skipUnless(os.name == "posix", "POSIX integration; Linux is the supported run path")
class PilotAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.private = self.base / "soup-wall-run-owned-test"
        self.private.mkdir(mode=0o700)
        self.output = self.base / "summary.json"
        _, self.receipt = A.selection(self.private, "a" * 40, *("b" * 64 for _ in range(4)))
        self.write(self.private / "audit-run.json", self.receipt)
        self.write(self.private / "audit-finished.json", {"format": A.FORMAT,
                   "run_id": "owned-test", "owned_processes_stopped": True})
        self.canary = "PRIVATE_TOOL_RESULT_BEARER_TOKEN_PROMPT_AND_USER_PATH"
        # The non-Linux fixture uses the same POSIX readers only to test parsing
        # and privacy. This is not a claim of Linux daemon/containment acceptance.
        self.enterContext(patch.object(A.REPORT.sys, "platform", "linux"))
        self.enterContext(patch.object(A.REPORT, "_linux_filesystem", return_value="tmpfs"))

    def write(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def row(self, event="native_call", **more):
        result = dict(at_ms=1760000000000, session=self.canary, seq=1,
                      event=event, tool=self.canary, verdict="allow", shadow=False,
                      rule=self.canary, findings=[], taint=None, latency_us=1,
                      call_id=self.canary, released=True, raw=self.canary)
        result.update(more)
        return json.dumps(result).encode() + b"\n"

    def segments(self, bodies, pruned=0):
        meta = []
        for number, body in enumerate(bodies, pruned + 1):
            path = self.private / "audit" / f"segment-{number:020}.jsonl"
            path.write_bytes(body)
            path.chmod(0o600)
            closed = number != pruned + len(bodies)
            meta.append(dict(id=number, closed=closed, bytes=len(body) if closed else 0,
                sha256=hashlib.sha256(body).hexdigest() if closed else None, partial_tail=False))
        self.write(self.private / "audit" / "manifest.json", dict(version=1,
            limits={k: v for k, v in A.LIMITS.items() if k != "version"}, generation=2,
            next_id=pruned + len(bodies) + 1, pruned_through=pruned,
            pending_prune=None, segments=meta))

    def export(self, run="owned-test"):
        result = A.export_run(self.private, self.output, run)
        self.assertNotIn(self.canary, self.output.read_text())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertFalse(list(self.private.glob("pilot-audit-export-*")))
        return result, json.loads(self.output.read_bytes())

    def test_selected_config_is_finite_private_and_reuses_existing_engine(self):
        self.assertEqual(stat.S_IMODE((self.private / "audit").stat().st_mode), 0o700)
        self.assertLessEqual(A.LIMITS["segment_count"] * A.LIMITS["segment_size_bytes"] + 135168,
                             A.LIMITS["total_disk_bytes"])
        self.segments([self.row() + self.row("native_result")])
        _, summary = self.export()
        self.assertEqual(summary["completeness"], "selected_history_only")
        self.assertEqual(summary["decisions"][0]["correlation"], summary["decisions"][1]["correlation"])
        self.assertFalse(summary["allow_proves_execution"])

    def test_rotated_missing_corrupt_and_partial_evidence_is_not_absence_of_execution(self):
        self.segments([self.row(), self.row(), self.row() + b'{"partial"'], pruned=3)
        (self.private / "audit" / "segment-00000000000000000004.jsonl").unlink()
        (self.private / "audit" / "segment-00000000000000000005.jsonl").write_bytes(b"changed\n")
        _, summary = self.export()
        self.assertEqual(summary["completeness"], "incomplete")
        self.assertTrue({"intentional_retention", "missing_segment", "corrupt_segment", "partial_tail"}
                        <= set(summary["notices"]))
        self.assertFalse(summary["missing_records_prove_no_execution"])

    def test_active_reader_is_explicit_and_does_not_change_source(self):
        self.segments([self.row()])
        (self.private / "audit-finished.json").unlink()
        before = {p.name: p.read_bytes() for p in (self.private / "audit").iterdir()}
        _, summary = self.export()
        self.assertIn("run_not_confirmed_stopped", summary["notices"])
        self.assertEqual(before, {p.name: p.read_bytes() for p in (self.private / "audit").iterdir()})

    def test_stale_run_and_changed_retention_binding_refuse(self):
        self.segments([self.row()])
        with self.assertRaises(ValueError):
            self.export("other-run")
        self.receipt["retention_sha256"] = "0" * 64
        self.write(self.private / "audit-run.json", self.receipt)
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_replaced_store_and_linked_receipt_refuse_without_touching_target(self):
        self.segments([self.row()])
        original = self.private / "audit"
        original.rename(self.private / "previous")
        original.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.export()
        original.rmdir()
        (self.private / "previous").rename(original)
        os.link(self.private / "audit-run.json", self.private / "linked.json")
        with self.assertRaises(ValueError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_foreign_mode_fifo_symlink_and_unbounded_receipt_refuse(self):
        self.segments([self.row()])
        receipt = self.private / "audit-run.json"
        for kind in ("shared-mode", "symlink", "fifo", "oversize"):
            if receipt.exists() or receipt.is_symlink():
                receipt.unlink()
            if kind == "shared-mode":
                self.write(receipt, self.receipt); receipt.chmod(0o644)
            elif kind == "symlink":
                receipt.symlink_to(self.base / "unrelated")
            elif kind == "fifo":
                os.mkfifo(receipt, 0o600)
            else:
                receipt.write_bytes(b" " * 65537); receipt.chmod(0o600)
            with self.subTest(kind=kind), self.assertRaises((OSError, ValueError)):
                self.export()
        self.assertFalse(self.output.exists())

    def test_summary_is_bounded_and_create_new(self):
        self.segments([self.row() * 75, self.row() * 75])
        _, summary = self.export()
        self.assertEqual(len(summary["decisions"]), A.MAX_DECISIONS)
        self.assertIn("decision_reference_limit", summary["notices"])
        with self.assertRaises((OSError, A.REPORT.ReportError)):
            self.export()
        self.assertLessEqual(self.output.stat().st_size, A.MAX_SUMMARY)

    def test_unknown_schema_and_orphan_result_stay_incomplete(self):
        self.segments([self.row("native_result") + self.row(version=99)])
        _, summary = self.export()
        self.assertEqual(summary["completeness"], "incomplete")
        self.assertTrue(summary["decisions"][0]["evidence_missing"])

    def test_empty_history_and_export_inside_source_are_not_complete_evidence(self):
        self.segments([b""])
        _, summary = self.export()
        self.assertIn("no_decision_records", summary["notices"])
        self.assertEqual(summary["completeness"], "incomplete")
        with self.assertRaises(ValueError):
            A.export_run(self.private, self.private / "audit" / "new.json", "owned-test")

    def test_manifest_change_during_read_refuses_without_publishing(self):
        self.segments([self.row()])
        original = A.REPORT._pair_object
        changed = False
        def mutate(pairs):
            nonlocal changed
            value = original(pairs)
            if value.get("version") == 1 and "segments" in value and not changed:
                changed = True
                manifest = self.private / "audit" / "manifest.json"
                manifest.write_bytes(manifest.read_bytes() + b" ")
            return value
        with patch.object(A.REPORT, "_pair_object", side_effect=mutate), self.assertRaises(A.REPORT.ReportError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_foreign_unlisted_file_is_never_exported_or_removed(self):
        self.segments([self.row()])
        foreign = self.private / "audit" / "operator-private.txt"
        foreign.write_text(self.canary)
        self.export()
        self.assertEqual(foreign.read_text(), self.canary)


if __name__ == "__main__":
    unittest.main()
