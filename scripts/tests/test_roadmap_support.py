"""SOU-80 integrity, identity and review-boundary controls."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
import shutil
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("roadmap_support", REPO / "scripts/roadmap_support.py")
support = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(support)
INDEX = REPO / "docs/operations/roadmap-support-index.json"
PUBLIC = REPO / "docs/operations/evidence"
TARGET = "38c981bddbedfd2b06b80fb4c9af474b9b897ad3"


def load_index():
    return support.validate_index(support.load_json(INDEX, support.MAX_INDEX)[0])


class RoadmapSupportTests(unittest.TestCase):
    def setUp(self):
        self.index = copy.deepcopy(load_index())
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "evidence"
        self.root.mkdir()
        for row in self.index["evidence"]:
            target = self.root / row["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(PUBLIC / row["path"], target)

    def row(self, evidence_id):
        return next(row for row in self.index["evidence"] if row["id"] == evidence_id)

    def replace_report(self, evidence_id, obj):
        row = self.row(evidence_id)
        data = json.dumps(obj, separators=(",", ":")).encode()
        (self.root / row["path"]).write_bytes(data)
        row["sha256"] = hashlib.sha256(data).hexdigest()

    def status(self, cap_id, target=TARGET):
        result = support.build(self.index, self.root, target, [])
        return next(c for c in result["capabilities"] if c["id"] == cap_id)

    def test_public_sanitized_selection_is_truthful(self):
        result = support.build(self.index, self.root, TARGET, [])
        self.assertEqual(len(result["criteria"]), 38)
        self.assertEqual(result["summary"], {
            "unsupported": 1, "missing": 4, "invalid": 0, "incomplete": 1, "mismatch": 0,
            "unbound": 2, "historical": 2, "component": 0, "pending-review": 0})
        self.assertTrue(all(c["status"] == "open" for c in result["criteria"]))
        self.assertEqual(self.status("create-file-linux")["evidence"][0]["observed"]["counts"]["passed"], 26)
        self.assertEqual(self.status("https-get-linux")["evidence"][0]["observed"]["counts"]["passed"], 48)
        self.assertEqual(self.status("shared-session-macos")["evidence"][0]["observed"]["counts"]["skipped"], 10)
        self.assertEqual(self.status("create-file-linux", "dbd7a097f4da79341aab5fcf49b32598d523bb41")["status"],
                         "component")

    def test_missing_and_tampered_evidence(self):
        path = self.root / self.row("create-file-followup")["path"]
        path.unlink()
        self.assertEqual(self.status("create-file-linux")["status"], "missing")
        path.write_bytes(b"{}")
        self.assertEqual(self.status("create-file-linux")["status"], "invalid")
        self.assertIn("SHA-256", self.status("create-file-linux")["blocker"])

    def test_wrong_source_and_platform_even_with_rehashed_file(self):
        row = self.row("https-get-run")
        data = json.loads((self.root / row["path"]).read_text())
        data["exact_build_runtime_source"] = TARGET
        self.replace_report("https-get-run", data)
        self.assertEqual(self.status("https-get-linux")["status"], "invalid")
        data["environment"]["source"] = TARGET
        data["environment"]["binary_build_source"] = TARGET
        data["environment"]["architecture"] = "x86_64"
        self.replace_report("https-get-run", data)
        self.assertEqual(self.status("https-get-linux")["status"], "invalid")
        self.assertIn("platform", self.status("https-get-linux")["blocker"])

    def test_zero_denominator_and_skipped_positive_cannot_pass(self):
        row = self.row("create-file-followup")
        data = json.loads((self.root / row["path"]).read_text())
        data["stdio"].update(cases_expected=0, cases_run=0, passed=0, failed=0, skips=0)
        self.replace_report("create-file-followup", data)
        self.assertEqual(self.status("create-file-linux")["status"], "incomplete")
        data["stdio"].update(cases_expected=26, cases_run=26, passed=25, failed=0, skips=1)
        self.replace_report("create-file-followup", data)
        self.assertEqual(self.status("create-file-linux")["status"], "incomplete")

    def test_self_test_scenario_disagreement_is_invalid(self):
        row = self.row("self-test-linux-run")
        data = json.loads((self.root / row["path"]).read_text())
        data["scenarios"][0]["status"] = "skipped"
        self.replace_report("self-test-linux-run", data)
        self.assertEqual(self.status("self-test-linux")["status"], "invalid")

    def test_fake_review_in_report_cannot_approve(self):
        row = self.row("https-get-run")
        data = json.loads((self.root / row["path"]).read_text())
        data["approval"] = {"reviewer": "invented", "decision": "accepted"}
        self.replace_report("https-get-run", data)
        result = support.build(self.index, self.root, TARGET, [])
        self.assertEqual(self.status("https-get-linux")["status"], "historical")
        self.assertTrue(all(c["status"] == "open" for c in result["criteria"]))
        self.assertNotIn("invented", json.dumps(result))

    def test_decision_file_must_bind_pending_candidate_and_criterion(self):
        decision = {"version": support.DECISION_VERSION, "source": TARGET, "decisions": [{
            "decision_id": "operator-supplied-1", "criterion_id": "phase-1.1",
            "evidence_id": "https-get-run", "evidence_sha256": self.row("https-get-run")["sha256"],
            "decision": "accepted"}]}
        rows = support.validate_decisions(decision, TARGET, self.index)
        with self.assertRaisesRegex(support.Invalid, "does not bind"):
            support.build(self.index, self.root, TARGET, rows)
        decision["source"] = "0" * 40
        with self.assertRaisesRegex(support.Invalid, "source/version"):
            support.validate_decisions(decision, TARGET, self.index)

    def test_generic_integrated_report_still_needs_operator_decision(self):
        row = self.row("https-get-run")
        cap = next(c for c in self.index["capabilities"] if c["id"] == "https-get-linux")
        identities = {key: str(i + 1) * 64 for i, key in enumerate(sorted(support.IDENTITY_FIELDS))}
        cap["identity"] = identities
        row.update(format=support.EVIDENCE_VERSION, kind="integrated-candidate", source=TARGET,
                   identity=identities)
        obj = {"version": support.EVIDENCE_VERSION, "source": TARGET,
               "platform": row["platform"], "architecture": row["architecture"],
               "host": row["host"], "transport": row["transport"], "server": row["server"],
               "profile": row["profile"], "identity": identities, "execution": "original-host",
               "outcome": "passed", "counts": {"passed": 3, "failed": 0, "skipped": 0, "expected": 3}}
        self.replace_report("https-get-run", obj)
        self.assertEqual(self.status("https-get-linux")["status"], "pending-review",
                         self.status("https-get-linux")["blocker"])
        decision = {"version": support.DECISION_VERSION, "source": TARGET, "decisions": [{
            "decision_id": "supplied-by-operator", "criterion_id": "phase-1.1",
            "evidence_id": "https-get-run", "evidence_sha256": row["sha256"],
            "decision": "accepted"}]}
        reviewed = support.build(self.index, self.root, TARGET,
                                 support.validate_decisions(decision, TARGET, self.index))
        self.assertEqual(next(c for c in reviewed["criteria"] if c["id"] == "phase-1.1")["status"],
                         "review-recorded")
        self.assertTrue(all(c["status"] != "complete" for c in reviewed["criteria"]))
        absent = {**row, "id": "additional-required-target-report", "path": "missing-target.json"}
        self.index["evidence"].append(absent)
        self.assertEqual(self.status("https-get-linux")["status"], "missing")
        with self.assertRaisesRegex(support.Invalid, "does not bind"):
            support.build(self.index, self.root, TARGET,
                          support.validate_decisions(decision, TARGET, self.index))
        self.index["evidence"].pop()
        obj["counts"]["expected"] = 0
        self.replace_report("https-get-run", obj)
        self.assertEqual(self.status("https-get-linux")["status"], "invalid")

    def test_strict_index_duplicate_ids_paths_and_json_keys(self):
        clone = copy.deepcopy(self.index)
        clone["capabilities"].append(copy.deepcopy(clone["capabilities"][0]))
        with self.assertRaisesRegex(support.Invalid, "duplicate capability"):
            support.validate_index(clone)
        clone = copy.deepcopy(self.index)
        clone["evidence"][0]["path"] = "../secret.json"
        with self.assertRaisesRegex(support.Invalid, "unsafe path"):
            support.validate_index(clone)
        path = Path(self.tmp.name) / "duplicate.json"
        path.write_text('{"a":1,"a":2}', encoding="utf-8")
        with self.assertRaisesRegex(support.Invalid, "duplicate JSON key"):
            support.load_json(path, 100)

    def test_hardlinks_and_oversize_inputs_refuse(self):
        row = self.row("https-get-run")
        path = self.root / row["path"]
        second = self.root / "same-inode.json"
        try:
            second.hardlink_to(path)
        except OSError:
            self.skipTest("hardlink creation unavailable on this filesystem")
        self.assertEqual(self.status("https-get-linux")["status"], "invalid")
        second.unlink()
        path.write_bytes(b"x" * (support.MAX_REPORT + 1))
        self.assertEqual(self.status("https-get-linux")["status"], "invalid")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "POSIX FIFO control")
    def test_fifo_swap_between_stat_and_open_is_refused_without_blocking(self):
        # Exercise the real OS open after a deterministic filesystem replacement.
        # The subprocess deadline also catches a regression before fstat runs.
        script = r"""
import importlib.util, os, pathlib, sys
spec = importlib.util.spec_from_file_location("support", sys.argv[1])
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
path = pathlib.Path(sys.argv[2])
original = os.open
def swap(selected, flags, *args, **kwargs):
    if pathlib.Path(selected) == path:
        path.unlink()
        os.mkfifo(path, 0o600)
    return original(selected, flags, *args, **kwargs)
support.os.open = swap
try:
    support.safe_file(path, 128)
except support.Invalid:
    print("unsafe replacement refused")
else:
    raise AssertionError("replacement accepted")
"""
        selected = Path(self.tmp.name) / "swapped.json"
        selected.write_text("{}", encoding="utf-8")
        run = subprocess.run([sys.executable, "-B", "-c", script,
                              str(REPO / "scripts/roadmap_support.py"), str(selected)],
                             capture_output=True, text=True, timeout=3)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "unsafe replacement refused")

    def test_profile_input_drift_is_detected(self):
        support.validate_profile_inputs(self.index, REPO)
        entry = self.index["profile_inputs"][0]
        isolated = Path(self.tmp.name) / "source"
        target = isolated / entry["path"]
        target.parent.mkdir(parents=True)
        shutil.copyfile(REPO / entry["path"], target)
        support.validate_profile_inputs({"profile_inputs": [entry]}, isolated)
        target.write_bytes(target.read_bytes() + b"\n")
        with self.assertRaisesRegex(support.Invalid, "profile input changed"):
            support.validate_profile_inputs({"profile_inputs": [entry]}, isolated)

    def test_unsafe_html_is_inert_and_raw_report_data_is_not_projected(self):
        title = '<img src=x onerror=alert(1)><script>alert(2)</script>'
        self.index["capabilities"][0]["title"] = title
        row = self.row("https-get-run")
        data = json.loads((self.root / row["path"]).read_text())
        data["private_prompt"] = "DO_NOT_EMBED_THIS_SENTINEL"
        self.replace_report("https-get-run", data)
        report = support.build(self.index, self.root, TARGET, [])
        assets = REPO / "scripts/roadmap_support_assets"
        page = support.render(report, (assets / "report.css").read_text(),
                              (assets / "report.js").read_text())
        self.assertNotIn(title, page)
        self.assertIn("\\u003cimg", page)
        self.assertNotIn("DO_NOT_EMBED_THIS_SENTINEL", page)
        self.assertIn("connect-src 'none'", page)
        self.assertEqual(page.count("<script>"), 1)


if __name__ == "__main__":
    unittest.main()
