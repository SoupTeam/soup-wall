# SPDX-License-Identifier: Apache-2.0
"""Transaction, recovery and active-run boundaries for prepared selection."""
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("sou133_transition", ROOT / "scripts/switch-prepared-pilot.py")
SW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SW)


@unittest.skipUnless(os.name == "posix", "selection coordination requires POSIX locks")
class PreparedTransition(unittest.TestCase):
    A, B = "a" * 32, "b" * 32
    SOURCE = ROOT

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "prepared"
        self.output.mkdir(mode=0o700)
        (self.output / "generations").mkdir(mode=0o700)
        self.summaries = {self.A: self.summary(self.A), self.B: self.summary(self.B)}
        SW.publish_json(self.output, "current.json", self.marker(self.A))
        self.generation = patch.object(SW, "generation", side_effect=self.lookup)
        self.generation.start()
        self.addCleanup(self.generation.stop)

    def summary(self, identifier):
        return {"generation": identifier, "selection_sha256": identifier[0] * 64,
                "source": {"commit": identifier[0] * 40, "tree": identifier[0] * 40,
                           "dirty": False, "files_sha256": identifier[0] * 64},
                "agent_sha256": identifier[0] * 64,
                "agent_path": "/absent/agentfw-" + identifier,
                "claude_path": "/absent/claude-" + identifier,
                "server_profiles": {"filesystem": {"profile": {"sha256": identifier[0] * 64}},
                                    "git": {"profile": {"sha256": identifier[0] * 64}}},
                "policy_sha256": identifier[0] * 64,
                "filesystem_classifier_sha256": identifier[0] * 64,
                "git_classifier_sha256": identifier[0] * 64}

    def lookup(self, _output, identifier, _source):
        if identifier not in self.summaries:
            raise ValueError("incomplete_target")
        return self.summaries[identifier]

    def marker(self, identifier):
        return {"format": SW.MARKER_FORMAT, "generation": identifier,
                "selection_sha256": identifier[0] * 64, "status": "prepared-not-active"}

    def planned(self, target):
        return SW.plan(self.output, target, self.SOURCE, self.SOURCE)[3]

    def test_plan_is_read_only_and_a_b_a_uses_exact_plan(self):
        before = sorted(item.name for item in self.output.iterdir())
        first = self.planned(self.B)
        self.assertEqual(before, sorted(item.name for item in self.output.iterdir()))
        self.assertEqual(first["previous"]["source"]["commit"], "a" * 40)
        self.assertEqual(first["target"]["agent_sha256"], "b" * 64)
        self.assertEqual(SW.apply(self.output, self.B, self.SOURCE, self.SOURCE,
                                  first["plan_sha256"])["status"], "selected")
        self.assertEqual(SW.marker(self.output)[2]["generation"], self.B)
        back = self.planned(self.A)
        SW.apply(self.output, self.A, self.SOURCE, self.SOURCE, back["plan_sha256"])
        self.assertEqual(SW.marker(self.output)[2]["generation"], self.A)
        self.assertEqual(len(SW.journal(self.output)["history"]), 2)

    def test_changed_target_confirmation_and_failed_validation_preserve_current(self):
        first = self.planned(self.B)
        before = (self.output / "current.json").read_bytes()
        self.summaries[self.B]["policy_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "plan_confirmation_changed"):
            SW.apply(self.output, self.B, self.SOURCE, self.SOURCE, first["plan_sha256"])
        with self.assertRaisesRegex(ValueError, "incomplete_target"):
            SW.apply(self.output, "c" * 32, self.SOURCE, self.SOURCE, first["plan_sha256"])
        self.assertEqual((self.output / "current.json").read_bytes(), before)
        self.assertFalse((self.output / SW.JOURNAL).exists())

    def test_active_run_blocks_transition(self):
        first = self.planned(self.B)
        with SW.LOCK.hold(self.output, exclusive=False):
            with self.assertRaisesRegex(ValueError, "selected_generation_in_use"):
                SW.apply(self.output, self.B, self.SOURCE, self.SOURCE, first["plan_sha256"])
        self.assertEqual(SW.marker(self.output)[2]["generation"], self.A)

    def test_interrupted_before_and_after_publication_recover_actual_pointer(self):
        first = self.planned(self.B)
        original = (self.output / "current.json").read_bytes()
        actual_publish = SW.publish_json
        def crash_before(output, name, value):
            if name == "current.json":
                raise OSError("simulated interruption")
            return actual_publish(output, name, value)
        with patch.object(SW, "publish_json", side_effect=crash_before):
            with self.assertRaises(OSError):
                SW.apply(self.output, self.B, self.SOURCE, self.SOURCE, first["plan_sha256"])
        self.assertEqual((self.output / "current.json").read_bytes(), original)
        self.assertEqual(SW.recover(self.output)["status"], "interrupted_before_publication")
        def crash_after(output, name, value):
            if name == SW.JOURNAL and value.get("pending") is None:
                raise OSError("simulated interruption")
            return actual_publish(output, name, value)
        with patch.object(SW, "publish_json", side_effect=crash_after):
            with self.assertRaises(OSError):
                SW.apply(self.output, self.B, self.SOURCE, self.SOURCE, first["plan_sha256"])
        self.assertEqual(SW.marker(self.output)[2]["generation"], self.B)
        self.assertEqual(SW.recover(self.output)["status"], "published_before_journal_completion")

    def test_conflicting_operator_edit_is_reported_and_never_overwritten(self):
        first = self.planned(self.B)
        before = (self.output / "current.json").read_bytes()
        after = SW.canonical(self.marker(self.B)) + b"\n"
        SW.publish_json(self.output, SW.JOURNAL, {"format": SW.JOURNAL_FORMAT, "history": [],
            "pending": {"plan_sha256": first["plan_sha256"], "previous": self.A, "target": self.B,
                        "before_sha256": hashlib.sha256(before).hexdigest(),
                        "after_sha256": hashlib.sha256(after).hexdigest()}})
        altered = {**self.marker(self.A), "status": "operator-edit"}
        SW.publish_json(self.output, "current.json", altered)
        report = SW.recover(self.output)
        self.assertEqual(report["status"], "conflicting_operator_edit")
        self.assertIsNone(report["actual_generation"])
        self.assertEqual(json.loads((self.output / "current.json").read_bytes()), altered)
        self.assertIsNotNone(SW.journal(self.output)["pending"])

    def test_symlinked_marker_and_lock_are_refused(self):
        original = self.output / "original"
        (self.output / "current.json").rename(original)
        (self.output / "current.json").symlink_to(original)
        with self.assertRaises(OSError):
            self.planned(self.B)
        (self.output / "current.json").unlink()
        original.rename(self.output / "current.json")
        foreign = Path(self.temp.name) / "unrelated"
        foreign.write_text("keep")
        (self.output / SW.LOCK.NAME).symlink_to(foreign)
        with self.assertRaises(OSError):
            SW.apply(self.output, self.B, self.SOURCE, self.SOURCE, self.planned(self.B)["plan_sha256"])
        self.assertEqual(foreign.read_text(), "keep")

    def test_source_without_lifetime_lock_is_incompatible_even_if_receipt_matches(self):
        source = Path(self.temp.name) / "old-source"
        (source / "scripts").mkdir(parents=True)
        (source / "scripts/pilot-run.py").write_text("# accepted old runner without transition lock\n")
        with patch.object(SW, "source_identity", return_value=self.summaries[self.A]["source"]):
            with self.assertRaisesRegex(ValueError, "source_run_lifetime_lock_unavailable"):
                SW.source_compatible(source, self.summaries[self.A]["source"])

    def test_orphaned_selected_process_refuses_even_without_live_lock(self):
        current = self.summaries[self.A]
        current["agent_path"] = str(Path(sys.executable).resolve())
        # This unittest process itself is excluded; a separate owned process
        # demonstrates observation of a surviving child after its lock is gone.
        import subprocess
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with self.assertRaisesRegex(ValueError, "active_or_uncertain_pilot_run"):
                SW.require_inactive(current, self.summaries[self.B])
        finally:
            child.terminate()
            child.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()

@unittest.skipUnless(os.name == "posix", "FIFO controls require POSIX")
class SpecialRecordReads(unittest.TestCase):
    def test_record_entrypoints_refuse_fifo_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            for operation in ["marker", "journal", "generation", "recover"]:
                with self.subTest(operation=operation):
                    output = base / operation
                    output.mkdir(mode=0o700)
                    (output / "generations").mkdir(mode=0o700)
                    if operation == "journal":
                        record = output / SW.JOURNAL
                    elif operation == "generation":
                        directory = output / "generations" / ("a" * 32)
                        directory.mkdir(mode=0o700)
                        record = directory / "selection.json"
                    else:
                        record = output / "current.json"
                    os.mkfifo(record, 0o600)
                    program = """
import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location("owned_transition",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
output=Path(sys.argv[2]);operation=sys.argv[3]
try:
    if operation=="generation":
        module.generation(output,"a"*32,output)
    else:
        result=getattr(module,operation)(output)
        if operation=="recover":
            assert result["status"]=="conflicting_operator_edit"
            print("refused-unknown-pointer")
            raise SystemExit(0)
except ValueError as error:
    assert str(error)=="owned_bounded_record_required",str(error)
    print("refused-special-record")
    raise SystemExit(0)
raise SystemExit("special record accepted")
"""
                    result = subprocess.run(
                        [sys.executable, "-I", "-B", "-c", program,
                         str(ROOT / "scripts/switch-prepared-pilot.py"), str(output), operation],
                        capture_output=True, text=True, timeout=3, check=False)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("refused-", result.stdout)
