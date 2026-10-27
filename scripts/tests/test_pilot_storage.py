# SPDX-License-Identifier: Apache-2.0
"""Storage outcome controls; loader/helper checks are not native pilot acceptance."""
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("pilot_storage_test", ROOT / "scripts/qualify-pilot-storage.py")
STORAGE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(STORAGE)


class ReportControls(unittest.TestCase):
    def test_unexecuted_cases_keep_separate_fixed_denominator(self):
        report = STORAGE.finish(STORAGE.new_report())
        self.assertEqual(report["required"], 23)
        self.assertEqual(report["counts"]["incomplete"], 23)
        self.assertFalse(report["native_acceptance"])
        self.assertEqual(report["status"], "incomplete")
        for stage in ("publication", "startup", "audit"):
            self.assertTrue(all(stage + "-" + name.lower() in STORAGE.CASES for name in STORAGE.ERRORS))

    def test_removed_duplicate_reordered_or_lowered_denominator_is_rejected(self):
        for change in (lambda report: report["cases"].pop(),
                       lambda report: report["cases"].append(copy.deepcopy(report["cases"][0])),
                       lambda report: report["cases"].reverse(),
                       lambda report: report.update(required=22)):
            report = STORAGE.new_report()
            change(report)
            with self.assertRaises(STORAGE.Failure):
                STORAGE.finish(report)

    def test_partial_cannot_be_promoted_by_summary(self):
        report = STORAGE.new_report()
        STORAGE.measure(report, STORAGE.CASES[0], lambda: {"input": "owned"})
        report.update(status="passed", native_acceptance=True, counts={"passed": 23})
        STORAGE.finish(report)
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["native_acceptance"])
        self.assertEqual(report["counts"]["passed"], 1)

    def test_unsupported_is_nonacceptance_without_hidden_skip(self):
        report = STORAGE.new_report()
        report["cases"][0].update(status="unsupported", reason="native_linux_x86_64_required")
        STORAGE.finish(report)
        self.assertEqual(report["status"], "unsupported")
        self.assertFalse(report["native_acceptance"])
        self.assertEqual(len(report["remaining_blockers"]), len(STORAGE.CASES))

    def test_pass_requires_evidence_valid_duration_and_known_outcome(self):
        for change in ({"status": "passed", "reason": None, "elapsed_ms": 1},
                       {"status": "passed", "reason": None, "elapsed_ms": None, "evidence": {"owned": True}},
                       {"elapsed_ms": float("nan")}, {"elapsed_ms": True}, {"status": "skipped"}):
            report = STORAGE.new_report()
            report["cases"][0].update(change)
            with self.assertRaises(STORAGE.Failure):
                STORAGE.finish(report)

    def test_failed_case_cannot_be_replaced_and_exception_does_not_leak(self):
        report = STORAGE.new_report()
        def broken():
            raise OSError("secret-test-token")
        self.assertFalse(STORAGE.measure(report, STORAGE.CASES[0], broken))
        with self.assertRaises(STORAGE.Failure):
            STORAGE.measure(report, STORAGE.CASES[0], lambda: {"replacement": True})
        self.assertNotIn("secret-test-token", json.dumps(STORAGE.finish(report)))

    def test_slow_case_fails_with_original_evidence(self):
        report = STORAGE.new_report()
        with patch.object(STORAGE.time, "monotonic", side_effect=[1, 182, 183]):
            self.assertFalse(STORAGE.measure(report, STORAGE.CASES[0], lambda: {"observed": True}))
        self.assertEqual(report["cases"][0]["reason"], "storage_case_deadline")
        self.assertEqual(report["cases"][0]["evidence"], {"observed": True})

    def complete(self):
        report = STORAGE.new_report()
        for row in report["cases"]:
            row.update(status="passed", reason=None, elapsed_ms=1, evidence={"owned": True})
        before = {"dirty": False, "commit": "a" * 40, "tree": "b" * 40, "files_sha256": "c" * 64}
        report.update(source_before=before, source_after=copy.deepcopy(before),
                      selected_sha256={role: "d" * 64 for role in STORAGE.PILOT.ROLES},
                      environment={"os": "Linux", "machine": "x86_64", "kernel": "6.8-owned",
                                   "non_root": True, "ubuntu": "24.04"})
        report.update({key: "e" * 64 for key in ("selection_sha256", "strace_sha256", "driver_sha256", "fixture_sha256")})
        return report

    def test_all_green_requires_native_platform_and_exact_source_inputs(self):
        for change in (lambda report: report.pop("environment"),
                       lambda report: report["environment"].update(os="Windows"),
                       lambda report: report["environment"].update(kernel="microsoft-WSL2"),
                       lambda report: report["environment"].update(non_root=False),
                       lambda report: report["environment"].update(ubuntu="22.04"),
                       lambda report: report["source_after"].update(dirty=True),
                       lambda report: report["selected_sha256"].pop("agentfw"),
                       lambda report: report.pop("fixture_sha256")):
            report = self.complete()
            change(report)
            with self.assertRaises(STORAGE.Failure):
                STORAGE.finish(report)
        self.assertEqual(STORAGE.finish(self.complete())["status"], "passed")

    def test_public_report_size_bound(self):
        report = STORAGE.new_report()
        report["unbounded"] = "x" * STORAGE.LIMITS["report_bytes"]
        with self.assertRaises(STORAGE.Failure):
            STORAGE.finish(report)


class FaultBoundaryControls(unittest.TestCase):
    def test_fault_cannot_target_foreign_or_symlink_path(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as other:
            root = Path(folder).resolve()
            with self.assertRaises(STORAGE.Failure):
                STORAGE.Fault(root, root / "unused.so", Path(other).resolve() / "foreign", "case", errno.ENOSPC, "write")
            if os.name != "nt":
                (root / "link").symlink_to(Path(other) / "foreign")
                with self.assertRaises(STORAGE.Failure):
                    STORAGE.Fault(root, root / "unused.so", root / "link", "case", errno.ENOSPC, "write")

    def test_fault_arm_is_explicit_and_event_witness_required(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve()
            original_env = dict(os.environ)
            fault = STORAGE.Fault(root, root / "unused.so", root / "owned", "case", errno.ENOSPC, "write")
            self.assertFalse(fault.arm.exists())
            self.assertEqual(dict(os.environ), original_env)
            with self.assertRaises(STORAGE.Failure):
                fault.evidence()
            fault.enable()
            self.assertTrue(fault.arm.exists())
            fault.disable()
            self.assertFalse(fault.arm.exists())
            fault.events.write_text('{"op":"write","errno":28}\n')
            self.assertEqual(fault.evidence(["write"])["injections"], 1)
            with self.assertRaises(STORAGE.Failure):
                fault.evidence(["open"])


class StateSnapshotControls(unittest.TestCase):
    def pilot(self, root):
        pilot = object.__new__(STORAGE.StoragePilot)
        pilot.output = root / "evidence"
        pilot.output.mkdir()
        pilot.workspace, pilot.git_workspace, pilot.home = root / "filesystem", root / "git", root / "home"
        for path in (pilot.workspace, pilot.git_workspace, pilot.home):
            path.mkdir()
        (pilot.workspace / "guide.txt").write_text("owned guide")
        (pilot.git_workspace / "tracked.txt").write_text("owned history")
        (pilot.home / "native-token").write_text("private-token-must-not-be-archived")
        (pilot.home / "config.yaml").write_text("private-config-must-not-be-archived")
        pilot.sentinel = root / "foreign.txt"
        pilot.sentinel.write_text("owned unrelated guard")
        pilot.unrelated = SimpleNamespace(pid=12345, poll=lambda: None)
        pilot.unrelated_start = 67890
        pilot.receiver = SimpleNamespace(bodies=[])
        pilot.secrets = ["private-token-must-not-be-archived"]
        pilot.report = {"source_before": {"commit": "a" * 40, "dirty": False}}
        return pilot

    def test_archived_baseline_and_preserved_maps_match_and_exclude_private_home(self):
        with tempfile.TemporaryDirectory() as folder:
            pilot = self.pilot(Path(folder))
            with patch.object(STORAGE.PILOT.Pilot, "prepare", return_value={"installed": True}) as prepare, \
                 patch.object(STORAGE.PILOT.Pilot, "preserve", return_value={"unchanged": True}) as preserve, \
                 patch.object(STORAGE.PILOT.BASE.ProcessWitness, "identity", return_value=67890):
                baseline = pilot.prepare()["state_snapshot"]
                current = pilot.preserve()["state_snapshot"]
            prepare.assert_called_once_with(None)
            preserve.assert_called_once_with()
            self.assertNotEqual(baseline["file"], current["file"])
            records = []
            for reference in (baseline, current):
                path = pilot.output / reference["file"]
                self.assertEqual(STORAGE.sha(path), reference["sha256"])
                raw = path.read_text()
                self.assertNotIn("private-token", raw)
                self.assertNotIn("private-config", raw)
                record = json.loads(raw)
                self.assertNotIn("home", record)
                self.assertEqual(record["foreign_process"], {"pid": 12345, "expected_start_time_ticks": 67890,
                    "observed_start_time_ticks": 67890, "alive": True})
                self.assertEqual(record["receiver"], {"bodies": []})
                self.assertEqual(record["foreign_file_sha256"], STORAGE.sha(pilot.sentinel))
                records.append(record)
            self.assertEqual(records[0]["filesystem"], STORAGE.PILOT.BASE.snapshot(pilot.workspace))
            self.assertEqual(records[0]["filesystem"], records[1]["filesystem"])
            self.assertEqual(records[0]["git"], records[1]["git"])
            self.assertEqual([record["phase"] for record in records], ["prepared", "preserved"])
            with patch.object(STORAGE.PILOT.Pilot, "cleanup", return_value={"all_owned_processes_stopped": True}):
                self.assertEqual(pilot.cleanup()["state_snapshots"], [baseline, current])

    def test_preservation_or_capture_failure_is_not_hidden(self):
        with tempfile.TemporaryDirectory() as folder:
            pilot = self.pilot(Path(folder))
            with patch.object(STORAGE.PILOT.Pilot, "preserve", side_effect=STORAGE.Failure("workspace_effect_detected")), \
                 patch.object(pilot, "retain_state") as capture:
                with self.assertRaisesRegex(STORAGE.Failure, "workspace_effect_detected"):
                    pilot.preserve()
                capture.assert_not_called()
            with patch.object(STORAGE.PILOT.Pilot, "preserve", return_value={"unchanged": True}), \
                 patch.object(pilot, "retain_state", side_effect=OSError("owned write failure")):
                with self.assertRaises(OSError):
                    pilot.preserve()
            self.assertEqual(list(pilot.output.iterdir()), [])


@unittest.skipUnless(sys.platform == "linux" and shutil.which("cc"), "Linux C loader fixture required")
class LinuxFixtureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stage = tempfile.TemporaryDirectory(prefix="storage-fixture-test-")
        cls.root = Path(cls.stage.name).resolve()
        cls.library = STORAGE.compile_fixture(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.stage.cleanup()

    def child(self, fault, target, other, operation):
        code = ("import os,sys,json\n"
                "results=[]\n"
                "for path in sys.argv[1:]:\n"
                " try:\n"
                "  fd=os.open(path,os.O_WRONLY|os.O_CREAT,0o600)\n"
                "  try:\n"
                "   os.write(fd,b'owned')\n"
                "   os.fsync(fd)\n"
                "  finally: os.close(fd)\n"
                "  results.append(0)\n"
                " except OSError as error: results.append(error.errno)\n"
                "print(json.dumps(results))\n")
        result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(target), str(other)],
            env={"PATH": os.defpath, **fault.env}, capture_output=True, timeout=10, check=True)
        return json.loads(result.stdout)

    def test_native_loader_fails_only_exact_armed_owned_path(self):
        for operation in ("write", "open", "fsync"):
            for name in STORAGE.ERRORS:
                label = operation + "-" + name.lower()
                target, other = self.root / (label + "-target"), self.root / (label + "-other")
                fault = STORAGE.Fault(self.root, self.library, target, label, getattr(errno, name), operation)
                self.assertEqual(self.child(fault, target, other, operation), [0, 0])
                fault.enable()
                try:
                    self.assertEqual(self.child(fault, target, other, operation), [getattr(errno, name), 0])
                    self.assertTrue(fault.evidence([operation])["exact_owned_path"])
                    # Parent process never inherits injection settings.
                    target.write_text("parent remains able to write")
                finally:
                    fault.disable()
                self.assertEqual(self.child(fault, target, other, operation), [0, 0])

    @unittest.skipUnless(shutil.which("strace"), "strace helper observation required")
    def test_actual_publication_helper_preserves_old_marker_and_retries(self):
        output = self.root / "evidence"
        output.mkdir(mode=0o700)
        cases = [("publication-" + name.lower(), "write") for name in STORAGE.ERRORS]
        cases += [("publication-rename", "rename"), ("publication-directory-sync", "directory-sync"),
                  ("interrupted-publication", "interrupt"), ("publication-cleanup-failure", "cleanup")]
        if os.geteuid() != 0:
            cases.append(("publication-directory-permission", "directory-permission"))
        for label, mode in cases:
            with self.subTest(mode=mode, label=label):
                evidence = STORAGE.publication_case(self.root, output, self.library, Path(shutil.which("strace")), label, mode)
                self.assertTrue(evidence["retry_published"])
                self.assertTrue(evidence["foreign_file_preserved"])
                self.assertEqual(evidence["previous_marker_preserved"], mode != "directory-sync")


if __name__ == "__main__":
    unittest.main()
