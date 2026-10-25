#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reproduce disposable prepared-run fixture checks; never native acceptance."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "scripts/tests"))
import pilot_run_state as S

FILES = (
    "scripts/pilot_run_state.py", "scripts/pilot-runs.py", "scripts/pilot-run-archive.py",
    "scripts/tests/test_pilot_run_operations.py", "scripts/pilot_audit.py",
    "scripts/agent-audit-report.py", "scripts/tests/test_pilot_audit.py",
    "scripts/verify-prepared-run-checkpoint.py",
)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, timeout=10).decode().strip()


class Results(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.rows = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.rows.append({"test": test.id(), "status": "passed"})

    def addError(self, test, error):
        super().addError(test, error)
        self.rows.append({"test": test.id(), "status": "error"})

    def addFailure(self, test, error):
        super().addFailure(test, error)
        self.rows.append({"test": test.id(), "status": "failed"})

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.rows.append({"test": test.id(), "status": "skipped"})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    S.platform()
    before = {"commit": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain"))}
    S.require(before["commit"] == args.expected_commit and not before["dirty"], "clean_exact_source_required")
    with S.Directory(args.output.parent):
        S.require(not args.output.exists(), "output_already_exists")
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FILES}
    suites = unittest.defaultTestLoader.loadTestsFromNames(["test_pilot_run_operations", "test_pilot_audit"])
    result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0, resultclass=Results).run(suites)
    after = {"commit": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain"))}
    passed = result.wasSuccessful() and not result.skipped and before == after
    report = {"format": "sw-prepared-run-fixture-checkpoint/1",
              "status": "fixture-checkpoint-passed" if passed else "fixture-checkpoint-incomplete",
              "source_before": before, "source_after": after, "source_files_sha256": hashes,
              "environment": {"system": platform.system(), "kernel": platform.release(),
                              "python": platform.python_version(), "non_root": os.getuid() != 0,
                              "wsl": "microsoft" in platform.release().lower()},
              "tests_run": result.testsRun, "tests": result.rows,
              "counts": {"failed": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped)},
              "evidence_kind": "disposable_synthetic_files_and_loopback_http_fixtures",
              "real_prepared_runs": False, "real_original_servers": False,
              "launcher_proof_mocked_in_positive_http_fixture": True,
              "foreign_uid_fixture_emulated": True,
              "native_acceptance": False, "provider_calls": 0,
              "remaining_work": ["full_accepted_diagnostic_projection", "genuine_native_ubuntu_prepared_runs",
                                 "native_foreign_ownership_controls", "full_concurrent_race_and_crash_matrix",
                                 "reviewed_partial_removal_recovery", "final_ready_qualification"]}
    S.AUDIT.REPORT._private_output(args.output, S.encoded(report) + b"\n")
    print(json.dumps({"status": report["status"], "tests_run": result.testsRun, "native_acceptance": False}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
