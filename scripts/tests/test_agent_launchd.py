# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("launchd_acceptance", Path(__file__).resolve().parents[1] / "test-agent-launchd.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LaunchdEvidenceTests(unittest.TestCase):
    def complete(self):
        return {"native_launchd": True, "architecture": "arm64",
                "cases": [{"name": name, "status": "passed"} for name in MODULE.CASES]}

    def test_missing_skipped_failed_or_non_native_execution_never_passes(self):
        report = self.complete()
        self.assertTrue(MODULE.grade(report))
        changes = [lambda r: r["cases"].pop(), lambda r: r["cases"].append(r["cases"][0]),
                   lambda r: r.update(native_launchd=False), lambda r: r.update(architecture="x86_64"),
                   lambda r: r.update(error="failed"), lambda r: r.update(cleanup_error="still loaded")]
        for change in changes:
            changed = copy.deepcopy(report)
            change(changed)
            self.assertFalse(MODULE.grade(changed))
        for status in ("skipped", "failed", "not_run", True):
            changed = copy.deepcopy(report)
            changed["cases"][0]["status"] = status
            self.assertFalse(MODULE.grade(changed))

    def test_manager_evidence_excludes_environment(self):
        output = b"job = {\n\tstate = running\n\tenvironment = {\n\t\tTOKEN => private\n\t\tpid = 999\n\t}\n\tpid = 123\n}"
        self.assertEqual(MODULE.manager_observation(output), ["state = running", "pid = 123"])


if __name__ == "__main__":
    unittest.main()
