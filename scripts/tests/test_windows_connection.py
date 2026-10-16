# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "test-windows-connection.py"
SPEC = importlib.util.spec_from_file_location("windows_connection_driver", SCRIPT)
D = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(D)

class NativeEvidenceTests(unittest.TestCase):
    def valid(self):
        lines = ["test mcp::connection::windows::tests::" + name + " ... ok" for name in sorted(D.NATIVE_TESTS)]
        return "\n".join(lines + ["test result: ok. 14 passed; 0 failed; 0 ignored;"])

    def test_complete_native_log_passes(self):
        self.assertTrue(D.native_tests_passed(self.valid(), 0))

    def test_zero_test_filter_is_refused(self):
        self.assertFalse(D.native_tests_passed("test result: ok. 0 passed; 0 failed; 0 ignored;", 0))

    def test_missing_boundary_test_is_refused(self):
        text = self.valid().replace("boundary_replacement_retains_external_inode ... ok", "other ... ok")
        self.assertFalse(D.native_tests_passed(text, 0))

    def test_duplicate_or_failed_result_is_refused(self):
        self.assertFalse(D.native_tests_passed(self.valid() + "\ntest mcp::connection::windows::tests::crash_child ... ok", 0))
        self.assertFalse(D.native_tests_passed(self.valid(), 1))
        self.assertFalse(D.native_tests_passed(self.valid().replace("0 ignored", "1 ignored"), 0))

if __name__ == "__main__":
    unittest.main()
