# SPDX-License-Identifier: Apache-2.0
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
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

    @unittest.skipUnless(os.name == "nt", "Windows ACL regression")
    def test_fixture_removes_owner_rights_from_directory_and_file(self):
        sid = D.account()["sid"]
        icacls = str(Path(os.environ["SystemRoot"]) / "System32/icacls.exe")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "config.json"
            file.write_text("{}", encoding="utf-8")
            for path in (root, file):
                subprocess.run([icacls, str(path), "/grant", "*S-1-3-4:F"],
                               capture_output=True, check=True, timeout=20)
                before = subprocess.run([icacls, str(path), "/findsid", "*S-1-3-4"],
                                        capture_output=True, check=True, timeout=20)
                self.assertIn(str(path).encode(), before.stdout)
                D.secure(path, sid)
                output = subprocess.run([icacls, str(path), "/findsid", "*S-1-3-4"],
                                        capture_output=True, check=True, timeout=20)
                self.assertNotIn(str(path).encode(), output.stdout)

if __name__ == "__main__":
    unittest.main()
