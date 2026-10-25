# SPDX-License-Identifier: Apache-2.0
"""Controls for the independent syscall witness, not production runtime results."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("workspace_witness", Path(__file__).resolve().parents[1] / "check_pilot_workspaces.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WitnessControls(unittest.TestCase):
    def trace(self, *rows):
        return ('10 execve("/owned/agentfw", ["agentfw"], 0x0) = 0\n' + '\n'.join(rows) + '\n').encode()

    def test_read_only_stdout_is_not_a_workspace_write(self):
        result = MODULE.analyze_trace(self.trace(
            '10 openat(AT_FDCWD, "/synthetic/config", O_RDONLY|O_NOFOLLOW) = 3',
            '10 write(1, "report", 6) = 6'))
        self.assertEqual(result, {"exec": 1, "children": 0, "network": 0, "mutation_intents": 0})

    def test_helper_execution_and_child_are_rejected(self):
        for row in ('10 execve("/helper", [], 0x0) = -1 ENOENT', '10 clone(SIGCHLD, 0) = 11'):
            with self.subTest(row=row), self.assertRaises(ValueError):
                MODULE.analyze_trace(self.trace(row))

    def test_network_attempt_is_failure_even_when_refused(self):
        for row in ('10 socket(AF_INET, SOCK_STREAM, 0) = -1 EPERM',
                    '10 connect(3, {}, 8) = -1 EPERM',
                    '10 sendmsg(3, {}, 0) = -1 EBADF'):
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, "network_effect"):
                MODULE.analyze_trace(self.trace(row))

    def test_mutations_and_write_opens_are_rejected(self):
        for row in ('10 chmod("/file", 0600) = 0',
                    '10 openat(AT_FDCWD, "/file", O_RDWR) = 3',
                    '10 openat2(AT_FDCWD, "/file", {flags=O_CREAT|O_WRONLY}, 24) = 3',
                    '10 write(3, "changed", 7) = 7',
                    '10 ftruncate(3, 0) = 0',
                    '10 mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, 3, 0) = 0x10',
                    '10 io_uring_setup(8, {}) = 3'):
            with self.subTest(row=row), self.assertRaisesRegex(ValueError, "write_or_repair_effect"):
                MODULE.analyze_trace(self.trace(row))

    def test_incomplete_or_unrecognized_trace_cannot_pass(self):
        for raw in (self.trace('10 openat( <unfinished ...>'), self.trace('10 <... openat resumed> 0'),
                    b'not a trace\n', b''):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                MODULE.analyze_trace(raw)

    def test_oversized_trace_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, "trace_bound"):
            MODULE.analyze_trace(b'x' * (MODULE.MAX_TRACE + 1))

    def test_independent_snapshot_detects_content_and_new_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            file = root / "note"
            file.write_text("before")
            before = MODULE.snapshot(root)
            file.write_text("after")
            self.assertNotEqual(MODULE.snapshot(root), before)
            before = MODULE.snapshot(root)
            (root / "new").write_text("new")
            self.assertNotEqual(MODULE.snapshot(root), before)


if __name__ == "__main__":
    unittest.main()
