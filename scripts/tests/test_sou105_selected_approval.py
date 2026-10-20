# SPDX-License-Identifier: Apache-2.0
"""Fault controls for independent kernel witness; no Linux execution claim."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("sou105", Path(__file__).resolve().parents[1] / "verify-sou105-selected-approval.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class Witness(unittest.TestCase):
    def count(self, text, kind):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "syscalls"
            path.write_text(text)
            return M.trace_effects(path, kind)

    def test_git_failed_attempts_and_unrelated_peer_do_not_count(self):
        trace = '12 execve("/mcp-runtime/git", ["git", "show", "HEAD"], 0x1) = -1 EACCES (Permission denied)\n'
        trace += '13 execve("/mcp-runtime/git", ["git", "status"], 0x1) = 0\n'
        trace += '14 execve("/mcp-runtime/git", ["git", "show", "HEAD"], 0x1) = 0\n'
        self.assertEqual(self.count(trace, "git"), 1)
        self.assertEqual(self.count(trace + trace, "git"), 2, "duplicate execution must be visible")

    def test_unfinished_syscalls_are_joined_by_process_not_order(self):
        trace = '12 execve("/mcp-runtime/git", ["git", "show", "HEAD"], 0x1 <unfinished ...>\n'
        trace += '13 openat(AT_FDCWD, "/workspace/notes.txt", O_RDONLY|O_CLOEXEC <unfinished ...>\n'
        self.assertEqual(self.count(trace, "git"), 0)
        trace += '13 <... openat resumed>) = 7\n12 <... execve resumed>) = 0\n'
        self.assertEqual(self.count(trace, "git"), 1)
        self.assertEqual(self.count(trace, "filesystem"), 1)
        # Padding must not collapse distinct process/thread IDs into one empty
        # key and attribute a sibling's completion to the target syscall.
        padded = "\n".join("    " + row for row in trace.splitlines()) + "\n"
        self.assertEqual(self.count(padded, "git"), 1)
        self.assertEqual(self.count(padded, "filesystem"), 1)

    def test_only_successful_exact_read_counts(self):
        trace = '15 openat(AT_FDCWD, "/workspace/other.txt", O_RDONLY) = 4\n'
        trace += '15 openat(AT_FDCWD, "/workspace/notes.txt", O_RDONLY) = -1 EACCES (Permission denied)\n'
        trace += '15 openat(AT_FDCWD, "/workspace/notes.txt", O_WRONLY) = 4\n'
        self.assertEqual(self.count(trace, "filesystem"), 0)
        trace += '15 openat(AT_FDCWD, "/workspace/notes.txt", O_RDONLY|O_CLOEXEC) = 4\n'
        self.assertEqual(self.count(trace, "filesystem"), 1)

if __name__ == "__main__":
    unittest.main()
