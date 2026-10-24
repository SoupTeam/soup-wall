# SPDX-License-Identifier: Apache-2.0
"""Filesystem path driver controls: witness attribution, fixtures and grading.

Public synthetic checks only; Linux original-server coverage is the driver run.
"""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("filesystem_paths", ROOT / "scripts/verify-filesystem-paths.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)

TRACE = r'''100  execve("/srv/agentfw", ["agentfw"], 0x1 /* 3 vars */) = 0
100  clone(child_stack=NULL, flags=SIGCHLD) = 101
101  execve("/usr/bin/python3", ["/usr/bin/python3", "-I"], 0x1 /* 0 vars */) = 0
101  openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
100  clone(child_stack=NULL, flags=CLONE_NEWPID|SIGCHLD) = 102
102  clone(child_stack=NULL, flags=SIGCHLD) = 2 /* 103 in strace's PID NS */
103  execve("/mcp-runtime/node", ["/mcp-runtime/node", "/mcp-server/index.js", "/workspace"], 0x1 /* 1 var */ <unfinished ...>
103  <... execve resumed>)             = 0
103  clone3({flags=CLONE_VM|CLONE_THREAD, child_tid=0x1}, 88 <unfinished ...>
103  <... clone3 resumed>) = 7 /* 104 in strace's PID NS */
104  openat(AT_FDCWD, "/workspace/\320\272\320\270\321\200/\321\204.txt", O_RDONLY|O_CLOEXEC) = 18
104  openat(AT_FDCWD, "/workspace/quote\"name.txt", O_RDONLY|O_CLOEXEC) = 18
104  openat(AT_FDCWD, "/workspace/missing.txt", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
'''


class WitnessControls(unittest.TestCase):
    def trace(self, text):
        handle = tempfile.NamedTemporaryFile("w", delete=False, suffix=".syscalls")
        handle.write(text)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return Path(handle.name)

    def test_strace_spelling_matches_utf8_quotes_and_tabs(self):
        self.assertEqual(M.strace_quoted("/workspace/кир/ф.txt"),
                         '"/workspace/\\320\\272\\320\\270\\321\\200/\\321\\204.txt"')
        self.assertEqual(M.strace_quoted('/workspace/quote"name.txt'), '"/workspace/quote\\"name.txt"')
        self.assertEqual(M.strace_quoted("/workspace/a\tb"), '"/workspace/a\\tb"')

    def test_only_original_server_tasks_count_and_failures_do_not(self):
        path = self.trace(TRACE)
        self.assertEqual(M.server_tasks(TRACE.splitlines()), {"103", "104"})
        self.assertEqual(M.reads(path, "/workspace/кир/ф.txt"), 1)
        self.assertEqual(M.reads(path, '/workspace/quote"name.txt'), 1)
        self.assertEqual(M.reads(path, "/workspace/missing.txt"), 0)
        # A host-side helper reading /etc/passwd is not a server access.
        self.assertEqual(M.reads(path, "/etc/passwd"), 0)
        server_escape = TRACE + '104  openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 19\n'
        self.assertEqual(M.reads(self.trace(server_escape), "/etc/passwd"), 1)

    def test_missing_server_process_fails_instead_of_counting_zero(self):
        with self.assertRaises(ValueError):
            M.reads(self.trace('101  openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3\n'), "/etc/passwd")


class FixtureControls(unittest.TestCase):
    def test_names_cover_the_reviewed_cases(self):
        names = set(M.FILES)
        self.assertEqual(len(M.LONG.encode()), 255)
        self.assertNotEqual(M.NFC, M.NFD)
        self.assertTrue({M.NFC, M.NFD, "a:b.txt", "-leading-dash.txt", ".hidden", "$(touch pwned).txt",
                         'quote"name.txt', "кириллица/файл.txt", "crlf.txt", "empty.txt"} <= names)
        self.assertIn(b"\r\n", M.FILES["crlf.txt"])
        labels = [case[0] for case in M.CASES]
        self.assertEqual(len(labels), len(set(labels)))
        for expect in ("exact", "server_error:ENOENT", "server_error:EACCES", "outside", "spelling", "schema",
                       "unsupported", "classifier_ask", "policy", "false_positive"):
            self.assertIn(expect, {case[3] for case in M.CASES})


class GradeControls(unittest.TestCase):
    def fixture(self):
        source = {"commit": "a" * 40, "tree": "b" * 40, "dirty": False}
        return {"source_before": source, "source_after": dict(source), "source_files_before": {"f": "c"},
                "source_files_after": {"f": "c"}, "skipped": 0,
                "cases": [{"case": label, "passed": True} for label in M.LABELS],
                "workspace_before": {"w": 1}, "workspace_after": {"w": 1}, "outside_reads": {"before": 0, "after": 0},
                "phase": {"client": {"exit_code": 0, "forced_cleanup": False,
                                     "process_cleanup": {"all_stopped": True, "descendant_count": 4}},
                          "daemon_cleanup": {"all_stopped": True}, "daemon_exit_code": -15,
                          "cleanup_audit": {"cleanup_verified": True}},
                "direct_control_cleanup": {"all_stopped": True}, "actual_claude_host": {"status": "pass"}}

    def test_rejects_failed_missing_or_effectful_evidence(self):
        valid = self.fixture()
        M.grade(copy.deepcopy(valid))
        mutations = [
            lambda r: r["cases"].pop(),
            lambda r: r["cases"][5].update(passed=False),
            lambda r: r.update(workspace_after={"w": 2}),
            lambda r: r["outside_reads"].update(after=1),
            lambda r: r.update(skipped=1),
            lambda r: r["source_files_after"].update(f="d"),
            lambda r: r["phase"]["client"].update(forced_cleanup=True),
            lambda r: r["phase"]["cleanup_audit"].update(cleanup_verified=False),
            lambda r: r["direct_control_cleanup"].update(all_stopped=False),
            lambda r: r["actual_claude_host"].update(status="incomplete"),
        ]
        for mutate in mutations:
            report = copy.deepcopy(valid)
            mutate(report)
            with self.assertRaises(ValueError):
                M.grade(report)


if __name__ == "__main__":
    unittest.main()
