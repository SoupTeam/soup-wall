# SPDX-License-Identifier: Apache-2.0
"""Fault controls for independent kernel witness; no Linux execution claim."""
import importlib.util
import json
import queue
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("sou105", Path(__file__).resolve().parents[1] / "verify-sou105-selected-approval.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class Witness(unittest.TestCase):
    def count(self, text, kind):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "syscalls"
            path.write_text(text)
            return M.trace_effects(path, kind, git_revision="a" * 40 if kind == "git" else None)

    def test_git_failed_attempts_and_unrelated_peer_do_not_count(self):
        argv = '["git", "diff-tree", "' + "a" * 40 + '", "--root", "-p"]'
        trace = '12 execve("/mcp-runtime/git", ' + argv + ', 0x1) = -1 EACCES (Permission denied)\n'
        trace += '13 execve("/mcp-runtime/git", ["git", "status"], 0x1) = 0\n'
        trace += '13 execve("/mcp-runtime/git", ["git", "show", "HEAD"], 0x1) = 0\n'
        trace += '13 execve("/mcp-runtime/git", ["git", "diff-tree", "' + "b" * 40 + '", "--root", "-p"], 0x1) = 0\n'
        trace += '13 execve("/usr/bin/git", ' + argv + ', 0x1) = 0\n'
        trace += '13 execve("/mcp-runtime/git", ["git", "diff-tree", "' + "a" * 40 + '", "--root"], 0x1) = 0\n'
        self.assertEqual(self.count(trace, "git"), 0)
        trace += '14 execve("/mcp-runtime/git", ' + argv + ', 0x1) = 0\n'
        self.assertEqual(self.count(trace, "git"), 1)
        self.assertEqual(self.count(trace + trace, "git"), 2, "duplicate execution must be visible")

    def test_unfinished_syscalls_are_joined_by_process_not_order(self):
        trace = '12 execve("/mcp-runtime/git", ["git", "diff-tree", "' + "a" * 40 + '", "--root", "-p"], 0x1 <unfinished ...>\n'
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

    def test_trace_overflow_fails_before_parsing_or_export(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "syscalls"
            with path.open("wb") as stream:
                stream.truncate(129)
            with patch.object(M, "TRACE_LIMIT", 128):
                with self.assertRaisesRegex(ValueError, "syscall witness exceeded bound"):
                    M.trace_effects(path, "filesystem")


class OperatorInspect(unittest.TestCase):
    def test_record_and_exact_existing_cli_hint_are_required(self):
        pending, binding = "owned-call", "a" * 64
        record = {"pending_id": pending, "binding_sha256": binding, "args": {"path": "/workspace/notes.txt"}}
        text = json.dumps(record, indent=2) + "\nTo approve exactly this call:\n  agentfw native-approval approve " + pending + " --binding " + binding
        self.assertEqual(M.inspected_output(text, pending, binding), record)
        for bad, identifier, digest in [
            (text + "\n{}", pending, binding),
            (json.dumps(record), pending, binding),
            (text, "foreign-call", binding),
            (text, pending, "b" * 64),
        ]:
            with self.subTest(text=bad, identifier=identifier, digest=digest), self.assertRaises(ValueError):
                M.inspected_output(bad, identifier, digest)

class ApprovedResponseObservation(unittest.TestCase):
    def test_post_decision_observation_preserves_original_bytes(self):
        raw = b'{"jsonrpc":"2.0","id":50,"result":{"content":[]}}\n'
        client = Mock()
        client.receive.return_value = (json.loads(raw), raw)
        evidence = {}
        with patch.object(M.time, "monotonic", side_effect=[10, 22.5]):
            self.assertEqual(M.approved_response(client, evidence), (json.loads(raw), raw))
        client.receive.assert_called_once_with(timeout=35)
        self.assertEqual(evidence, {"approved_response_budget_ms": 35000,
                                    "approved_response_elapsed_ms": 12500.0})

    def test_observation_timeout_fails_once_with_bounded_diagnostics(self):
        client = Mock()
        client.receive.side_effect = queue.Empty
        evidence = {}
        with patch.object(M.time, "monotonic", side_effect=[10, 45]):
            with self.assertRaisesRegex(ValueError, "approved original response not observed within 35 seconds"):
                M.approved_response(client, evidence)
        client.receive.assert_called_once_with(timeout=35)
        self.assertEqual(evidence["approved_response_elapsed_ms"], 35000)

    def test_other_receive_failures_remain_failures(self):
        client = Mock()
        client.receive.side_effect = ValueError("closed before correlated response")
        evidence = {}
        with self.assertRaisesRegex(ValueError, "closed before correlated response"):
            M.approved_response(client, evidence)
        client.receive.assert_called_once_with(timeout=35)
        self.assertIn("approved_response_elapsed_ms", evidence)


if __name__ == "__main__":
    unittest.main()
