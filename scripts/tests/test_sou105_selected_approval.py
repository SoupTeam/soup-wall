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


class PendingPublicationObservation(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.enterContext(patch.object(M.time, "monotonic", side_effect=lambda: self.now))
        self.enterContext(patch.object(M.time, "sleep", side_effect=self.advance))
        self.record = {"pending_id": "selected", "binding_sha256": "a" * 64}
        self.publication = {"event": "mcp_native_approval_pending", "host_call_id": 50, **self.record}
        self.evidence = {}

    def advance(self, seconds):
        self.now += seconds

    def events_after_preparation(self, _path):
        return [self.publication] if self.now >= 6 else []

    def observe(self):
        return M.published_pending(None, {}, Path("owned-collector.log"), 50, self.evidence)

    def test_six_second_preparation_then_exact_pending_among_concurrent_peers(self):
        foreign = {"pending_id": "other", "binding_sha256": "b" * 64}
        def listed(*_args):
            self.assertGreaterEqual(self.now, 6, "broker polled before selected publication")
            return json.dumps([foreign, self.record])
        with patch.object(M.BASE, "events", side_effect=self.events_after_preparation), \
                patch.object(M, "command", side_effect=listed) as command:
            self.assertEqual(self.observe(), self.record)
        command.assert_called_once_with(None, {}, "native-approval", "list")
        observation, = self.evidence["pending_observations"]
        self.assertGreaterEqual(observation["publication_elapsed_ms"], 6000)
        self.assertEqual(observation["publication_budget_ms"], 20000)
        self.assertEqual(observation["broker_budget_ms"], 5000)
        self.assertEqual(observation["broker_elapsed_ms"], 0)

    def test_foreign_or_wrong_kind_events_cannot_start_broker_observation(self):
        unrelated = [{**self.publication, "host_call_id": 70},
                     {**self.publication, "event": "mcp_real_call"},
                     {**self.publication, "host_call_id": True}]
        with patch.object(M.BASE, "events", return_value=unrelated), \
                patch.object(M, "command") as command:
            with self.assertRaisesRegex(ValueError, "publication missed preparation deadline"):
                self.observe()
        command.assert_not_called()
        self.assertGreaterEqual(self.evidence["pending_observations"][0]["publication_elapsed_ms"], 20000)
        self.assertNotIn("broker_elapsed_ms", self.evidence["pending_observations"][0])

    def test_preparation_does_not_extend_five_second_broker_deadline(self):
        foreign = {"pending_id": "other", "binding_sha256": "b" * 64}
        with patch.object(M.BASE, "events", side_effect=self.events_after_preparation), \
                patch.object(M, "command", return_value=json.dumps([foreign])):
            with self.assertRaisesRegex(ValueError, "pending approval state missed declared deadline"):
                self.observe()
        observation, = self.evidence["pending_observations"]
        self.assertGreaterEqual(observation["broker_elapsed_ms"], 5000)
        self.assertLess(observation["broker_elapsed_ms"], 5026)

    def test_changed_published_binding_is_a_failure(self):
        changed = {**self.record, "binding_sha256": "b" * 64}
        with patch.object(M.BASE, "events", return_value=[self.publication]), \
                patch.object(M, "command", return_value=json.dumps([changed])):
            with self.assertRaisesRegex(ValueError, "binding changed"):
                self.observe()

    def test_ambiguous_publication_is_a_failure_before_cli(self):
        with patch.object(M.BASE, "events", return_value=[self.publication, self.publication]), \
                patch.object(M, "command") as command:
            with self.assertRaisesRegex(ValueError, "ambiguous selected approval publication"):
                self.observe()
        command.assert_not_called()

    def test_cleanup_keeps_its_existing_eight_second_deadline(self):
        with patch.object(M.BASE, "events") as events, \
                patch.object(M, "command", return_value=json.dumps([self.record])):
            with self.assertRaisesRegex(ValueError, "pending approval state missed declared deadline"):
                M.pending(None, {}, timeout=8, empty=True)
        events.assert_not_called()
        self.assertGreaterEqual(self.now, 8)
        self.assertLess(self.now, 8.026)


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
