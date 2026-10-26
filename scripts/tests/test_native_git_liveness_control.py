# SPDX-License-Identifier: Apache-2.0
"""Audit correlation must not turn another session's expiry into a pass."""
import importlib.util
import queue
import subprocess
from pathlib import Path
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location("git_lease_control", Path(__file__).resolve().parents[1] / "native_git_liveness_control.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class LeaseEvidence(unittest.TestCase):
    def test_granted_lease_must_match_exact_session_and_duration(self):
        row = {"event": "native_liveness_enrolled", "session_id": "owned", "session": "epoch", "lease_seconds": 2, "released": True}
        self.assertEqual(M.enrolled_epoch([row], "owned", 2), "epoch")
        for rows, sid, seconds in (([], "owned", 2), ([row], "other", 2), ([row], "owned", 10),
                                   ([row, row], "owned", 2), ([{**row, "released": False}], "owned", 2)):
            with self.assertRaises(RuntimeError):
                M.enrolled_epoch(rows, sid, seconds)

    def test_only_native_expiry_with_exact_session_and_epoch_is_evidence(self):
        row = {"event": "native_session_expired", "session_id": "owned", "session": "epoch", "released": False}
        self.assertTrue(M.expired([row], "owned", "epoch"))
        for bad in ({**row, "session": "other"}, {**row, "session_id": "other"},
                    {**row, "event": "native_session_retired"},
                    {**row, "event": "native_liveness_expired"}, {**row, "released": True}):
            self.assertFalse(M.expired([bad], "owned", "epoch"))

    def test_stdout_queue_is_drained_to_eof_and_unread_results_cannot_pass(self):
        def client(items, alive=False):
            lines = queue.Queue()
            for item in items:
                lines.put(item)
            return SimpleNamespace(lines=lines, received=[], reader=SimpleNamespace(
                join=lambda timeout: None, is_alive=lambda: alive))
        observed = M.drain_host_eof(client([None]))
        self.assertTrue(observed["eof_observed"])
        for items, alive in (([], False), ([None], True), ([None, b"{}\n"], False),
                             ([b'{"id":90,"result":{}}\n', None], False),
                             ([b"malformed\n", None], False)):
            with self.assertRaises(RuntimeError):
                M.drain_host_eof(client(items, alive))

    def test_cleanup_timeout_does_not_export_the_collector_command(self):
        sentinel = "private-qualification-sentinel"
        def close():
            raise subprocess.TimeoutExpired(["agentfw", "--child-authority", sentinel], 8)
        with self.assertRaises(RuntimeError) as failure:
            M.safe_close(SimpleNamespace(close=close))
        self.assertNotIn(sentinel, str(failure.exception))
        self.assertEqual(str(failure.exception), "owned collector cleanup deadline exceeded")
