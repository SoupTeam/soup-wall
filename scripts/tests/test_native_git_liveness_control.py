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
    def owner_context(self, combined):
        owner = {"format": "sw-mcp/linux-crash-owner/1", "instance": "owned-instance",
                 "owner_pid": 101, "owner_start_ticks": 11, "sandbox_pid": 102,
                 "sandbox_start_ticks": 12, "pid1_pid": 103, "pid1_start_ticks": 13,
                 "lease_ms": 1500, "failed": False, "reason": "mcp_owner_active"}
        ended = {**owner, "failed": combined,
                 "reason": "mcp_owner_liveness_expired" if combined else "mcp_owner_active"}
        records = [{"event": "mcp_real_owner_start", "owner": owner},
                   {"event": "mcp_real_owner_end", "owner": ended, "cleanup_verified": not combined,
                    "observed_failure": combined},
                   {"event": "mcp_real_server_end", "owner": dict(ended), "profile": "selected-profile",
                    "transport_complete": False, "budget_failure_observed": False,
                    "budget_cleanup_verified": True, "cleanup_verified": not combined,
                    "owner_cleanup_verified": not combined, "owner_failure_observed": combined}]
        cleanup = {"all_stopped": True, "observation_complete": True, "remaining": [],
                   "observed": [{"pid": 100, "start_time_ticks": 10, "parent_process": True},
                                *[{"pid": p, "start_time_ticks": t, "parent_process": False}
                                  for p, t in ((101, 11), (102, 12), (103, 13))],
                                {"pid": 104, "start_time_ticks": 14, "parent_process": False,
                                 "original_git_server": True}]}
        return records, cleanup, {"pid": 100, "start_time_ticks": 10}

    def test_exact_native_and_combined_guard_branches_are_distinct(self):
        for combined, terminal in ((False, "Error: native_liveness_uncertain"),
                                   (True, "Error: pilot_cleanup_unconfirmed")):
            records, cleanup, collector = self.owner_context(combined)
            grade = M.grade_terminal(terminal, records, cleanup, collector, "selected-profile")
            self.assertEqual(grade["production_owner_cleanup_verified"], not combined)
            self.assertEqual(grade["guard_scope"], "combined_native_expiry_and_namespace_owner_guard"
                             if combined else "native_expiry")

    def test_arbitrary_error_or_missing_wrong_owner_context_never_passes(self):
        import copy
        records, cleanup, collector = self.owner_context(True)
        bad = []
        bad.append(("Error: arbitrary_failure", records, cleanup))
        bad.append(("Error: pilot_cleanup_unconfirmed", records[:-1], cleanup))
        wrong = copy.deepcopy(records); wrong[1]["owner"]["instance"] = "other"
        bad.append(("Error: pilot_cleanup_unconfirmed", wrong, cleanup))
        wrong = copy.deepcopy(records); wrong[1]["owner"]["reason"] = "unrelated_failure"
        bad.append(("Error: pilot_cleanup_unconfirmed", wrong, cleanup))
        wrong = copy.deepcopy(records); wrong[2]["owner"]["pid1_start_ticks"] = 99
        bad.append(("Error: pilot_cleanup_unconfirmed", wrong, cleanup))
        wrong = copy.deepcopy(records); wrong[2]["cleanup_verified"] = True
        bad.append(("Error: pilot_cleanup_unconfirmed", wrong, cleanup))
        wrong = copy.deepcopy(cleanup); wrong["observed"] = wrong["observed"][:1]
        bad.append(("Error: pilot_cleanup_unconfirmed", records, wrong))
        wrong = copy.deepcopy(cleanup); wrong["observation_complete"] = False
        bad.append(("Error: pilot_cleanup_unconfirmed", records, wrong))
        bad.append(("Error: native_liveness_uncertain", records, cleanup))
        for terminal, context, processes in bad:
            with self.subTest(terminal=terminal), self.assertRaises(RuntimeError):
                M.grade_terminal(terminal, context, processes, collector, "selected-profile")

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
