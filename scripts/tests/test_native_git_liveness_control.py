# SPDX-License-Identifier: Apache-2.0
"""Audit correlation must not turn another session's expiry into a pass."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("git_lease_control", Path(__file__).resolve().parents[1] / "native_git_liveness_control.py")
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class LeaseEvidence(unittest.TestCase):
    def test_granted_lease_must_match_exact_session_and_duration(self):
        row = {"event": "native_liveness_enrolled", "session_id": "owned", "session": "epoch", "lease_seconds": 2}
        self.assertEqual(M.enrolled_epoch([row], "owned", 2), "epoch")
        for rows, sid, seconds in (([], "owned", 2), ([row], "other", 2), ([row], "owned", 10),
                                   ([row, row], "owned", 2)):
            with self.assertRaises(RuntimeError):
                M.enrolled_epoch(rows, sid, seconds)

    def test_only_native_expiry_with_exact_session_and_epoch_is_evidence(self):
        row = {"event": "native_session_expired", "session_id": "owned", "session": "epoch"}
        self.assertTrue(M.expired([row], "owned", "epoch"))
        for bad in ({**row, "session": "other"}, {**row, "session_id": "other"},
                    {**row, "event": "native_session_retired"},
                    {**row, "event": "native_liveness_expired"}):
            self.assertFalse(M.expired([bad], "owned", "epoch"))
