# SPDX-License-Identifier: Apache-2.0
"""Owned provider scheduling must not spend approval leases on host startup."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ask_scheduling', ROOT / 'scripts/qualify-pilot-ask.py')
ASK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASK)


class ProposalScheduling(unittest.TestCase):
    def pilot(self, pending=False, dispatched=False):
        return SimpleNamespace(proposals=ASK.ProposalGate(deferred=True), offered=set(),
            process=SimpleNamespace(poll=lambda: None),
            operator=lambda command: ['pending'] if pending else [], undispatched=lambda: not dispatched)

    def test_provider_cannot_offer_while_deferred(self):
        gate = ASK.ProposalGate(deferred=True)
        result = []
        thread = threading.Thread(target=lambda: result.append(gate.wait(timeout=2)))
        thread.start()
        try:
            self.assertTrue(gate.ready.wait(timeout=1))
            self.assertEqual(result, [])
            gate.release(); thread.join(timeout=1)
            self.assertEqual(result, [True])
        finally:
            gate.cancel(); thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_all_hosts_must_be_ready_before_any_release(self):
        pilots = [self.pilot(), self.pilot()]
        pilots[0].proposals.ready.set()
        results = []
        thread = threading.Thread(target=lambda: results.append(ASK.release_ready_pilots(pilots, seconds=2)))
        thread.start()
        try:
            self.assertFalse(any(p.proposals.released.is_set() for p in pilots))
            pilots[1].proposals.ready.set(); thread.join(timeout=2)
            self.assertEqual(len(results), 1)
            self.assertTrue(all(p.proposals.released.is_set() for p in pilots))
        finally:
            for pilot in pilots: pilot.proposals.cancel()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_failed_pre_release_controls_leave_every_gate_closed(self):
        for pending, dispatched in [(True, False), (False, True)]:
            pilots = [self.pilot(), self.pilot(pending=pending, dispatched=dispatched)]
            for pilot in pilots: pilot.proposals.ready.set()
            with self.assertRaises(ValueError):
                ASK.release_ready_pilots(pilots, seconds=.1)
            self.assertFalse(any(p.proposals.released.is_set() for p in pilots))

    def test_cancellation_wakes_provider_without_authorizing_proposals(self):
        gate = ASK.ProposalGate(deferred=True)
        gate.cancel()
        self.assertFalse(gate.wait(timeout=.1))
        normal = ASK.ProposalGate()
        self.assertTrue(normal.wait(timeout=.1))


if __name__ == '__main__':
    unittest.main()
