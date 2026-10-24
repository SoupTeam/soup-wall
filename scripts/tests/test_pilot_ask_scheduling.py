# SPDX-License-Identifier: Apache-2.0
"""Owned provider scheduling must not spend approval leases on host startup."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import threading
import json
import tempfile
from unittest.mock import patch
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

    def test_expiry_does_not_consume_the_separate_followup_wait(self):
        clock = SimpleNamespace(now=0.0)
        def sleep(seconds):
            self.assertGreaterEqual(seconds, 0)
            clock.now += seconds
        def followup():
            return {"pending_id": "separate-useful-call"} if clock.now >= 21 else None
        with patch.object(ASK.time, "monotonic", side_effect=lambda: clock.now), \
             patch.object(ASK.time, "time_ns", side_effect=lambda: int((1000 + clock.now) * 1_000_000_000)), \
             patch.object(ASK.time, "sleep", side_effect=sleep):
            # The old combined wait ends before the follow-up can be offered.
            with self.assertRaisesRegex(ValueError, "followup_missing"):
                ASK.until(followup, "followup_missing")
            clock.now = 0
            ASK.await_original_expiry(1_020_000)
            self.assertEqual(clock.now, 20)
            result = ASK.until(followup, "followup_missing")
            self.assertEqual(result["pending_id"], "separate-useful-call")
            self.assertLess(clock.now, 22)

    def test_expiry_phase_rejects_unknown_or_unbounded_deadlines(self):
        with patch.object(ASK.time, "time_ns", return_value=1_000_000_000_000), \
             patch.object(ASK.time, "sleep") as sleep:
            for value in (True, "1020000", -1, 1_020_001):
                with self.subTest(expiry=value), self.assertRaises(ValueError):
                    ASK.await_original_expiry(value)
            sleep.assert_not_called()
            ASK.await_original_expiry(999_000)
            sleep.assert_not_called()
            with self.assertRaisesRegex(ValueError, "original_expiry_not_reached"):
                ASK.await_original_expiry(1_020_000)
            sleep.assert_called_once_with(20)

    def test_diagnostic_thread_birth_precedes_parent_clone_return(self):
        event = '{"event":"mcp_verified_inputs_resume","immutable_files":0,"leased_files":1,"rehashed_files":2}\n'
        for result in ('8', '-1 EAGAIN (Resource unavailable)'):
            text = '\n'.join([
                '7 clone(child_stack=NULL, flags=CLONE_VM|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD <unfinished ...>',
                f'8 write(2, {json.dumps(event)}, {len(event)}) = {len(event)}',
                '7 <... clone resumed>) = ' + result,
            ])
            original, pending = ASK.LAUNCH.normalized_syscalls(text)
            self.assertEqual(pending, {})
            self.assertTrue(original[0].startswith('8 write'))
            ordered, pending = ASK.LAUNCH.normalized_syscalls(text, thread_birth_order=True)
            self.assertEqual(pending, {})
            if result == '8':
                self.assertEqual(ASK.LATENCY.reuse_observation(ordered, 7)['leased_files'], 1)
            else:
                with self.assertRaises(ValueError): ASK.LATENCY.reuse_observation(ordered, 7)

    def test_failure_observation_never_exports_raw_results_or_stderr(self):
        secret = 'private-token-and-arguments-never-exported'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # The scrubber receives simulated input entirely in memory. No
            # fixture token is written to a filesystem/log sink by the test.
            pilot = SimpleNamespace(kind='git', process=SimpleNamespace(poll=lambda: None),
                offered={'toolu_primary'}, model=SimpleNamespace(requests=[{}], results={
                    'primary': {'is_error': True, 'content': secret + ' selected asset changed during hashing'}}),
                root=root, trace=root / 'absent', err=SimpleNamespace(flush=lambda: None))
            with patch.object(Path, 'read_bytes', return_value=(secret + ' selected asset read lease lost').encode()):
                result = ASK.Pilot.failure_observation(pilot)
            self.assertNotIn(secret, json.dumps(result))
            self.assertEqual(result['primary_diagnostic'], 'capture_bytes_changed')
            self.assertEqual(result['stderr_diagnostic'], 'read_lease_lost')
            self.assertTrue(result['primary_is_error'])

    def test_cancellation_wakes_provider_without_authorizing_proposals(self):
        gate = ASK.ProposalGate(deferred=True)
        gate.cancel()
        self.assertFalse(gate.wait(timeout=.1))
        normal = ASK.ProposalGate()
        self.assertTrue(normal.wait(timeout=.1))

    def test_finished_pilot_keeps_only_finite_observer_failure_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = 'private-trace-contents-must-not-be-exported'
            trace = SimpleNamespace(exists=lambda: True, stat=lambda: SimpleNamespace(st_size=1),
                                    read_text=lambda: private)
            pilot = SimpleNamespace(kind='git', process=SimpleNamespace(poll=lambda: 0),
                offered=set(), model=SimpleNamespace(requests=[], results={}), root=root,
                trace=trace, setup=SimpleNamespace(binary=root / 'agentfw'),
                err=SimpleNamespace(closed=True, flush=lambda: self.fail('closed stream was flushed')))
            error = ASK.LATENCY.ObservationError('write_syntax', private)
            with patch.object(Path, 'read_bytes', return_value=b''), \
                 patch.object(ASK.LAUNCH, 'normalized_syscalls', return_value=([], {})), \
                 patch.object(ASK.LAUNCH, 'collector_processes', return_value={7: 'git'}), \
                 patch.object(ASK.LATENCY, 'collector_stderr_rows', side_effect=error):
                result = ASK.Pilot.failure_observation(pilot)
            self.assertNotIn(private, json.dumps(result))
            self.assertEqual(result['trace_diagnostic'], dict(
                reason='write_unobserved', kind='write_syntax', record_sha256=error.record_sha256))


if __name__ == '__main__':
    unittest.main()
