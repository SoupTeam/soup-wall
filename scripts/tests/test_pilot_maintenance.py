# SPDX-License-Identifier: Apache-2.0
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('pilot_maintenance', Path(__file__).resolve().parents[1] / 'pilot_maintenance.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class Marker(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.home.chmod(0o700)
        self.binding = {'format': 'test-binding', 'selection': 'a'*64}
        self.inventory = {'uncertain': False, 'runs': []}

    def create(self, active=False):
        return M.Store.create(self.home, self.binding, maintenance=active)

    def transition(self, store, operation, inventory=None):
        inventory = inventory or self.inventory
        with store.locked(exclusive=True):
            plan = store.plan(self.binding, operation, inventory)
            return store.transition(self.binding, operation, inventory, plan['confirmation_sha256'])

    def test_enter_leave_reopen_and_sibling_are_independent(self):
        with self.create() as store:
            with store.locked(exclusive=False):
                self.assertFalse(store.admit(self.binding)['maintenance'])
            self.assertEqual(self.transition(store, 'enter')['status'], 'entered')
        with M.Store(self.home) as store:
            with store.locked(exclusive=False):
                with self.assertRaises(M.Refusal): store.admit(self.binding)
            self.assertEqual(self.transition(store, 'leave')['status'], 'left')
        sibling = self.home / 'sibling'; sibling.mkdir(mode=0o700)
        with M.Store.create(sibling, self.binding, maintenance=False) as store:
            with store.locked(exclusive=False): self.assertFalse(store.admit(self.binding)['maintenance'])

    def test_stale_confirmation_and_selection_cannot_clear_maintenance(self):
        with self.create(active=True) as store:
            with store.locked(exclusive=False):
                plan = store.plan(self.binding, 'leave', self.inventory)
            self.transition(store, 'enter')
            with store.locked(exclusive=True):
                with self.assertRaises(M.Refusal):
                    store.transition(self.binding, 'leave', self.inventory, plan['confirmation_sha256'])
                other = {'format': 'test-binding', 'selection': 'b'*64}
                new = store.plan(other, 'leave', self.inventory)
                with self.assertRaises(M.Refusal):
                    store.transition(other, 'leave', self.inventory, new['confirmation_sha256'])
            with store.locked(exclusive=False): self.assertEqual(store.snapshot()['mode'], 'entered')

    def test_replaced_same_bytes_marker_and_missing_record_refuse(self):
        with self.create() as store:
            path = self.home / M.DIRECTORY / 'marker.json'
            raw = path.read_bytes(); path.rename(path.with_suffix('.held'))
            path.write_bytes(raw); path.chmod(0o600)
            with self.assertRaises(M.Refusal), store.locked(exclusive=False): store.admit(self.binding)

    def test_initial_enter_cannot_be_cleared_in_place_without_history(self):
        with self.create(active=True) as store:
            path = self.home / M.DIRECTORY / 'marker.json'
            value = M.strict(path.read_bytes()); value['maintenance'] = False
            path.write_bytes(M.encoded(value))
            with store.locked(exclusive=False):
                with self.assertRaises(M.Refusal): store.admit(self.binding)

    def test_symlink_hardlink_foreign_anchor_and_missing_store_are_not_repaired(self):
        with self.create() as store:
            gate = self.home / M.DIRECTORY / 'gate'
            os.link(gate, gate.with_suffix('.alias'))
            with self.assertRaises(M.Refusal), store.locked(exclusive=False): pass
        sibling = self.home / 'other'; sibling.mkdir(mode=0o700)
        target = sibling / M.ANCHOR
        target.write_bytes((self.home / M.ANCHOR).read_bytes()); target.chmod(0o600)
        with self.assertRaises(M.Refusal): M.Store(sibling)
        self.assertEqual(target.read_bytes(), (self.home / M.ANCHOR).read_bytes())
        with self.assertRaises(M.Refusal): M.Store.absent(sibling)

    def test_gate_excludes_transition_but_is_not_a_host_lifetime_lock(self):
        with self.create() as a, M.Store(self.home) as b:
            with a.locked(exclusive=False):
                with self.assertRaises(M.Refusal), b.locked(exclusive=True): pass
            # A long-lived host has released its spawn boundary by this point.
            # Enter succeeds independently of any selected-run lifetime lock.
            self.assertEqual(self.transition(b, 'enter')['status'], 'entered')

    def test_interrupted_leave_is_uncertain_and_only_explicit_enter_recovers(self):
        with self.create(active=True) as store:
            sync = M.os.fsync
            def fail(fd):
                info = os.fstat(fd)
                if M.object_id(info) == store.anchor['marker']:
                    raise OSError('disposable marker sync failure')
                return sync(fd)
            with mock.patch.object(M.os, 'fsync', side_effect=fail):
                with self.assertRaises(OSError): self.transition(store, 'leave')
        with M.Store(self.home) as store:
            with store.locked(exclusive=False):
                self.assertEqual(store.snapshot()['mode'], 'uncertain')
                with self.assertRaises(M.Refusal): store.admit(self.binding)
            with self.assertRaises(M.Refusal): self.transition(store, 'leave')
            self.assertEqual(self.transition(store, 'enter')['status'], 'entered')
            self.assertTrue(any(x.name.startswith('unresolved-') for x in (self.home / M.DIRECTORY / 'events').iterdir()))
            self.assertEqual(self.transition(store, 'leave')['status'], 'left')

    def test_unknown_inventory_never_authorizes_leave(self):
        with self.create(active=True) as store:
            with self.assertRaises(M.Refusal): self.transition(store, 'leave', {'uncertain': True, 'runs': []})
            with store.locked(exclusive=False): self.assertEqual(store.snapshot()['mode'], 'entered')

    def test_signed_old_open_marker_and_unsigned_rehashed_history_cannot_clear_entered_mode(self):
        with self.create() as store:
            path = self.home / M.DIRECTORY / 'marker.json'
            old_open = path.read_bytes()
            self.transition(store, 'enter')
            entered = path.read_bytes()
            path.write_bytes(old_open)
            with store.locked(exclusive=False):
                with self.assertRaises(M.Refusal): store.admit(self.binding)
            path.write_bytes(entered)
            value = M.strict(entered); value['maintenance'] = False
            path.write_bytes(M.encoded(value))
            event = self.home / M.DIRECTORY / 'events' / (value['last_event'] + '.json')
            claim = M.strict(event.read_bytes()); claim['after_sha256'] = M.digest(value)
            event.write_bytes(M.encoded(claim))
            with store.locked(exclusive=False):
                with self.assertRaises(M.Refusal): store.admit(self.binding)


spec = importlib.util.spec_from_file_location('pilot_maintenance_launch', Path(__file__).resolve().parents[1] / 'pilot_maintenance_launch.py')
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)


class Admission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve(); self.base.chmod(0o700)
        self.home = self.base / 'agent-home'; self.home.mkdir(mode=0o700)
        self.root = self.base / 'run-state'; self.root.mkdir(mode=0o700)
        self.bound = {'state_root': str(self.root), 'launch': {'agent_bin': '/owned/agentfw'},
                      'component_home': str(self.home)}
        self.proc = {'pid': os.getpid(), 'uid': os.geteuid(), 'boot': 'test-boot', 'start': 35}
        patch = mock.patch.object(L, 'process', return_value=self.proc); patch.start(); self.addCleanup(patch.stop)
        patch = mock.patch.object(L, 'revalidate'); self.validate = patch.start(); self.addCleanup(patch.stop)
        self.store = L.M.Store.create(self.home, self.bound, maintenance=False); self.addCleanup(self.store.close)

    def claim(self, name='soup-wall-run-owned'):
        private = self.root / name; private.mkdir(mode=0o700)
        with self.store.locked(exclusive=True):
            context = L.claim(self.store, self.bound, private)
        return context

    def inventory(self):
        with self.store.locked(exclusive=False): return L.inventory(self.store, self.bound)

    def test_live_identity_and_confirmed_cleanup_are_distinct(self):
        context = self.claim()
        self.assertEqual(self.inventory()['active'], 1)
        with mock.patch.object(L, 'process', side_effect=ValueError('unavailable')):
            self.assertTrue(self.inventory()['uncertain'])
        L.finish(self.store, context)
        self.assertEqual(self.inventory()['drained'], 1)
        self.assertFalse(self.inventory()['uncertain'])
        self.validate.assert_called()

    def test_missing_run_intent_and_replaced_inventory_are_not_empty_drain(self):
        context = self.claim()
        runs = self.home / L.M.DIRECTORY / 'runs'
        intent = runs / (context['run_id'] + '.json'); intent.unlink()
        with self.assertRaises(ValueError): self.inventory()
        runs.rename(runs.with_name('runs-held')); runs.mkdir(mode=0o700)
        with self.assertRaises(ValueError): self.inventory()

    def test_unsigned_orphan_finished_record_is_not_drain(self):
        context = self.claim()
        path = self.home / L.M.DIRECTORY / 'runs' / (context['run_id'] + '.finished.json')
        path.write_bytes(L.M.encoded({'owned_processes_stopped': True})); path.chmod(0o600)
        with self.assertRaises(ValueError): self.inventory()

    def test_interrupted_claim_is_uncertain_instead_of_implicitly_repaired(self):
        original = L.M.create_at
        def failed(fd, name, value):
            if value.get('intent_sha256') is not None: raise OSError('synthetic sync failure')
            return original(fd, name, value)
        with mock.patch.object(L.M, 'create_at', side_effect=failed):
            with self.assertRaises(OSError): self.claim()
        with self.assertRaises(ValueError): self.inventory()

    def test_other_home_run_is_authenticated_unrelated_and_survives(self):
        first = self.claim()
        other = self.base / 'other-home'; other.mkdir(mode=0o700)
        other_bound = {**self.bound, 'component_home': str(other)}
        with L.M.Store.create(other, other_bound, maintenance=False) as other_store:
            with other_store.locked(exclusive=False):
                self.assertFalse(L.inventory(other_store, other_bound)['uncertain'])
            self.assertEqual(self.inventory()['active'], 1)
        self.assertTrue((Path(first['private']) / 'maintenance-owner.json').is_file())

    def test_unenrolled_legacy_and_pid_reuse_remain_uncertain(self):
        old = self.root / 'soup-wall-run-legacy'; old.mkdir(mode=0o700)
        self.assertTrue(self.inventory()['uncertain'])
        old.rmdir()
        self.claim()
        with mock.patch.object(L, 'process', return_value={**self.proc, 'start': 36}):
            self.assertTrue(self.inventory()['uncertain'])

    def test_second_spawn_check_uses_current_mode_and_exact_parent_context(self):
        context = self.claim()
        expected = {'launcher_parent_pid': os.getpid(), 'home': context['private'] + '/.agentfw',
                    'component_home': str(self.home), 'agent_bin': '/owned/agentfw'}
        self.assertTrue(L.check_spawn(self.home, context['run_id'], expected))
        with self.assertRaises(ValueError):
            L.check_spawn(self.home, context['run_id'], {**expected, 'agent_bin': '/other/agentfw'})
        with self.store.locked(exclusive=True):
            inv = L.inventory(self.store, self.bound)
            plan = self.store.plan(self.bound, 'enter', inv)
            self.store.transition(self.bound, 'enter', inv, plan['confirmation_sha256'])
        with self.assertRaises(ValueError): L.check_spawn(self.home, context['run_id'], expected)
        self.assertEqual(self.inventory()['active'], 1)

    def test_replaced_history_cannot_replay_valid_initial_open_state(self):
        original = (self.home / L.M.DIRECTORY / 'marker.json').read_bytes()
        with self.store.locked(exclusive=True):
            inv = L.inventory(self.store, self.bound)
            plan = self.store.plan(self.bound, 'enter', inv)
            self.store.transition(self.bound, 'enter', inv, plan['confirmation_sha256'])
        events = self.home / L.M.DIRECTORY / 'events'
        events.rename(events.with_name('events-held')); events.mkdir(mode=0o700)
        (self.home / L.M.DIRECTORY / 'marker.json').write_bytes(original)
        with self.assertRaises(ValueError), self.store.locked(exclusive=False): self.store.admit(self.bound)
