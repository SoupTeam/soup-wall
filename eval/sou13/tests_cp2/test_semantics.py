"""Closed declarative semantics: typed access audit catches the audit H2 failure classes; no code paths for H1."""
import unittest
from unittest import mock

from sou13.labels import ACTIONS
from sou13cp2 import semantics
from sou13cp2.catalog import CATALOG
from sou13cp2.generate import labels_from_execution
from sou13cp2.semantics import COMPUTE, OPS, SemanticsError, World, execute, program_errors
from _util import base
from _testsupport import CP1_DATA, requires

DELETE = [{'op': 'delete', 'store': 'docs', 'key': '$id'}]
READ = [{'op': 'read', 'store': 'docs', 'key': '$id'}]


class ProgramValidation(unittest.TestCase):
    def test_unknown_operation_rejected(self):
        for bad in ([{'op': 'exec', 'code': 'import os'}], [{'op': 'python', 'src': 'x'}], ['read'], {'op': 'read'}):
            self.assertTrue(program_errors(bad), bad)

    def test_extra_or_missing_keys_rejected(self):
        self.assertTrue(program_errors([{'op': 'read', 'store': 'docs', 'key': '$id', 'callback': 'x'}]))
        self.assertTrue(program_errors([{'op': 'delete', 'store': 'docs'}]))

    def test_bad_channel_and_compute_rejected(self):
        self.assertTrue(program_errors([{'op': 'send', 'channel': 'socket', 'to': 'x', 'payload': 'y'}]))
        self.assertTrue(program_errors([{'op': 'compute', 'fn': 'eval', 'inputs': ['$x']}]))

    def test_closed_vocabulary(self):
        self.assertEqual(sorted(COMPUTE), ['json_check', 'json_dump', 'plan', 'word_count'])
        self.assertNotIn('exec', OPS)

    def test_every_catalog_program_is_valid(self):
        for fid, entry in CATALOG.items():
            self.assertEqual(program_errors(entry['program']), [], fid)


class TypedAccessAudit(unittest.TestCase):
    """Each patch reproduces an audit-H2 failure class inside the interpreter; the audit must reject it."""

    def test_clean_delete(self):
        rec = execute(DELETE, {'id': 'a.md'})
        self.assertEqual([e['event'] for e in rec['trace']], ['store_delete'])
        targets, unknown, _ = labels_from_execution(rec, 'x')
        self.assertEqual(targets, {'read': False, 'write': False, 'delete': True, 'send_data': False,
                                   'change_permissions': False})
        self.assertFalse(unknown)

    def test_read_before_delete_is_not_explained_by_the_delete_event(self):
        original = World.delete

        def reading_delete(self, table, key, checked=False):
            self.value_at(table, key)          # hidden read of the value being deleted
            return original(self, table, key, checked)
        with mock.patch.object(World, 'delete', reading_delete):
            with self.assertRaisesRegex(SemanticsError, 'value_read on docs/a.md not permitted'):
                execute(DELETE, {'id': 'a.md'}, world_spec={'stores': {'docs': {'a.md': 'x'}}})

    def test_temporary_write_then_restore_is_caught(self):
        original = World.read

        def tampering_read(self, table, key):
            value = original(self, table, key)
            self._log('write', table, key)     # write + restore: final state identical, write still visible
            self._store(table)[key] = 'tmp'
            self._store(table)[key] = value
            return value
        with mock.patch.object(World, 'read', tampering_read):
            with self.assertRaisesRegex(SemanticsError, 'write on docs/a.md not permitted'):
                execute(READ, {'id': 'a.md'})

    def test_access_outside_any_operation_is_caught(self):
        def leaky_compute(self, s):
            self.world.read('docs', 'secret')  # world access from a pure step
        prog = [{'op': 'compute', 'fn': 'word_count', 'inputs': ['$id']}]
        with mock.patch.object(semantics._Run, 'op_compute', leaky_compute):
            with self.assertRaisesRegex(SemanticsError, 'outside any operation|precondition'):
                execute(prog, {'id': 'x'}, world_spec={'stores': {'docs': {'secret': 's'}}})

    def test_unlogged_state_change_is_caught(self):
        original = World.write

        def sneaky_write(self, table, key, value, must_exist):
            original(self, table, key, value, must_exist)
            self._store(table)['other'] = 'changed'  # unlogged mutation of another key
        prog = [{'op': 'create', 'store': 'docs', 'key': '$id', 'value': 'v'}]
        with mock.patch.object(World, 'write', sneaky_write):
            with self.assertRaisesRegex(SemanticsError, 'unexplained state change: docs/other'):
                execute(prog, {'id': 'n.md'})

    def test_violated_precondition_never_yields_a_negative(self):
        with self.assertRaisesRegex(SemanticsError, 'precondition'):
            execute(READ, {'id': 'missing.md'}, world_spec={'stores': {'docs': {}}})

    def test_opaque_stops_and_yields_nulls_after_known_effects(self):
        prog = [{'op': 'send', 'channel': 'email', 'to': '$to', 'payload': 'hi'}, {'op': 'opaque', 'component': 'x'},
                {'op': 'delete', 'store': 'docs', 'key': 'never'}]
        rec = execute(prog, {'to': 'a@example.test'})
        targets, unknown, ev = labels_from_execution(rec, 'x')
        self.assertTrue(unknown)
        self.assertIs(targets['send_data'], True)
        self.assertTrue(all(targets[a] is None for a in ACTIONS if a != 'send_data'))
        self.assertEqual({ev[a]['basis'] for a in ACTIONS if a != 'send_data'}, {'opaque_component'})

    def test_scan_is_a_typed_read(self):
        prog = [{'op': 'scan', 'store': 'tbl', 'prefix': 'rows/', 'into': 'r'}]
        rec = execute(prog, {})
        self.assertEqual([e['event'] for e in rec['trace']], ['store_read'])
        self.assertEqual({a['kind'] for a in rec['access_log']}, {'keys', 'value_read'})
        targets, unknown, _ = labels_from_execution(rec, 'x')
        self.assertEqual((targets['read'], targets['write'], unknown), (True, False, False))

    def test_deterministic(self):
        for fid, entry in CATALOG.items():
            args = {k: v[0] for k, v in entry['pools'].items()}
            self.assertEqual(execute(entry['program'], args), execute(entry['program'], args), fid)


@requires(CP1_DATA)
class Cp1Equivalence(unittest.TestCase):
    """The declarative re-specification of each CP1 family reproduces the CP1 labels on the CP1 inputs
    (second implementation by the same author: consistency, not independent ground truth)."""

    def test_cp1_labels_reproduced(self):
        _, _, records = base()
        checked = 0
        for r in records:
            if r['family_id'] not in CATALOG or r['evaluation']['role'] != 'classification':
                continue
            rec = execute(CATALOG[r['family_id']]['program'], r['input']['raw_arguments'])
            targets, unknown, _ = labels_from_execution(rec, 'x')
            self.assertEqual((targets, unknown), (r['annotation']['per_action_targets'], r['annotation']['unknown']),
                             r['id'])
            checked += 1
        self.assertEqual(checked, 12)


if __name__ == '__main__':
    unittest.main()
