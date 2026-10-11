# SPDX-License-Identifier: Apache-2.0
"""Data-free, deterministic CP2 semantics regression smoke tests (no dataset, network or sealed material)."""
import unittest

from sou13cp2.generate import labels_from_execution
from sou13cp2.semantics import execute, program_errors

ACTIONS = ('read', 'write', 'delete', 'send_data', 'change_permissions')


def classify(program, args):
    execution = execute(program, args)
    labels, unknown, _ = labels_from_execution(execution, 'synthetic-test')
    return labels, unknown, execution


class ClosedProgramSemantics(unittest.TestCase):
    def test_closed_program_read_send(self):
        program = [{'op': 'read', 'store': 'files', 'key': '$path', 'into': 'data'},
                   {'op': 'send', 'channel': 'http', 'to': '$url', 'payload': '@data'}]
        labels, unknown, rec = classify(program, {'path': 'example.csv', 'url': 'https://example.test/inbox'})
        self.assertEqual(labels, {'read': True, 'write': False, 'delete': False, 'send_data': True,
                                  'change_permissions': False})
        self.assertIs(unknown, False)
        self.assertEqual([x['event'] for x in rec['trace']], ['store_read', 'send'])
        self.assertIs(rec['audit']['clean'], True)

    def test_opaque_keeps_known_effects_and_masks_other_actions(self):
        program = [{'op': 'send', 'channel': 'email', 'to': '$to', 'payload': 'hello'},
                   {'op': 'opaque', 'component': 'unmodeled'}]
        labels, unknown, _ = classify(program, {'to': 'user@example.test'})
        self.assertIs(unknown, True)
        self.assertIs(labels['send_data'], True)
        for action in ACTIONS:
            if action != 'send_data':
                self.assertIsNone(labels[action], action)  # unproven effects stay null, never coerced to false

    def test_dry_run_no_effect_vs_mutation(self):
        program = [{'op': 'when', 'arg': 'dry_run', 'equals': True,
                    'then': [{'op': 'compute', 'fn': 'plan', 'inputs': ['$version']}],
                    'else': [{'op': 'set', 'store': 'settings', 'key': 'schema', 'value': '$version'}]}]
        self.assertEqual(program_errors(program), [])
        dry, dry_unknown, _ = classify(program, {'dry_run': True, 'version': 'v2'})
        real, real_unknown, _ = classify(program, {'dry_run': False, 'version': 'v2'})
        self.assertIs(dry_unknown, False)
        self.assertIs(real_unknown, False)
        self.assertFalse(any(dry.values()))
        self.assertIs(real['write'], True)
        self.assertTrue(all(real[a] is False for a in ACTIONS if a != 'write'))

    def test_unknown_operation_rejected_not_silently_no_effect(self):
        self.assertTrue(program_errors([{'op': 'exec', 'code': 'rm -rf /'}]))


if __name__ == '__main__':
    unittest.main()
