import builtins
import os
import socket
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13 import fixtures  # noqa: E402
from sou13.sandbox import (CANARY_WORLD, EVENT_TO_ACTION, EvidenceError, ChannelUnavailable, execute,  # noqa: E402
                           labels_from_execution, run_canaries)

COVERED = {a: True for a in ('read', 'write', 'delete', 'send_data', 'change_permissions')}


class Guard(unittest.TestCase):
    def assert_blocked(self, fn):
        rec = execute(fn, {}, CANARY_WORLD)
        self.assertEqual(rec['outcome'], 'sandbox_violation')
        self.assertTrue(rec['guard_violations'])
        with self.assertRaises(EvidenceError):
            labels_from_execution(rec, COVERED)

    def test_blocks_open(self):
        self.assert_blocked(lambda fx, a: open('sou13-nonexistent/x', 'r'))

    def test_blocks_socket(self):
        self.assert_blocked(lambda fx, a: socket.socket())

    def test_blocks_subprocess(self):
        self.assert_blocked(lambda fx, a: subprocess.run(['echo', 'x']))

    def test_blocks_os_remove(self):
        self.assert_blocked(lambda fx, a: os.remove('sou13-nonexistent/x'))

    def test_blocks_import(self):
        self.assert_blocked(lambda fx, a: __import__('urllib.request'))

    def test_direct_collections_import_stays_blocked(self):
        self.assert_blocked(lambda fx, a: __import__('collections', fromlist=('deque',)))

    def test_shell_tokenizer_uses_only_its_stdlib_import(self):
        rec = execute(lambda fx, a: fixtures.sh_tokens('cat a.txt >> b.txt'), {}, CANARY_WORLD)
        self.assertEqual(rec['outcome'], 'completed')
        self.assertEqual(rec['guard_violations'], [])

    def test_violation_recorded_even_if_swallowed(self):
        def sneaky(fx, a):
            try:
                open('sou13-nonexistent/x', 'r')
            except Exception:
                pass
        self.assert_blocked(sneaky)

    def test_guard_restores_originals(self):
        before = (builtins.open, builtins.__import__, socket.socket, subprocess.Popen, os.remove)
        execute(lambda fx, a: open('sou13-nonexistent/x'), {}, CANARY_WORLD)
        self.assertEqual(before, (builtins.open, builtins.__import__, socket.socket, subprocess.Popen, os.remove))


class Coverage(unittest.TestCase):
    def test_canaries_detect_every_channel_and_bypass(self):
        report = run_canaries()
        self.assertTrue(all(report['per_event'].values()), report)
        self.assertTrue(all(report['detectors'].values()), report)
        self.assertEqual(set(report['by_action']), set(COVERED))
        self.assertTrue(all(report['by_action'].values()))

    def test_every_action_has_an_event(self):
        self.assertEqual({a for a, _ in EVENT_TO_ACTION.values()}, set(COVERED))

    def test_unexplained_write_is_detected(self):
        def rogue(fx, a):
            dict.__getitem__(fx._world.tables, 'docs')['k'] = 'tampered'
        rec = execute(rogue, {}, CANARY_WORLD)
        self.assertTrue(rec['unexplained'])
        with self.assertRaises(EvidenceError):
            labels_from_execution(rec, COVERED)

    def test_unexplained_read_is_detected(self):
        rec = execute(lambda fx, a: dict.__getitem__(fx._world.tables, 'docs')['k'], {}, CANARY_WORLD)
        self.assertTrue(rec['unexplained'])

    def test_unexplained_outbox_is_detected(self):
        rec = execute(lambda fx, a: fx._world.outbox.append({'channel': 'x', 'recipient': 'y', 'payload': 'z'}), {}, CANARY_WORLD)
        self.assertTrue(rec['unexplained'])

    def test_missing_canary_coverage_blocks_false_labels(self):
        rec = execute(fixtures.text_stats, {'text': 'a b'}, {})
        with self.assertRaises(EvidenceError):
            labels_from_execution(rec, {**COVERED, 'delete': False})


class Derivation(unittest.TestCase):
    def test_noop_is_all_false_known(self):
        rec = execute(fixtures.text_stats, {'text': 'delete everything'}, {})
        targets, unknown, ev = labels_from_execution(rec, COVERED)
        self.assertEqual(set(targets.values()), {False})
        self.assertFalse(unknown)
        self.assertTrue(all(e['basis'] == 'controlled_execution_absence' for e in ev.values()))

    def test_opaque_keeps_known_and_nulls_rest(self):
        fn, world = fixtures.REGISTRY['report_with_postprocessor']
        rec = execute(fn, {'source_document': 'reports/weekly.md', 'postprocessor': 'p'}, world)
        targets, unknown, _ = labels_from_execution(rec, COVERED)
        self.assertTrue(unknown)
        self.assertIs(targets['read'], True)
        self.assertTrue(all(targets[a] is None for a in ('write', 'delete', 'send_data', 'change_permissions')))

    def test_disabled_channel_raises_if_used(self):
        def sender(fx, a):
            fx.send('http', 'https://x.example.test', 'p')
        with self.assertRaises(ChannelUnavailable):
            execute(sender, {}, {'disabled_actions': ['send_data']})

    def test_execution_is_deterministic(self):
        fn, world = fixtures.REGISTRY['workflow_run']
        args = {'steps': [{'action': 'read_file', 'path': 'inbox/agenda.txt'},
                          {'action': 'send_email', 'to': 't@example.test', 'body': 'x'}]}
        self.assertEqual(execute(fn, args, world), execute(fn, args, world))

    def test_create_refuses_existing_and_append_requires_existing(self):
        with self.assertRaises(ValueError):
            execute(lambda fx, a: fx.create('docs', 'k', 'x'), {}, CANARY_WORLD)
        with self.assertRaises(ValueError):
            execute(lambda fx, a: fx.append('docs', 'missing', 'x'), {}, CANARY_WORLD)
        rec = execute(lambda fx, a: fx.append('docs', 'k', '+'), {}, CANARY_WORLD)
        self.assertEqual([e['event'] for e in rec['trace']], ['store_write'])  # append does not read
        self.assertFalse(rec['unexplained'])

    def test_world_spec_not_mutated(self):
        fn, world = fixtures.REGISTRY['doc_delete']
        before = repr(world)
        execute(fn, {'document_id': 'drafts/q3-old.md'}, world)
        self.assertEqual(repr(world), before)


class ShellModel(unittest.TestCase):
    WORLD = {'stores': {'files': {'a.txt': 'A', 'b.txt': 'B', 'dir/x': 'X'}}, 'acl': {'a.txt': {'posix_mode': '0644'}}}

    def run_sh(self, command):
        fn, _ = fixtures.REGISTRY['posix_sh_model']
        rec = execute(fn, {'command': command}, self.WORLD)
        return rec, labels_from_execution(rec, COVERED, 'model_execution')

    def test_tokenizer_handles_comment_and_operators(self):
        self.assertEqual(fixtures.sh_tokens('ls dir # ; rm -rf dir'), ['ls', 'dir'])
        self.assertEqual(fixtures.sh_tokens('chmod 640 a.txt && ls -l a.txt'),
                         ['chmod', '640', 'a.txt', '&&', 'ls', '-l', 'a.txt'])
        self.assertEqual(fixtures.sh_tokens('cat a.txt >> b.txt'), ['cat', 'a.txt', '>>', 'b.txt'])

    def test_comment_is_not_executed(self):
        rec, (targets, unknown, _) = self.run_sh('ls dir # ; rm -rf dir')
        self.assertEqual([e['event'] for e in rec['trace']], ['store_read'])
        self.assertEqual({a for a, v in targets.items() if v}, {'read'})
        self.assertFalse(unknown)

    def test_append_is_read_plus_write_without_delete(self):
        rec, (targets, unknown, _) = self.run_sh('cat a.txt >> b.txt')
        self.assertEqual({a for a, v in targets.items() if v}, {'read', 'write'})
        self.assertIs(targets['delete'], False)
        self.assertFalse(unknown)

    def test_append_to_missing_file_fails_precondition(self):
        fn, _ = fixtures.REGISTRY['posix_sh_model']
        with self.assertRaises(ValueError):
            execute(fn, {'command': 'cat a.txt >> new.txt'}, self.WORLD)

    def test_out_of_scope_and_unmodelled_are_unknown(self):
        for command, component in [('cat a.txt; eval "$X"', 'd05_out_of_scope:eval'),
                                   ('for f in a; do cat a.txt; done', 'd05_out_of_scope:for'),
                                   ('cat a.txt > b.txt', 'not_modelled:>'),
                                   ('cat a.txt | wc', 'not_modelled:|'),
                                   ('sudo chmod 600 a.txt', 'not_modelled:sudo'),
                                   ('rm -rf dir', 'unmodelled_command:rm')]:
            rec, (_, unknown, _) = self.run_sh(command)
            self.assertTrue(unknown, command)
            self.assertEqual(rec['opaque_component'], component)

    def test_shell_model_never_spawns_processes(self):
        rec, _ = self.run_sh('chmod 640 a.txt && ls -l a.txt')
        self.assertEqual(rec['guard_violations'], [])
        self.assertEqual([e['event'] for e in rec['trace']], ['acl_change', 'store_read'])


if __name__ == '__main__':
    unittest.main()
