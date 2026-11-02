# SPDX-License-Identifier: Apache-2.0
"""Installed policy-candidate activation: transaction, gating and refusal controls (SOU-209)."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


A = load('activation_tests', 'pilot_policy_activation.py')
SW = A.modules()['sw']
POSIX = unittest.skipUnless(os.name == 'posix', 'POSIX descriptor logic; installed command is Linux-only')
G_OLD, G_NEW = 'a' * 32, 'b' * 32
BASE, CANDIDATE = 'c' * 64, 'd' * 64


def selection(policy_path='/owned/inputs/policy.yaml', policy_sha=BASE, **extra):
    files = {role: {'path': '/owned/' + role, 'sha256': str(i) * 64} for i, role in enumerate(
        ('agentfw', 'git_launcher', 'sandbox_tests', 'bwrap', 'git', 'claude', 'python', 'filesystem_classifier', 'git_classifier'))}
    files.update(node={'path': '/owned/gen/node/bin/node', 'sha256': 'e' * 64}, npm={'path': '/owned/gen/node/bin/npm', 'sha256': 'f' * 64},
                 policy={'path': policy_path, 'sha256': policy_sha})
    value = {'format': 'sw-installed-pilot-selection/3', 'source': {'commit': '1' * 40}, 'git_selection': {'id': 'git-readonly-v1'},
             'expected_refusal': {'verdict': 'ask', 'rule': 'r'}, 'files': files,
             'prepared_profiles': {k: {'format': 'f', 'registry_sha256': '2' * 64, 'package_tree_sha256': '3' * 64,
                                       'policy_sha256': '4' * 64, 'profile': {'path': '/owned/' + k + '/profile.json', 'sha256': '5' * 64},
                                       'installation_sha256': '6' * 64} for k in ('filesystem', 'git')}}
    value.update(extra)
    return value


class Fixture(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.prefix = self.root / 'prefix'
        self.prefix.mkdir(mode=0o700)
        self.preparation = self.prefix / 'preparation'
        self.preparation.mkdir(mode=0o700)
        (self.preparation / 'generations').mkdir(mode=0o700)
        self.state_path = self.prefix / 'front-door.json'
        self.state = {'format': 'sw-pilot-front-door/1', 'commit': '1' * 40, 'selection': str(self.preparation / 'generations' / G_OLD / 'selection.json'),
                      'selection_sha256': '7' * 64, 'status': 'prepared-not-active', 'inputs': {}}
        self.write_state(self.state)
        self.marker = {'format': A.MARKER_FORMAT, 'generation': G_OLD, 'selection_sha256': '7' * 64, 'status': 'prepared-not-active'}
        SW.publish_json(self.preparation, 'current.json', self.marker)
        self.front = types.SimpleNamespace(layout=lambda prefix: {'state': prefix / 'front-door.json'},
                                           write_state=lambda prefix, value: self.write_state(value))

    def write_state(self, value):
        # Same exclusive-temporary-then-replace shape as the front door's own write_state.
        temporary = self.state_path.with_name(self.state_path.name + '.tmp')
        with temporary.open('x') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(A.state_bytes(value).decode())
        os.replace(temporary, self.state_path)

    def ctx(self):
        _, raw, marker = SW.marker(self.preparation)
        return {'home': self.root, 'prefix': self.prefix, 'preparation': self.preparation, 'state': dict(self.state),
                'state_raw': self.state_path.read_bytes(), 'selection': selection(), 'marker': marker, 'marker_raw': raw,
                'paths': {'agentfw': Path('/owned/agentfw'), 'claude': Path('/owned/claude'), 'policy': Path('/owned/policy')},
                'policy_raw': b'base'}

    def plan(self, digest='9' * 64):
        return {'confirmation_sha256': digest}

    NEW_SELECTION = b'{"verified":"new generation"}'

    def target(self):
        path = self.preparation / 'generations' / G_NEW / 'selection.json'
        if not path.exists():
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            path.write_bytes(self.NEW_SELECTION)
            path.chmod(0o600)
        return {'generation': G_NEW, 'selection_sha256': A.sha(self.NEW_SELECTION), 'selection_path': path,
                'policy_sha256': CANDIDATE, 'candidate_sha256': 'e' * 64}


@POSIX
class Journal(Fixture):
    def test_roundtrip_bounds_and_strictness(self):
        self.assertEqual(A.read_journal(self.preparation), A.empty_journal())
        value = A.empty_journal()
        value['history'] = [{'n': i} for i in range(A.HISTORY)]
        A.write_journal(self.preparation, value)
        self.assertEqual(A.read_journal(self.preparation), value)
        for bad in ({'format': 'other', 'pending': None, 'history': []}, {'format': A.JOURNAL_FORMAT, 'pending': None},
                    {'format': A.JOURNAL_FORMAT, 'pending': 'x', 'history': []},
                    {'format': A.JOURNAL_FORMAT, 'pending': None, 'history': [{}] * (A.HISTORY + 1)}):
            (self.preparation / A.JOURNAL).write_bytes(json.dumps(bad).encode())
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                A.read_journal(self.preparation)
        with self.assertRaisesRegex(ValueError, 'journal_limit'):
            A.write_journal(self.preparation, {**A.empty_journal(), 'history': [{'x': 'y' * A.LIMIT}]})

    def test_linked_or_shared_journal_refuses(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'{}')
        (self.preparation / A.JOURNAL).symlink_to(outside)
        with self.assertRaises(ValueError):
            A.read_journal(self.preparation)


@POSIX
class StoredPolicy(Fixture):
    def facts(self, **over):
        return {'candidate_sha256': 'e' * 64, 'policy_raw': b'deny-only policy', 'manifest_raw': b'{"active":false}', **over}

    def test_private_immutable_copy_and_idempotent_retry(self):
        path = A.store_candidate(self.preparation, self.facts())
        self.assertEqual(path.read_bytes(), b'deny-only policy')
        self.assertEqual(oct(path.stat().st_mode & 0o777), '0o600')
        self.assertEqual(oct(path.parent.stat().st_mode & 0o777), '0o700')
        self.assertEqual(A.store_candidate(self.preparation, self.facts()), path)

    def test_changed_extra_or_replaced_copy_refuses_without_overwrite(self):
        path = A.store_candidate(self.preparation, self.facts())
        with self.assertRaisesRegex(ValueError, 'staged_policy_changed'):
            A.store_candidate(self.preparation, self.facts(policy_raw=b'other'))
        (path.parent / 'surprise').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'staged_policy_changed'):
            A.store_candidate(self.preparation, self.facts())
        self.assertEqual(path.read_bytes(), b'deny-only policy')


class SameScope(unittest.TestCase):
    def new(self, **over):
        value = selection(policy_path='/owned/operator-policies/x/policy.yaml', policy_sha=CANDIDATE)
        value.update(over)
        return value

    ITEM = {'path': '/owned/operator-policies/x/policy.yaml', 'sha256': CANDIDATE}

    def test_only_the_selected_policy_may_differ(self):
        A.same_scope(selection(), self.new(), self.ITEM)

    def test_every_other_change_refuses(self):
        def mutate(change):
            value = self.new()
            change(value)
            return value
        cases = {
            'source': lambda v: v['source'].update(commit='9' * 40),
            'expected_refusal': lambda v: v['expected_refusal'].update(verdict='deny'),
            'git_selection': lambda v: v['git_selection'].update(id='other'),
            'new_key': lambda v: v.update(linked_worktree={}),
            'executable': lambda v: v['files']['agentfw'].update(sha256='f' * 64),
            'classifier': lambda v: v['files']['git_classifier'].update(path='/other'),
            'node': lambda v: v['files']['node'].update(sha256='0' * 64),
            'role_removed': lambda v: v['files'].pop('git'),
            'policy_other_file': lambda v: v['files']['policy'].update(sha256='0' * 64),
            'registry': lambda v: v['prepared_profiles']['git'].update(registry_sha256='0' * 64),
            'profile_policy': lambda v: v['prepared_profiles']['git'].update(policy_sha256='0' * 64),
            'profile_format': lambda v: v['prepared_profiles']['git'].update(format='x'),
        }
        for name, change in cases.items():
            with self.subTest(name), self.assertRaises(ValueError):
                A.same_scope(selection(), mutate(change), self.ITEM)

    def test_package_tree_digest_may_differ_because_it_embeds_install_paths(self):
        value = self.new()
        value['prepared_profiles']['git']['package_tree_sha256'] = '0' * 64
        A.same_scope(selection(), value, self.ITEM)

    def test_node_path_may_move_but_not_its_digest(self):
        value = self.new()
        value['files']['node']['path'] = '/owned/newgen/node/bin/node'
        A.same_scope(selection(), value, self.ITEM)


class IdleScan(unittest.TestCase):
    def test_wrappers_that_name_the_selected_agent_are_not_orphaned_runs(self):
        self.assertIn(os.getpid(), A.ancestors())
        ctx = {'paths': {'agentfw': Path('/owned/agentfw'), 'claude': Path('/owned/claude')}}
        with patch.object(SW, 'require_inactive') as scan:
            A.require_idle(ctx)
        summary = scan.call_args.args[0]
        self.assertEqual((summary['agent_path'], summary['claude_path']), ('/owned/agentfw', '/owned/claude'))
        self.assertIn(os.getpid(), scan.call_args.kwargs['ignore'])

    def test_a_real_selected_process_elsewhere_still_refuses(self):
        ctx = {'paths': {'agentfw': Path('/owned/agentfw'), 'claude': Path('/owned/claude')}}
        with patch.object(SW, 'require_inactive', side_effect=ValueError('active_or_uncertain_pilot_run')), \
                self.assertRaisesRegex(ValueError, 'active_or_uncertain'):
            A.require_idle(ctx)


class Blockers(unittest.TestCase):
    VIEW = {'mode': 'entered', 'installation': 'matches', 'active': 0, 'uncertain': False}

    def test_only_an_entered_certain_idle_matching_installation_is_eligible(self):
        self.assertEqual(A.blockers(self.VIEW, A.empty_journal()), [])
        cases = [({'mode': 'open'}, 'maintenance_entry_required'), ({'mode': 'not-enrolled'}, 'maintenance_entry_required'),
                 ({'mode': 'uncertain'}, 'maintenance_state_uncertain'), ({'installation': 'mismatch'}, 'installation_mismatch'),
                 ({'active': 1}, 'runs_active'), ({'uncertain': True}, 'runs_uncertain')]
        for change, code in cases:
            with self.subTest(code):
                self.assertIn(code, A.blockers({**self.VIEW, **change}, A.empty_journal()))
        pending = {**A.empty_journal(), 'pending': {'x': 1}}
        self.assertIn('recover_pending_activation_first', A.blockers(self.VIEW, pending))


@POSIX
class Transition(Fixture):
    def publish(self, journal=None, ctx=None):
        ctx = ctx or self.ctx()
        journal = journal if journal is not None else A.read_journal(self.preparation)
        with patch.object(SW, 'require_inactive'):
            return A.publish(ctx, self.front, journal, self.plan(), 'activate', self.target())

    def marker_generation(self):
        return json.loads(SW.marker(self.preparation)[1])['generation']

    def state_selection(self):
        return json.loads(self.state_path.read_bytes())['selection']

    def test_publication_moves_marker_state_and_journal_together(self):
        pending = self.publish()
        self.assertEqual(self.marker_generation(), G_NEW)
        self.assertEqual(self.state_selection(), pending['target_selection_path'])
        journal = A.read_journal(self.preparation)
        self.assertIsNone(journal['pending'])
        self.assertEqual([(h['operation'], h['outcome'], h['previous_generation']) for h in journal['history']],
                         [('activate', 'published', G_OLD)])
        self.assertNotIn('after_state', journal['history'][0])
        self.assertTrue((self.preparation / 'generations').is_dir())

    def crash_at(self, point):
        def boom(name):
            if name == point:
                raise KeyboardInterrupt
        with patch.object(A, 'inject', side_effect=boom), self.assertRaises(KeyboardInterrupt):
            self.publish()

    def recover(self):
        ctx = {'prefix': self.prefix, 'preparation': self.preparation, 'marker': {'generation': G_OLD}}
        return A.recover_pending(ctx, self.front, A.read_journal(self.preparation))

    def test_interrupt_after_intent_keeps_the_valid_old_generation(self):
        self.crash_at('after_intent')
        self.assertEqual(self.marker_generation(), G_OLD)
        self.assertEqual(self.state_selection(), self.state['selection'])
        self.assertIsNotNone(A.read_journal(self.preparation)['pending'])
        self.assertEqual(self.recover()['status'], 'interrupted_before_publication')
        self.assertIsNone(A.read_journal(self.preparation)['pending'])
        self.assertEqual(self.marker_generation(), G_OLD)

    def test_interrupt_between_marker_and_state_rolls_forward_only_the_journaled_state(self):
        self.crash_at('after_marker')
        self.assertEqual((self.marker_generation(), self.state_selection()), (G_NEW, self.state['selection']))
        self.assertEqual(self.recover()['status'], 'completed_by_recovery')
        self.assertEqual(self.state_selection(), str(self.target()['selection_path']))
        self.assertIsNone(A.read_journal(self.preparation)['pending'])
        self.assertEqual(A.read_journal(self.preparation)['history'][-1]['outcome'], 'completed_by_recovery')

    def test_a_leftover_state_temporary_from_a_failed_write_cannot_wedge_recovery(self):
        self.crash_at('after_marker')
        leftover = self.state_path.with_name(self.state_path.name + '.tmp')
        leftover.write_bytes(b'half written state')
        leftover.chmod(0o600)
        self.assertEqual(self.recover()['status'], 'completed_by_recovery')
        self.assertFalse(leftover.exists())
        self.assertEqual(self.state_selection(), str(self.target()['selection_path']))

    def test_a_stale_temporary_is_swept_before_intent_so_publication_cannot_split(self):
        leftover = self.state_path.with_name(self.state_path.name + '.tmp')
        leftover.write_bytes(b'stale')
        leftover.chmod(0o600)
        self.publish()
        self.assertFalse(leftover.exists())
        self.assertEqual((self.marker_generation(), self.state_selection()), (G_NEW, str(self.target()['selection_path'])))

    def test_an_unsafe_state_temporary_refuses_without_removal_or_intent(self):
        leftover = self.state_path.with_name(self.state_path.name + '.tmp')
        outside = self.root / 'outside'
        outside.write_bytes(b'owned elsewhere')
        for kind in ('symlink', 'hardlink', 'directory'):
            with self.subTest(kind):
                if kind == 'symlink':
                    leftover.symlink_to(outside)
                elif kind == 'hardlink':
                    os.link(outside, leftover)
                else:
                    leftover.mkdir()
                with self.assertRaisesRegex(ValueError, 'state_temporary_unsafe'):
                    self.publish()
                self.assertEqual(self.marker_generation(), G_OLD)
                self.assertFalse((self.preparation / A.JOURNAL).exists())
                self.assertTrue(leftover.exists() or leftover.is_symlink())
                if kind == 'directory':
                    leftover.rmdir()
                else:
                    leftover.unlink()
        self.assertEqual(outside.read_bytes(), b'owned elsewhere')

    def test_interrupt_after_state_settles_without_replay(self):
        self.crash_at('after_state')
        self.assertEqual(self.recover()['status'], 'published_before_journal_completion')
        self.assertEqual(self.marker_generation(), G_NEW)

    def test_operator_edit_is_a_conflict_that_is_never_overwritten(self):
        self.crash_at('after_intent')
        foreign = {'format': A.MARKER_FORMAT, 'generation': 'c' * 32, 'selection_sha256': '1' * 64, 'status': 'prepared-not-active'}
        SW.publish_json(self.preparation, 'current.json', foreign)
        result = self.recover()
        self.assertEqual(result['status'], 'conflicting_operator_edit')
        self.assertEqual(self.marker_generation(), 'c' * 32)
        self.assertIsNotNone(A.read_journal(self.preparation)['pending'])
        self.state_path.write_bytes(b'{}')
        self.assertEqual(self.recover()['status'], 'conflicting_operator_edit')

    def test_unrecognizable_marker_is_a_conflict_not_a_repair(self):
        self.crash_at('after_marker')
        (self.preparation / 'current.json').write_bytes(b'garbage')
        (self.preparation / 'current.json').chmod(0o600)
        self.assertEqual(self.recover()['status'], 'conflicting_operator_edit')
        self.assertEqual((self.preparation / 'current.json').read_bytes(), b'garbage')

    def test_a_generation_changed_after_verification_is_never_selected(self):
        target = self.target()
        target['selection_path'].write_bytes(b'{"changed":true}')
        with patch.object(SW, 'require_inactive'), self.assertRaisesRegex(ValueError, 'generation_changed_before_publication'):
            A.publish(self.ctx(), self.front, A.empty_journal(), self.plan(), 'activate', target)
        self.assertEqual(self.marker_generation(), G_OLD)
        self.assertFalse((self.preparation / A.JOURNAL).exists())

    def test_second_publication_from_the_same_stale_context_refuses(self):
        stale = self.ctx()
        self.publish(ctx=stale)
        with self.assertRaisesRegex(ValueError, 'concurrent_selection_change'):
            self.publish(ctx=stale, journal=A.read_journal(self.preparation))
        self.assertEqual(self.marker_generation(), G_NEW)

    def test_concurrent_marker_or_state_edit_before_publication_refuses_cleanly(self):
        for edit in ('marker', 'state'):
            with self.subTest(edit):
                self.setUp()
                ctx = self.ctx()
                if edit == 'marker':
                    SW.publish_json(self.preparation, 'current.json', {**self.marker, 'generation': 'c' * 32})
                else:
                    self.write_state({**self.state, 'status': 'edited'})
                with self.assertRaisesRegex(ValueError, 'concurrent_selection_change'):
                    self.publish(ctx=ctx)
                self.assertIsNone(A.read_journal(self.preparation)['pending'])

    def test_active_or_uncertain_process_refuses_before_any_intent(self):
        with patch.object(SW, 'require_inactive', side_effect=ValueError('active_or_uncertain_pilot_run')), \
                self.assertRaisesRegex(ValueError, 'active_or_uncertain'):
            A.publish(self.ctx(), self.front, A.empty_journal(), self.plan(), 'activate', self.target())
        self.assertFalse((self.preparation / A.JOURNAL).exists())
        self.assertEqual(self.marker_generation(), G_OLD)

    def test_held_selection_lock_refuses(self):
        with SW.LOCK.hold(self.preparation, exclusive=False), self.assertRaisesRegex(ValueError, 'in_use_or_transitioning'):
            self.publish()
        self.assertEqual(self.marker_generation(), G_OLD)

    def test_revert_requires_a_previously_confirmed_published_target(self):
        self.publish()
        journal = A.read_journal(self.preparation)
        ctx = self.ctx()
        ctx['marker']['generation'] = G_NEW
        with patch.object(A, 'verified_generation', return_value=(Path(self.state['selection']), '7' * 64, selection())):
            target = A.revert_target(ctx, self.front, journal, G_OLD)
            self.assertEqual((target['generation'], target['selection_sha256']), (G_OLD, '7' * 64))
            for generation in ('c' * 32, G_NEW, 'zz', None):
                with self.subTest(generation), self.assertRaises(ValueError):
                    A.revert_target(ctx, self.front, journal, generation)
        with patch.object(A, 'verified_generation', return_value=(Path(self.state['selection']), '0' * 64, selection())), \
                self.assertRaisesRegex(ValueError, 'revert_target_changed'):
            A.revert_target(ctx, self.front, journal, G_OLD)
        with patch.object(A, 'verified_generation', return_value=(self.preparation / 'other.json', '7' * 64, selection())), \
                self.assertRaisesRegex(ValueError, 'revert_target_changed'):
            A.revert_target(ctx, self.front, journal, G_OLD)

    def test_interrupted_activation_is_not_a_revert_target(self):
        self.crash_at('after_intent')
        self.recover()
        ctx = self.ctx()
        ctx['marker']['generation'] = G_NEW
        with self.assertRaisesRegex(ValueError, 'not_previously_confirmed'):
            A.revert_target(ctx, self.front, A.read_journal(self.preparation), G_OLD)


@POSIX
class RecoveryEntrypoint(Transition):
    """Public `recover`/`inspect` dispatch for a real marker-new/state-old split (reviewer boundary control)."""

    def setUp(self):
        super().setUp()
        self.view = {'mode': 'entered', 'installation': 'matches', 'active': 0, 'uncertain': False, 'revision': 3,
                     'marker_sha256': 'a' * 64, 'inventory_sha256': 'b' * 64}
        self.front.INSTALLED_HOME = self.root
        self.front.PROJECT_HOME = self.root
        self.front.PREP = object()
        self.front.read_state = lambda prefix: json.loads(self.state_path.read_bytes())
        self.front.source = lambda: {'dirty': False, 'commit': '1' * 40}
        self.front.verified_state = lambda prefix: (_ for _ in ()).throw(Exception('selection_not_current'))
        self.args = types.SimpleNamespace(action='recover', prefix=self.prefix, state_root=self.root)
        modules = A.modules()
        self.observed = []
        paths = {'agentfw': Path('/owned/agentfw'), 'claude': Path('/owned/claude'), 'policy': Path('/owned/policy')}
        for patcher in (patch.dict(modules, {'runner': types.SimpleNamespace(selected=lambda ns: (selection(), paths, {}))}),
                        patch.object(modules['pml'], 'selected_binding', return_value={'b': 1}),
                        patch.object(A, 'require_supported_home'),
                        patch.object(A, 'observe', side_effect=lambda ctx, exclusive: self.observe(exclusive)),
                        patch.object(SW, 'output_root')):
            patcher.start()
            self.addCleanup(patcher.stop)

    def observe(self, exclusive):
        self.observed.append(('exclusive', exclusive))
        return contextlib.ExitStack(), None, dict(self.view)

    def split(self):
        self.crash_at('after_marker')
        self.assertEqual((self.marker_generation(), self.state_selection()), (G_NEW, self.state['selection']))

    def test_public_recover_rolls_forward_exactly_the_journaled_state(self):
        self.split()
        with patch.object(A, 'require_idle') as idle:
            result = A.operation(self.args, self.front)
            idle.assert_called_once()
        self.assertEqual((result['status'], result['actual_generation']), ('completed_by_recovery', G_NEW))
        self.assertEqual(self.observed, [('exclusive', True)])
        self.assertEqual(self.state_selection(), str(self.target()['selection_path']))
        self.assertIsNone(A.read_journal(self.preparation)['pending'])
        self.assertEqual(A.read_journal(self.preparation)['history'][-1]['outcome'], 'completed_by_recovery')

    def test_public_inspect_reports_the_split_instead_of_refusing_blindly(self):
        self.split()
        self.args.action = 'inspect'
        report = A.operation(self.args, self.front)
        self.assertEqual((report['status'], report['state'], report['matches_journal']), ('inspected', 'split-pending-recovery', True))
        self.assertEqual(report['marker_generation'], G_NEW)
        self.assertNotIn('"after_state":', json.dumps(report))
        self.assertEqual(self.marker_generation(), G_NEW)
        self.assertEqual(self.state_selection(), self.state['selection'])

    def test_every_blocker_refuses_before_any_roll_forward(self):
        self.split()
        for change, code in (({'mode': 'open'}, 'maintenance_entry_required'), ({'mode': 'uncertain'}, 'maintenance_state_uncertain'),
                             ({'active': 1}, 'runs_active'), ({'uncertain': True}, 'runs_uncertain'),
                             ({'installation': 'mismatch'}, 'installation_mismatch')):
            with self.subTest(code):
                self.view = {**self.view, **change}
                with patch.object(A, 'require_idle'), self.assertRaisesRegex(ValueError, code):
                    A.operation(self.args, self.front)
                self.assertEqual(self.state_selection(), self.state['selection'])
                self.assertIsNotNone(A.read_journal(self.preparation)['pending'])
                self.view = {'mode': 'entered', 'installation': 'matches', 'active': 0, 'uncertain': False}

    def test_a_live_selected_process_refuses_before_any_roll_forward(self):
        self.split()
        with patch.object(SW, 'require_inactive', side_effect=ValueError('active_or_uncertain_pilot_run')), \
                self.assertRaisesRegex(ValueError, 'active_or_uncertain'):
            A.operation(self.args, self.front)
        self.assertEqual(self.state_selection(), self.state['selection'])
        self.assertIsNotNone(A.read_journal(self.preparation)['pending'])

    def test_an_unlocked_gate_is_required_so_an_unenrolled_home_cannot_recover(self):
        self.split()
        with patch.object(A, 'observe', side_effect=ValueError('policy_activation_maintenance_entry_required')), \
                self.assertRaisesRegex(ValueError, 'maintenance_entry_required'):
            A.operation(self.args, self.front)
        self.assertEqual(self.state_selection(), self.state['selection'])

    def test_operator_edits_stay_fail_closed_and_build_nothing(self):
        self.split()
        for edit in ('state', 'marker'):
            with self.subTest(edit):
                held = (self.state_path.read_bytes(), (self.preparation / 'current.json').read_bytes())
                if edit == 'state':
                    self.write_state({**self.state, 'status': 'edited'})
                else:
                    SW.publish_json(self.preparation, 'current.json', {**self.marker, 'generation': 'c' * 32})
                with patch.object(A, 'recovery_context', side_effect=AssertionError('built context for a conflict')), \
                        patch.object(A, 'observe', side_effect=AssertionError('took the gate for a conflict')):
                    result = A.operation(self.args, self.front)
                self.assertEqual(result['status'], 'conflicting_operator_edit')
                self.assertIsNotNone(A.read_journal(self.preparation)['pending'])
                self.state_path.write_bytes(held[0])
                (self.preparation / 'current.json').write_bytes(held[1])

    def test_unreadable_marker_is_a_conflict_not_a_repair(self):
        self.split()
        (self.preparation / 'current.json').write_bytes(b'garbage')
        (self.preparation / 'current.json').chmod(0o600)
        self.assertEqual(A.operation(self.args, self.front)['status'], 'conflicting_operator_edit')
        self.assertEqual((self.preparation / 'current.json').read_bytes(), b'garbage')

    def test_main_exit_codes_for_the_public_command(self):
        self.split()
        front = types.SimpleNamespace(**vars(self.front), PROG='owned', platform_reason=lambda: None)
        out = io.StringIO()
        argv = ['recover', '--prefix', str(self.prefix), '--state-root', str(self.root)]
        with patch.object(A.sys, 'platform', 'linux'), patch.object(A, 'require_idle'), contextlib.redirect_stdout(out):
            self.assertEqual(A.main(argv, front), 0)
        self.assertEqual(json.loads(out.getvalue())['status'], 'completed_by_recovery')
        out = io.StringIO()
        self.write_state({**self.state, 'status': 'edited'})
        self.crash_at_new_pending()
        with patch.object(A.sys, 'platform', 'linux'), contextlib.redirect_stdout(out):
            self.assertEqual(A.main(argv, front), 2)
        self.assertEqual(json.loads(out.getvalue())['status'], 'conflicting_operator_edit')

    def crash_at_new_pending(self):
        journal = A.read_journal(self.preparation)
        journal['pending'] = {**{k: 'f' * 64 for k in ('before_marker_sha256', 'after_marker_sha256', 'before_state_sha256',
                                                       'after_state_sha256')}, 'after_state': {}, 'operation': 'activate',
                              'plan_sha256': '9' * 64, 'previous_generation': G_OLD, 'target_generation': G_NEW}
        A.write_journal(self.preparation, journal)

    def test_no_pending_intent_reports_a_settled_installation(self):
        self.publish()
        modules = A.modules()
        with patch.object(A, 'context', return_value={**self.ctx(), 'bound': {}}):
            result = A.operation(self.args, self.front)
        self.assertEqual(result['status'], 'settled')


class Cancellation(unittest.TestCase):
    def test_term_unwinds_as_cancellation_and_the_previous_handler_is_restored(self):
        import signal
        previous = signal.getsignal(signal.SIGTERM)
        with A.terminating_as_cancellation():
            handler = signal.getsignal(signal.SIGTERM)
            self.assertIsNot(handler, previous)
            with self.assertRaises(KeyboardInterrupt):
                handler(signal.SIGTERM, None)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_main_reports_cancellation_without_claiming_an_outcome(self):
        front = types.SimpleNamespace(PROG='owned', platform_reason=lambda: None)
        out = io.StringIO()
        with patch.object(A.sys, 'platform', 'linux'), patch.object(A, 'operation', side_effect=KeyboardInterrupt), \
                contextlib.redirect_stdout(out):
            code = A.main(['inspect', '--prefix', '/a', '--state-root', '/b'], front)
        value = json.loads(out.getvalue())
        self.assertEqual((code, value['status'], value['reason'], value['executed']), (130, 'cancelled', 'policy_activation_cancelled', None))

    def test_operator_views_never_print_private_paths_or_stored_state(self):
        entry = {'operation': 'activate', 'previous_selection_path': '/private/a', 'target_selection_path': '/private/b',
                 'after_state': {'x': 1}, 'before_marker_sha256': 'a' * 64}
        view = A.public(entry, 'pending')
        self.assertEqual(view, {'operation': 'activate', 'before_marker_sha256': 'a' * 64, 'outcome': 'pending'})
        self.assertIn('previous_selection_path', A.record(entry, 'pending'))


class Facts(unittest.TestCase):
    def setUp(self):
        self.ctx = {'paths': {'agentfw': Path('/owned/agentfw'), 'policy': Path('/owned/policy')}, 'selection': selection(),
                    'policy_raw': b'base'}
        self.args = types.SimpleNamespace(profile=Path('/p'), constraints=Path('/c'), examples=Path('/e'), candidate=Path('/x'),
                                          expect_candidate='a' * 64)
        self.inspected = {'status': 'inspected', 'active': False, 'executed': False, 'pins': {'policy_sha256': BASE}}
        self.validated = {'status': 'validated_inert', 'active': False, 'executed': False, 'restricting_only': True,
                          'candidate_sha256': 'a' * 64, 'base_policy_sha256': BASE, 'added_rules': 1,
                          'policy_sha256': A.sha(b'candidate'), 'constraints_sha256': 'b' * 64}
        self.constraints = {'format': 'sw-operator-policy-constraints/1', 'deny_actions': ['read_only'], 'deny_tools': [],
                            'allowed_destinations': None}
        sw = types.SimpleNamespace(regular=lambda path: (None, b'candidate' if path.name == 'policy.yaml' else
                                                         json.dumps(self.constraints).encode() if path.name == 'constraints.json' else b'{}'))
        patcher = patch.dict(A._MODULES, {'sw': sw})
        patcher.start()
        self.addCleanup(patcher.stop)

    def facts(self, **over):
        validated = {**self.validated, **over}
        with patch.object(A, 'run_agent', side_effect=[self.inspected, validated]):
            return A.candidate_facts(self.args, self.ctx)

    def test_reconstruction_facts_authorize_only_when_every_binding_holds(self):
        facts = self.facts()
        self.assertEqual((facts['candidate_sha256'], facts['added_rules']), ('a' * 64, 1))
        for key, value in {'restricting_only': False, 'status': 'exported_inert', 'candidate_sha256': 'f' * 64,
                           'base_policy_sha256': 'f' * 64, 'added_rules': 0, 'policy_sha256': 'f' * 64,
                           'constraints_sha256': 'z'}.items():
            with self.subTest(key), self.assertRaises(ValueError):
                self.facts(**{key: value})

    def test_only_action_class_denials_are_activated(self):
        for change in ({'deny_tools': ['write']}, {'allowed_destinations': ['example.test']}, {'deny_actions': []}):
            self.constraints = {**self.constraints, **change}
            with self.subTest(change), self.assertRaisesRegex(ValueError, 'candidate_scope_unsupported'):
                self.facts()
            self.constraints = {'format': 'sw-operator-policy-constraints/1', 'deny_actions': ['read_only'], 'deny_tools': [],
                                'allowed_destinations': None}

    def test_a_matching_hash_alone_never_authorizes(self):
        self.args.expect_candidate = 'not-a-digest'
        with self.assertRaisesRegex(ValueError, 'candidate_digest_required'):
            self.facts()

    def test_base_policy_must_be_the_currently_selected_policy(self):
        self.inspected['pins']['policy_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'base_policy_mismatch'):
            self.facts()

    def test_candidate_identical_to_the_live_policy_or_relative_paths_refuse(self):
        self.ctx['policy_raw'] = b'candidate'
        with self.assertRaisesRegex(ValueError, 'candidate_policy_mismatch'):
            self.facts()
        self.ctx['policy_raw'] = b'base'
        self.args.candidate = Path('relative')
        with self.assertRaisesRegex(ValueError, 'absolute_candidate_inputs_required'):
            self.facts()

    def test_validator_refusal_or_output_is_never_trusted(self):
        with patch.object(A.subprocess, 'run', return_value=types.SimpleNamespace(returncode=2, stdout=b'{}')), \
                self.assertRaisesRegex(ValueError, 'candidate_validation_refused'):
            A.run_agent('/owned/agentfw', ['inspect'])
        out = json.dumps({'active': True, 'executed': False}).encode()
        with patch.object(A.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout=out)), \
                self.assertRaisesRegex(ValueError, 'candidate_validation_refused'):
            A.run_agent('/owned/agentfw', ['inspect'])

    def test_validator_runs_without_ambient_environment_or_provider_access(self):
        out = json.dumps({'active': False, 'executed': False}).encode()
        with patch.object(A.subprocess, 'run', return_value=types.SimpleNamespace(returncode=0, stdout=out)) as call:
            A.run_agent('/owned/agentfw', ['inspect'])
        self.assertEqual(call.call_args.kwargs['env'], {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})


class Support(unittest.TestCase):
    def test_managed_or_coordinated_installations_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            home, prefix = Path(temporary, 'home'), Path(temporary, 'prefix')
            home.mkdir()
            prefix.mkdir()
            A.require_supported_home(home, prefix)
            for name in ('console-enrollment.json', 'managed-policy.json', 'Enroll'):
                (home / name).write_text('x')
                with self.subTest(name), self.assertRaisesRegex(ValueError, 'managed_home_unsupported'):
                    A.require_supported_home(home, prefix)
                (home / name).unlink()
            for name in ('current.json', 'journal.json'):
                (prefix / name).write_text('x')
                with self.subTest(name), self.assertRaisesRegex(ValueError, 'coordinated_prefix_unsupported'):
                    A.require_supported_home(home, prefix)
                (prefix / name).unlink()

    def test_stage_words_reuse_the_selected_inputs_and_only_change_the_policy(self):
        front = types.SimpleNamespace(SCRIPTS=ROOT / 'scripts', PREP=types.SimpleNamespace(
            PILOT=types.SimpleNamespace(ROLES=('agentfw', 'node', 'npm', 'policy', 'git_classifier')),
            GIT_PROFILES=types.SimpleNamespace(from_selection=lambda value: 'git-readonly-v1')))
        sel = selection()
        sel['files'] = {k: v for k, v in sel['files'].items() if k in ('agentfw', 'node', 'npm', 'policy', 'git_classifier')}
        ctx = {'state': {'commit': '1' * 40, 'inputs': {}}, 'selection': sel, 'preparation': Path('/owned/preparation')}
        words = A.stage_words(ctx, front, Path('/owned/preparation/operator-policies/x/policy.yaml'))
        self.assertIn('--stage-only', words)
        self.assertEqual(words[words.index('--policy') + 1], '/owned/preparation/operator-policies/x/policy.yaml')
        self.assertEqual(words[words.index('--node') + 1], '/owned/gen/node/bin/node')
        self.assertNotIn('--allow-download', words)
        self.assertEqual(words.count('--policy'), 1)
        ctx['state'].update(allow_download=True, inputs={'node_archive': '/owned/node.tar.xz', 'npm_cache': '/owned/cache'})
        words = A.stage_words(ctx, front, Path('/p'))
        self.assertIn('--allow-download', words)
        self.assertNotIn('--node', words)
        self.assertEqual(words[words.index('--node-archive') + 1], '/owned/node.tar.xz')

    def test_staging_refusals_are_not_success(self):
        front = types.SimpleNamespace(child=lambda words, **kw: (0, {'status': 'prepared-not-active', 'generation': G_NEW}),
                                      SCRIPTS=ROOT / 'scripts', ROOT=ROOT)
        with patch.object(A, 'stage_words', return_value=[]), self.assertRaisesRegex(ValueError, 'staging_refused'):
            A.stage_generation({}, front, Path('/p'))
        front.child = lambda words, **kw: (2, {'status': 'staged-not-selected', 'generation': G_NEW, 'selection_sha256': '8' * 64})
        with patch.object(A, 'stage_words', return_value=[]), self.assertRaisesRegex(ValueError, 'staging_refused'):
            A.stage_generation({}, front, Path('/p'))

    def test_preparation_stage_only_requires_explicit_prepare_rebuild(self):
        prep = load('activation_prepare_cli', 'prepare-installed-pilot.py')
        for argv in (['--stage-only'], ['--prepare', '--stage-only']):
            with self.subTest(argv), patch.object(prep.sys, 'argv', ['prepare', *argv]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                prep.main()


@POSIX
class Operation(Fixture):
    """The confirmed command: gate, stale confirmation, blockers and cancellation."""

    def setUp(self):
        super().setUp()
        self.view = {'mode': 'entered', 'installation': 'matches', 'active': 0, 'uncertain': False, 'revision': 3,
                     'marker_sha256': 'a' * 64, 'inventory_sha256': 'b' * 64}
        self.facts = {'candidate_sha256': 'e' * 64, 'policy_sha256': CANDIDATE, 'base_policy_sha256': BASE,
                      'constraints_sha256': 'b' * 64, 'added_rules': 1, 'pins_sha256': 'c' * 64,
                      'policy_raw': b'deny', 'manifest_raw': b'{}'}
        self.args = types.SimpleNamespace(action='preview', prefix=self.prefix, state_root=self.root, confirm=None,
                                          candidate=Path('/x'), expect_candidate='e' * 64, profile=Path('/p'),
                                          constraints=Path('/c'), examples=Path('/e'), generation=None)
        bound = types.SimpleNamespace()
        self.ctx_value = {**self.ctx(), 'bound': {'b': 1}}
        self.stack = contextlib.ExitStack()
        self.patches = [patch.object(A, 'context', return_value=self.ctx_value),
                        patch.object(A, 'observe', side_effect=lambda ctx, exclusive: (contextlib.ExitStack(), None, dict(self.view))),
                        patch.object(A, 'candidate_facts', return_value=self.facts),
                        patch.object(modules_m := A.modules()['pml'].M, 'digest', side_effect=lambda v: A.digest(v))]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        del bound, modules_m

    def run_op(self, action, **over):
        self.args.action = action
        for key, value in over.items():
            setattr(self.args, key, value)
        return A.operation(self.args, self.front)

    def test_preview_is_inert_and_confirmation_binds_every_input(self):
        with patch.object(A, 'stage_generation') as stage, patch.object(A, 'publish') as publish:
            first = self.run_op('preview')
            stage.assert_not_called()
            publish.assert_not_called()
        self.assertEqual((first['status'], first['mutates'], first['blockers']), ('preview', False, []))
        self.assertFalse(first['effects']['overwrites_live_policy'] or first['effects']['starts_process'])
        for change in ({'mode': 'open'}, {'active': 1}, {'uncertain': True}, {'revision': 4}):
            self.view.update(change)
            self.assertNotEqual(self.run_op('preview')['confirmation_sha256'], first['confirmation_sha256'])
            self.view.update({'mode': 'entered', 'active': 0, 'uncertain': False, 'revision': 3})
        self.facts['policy_sha256'] = '0' * 64
        self.assertNotEqual(self.run_op('preview')['confirmation_sha256'], first['confirmation_sha256'])

    def test_stale_or_missing_confirmation_never_stages(self):
        with patch.object(A, 'stage_generation') as stage:
            with self.assertRaisesRegex(ValueError, 'confirmation_stale'):
                self.run_op('confirm', confirm='0' * 64)
            stage.assert_not_called()

    def test_blocked_installation_refuses_before_any_staging(self):
        digest = self.run_op('preview')['confirmation_sha256']
        for change, code in (({'mode': 'open'}, 'maintenance_entry_required'), ({'active': 1}, 'runs_active'),
                             ({'uncertain': True}, 'runs_uncertain')):
            self.view.update(change)
            blocked = self.run_op('preview')
            self.assertIn(code, blocked['blockers'])
            with patch.object(A, 'stage_generation') as stage, self.assertRaisesRegex(ValueError, code):
                self.run_op('confirm', confirm=blocked['confirmation_sha256'])
            stage.assert_not_called()
            self.view.update({'mode': 'entered', 'active': 0, 'uncertain': False})
        self.assertEqual(self.run_op('preview')['confirmation_sha256'], digest)

    def test_confirmed_activation_publishes_a_new_generation_and_copies_no_authority(self):
        plan = self.run_op('preview')
        selected = selection(policy_path=str(self.preparation / A.POLICIES / ('e' * 64) / 'policy.yaml'), policy_sha=CANDIDATE)
        staged = {'status': 'staged-not-selected', 'generation': G_NEW, 'selection_sha256': A.sha(self.NEW_SELECTION),
                  'selection': str(self.target()['selection_path'])}
        with patch.object(A, 'stage_generation', return_value=staged) as stage, \
                patch.object(A, 'verified_generation', return_value=(Path(staged['selection']), staged['selection_sha256'], selected)), \
                patch.object(SW, 'require_inactive'):
            result = self.run_op('confirm', confirm=plan['confirmation_sha256'])
            stage.assert_called_once()
        self.assertEqual((result['status'], result['generation'], result['previous_generation']), ('activated', G_NEW, G_OLD))
        self.assertEqual((result['active_protection'], result['session_authority_copied']), ('not-observed', False))
        self.assertEqual(json.loads(SW.marker(self.preparation)[1])['generation'], G_NEW)
        self.assertEqual((self.preparation / A.POLICIES / ('e' * 64) / 'policy.yaml').read_bytes(), b'deny')

    def test_staged_generation_that_changes_anything_else_is_never_published(self):
        plan = self.run_op('preview')
        wrong = selection(policy_path='/elsewhere', policy_sha=CANDIDATE)
        staged = {'status': 'staged-not-selected', 'generation': G_NEW, 'selection_sha256': A.sha(self.NEW_SELECTION),
                  'selection': str(self.target()['selection_path'])}
        with patch.object(A, 'stage_generation', return_value=staged), \
                patch.object(A, 'verified_generation', return_value=(Path(staged['selection']), staged['selection_sha256'], wrong)), \
                patch.object(SW, 'require_inactive'), self.assertRaisesRegex(ValueError, 'generation_policy_not_selected'):
            self.run_op('confirm', confirm=plan['confirmation_sha256'])
        self.assertEqual(json.loads(SW.marker(self.preparation)[1])['generation'], G_OLD)
        self.assertFalse((self.preparation / A.JOURNAL).exists())

    def test_cancellation_while_staging_leaves_the_old_generation_selected(self):
        plan = self.run_op('preview')
        with patch.object(A, 'stage_generation', side_effect=KeyboardInterrupt), patch.object(SW, 'require_inactive'), \
                self.assertRaises(KeyboardInterrupt):
            self.run_op('confirm', confirm=plan['confirmation_sha256'])
        self.assertEqual(json.loads(SW.marker(self.preparation)[1])['generation'], G_OLD)
        self.assertEqual(self.state_path.read_bytes(), self.ctx_value['state_raw'])
        self.assertFalse((self.preparation / A.JOURNAL).exists())

    def test_staging_refusal_is_not_success_and_selects_nothing(self):
        plan = self.run_op('preview')
        with patch.object(A, 'stage_generation', side_effect=ValueError('policy_activation_staging_refused')), \
                patch.object(SW, 'require_inactive'), self.assertRaisesRegex(ValueError, 'staging_refused'):
            self.run_op('confirm', confirm=plan['confirmation_sha256'])
        self.assertEqual(json.loads(SW.marker(self.preparation)[1])['generation'], G_OLD)

    def test_inspect_reports_state_without_claiming_protection(self):
        report = self.run_op('inspect')
        self.assertEqual((report['status'], report['active_protection'], report['selected_policy_origin']),
                         ('inspected', 'not-observed', 'baseline'))
        self.assertEqual(report['history'], [])

    def test_main_reports_only_finite_reasons_and_requires_linux(self):
        front = types.SimpleNamespace(PROG='owned', platform_reason=lambda: None)
        out = io.StringIO()
        with patch.object(A.sys, 'platform', 'darwin'), contextlib.redirect_stdout(out):
            code = A.main(['inspect', '--prefix', '/a', '--state-root', '/b'], front)
        value = json.loads(out.getvalue())
        self.assertEqual((code, value['reason'], value['executed']), (2, 'policy_activation_native_linux_required', False))
        out = io.StringIO()
        with patch.object(A.sys, 'platform', 'linux'), patch.object(A, 'operation', side_effect=ValueError('/secret/path leaked')), \
                contextlib.redirect_stdout(out):
            self.assertEqual(A.main(['inspect', '--prefix', '/a', '--state-root', '/b'], front), 2)
        self.assertEqual(json.loads(out.getvalue())['reason'], 'policy_activation_input_unavailable')
        self.assertNotIn('secret', out.getvalue())
        out = io.StringIO()
        with patch.object(A.sys, 'platform', 'linux'), patch.object(A, 'operation', side_effect=ValueError('active_or_uncertain_pilot_run')), \
                contextlib.redirect_stdout(out):
            A.main(['inspect', '--prefix', '/a', '--state-root', '/b'], front)
        self.assertEqual(json.loads(out.getvalue())['reason'], 'policy_activation_active_or_uncertain_pilot_run')


if __name__ == '__main__':
    unittest.main()
