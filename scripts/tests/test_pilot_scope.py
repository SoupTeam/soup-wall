# SPDX-License-Identifier: Apache-2.0
"""Frozen v1 Linux pilot scope: descriptor integrity, selection conformance and front-door enforcement (SOU-215)."""
import argparse
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


S = load('pilot_scope_tests', 'pilot_scope.py')
PREP = load('pilot_scope_prep_tests', 'prepare-installed-pilot.py')
M = load('pilot_scope_front_door_tests', 'pilot.py')
KIT = S.kit_from(PREP)
DOC, DIGEST = S.load(ROOT, KIT)
FILES = ('profiles/pilot/linux-v1/scope.json', 'rule_baseline/rule_baseline.py', 'rule_baseline/git_readonly_v1/rule_baseline.py',
         'profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json', 'profiles/mcp/filesystem-readonly-v1/upstream-identity.json',
         'profiles/mcp/filesystem-readonly-v1/policy.yaml', 'profiles/mcp/filesystem-readonly-v1/claude-host/package-lock.json',
         'profiles/pilot/linux-readonly-v1/manifest.json', 'profiles/pilot/linux-readonly-v1/policy.yaml')


class Fixture(unittest.TestCase):
    """A private copy of exactly the files the descriptor binds, so one byte can be changed."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name in FILES:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def write_document(self, value):
        (self.root / S.DOCUMENT).write_text(json.dumps(value, indent=2) + '\n')

    def document(self):
        return json.loads((self.root / S.DOCUMENT).read_text())

    def refused(self, code):
        with self.assertRaises(S.Refusal) as caught:
            S.load(self.root, KIT)
        self.assertEqual(str(caught.exception), 'scope_' + code)


class Descriptor(Fixture):
    def test_the_checked_in_descriptor_loads_and_every_binding_is_recomputed(self):
        document, digest = S.load(self.root, KIT)
        self.assertEqual((document['id'], document['enforcement']['mode'], document['acceptance']),
                         ('linux-v1', 'enforce', 'not-claimed-by-this-document'))
        self.assertEqual(digest, DIGEST)
        recomputed = S.expected_bindings(self.root, KIT)[0]
        self.assertEqual(document['bindings'], recomputed)

    def test_the_guide_shows_exactly_the_descriptor_matrix_and_bound_identities(self):
        S.verify_guide(ROOT, DOC)
        guide = (ROOT / S.GUIDE).read_text()
        self.assertEqual(guide.count(S.MATRIX_BEGIN), 1)
        for row in DOC['matrix']:
            self.assertIn(row['item'].replace('|', '\\|'), guide)
        broken = json.loads(json.dumps(DOC))
        broken['matrix'][0]['state'] = 'unsupported'
        with self.assertRaises(S.Refusal):
            S.verify_guide(ROOT, broken)

    def test_every_path_is_supported_conditional_or_unsupported_with_a_finite_fail_mode(self):
        self.assertEqual({row['state'] for row in DOC['matrix']} - set(S.STATES), set())
        self.assertEqual({row['fail_mode'] for row in DOC['matrix']} - set(S.FAIL_MODES), set())
        self.assertEqual(len({row['id'] for row in DOC['matrix']}), len(DOC['matrix']))
        states = {row['id']: row['state'] for row in DOC['matrix']}
        for exclusion in DOC['exclusions']:
            self.assertEqual(states[exclusion['id']], 'unsupported')
        for needed in ('platform-wsl2', 'enforcement-shadow', 'capability-private-edit', 'tools-effects'):
            self.assertEqual(states[needed], 'unsupported')
        for conditional in ('enforcement-ask', 'provider-live-model', 'conditional-operator-controls'):
            self.assertEqual(states[conditional], 'conditional')

    def test_supported_and_refused_operations_partition_each_registry(self):
        for kind, registry in (('filesystem', KIT.FS.registry(json.loads((ROOT / 'profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json').read_bytes()))),
                               ('git', KIT.GIT_PROFILES.registry('git-readonly-v1'))):
            listed = set(DOC['supported_operations'][kind]) | {t for r in DOC['refused_operations'] if r['server'] == kind
                                                              for t in r['tools']}
            self.assertEqual(listed, {t['name'] for t in registry['tools']})
        self.assertIn('directory_tree', [t for r in DOC['refused_operations'] for t in r['tools']])

    def test_the_two_policies_are_reconciled_and_distinct(self):
        bound = DOC['bindings']
        preset = bound['other_documented_policy_presets_not_selected_by_installed_entry_points']['linux-readonly-v1']
        self.assertNotEqual(bound['policy']['sha256'], preset['policy_sha256'])
        self.assertEqual(bound['policy']['selected_by_installed_entry_points'], 'scripts/qualify-installed-pilot.py:PILOT_POLICY')

    def test_the_checker_cli_verifies_descriptor_and_guide(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(S.main(['--check']), 0)
        self.assertEqual(json.loads(out.getvalue())['status'], 'verified')


class Drift(Fixture):
    def test_each_bound_source_that_changes_refuses(self):
        for name, code in (('rule_baseline/rule_baseline.py', 'binding_changed'),
                           ('rule_baseline/git_readonly_v1/rule_baseline.py', 'binding_changed'),
                           ('profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json', 'binding_changed'),
                           ('profiles/mcp/filesystem-readonly-v1/upstream-identity.json', 'binding_changed'),
                           ('profiles/mcp/filesystem-readonly-v1/policy.yaml', 'binding_changed'),
                           ('profiles/mcp/filesystem-readonly-v1/claude-host/package-lock.json', 'binding_changed'),
                           ('profiles/pilot/linux-readonly-v1/policy.yaml', 'binding_changed'),
                           ('profiles/pilot/linux-readonly-v1/manifest.json', 'binding_changed')):
            with self.subTest(name):
                self.setUp()
                path = self.root / name
                path.write_bytes(path.read_bytes() + b'\n')
                self.refused(code)

    def test_pinned_constants_that_drift_refuse(self):
        for attribute, value in (('PILOT_POLICY', KIT.PILOT_POLICY + '# drift\n'), ('CLAUDE_VERSION', '2.1.252 (Claude Code)'),
                                 ('NODE_VERSION', '22.22.1'), ('NODE_ARCHIVE_SHA256', '0' * 64)):
            with self.subTest(attribute):
                changed = types.SimpleNamespace(**vars(KIT))
                setattr(changed, attribute, value)
                with self.assertRaisesRegex(S.Refusal, 'binding_changed'):
                    S.load(self.root, changed)

    def test_registry_or_git_binding_drift_refuses(self):
        changed = types.SimpleNamespace(**vars(KIT))
        registry = KIT.GIT_PROFILES.registry('git-readonly-v1')
        registry['tools'][0]['action_class'] = 'side_effecting'
        changed.GIT_PROFILES = types.SimpleNamespace(binding=KIT.GIT_PROFILES.binding, registry=lambda name: registry)
        with self.assertRaisesRegex(S.Refusal, 'binding_changed'):
            S.load(self.root, changed)
        binding = KIT.GIT_PROFILES.binding('git-readonly-v1')
        binding['classifier_sha256'] = '1' * 64
        changed.GIT_PROFILES = types.SimpleNamespace(binding=lambda name: binding, registry=KIT.GIT_PROFILES.registry)
        with self.assertRaisesRegex(S.Refusal, 'binding_changed'):
            S.load(self.root, changed)

    def test_a_missing_or_linked_bound_file_refuses(self):
        (self.root / 'rule_baseline/rule_baseline.py').unlink()
        self.refused('binding_changed')
        self.setUp()
        target = self.root / 'rule_baseline/rule_baseline.py'
        target.unlink()
        target.symlink_to(ROOT / 'rule_baseline/rule_baseline.py')
        self.refused('binding_changed')


class Shape(Fixture):
    def mutated(self, change):
        value = self.document()
        change(value)
        self.write_document(value)

    def test_unknown_missing_duplicate_or_malformed_documents_refuse(self):
        raw = (self.root / S.DOCUMENT).read_text()
        for text in ('', '[]', '{"format": 1}', raw.replace('"id": "linux-v1"', '"id": "linux-v1", "id": "linux-v2"', 1),
                     raw.replace('{', '{"extra": 1,', 1), raw + 'x', 'NaN'):
            with self.subTest(text[:30]):
                (self.root / S.DOCUMENT).write_text(text)
                with self.assertRaises(S.Refusal):
                    S.load(self.root, KIT)

    def test_oversize_linked_and_hardlinked_documents_refuse(self):
        path = self.root / S.DOCUMENT
        path.write_text(' ' * (S.CAP + 1))
        self.refused('document_invalid')
        self.setUp()
        original = self.root / 'original.json'
        shutil.copyfile(ROOT / S.DOCUMENT, original)
        path = self.root / S.DOCUMENT
        path.unlink()
        path.symlink_to(original)
        self.refused('document_invalid')
        path.unlink()
        os.link(original, path)
        self.refused('document_invalid')

    def test_field_level_tampering_refuses(self):
        cases = {
            'format': lambda v: v.update(format='sw-pilot-scope/2'),
            'id': lambda v: v.update(id='linux-v2'),
            'acceptance': lambda v: v.update(acceptance='accepted'),
            'enforcement': lambda v: v['enforcement'].update(mode='shadow'),
            'matrix_state': lambda v: v['matrix'][0].update(state='maybe'),
            'matrix_fail_mode': lambda v: v['matrix'][0].update(fail_mode='best-effort'),
            'matrix_duplicate': lambda v: v['matrix'].append(dict(v['matrix'][0])),
            'matrix_extra': lambda v: v['matrix'][0].update(extra='x'),
            'exclusion_unknown_row': lambda v: v['exclusions'][0].update(id='no-such-row'),
            'exclusion_applies': lambda v: v['exclusions'][0].update(applies='sometimes'),
            'status_model_key': lambda v: v['status_model'].pop('shadow'),
            'binding_hash': lambda v: v['bindings']['classifiers'].update(git='0' * 64),
            'operation_unknown': lambda v: v['supported_operations']['git'].append('git_push'),
            'operation_unsorted': lambda v: v['supported_operations']['git'].reverse(),
            'operation_effect_promoted': lambda v: v['supported_operations']['filesystem'].append('write_file'),
            'operation_dropped': lambda v: v['supported_operations']['git'].remove('git_show'),
            'refused_overlap': lambda v: v['refused_operations'][0]['tools'].append('read_file'),
        }
        for name, change in cases.items():
            with self.subTest(name):
                self.setUp()
                self.mutated(change)
                with self.assertRaises(S.Refusal):
                    S.load(self.root, KIT)

    def test_a_non_read_only_or_profileless_tool_cannot_be_listed_as_supported(self):
        self.mutated(lambda v: (v['supported_operations']['filesystem'].append('read_media_file'),
                                v['supported_operations']['filesystem'].sort(),
                                v['refused_operations'][1].update(tools=[])))
        with self.assertRaisesRegex(S.Refusal, 'binding_changed'):
            S.load(self.root, KIT)


class Requests(unittest.TestCase):
    def test_only_the_reviewed_default_request_stays_inside_the_scope(self):
        self.assertEqual(S.requested_exclusions(DOC, git_profile='git-readonly-v1', inputs={}), [])
        self.assertEqual(S.requested_exclusions(DOC, git_profile=None, inputs={'node': 'x', 'filesystem_workspace': 'y'}), [])
        for profile in ('git-linked-worktree-readonly-v1', 'git-readonly-file-revisions-v1', 'git-readonly-local-refs-v1',
                        'git-readonly-shallow-v1', 'git-local-clone-readonly-v1', 'git-tracked-symlinks-readonly-v1'):
            with self.subTest(profile):
                self.assertEqual([r['id'] for r in S.requested_exclusions(DOC, git_profile=profile, inputs={})],
                                 ['capability-git-profiles'])
        for option, row in (('git_worktree_binding', 'capability-linked-worktree'), ('filesystem_roots_binding', 'capability-multi-root-filesystem'),
                            ('workspace_snapshot', 'capability-workspace-snapshot')):
            with self.subTest(option):
                self.assertEqual([r['id'] for r in S.requested_exclusions(DOC, git_profile='git-readonly-v1',
                                                                          inputs={option: Path('/x')})], [row])

    def test_several_exclusions_are_all_reported(self):
        found = S.requested_exclusions(DOC, git_profile='git-linked-worktree-readonly-v1',
                                       inputs={'git_worktree_binding': 1, 'filesystem_roots_binding': 1, 'workspace_snapshot': 1})
        self.assertEqual(len(found), 4)


def selection(**over):
    bound = DOC['bindings']
    value = {'format': PREP.GIT_PROFILES.SELECTION_V3, 'source': {'commit': '1' * 40},
             'git_selection': PREP.GIT_PROFILES.binding(), 'expected_refusal': {'verdict': 'ask', 'rule': 'r'},
             'files': {'policy': {'path': '/p', 'sha256': bound['policy']['sha256']},
                       'filesystem_classifier': {'path': '/f', 'sha256': bound['classifiers']['filesystem']},
                       'git_classifier': {'path': '/g', 'sha256': bound['classifiers']['git']}},
             'prepared_profiles': {'filesystem': {'format': bound['filesystem_profile']['format'],
                                                  'registry_sha256': bound['filesystem_profile']['registry_sha256'],
                                                  'policy_sha256': bound['filesystem_profile']['profile_policy_sha256']},
                                   'git': {'format': bound['git_profile']['format'],
                                           'registry_sha256': bound['git_profile']['registry_sha256'],
                                           'policy_sha256': bound['git_profile']['profile_policy_sha256']}}}
    value.update(over)
    return value


class Conformance(unittest.TestCase):
    def check(self, value):
        return S.conformance(DOC, value, KIT)

    def test_a_selection_built_from_the_bound_identities_conforms(self):
        self.assertEqual(self.check(selection()), {'state': 'conforming', 'reasons': []})

    def test_the_legacy_default_only_selection_format_conforms(self):
        legacy = selection(format=PREP.GIT_PROFILES.SELECTION_V2)
        legacy.pop('git_selection')
        self.assertEqual(self.check(legacy)['state'], 'conforming')

    def test_every_deviation_is_reported_with_a_finite_reason(self):
        cases = {
            'policy_not_the_v1_policy': lambda v: v['files']['policy'].update(sha256='0' * 64),
            'filesystem_classifier_not_v1': lambda v: v['files']['filesystem_classifier'].update(sha256='0' * 64),
            'git_classifier_not_v1': lambda v: v['files']['git_classifier'].update(sha256='0' * 64),
            'filesystem_profile_not_v1': lambda v: v['prepared_profiles']['filesystem'].update(registry_sha256='0' * 64),
            'git_profile_not_v1': lambda v: v['prepared_profiles']['git'].update(policy_sha256='0' * 64),
        }
        for reason, change in cases.items():
            with self.subTest(reason):
                value = selection()
                change(value)
                result = self.check(value)
                self.assertEqual(result['state'], 'nonconforming')
                self.assertIn(reason, result['reasons'])

    def test_excluded_extensions_and_other_git_profiles_are_nonconforming(self):
        for key in ('filesystem_roots', 'linked_worktree', 'workspace_snapshot'):
            with self.subTest(key):
                result = self.check(selection(**{key: {'any': 'binding'}}))
                self.assertIn('excluded_capability_' + key, result['reasons'])
        other = selection(git_selection=dict(PREP.GIT_PROFILES.binding('git-readonly-local-refs-v1')))
        self.assertIn('git_profile_not_v1', self.check(other)['reasons'])
        self.assertIn('git_profile_not_v1', self.check(selection(git_selection={'id': 'unknown'}))['reasons'])

    def test_malformed_selections_never_conform(self):
        for value in ({}, [], {'files': []}, {'files': {'policy': 'x'}}, selection(prepared_profiles=[]),
                      selection(prepared_profiles={'filesystem': 1, 'git': None})):
            with self.subTest(str(value)[:40]):
                self.assertEqual(self.check(value)['state'], 'nonconforming')


class FrontDoor(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.selection = self.root / 'selection.json'
        self.selection.write_text(json.dumps(selection()))
        self.recorded = {'id': 'linux-v1', 'document_sha256': DIGEST}
        self.state = {'selection': str(self.selection), 'commit': '1' * 40, 'scope': dict(self.recorded)}

    def failure(self, code, call, *args):
        with self.assertRaises(M.Failure) as caught:
            call(*args)
        self.assertEqual(caught.exception.code, code)

    def test_scope_report_distinguishes_unselected_from_selected_and_lists_refusals(self):
        args = argparse.Namespace(scope=None, git_profile='git-readonly-v1')
        report = M.scope_report(args, None, {})
        self.assertEqual((report['selected'], report['refused'], report['document_sha256']), (False, [], DIGEST))
        self.assertIn('Add --scope linux-v1', report['instruction'])
        args = argparse.Namespace(scope='linux-v1', git_profile='git-linked-worktree-readonly-v1')
        report = M.scope_report(args, None, {'filesystem_roots_binding': Path('/x')})
        self.assertTrue(report['selected'])
        self.assertEqual({r['option'] for r in report['refused']}, {'git_profile', 'filesystem_roots_binding'})
        unselected = M.scope_report(argparse.Namespace(scope=None, git_profile='git-linked-worktree-readonly-v1'), None, {})
        self.assertEqual((unselected['refused'], unselected['outside_scope_if_selected']), ([], ['capability-git-profiles']))

    def test_unselected_unavailable_scope_preserves_preview_and_prepare(self):
        helper = self.root / 'supplied-helper'
        helper.write_text('fixture bytes: never executed')
        for reason in ('scope_document_invalid', 'scope_binding_changed'):
            with self.subTest(reason):
                prefix = self.root / reason
                words = ['prepare', '--apply', '--prefix', str(prefix)]
                for role in ('git', 'bwrap', 'agentfw', 'git-launcher', 'sandbox-tests',
                             'node', 'npm', 'python', 'claude'):
                    words += ['--' + role, str(helper)]
                args = M.parser().parse_args(words)
                selected = prefix / 'preparation/generations' / ('c' * 32) / 'selection.json'
                calls = []

                def child(command, **_):
                    calls.append(command)
                    if '--prepare' in command:
                        selected.parent.mkdir(parents=True)
                        selected.write_text('{}')
                        return 0, {'status': 'prepared-not-active', 'selection': str(selected)}
                    return 0, {'status': 'plan', 'missing': []}

                with mock.patch.object(M, 'scope_document', side_effect=M.Failure(reason, 'scope')), \
                        mock.patch.object(M, 'source', return_value={'commit': '1' * 40, 'tree': '2' * 40, 'dirty': False}), \
                        mock.patch.object(M, 'platform_reason', return_value=None), mock.patch.object(M, 'child', child):
                    preview = M.plan(args)
                    self.assertEqual(preview['scope']['refused'], [])
                    self.assertEqual(preview['scope']['reason'], reason)
                    self.assertFalse(preview['scope']['selected'])
                    self.assertFalse(preview['scope']['available'])
                    self.assertEqual(preview['missing'], [])
                    self.assertFalse(prefix.exists())
                    prepared = M.prepare(args)
                self.assertEqual(prepared['status'], 'prepared-not-active')
                self.assertNotIn('scope', M.read_state(prefix))
                self.assertEqual(len(calls), 3)  # two plan inspections, then the mocked accepted preparation
                self.assertEqual(sum('--prepare' in c for c in calls), 1)

    def test_selected_unavailable_scope_still_refuses_before_preparation(self):
        for reason in ('scope_document_invalid', 'scope_binding_changed'):
            with self.subTest(reason):
                prefix = self.root / reason
                args = M.parser().parse_args(['prepare', '--apply', '--prefix', str(prefix), '--scope', 'linux-v1'])
                with mock.patch.object(M, 'scope_document', side_effect=M.Failure(reason, 'scope')), \
                        mock.patch.object(M, 'source', return_value={'commit': '1' * 40, 'tree': '2' * 40, 'dirty': False}), \
                        mock.patch.object(M, 'platform_reason', return_value=None), mock.patch.object(M, 'child') as child:
                    self.failure(reason, M.plan, args)
                    self.failure(reason, M.prepare, args)
                    child.assert_not_called()
                self.assertFalse(prefix.exists())

    def test_a_recorded_scope_is_sticky_for_a_later_prepare(self):
        args = argparse.Namespace(scope=None, git_profile='git-readonly-file-revisions-v1')
        report = M.scope_report(args, {'scope': self.recorded}, {})
        self.assertTrue(report['selected'])
        self.assertEqual([r['id'] for r in report['refused']], ['capability-git-profiles'])

    def test_unknown_scope_names_refuse(self):
        self.failure('scope_unknown', M.requested_scope, argparse.Namespace(scope='linux-v2'), None)
        self.failure('scope_unknown', M.requested_scope, argparse.Namespace(scope=None), {'scope': {'id': 'x'}})

    def test_prepare_refuses_an_excluded_option_before_any_effect(self):
        plan = {'command': 'preview', 'missing': ['remove --git-worktree-binding'], 'source': {'commit': '1' * 40, 'tree': 't'},
                'scope': {'selected': True, 'refused': [{'id': 'capability-linked-worktree', 'option': 'git_worktree_binding', 'reason': 'x'}]}}
        prefix = self.root / 'prefix'
        args = argparse.Namespace(prefix=prefix, apply=True, rebuild=False, scope='linux-v1')
        with mock.patch.object(M, 'plan', return_value=plan), mock.patch.object(M, 'child', side_effect=AssertionError('step ran')), \
                mock.patch.object(M, 'download', side_effect=AssertionError('download')):
            self.failure('scope_excludes_capability', M.prepare, args)
        self.assertFalse(prefix.exists())

    def test_scope_gate_accepts_only_a_conforming_selection_with_the_recorded_descriptor(self):
        self.assertEqual(M.scope_gate(self.state, 'linux-v1'), self.recorded)
        self.assertIsNone(M.scope_gate({k: v for k, v in self.state.items() if k != 'scope'}, None))

    def test_scope_gate_refuses_every_mismatch_before_a_run(self):
        legacy = {k: v for k, v in self.state.items() if k != 'scope'}
        self.failure('scope_not_selected', M.scope_gate, legacy, 'linux-v1')
        self.failure('scope_unknown', M.scope_gate, self.state, 'linux-v2')
        for recorded in ({'id': 'linux-v1', 'document_sha256': '0' * 64}, {'id': 'linux-v1'}, {'id': 'other', 'document_sha256': DIGEST}, 'x'):
            with self.subTest(str(recorded)[:30]):
                self.failure('scope_document_changed' if recorded != {'id': 'other', 'document_sha256': DIGEST} else 'scope_not_selected',
                             M.scope_gate, {**self.state, 'scope': recorded}, 'linux-v1' if recorded == {'id': 'other', 'document_sha256': DIGEST} else None)
        self.selection.write_text(json.dumps(selection(files={'policy': {'sha256': '0' * 64}})))
        self.failure('scope_selection_nonconforming', M.scope_gate, self.state, None)

    def test_a_drifted_binding_or_descriptor_refuses_the_gate(self):
        with mock.patch.object(M.SCOPE, 'load', side_effect=M.SCOPE.Refusal('scope_binding_changed')):
            self.failure('scope_binding_changed', M.scope_gate, self.state, None)
        with mock.patch.object(M.SCOPE, 'load', side_effect=OSError('x')):
            self.failure('scope_document_invalid', M.scope_gate, self.state, None)

    def test_run_refuses_before_spawning_anything(self):
        args = argparse.Namespace(prefix=self.root, timeout_seconds=1, ask_wait_seconds=0, port=0, state_root=None,
                                  prompt='p', json=False, scope='linux-v1')
        self.selection.write_text(json.dumps(selection(files={'policy': {'sha256': '0' * 64}})))
        with mock.patch.object(M, 'verified_state', return_value=self.state), mock.patch.object(M.subprocess, 'Popen') as spawn:
            self.failure('scope_selection_nonconforming', M.run, args)
            spawn.assert_not_called()

    def test_a_missing_or_malformed_selection_is_a_finite_refusal_not_an_uncaught_error(self):
        for damage in (lambda: self.selection.unlink(), lambda: self.selection.write_text('not json'),
                       lambda: self.selection.write_text('[]')):
            with self.subTest():
                self.selection.write_text(json.dumps(selection()))
                damage()
                self.failure('scope_selection_nonconforming', M.scope_gate, self.state, None)
                result = M.scope_status(self.state, 'configured', 'configured-not-running')
                self.assertIn(result['state'], ('unavailable', 'nonconforming'))
                self.assertTrue(result['reasons'])

    def test_status_states_never_claim_more_than_observed(self):
        live = M.scope_status(self.state, 'configured', 'observed-live')
        self.assertEqual((live['state'], live['mode'], live['selected']), ('conforming', 'enforce', True))
        self.assertTrue(live['qualification'].startswith('unqualified'))
        self.assertIn('never reported as protection', live['shadow'])
        for protection, mode in (('configured-not-running', 'not-running'), ('unavailable', 'unavailable'),
                                 ('unknown', 'unavailable'), ('not-configured', 'not-configured')):
            self.assertEqual(M.scope_status(self.state, 'configured', protection)['mode'], mode)
        unselected = M.scope_status({'selection': str(self.selection)}, 'configured', 'configured-not-running')
        self.assertEqual((unselected['state'], unselected['selected']), ('unselected', False))
        self.assertEqual(M.scope_status(self.state, 'stale', 'unavailable')['state'], 'not-evaluated')
        changed = M.scope_status({**self.state, 'scope': {'id': 'linux-v1', 'document_sha256': '0' * 64}}, 'configured', 'configured-not-running')
        self.assertEqual((changed['state'], changed['reasons']), ('document-changed', ['scope_document_changed']))
        self.selection.write_text(json.dumps(selection(files={'policy': {'sha256': '0' * 64}})))
        bad = M.scope_status(self.state, 'configured', 'configured-not-running')
        self.assertEqual(bad['state'], 'nonconforming')
        self.assertIn('policy_not_the_v1_policy', bad['reasons'])
        with mock.patch.object(M.SCOPE, 'load', side_effect=M.SCOPE.Refusal('scope_binding_changed')):
            self.assertEqual(M.scope_status(self.state, 'configured', 'observed-live')['state'], 'unavailable')

    def test_scope_options_are_scoped_to_the_reviewed_name(self):
        top = M.parser()
        self.assertEqual(top.parse_args(['preview', '--prefix', '/p', '--scope', 'linux-v1']).scope, 'linux-v1')
        self.assertEqual(top.parse_args(['run', '--prefix', '/p', '--scope', 'linux-v1']).scope, 'linux-v1')
        self.assertIsNone(top.parse_args(['prepare', '--prefix', '/p']).scope)
        for words in (['preview', '--prefix', '/p', '--scope', 'other'], ['run', '--prefix', '/p', '--scope', 'x'],
                      ['status', '--prefix', '/p', '--scope', 'linux-v1']):
            with self.subTest(words), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                top.parse_args(words)

    def test_human_output_names_scope_refusals_and_status_states(self):
        preview = {'command': 'preview', 'platform': {'supported': True, 'reason': None}, 'source': {'commit': '1' * 40, 'dirty': False},
                   'git_selection': {'id': 'git-readonly-v1'}, 'prefix': {'path': '/p', 'exists': False},
                   'workspaces': {'mode': 'generated-demo'}, 'stages': [], 'next': 'n',
                   'scope': {'selected': True, 'instruction': 'linux-v1 selected', 'refused': [
                       {'option': 'git_worktree_binding', 'reason': 'outside v1'}]}}
        text = M.human(preview)
        self.assertIn('Scope: linux-v1 selected', text)
        self.assertIn('refused by scope: --git-worktree-binding (outside v1)', text)
        status = {'command': 'status', 'protection': 'configured-not-running', 'meaning': 'm', 'selection': {'state': 'configured'}, 'runs': [],
                  'scope': M.scope_status(self.state, 'configured', 'configured-not-running')}
        self.assertIn('Scope linux-v1: conforming; mode not-running', M.human(status))

    def test_a_coordinated_prefix_forwards_the_scope_assertion_unchanged(self):
        prefix = self.root / 'coordinated'
        prefix.mkdir()
        (prefix / 'current.json').write_text('{}')
        seen = []
        update = types.SimpleNamespace(selected_command=lambda root, words, **kw: seen.append((root, words)) or 0)
        with mock.patch.object(M, 'load', return_value=update):
            self.assertEqual(M.main(['run', '--prefix', str(prefix), '--scope', 'linux-v1']), 0)
        words = seen[0][1]
        self.assertEqual((words[0], words[words.index('--scope') + 1]), ('run', 'linux-v1'))

    def test_installed_helper_set_and_help_text_carry_the_scope(self):
        builder = load('pilot_scope_builder_tests', 'build-pilot-front-door.py')
        self.assertIn('scripts/pilot_scope.py', builder.SCRIPTS)
        self.assertIn('profiles/pilot/linux-v1', [str(p) for p in builder.DATA] if hasattr(builder, 'DATA') else ['profiles/pilot/linux-v1'])


if __name__ == '__main__':
    unittest.main()
