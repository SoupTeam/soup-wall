# SPDX-License-Identifier: Apache-2.0
import importlib.util
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('installed_edit', ROOT / 'scripts/qualify-installed-edit.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class InstalledEditEvidence(unittest.TestCase):
    def test_shared_cli_decodes_pretty_status_and_retains_run_line_framing(self):
        suite = object.__new__(probe.Suite)
        suite.binary, suite.work, suite.env, suite.report = Path('/agentfw'), Path('/work'), {}, {}
        status = {'schema': probe.DIAGNOSTIC_FORMAT,
                  'effects': 'indeterminate', 'host_delivery': 'unknown', 'model_consumption': 'unknown',
                  'audit': {'calls': []}, 'outputs': [], 'recorded_host_outcome': 'recorded_operator_stop'}
        for raw, expected in ((json.dumps(status, indent=2).encode() + b'\n', status),
                              (b'{"running":true}\n{"finished":true}\n', {'finished': True}),
                              (b'', None), (b'{broken\n', None)):
            with self.subTest(raw=raw), mock.patch.object(probe.subprocess, 'run',
                    return_value=subprocess.CompletedProcess([], 0, raw, b'')):
                code, value = suite.cli('status', '--run', '/owned', '--json')
                self.assertEqual((code, value), (0, expected))
                self.assertEqual(suite.last_cli['stdout_sha256'], probe.sha(raw))
                if value == status:
                    probe.require_indeterminate_status(value)
        with mock.patch.object(probe.subprocess, 'run',
                return_value=subprocess.CompletedProcess([], 0, b'x' * (128 * 1024 + 1), b'')):
            with self.assertRaisesRegex(ValueError, 'cli_output_cap'):
                suite.cli('status', '--run', '/owned', '--json')
        with self.assertRaisesRegex(ValueError, 'diagnosis_response_not_object'):
            probe.require_indeterminate_status(None)

    def seed(self):
        report = {'format': probe.FORMAT, 'status': 'passed', 'paid_inference': False,
                'claude_sha256': probe.CLAUDE,
                'expected': list(probe.CASES), 'cases': [{'id': name, 'status': 'passed', 'attempted': True} for name in probe.CASES]}
        identity = {'exists': True, 'device': 1, 'inode': 2, 'mode': 0o100600, 'links': 2, 'size': 3, 'sha256': probe.sha(b'old')}
        row = next(r for r in report['cases'] if r['id'] == 'hardlink-target')
        row.update(authority=False, new_runs=0, target_before=dict(identity), target_after=dict(identity),
                   outside_alias_before=dict(identity), outside_alias_after=dict(identity))
        return report

    def test_missing_or_failed_control_cannot_be_called_complete(self):
        self.assertTrue(probe.passed_report(self.seed()))
        for index in range(len(probe.CASES)):
            row = self.seed();row['cases'][index]['status'] = 'incomplete'
            self.assertFalse(probe.passed_report(row))
        for key in ('claude_sha256', 'paid_inference', 'format'):
            row = self.seed();row.pop(key)
            self.assertFalse(probe.passed_report(row))
        row = self.seed();row['cases'].pop()
        self.assertFalse(probe.passed_report(row))
        row = self.seed();row['cases'].reverse()
        self.assertFalse(probe.passed_report(row))

    def test_inspect_failure_keeps_a_safe_typed_reason_and_never_payload(self):
        import json
        secret = b'{"args":{"content":"owned-private-payload"}}'
        row = probe.cli_observation(1, secret, b'Error: edit_run_ended\n')
        self.assertEqual(row['exit_code'], 1)
        self.assertEqual(row['reason'], 'run_ended')
        self.assertFalse(row['raw_retained'])
        self.assertNotIn('owned-private-payload', json.dumps(row))
        self.assertEqual(probe.cli_observation(1, b'', b'Error: arbitrary failure\n')['reason'], 'cli_failed')
        report = self.seed();report['cases'][0]['attempted'] = False
        self.assertFalse(probe.passed_report(report))
        self.assertEqual(probe.failure_code(ValueError('diagnosis_changed_selected_state')),
                         'diagnosis_changed_selected_state')
        self.assertEqual(probe.failure_code(FileNotFoundError('/private/owned-secret-canary')),
                         'qualification_runtime_error')
        self.assertEqual(probe.failure_code(ValueError('payload /private/owned-secret-canary')),
                         'qualification_runtime_error')

    def test_opaque_hyphenated_ids_cannot_be_interpreted_as_cli_options(self):
        for identity in ('-owned-id', '--help', '--', 'ordinary-id'):
            for action in ('inspect', 'reject', 'approve'):
                extra = ['--binding', 'a' * 64] if action == 'approve' else []
                words = probe.ask_words(Path('/owned/missing-run'), action, identity, *extra)
                self.assertEqual(words[-2:], ['--', identity])
                # Any native approval option must remain on the option side;
                # leaving --binding after '--' would silently change parsing.
                if extra:
                    self.assertEqual(words[4:-2], extra)
        self.assertEqual(probe.ask_words('/owned/run', 'list'), ['ask', '--run', '/owned/run', 'list'])
        diagnostic = probe.cli_observation(2, b'', b'error: hidden private argument\n\nUsage: agentfw edit-session ask inspect <ID>\n')
        self.assertEqual(diagnostic['reason'], 'argument_parse_refused')
        self.assertNotIn('hidden private argument', str(diagnostic))

    def test_hardlink_control_requires_both_independent_alias_snapshots(self):
        report = self.seed()
        row = next(r for r in report['cases'] if r['id'] == 'hardlink-target')
        self.assertTrue(probe.hardlink_preserved(row))
        row['outside_alias_after']['sha256'] = probe.sha(b'changed')
        self.assertFalse(probe.passed_report(report))
        report = self.seed()
        row = next(r for r in report['cases'] if r['id'] == 'hardlink-target')
        row.pop('outside_alias_before')
        self.assertFalse(probe.passed_report(report))

    def test_default_command_is_inert(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/qualify-installed-edit.py')],
                                capture_output=True, check=True, timeout=10)
        self.assertIn(b'"executed": false', result.stdout)
        self.assertNotIn(b'"status": "passed"', result.stdout)

    def test_diagnostic_inventory_keeps_every_runtime_and_simulated_case(self):
        report = self.seed()
        report['diagnosis_requested'] = True
        report['diagnosis'] = probe.diagnostic_inventory()
        self.assertFalse(probe.passed_report(report))
        for row in report['diagnosis']['cases']:
            row.update(attempted=True, status='passed', state_unchanged=True,
                       target_unchanged=True, sentinel_unchanged=True)
        self.assertTrue(probe.passed_report(report))
        for index in range(len(probe.DIAGNOSTIC_CASES)):
            missing = copy.deepcopy(report)
            missing['diagnosis']['cases'].pop(index)
            self.assertFalse(probe.passed_report(missing))
            failed = copy.deepcopy(report)
            failed['diagnosis']['cases'][index]['status'] = 'incomplete'
            self.assertFalse(probe.passed_report(failed))
            changed = copy.deepcopy(report)
            changed['diagnosis']['cases'][index]['target_unchanged'] = False
            self.assertFalse(probe.passed_report(changed))
        mislabeled = copy.deepcopy(report)
        fixture = next(r for r in mislabeled['diagnosis']['cases'] if r['kind'] == 'simulated-retained-state')
        fixture['kind'] = 'native-runtime'
        self.assertFalse(probe.passed_report(mislabeled))

    def test_diagnosis_default_freezes_inventory_without_executing(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/qualify-installed-edit.py'), '--diagnose'],
                                capture_output=True, check=True, timeout=10)
        value = json.loads(result.stdout)
        self.assertFalse(value['executed'])
        self.assertEqual(value['diagnosis'], probe.diagnostic_inventory())
        self.assertTrue(all(row['attempted'] is False for row in value['diagnosis']['cases']))

    def test_result_absence_and_matching_output_cannot_claim_commit_or_delivery(self):
        status = {'schema': probe.DIAGNOSTIC_FORMAT, 'effects': 'indeterminate',
                  'host_delivery': 'unknown', 'model_consumption': 'unknown',
                  'audit': {'calls': [{'commit': 'unknown', 'host_delivery': 'unknown', 'model_consumption': 'unknown'}]},
                  'outputs': [{'attribution': 'observed_postcondition_not_writer_or_commit_proof'}]}
        probe.require_indeterminate_status(status)
        for field in ('effects', 'host_delivery', 'model_consumption'):
            changed = copy.deepcopy(status)
            changed[field] = 'success'
            with self.assertRaises(ValueError):
                probe.require_indeterminate_status(changed)
        changed = copy.deepcopy(status)
        changed['audit']['calls'][0]['commit'] = 'committed'
        with self.assertRaises(ValueError):
            probe.require_indeterminate_status(changed)
        changed = copy.deepcopy(status)
        changed['outputs'][0]['attribution'] = 'matching_output_proves_writer'
        with self.assertRaises(ValueError):
            probe.require_indeterminate_status(changed)

    def test_live_audit_allows_only_correlated_append_only_lease_renewals(self):
        now = int(time.time() * 1000)
        def line(row):
            return json.dumps(row, sort_keys=True).encode() + b'\n'
        enrolled = {'event': 'native_liveness_enrolled', 'session': 'epoch', 'session_id': 'session',
                    'at_ms': now, 'released': True}
        renewal = {'event': 'native_liveness_renewed', 'session': 'epoch', 'session_id': 'session',
                   'at_ms': now + 1, 'released': True, 'lease_seq': 1}
        original = line(enrolled)
        def witness(raw, *, identity=(1, 2, 0o100600, 1, 1000, 1000), tick=1):
            return {'identity': identity, 'raw': raw, 'size': len(raw), 'mtime_ns': tick, 'ctime_ns': tick}
        before = witness(original)
        self.assertEqual(probe.live_audit_delta(before, copy.deepcopy(before)), 0)
        self.assertEqual(probe.live_audit_delta(before, witness(original + line(renewal), tick=2)), 1)
        negatives = [witness(original, tick=2), witness(original.replace(b'epoch', b'other')),
                     witness(original + line(renewal), identity=(1, 3, 0o100600, 1, 1000, 1000)),
                     witness(original + line(dict(renewal, event='native_call'))),
                     witness(original + line(dict(renewal, session='another-epoch'))),
                     witness(original + line(dict(renewal, session_id='another-session'))),
                     witness(original + line(dict(renewal, released=False))),
                     witness(original + line(dict(renewal, lease_seq=True))),
                     witness(original + line(dict(renewal, raw_arguments='must-not-appear'))),
                     witness(original + line(renewal) + line(renewal)),
                     witness(original + line(renewal).rstrip(b'\n')),
                     witness(original + b'{"event":"native_liveness_renewed","event":"native_call"}\n')]
        for after in negatives:
            with self.subTest(after_sha256=probe.sha(after['raw'])):
                with self.assertRaises(ValueError):
                    probe.live_audit_delta(before, after)

    def native_success_status(self):
        mutation = {'target_index': 0, 'operation': 'create', 'session_sha256': 'a' * 64,
                    'call_sha256': 'b' * 64, 'binding_sha256': 'c' * 64, 'admission': 'recorded_allow',
                    'publication_gate': 'not_recorded', 'result_release': 'recorded_allow',
                    'commit': 'unknown', 'host_delivery': 'unknown', 'model_consumption': 'unknown'}
        read = dict(mutation, operation='read', call_sha256='d' * 64)
        value = {'schema': probe.DIAGNOSTIC_FORMAT, 'effects': 'indeterminate', 'host_delivery': 'unknown',
                 'model_consumption': 'unknown',
                 'outputs': [{'target_index': 0, 'operation': 'create', 'observation': 'present',
                              'sha256': probe.sha(probe.NEW.encode()), 'bytes': len(probe.NEW.encode()),
                              'attribution': 'observed_postcondition_not_writer_or_commit_proof'}],
                 'audit': {'completeness': 'selected_bounded_records_only', 'calls': [mutation, read]}}
        return value

    def test_native_success_requires_correlated_audit_boundaries_and_following_read(self):
        value = self.native_success_status()
        read = value['audit']['calls'][1]
        probe.require_diagnostic(value, operation='create', binding_sha256='c' * 64, read_after=True)
        negatives = []
        for field, replacement in [('completeness', 'incomplete'), ('calls', []), ('calls', [read])]:
            changed = copy.deepcopy(value);changed['audit'][field] = replacement;negatives.append(changed)
        for field, replacement in [('result_release', 'not_recorded'), ('admission', 'recorded_ask'),
                                   ('binding_sha256', 'e' * 64), ('target_index', 1), ('call_sha256', None)]:
            changed = copy.deepcopy(value);changed['audit']['calls'][0][field] = replacement;negatives.append(changed)
        changed = copy.deepcopy(value);changed['audit']['calls'][1]['session_sha256'] = 'e' * 64;negatives.append(changed)
        changed = copy.deepcopy(value);changed['audit']['calls'].reverse();negatives.append(changed)
        for changed in negatives:
            with self.assertRaises(ValueError):
                probe.require_diagnostic(changed, operation='create', binding_sha256='c' * 64, read_after=True)
        replacement = copy.deepcopy(value)
        replacement['outputs'][0]['operation'] = 'replace'
        replacement['audit']['calls'][0].update(operation='replace', publication_gate='recorded_allow')
        probe.require_diagnostic(replacement, operation='replace', binding_sha256='c' * 64, read_after=True)
        replacement['audit']['calls'][0]['publication_gate'] = 'not_recorded'
        with self.assertRaises(ValueError):
            probe.require_diagnostic(replacement, operation='replace', binding_sha256='c' * 64, read_after=True)

    def test_prior_exact_ask_is_not_counted_as_an_executed_mutation(self):
        value = self.native_success_status()
        ask = dict(value['audit']['calls'][0], admission='recorded_ask', call_sha256=None,
                   binding_sha256=None, result_release='not_recorded')
        value['audit']['calls'].insert(0, ask)
        probe.require_diagnostic(value, operation='create', binding_sha256='c' * 64, read_after=True)
        for key, replacement in [('session_sha256', 'e' * 64), ('target_index', 1),
                                 ('operation', 'replace'), ('result_release', 'recorded_allow'),
                                 ('binding_sha256', 'c' * 64)]:
            changed = copy.deepcopy(value)
            changed['audit']['calls'][0][key] = replacement
            with self.assertRaises(ValueError):
                probe.require_diagnostic(changed, operation='create', binding_sha256='c' * 64, read_after=True)
        second_allow = copy.deepcopy(value)
        second_allow['audit']['calls'].insert(2, copy.deepcopy(second_allow['audit']['calls'][1]))
        with self.assertRaises(ValueError):
            probe.require_diagnostic(second_allow, operation='create', binding_sha256='c' * 64, read_after=True)
        late_ask = copy.deepcopy(value)
        late_ask['audit']['calls'].append(late_ask['audit']['calls'].pop(0))
        with self.assertRaises(ValueError):
            probe.require_diagnostic(late_ask, operation='create', binding_sha256='c' * 64, read_after=True)

    def test_failed_diagnostic_value_is_retained_privately_before_grading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = self.native_success_status()
            value['authenticated_daemon'] = 'unavailable'
            response = subprocess.CompletedProcess([], 0, json.dumps(value).encode() + b'\n',
                                                    b'owned-privacy-regression-canary')
            observation = probe.retain_diagnostic_response(root, 'pending-ask-status', 'output', response)
            with self.assertRaises(ValueError):
                probe.require_diagnostic(json.loads(response.stdout), daemon='matching_current_epoch')
            self.assertEqual((root / observation['stdout_artifact']).read_bytes(), response.stdout)
            self.assertEqual((root / observation['stderr_artifact']).read_bytes(), response.stderr)
            self.assertNotIn('owned-privacy-regression-canary', json.dumps(observation))
            if os.name != 'nt':
                self.assertTrue(all(path.stat().st_mode & 0o077 == 0 for path in root.iterdir()))
            with self.assertRaises(FileExistsError):
                probe.retain_diagnostic_response(root, 'pending-ask-status', 'output', response)

    def test_oversized_diagnostic_response_is_not_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            response = subprocess.CompletedProcess([], 0, b'x' * (128 * 1024 + 1), b'')
            with self.assertRaises(ValueError):
                probe.retain_diagnostic_response(root, 'pending-ask-status', 'output', response)
            self.assertEqual(list(root.iterdir()), [])

    def test_diagnostic_failure_retains_completed_native_witnesses_without_passing_case(self):
        native = {'status': 'passed', 'before': {'exists': False},
                  'after': {'exists': True, 'sha256': probe.sha(probe.NEW.encode())},
                  'observed_results': 3, 'write_admissions': 1,
                  'process_cleanup': {'all_stopped': True, 'descendant_count': 3},
                  'terminal': {'state': 'host_completed'}, 'audit_sha256': 'a' * 64}
        def completed_native_then_failed_diagnosis(args, report):
            probe.retain_validated_runtime_case(report, 'useful-create', native)
            row = next(r for r in report['diagnosis']['cases'] if r['id'] == 'create-read-status')
            row['attempted'] = True
            raise ValueError('diagnosis_host_outcome')
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'new-attempt'
            with mock.patch.object(sys, 'argv', ['qualify-installed-edit.py', '--run', '--diagnose', '--output', str(output)]), \
                 mock.patch.object(probe, 'qualify', side_effect=completed_native_then_failed_diagnosis), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(probe.main(), 1)
            saved = json.loads((output / 'report.json').read_bytes())
            row = next(r for r in saved['cases'] if r['id'] == 'useful-create')
            self.assertEqual(row['status'], 'failed')
            self.assertEqual(row['failure'], 'diagnosis_host_outcome')
            self.assertEqual(row['qualification_stage'], 'native_checks_complete_diagnosis_pending')
            for key, value in native.items():
                if key != 'status':
                    self.assertEqual(row[key], value)
            self.assertEqual(saved['diagnosis']['cases'][0]['status'], 'failed')
            self.assertEqual(saved['inventory']['passed'], 0)
            self.assertFalse(probe.passed_report(saved))

    def test_create_and_replace_remain_known_write_in_the_real_classifier(self):
        for tool, description, arguments in (
            ('create_output_0', 'Create the exact selected private output with bounded text.',
             {'path': 'result.txt', 'content': probe.NEW}),
            ('replace_output_0', 'Replace the exact selected private output using the required fixed old identity and digest.',
             {'path': 'result.txt', 'content': probe.NEW, 'old_sha256': 'a' * 64,
              'old_identity': {key: 1 for key in ('device', 'inode', 'size', 'mtime_seconds', 'mtime_nanoseconds',
                                'ctime_seconds', 'ctime_nanoseconds', 'uid', 'gid', 'mode')}})):
            import json
            event = {'tool_name': tool, 'raw_arguments': arguments, 'tool_description': description,
                     'tool_schema': {'type': 'object'}, 'server_id': 'private-output'}
            result = subprocess.run([sys.executable, '-I', str(ROOT / 'rule_baseline/rule_baseline.py')],
                                    input=json.dumps(event).encode() + b'\n', capture_output=True, check=True, timeout=5)
            prediction = json.loads(result.stdout)
            self.assertEqual(prediction['actions'], ['write'])
            self.assertFalse(prediction['unknown'])
