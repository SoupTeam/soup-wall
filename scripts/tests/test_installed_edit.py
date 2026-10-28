# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('installed_edit', ROOT / 'scripts/qualify-installed-edit.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class InstalledEditEvidence(unittest.TestCase):
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
