# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('edit_stop_probe', ROOT / 'scripts/qualify-installed-edit-stop.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class InstalledEditStopEvidence(unittest.TestCase):
    def test_stop_decisions_use_shared_ask_helper_and_preserve_opaque_ids(self):
        calls = []
        suite = object.__new__(probe.BASE.Suite)
        suite.cli = lambda *words: (calls.append(words) or (0, None))
        run = object.__new__(probe.Run)
        run.suite, run.run = suite, Path('/owned-run-not-executed')
        pending = {'pending_id': '--help', 'binding_sha256': 'a' * 64}
        self.assertEqual(run.decision(pending), (0, None))
        self.assertEqual(calls[-1], ('ask', '--run', run.run, 'approve',
                                    '--binding', pending['binding_sha256'], '--', '--help'))
        self.assertEqual(run.decision(pending, False), (0, None))
        self.assertEqual(calls[-1], ('ask', '--run', run.run, 'reject', '--', '--help'))

    def test_shared_cli_parses_complete_pretty_status_and_keeps_run_line_contract(self):
        suite = object.__new__(probe.BASE.Suite)
        suite.binary, suite.work, suite.env, suite.report = Path('/not-executed/agentfw'), ROOT, {}, {}
        value = {'schema': probe.BASE.DIAGNOSTIC_FORMAT, 'effects': 'indeterminate',
                 'audit': {'completeness': 'selected_bounded_records_only'}}
        def observed(words, raw):
            with patch.object(probe.BASE.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, raw, b'')):
                return suite.cli(*words)
        self.assertEqual(observed(('status', '--run', '/not-executed/run', '--json'),
                                  (json.dumps(value, indent=2) + '\n').encode()), (0, value))
        # A partial/multi-document response must not acquire status authority.
        self.assertEqual(observed(('status', '--json'), b'not-json\n' + json.dumps(value).encode()), (0, None))
        # Existing launchers legitimately print a run record and final outcome.
        self.assertEqual(observed(('run',), b'{"run":"one"}\n{"state":"failed"}\n'),
                         (0, {'state': 'failed'}))

    def test_partial_or_missing_native_inventory_cannot_pass(self):
        report = {'format': probe.FORMAT, 'status': 'passed', 'expected': list(probe.CASES),
                  'claude_sha256': probe.BASE.CLAUDE, 'paid_inference': False, 'unrelated_process_preserved': True,
                  'cases': [{'id': name, 'status': 'passed', 'attempted': True} for name in probe.CASES]}
        self.assertTrue(probe.passed(report))
        for i in range(len(probe.CASES)):
            changed = copy.deepcopy(report);changed['cases'][i]['status'] = 'incomplete'
            self.assertFalse(probe.passed(changed))
        for key in ('claude_sha256', 'unrelated_process_preserved', 'paid_inference'):
            changed = copy.deepcopy(report);changed.pop(key)
            self.assertFalse(probe.passed(changed))

    def test_queued_or_partial_stop_never_counts_as_confirmation(self):
        value = {'format': 'sw-installed-edit-stop-result/1', 'status': 'stopped',
                 'revocation_confirmed': True, 'cleanup_confirmed': True,
                 'effects_may_remain_committed': True, 'running_effects_rolled_back': False, 'automatic_retry': False}
        self.assertTrue(probe.stop_ok(0, value, 'stopped'))
        for key in value:
            changed = dict(value);changed.pop(key)
            self.assertFalse(probe.stop_ok(0, changed, 'stopped'))
        for status in ('requested_unconfirmed', 'cleanup_incomplete'):
            self.assertFalse(probe.stop_ok(0, dict(value, status=status), 'stopped'))
        self.assertFalse(probe.stop_ok(1, value, 'stopped'))

    def test_default_driver_is_inert(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/qualify-installed-edit-stop.py')],
                                capture_output=True, check=True, timeout=10)
        value = json.loads(result.stdout)
        self.assertIs(value['executed'], False)
        self.assertEqual(value['expected'], list(probe.CASES))


if __name__ == '__main__':
    unittest.main()
