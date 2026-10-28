# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('edit_stop_probe', ROOT / 'scripts/qualify-installed-edit-stop.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class InstalledEditStopEvidence(unittest.TestCase):
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
