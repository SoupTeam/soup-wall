# SPDX-License-Identifier: Apache-2.0
"""Finite qualification accounting; the positive workflow requires real Linux."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('refresh_qualification', ROOT / 'scripts/qualify-edit-refresh.py')
refresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(refresh)


class RefreshQualification(unittest.TestCase):
    def report(self):
        report = {'format': refresh.FORMAT, 'status': 'passed', 'paid_inference': False,
                  'claude_sha256': refresh.EDIT.CLAUDE, 'expected': list(refresh.CASES),
                  'sentinel_preserved': True, 'all_owned_stopped': True,
                  'cases': [{'id': name, 'status': 'passed', 'attempted': True} for name in refresh.CASES]}
        useful = report['cases'][1]
        useful.update(first_readback=True, second_readback=True, new_epoch=True,
                      new_binding=True, retired_authority_refused=True)
        return report

    def test_incomplete_failed_or_unattempted_control_is_never_accepted(self):
        self.assertTrue(refresh.passed_report(self.report()))
        for index in range(len(refresh.CASES)):
            for key, value in (('status', 'failed'), ('status', 'incomplete'), ('attempted', False)):
                report = self.report();report['cases'][index][key] = value
                self.assertFalse(refresh.passed_report(report))
        report = self.report();report['cases'].pop()
        self.assertFalse(refresh.passed_report(report))

    def test_positive_evidence_requires_both_readbacks_fresh_authority_and_cleanup(self):
        for key in ('first_readback', 'second_readback', 'new_epoch', 'new_binding', 'retired_authority_refused'):
            report = self.report();report['cases'][1][key] = False
            self.assertFalse(refresh.passed_report(report))
        for key in ('sentinel_preserved', 'all_owned_stopped', 'claude_sha256', 'paid_inference'):
            report = self.report();report.pop(key)
            self.assertFalse(refresh.passed_report(report))

    def test_default_is_inert_and_lists_the_complete_fixed_denominator(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/qualify-edit-refresh.py')],
                                capture_output=True, check=True, timeout=10)
        report = json.loads(result.stdout)
        self.assertIs(report['executed'], False)
        self.assertEqual(report['expected'], list(refresh.CASES))
        self.assertNotIn('status', report)
