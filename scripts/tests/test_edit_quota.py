# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('installed_edit_quota', ROOT / 'scripts/qualify-edit-quota.py')
quota = importlib.util.module_from_spec(spec);spec.loader.exec_module(quota)


class InstalledQuotaEvidence(unittest.TestCase):
    def report(self):
        report = {'format': quota.FORMAT, 'status': 'passed', 'paid_inference': False,
                  'claude_sha256': quota.EDIT.CLAUDE, 'expected': list(quota.CASES),
                  'sentinel_preserved': True, 'owned_cleanup': True,
                  'cases': [{'id': name, 'status': 'passed', 'attempted': True} for name in quota.CASES]}
        for row in report['cases']:
            if row['id'] in ('useful-create', 'useful-replace'):
                row['exact_readback'] = True
            if row['id'] == 'fresh-run-recovery':
                row['old_epoch_refused'] = True
            if row['id'] == 'independent-run':
                row['both_runs_preserved'] = True
            if row['id'].startswith('postcommit-'):
                row['execution'] = {'externally_observed_commit': True, 'actual_success_result_observed': False}
        return report

    def test_every_planned_case_must_be_attempted_and_pass(self):
        self.assertTrue(quota.passed_report(self.report()))
        for i in range(len(quota.CASES)):
            for key, value in (('status', 'failed'), ('status', 'incomplete'), ('attempted', False)):
                report = self.report();report['cases'][i][key] = value
                self.assertFalse(quota.passed_report(report))
        report = self.report();report['cases'].pop()
        self.assertFalse(quota.passed_report(report))

    def test_useful_effects_commit_losses_fresh_authority_and_cleanup_are_required(self):
        for name, key in (('useful-create', 'exact_readback'), ('useful-replace', 'exact_readback'),
                          ('fresh-run-recovery', 'old_epoch_refused'), ('independent-run', 'both_runs_preserved')):
            report = self.report();next(r for r in report['cases'] if r['id'] == name)[key] = False
            self.assertFalse(quota.passed_report(report))
        for name in ('postcommit-withheld-create', 'postcommit-withheld-replace',
                     'postcommit-interrupted-create', 'postcommit-interrupted-replace'):
            report = self.report();next(r for r in report['cases'] if r['id'] == name)['execution'].pop('externally_observed_commit')
            self.assertFalse(quota.passed_report(report))
        for key in ('sentinel_preserved', 'owned_cleanup', 'paid_inference', 'claude_sha256'):
            report = self.report();report.pop(key)
            self.assertFalse(quota.passed_report(report))

    def test_default_is_inert_with_a_frozen_finite_inventory(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/qualify-edit-quota.py')],
                                capture_output=True, check=True, timeout=10)
        value = json.loads(result.stdout)
        self.assertIs(value['executed'], False)
        self.assertEqual(value['expected'], list(quota.CASES))
        self.assertNotIn('status', value)
