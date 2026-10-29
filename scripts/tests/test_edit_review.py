# SPDX-License-Identifier: Apache-2.0
"""Qualification grading must reject missing, reordered or unsupported evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('review_qualification', ROOT / 'scripts/qualify-edit-review.py')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


class ReviewQualification(unittest.TestCase):
    def report(self):
        report = {'format':review.FORMAT, 'status':'passed', 'paid_inference':False,
                  'claude_sha256':review.EDIT.CLAUDE, 'expected':list(review.CASES),
                  'provider_requests_during_review':0, 'sentinel_preserved':True,
                  'all_owned_stopped':True, 'exact_export_verified':True,
                  'cases':[{'id':n, 'status':'passed', 'attempted':True} for n in review.CASES]}
        for row in report['cases'][1:3]: row.update(genuine_readback=True, unchanged=True)
        for row in report['cases']:
            if row['id'] == 'read-substitution-race':
                row.update(review={'exit_code':1}, actual_descriptor_read_race=True, outside_unchanged=True)
            if row['id'] == 'undeclared-target': row.update(exit=1, review={'exit_code':1})
        return report

    def test_every_control_must_be_attempted_and_pass(self):
        self.assertTrue(review.passed_report(self.report()))
        for index in range(len(review.CASES)):
            for key, value in [('attempted', False), ('status', 'failed'), ('status', 'incomplete')]:
                report = self.report();report['cases'][index][key] = value
                self.assertFalse(review.passed_report(report))

    def test_fixed_complete_denominator_and_order(self):
        for operation in ['drop', 'duplicate', 'reorder']:
            report = self.report()
            if operation == 'drop': report['cases'].pop()
            if operation == 'duplicate': report['cases'].append(copy.deepcopy(report['cases'][0]))
            if operation == 'reorder': report['cases'].reverse()
            self.assertFalse(review.passed_report(report))

    def test_positive_requires_actual_host_readback_export_and_preservation(self):
        for index in [1, 2]:
            for key in ['genuine_readback', 'unchanged']:
                report = self.report();report['cases'][index][key] = False
                self.assertFalse(review.passed_report(report))
        for key in ['provider_requests_during_review', 'sentinel_preserved', 'all_owned_stopped',
                    'exact_export_verified', 'claude_sha256', 'paid_inference']:
            report = self.report();report.pop(key)
            self.assertFalse(review.passed_report(report))
        report = self.report();report['provider_requests_during_review'] = 1
        self.assertFalse(review.passed_report(report))
        report = self.report();report['provider_requests_during_review'] = False
        self.assertFalse(review.passed_report(report))

    def test_default_is_inert(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/qualify-edit-review.py')],
                                capture_output=True, check=True, timeout=10)
        value = json.loads(result.stdout)
        self.assertIs(value['executed'], False)
        self.assertEqual(value['expected'], list(review.CASES))
        self.assertNotIn('status', value)

    def test_followup_cannot_overwrite_a_completed_refusal_or_hide_contradiction(self):
        for state in ['passed', 'failed']:
            active = {'status':state, 'review':{'exit_code':1}};report = {}
            review.retain_review_diagnostic(report, active, {'exit_code':0})
            self.assertEqual(active['review']['exit_code'], 1)
            self.assertEqual(report['last_review']['exit_code'], 0)
        active = {'status':'incomplete'};review.retain_review_diagnostic({}, active, {'exit_code':1})
        self.assertEqual(active['review']['exit_code'], 1)
        for name in ['undeclared-target', 'read-substitution-race']:
            report = self.report();row = next(r for r in report['cases'] if r['id'] == name)
            row['review']['exit_code'] = 0
            self.assertFalse(review.passed_report(report))
