# SPDX-License-Identifier: Apache-2.0
"""A summary cannot grade missing genuine operations or interrupted custody green."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('application_qualification', ROOT / 'scripts/qualify-edit-application.py')
application = importlib.util.module_from_spec(spec)
spec.loader.exec_module(application)


class ApplicationQualification(unittest.TestCase):
    def report(self):
        report = {'format':application.FORMAT, 'status':'passed', 'expected':list(application.CASES),
                  'paid_inference':False, 'provider_requests_during_operator':0, 'operator_tool_requests':0,
                  'operator_state_checks':100, 'all_owned_stopped':True,
                  'sentinel_preserved':True, 'claude_sha256':application.EDIT.CLAUDE,
                  'source_commit':'a' * 40, 'source_tree':'b' * 40,
                  'cases':[{'id':name, 'attempted':True, 'status':'passed'} for name in application.CASES]}
        for key in ('agentfw_sha256', 'component_sha256', 'helper_sha256', 'fault_sha256'):
            report[key] = 'c' * 64
        for row in report['cases']:
            if row['id'].startswith('genuine-'):
                row.update(genuine_host_readback=True, apply_readback=True, revert_readback=True, source_unchanged=True)
            if row['id'] in application.FAULTS:
                row.update(actual_syscall_fault=True, recovery_indeterminate=True,
                           fault_exit=-9 if row['id'] in ('before-publication', 'after-publication', 'after-receipt-sync') else 1)
            if row['id'] == 'concurrent-application':
                row.update(actual_processes=2, exact_single_winner=True)
        return report

    def test_every_declared_control_must_really_be_attempted_and_pass(self):
        self.assertTrue(application.passed_report(self.report()))
        for i in range(len(application.CASES)):
            for key, value in [('attempted', False), ('status', 'failed'), ('status', 'incomplete')]:
                report = self.report(); report['cases'][i][key] = value
                self.assertFalse(application.passed_report(report))

    def test_denominator_source_and_runtime_identity_are_mandatory(self):
        for operation in ('missing', 'duplicate', 'reordered'):
            report = self.report()
            if operation == 'missing': report['cases'].pop()
            if operation == 'duplicate': report['cases'].append(copy.deepcopy(report['cases'][0]))
            if operation == 'reordered': report['cases'].reverse()
            self.assertFalse(application.passed_report(report))
        for key in ('source_commit', 'source_tree', 'agentfw_sha256', 'component_sha256', 'helper_sha256', 'fault_sha256'):
            report = self.report(); report.pop(key)
            self.assertFalse(application.passed_report(report))

    def test_genuine_readback_revert_and_actual_interruption_cannot_be_backfilled(self):
        for name in ('genuine-create-apply-revert', 'genuine-replace-apply-revert'):
            for key in ('genuine_host_readback', 'apply_readback', 'revert_readback', 'source_unchanged'):
                report = self.report(); next(r for r in report['cases'] if r['id'] == name)[key] = False
                self.assertFalse(application.passed_report(report))
        for name in application.FAULTS:
            for key, value in [('actual_syscall_fault', False), ('recovery_indeterminate', False), ('fault_exit', 0), ('fault_exit', False)]:
                report = self.report(); next(r for r in report['cases'] if r['id'] == name)[key] = value
                self.assertFalse(application.passed_report(report))

    def test_external_effects_or_boolean_zero_cannot_grade_as_offline(self):
        for key, value in [('provider_requests_during_operator', 1), ('provider_requests_during_operator', False),
                           ('operator_tool_requests', 1), ('operator_tool_requests', False),
                           ('operator_state_checks', 0), ('operator_state_checks', True),
                           ('all_owned_stopped', False), ('sentinel_preserved', False), ('paid_inference', True)]:
            report = self.report(); report[key] = value
            self.assertFalse(application.passed_report(report))
        for key, value in [('actual_processes', 1), ('actual_processes', True), ('exact_single_winner', False)]:
            report = self.report(); next(r for r in report['cases'] if r['id'] == 'concurrent-application')[key] = value
            self.assertFalse(application.passed_report(report))

    def test_default_does_not_execute_or_publish(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/qualify-edit-application.py')],
                                capture_output=True, timeout=10, check=True)
        value = json.loads(result.stdout)
        self.assertIs(value['executed'], False)
        self.assertEqual(value['expected'], list(application.CASES))
        self.assertNotIn('status', value)
