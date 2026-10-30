# SPDX-License-Identifier: Apache-2.0
"""Evidence grading controls; Linux boundary acceptance belongs to the native run."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('inventory_qualification', ROOT / 'scripts/qualify-edit-inventory.py')
probe = importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)


class Evidence(unittest.TestCase):
    def test_review_flags_are_read_from_the_accepted_response_wrapper(self):
        response = {'format':'sw-installed-edit-review/1', 'status':'reviewed',
                    'observation':{'executed':False, 'authority':False}}
        self.assertTrue(probe.read_only_review(response))
        for field in ('executed', 'authority'):
            changed = copy.deepcopy(response);changed['observation'].pop(field)
            self.assertFalse(probe.read_only_review(changed))
            changed = copy.deepcopy(response);changed['observation'][field] = True
            self.assertFalse(probe.read_only_review(changed))
        self.assertFalse(probe.read_only_review({'format':response['format'], 'status':'reviewed', 'executed':False}))
        self.assertFalse(probe.read_only_review(dict(response, observation=None)))

    def passing(self):
        report = {'format':probe.FORMAT, 'status':'passed', 'paid_inference':False,
                  'claude_sha256':probe.EDIT.CLAUDE, 'expected':list(probe.CASES),
                  'cases':[{'id':name, 'attempted':True, 'status':'passed'} for name in probe.CASES],
                  'sentinel_preserved':True, 'all_owned_stopped':True}
        facts = {'completed-and-interrupted-history':{'genuine_readback':True},
                 'two-live-zero-execution':{'zero_provider_requests':True, 'zero_tool_calls':True,
                                            'state_and_outputs_preserved':True},
                 'exact-status-and-stop-peer-preserved':{'peer_preserved':True},
                 'exact-completed-review':{'zero_provider_requests':True, 'output_and_plan_preserved':True},
                 'stale-selection-refused':{'state_preserved':True, 'old_selection_refused':True},
                 'unsafe-selector-refused':{'explicit_actions_only':True},
                 'malformed-and-old-boot-history':{'unknown_preserved':True},
                 'linked-and-foreign-entry':{'foreign_refused':True},
                 'concurrent-disappearance':{'moves':2, 'incomplete_observed':True},
                 'capacity-bound':{'rows':32}, 'helper-integrity':{'changed_helper_refused':True}}
        for row in report['cases']: row.update(facts.get(row['id'], {}))
        return report

    def test_default_is_inert_and_freezes_every_control(self):
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/qualify-edit-inventory.py')],
                                capture_output=True, check=True, timeout=10)
        value = json.loads(result.stdout)
        self.assertIs(value['executed'], False)
        self.assertEqual(value['expected'], list(probe.CASES))
        self.assertEqual(len(probe.CASES), 12)

    def test_missing_incomplete_or_unattempted_control_prevents_pass(self):
        report = self.passing();self.assertTrue(probe.passed_report(report))
        for index in range(len(probe.CASES)):
            for key, value in (('attempted', False), ('status', 'incomplete'), ('status', 'failed')):
                changed = copy.deepcopy(report);changed['cases'][index][key] = value
                self.assertFalse(probe.passed_report(changed))
            changed = copy.deepcopy(report);changed['cases'].pop(index)
            self.assertFalse(probe.passed_report(changed))
        changed = copy.deepcopy(report);changed['cases'].reverse()
        self.assertFalse(probe.passed_report(changed))

    def test_preservation_execution_and_race_witnesses_are_required(self):
        report = self.passing()
        for index, row in enumerate(report['cases']):
            for key in set(row) - {'id', 'attempted', 'status'}:
                changed = copy.deepcopy(report);changed['cases'][index].pop(key)
                self.assertFalse(probe.passed_report(changed), (row['id'], key))
        for value in (True, 0, -1, None):
            changed = copy.deepcopy(report)
            next(r for r in changed['cases'] if r['id'] == 'concurrent-disappearance')['moves'] = value
            self.assertFalse(probe.passed_report(changed))
        for key in ('paid_inference', 'claude_sha256', 'sentinel_preserved', 'all_owned_stopped'):
            changed = copy.deepcopy(report);changed.pop(key)
            self.assertFalse(probe.passed_report(changed))


if __name__ == '__main__': unittest.main()
