# SPDX-License-Identifier: Apache-2.0
"""Frozen v1/v2 archival evidence accounting; native execution stays opt-in."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('archive_qualification', ROOT / 'scripts/qualify-installed-edit-archive.py')
archive = importlib.util.module_from_spec(spec);spec.loader.exec_module(archive)


class ArchiveQualification(unittest.TestCase):
    def report(self):
        result = {'format':archive.FORMAT, 'status':'passed', 'paid_inference':False, 'preserved':True,
                  'expected':list(archive.CASES), 'claude_sha256':archive.B.CLAUDE,
                  'cases':[{'id':name, 'status':'passed', 'attempted':True} for name in archive.CASES]}
        rows = {r['id']:r for r in result['cases']}
        rows['completed-archive-cleanup']['profile_format'] = archive.Q.LEGACY_PROFILE
        v2 = rows['quota-v2-completed-archive-cleanup']
        v2.update(profile_format=archive.Q.PROFILE, genuine_read_edit_read=True, exact_limits_bound=True,
                  source_retained_after_archive=True, output_preserved=True, immutable_plan_preserved=True,
                  sentinel_preserved=True, consent_refusal='explicit_raw_evidence_loss_consent_required',
                  cleanup_outcome='archived_and_cleaned', repeat_outcome='already_cleaned', quota_is_execution_proof=False)
        rows['quota-v2-malformed-refusals'].update(source_retained=True, preserved=True, controls=[
            {'id':name, 'exit_code':1, 'reason':reason, 'unchanged':True}
            for name,reason in archive.QUOTA_REFUSALS.items()])
        return result

    def test_all_frozen_controls_must_be_attempted_and_passed(self):
        self.assertTrue(archive.passed(self.report()))
        for index in range(len(archive.CASES)):
            for key,value in [('status','failed'), ('status','incomplete'), ('attempted',False)]:
                report=self.report();report['cases'][index][key]=value
                self.assertFalse(archive.passed(report))
        report=self.report();report['cases'].reverse();self.assertFalse(archive.passed(report))

    def test_both_versions_and_genuine_v2_preservation_and_consent_are_mandatory(self):
        for key in ['profile_format','genuine_read_edit_read','exact_limits_bound','output_preserved',
                    'immutable_plan_preserved','sentinel_preserved','source_retained_after_archive',
                    'consent_refusal','cleanup_outcome','repeat_outcome','quota_is_execution_proof']:
            report=self.report();row=next(r for r in report['cases'] if r['id']=='quota-v2-completed-archive-cleanup')
            row.pop(key);self.assertFalse(archive.passed(report))
        report=self.report();next(r for r in report['cases'] if r['id']=='completed-archive-cleanup').pop('profile_format')
        self.assertFalse(archive.passed(report))

    def test_malformed_quota_denominator_refusal_and_preservation_cannot_be_omitted(self):
        for index in range(len(archive.QUOTA_REFUSALS)):
            for key,value in [('exit_code',0), ('exit_code',True), ('reason','unknown'), ('unchanged',False)]:
                report=self.report();report['cases'][-1]['controls'][index][key]=value
                self.assertFalse(archive.passed(report))
        report=self.report();report['cases'][-1]['controls'].pop();self.assertFalse(archive.passed(report))

    def test_default_is_inert_and_declares_the_full_inventory(self):
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/qualify-installed-edit-archive.py')],
                              check=True,capture_output=True,timeout=10)
        value=json.loads(result.stdout)
        self.assertIs(value['executed'],False);self.assertEqual(value['expected'],list(archive.CASES))
        self.assertNotIn('status',value)
