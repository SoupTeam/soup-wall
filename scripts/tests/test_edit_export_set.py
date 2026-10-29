# SPDX-License-Identifier: Apache-2.0
"""Frozen qualification evidence must contain the actual controls and witnesses."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('set_qualification', ROOT/'scripts/qualify-edit-export-set.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class ExportSetQualification(unittest.TestCase):
    def report(self):
        rows = []
        for i,name in enumerate(driver.CASES):
            row = {'id':name,'status':'passed','attempted':True,'source_preserved':True,
                   'genuine_readback':True,'exact_manifest_and_bytes':True,'fault_observed':True,'no_partial_publication':True}
            if i >= 3:
                row['calls'] = [{'exit_code':0 if i < 6 else 1,'accepted':i < 6,
                                 'status':('preview' if i == 3 else 'published') if i < 6 else 'incomplete'}]
            rows.append(row)
        return {'format':driver.FORMAT,'status':'passed','paid_inference':False,'claude_sha256':driver.EDIT.CLAUDE,
                'expected':list(driver.CASES),'cases':rows,'provider_requests_during_export':0,
                'sentinel_preserved':True,'all_owned_stopped':True}

    def test_default_is_inert_and_freezes_complete_inventory(self):
        result = subprocess.run([sys.executable,'-B',str(ROOT/'scripts/qualify-edit-export-set.py')],capture_output=True,timeout=10,check=True)
        value = json.loads(result.stdout)
        self.assertIs(value['executed'],False)
        self.assertEqual(value['expected'],list(driver.CASES))
        self.assertEqual(len(driver.CASES),31)

    def test_missing_reordered_incomplete_or_unattempted_cases_never_pass(self):
        self.assertTrue(driver.passed_report(self.report()))
        for i in range(len(driver.CASES)):
            for key,value in [('status','failed'),('status','incomplete'),('attempted',False)]:
                report=self.report();report['cases'][i][key]=value
                self.assertFalse(driver.passed_report(report),(i,key,value))
        for op in ('drop','duplicate','reverse'):
            report=self.report()
            if op == 'drop': report['cases'].pop()
            elif op == 'duplicate': report['cases'].append(copy.deepcopy(report['cases'][0]))
            else: report['cases'].reverse()
            self.assertFalse(driver.passed_report(report))

    def test_faults_readback_bytes_and_preservation_are_mandatory(self):
        for i,name in enumerate(driver.CASES):
            fields = ['source_preserved'] if i >= 3 else []
            if name in driver.FAULTS: fields += ['fault_observed','no_partial_publication']
            if name in ('genuine-two-file-run','genuine-eight-file-run'): fields += ['genuine_readback']
            if name in ('two-file-atomic-export','eight-file-atomic-export'): fields += ['exact_manifest_and_bytes']
            for field in fields:
                report=self.report();report['cases'][i].pop(field)
                self.assertFalse(driver.passed_report(report),(name,field))
        for field in ('provider_requests_during_export','sentinel_preserved','all_owned_stopped','claude_sha256','paid_inference'):
            report=self.report();report.pop(field)
            self.assertFalse(driver.passed_report(report))
        for value in (False,True,1,None):
            report=self.report();report['provider_requests_during_export']=value
            self.assertFalse(driver.passed_report(report))

    def test_refusal_is_typed_and_cannot_be_replaced_by_a_success(self):
        for i in range(3,len(driver.CASES)):
            report=self.report();report['cases'][i]['calls']=[]
            self.assertFalse(driver.passed_report(report))
        for i in range(6,len(driver.CASES)):
            report=self.report();report['cases'][i]['calls'][-1].update(exit_code=0,accepted=True,status='published')
            self.assertFalse(driver.passed_report(report))
        report=self.report();report['cases'][6]['calls'][0]['exit_code']=True
        self.assertFalse(driver.passed_report(report))
