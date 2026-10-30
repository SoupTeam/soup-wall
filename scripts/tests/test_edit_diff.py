# SPDX-License-Identifier: Apache-2.0
"""Qualification must not turn missing controls or absent observations into pass."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('diff_qualification',ROOT/'scripts/qualify-edit-diff.py')
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)


class DiffQualification(unittest.TestCase):
    def report(self):
        rows=[]
        for name in driver.CASES:
            row={'id':name,'status':'passed','attempted':True,'genuine_readback':True,'preserved':True,
                 'observer_captured_attempt':True,'fault_observed':True,'outside_not_read':True,'controlled_fixture_restored':True}
            if name not in driver.SETUP:row['calls']=[{'exit':driver.expected_exit(name),'observer_loaded':True,'exec_attempts':0}]
            rows.append(row)
        return {'format':driver.FORMAT,'status':'passed','paid_inference':False,'expected':list(driver.CASES),'cases':rows,
            'source_commit':'a'*40,'source_tree':'b'*40,'component':'c'*64,'agentfw_sha256':'d'*64,'claude_sha256':driver.EDIT.CLAUDE,
            'provider_requests_during_diff':0,'process_exec_attempts_during_diff':0,'sentinel_preserved':True,'all_owned_stopped':True}

    def test_default_is_inert_and_frozen(self):
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/qualify-edit-diff.py')],capture_output=True,timeout=10,check=True)
        value=json.loads(result.stdout);self.assertIs(value['executed'],False)
        self.assertEqual(value['expected'],list(driver.CASES));self.assertEqual(len(driver.CASES),42)

    def test_missing_reordered_failed_unattempted_controls_refuse(self):
        self.assertTrue(driver.passed_report(self.report()))
        for i in range(len(driver.CASES)):
            for field,value in [('attempted',False),('status','failed'),('status','incomplete')]:
                report=self.report();report['cases'][i][field]=value;self.assertFalse(driver.passed_report(report),(i,field))
        for op in ('drop','duplicate','reorder'):
            report=self.report()
            if op=='drop':report['cases'].pop()
            elif op=='duplicate':report['cases'].append(copy.deepcopy(report['cases'][0]))
            else:report['cases'].reverse()
            self.assertFalse(driver.passed_report(report))

    def test_actual_readback_and_fault_observations_are_required(self):
        for i,name in enumerate(driver.CASES):
            required=['preserved']if name not in driver.SETUP else[]
            if name in driver.RACES:required+=['fault_observed','outside_not_read','controlled_fixture_restored']
            if name.startswith('genuine-'):required+=['genuine_readback']
            if name=='execution-observer-control':required+=['observer_captured_attempt']
            for field in required:
                report=self.report();report['cases'][i].pop(field);self.assertFalse(driver.passed_report(report),(name,field))
            if name not in driver.SETUP:
                for field,value in [('calls',[]),('calls',[{'exit':0,'observer_loaded':False,'exec_attempts':0}])]:
                    report=self.report();report['cases'][i][field]=value;self.assertFalse(driver.passed_report(report))

    def test_zero_counters_and_complete_provenance_are_not_optional(self):
        for field in ('provider_requests_during_diff','process_exec_attempts_during_diff'):
            for value in (None,False,True,1,-1):
                report=self.report();report[field]=value;self.assertFalse(driver.passed_report(report))
        for field in ('source_commit','source_tree','component','agentfw_sha256','claude_sha256','sentinel_preserved','all_owned_stopped','paid_inference'):
            report=self.report();report.pop(field);self.assertFalse(driver.passed_report(report))
        for i,name in enumerate(driver.CASES):
            if name not in driver.SETUP:
                for field,value in [('exit',True),('exit',99),('observer_loaded',False),('exec_attempts',True),('exec_attempts',1)]:
                    report=self.report();report['cases'][i]['calls'][0][field]=value;self.assertFalse(driver.passed_report(report))

    def test_native_readback_decodes_json_wrappers_without_matching_metadata(self):
        text='b\n'*2048
        wrapped=[{'type':'text','text':json.dumps({'payload':{'text':text}})}]
        self.assertTrue(driver.delivered_text(wrapped,text))
        self.assertFalse(driver.delivered_text([{'text':driver.sha(text.encode())}],text))
        self.assertFalse(driver.delivered_text(None,text))
        self.assertFalse(driver.delivered_text({'text':''},''))

    def test_malformed_inventory_is_not_accepted(self):
        for bad in (None,[],{'cases':None},{'cases':[None]}):self.assertFalse(driver.passed_report(bad))

    def test_host_failure_diagnostics_retain_only_known_tags_and_digests(self):
        with tempfile.TemporaryDirectory()as tmp:
            work=Path(tmp);secret='private-path-secret\x1b'
            (work/'owned-stdout.private').write_text(json.dumps({'run':secret,'reason':'provider_child_environment_unavailable'})+'\n'+json.dumps({'reason':{'private':secret}})+'\n')
            (work/'owned-stderr.private').write_text('Error: edit_session_incomplete\n'+secret+'\n')
            result=driver.host_failure_diagnostic(work,'owned');raw=json.dumps(result)
            self.assertNotIn(secret,raw);self.assertNotIn('private-path-secret',raw)
            self.assertEqual(result[0]['known_outcomes'],['provider_child_environment_unavailable'])
            self.assertEqual(result[1]['known_outcomes'],['edit_session_incomplete'])
            self.assertTrue(all(r['raw_retained']is False and driver.digest(r['sha256'],64)for r in result))
