# SPDX-License-Identifier: Apache-2.0
"""Gate fixtures only: never presented as actual-host qualification."""
import copy
import sys
import os
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from pilot_measurement import load_workload, restore_control_files, useful_result
from pilot_qualification import digest, matched_gate, Failure

class MatchedGateTests(unittest.TestCase):
    def setUp(self):
        self.workload = load_workload(ROOT)
        self.report = {'workload_sha256': digest(self.workload), 'identity': {'source': 'fixture'},
                       'rows': [], 'cleanup': True, 'source_unchanged': True}
        for c in self.workload['cases']:
            for arm in ('control','protected'):
                self.report['rows'].append({'case':c['id'],'arm':arm,'identity':self.report['identity'],
                    'input_sha256':'fixture', 'operation_sha256':digest(c['batches']),'status':'passed','actual_host':True,'cleanup':True,
                    'latencies_ms':{f'toolu_pilot_{i}':10.0 for i in range(sum(map(len,c['batches'])))},
                    'host_start_ms':20.0,'useful_continuation':True,'all_results_useful':True,
                    'normalized_results_sha256':'fixture','effect_observed':arm=='control',
                    'explicit_refusal':arm=='protected','original_opens':0 if arm=='protected' else 1,
                    'forbidden_result_delivery_count':0,'denied_execution_count':len(c['batches'][1]) if c['kind']=='refusal' and arm=='protected' else 0})
    def gate(self): return matched_gate(self.workload,self.report)
    def test_complete_fixture_has_full_denominators(self):
        r=self.gate();self.assertEqual(r['status'],'passed');self.assertEqual(r['metrics']['benign_completed'],12)
        self.assertEqual(r['metrics']['refusal_required'],8)
        self.assertGreater(r['metrics']['call_overhead_ms']['n'],40)
    def test_missing_duplicate_and_reordered_pairs(self):
        for mutate in (lambda r:r.pop(),lambda r:r.append(r[0]),lambda r:r.reverse()):
            with self.subTest(mutate=mutate):
                r=copy.deepcopy(self.report);mutate(r['rows'])
                with self.assertRaisesRegex(Failure,'missing_duplicate_or_reordered_pair'): matched_gate(self.workload,r)
    def test_identity_drift(self):
        self.report['rows'][1]['identity']={'source':'changed'}
        with self.assertRaisesRegex(Failure,'paired_identity_drift'):self.gate()
    def test_workload_and_operation_drift(self):
        for key in ('workload_sha256','operation_sha256'):
            with self.subTest(key=key):
                r=copy.deepcopy(self.report)
                (r if key=='workload_sha256' else r['rows'][0])[key]='changed'
                with self.assertRaises(Failure):matched_gate(self.workload,r)
    def test_input_drift(self):
        self.report["rows"][1]["input_sha256"]="changed"
        with self.assertRaisesRegex(Failure,"paired_input_drift"):self.gate()
    def test_skips_rejected(self):
        self.report['rows'][0]['status']='skipped'
        with self.assertRaisesRegex(Failure,'hidden_skip'):self.gate()
    def test_missing_calibration_rejected(self):
        self.report['rows'][24]['effect_observed']=False
        with self.assertRaisesRegex(Failure,'absent_control_calibration'):self.gate()
    def test_forbidden_effect_fails(self):
        self.report['rows'][25]['effect_observed']=True
        self.assertEqual(self.gate()['status'],'failed')
    def test_benign_failure_and_incomplete_keep_denominator(self):
        self.report['rows'][1].update(status='failed',false_interruption=True)
        self.report['rows'][3]['status']='incomplete'
        r=self.gate();self.assertEqual(r['status'],'failed');self.assertEqual(r['metrics']['benign_required'],12)
        self.assertEqual(r['metrics']['benign_completed'],10)
    def test_zero_or_nonfinite_latency_denominators(self):
        self.report['rows'][0]['latencies_ms']={}
        with self.assertRaises(Failure):self.gate()
    def test_missing_independent_execution_witness(self):
        self.report['rows'][25]['original_opens']=1
        with self.assertRaisesRegex(Failure,'denied_execution_witness_missing'):self.gate()
    def test_benign_result_changed(self):
        self.report['rows'][1]['normalized_results_sha256']='changed'
        with self.assertRaisesRegex(Failure,'useful_result_mismatch'):self.gate()
    def test_cleanup_or_source_change_fails(self):
        self.report['source_unchanged']=False
        self.assertEqual(self.gate()['status'],'failed')

class UsefulContentTests(unittest.TestCase):
    def test_original_head_tail_and_full_read_bytes(self):
        api=SimpleNamespace(BASE=SimpleNamespace(TEXT='guide\n'),NOTES='notes\n')
        self.assertTrue(useful_result(api,'read_text_file',{'path':'/workspace/guide.txt','head':1},'guide'))
        self.assertFalse(useful_result(api,'read_text_file',{'path':'/workspace/guide.txt','head':1},'guide\n'))
        self.assertTrue(useful_result(api,'read_text_file',{'path':'/workspace/notes.txt','tail':2},'notes\n'))
        self.assertTrue(useful_result(api,'read_text_file',{'path':'/workspace/notes.txt'},'notes\n'))
    def test_successful_mcp_envelope_with_file_errors_is_not_useful(self):
        api=SimpleNamespace(BASE=SimpleNamespace(TEXT='guide\n'),NOTES='notes\n')
        self.assertFalse(useful_result(api,'read_multiple_files',{},'guide.txt: Error - Access denied'))

class OwnedRestorationTests(unittest.TestCase):
    def test_inplace_and_replaced_inode_restore_original(self):
        for replace in (False, True):
            with self.subTest(replace=replace), tempfile.TemporaryDirectory() as folder:
                root=Path(folder); path=root/'owned'; backup=root/'backup'; added=root/'added'
                path.write_bytes(b'original'); inode=path.stat().st_ino
                os.link(path,backup)
                if replace:
                    other=root/'lock'; other.write_bytes(b'changed'); os.replace(other,path)
                else:
                    path.write_bytes(b'changed')
                added.write_bytes(b'new')
                restore_control_files({path:b'original',added:None},{path:backup})
                self.assertEqual(path.read_bytes(),b'original')
                self.assertEqual(path.stat().st_ino,inode)
                self.assertEqual(path.stat().st_nlink,1)
                self.assertFalse(backup.exists());self.assertFalse(added.exists())

if __name__=='__main__': unittest.main()
