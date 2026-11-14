# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('batch',ROOT/'scripts/qualify-edit-batch.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
class BatchEvidence(unittest.TestCase):
    def report(self):
        r={'format':M.FORMAT,'status':'passed','expected':list(M.CASES),'paid_inference':False,'claude_sha256':M.EDIT.CLAUDE,
           'operator_provider_requests':0,'source_and_siblings_preserved':True,'all_owned_stopped':True,
           'cases':[{'id':n,'attempted':True,'status':'passed'}for n in M.CASES]}
        for k,n in [('source_commit',40),('source_tree',40),('agentfw_sha256',64),('helper_sha256',64),('fault_sha256',64),('component_sha256',64)]:r[k]='a'*n
        for c in r['cases']:
            if c['id']=='installed-closure':c['standard_stack_bytes']=1048576
            if c['id']in ('genuine-two-file-flow','genuine-eight-file-flow'):c.update({k:True for k in ('genuine_host_readback','apply_readback','revert_readback','reviewed','source_preserved')})
            if c['id']in M.FAULTS:c.update(fault_observed=True,truthful_partial=True,safe_recovery=True,preserved=True,fault_exit=-9 if c['id'].endswith('kill')or c['id']=='after-receipt-sync'else 0)
            if c['id']=='concurrent-application':c['exact_single_winner']=True
        return r
    def test_finite_denominator_and_every_attempt_are_required(self):
        self.assertTrue(M.passed(self.report()))
        for i in range(len(M.CASES)):
            for k,v in [('attempted',False),('status','incomplete')]:r=self.report();r['cases'][i][k]=v;self.assertFalse(M.passed(r))
        for op in ('missing','duplicate','reorder'):
            r=self.report()
            if op=='missing':r['cases'].pop()
            elif op=='duplicate':r['cases'].append(copy.deepcopy(r['cases'][0]))
            else:r['cases'].reverse()
            self.assertFalse(M.passed(r))
    def test_actual_effects_identity_and_no_provider_claims_are_required(self):
        for k in ('source_commit','source_tree','agentfw_sha256','helper_sha256','fault_sha256','component_sha256'):
            r=self.report();r.pop(k);self.assertFalse(M.passed(r))
        for i,row in enumerate(self.report()['cases']):
            for k in row:
                if k in ('id','attempted','status'):continue
                r=self.report();r['cases'][i][k]=False;self.assertFalse(M.passed(r))
        for k,v in [('operator_provider_requests',False),('operator_provider_requests',1),('source_and_siblings_preserved',False),('all_owned_stopped',False)]:r=self.report();r[k]=v;self.assertFalse(M.passed(r))
    def test_default_is_inert(self):
        v=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/qualify-edit-batch.py')],capture_output=True,check=True,timeout=10)
        r=json.loads(v.stdout);self.assertIs(r['executed'],False);self.assertEqual(r['expected'],list(M.CASES));self.assertNotIn('status',r)
