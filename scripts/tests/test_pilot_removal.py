# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('removal',ROOT/'scripts/qualify-pilot-removal.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
class RemovalEvidence(unittest.TestCase):
    def report(self):
        v={'format':M.FORMAT,'status':'passed','expected':list(M.CASES),'paid_inference':False,
           'all_owned_stopped':True,'sibling_and_project_preserved':True,'operator_provider_requests':0,
           'claude_sha256':M.EDIT.CLAUDE,'cases':[{'id':n,'status':'passed','attempted':True} for n in M.CASES]}
        for key in ('source_commit','source_tree'):v[key]='a'*40
        for key in ('agentfw_sha256','helper_sha256','component_sha256','fault_sha256'):v[key]='b'*64
        for r in v['cases']:
            if r['id'] in M.FAULTS:r.update(actual_syscall_fault=True,preserved=True,
                fault_exit=-9 if r['id'] in ('before-unlink','between-objects','after-unlink') else 0,
                explicit_retry_completed=True,uncertain_not_success=True)
            if r['id'] in ('genuine-completed-edit','actual-removal-preserves-user-data'):
                r.update(actual_installed_effect=True,preserved=True)
        return v
    def test_every_case_is_required_without_duplicates_or_missing_attempts(self):
        self.assertTrue(M.passed(self.report()))
        for i in range(len(M.CASES)):
            for key,val in [('status','incomplete'),('attempted',False)]:
                v=self.report();v['cases'][i][key]=val;self.assertFalse(M.passed(v))
        for change in ('missing','duplicate','reversed'):
            v=self.report()
            if change=='missing':v['cases'].pop()
            elif change=='duplicate':v['cases'].append(copy.deepcopy(v['cases'][0]))
            else:v['cases'].reverse()
            self.assertFalse(M.passed(v))
    def test_faults_actual_effect_preservation_and_identity_cannot_be_backfilled(self):
        for key in ('source_commit','source_tree','agentfw_sha256','helper_sha256','component_sha256','fault_sha256'):
            v=self.report();v.pop(key);self.assertFalse(M.passed(v))
        for r in self.report()['cases']:
            keys=[k for k in ('actual_syscall_fault','preserved','explicit_retry_completed','uncertain_not_success','actual_installed_effect') if k in r]
            for key in keys:
                # Only assertions applicable to this particular fault count.
                v=self.report();target=next(x for x in v['cases'] if x['id']==r['id']);target[key]=False
                if key=='explicit_retry_completed' and r['id'] not in ('before-unlink','between-objects','unlink-io'):continue
                if key=='uncertain_not_success' and r['id'] not in ('after-unlink','directory-sync'):continue
                self.assertFalse(M.passed(v))
        for key,val in [('operator_provider_requests',False),('operator_provider_requests',1),('all_owned_stopped',False),('sibling_and_project_preserved',False)]:
            v=self.report();v[key]=val;self.assertFalse(M.passed(v))
    def test_default_only_lists_inventory(self):
        p=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/qualify-pilot-removal.py')],capture_output=True,check=True,timeout=10)
        v=json.loads(p.stdout);self.assertIs(v['executed'],False);self.assertEqual(v['expected'],list(M.CASES));self.assertNotIn('status',v)
