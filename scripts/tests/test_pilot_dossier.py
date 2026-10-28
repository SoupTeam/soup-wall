# SPDX-License-Identifier: Apache-2.0
"""Synthetic reconciliation controls, not runtime/product acceptance."""
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import pilot_dossier as d
from pilot_qualification import digest, matched_gate


class DossierTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.m = json.loads((ROOT / 'docs/operations/evidence/sou129/selection.json').read_text(encoding='utf-8'))
        self.index = json.loads((ROOT / self.m['support_index']['path']).read_text(encoding='utf-8'))
        self.work = json.loads((ROOT / self.m['workload']['path']).read_text(encoding='utf-8'))
        self.m['support_index'] = self.put('index.json', self.index)
        self.m['workload'] = self.put('workload.json', self.work)
        self.m['identities'] = {k: 'a' * 64 for k in d.IDENTITIES}
        self.m['environment']['kernel_release'] = 'synthetic-test-kernel'
        self.m['evidence'] = []
        self.tree = patch.object(d, 'git_tree', return_value=self.m['candidate']['tree'])
        self.tree_mock = self.tree.start(); self.addCleanup(self.tree.stop)
        self.objects = patch.object(d, 'git_json', side_effect=lambda repo, commit, path:
            self.index if 'support-index' in path else self.work)
        self.objects_mock = self.objects.start(); self.addCleanup(self.objects.stop)

    def put(self, name, value):
        raw = json.dumps(value).encode()
        (self.root / name).write_bytes(raw)
        return {'path': name, 'sha256': d.sha(raw), 'member': None, 'member_sha256': None}

    def add(self, name, report, role='candidate'):
        self.m['evidence'].append({'id': name, 'file': self.put(name + '.json', report),
                                  'owner': 'fixture-owner', 'scope': d.SCOPE, 'role': role})

    def result(self):
        return d.build(self.m, self.root, ROOT)

    def matched(self):
        r = json.loads((ROOT / 'docs/operations/evidence/sou106/measured-report.json').read_text(encoding='utf-8'))
        r['identity']['source'] = dict(self.m['candidate'], dirty=False)
        r['source_after'] = r['identity']['source'].copy()
        r['environment'] = self.m['environment'].copy()
        r['identity']['selected'] = {k: 'a' * 64 for k in d.IDENTITIES}
        r['identity']['policy_sha256'] = 'a'*64
        r['identity']['profiles'] = {name: {k: 'a' * 64 for k in
            ('profile_sha256', 'registry_sha256', 'classifier_sha256')} for name in ('filesystem', 'git')}
        r['rows'] = []
        for case in self.work['cases']:
            for arm in ('control', 'protected'):
                r['rows'].append({'case': case['id'], 'arm': arm, 'identity': r['identity'],
                    'input_sha256': 'a'*64, 'operation_sha256': digest(case['batches']),
                    'status': 'passed', 'actual_host': True, 'cleanup': True,
                    'latencies_ms': {f'toolu_pilot_{i}': 10.0 for i in range(sum(map(len, case['batches'])))},
                    'host_start_ms': 20.0, 'useful_continuation': True, 'all_results_useful': True,
                    'normalized_results_sha256': 'b'*64, 'effect_observed': arm == 'control',
                    'explicit_refusal': arm == 'protected', 'original_opens': 0,
                    'forbidden_result_delivery_count': 0,
                    'denied_execution_count': len(case['batches'][case['refused_batch']])
                        if case['kind'] == 'refusal' and arm == 'protected' else 0})
        r['gate'] = matched_gate(self.work, r)
        return r

    def full_fixture(self):
        self.add('matched', self.matched())
        r = json.loads((ROOT / 'docs/operations/evidence/sou-116/linux-prepared-run.json').read_text(encoding='utf-8'))
        r['source_before'] = dict(self.m['candidate'], dirty=False)
        r['source_after'] = r['source_before'].copy()
        r['environment'] = self.m['environment'].copy()
        r['selected_sha256'] = {k: 'a'*64 for k in d.IDENTITIES}
        r['profiles'] = {name: {k: 'a'*64 for k in ('profile_sha256','registry_sha256','classifier_sha256')}
                         for name in ('filesystem','git')}
        crash = copy.deepcopy(next(c for c in r['cases'] if c['case'] == 'daemon-loss'))
        crash['case'] = 'host-crash'  # Synthetic current-schema control, not a runtime observation.
        r['cases'].insert(-1, crash)
        self.add('prepared', r)
        a = json.loads((ROOT / 'docs/operations/evidence/sou-112/linux-qualification.json').read_text(encoding='utf-8'))
        a['source'] = dict(self.m['candidate'], dirty=False); a['source_after'] = a['source'].copy()
        a['environment'] = self.m['environment'].copy(); a['selected_sha256'] = r['selected_sha256']
        a['profiles'] = r['profiles']
        for row in a['cases']: row['policy_sha256'] = 'a'*64
        terminated = copy.deepcopy(next(c for c in a['cases'] if c['profile']=='git' and c['case']=='restart'))
        terminated.update(case='collector_term', collector_sigterm='pidfd_pinned_graceful_cleanup_confirmed', released=False)
        a['cases'].insert(7, terminated)
        self.add('ask', a)

    def test_complete_synthetic_fixture_can_be_ready(self):
        self.full_fixture()
        self.assertEqual(self.result()['status'], 'READY')

    def test_empty_evidence_not_ready(self):
        self.assertEqual(self.result()['status'], 'NOT_READY')

    def test_missing_file_records_incomplete(self):
        self.add('missing', self.matched()); (self.root / 'missing.json').unlink()
        result = self.result()
        self.assertEqual(result['status'], 'NOT_READY')
        self.assertIn('FileNotFoundError', result['evidence'][0]['blockers'][0])

    def test_corrupted_report_hash(self):
        self.add('corrupt', self.matched()); (self.root / 'corrupt.json').write_bytes(b'{}')
        self.assertIn('file_hash_mismatch', self.result()['evidence'][0]['blockers'][0])

    def test_stale_source_cannot_pass(self):
        r=self.matched(); r['identity']['source']['commit']='b'*40; r['source_after']=r['identity']['source'].copy()
        r['gate']=matched_gate(self.work,r); self.add('stale',r)
        self.assertIn('historical_source',self.result()['evidence'][0]['blockers'])

    def test_wrong_policy_profile_registry_classifier(self):
        for key in ('policy','filesystem_profile','git_registry','filesystem_classifier'):
            with self.subTest(key=key):
                self.m['evidence']=[]; self.add('mismatch',self.matched())
                self.m['identities'][key]='b'*64
                self.assertIn('identity_mismatch:'+key,self.result()['evidence'][0]['blockers'])
                self.m['identities'][key]='a'*64

    def test_missing_environment_and_environment_mismatch(self):
        for env in (None, dict(self.m['environment'],platform='wsl2')):
            self.m['evidence']=[];r=self.matched();r['environment']=env;self.add('env',r)
            self.assertIn('environment_absent_or_mismatched',self.result()['evidence'][0]['blockers'])

    def test_intentionally_failed_measurement_stays_failed(self):
        self.full_fixture()
        r=self.matched();r['rows'][1].update(status='failed',false_interruption=True)
        r['gate']=matched_gate(self.work,r)
        self.m['evidence'][0]['file']=self.put('matched.json',r)
        out=self.result();self.assertEqual(out['status'],'NOT_READY')
        row=next(x for x in out['ledger'] if x['item']=='useful-workflows')
        self.assertEqual(row['status'],'fail');self.assertEqual(row['counts'],{'passed':11,'required':12})

    def test_stored_green_gate_cannot_override_rows(self):
        r=self.matched();r['rows'][1].update(status='failed',false_interruption=True);self.add('lie',r)
        self.assertIn('stored_gate_disagrees',self.result()['evidence'][0]['blockers'][0])

    def test_duplicate_evidence_rejected(self):
        self.add('one',self.matched());self.m['evidence']*=2
        with self.assertRaises(d.Invalid):self.result()

    def test_changed_source_tree_rejected(self):
        self.tree_mock.return_value='c'*40
        with self.assertRaisesRegex(d.Invalid,'candidate_tree_mismatch'):self.result()

    def test_source_after_change_is_invalid(self):
        r=self.matched();r['source_after']['tree']='c'*40;self.add('change',r)
        self.assertIn('source_changed',self.result()['evidence'][0]['blockers'][0])

    def test_published_support_index_cannot_be_replaced(self):
        self.objects_mock.side_effect=lambda repo,commit,path: {} if 'support-index' in path else self.work
        with self.assertRaisesRegex(d.Invalid,'published_support_index_mismatch'):self.result()

    def test_unknown_schema_does_not_pass(self):
        self.add('unknown',{'format':'future/1'})
        self.assertIn('unsupported_report_schema',self.result()['evidence'][0]['blockers'][0])

    def test_ask_missing_case_cannot_reduce_denominator(self):
        self.full_fixture();ref=self.m['evidence'][2]['file'];r=json.loads((self.root/ref['path']).read_text(encoding='utf-8'))
        r['cases'].pop();self.m['evidence'][2]['file']=self.put('ask.json',r)
        self.assertIn('ask_case_denominator_changed',self.result()['evidence'][2]['blockers'][0])

    def test_history_cannot_supply_candidate_pass(self):
        self.add('historical',self.matched(),'history')
        out=self.result();self.assertEqual(out['status'],'NOT_READY');self.assertEqual(out['evidence'][0]['observations'],[])

    def test_wsl_never_inherits_linux_qualification(self):
        self.full_fixture();self.m['environment']['platform']='wsl2'
        self.assertEqual(self.result()['status'],'NOT_READY')

    def test_archive_and_member_hashes(self):
        data=b'{"ok":true}'
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:z.writestr('report.json',data)
        raw=b.getvalue();(self.root/'evidence.zip').write_bytes(raw)
        ref={'path':'evidence.zip','sha256':d.sha(raw),'member':'report.json','member_sha256':d.sha(data)}
        self.assertEqual(d.selected_bytes(self.root,ref),data)
        ref['member_sha256']='0'*64
        with self.assertRaisesRegex(d.Invalid,'member_hash_mismatch'):d.selected_bytes(self.root,ref)
        ref['sha256']='0'*64
        with self.assertRaisesRegex(d.Invalid,'file_hash_mismatch'):d.selected_bytes(self.root,ref)

    def test_archive_unsafe_members_are_rejected_without_extraction(self):
        for name in ('../outside.json','/absolute.json'):
            b=io.BytesIO()
            with zipfile.ZipFile(b,'w') as z:z.writestr(name,b'{}')
            raw=b.getvalue();(self.root/'bad.zip').write_bytes(raw)
            ref={'path':'bad.zip','sha256':d.sha(raw),'member':'report.json','member_sha256':d.sha(b'{}')}
            with self.assertRaises(d.Invalid):d.selected_bytes(self.root,ref)

    def test_duplicate_json_and_nonfinite_rejected(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":1e999}'):
            with self.assertRaises(d.Invalid):d.parse(raw)

    def test_bounded_input(self):
        with self.assertRaises(d.Invalid):d.parse(b' '* (d.MAX_REPORT+1))

    def test_cli_nonpassing_exit_and_no_overwrite(self):
        m=self.root/'selection.json';m.write_text(json.dumps(self.m))
        output=self.root/'out'
        args=['--selection',str(m),'--root',str(self.root),'--repo',str(ROOT),
              '--candidate',self.m['candidate']['commit'],'--output',str(output)]
        self.assertEqual(d.main(args),1)
        self.assertTrue((output/'dossier.json').is_file())
        self.assertEqual(d.main(args),2)
        self.assertEqual(d.main(args[:-3]+['0'*40,'--output',str(self.root/'other')]),2)

    def test_real_failed_public_report_preserves_10_of_12(self):
        r=json.loads((ROOT/'docs/operations/evidence/sou106/measured-report.json').read_text(encoding='utf-8'))
        _,src,_,obs=d.project(r,self.work)
        self.assertEqual(src['commit'],'ce4f76d823f9f1b5a7ea1dec97a8ff260a5f94dc')
        self.assertEqual(obs[0]['counts'],{'passed':10,'required':12})
        self.assertEqual(obs[0]['details']['false_interruptions'],2)
        self.assertEqual(obs[1]['counts'],{'passed':8,'required':8})
        self.assertEqual(obs[1]['details']['forbidden_effects'],0)

    def test_mixed_candidate_sources_block_even_complete_other_evidence(self):
        self.full_fixture()
        stale = self.matched()
        stale['identity']['source']['commit'] = 'b'*40
        stale['source_after'] = stale['identity']['source'].copy()
        stale['gate'] = matched_gate(self.work, stale)
        self.add('mixed', stale)
        self.assertEqual(self.result()['status'], 'NOT_READY')

    def test_missing_identity_blocks(self):
        self.add('missing-id', self.matched())
        self.m['identities']['policy'] = None
        self.assertIn('missing_identity:policy', self.result()['evidence'][0]['blockers'])

    def test_archive_missing_selected_member(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:z.writestr('other.json',b'{}')
        raw=b.getvalue();(self.root/'missing.zip').write_bytes(raw)
        ref={'path':'missing.zip','sha256':d.sha(raw),'member':'report.json','member_sha256':d.sha(b'{}')}
        with self.assertRaisesRegex(d.Invalid,'missing_archive_member'):d.selected_bytes(self.root,ref)

    def test_archive_symlink_rejected(self):
        b=io.BytesIO()
        info=zipfile.ZipInfo('link.json');info.create_system=3;info.external_attr=(0o120777 << 16)
        with zipfile.ZipFile(b,'w') as z:z.writestr(info,b'other.json')
        raw=b.getvalue();(self.root/'link.zip').write_bytes(raw)
        ref={'path':'link.zip','sha256':d.sha(raw),'member':'link.json','member_sha256':d.sha(b'other.json')}
        with self.assertRaisesRegex(d.Invalid,'archive_link_or_encryption'):d.selected_bytes(self.root,ref)

    def test_archive_expansion_bound(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('large.json',b' '*(d.MAX_REPORT+1))
        raw=b.getvalue();(self.root/'large.zip').write_bytes(raw)
        ref={'path':'large.zip','sha256':d.sha(raw),'member':'large.json','member_sha256':'a'*64}
        with self.assertRaisesRegex(d.Invalid,'archive_member_size_limit'):d.selected_bytes(self.root,ref)

    def test_prepared_cleanup_witness_cannot_be_dropped(self):
        self.full_fixture();r=json.loads((self.root/'prepared.json').read_text(encoding='utf-8'))
        r['cases'][-1]['process_cleanup']['all_stopped']=False
        self.m['evidence'][1]['file']=self.put('prepared.json',r)
        self.assertIn('prepared_cleanup_missing',self.result()['evidence'][1]['blockers'][0])

    def test_scope_change_rejected(self):
        self.m['scope']='live-model'
        with self.assertRaisesRegex(d.Invalid,'selection_scope'):self.result()

    def test_cli_failed_measurement_returns_one_with_reason(self):
        self.full_fixture()
        r=self.matched();r['rows'][1].update(status='failed',false_interruption=True)
        r['gate']=matched_gate(self.work,r)
        self.m['evidence'][0]['file']=self.put('matched.json',r)
        selection=self.root/'selection.json';selection.write_text(json.dumps(self.m))
        output=self.root/'failed'
        self.assertEqual(d.main(['--selection',str(selection),'--root',str(self.root),
            '--repo',str(ROOT),'--candidate',self.m['candidate']['commit'],'--output',str(output)]),1)
        report=json.loads((output/'dossier.json').read_text(encoding='utf-8'))
        self.assertEqual(next(x for x in report['ledger'] if x['item']=='useful-workflows')['status'],'fail')

    def test_unknown_kernel_cannot_make_environment_ready(self):
        self.full_fixture();self.m['environment']['kernel_release']=None
        self.assertEqual(self.result()['status'],'NOT_READY')
        self.assertIn('expected_environment_unbound',self.result()['evidence'][0]['blockers'])

    def test_current_scenario_denominators(self):
        self.full_fixture()
        out=self.result()
        self.assertEqual(out['status'],'READY')
        ask=next(r for r in out['ledger'] if r['item']=='ask')
        cleanup=next(r for r in out['ledger'] if r['item']=='cancellation-cleanup')
        self.assertEqual(ask['counts'],{'passed':15,'required':15})
        self.assertEqual(cleanup['counts'],{'passed':3,'required':3})
        self.assertEqual(len(json.loads((self.root/'prepared.json').read_text(encoding='utf-8'))['cases']),11)

    def test_new_required_cases_cannot_be_omitted_or_duplicated(self):
        for name, key, case in [('ask','ask','collector_term'),('prepared','prepared','host-crash')]:
            for duplicate in (False,True):
                with self.subTest(name=name,duplicate=duplicate):
                    self.m['evidence']=[];self.full_fixture()
                    r=json.loads((self.root/(name+'.json')).read_text(encoding='utf-8'))
                    row=next(x for x in r['cases'] if x['case']==case)
                    if duplicate:r['cases'].append(copy.deepcopy(row))
                    else:r['cases'].remove(row)
                    entry=next(e for e in self.m['evidence'] if e['id']==name)
                    entry['file']=self.put(name+'.json',r)
                    record=next(e for e in self.result()['evidence'] if e['id']==name)
                    self.assertIn(key+'_case_denominator_changed',record['blockers'][0])

    def test_new_cleanup_witnesses_are_required(self):
        for name in ('ask','prepared'):
            self.m['evidence']=[];self.full_fixture()
            r=json.loads((self.root/(name+'.json')).read_text(encoding='utf-8'))
            if name=='ask':
                next(c for c in r['cases'] if c['case']=='collector_term')['collector_sigterm']='unconfirmed'
            else:
                next(c for c in r['cases'] if c['case']=='host-crash')['process_cleanup']['all_stopped']=False
            next(e for e in self.m['evidence'] if e['id']==name)['file']=self.put(name+'.json',r)
            self.assertEqual(self.result()['status'],'NOT_READY')


class GitIdentityTests(unittest.TestCase):
    def test_real_checkout_commit_and_tree(self):
        commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
        tree=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip()
        self.assertEqual(d.git_tree(ROOT,commit),tree)


if __name__ == '__main__': unittest.main()
