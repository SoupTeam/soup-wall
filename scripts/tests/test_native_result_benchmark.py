# SPDX-License-Identifier: Apache-2.0
"""Finite denominator and artifact identity controls; native evidence is separate."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import hashlib
import json
import runpy
import sys
import os

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bench', ROOT / 'scripts/benchmark-native-results.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


class BenchmarkControls(unittest.TestCase):
    def test_summary_preserves_failed_and_unattempted_trials(self):
        rows = [{'condition': 'debug-idle', 'variant': 'measured-candidate', 'status': 'passed',
                 'burst_ms': 4000, 'burst_result_timing': [{'tracking_us': 2000}]},
                {'condition': 'debug-idle', 'variant': 'measured-candidate', 'status': 'failed'}]
        summary = B.summarize(rows)
        result = next(r for r in summary if r['condition'] == 'debug-idle' and r['variant'] == 'measured-candidate')
        self.assertEqual((result['planned'], result['attempted'], result['passed'], result['failed'], result['incomplete']),
                         (3, 2, 1, 1, 1))
        self.assertEqual(result['successful_burst_median_ms'], 4000)
        empty = next(r for r in summary if r['condition'] == 'distribution-idle')
        self.assertIsNone(empty['successful_burst_median_ms'])
        self.assertEqual(empty['incomplete'], 3)

    def test_manifest_rejects_changed_binary_wrong_profile_and_missing_variant(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'owned'; binary.write_bytes(b'public build fixture')
            entry = {'binary': str(binary), 'binary_sha256': B.sha(binary), 'source': 'a' * 40,
                     'rustc': 'rustc owned fixture', 'profile': 'dev'}
            value = {variant: {'dev': dict(entry), 'release': dict(entry, profile='release')}
                     for variant in ('instrumented-baseline', 'measured-candidate')}
            B.check_manifest(value)
            for mutate in (lambda r: r.pop('instrumented-baseline'),
                           lambda r: r['measured-candidate']['dev'].update(profile='release'),
                           lambda r: r['measured-candidate']['dev'].update(binary_sha256='b' * 64)):
                broken = copy.deepcopy(value); mutate(broken)
                with self.assertRaises(ValueError): B.check_manifest(broken)
            binary.write_bytes(b'changed fixture')
            with self.assertRaises(ValueError): B.check_manifest(value)

    def test_actual_client_interface_and_refused_or_incomplete_bursts(self):
        # Exercise the whole trial with the actual Client method interface;
        # no network, model, daemon or synthetic performance claim.
        for mode in ('exact', 'refused', 'missing', 'cleanup_failed', 'startup_failed'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                root=Path(folder)
                workspace=root/'workspace'; workspace.mkdir()
                payload=b'owned public fixture'
                (workspace/'k120.txt').write_bytes(payload)
                recorded=[]
                class Client:
                    # Only the real Client's methods are exposed here.
                    def send(self, *frames):
                        self.replies=[]
                        for i, frame in enumerate(frames):
                            ident=frame['id']
                            value=({'jsonrpc':'2.0','id':ident,'result':{'content':[{'type':'text','text':payload.decode()}],
                                    'structuredContent':{'content':payload.decode()}}} if i<8 else
                                   {'jsonrpc':'2.0','id':ident,'error':{'code':-32603,'message':B.L.budgets()['frame_message']}})
                            if mode=='refused' and i==3:value={'jsonrpc':'2.0','id':ident,'error':{'code':-32603,'message':'refused'}}
                            raw=json.dumps(value).encode()+b'\n'
                            self.replies.append((value,raw))
                            recorded.append({'request_event':'result','content_sha256':hashlib.sha256(raw).hexdigest(),
                                             'release_decision':True,'tracking_us':100})
                        if mode=='missing':self.replies.pop()
                    def receive(self, timeout):
                        if not self.replies:raise TimeoutError()
                        return self.replies.pop(0)
                class Phase:
                    def __init__(self,args,context,label,installed,workspace):
                        if mode=='startup_failed':raise ValueError('owned startup failure')
                        self.root=root/label;self.root.mkdir()
                        self.client=Client();self.count=0;self.sent=False
                        self.section={'memory_after_initialize':{'vm_rss_kib':100},'memory_final':{'vm_hwm_kib':101},
                            'client':{'exit_code':0,'forced_cleanup':False,'process_cleanup':{'all_stopped':True}},
                            'daemon_cleanup':{'all_stopped':True},'daemon_exit_code':0,
                            'cleanup_audit':{'cleanup_verified':mode!='cleanup_failed'}}
                        context['phases'][label]=self.section
                    def start(self):pass
                    def stop(self):pass
                    def exchange(self,*args):
                        return 0,{'result':{'content':[{'type':'text','text':payload.decode()}],
                                           'structuredContent':{'content':payload.decode()}}},b'',[],[]
                    def ident(self):self.count+=1;return self.count
                    def reads(self,path):
                        return (8 if path.endswith('k120.txt') else 1) if recorded else 0
                    def useful(self,label):return True
                for method in ('send','receive'):
                    self.assertTrue(hasattr(B.L.BASE.Client,method))
                report={'trials':[]}
                with patch.object(B.L,'Phase',Phase),patch.object(B,'timing_rows',lambda path,event: recorded if event=='native_admission_timing' else []):
                    B.trial(SimpleNamespace(output=root),report,{'binary':'/owned-fixture'},
                            {'name':'debug-idle','owned_cpu_loaders':0},'measured-candidate',0,root,workspace)
                row=report['trials'][0]
                self.assertEqual(row['status'],'passed' if mode=='exact' else 'failed')
                if mode=='missing':self.assertEqual(len(row['responses']),8)
                self.assertEqual(row['planned_responses'],9)
                self.assertTrue((root/'report.json').is_file())

    def test_builds_cannot_alias_old_and_candidate_cargo_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            scratch=root/'scratch';scratch.mkdir();(scratch/'binaries').mkdir()
            baseline=root/'baseline';candidate=root/'candidate'
            baseline.mkdir();candidate.mkdir()
            observed=[]
            def checked(command, **options):
                if command[:2]==['rustc','--version']:return 'rustc owned fixture'
                if command[:3]==['git','status','--porcelain']:return b''
                return ('a'*40 if options['cwd']==baseline else 'b'*40)
            def build(command, **options):
                target=Path(options['env']['CARGO_TARGET_DIR'])
                profile=command[command.index('--profile')+1]
                manifest=Path(command[command.index('--manifest-path')+1])
                self.assertEqual(manifest,options['cwd']/'Cargo.toml')
                out=target/('debug' if profile=='dev' else 'release')/'agentfw'
                out.parent.mkdir(parents=True,exist_ok=True)
                out.write_bytes((str(options['cwd'])+profile).encode())
                observed.append((options['cwd'],target))
            argv=['build-native-result-benchmark.py','--baseline',str(baseline),'--candidate',str(candidate),'--scratch',str(scratch)]
            with patch.object(sys,'argv',argv),patch('subprocess.check_output',checked),patch('subprocess.run',build):
                runpy.run_path(str(ROOT/'scripts/build-native-result-benchmark.py'),run_name='__main__')
            self.assertEqual(len(observed),4)
            self.assertNotEqual(observed[0][1],observed[2][1])
            value=json.loads((scratch/'builds.json').read_text())
            self.assertNotEqual(value['instrumented-baseline']['dev']['binary_sha256'],value['measured-candidate']['dev']['binary_sha256'])


if __name__ == '__main__':
    unittest.main()
