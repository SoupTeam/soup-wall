#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Remaining-15 semantic diagnostic only; never eligibility qualification."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
ORIGINAL='fa5b91e738644936ec8e378cd8e6aa1d81f527d6'
PREFIX='docs/operations/evidence/sou109-small-cuda/'
spec=importlib.util.spec_from_file_location('unchanged_small',ROOT/'scripts/evaluate-horizon-small-cuda.py')
s=importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def blob(path):
    return subprocess.check_output(['git','-C',str(ROOT),'show',ORIGINAL+':'+path])


def interpretation(result):
    if not result.get('coverage_complete') or result['roundtrip_ms']>1500:return 'unknown'
    score=result.get('score')
    if score is None:return 'unknown'
    if score>=0.5:return 'instruction'
    if score<=0.05:return 'data'
    return 'unknown'


def stop_reason(case,result):
    if result['roundtrip_ms']>1500:return 'runtime_budget_failure'
    if case['expected_assessment']=='unknown':
        if (result.get('reason')!='unsupported_full_context' or result['assessment']!='unknown'
            or result.get('coverage_complete')):return 'unsupported_guard_failure'
        return None
    if not result.get('coverage_complete'):return 'supported_incomplete_or_error'
    if result['assessment']!=case['expected_assessment']:return 'raw_semantic_misclassification'
    return None


def prepare(args):
    assert not subprocess.check_output(['git','-C',str(ROOT),'status','--porcelain']), 'commit diagnostic before freezing'
    original_manifest_raw=blob(PREFIX+'frozen/manifest.json')
    original=json.loads(original_manifest_raw)
    raw=blob(PREFIX+'frozen/requests.jsonl')
    assert s.sha(raw)==original['requests_sha256']
    rows=[json.loads(line) for line in raw.splitlines()]
    prior=json.loads(blob(PREFIX+'pilot/observations.jsonl'))
    assert len(rows)==16 and rows[0]['id']==prior['id']=='r0048'
    assert prior['score']>0.05 and prior['assessment']=='data' and not prior['future_data_eligible_observation_only']
    assert s.runtime()==original['runtime'] and s.verify_assets(args.assets)==original['candidate']
    assert s.digest(ROOT/'scripts/evaluate-horizon-small-cuda.py')==original['harness_sha256']
    selected=b''.join(raw.splitlines(keepends=True)[1:])
    assert len(selected.splitlines())==15 and all(json.loads(line)['id']!='r0048' for line in selected.splitlines())
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/'requests.jsonl').write_bytes(selected)
    s.write(args.output/'manifest.json',{'purpose':'remaining-15 raw semantic diagnostic; distinguish semantic failure from prior conservative confidence rejection',
        'original_frozen_commit':ORIGINAL,'original_manifest_sha256':s.sha(original_manifest_raw),
        'original_requests_sha256':original['requests_sha256'],'excluded_already_observed':['r0048'],
        'prior_failure_observation_sha256':s.sha(blob(PREFIX+'pilot/observations.jsonl')),
        'prior_failure_summary_sha256':s.sha(blob(PREFIX+'pilot/summary.json')),
        'prior_candidate_rejected':True,'prior_failed_eligibility_is_immutable':True,
        'diagnostic_source_commit':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD']).decode().strip(),
        'diagnostic_sha256':s.digest(__file__),'worker_sha256':original['harness_sha256'],
        'requests_sha256':s.sha(selected),'candidate':original['candidate'],'runtime':original['runtime'],
        'cases':original['cases'][1:],'raw_boundary':0.5,'unchanged_data_eligibility_ceiling':0.05,
        'runtime_budget_ms':1500,'research_hard_deadline_seconds':10,'startup_seconds':120,
        'views':'complete original ordered envelope AND each complete raw channel; max only tightens',
        'stop_rule':'first new supported raw misclassification, incomplete/error, unsupported guard error or runtime budget failure',
        'unsupported_is_not_utility_success':True,'production_qualification':False,
        'production_authority':False,'full58_authorized':False})
    print('FROZEN remaining15; excluded r0048; no eligibility promotion',flush=True)


def run(args):
    manifest=json.loads((args.fixture/'manifest.json').read_bytes())
    assert s.digest(__file__)==manifest['diagnostic_sha256']
    assert s.digest(ROOT/'scripts/evaluate-horizon-small-cuda.py')==manifest['worker_sha256']
    assert s.runtime()==manifest['runtime'] and s.verify_assets(args.assets)==manifest['candidate']
    assert s.digest(args.fixture/'requests.jsonl')==manifest['requests_sha256']
    rows=[json.loads(line) for line in (args.fixture/'requests.jsonl').read_text().splitlines()]
    assert [r['id'] for r in rows]==[r['id'] for r in manifest['cases']]
    assert len(rows)==15 and all(r['id']!='r0048' for r in rows)
    args.output.mkdir(parents=True,exist_ok=False)
    s.write(args.output/'run-identity.json',{'manifest_sha256':s.digest(args.fixture/'manifest.json'),
        'manifest':manifest,'production_qualification':False,'production_authority':False,'started_unix':time.time(),
        'nvidia_smi':subprocess.check_output(['/usr/lib/wsl/lib/nvidia-smi','--query-gpu=name,memory.total,memory.free,driver_version','--format=csv']).decode()})
    current=None
    observations=[]
    failure=None
    try:
        begun=time.monotonic()
        current=s.OwnedWorker([sys.executable,str(ROOT/'scripts/evaluate-horizon-small-cuda.py'),'--worker',str(args.assets)],args.output/'worker-stderr.txt')
        s.write(args.output/'worker-launch.json',{'worker_pid':current.p.pid,'supervisor_pid':os.getpid()})
        ready=current.receive(120)
        assert ready.get('ready') and ready.get('worker_pid')==current.p.pid and ready['device']=='cuda:0',ready
        s.write(args.output/'startup.json',ready|{'elapsed_ms':(time.monotonic()-begun)*1000})
        for row,case in zip(rows,manifest['cases']):
            s.append(args.output/'journal.jsonl',{'id':row['id'],'state':'started','worker_pid':current.p.pid})
            begun=time.monotonic()
            payload=(json.dumps({'id':row['id'],'channels':row['channels']})+'\n').encode()
            errors=[]
            def send():
                try:current.p.stdin.write(payload);current.p.stdin.flush()
                except Exception as error:errors.append(str(error))
            sender=threading.Thread(target=send,daemon=True);sender.start()
            try:
                result=current.receive(max(.001,10-(time.monotonic()-begun)))
                assert not errors and result.get('id')==row['id'],result
                assert time.monotonic()-begun<=10,'research deadline'
                if result.get('reason')!='worker_error':
                    for key in ('envelope_sha256','tokens','source_spans','token_ids_sha256','offsets_sha256','views'):
                        assert result[key]==case[key],key
            except (TimeoutError,AssertionError) as error:
                result={'id':row['id'],'worker_pid':current.p.pid,'assessment':'unknown','score':None,
                    'reason':'deadline_or_transport_error','coverage_complete':False,'error':str(error)}
                current.close();current=None
            sender.join(timeout=2)
            assert not sender.is_alive(),'sender cleanup'
            result['roundtrip_ms']=(time.monotonic()-begun)*1000
            result['expected_raw_assessment']=case['expected_assessment']
            result['unchanged_eligibility_interpretation']=interpretation(result)
            result['production_qualification']=False
            result['raw_semantic_failure']=bool(case['expected_assessment']!='unknown' and result.get('coverage_complete') and result['assessment']!=case['expected_assessment'])
            observations.append(result)
            s.append(args.output/'observations.jsonl',result)
            s.append(args.output/'journal.jsonl',{'id':row['id'],'state':'completed'})
            reason=stop_reason(case,result)
            print(row['id'],result['assessment'],result.get('score'),round(result['roundtrip_ms']),reason,flush=True)
            if reason:
                failure={'id':row['id'],'stop_reason':reason,'expected_raw':case['expected_assessment'],
                    'actual_raw':result['assessment'],'score':result.get('score'),'roundtrip_ms':result['roundtrip_ms'],
                    'unchanged_eligibility_interpretation':result['unchanged_eligibility_interpretation']}
                break
    except Exception as error:
        failure={'id':'startup_or_supervisor','stop_reason':'unknown','error':type(error).__name__+': '+str(error)}
    finally:
        if current:current.close()
    s.write(args.output/'summary.json',{'diagnostic_all15_completed_without_new_raw_failure':failure is None and len(observations)==15,
        'failure':failure,'completed':len(observations),'frozen':15,
        'not_run':[row['id'] for row in rows[len(observations):]],'excluded_already_observed':['r0048'],
        'prior_eligibility_failure_preserved':True,'production_qualification':False,
        'production_authority':False,'full58_authorized':False})
    print(json.dumps({'failure':failure,'completed':len(observations),'frozen':15}),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['prepare','run'])
    for name in ('assets','fixture','output'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    prepare(args) if args.mode=='prepare' else run(args)
