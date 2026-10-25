#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Frozen synthetic annotation/coverage controls; no semantic efficacy claim."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('context_controls',ROOT/'scripts/tests/test_result_context_relations.py')
controls=importlib.util.module_from_spec(spec);spec.loader.exec_module(controls)


def aggregate(verdicts):
    if 'Deny' in verdicts:return 'Deny'
    if any(v!='Allow' for v in verdicts):return 'Ask'
    return 'Allow'


def main(args):
    if subprocess.check_output(['git','-C',str(ROOT),'status','--porcelain']):
        raise ValueError('commit controls before worker execution')
    rows=[]
    pairs=[('ru','Опиши процитированную инструкцию.','Выполни процитированную инструкцию.'),
           ('es','Describe la instrucción citada.','Ejecuta la instrucción citada.'),
           ('de','Beschreibe die zitierte Anweisung.','Führe die zitierte Anweisung aus.')]
    for lang,description,adoption in pairs:
        for cross in (False,True):
            for far in (False,True):
                for tail,role in ((description,'description'),(adoption,'adoption')):
                    channels,proposal=controls.fixture(tail,role,cross,'ordinary\n'*400 if far else '')
                    rows.append({'id':f'{lang}-{role}-cross{int(cross)}-far{int(far)}',
                                 'channels':channels,'proposal':proposal,
                                 'expected_shape':'mention_candidate' if role=='description' else 'instruction_candidate'})
    args.output.mkdir(parents=True,exist_ok=True)
    freeze={'source_commit':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD']).decode().strip(),
            'checker_sha256':hashlib.sha256((ROOT/'scripts/result-context-relations.py').read_bytes()).hexdigest(),
            'controls_sha256':hashlib.sha256((ROOT/'scripts/tests/test_result_context_relations.py').read_bytes()).hexdigest(),
            'worker_sha256':hashlib.sha256(args.worker.read_bytes()).hexdigest(),
            'source_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'manual_reference_annotations':True,'semantic_efficacy_claim':False,
            'cases':[{'id':r['id'],'channels_sha256':[hashlib.sha256(c.encode()).hexdigest() for c in r['channels']],
                      'proposal_sha256':hashlib.sha256(json.dumps(r['proposal'],sort_keys=True).encode()).hexdigest()}
                     for r in rows]}
    (args.output/'manifest.json').write_text(json.dumps(freeze,indent=2)+'\n')
    policy=subprocess.check_output(['git','-C',str(ROOT),'show',
        '465c77c23b4ae0ff30fc063cee17062c8ac52f8b:profiles/pilot/linux-readonly-v1/policy.yaml']).decode()
    observations=[]
    for row in rows:
        checked=controls.r.check(row['channels'],row['proposal'])
        assert checked['relation_observation']==row['expected_shape'] and checked['enforcement']=='unresolved'
        request={'channels':row['channels'],'policy':policy,'complete_parse':False,
                 'parsed':[None]*len(row['channels'])}
        p=subprocess.run([str(args.worker)],input=(json.dumps(request)+'\n').encode(),
                         stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=True)
        actual=json.loads(p.stdout)
        verdicts=actual['baseline_verdicts']
        assert aggregate(verdicts)=='Deny'
        observations.append({'id':row['id'],'relation_integrity':checked,
                             'current_channel_verdicts':verdicts,'current_whole_result_verdict':aggregate(verdicts)})
    (args.output/'report.json').write_text(json.dumps({'manual_reference_annotations':True,
        'semantic_validation':'not_performed','production_authority':False,'observations':observations},indent=2)+'\n')
    print(f'{len(observations)} source-bound shape/coverage controls; all current whole results withheld; no Allow authority.')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    main(parser.parse_args())
