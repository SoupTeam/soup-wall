#!/usr/bin/env python3
"""Bounded local official-SDK compatibility acceptance. Never contacts providers."""
# SPDX-License-Identifier: Apache-2.0
import argparse
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
import time
from sdk_compat.runner import APIS, CASES, PINNED, digest, run_case, write_json

def source(root):
    def git(*args):return subprocess.check_output(['git','-C',str(root),*args],text=True).strip()
    return {'commit':git('rev-parse','HEAD'),'dirty':bool(git('status','--porcelain'))}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true')
    parser.add_argument('--gateway',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--expected-commit',required=True)
    parser.add_argument('--dev',action='store_true',help='diagnostic subset/dirty run; never acceptance')
    parser.add_argument('--case',choices=CASES)
    args=parser.parse_args(); root=Path(__file__).resolve().parents[1]
    if not args.run:print('Preview only; use --run to start owned fixtures.');return 0
    if args.output.exists() or args.output.with_suffix('.partial.jsonl').exists():raise SystemExit('Fresh report path required')
    before=source(root)
    if before['commit']!=args.expected_commit or (before['dirty'] and not args.dev):raise SystemExit('Exact clean source required')
    if args.case and not args.dev:raise SystemExit('Subset cannot establish acceptance')
    versions={name:importlib.metadata.version(name) for name in PINNED}
    if versions!=PINNED:raise SystemExit('Pinned SDK versions required')
    dependencies=json.loads((root/'docs/operations/evidence/SOU92_DEPENDENCIES.json').read_text())['packages']
    for dep in dependencies:
        if importlib.metadata.version(dep['name'])!=dep['version']:raise SystemExit('Pinned dependency required: '+dep['name'])
    binary=args.gateway.resolve(strict=True); binary_hash=digest(binary.read_bytes())
    planned=[(api,stream,case,enforce) for api in APIS for stream in (False,True)
             for case in CASES if (not args.case or case==args.case) and (stream or case!='cancel')
             for enforce in ((True,False) if case in ('deny','ask','destructive') else (True,))]
    report={'schema':'sou92-sdk-acceptance/1','status':'incomplete','release_acceptance':False,
            'source_before':before,'binary_sha256':binary_hash,'sdk_versions':versions,
            'dependency_lock_sha256':digest((root/'scripts/requirements-sou92.txt').read_bytes()),
            'dependencies':{dep['name']:dep['version'] for dep in dependencies},
            'environment':{'system':platform.system(),'python':platform.python_version()},
            'cases_expected':len(planned),'cases':[],'limitations':['Owned deterministic upstream; no live-model effectiveness claim.',
            'Synchronous Python SDKs only; client retries explicitly disabled.','POST side effects cannot be undone by withholding a response.']}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    partial=args.output.with_suffix('.partial.jsonl')
    started=time.monotonic()
    with partial.open('x',encoding='utf-8') as checkpoint:
        checkpoint.write(json.dumps({'status':'incomplete','source':before})+'\n');checkpoint.flush()
        for api,stream,case,enforce in planned:
            try:row=run_case(binary,api,stream,case,enforce)
            except Exception as error:row={'api':api,'streaming':stream,'case':case,'enforce':enforce,'grade':{'status':'incomplete','errors':[type(error).__name__]}}
            report['cases'].append(row);checkpoint.write(json.dumps(row,ensure_ascii=False)+'\n');checkpoint.flush()
            print(json.dumps({k:row[k] for k in ('api','streaming','case','enforce','grade')}),flush=True)
    after=source(root);report['source_after']=after
    report['elapsed_seconds']=round(time.monotonic()-started,3)
    report['summary']={name:sum(r['grade']['status']==name for r in report['cases']) for name in ('pass','fail','incomplete')}
    report['source_binary_stable']=before==after and digest(binary.read_bytes())==binary_hash
    complete=(not args.dev and not before['dirty'] and report['source_binary_stable'] and len(report['cases'])==len(planned))
    report['status']='pass' if complete and report['summary']['pass']==len(planned) else ('fail' if report['summary']['fail'] else 'incomplete')
    write_json(args.output,report)
    print(json.dumps({'status':report['status'],'summary':report['summary']}))
    return 0 if report['status']=='pass' else 1 if report['status']=='fail' else 2

if __name__=='__main__':raise SystemExit(main())
