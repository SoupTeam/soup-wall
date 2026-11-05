#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded real production CLI and interruption controls on installed owned profiles."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import pilot_candidate as c

def run(args):
    args.output.mkdir(mode=0o700)
    agent=args.candidate_directory/'agentfw'
    state=json.loads((args.installed_output/'pilot-prefix/front-door.json').read_bytes())
    selection=json.loads(Path(state['selection']).read_bytes())
    profiles={kind:Path(row['profile']['path']) for kind,row in selection['prepared_profiles'].items()}
    report={'format':'sw-installed-sandbox-exercise-qualification/1','status':'failed','cases':[],
            'active_protection':False,'cargo_or_libtest':'not-required'}
    env={'HOME':str(args.output),'PATH':'/usr/bin:/bin','LANG':'C','TMPDIR':str(args.output),
         'SOU62_INHERITED_SECRET':'owned-calibration-canary','SOU68_INHERITED_SECRET':'owned-calibration-canary'}
    def case(label,kind,profile,*,execute=True,digest=None,interrupt=False):
        words=[str(agent),'sandbox-exercise','--kind',kind,'--profile',str(profile),
               '--profile-sha256',digest or c.sha(profile.read_bytes())]
        if execute:words.append('--execute')
        process=subprocess.Popen(words,cwd=args.output,env=env,stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        observed=[]
        try:
            if interrupt:
                deadline=time.monotonic()+8
                while time.monotonic()<deadline and process.poll() is None:
                    child_file=Path(f'/proc/{process.pid}/task/{process.pid}/children')
                    for pid in child_file.read_text().split():
                        try:
                            if b'--agentfw-mcp-owner-v1' in Path('/proc',pid,'cmdline').read_bytes():
                                observed.append(pid)
                        except OSError:pass
                    if observed:
                        process.send_signal(signal.SIGTERM);break
                    time.sleep(.002)
                c.require(observed,'interruption_owner_not_observed')
            out,err=process.communicate(timeout=25)
            c.require(len(out)<=128*1024 and len(err)<=65536,'exercise_operator_output_limit')
            value=c.parse(out)
            (args.output/(label+'.json')).write_bytes(c.canonical(value))
            row={'case':label,'exit':process.returncode,'status':value.get('status'),
                 'reason':value.get('reason'),'cleanup_confirmed':value.get('cleanup_confirmed'),
                 'report_sha256':c.sha(out),'passed':False}
            report['cases'].append(row)
            if label.startswith('positive-'):
                c.require(process.returncode==0 and value['status']=='passed' and value['cleanup_confirmed'] is True
                          and value['calibration_passed'] is True and value['active_protection'] is False,
                          'exercise_positive_failed')
            elif interrupt:
                c.require(process.returncode==3 and value['status']=='failed' and value['reason']=='exercise_interrupted'
                          and value['cleanup_confirmed'] is True,'interrupted_cleanup_not_confirmed')
                for pid in observed:
                    c.require(not Path('/proc',pid).exists(),'owned_owner_survived_interruption')
            else:
                c.require(process.returncode==3 and value['status']=='failed','exercise_refusal_missing')
            row['passed']=True
        finally:
            if process.poll() is None:
                process.kill();process.wait(timeout=5)
    try:
        for kind,profile in profiles.items():
            case('positive-'+kind,kind,profile)
            case('explicit-consent-'+kind,kind,profile,execute=False)
            case('mismatched-profile-'+kind,kind,profile,digest='f'*64)
            value=json.loads(profile.read_bytes());value['runtimeSha256']='f'*64
            changed=args.output/(kind+'-changed-profile.json');changed.write_bytes(c.canonical(value))
            case('mismatched-runtime-'+kind,kind,changed)
            malformed=args.output/(kind+'-malformed.json');malformed.write_bytes(b'{')
            case('malformed-profile-'+kind,kind,malformed)
            case('interrupt-'+kind,kind,profile,interrupt=True)
        report['status']='passed'
    finally:
        (args.output/'report.json').write_text(json.dumps(report,sort_keys=True)+'\n')
    return 0

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate-directory',type=Path,required=True)
    parser.add_argument('--installed-output',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    raise SystemExit(run(parser.parse_args()))
