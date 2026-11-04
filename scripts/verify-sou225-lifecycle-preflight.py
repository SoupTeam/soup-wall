#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact-source native diagnosis observations using existing bounded doctor tracing.

The driver alone installs an owned front-door component and starts a synthetic
non-dumpable child to reproduce EACCES. Diagnosis never changes the child or host.
Raw syscall/identity/path evidence stays private; publish only report.json.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

TRACE = load('sou225_existing_doctor_observation', 'verify-sou114-pilot-doctor.py')
PREP = load('sou225_existing_platform', 'prepare-installed-pilot.py')

def require(ok, code):
    if not ok: raise ValueError(code)

def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()

def git(*words):
    return subprocess.check_output(['git', '-C', str(ROOT), *words], text=True).strip()

@contextmanager
def inaccessible_owned_child(work):
    ready = work / 'fixture-ready'
    code = ('import ctypes,sys;from pathlib import Path;'
            'assert ctypes.CDLL(None).prctl(4,0,0,0,0)==0;'
            'Path(sys.argv[1]).write_text("ready");sys.stdin.buffer.read(1)')
    p = subprocess.Popen([sys.executable, '-I', '-B', '-c', code, str(ready)], stdin=subprocess.PIPE,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        until = time.monotonic() + 5
        while not ready.exists() and p.poll() is None and time.monotonic() < until: time.sleep(.01)
        require(ready.is_file() and p.poll() is None, 'private_eacces_fixture_unavailable')
        yield
    finally:
        if p.stdin:
            try: p.stdin.close()
            except BrokenPipeError: pass
        try: p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait(timeout=5)
        require(p.poll() is not None, 'owned_fixture_cleanup_incomplete')


def observe(command, expected_images, work, env, label):
    private = work / 'private'; private.mkdir(mode=0o700, exist_ok=True)
    trace = private / (label + '.trace')
    words = [shutil.which('strace'), '-f', '-qq', '-o', str(trace), '-e',
             'trace=process,file,network,signal', *map(str,command)]
    require(words[0] is not None, 'strace_unavailable')
    result = TRACE.run_observed(words, work, env, trace, private, label)
    return result, trace


def audit(trace, expected_images):
    raw = trace.read_text()
    attempts = [line for line in raw.splitlines() if re.search(r'\b(?:execve|execveat)\(', line)]
    require(len(attempts) == len(expected_images), 'unexpected_program_execution')
    for line, image in zip(attempts,expected_images):
        require(re.search(r'\bexecve\(' + re.escape(json.dumps(str(image))) + r',.*\)\s*= 0$', line), 'unexpected_program_execution')
    for line in raw.splitlines():
        require(not re.search(r'\b(?:fork|vfork)\(',line), 'diagnosis_spawned_child')
        if re.search(r'\b(?:clone|clone3)\(',line): require('CLONE_THREAD' in line and 'CLONE_NEW' not in line, 'diagnosis_spawned_child')
        require(not re.search(r'\b(?:socket|socketpair|connect|accept|accept4|bind|listen|sendto|sendmsg|sendmmsg|recvfrom|recvmsg|recvmmsg|shutdown|setuid|setgid|setresuid|setresgid|mount|umount2|unshare|setns|kill|tgkill|mkdir|mkdirat|unlink|unlinkat|rename|renameat|renameat2|chmod|fchmod|fchmodat|chown|fchown|symlink|link|truncate|ftruncate)\(',line), 'diagnosis_effect_attempt')
        if re.search(r'\b(?:open|openat|openat2)\(',line):
            require(not re.search(r'O_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)',line), 'diagnosis_write_open_attempt')
    return {'trace_sha256': sha(trace), 'allowed_entry_images':len(expected_images),
            'extra_execution_attempts':0,'non_thread_children':0,'network_effect_attempts':0,'host_mutation_attempts':0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agentfw',type=Path,required=True)
    parser.add_argument('--component',type=Path,required=True)
    parser.add_argument('--python',type=Path,required=True)
    parser.add_argument('--expected-commit',required=True)
    parser.add_argument('--mode',choices=['ordinary','installed'],required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    PREP.supported_platform()
    require(git('rev-parse','HEAD')==args.expected_commit and not git('status','--porcelain','--untracked-files=all'),'exact_clean_source_required')
    require(args.output.is_absolute() and not args.output.exists() and not args.output.is_relative_to(ROOT),'new_private_output_required')
    os.umask(0o077);args.output.mkdir(mode=0o700)
    report={'format':'sw-lifecycle-preflight-observation/1','source':args.expected_commit,'mode':args.mode,
            'agent_sha256':sha(args.agentfw),'component_sha256':sha(args.component),'python_sha256':sha(args.python),
            'environment':'ordinary native Ubuntu 24.04 GitHub-hosted x86-64' if args.mode=='ordinary' else 'owned disposable native Ubuntu with verified installed front-door component',
            'cases':[],'active_protection':'not_measured','removal_authorized':False,'status':'incomplete'}
    try:
        with tempfile.TemporaryDirectory(prefix='sou225-owned-') as temporary:
            work=Path(temporary).resolve(); home=work/'home';home.mkdir(mode=0o700)
            env={'PATH':'/usr/bin:/bin','HOME':str(home),'LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}
            if args.mode=='installed':
                result=subprocess.run([str(args.agentfw),'pilot-component','--home',str(home),'install',str(args.component),
                    '--sha256',sha(args.component),'--python',str(args.python)],cwd=work,env=env,capture_output=True,timeout=30)
                require(result.returncode==0,'component_install_failed')
            # Reports are decoded only after the existing stream/trace bounds.
            def call(label,command,images,expected_exit=0):
                result,trace=observe(command,images,work,env,label)
                code,out,err=result.returncode,result.stdout,result.stderr
                require(code==expected_exit,'unexpected_diagnostic_exit')
                require(len(out)<=256*1024 and len(err)<=256*1024,'diagnostic_output_bound')
                value=json.loads(out)
                witness=audit(trace,images)
                return value,witness
            native,witness=call('ordinary-environment',[args.agentfw,'doctor','--lifecycle','--json'],[args.agentfw])
            require(native['lifecycle']['setup']=='satisfied','ordinary_setup_not_satisfied')
            require(native['lifecycle']['protected_run']=='unknown' and not native['lifecycle']['removal_authorized'],'diagnosis_overclaim')
            report['cases'].append({'case':'ordinary-current-environment','passed':True,'original':native,'witness':witness})
            with inaccessible_owned_child(work):
                native,witness=call('eacces-doctor',[args.agentfw,'doctor','--lifecycle','--json'],[args.agentfw])
                require(native['lifecycle']['removal']=='blocked','native_eacces_not_blocked')
                require(any(c['reason_code']=='process_evidence_inaccessible' for c in native['lifecycle']['checks']),'native_eacces_reason_missing')
                report['cases'].append({'case':'owned-eacces-doctor','passed':True,'original':native,'witness':witness})
                prefix=work/'must-not-exist'
                if args.mode=='installed':
                    command=[args.agentfw,'pilot','--home',home,'prepare','--apply','--prefix',prefix,'--allow-download','--require-removal-eligible','--json']
                    images=[args.agentfw,args.python]
                else:
                    command=[args.python,'-I','-B',ROOT/'scripts/prepare-installed-pilot.py','--prepare','--output',prefix,'--allow-download','--require-removal-eligible','--expected-commit',args.expected_commit]
                    images=[args.python]
                refused,witness=call('early-required-refusal',command,images,2)
                require(refused['reason']=='lifecycle_prerequisite_unavailable' and not refused['executed'] and not prefix.exists(),'early_refusal_had_effects')
                report['cases'].append({'case':'required-removal-prerequisite-before-preparation','passed':True,'original':refused,'witness':witness})
            if args.mode=='installed':
                value,witness=call('installed-preflight',[args.agentfw,'pilot','--home',home,'preflight','--json'],[args.agentfw,args.python])
                require(value['setup']=='satisfied' and not value['removal_authorized'],'installed_preflight_invalid')
                report['cases'].append({'case':'installed-outside-checkout','passed':True,'original':value,'witness':witness})
            report['owned_fixture_cleanup_confirmed']=True
            report['environment_preservation']='no diagnostic host mutation, namespace change or service control attempted'
        require(not git('status','--porcelain','--untracked-files=all'),'source_changed')
        report['status']='passed'
    except Exception as error:
        reason=str(error);report['reason']=reason if re.fullmatch(r'[a-z0-9_]{1,100}',reason) else type(error).__name__
        report['status']='failed'
    # Original diagnostics contain fixed public fields only; syscall traces and
    # temporary source/home paths are deliberately absent from the retained report.
    raw=json.dumps(report,sort_keys=True,indent=2)
    require(not any(token in raw for token in ('/home/','/Users/','PRIVATE_CREDENTIAL','secret-value-canary')),'published_private_data')
    (args.output/'report.json').write_text(raw+'\n')
    print(json.dumps({'status':report['status'],'cases':len(report['cases'])}))
    return 0 if report['status']=='passed' else 1

if __name__=='__main__': raise SystemExit(main())
