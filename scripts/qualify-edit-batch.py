#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit disposable installed Linux batch qualification; default is inert.

Raw mappings, generated content and returned private proofs stay local. Only
finite outcomes and exact source/binary/helper identities enter report.json.
"""
from __future__ import annotations
import argparse
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('batch_review',ROOT/'scripts/qualify-edit-review.py')
REVIEW=importlib.util.module_from_spec(spec);spec.loader.exec_module(REVIEW)
EDIT=REVIEW.EDIT
require,sha=EDIT.require,EDIT.sha
FORMAT='sw-installed-edit-batch-qualification/1'
FAULTS=('between-publications-kill','between-publications-io','after-publication-kill','receipt-sync','after-receipt-sync')
CASES=('installed-closure','genuine-two-file-flow','genuine-eight-file-flow','preview-no-writes','no-consent',
       'changed-last-output','changed-last-target','duplicate-output','duplicate-target','missing-last-target','linked-last-target',
       'hardlinked-last-target','special-last-target','redirected-parent','protected-root','stale-confirmation','duplicate-application',
       'later-user-change','same-bytes-substitution','missing-applied-member','stale-recovery','without-returned-proof','corrupt-backup','unknown-journal',
       'active-run','cancelled-run','concurrent-application',*FAULTS)

def passed(report):
    rows=report.get('cases',[]);by={r.get('id'):r for r in rows}
    if not(report.get('format')==FORMAT and report.get('status')=='passed' and report.get('expected')==list(CASES)
        and [r.get('id') for r in rows]==list(CASES) and all(r.get('attempted') is True and r.get('status')=='passed' for r in rows)
        and type(report.get('operator_provider_requests')) is int and report['operator_provider_requests']==0
        and report.get('source_and_siblings_preserved') is True and report.get('all_owned_stopped') is True and report.get('paid_inference') is False
        and report.get('claude_sha256')==EDIT.CLAUDE):return False
    for k,n in [('source_commit',40),('source_tree',40),('agentfw_sha256',64),('helper_sha256',64),('fault_sha256',64),('component_sha256',64)]:
        if not re.fullmatch('[0-9a-f]{'+str(n)+'}',str(report.get(k,''))):return False
    for name in ('genuine-two-file-flow','genuine-eight-file-flow'):
        if not all(by[name].get(k) is True for k in ('genuine_host_readback','apply_readback','revert_readback','reviewed','source_preserved')):return False
    if by['installed-closure'].get('standard_stack_bytes')!=1048576:return False
    for name in FAULTS:
        if not all(by[name].get(k) is True for k in ('fault_observed','truthful_partial','safe_recovery','preserved')):return False
        if name.endswith('kill') or name=='after-receipt-sync':
            if by[name].get('fault_exit')!=-signal.SIGKILL:return False
        elif type(by[name].get('fault_exit')) is not int or by[name]['fault_exit'] not in (0,1):return False
    if by['concurrent-application'].get('exact_single_winner') is not True:return False
    return True

def tree(root):
    rows=[]
    for p in sorted([root,*root.rglob('*')]):
        m=p.lstat();raw=b''
        if stat.S_ISREG(m.st_mode):require(m.st_size<=1024*1024,'witness_cap');raw=p.read_bytes()
        rows.append((str(p.relative_to(root)),m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns,sha(raw)))
        require(len(rows)<=256,'witness_count')
    return rows

@contextlib.contextmanager
def changed(path,holding,kind):
    kept=holding/'held-original';path.rename(kept)
    try:
        if kind=='symlink':path.symlink_to(kept)
        elif kind=='fifo':os.mkfifo(path,0o600)
        elif kind=='same':path.write_bytes(kept.read_bytes());path.chmod(0o600)
        elif kind=='edit':path.write_text('Later owned user change.\n');path.chmod(0o600)
        yield
    finally:
        if path.exists() or path.is_symlink():path.unlink()
        kept.rename(path)

def qualify(args,report):
    require(platform.system()=='Linux' and platform.machine()=='x86_64' and os.geteuid()!=0,'native_linux_user_required')
    suite=EDIT.Suite(args,report)
    archive=args.output/'component.tar'
    built=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/build-pilot-front-door.py'),'--out',str(archive)],cwd=ROOT,env=suite.env,capture_output=True,timeout=60)
    require(built.returncode==0,'component_build_failed');built=json.loads(built.stdout.splitlines()[-1])
    installed=subprocess.run([str(suite.binary),'pilot-component','--home',str(suite.home),'install',str(archive),'--sha256',built['archive_sha256'],'--python',str(args.python)],cwd=suite.work,env=suite.env,capture_output=True,timeout=60)
    require(installed.returncode==0,'component_install_failed')
    report.update(source_commit=built['commit'],source_tree=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip(),
                  agentfw_sha256=sha(suite.binary.read_bytes()),helper_sha256=sha(Path(__file__).read_bytes()),fault_sha256=sha(args.fault.read_bytes()),component_sha256=built['component'],claude_sha256=EDIT.CLAUDE)
    def begin(n):r=report['cases'][CASES.index(n)];r['attempted']=True;suite.active=r;return r
    def done(n,**facts):report['cases'][CASES.index(n)].update(status='passed',**facts)
    begin('installed-closure')
    for command in ('preview','apply','status','recover-preview','recover','revert-preview','revert'):
        v=subprocess.run(['/usr/bin/prlimit','--stack=1048576','--',str(suite.binary),'edit-session','batch',command,'--help'],cwd=suite.work,env=suite.env,capture_output=True,timeout=20)
        require(v.returncode==0,'batch_startup_failed')
    done('installed-closure',standard_stack_bytes=1048576)
    journals=suite.work/'batch-journals';journals.mkdir(mode=0o700)
    holding=suite.work/'holding';holding.mkdir(mode=0o700)
    sentinel=EDIT.snapshot(suite.sentinel)
    trap=EDIT.HOST.ScriptedModel([])
    env=dict(suite.env,ANTHROPIC_API_KEY='owned-batch-provider-trap',ANTHROPIC_BASE_URL=trap.url,HTTP_PROXY=trap.url,HTTPS_PROXY=trap.url)
    completed=[];counter=0
    def source_witness(data):
        root,plan,prepared,run,names=data
        return (EDIT.private_state_witness(run,include_audit=(run/'terminal.json').exists()),[(n,EDIT.snapshot(root/n))for n in names],[(n,EDIT.snapshot(plan/n))for n in ('profile.json','profile.sha256')])
    def fixture(label,count,mode='approve',on_pending=None):
        root=suite.work/label;root.mkdir(mode=0o700);target=root/'result.txt';target.write_text(EDIT.OLD);target.chmod(0o600)
        names=['result.txt',*[f'created-{i}.txt'for i in range(1,count)]]
        plan=suite.work/(label+'-plan')
        words=['prepare','--home',suite.home,'--root',root,'--claude',suite.claude,'--private-sole-writer','--max-mutations',str(count),'--max-write-bytes',str(count*4096),'--out',plan,'--apply']
        for n in names:words+=['--read',n,'--replace'if n=='result.txt'else'--create',n]
        code,prepared=suite.cli(*words);require(code==0,'batch_prepare_failed');targets=prepared['profile']['targets'];proposals=[]
        for i,t in enumerate(targets):
            payload={'path':t['name'],'content':EDIT.NEW}
            if t.get('replacement'):payload.update(old_identity=t['replacement']['identity'],old_sha256=t['replacement']['sha256'])
            proposals.append((('replace'if t.get('replacement')else'create')+f'_output_{i}',payload))
        for i,t in enumerate(targets):proposals.append((f'read_output_{i}',{'path':t['name']}))
        if on_pending is not None:on_pending.prepared=prepared;on_pending.plan=plan;on_pending.root=root;on_pending.names=names
        native,seen,_=suite.host(label,root,target,plan,prepared,proposals,mode=mode,timeout=90,on_pending=on_pending)
        if mode=='approve':
            require(native['exit']==0 and native['write_admissions']==count and native['process_cleanup']['all_stopped'],'batch_host_failed')
            for i,t in enumerate(targets):require(not seen.get(f'toolu_edit_{count+i}',{}).get('is_error',True) and EDIT.NEW.strip() in json.dumps(seen[f'toolu_edit_{count+i}']['content']) and (root/t['name']).read_text()==EDIT.NEW,'genuine_readback_failed')
        return root,plan,prepared,suite.last_run,names
    def invoke(data,action,words,extra=(),fault=None,target=None,journal=None):
        before=source_witness(data);e=dict(env)
        if fault:e.update(LD_PRELOAD=str(args.fault),SOU196_FAULT=fault,SOU196_TARGET_ROOT=str(target),SOU196_DONE=str(journal/'apply-00-done.json'))
        v=subprocess.run([str(suite.binary),'edit-session','batch',action,*map(str,words),*map(str,extra)],cwd=suite.work,env=e,stdin=subprocess.DEVNULL,capture_output=True,timeout=20)
        require(len(v.stdout)<=128*1024 and len(v.stderr)<=8192 and not trap.requests,'operator_bound_or_provider_request')
        values=[json.loads(line)for line in v.stdout.splitlines()];value=values[-1]if values else None
        require(before==source_witness(data),'operator_changed_source')
        for canary in (EDIT.NEW.encode().strip(),suite.secret_canary.encode()):require(canary not in v.stdout+v.stderr,'operator_private_content_leak')
        suite.active.setdefault('calls',[]).append({'exit_code':v.returncode,'status':value.get('status')if value else None,'stdout_sha256':sha(v.stdout),'stderr_bytes':len(v.stderr)})
        proofs=[x['proof']for x in values if x.get('status')=='member_completed']
        if value and 'proofs'in value:proofs=value['proofs']
        return v.returncode,value,proofs,v.stderr
    def project(data):
        nonlocal counter;counter+=1
        root=suite.work/f'owned-project-{counter}';root.mkdir(mode=0o700)
        maps=[]
        for i,n in enumerate(data[4]):
            target=f'target-{i}.txt';(root/target).write_text(f'Owned preimage {i}.\n');(root/target).chmod(0o600);maps.append(f'{n}={target}')
        (root/'sibling.txt').write_text('Unrelated owned sibling.\n');(root/'sibling.txt').chmod(0o600)
        journal=journals/f'batch-{counter}'
        words=['--run',data[3],'--plan',data[1],'--sha256',data[2]['profile_sha256'],'--root',root,'--journal',journal]
        for m in maps:words+=['--map',m]
        return root,journal,words
    def preview(data,words):
        code,v,_,_=invoke(data,'preview',words);require(code==0 and v['status']=='preview'and v['executed']is False,'batch_preview_failed');return v['confirmation_sha256']
    consent=['--private-sole-writer','--consent-private-backup']
    def apply(data,words,hash,flags=consent,**kw):return invoke(data,'apply',words,['--confirm',hash,*flags],**kw)
    def retained(j,h,proofs):
        words=['--journal',j,'--expect-plan',h]
        for p in proofs:words+=['--proof',p]
        return words
    def restore(data,j,h,proofs,partial=False):
        words=retained(j,h,proofs);a='recover'if partial else'revert';code,v,_,_=invoke(data,a+'-preview',words)
        require(code==0 and v['confirmation_sha256'],'restore_preview_failed')
        code,v,more,_=invoke(data,a,words,['--confirm',v['confirmation_sha256'],'--private-sole-writer'])
        require(code==0,'restore_failed');return v,more
    try:
        for case,count in [('genuine-two-file-flow',2),('genuine-eight-file-flow',8)]:
            begin(case);data=fixture(case,count);completed.append(data)
            code,review=suite.cli('review','--run',data[3],'--sha256',data[2]['profile_sha256']);require(code==0 and review['status']=='reviewed','review_failed')
            root,j,words=project(data);h=preview(data,words);old=tree(root)
            code,v,proofs,_=apply(data,words,h);require(code==0 and v['status']=='applied' and len(proofs)==count and all((root/f'target-{i}.txt').read_text()==EDIT.NEW for i in range(count)),'batch_apply_failed')
            v,_=restore(data,j,h,proofs);require(v['status']=='reverted'and all((root/f'target-{i}.txt').read_text()==f'Owned preimage {i}.\n'for i in range(count)),'batch_revert_failed')
            require(EDIT.snapshot(suite.sentinel)==sentinel and (root/'sibling.txt').read_text()=='Unrelated owned sibling.\n','positive_sibling_changed')
            done(case,genuine_host_readback=True,apply_readback=True,revert_readback=True,reviewed=True,source_preserved=True)
        data=completed[-1]
        begin('preview-no-writes');root,j,words=project(data);before=tree(root),tree(journals);preview(data,words);require(before==(tree(root),tree(journals)),'preview_wrote');done('preview-no-writes',preserved=True)
        begin('no-consent')
        for flags in ([],consent[:1],consent[1:]):
            root,j,words=project(data);h=preview(data,words);before=tree(root);code,_,_,_=apply(data,words,h,flags);require(code==1 and before==tree(root)and not j.exists(),'no_consent_not_refused')
        done('no-consent',preserved=True)
        for case in ('changed-last-output','changed-last-target','duplicate-output','duplicate-target','missing-last-target','linked-last-target','hardlinked-last-target','special-last-target','redirected-parent','protected-root','stale-confirmation'):
            begin(case);root,j,words=project(data);h=preview(data,words);context=contextlib.nullcontext();target=root/'target-7.txt';extra=None
            if case=='changed-last-output':context=changed(data[0]/data[4][-1],holding,'edit')
            elif case=='changed-last-target':context=changed(target,holding,'edit')
            elif case=='duplicate-output':words[-1]=f'{data[4][0]}=target-7.txt'
            elif case=='duplicate-target':words[-1]=f'{data[4][-1]}=target-0.txt'
            elif case=='missing-last-target':context=changed(target,holding,'missing')
            elif case=='linked-last-target':context=changed(target,holding,'symlink')
            elif case=='hardlinked-last-target':extra=holding/'hard';os.link(target,extra)
            elif case=='special-last-target':context=changed(target,holding,'fifo')
            elif case=='redirected-parent':
                held=root.with_name(root.name+'-held');root.rename(held);root.symlink_to(held)
            elif case=='protected-root':words[words.index('--root')+1]=data[0]
            elif case=='stale-confirmation':h='0'*64
            try:
                with context:
                    before=tree(root if not root.is_symlink()else held);code,_,_,_=apply(data,words,h);require(code==1 and before==tree(root if not root.is_symlink()else held)and not j.exists(),'preflight_refusal_failed')
            finally:
                if extra:extra.unlink()
            done(case,preserved=True)
        for case in ('duplicate-application','later-user-change','same-bytes-substitution','missing-applied-member','stale-recovery','without-returned-proof','corrupt-backup','unknown-journal'):
            begin(case);root,j,words=project(completed[0]);h=preview(completed[0],words);code,v,proofs,_=apply(completed[0],words,h);require(code==0 and v['status']=='applied','control_apply_failed')
            if case=='duplicate-application':
                before=tree(root);require(apply(completed[0],words,h)[0]==1 and tree(root)==before,'duplicate_apply_changed')
            elif case in ('later-user-change','same-bytes-substitution','missing-applied-member'):
                kind={'later-user-change':'edit','same-bytes-substitution':'same','missing-applied-member':'missing'}[case]
                with changed(root/'target-0.txt',holding,kind):
                    before=EDIT.snapshot(root/'target-0.txt');v,_=restore(completed[0],j,h,proofs,partial=True)
                    require(v['status']=='partial_or_uncertain' and EDIT.snapshot(root/'target-0.txt')==before and (root/'target-1.txt').read_text()=='Owned preimage 1.\n','safe_recovery_clobbered')
            elif case=='stale-recovery':
                retained_words=retained(j,h,proofs);code,v,_,_=invoke(completed[0],'revert-preview',retained_words);require(code==0,'stale_preview_failed')
                with changed(root/'target-1.txt',holding,'edit'):
                    before=tree(root);code,_,_,_=invoke(completed[0],'revert',retained_words,['--confirm',v['confirmation_sha256'],'--private-sole-writer']);require(code==1 and before==tree(root),'stale_restore_changed')
            elif case=='without-returned-proof':
                before=tree(root);code,v,_,_=invoke(completed[0],'status',retained(j,h,[]));require(code==0 and v['status']=='partial_or_uncertain','withheld_proof_promoted');require(invoke(completed[0],'recover-preview',retained(j,h,[]))[0]==1 and before==tree(root),'withheld_proof_restored')
            else:
                p=j/('images-01.bin'if case=='corrupt-backup'else'unknown.json');p.write_text('{}');p.chmod(0o600);before=tree(root)
                require(invoke(completed[0],'recover-preview',retained(j,h,proofs))[0]==1 and before==tree(root),'damaged_journal_mutated')
            done(case,preserved=True)
        begin('active-run');observed=[]
        def active(run,row):
            if observed:return
            live=(active.root,active.plan,active.prepared,run,active.names);root,j,words=project(live);before=tree(root)
            code,_,_,_=invoke(live,'preview',words);require(code==1 and before==tree(root)and not j.exists(),'active_not_refused');observed.append(True)
        cancelled=fixture('owned-cancelled',2,mode='cancel-pending',on_pending=active)
        require(observed and EDIT.snapshot(suite.sentinel)==sentinel,'active_control_missing');done('active-run',preserved=True)
        begin('cancelled-run');root,j,words=project(cancelled);before=tree(root);require(invoke(cancelled,'preview',words)[0]==1 and before==tree(root),'cancelled_not_refused');done('cancelled-run',preserved=True)
        begin('concurrent-application');root,j,words=project(completed[0]);h=preview(completed[0],words)
        command=[str(suite.binary),'edit-session','batch','apply',*map(str,words),'--confirm',h,*consent]
        with subprocess.Popen(command,cwd=suite.work,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)as a,subprocess.Popen(command,cwd=suite.work,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)as c:
            outs=[a.communicate(timeout=20),c.communicate(timeout=20)];codes=[a.returncode,c.returncode]
        require(sorted(codes)==[0,1] and sum(bool(o[0])and json.loads(o[0].splitlines()[-1]).get('status')=='applied'for o in outs)==1 and not trap.requests,'concurrent_winners')
        done('concurrent-application',exact_single_winner=True,preserved=True)
        for case in FAULTS:
            begin(case);root,j,words=project(completed[0]);h=preview(completed[0],words)
            code,v,proofs,err=apply(completed[0],words,h,fault=case,target=root,journal=j)
            require(b'sou196_owned_fault_observed'in err,'fault_not_observed')
            if case.endswith('kill')or case=='after-receipt-sync':require(code==-signal.SIGKILL,'actual_kill_missing')
            status_code,state,_,_=invoke(completed[0],'status',retained(j,h,proofs));require(status_code==0 and state['status'] not in ('applied','reverted'),'interruption_falsely_complete')
            if case.startswith('between-publications'):
                require(len(proofs)==1 and state['files'][0]['status']=='applied','completed_prefix_missing')
                # Second file is untouched or unproven, never automatically retried.
                v,_=restore(completed[0],j,h,proofs,partial=True)
                require(v['files'][0]['status']=='reverted'and(root/'target-0.txt').read_text()=='Owned preimage 0.\n','safe_prefix_restore_failed')
            else:
                before=tree(root);require(invoke(completed[0],'recover-preview',retained(j,h,proofs))[0]==1 and before==tree(root),'uncertain_effect_restored')
            require((root/'sibling.txt').read_text()=='Unrelated owned sibling.\n','fault_sibling_changed')
            done(case,fault_observed=True,truthful_partial=True,safe_recovery=True,preserved=True,fault_exit=code)
        require(EDIT.snapshot(suite.sentinel)==sentinel and not trap.requests,'final_preservation_failed')
        report.update(status='passed',operator_provider_requests=len(trap.requests),source_and_siblings_preserved=True,all_owned_stopped=True)
    finally:trap.close()

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');p.add_argument('--agentfw',type=Path);p.add_argument('--claude',type=Path);p.add_argument('--python',type=Path,default=Path('/usr/bin/python3.12'));p.add_argument('--fault',type=Path);p.add_argument('--output',type=Path);args=p.parse_args()
    if not args.run:print(json.dumps({'format':FORMAT,'executed':False,'expected':list(CASES)}));return 0
    require(args.output and args.output.is_absolute()and not args.output.exists(),'new_private_output_required');args.output.mkdir(mode=0o700)
    report={'format':FORMAT,'status':'incomplete','paid_inference':False,'expected':list(CASES),'cases':[{'id':n,'attempted':False,'status':'incomplete'}for n in CASES]}
    try:qualify(args,report)
    except Exception as error:
        code=EDIT.failure_code(error);report.update(status='failed',failure=code,failure_type=type(error).__name__)
        row=next((r for r in report['cases']if r['attempted']and r['status']=='incomplete'),None)
        if row:row.update(status='failed',failure=code)
    report['inventory']={s:sum(r['status']==s for r in report['cases'])for s in ('passed','failed','incomplete')}
    (args.output/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'format':FORMAT,'status':report['status'],'inventory':report['inventory']}));return 0 if passed(report)else 1
if __name__=='__main__':raise SystemExit(main())
