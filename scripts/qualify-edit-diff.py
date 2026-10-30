#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in installed, consented diff qualification. Default starts no process."""
from __future__ import annotations
import argparse
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('diff_review',ROOT/'scripts/qualify-edit-review.py')
REVIEW=importlib.util.module_from_spec(spec);spec.loader.exec_module(REVIEW)
EDIT=REVIEW.EDIT
require,sha=EDIT.require,EDIT.sha
FORMAT='sw-installed-edit-diff-qualification/1'
CASES=('installed-closure','execution-observer-control','genuine-two-file-diff','genuine-eight-file-diff',
       'default-summary-no-content','create-view','replacement-view','missing-baseline-view','unchanged-view',
       'empty-current','empty-created','crlf-change','missing-final-newline','terminal-content-and-labels',
       'spaces-unicode-paths','invalid-utf8-refused','binary-refused','oversize-refused','display-cap-refused',
       'genuine-dense-run','work-cap-refused','repeated-unchanged','output-consent-required','baseline-consent-required',
       'duplicate-output-refused','undeclared-output-refused','duplicate-baseline-refused','unselected-baseline-refused',
       'mismatched-baseline-refused','scope-overlap-refused','symlink-baseline-refused','hardlink-baseline-refused','foreign-baseline-refused',
       'fifo-baseline-refused','symlink-parent-refused','active-run-refused','cancelled-run-refused',
       'output-substitution-refused','baseline-substitution-refused','baseline-parent-substitution-refused',
       'late-last-output-change-refused','export-mode-conflict-refused')
RACES={'output-substitution-refused':'output-substitution','baseline-substitution-refused':'baseline-substitution',
       'baseline-parent-substitution-refused':'baseline-parent','late-last-output-change-refused':'late-output-change'}
SETUP={'installed-closure','execution-observer-control','genuine-dense-run'}


def expected_exit(name):
    return 2 if name=='export-mode-conflict-refused' else 1 if name.endswith(('-refused','-required')) else 0


def digest(value,size):
    return isinstance(value,str) and len(value)==size and all(c in '0123456789abcdef'for c in value)


def passed_report(report):
    if not isinstance(report,dict):return False
    rows=report.get('cases',[])
    if not isinstance(rows,list)or not all(isinstance(r,dict)for r in rows):return False
    by={r.get('id'):r for r in rows}
    if any('calls'in r and(not isinstance(r['calls'],list)or not all(isinstance(c,dict)for c in r['calls']))for r in rows):return False
    return (report.get('format')==FORMAT and report.get('status')=='passed' and report.get('paid_inference')is False
        and report.get('expected')==list(CASES) and [r.get('id')for r in rows]==list(CASES)
        and all(r.get('attempted')is True and r.get('status')=='passed'for r in rows)
        and all(digest(report.get(k),size)for k,size in [('source_commit',40),('source_tree',40),('component',64),('agentfw_sha256',64)])
        and report.get('claude_sha256')==EDIT.CLAUDE
        and all(by.get(n,{}).get('genuine_readback')is True for n in ('genuine-two-file-diff','genuine-eight-file-diff','genuine-dense-run'))
        and by.get('execution-observer-control',{}).get('observer_captured_attempt')is True
        and all(r.get('calls') and r.get('preserved')is True for r in rows if r['id']not in SETUP)
        and all(type(c.get('exit'))is int and c['exit']==expected_exit(r['id']) and c.get('observer_loaded')is True
                and type(c.get('exec_attempts'))is int and c['exec_attempts']==0 for r in rows for c in r.get('calls',[]))
        and all(by.get(n,{}).get('fault_observed')is True and by[n].get('outside_not_read')is True
                and by[n].get('controlled_fixture_restored')is True for n in RACES)
        and type(report.get('provider_requests_during_diff'))is int and report['provider_requests_during_diff']==0
        and type(report.get('process_exec_attempts_during_diff'))is int and report['process_exec_attempts_during_diff']==0
        and report.get('sentinel_preserved')is True and report.get('all_owned_stopped')is True)


def witness(path):
    try: m=path.lstat()
    except FileNotFoundError: return {'exists':False}
    value={'exists':True,'device':m.st_dev,'inode':m.st_ino,'mode':m.st_mode,'uid':m.st_uid,'gid':m.st_gid,
           'links':m.st_nlink,'bytes':m.st_size,'mtime_ns':m.st_mtime_ns,'ctime_ns':m.st_ctime_ns}
    if stat.S_ISREG(m.st_mode)and m.st_uid==os.geteuid():
        require(m.st_size<=128*1024,'diff_witness_cap');value['sha256']=sha(path.read_bytes())
    return value


def delivered_text(value,text):
    """Decode bounded native result wrappers; do not match escaped JSON bytes."""
    if not text.strip():return False
    stack=[(value,0)];visited=0
    while stack:
        node,depth=stack.pop();visited+=1
        require(visited<=128,'readback_wrapper_cap')
        if isinstance(node,dict):stack.extend((v,depth)for v in node.values())
        elif isinstance(node,list):stack.extend((v,depth)for v in node)
        elif isinstance(node,str):
            if text.strip()in node:return True
            if depth<4 and len(node)<=32*1024:
                try:decoded=json.loads(node)
                except ValueError:continue
                stack.append((decoded,depth+1))
    return False


def qualify(args,report):
    require(platform.system()=='Linux'and platform.machine()=='x86_64'and os.geteuid()!=0,'native_linux_operator_required')
    require(sha(args.claude.read_bytes())==EDIT.CLAUDE and not args.output.is_relative_to(ROOT),'genuine_installed_host_required')
    report['cases'][0]['attempted']=True;suite=EDIT.Suite(args,report)
    suite.before_sentinel_full=witness(suite.sentinel)
    state_path=suite.state.with_name('run state ü');suite.state.rename(state_path);suite.state=state_path
    archive=args.output/'component.tar'
    built_result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/build-pilot-front-door.py'),'--out',str(archive)],
        cwd=ROOT,env=suite.env,capture_output=True,timeout=60)
    require(built_result.returncode==0,'component_build_failed');built=json.loads(built_result.stdout.splitlines()[-1])
    install=subprocess.run([str(suite.binary),'pilot-component','--home',str(suite.home),'install',str(archive),
        '--sha256',built['archive_sha256'],'--python',str(args.python)],cwd=suite.work,env=suite.env,capture_output=True,timeout=60)
    require(install.returncode==0,'component_install_failed')
    report.update(source_commit=built['commit'],source_tree=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip(),
        component=built['component'],agentfw_sha256=sha(suite.binary.read_bytes()),claude_sha256=sha(suite.claude.read_bytes()))
    fixtures=[];call_number=0

    def begin(name):
        row=report['cases'][CASES.index(name)];row['attempted']=True;suite.active=row;return row

    def finish(name,**facts): report['cases'][CASES.index(name)].update(status='passed',**facts)

    def observed_env(extra=None):
        nonlocal call_number
        call_number+=1;prefix=args.output/f'observer-{call_number}'
        env=dict(suite.env,PATH='/owned-no-external-tools',LD_PRELOAD=str(args.fault),
                 SOU189_LOAD_WITNESS=str(prefix.with_suffix('.loaded')),SOU189_EXEC_WITNESS=str(prefix.with_suffix('.exec')),
                 ANTHROPIC_BASE_URL=trap.url,ANTHROPIC_API_KEY='owned-diff-trap',HTTP_PROXY=trap.url,HTTPS_PROXY=trap.url)
        if extra: env.update(extra)
        return env,prefix

    def state(data):
        root,plan,prepared,run,names,baselines,host=data
        retained=(EDIT.private_state_witness(run,include_audit=False)if host is None
                  else REVIEW.selected_witness(suite,run,root/'result.txt',plan))
        return {'retained':retained,'outputs':{n:witness(root/n)for n in names},
                'plans':{n:witness(plan/n)for n in ('profile.json','profile.sha256')},
                'baselines':{n:witness(p)for n,p in baselines.items()}}

    def all_state(data,baselines):
        return {'selected':state(data),'siblings':[state(f)for f in fixtures if f is not data],
                'explicit_baselines':{sha(str(p).encode()):witness(p)for _,p in baselines},'sentinel':witness(suite.sentinel)}

    def invoke(data,selected=None,baselines=None,content=True,baseline_consent=True,extra=(),fault_env=None):
        selected=data[4]if selected is None else selected;baselines=list(data[5].items())if baselines is None else baselines
        before=all_state(data,baselines);env,prefix=observed_env(fault_env)
        words=[str(suite.binary),'edit-session','review','--run',str(data[3]),'--sha256',data[2]['profile_sha256']]
        for name in selected: words+=['--diff',name]
        for name,path in baselines: words+=['--diff-baseline',f'{name}={path}']
        if content: words+=['--consent-private-content']
        if baselines and baseline_consent: words+=['--consent-baseline-content']
        result=subprocess.run([*words,*map(str,extra)],cwd=suite.work,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
        require(len(result.stdout)<=128*1024 and len(result.stderr)<=16384,'diff_response_cap')
        require(suite.secret_canary.encode()not in result.stdout+result.stderr,'diff_prompt_leak')
        loaded=prefix.with_suffix('.loaded').read_bytes()==b'loaded';execs=int(prefix.with_suffix('.exec').exists())
        diagnostic={'exit':result.returncode,'observer_loaded':loaded,'exec_attempts':execs,
            'stdout_sha256':sha(result.stdout),'stderr_sha256':sha(result.stderr),'before':before,'after':all_state(data,baselines)}
        suite.active.setdefault('calls',[]).append(diagnostic)
        require(loaded and execs==0,'diff_external_process_attempt')
        value=json.loads(result.stdout)if result.stdout else None
        if result.returncode==0:
            require(value is not None,'diff_missing_response')
            flags=value if selected else value['observation']
            require(flags.get('executed')is False and flags.get('authority')is False,'diff_claimed_execution')
            if selected: require(value['complete']is True and value['exported']is False and len(value['summary'])==len(selected),'diff_incomplete_success')
        elif result.returncode==1:
            require(value and value['format']=='sw-installed-edit-diff/1'and value['complete']is False and value['display']==[],'diff_refusal_not_explicit')
            diagnostic['reason']=value.get('reason')
        else: require(result.returncode==2 and value is None,'unexpected_parser_response')
        return result.returncode,value,result.stdout,diagnostic

    def checked(name,data=None,selected=None,baselines=None,check=None,**options):
        begin(name);data=fixtures[1]if data is None else data
        code,value,raw,diagnostic=invoke(data,selected,baselines,**options)
        require(code==expected_exit(name),'unexpected_diff_exit_'+name)
        require(diagnostic['before']==diagnostic['after'],'diff_mutated_inputs_'+name)
        if check: check(value,raw)
        finish(name,preserved=True,comparison_sha256=value.get('comparison_sha256')if value else None)
        return value

    def fixture(label,count,old=EDIT.OLD,new=EDIT.NEW,mode='approve',pending=None):
        root=suite.work/label;root.mkdir(mode=0o700);plan=suite.work/(label+' plan')
        base=args.output/(label+' baselines ü');base.mkdir(mode=0o700)
        names=['result.txt']+[('replace-'if i%2==0 else'created-')+str(i)+'.txt'for i in range(1,count)]
        baselines={};words=['prepare','--home',suite.home,'--root',root,'--claude',suite.claude,'--private-sole-writer',
            '--max-mutations',str(count),'--max-write-bytes',str(count*4096),'--out',plan,'--apply']
        for i,name in enumerate(names):
            replacing=(i%2==0)
            if replacing:
                (root/name).write_text(old);(root/name).chmod(0o600)
                copy=base/('old \u202e\x1b[31m space '+str(i)+'.txt');copy.write_text(old);copy.chmod(0o600);baselines[name]=copy
            words+=['--read',name,'--replace'if replacing else'--create',name]
        code,prepared=suite.cli(*words);require(code==0,'diff_prepare_failed')
        targets=prepared['profile']['targets'];proposals=[]
        for i,target in enumerate(targets):
            payload={'path':target['name'],'content':new}
            if target.get('replacement'):payload.update(old_identity=target['replacement']['identity'],old_sha256=target['replacement']['sha256'])
            proposals.append((('replace'if target.get('replacement')else'create')+f'_output_{i}',payload))
        for i,target in enumerate(targets):proposals.append((f'read_output_{i}',{'path':target['name']}))
        if pending: pending.prepared=prepared;pending.baselines=baselines
        host,observed,_=suite.host(label,root,root/'result.txt',plan,prepared,proposals,mode=mode,timeout=90,on_pending=pending)
        require(host['process_cleanup']['all_stopped'],'diff_owned_cleanup_failed')
        if mode=='approve':
            require(host['exit']==0 and host['write_admissions']==count,'diff_genuine_run_failed')
            for offset,target in enumerate(targets,start=count):
                value=observed.get(f'toolu_edit_{offset}',{})
                require(not value.get('is_error',True)and delivered_text(value.get('content'),new)
                    and (root/target['name']).read_bytes()==new.encode(),'diff_genuine_readback_failed')
        data=(root,plan,prepared,suite.last_run,sorted(names),baselines,host);fixtures.append(data)
        return data

    finish('installed-closure',installed_outside_checkout=True)
    trap=EDIT.HOST.ScriptedModel([])
    try:
        begin('execution-observer-control');env,prefix=observed_env({'SOU189_OBSERVER_PROBE':'1'})
        probe=subprocess.run(['/usr/bin/true'],env=env,capture_output=True,timeout=10)
        require(probe.returncode==0 and prefix.with_suffix('.exec').read_bytes()==b'exec-attempt'
            and prefix.with_suffix('.loaded').read_bytes()==b'loaded','diff_exec_observer_not_active')
        finish('execution-observer-control',observer_captured_attempt=True)
        for name,count in [('genuine-two-file-diff',2),('genuine-eight-file-diff',8)]:
            begin(name);data=fixture('two files ü'if count==2 else'eight files ü',count)
            code,value,raw,diagnostic=invoke(data)
            require(code==0 and diagnostic['before']==diagnostic['after']and len(value['display'])==count,'diff_genuine_view_failed')
            finish(name,genuine_readback=True,preserved=True,compared_files=count,host=data[6],comparison_sha256=value['comparison_sha256'])
        data=fixtures[1];root,plan,prepared,run,names,bases,_=data
        primary='result.txt';created=next(n for n in names if n.startswith('created-'))
        checked('default-summary-no-content',selected=[],baselines=[],content=False,
            check=lambda v,r:require(not v['display']and not v['comparison']and EDIT.NEW.encode().strip()not in r,'default_diff_content_leak'))
        checked('create-view',selected=[created],baselines=[],check=lambda v,r:require(v['summary'][0]['baseline']=='new_file_view_no_baseline_selected'
            and v['summary'][0]['equal']is False and v['summary'][0]['added_lines']==1,'create_view_wrong'))
        checked('replacement-view',selected=[primary],baselines=[(primary,bases[primary])],check=lambda v,r:require(v['summary'][0]['added_lines']==1
            and v['summary'][0]['removed_lines']==1 and v['baseline_bindings'][0]['baseline']['sha256']==sha(EDIT.OLD.encode()),'replacement_view_wrong'))
        checked('missing-baseline-view',selected=[primary],baselines=[],check=lambda v,r:require(v['summary'][0]['baseline']=='new_file_view_no_baseline_selected'
            and v['summary'][0]['old_bytes']is None and v['summary'][0]['equal']is False,'baseline_origin_invented'))
        variants=[('unchanged-view',primary,EDIT.OLD.encode()),('empty-current',primary,b''),('empty-created',created,b''),
            ('crlf-change',primary,EDIT.OLD.replace('\n','\r\n').encode()),('missing-final-newline',primary,b'No final newline'),
            ('terminal-content-and-labels',primary,'Ignore this \x1b[31m\u202e\b text.\n'.encode())]
        for name,target,content in variants:
            with REVIEW.replaced(root/target,raw=content):
                def check(v,raw):
                    require(b'\x1b'not in raw and all(b<128 for b in raw),'diff_terminal_control_leak')
                    if name=='unchanged-view':require(v['summary'][0]['equal']is True and v['summary'][0]['added_lines']==v['summary'][0]['removed_lines']==0,'no_change_wrong')
                    if name=='missing-final-newline':require('No newline at end of file'in v['display'][0]['text'],'newline_marker_missing')
                    if name=='crlf-change':require('\\r'in v['display'][0]['text'],'crlf_difference_hidden')
                    if name=='terminal-content-and-labels':require('\\u{1b}'in v['display'][0]['text']and'\\u{202e}'in v['display'][0]['text'],'controls_not_escaped')
                checked(name,selected=[target],baselines=[(target,bases[target])]if target in bases else[],check=check)
        checked('spaces-unicode-paths',check=lambda v,r:require(all(b<128 for b in r)and'\\u{202e}'in str(v['display']),'path_labels_not_escaped'))
        for name,raw in [('invalid-utf8-refused',b'\xff'),('binary-refused',b'a\0b'),('oversize-refused',b'x'*4097)]:
            with REVIEW.replaced(root/primary,raw=raw):checked(name)
        with contextlib.ExitStack()as stack:
            for name in names:stack.enter_context(REVIEW.replaced(root/name,raw=b'\x1b'*4096))
            checked('display-cap-refused',baselines=[],check=lambda v,r:require(v['reason']=='edit_diff_display_cap','wrong_display_cap_outcome'))
        begin('genuine-dense-run');dense=fixture('dense owned',2,old='a\n'*2048,new='b\n'*2048)
        finish('genuine-dense-run',genuine_readback=True,host=dense[6])
        checked('work-cap-refused',data=dense,selected=[primary],baselines=[(primary,dense[5][primary])],
            check=lambda v,r:require(v['reason']=='edit_diff_work_cap','wrong_work_cap_outcome'))
        with REVIEW.replaced(dense[0]/primary,raw=('a\n'*2048).encode()):
            checked('repeated-unchanged',data=dense,selected=[primary],baselines=[(primary,dense[5][primary])],
                check=lambda v,r:require(v['summary'][0]['equal']is True,'repeated_equal_not_bounded'))
        checked('output-consent-required',content=False)
        checked('baseline-consent-required',baseline_consent=False)
        checked('duplicate-output-refused',selected=[primary,primary],baselines=[(primary,bases[primary])])
        checked('undeclared-output-refused',selected=['../outside'],baselines=[])
        checked('duplicate-baseline-refused',baselines=[(primary,bases[primary]),(primary,bases[primary])])
        checked('unselected-baseline-refused',selected=[created])
        wrong=args.output/'wrong baseline';wrong.write_text('Wrong.');wrong.chmod(0o600)
        checked('mismatched-baseline-refused',baselines=[(primary,wrong)])
        with REVIEW.replaced(root/primary,raw=EDIT.OLD.encode()):
            checked('scope-overlap-refused',selected=[primary],baselines=[(primary,root/primary)],
                check=lambda v,r:require(v['reason']=='edit_diff_baseline_scope_overlap','wrong_overlap_outcome'))
        for name,options in [('symlink-baseline-refused',{'link':suite.sentinel}),('fifo-baseline-refused',{'fifo':True})]:
            with REVIEW.replaced(bases[primary],**options):checked(name)
        alias=args.output/'hard baseline alias';os.link(bases[primary],alias)
        try:checked('hardlink-baseline-refused')
        finally:alias.unlink()
        require(args.foreign and args.foreign.stat().st_uid!=os.geteuid(),'foreign_fixture_required')
        checked('foreign-baseline-refused',baselines=[(primary,args.foreign)])
        parent=bases[primary].parent;held=parent.with_name(parent.name+'.held');parent.rename(held);parent.symlink_to(held,target_is_directory=True)
        try:checked('symlink-parent-refused')
        finally:parent.unlink();held.rename(parent)
        begin('active-run-refused');seen=[]
        def pending(active,_):
            if seen:return
            live=(suite.work/'cancelled owned',suite.work/'cancelled owned plan',pending.prepared,active,
                ['created-1.txt','result.txt'],pending.baselines,None)
            code,value,raw,diagnostic=invoke(live)
            require(code==1 and diagnostic['before']==diagnostic['after'],'active_run_diff_accepted');seen.append(True)
        cancelled=fixture('cancelled owned',2,mode='cancel-pending',pending=pending)
        require(seen and cancelled[6]['terminal']['reason']=='cancelled','actual_cancellation_missing')
        finish('active-run-refused',preserved=True,actual_pending_run=True)
        checked('cancelled-run-refused',data=cancelled)
        for name,mode in RACES.items():
            begin(name);trigger=root/primary if mode=='output-substitution'else bases[primary]
            marker=args.output/(mode+'.fault');outside=args.output/(mode+'.outside')
            original=(root/primary).read_bytes();before_peer=[state(f)for f in fixtures if f is not data]
            before_outputs={n:witness(root/n)for n in names};before_baselines={n:witness(p)for n,p in bases.items()}
            extra={'SOU189_TRIGGER':str(trigger),'SOU189_MODE':mode,'SOU189_WITNESS':str(marker),
                   'SOU189_OUTSIDE':str(suite.sentinel),'SOU189_OUTSIDE_WITNESS':str(outside),
                   'SOU189_LAST_OUTPUT':str(root/primary),'SOU189_BASELINE_PARENT':str(parent)}
            code,value,raw,diagnostic=invoke(data,fault_env=extra)
            require(code==1 and marker.read_bytes()==(b'1'if mode=='output-substitution'else b'2')and not outside.exists(),'diff_race_not_observed_'+name)
            require(before_peer==[state(f)for f in fixtures if f is not data],'diff_race_changed_sibling')
            require(all(witness(root/n)==before_outputs[n]for n in names if n!=primary),'diff_race_changed_peer_output')
            if mode=='late-output-change':
                require((root/primary).read_bytes()==b'Changed during diff.\n'and before_baselines=={n:witness(p)for n,p in bases.items()},'late_output_fault_wrong')
                (root/primary).write_bytes(original)
            elif mode=='baseline-parent':
                require(not list(parent.iterdir())and all(witness(held/p.name)==before_baselines[n]for n,p in bases.items()),'baseline_parent_fixture_changed_bytes')
                parent.rmdir();held.rename(parent)
            else:
                require(trigger.is_symlink()and trigger.with_name(trigger.name+'.kept').is_file(),'substitution_not_actual')
                trigger.unlink();trigger.with_name(trigger.name+'.kept').rename(trigger)
            require((root/primary).read_bytes()==original and all(p.read_bytes()==EDIT.OLD.encode()for p in bases.values()),'fixture_bytes_not_restored')
            finish(name,preserved=True,fault_observed=True,outside_not_read=True,controlled_fixture_restored=True,
                   controlled_fixture_mutation=True,triggered_observation=int(marker.read_bytes()))
        checked('export-mode-conflict-refused',extra=['--export',args.output/'must-not-exist','--include',primary,
            '--expect-observation','0'*64])
        require(not(args.output/'must-not-exist').exists(),'diff_exported_content')
        require(not trap.requests and witness(suite.sentinel)==suite.before_sentinel_full,'diff_external_effect')
        report.update(status='passed',provider_requests_during_diff=len(trap.requests),process_exec_attempts_during_diff=0,
            sentinel_preserved=True,all_owned_stopped=True)
    finally:trap.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run',action='store_true')
    for name in ('agentfw','claude','python','fault','foreign','output'):parser.add_argument('--'+name,type=Path,default=Path('/usr/bin/python3.12')if name=='python'else None)
    args=parser.parse_args()
    if not args.run:print(json.dumps({'format':FORMAT,'executed':False,'expected':list(CASES)}));return 0
    require(args.output and args.output.is_absolute()and not args.output.exists(),'new_absolute_output_required');args.output.mkdir(mode=0o700)
    report={'format':FORMAT,'status':'incomplete','paid_inference':False,'expected':list(CASES),
        'cases':[{'id':n,'status':'incomplete','attempted':False}for n in CASES]}
    try:qualify(args,report)
    except Exception as error:
        code=EDIT.failure_code(error);report.update(status='failed',failure=code,failure_type=type(error).__name__)
        active=next((r for r in report['cases']if r['attempted']and r['status']=='incomplete'),None)
        if active is not None:active.update(status='failed',failure=code)
    report['inventory']={s:sum(r['status']==s for r in report['cases'])for s in ('passed','failed','incomplete')}
    raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();(args.output/'report.json').write_bytes(raw)
    summary={k:report[k]for k in ('format','status','inventory','failure','failure_type','source_commit','source_tree','component','agentfw_sha256','claude_sha256')if k in report}
    summary.update(evidence_sha256=sha(raw),case_results=[{'id':r['id'],'status':r['status'],'attempted':r['attempted'],
        'witnesses':{k:v for k,v in r.items()if type(v)is bool}}for r in report['cases']])
    print(json.dumps(summary,sort_keys=True));return 0 if passed_report(report)else 1


if __name__=='__main__':raise SystemExit(main())
