# SPDX-License-Identifier: Apache-2.0
"""Owned installed project-preset qualification, called by the installed driver."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import threading

CASES = ('two-explicit-presets','inert-check','stale-workspace','changed-selection',
         'changed-profile','changed-budget','changed-last-input','budget-no-fallback','provider-rotation','stale-update','damaged-store',
         'concurrent-update','two-protected-reads','frozen-running-settings',
         'stop-one-sibling-continues','private-catalog','owned-cleanup')


def qualify(args, door, home, env, report, first, installed, receiver):
    q, base, require = installed.QUAL, installed.BASE, installed.require
    presets = installed.load('qualification_project_presets','pilot_project_presets.py')
    profiles = installed.load('qualification_project_providers','pilot_provider_profiles.py')
    env = {k:v for k,v in env.items() if k not in profiles.PROVIDER.KEYS}
    rows = [{'id':n,'status':'incomplete','attempted':False}for n in CASES]
    evidence = {'format':'sw-installed-project-presets-qualification/1','status':'incomplete',
                'source':base.source(),'expected':list(CASES),'cases':rows}
    report['project_presets'] = evidence
    def begin(n): rows[CASES.index(n)]['attempted']=True
    def finish(n,**facts):rows[CASES.index(n)].update(status='passed',**facts)
    def call(words, expected=0, trace=None):
        command=[str(args.agentfw),'pilot','--home',str(home),'project',*map(str,words)]
        if trace is not None:
            command=[str(args.strace),'-f','-qq','-s','256','-e','trace=execve,connect','-o',str(trace),*command]
        result=subprocess.run(command,cwd=door.cwd,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=180)
        require(result.returncode==expected,'project_cli_exit')
        require(len(result.stdout)<=65536 and len(result.stderr)<=16384,'project_cli_output_bound')
        require(all(c.encode()not in result.stdout+result.stderr for c in canaries),'project_public_output_canary')
        return json.loads(result.stdout.splitlines()[-1])
    models=[base.DEMO.ScriptedModel([]),base.DEMO.ScriptedModel([])]
    canaries=['SOU197-OWNED-PROVIDER-A-318f','SOU197-OWNED-PROVIDER-B-9e21']
    processes=[]; witnesses=[]; streams=[]; release=threading.Event()
    try:
        second=argparse.Namespace(**vars(args));second.project=args.output/'second-project';second.repository=args.output/'second-repository';second.prefix=args.other_prefix
        q.make_projects(second,q.qualification_environment(args.output/'home'),receiver)
        texts=['Owned project A read witness.\n','Owned project B read witness.\n']
        for p,text in zip((args.project,second.project),texts):(p/'README.md').write_text(text)
        other=type(door)(second,env,door.cwd,home)
        code,prepared,_=other.call('prepare','--apply',timeout=3600)
        require(code==0 and prepared['status']=='prepared-not-active','second_project_prepare_failed')
        selections=[first,Path(prepared['selection'])];states=[];bindings=[];versions=[]
        baseline=[q.snapshot(p)for p in (args.project,args.repository,second.project,second.repository)]
        begin('two-explicit-presets')
        for i,name in enumerate(('one','two')):
            state=args.output/('project-state-'+str(i));state.mkdir(mode=0o700);states.append(state)
            with profiles.Store(home,create=True)as provider:
                provider.create(name,{'model':'owned-initial','ANTHROPIC_BASE_URL':models[i].url}, {'ANTHROPIC_API_KEY':canaries[i]})
                index=provider.index()
                current='legacy' if index is None else index['profiles'][name]['current']
                provider.update(name,{'model':'claude-sonnet-4-20250514'},None,current)
                versions.append(provider.index()['profiles'][name]['current'])
            words=['--name',name,'--selection',selections[i],'--provider-name',name,'--provider-version',versions[i],'--state-root',state]
            bindings.append(words)
            call(['create',*words,'--apply'])
        finish('two-explicit-presets')
        begin('inert-check');before=q.snapshot(home);trace=args.output/'project-check.trace.private'
        checked=call(['check','--name','one'],trace=trace)
        observed=q.executed(trace,{k:getattr(args,k)for k in q.SELECTED_PROGRAMS if getattr(args,k,None)is not None and k!='agentfw'})
        require(not observed['selected_started']and observed['inet_connects']==0 and checked['observed_protection']=='not-observed'
                and installed.agent_executions(trace,args.agentfw)==1,'project_check_executed')
        require(before==q.snapshot(home),'project_check_mutated')
        finish('inert-check',selected_started=0,network_connections=0)
        begin('stale-workspace');held=args.project.with_name('project-held');args.project.rename(held);args.project.mkdir(mode=0o700)
        try:call(['check','--name','one'],2)
        finally:args.project.rmdir();held.rename(args.project)
        finish('stale-workspace')
        for case,path in [('changed-selection',selections[0]),('changed-profile',selections[0].parent/'filesystem-profile/profile.json')]:
            begin(case);raw=path.read_bytes();mode=path.stat().st_mode&0o777;path.chmod(0o600);path.write_bytes(raw+b' ')
            try:call(['check','--name','one'],2)
            finally:path.write_bytes(raw);path.chmod(mode)
            finish(case)
        budget=args.output/'selected-project-budget.json'
        raw_budget=presets.encoded({'format':'sw-mcp/linux-cgroup-budget/1',
            'delegationRoot':str(args.output/'unavailable-delegation'),'memoryMaxBytes':268435456,
            'pidsMax':64,'cpuQuotaMicros':100000,'wallMillis':30000})
        budget.write_bytes(raw_budget);budget.chmod(0o600)
        budget_words=list(bindings[0]);budget_words[1]='budgeted';budget_words+=['--linux-budget',budget]
        call(['create',*budget_words,'--apply'])
        checked_budget=call(['check','--name','budgeted'])
        require(checked_budget['resource_budget']=='selected-not-validated','project_budget_claimed_enforcement')
        begin('changed-budget');budget.write_bytes(raw_budget.replace(b'30000',b'31000'))
        call(['check','--name','budgeted'],2);finish('changed-budget')
        begin('changed-last-input');trace=args.output/'project-last-input.trace.private'
        call(['run','--name','budgeted','--expected-version',checked_budget['digest'],'--apply'],2,trace)
        observed=q.executed(trace,{k:getattr(args,k)for k in q.SELECTED_PROGRAMS if getattr(args,k,None)is not None and k!='agentfw'})
        require(not observed['selected_started']and observed['inet_connects']==0
                and installed.agent_executions(trace,args.agentfw)==1,'project_stale_check_granted_execution')
        finish('changed-last-input',selected_started=0)
        budget.write_bytes(raw_budget)
        begin('budget-no-fallback');trace=args.output/'project-budget-refusal.trace.private'
        call(['run','--name','budgeted','--expected-version',checked_budget['digest'],'--apply'],2,trace)
        observed=q.executed(trace,{k:getattr(args,k)for k in q.SELECTED_PROGRAMS if getattr(args,k,None)is not None and k!='agentfw'})
        require(not observed['selected_started']and observed['inet_connects']==0,'project_budget_downgraded')
        call(['remove','--name','budgeted','--expected-version',checked_budget['digest'],'--apply'])
        finish('budget-no-fallback',host_started=False)
        begin('provider-rotation')
        with profiles.Store(home)as provider:
            provider.update('one',{'model':'owned-rotated'},None,versions[0]);new=provider.index()['profiles']['one']['current']
        call(['check','--name','one'],2)
        with profiles.Store(home)as provider:provider.restore('one',versions[0],new)
        finish('provider-rotation')
        begin('stale-update');call(['update',*bindings[0],'--expected-version','0'*64,'--apply'],2);finish('stale-update')
        begin('damaged-store');catalog=home/presets.DIRECTORY/'catalog.json';raw=catalog.read_bytes();catalog.write_bytes(b'{}')
        try:call(['inspect'],2)
        finally:catalog.write_bytes(raw)
        finish('damaged-store')
        begin('concurrent-update');old=call(['check','--name','one'])['digest']
        command=[str(args.agentfw),'pilot','--home',str(home),'project','update',*map(str,bindings[0]),'--expected-version',old,'--apply']
        contenders=[subprocess.Popen(command,cwd=door.cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)for _ in range(2)]
        results=[(p.communicate(timeout=180),p.wait())for p in contenders];require(sorted(r[1]for r in results)==[0,2],'project_concurrent_update_not_cas')
        finish('concurrent-update',one_writer=True)
        ready=[threading.Event(),threading.Event()];continued=threading.Event();received=[{},{}]
        def responder(i):
            def next_step(body):
                if not any(t.get('name')=='mcp__filesystem__read_text_file'for t in body.get('tools',[])):
                    return [{'type':'text','text':'Owned auxiliary.'}]
                for message in body.get('messages',[]):
                    for block in message.get('content',[])if isinstance(message.get('content'),list)else[]:
                        if isinstance(block,dict)and block.get('type')=='tool_result':received[i][block['tool_use_id']]=block
                first_id='toolu_project_'+str(i)+'_read'
                if first_id not in received[i]:return [{'type':'tool_use','id':first_id,'name':'mcp__filesystem__read_text_file','input':{'path':'/workspace/README.md'}}]
                require(texts[i].strip()in json.dumps(received[i][first_id]),'project_readback_missing')
                require(texts[1-i].strip()not in json.dumps(received[i]),'project_cross_read')
                ready[i].set();require(release.wait(120),'project_release_deadline')
                if i==1 and 'toolu_project_1_later'not in received[i]:return [{'type':'tool_use','id':'toolu_project_1_later','name':'mcp__filesystem__read_text_file','input':{'path':'/workspace/README.md'}}]
                if i==1:continued.set()
                return [{'type':'text','text':'Owned project read completed.'}]
            return next_step
        begin('two-protected-reads')
        for i,name in enumerate(('one','two')):
            models[i].next=responder(i);version=call(['check','--name',name])['digest']
            out=(args.output/('project-'+str(i)+'.out.private')).open('wb');err=(args.output/('project-'+str(i)+'.err.private')).open('wb');streams.extend((out,err))
            command=[str(args.strace),'-f','-qq','-v','-s','131072','-e','trace=execve,execveat','-o',str(args.output/('project-'+str(i)+'.trace.private')),
                     str(args.agentfw),'pilot','--home',str(home),'project','run','--name',name,'--expected-version',version,'--apply','--timeout-seconds','180']
            process=subprocess.Popen(command,cwd=door.cwd,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True);processes.append(process);witnesses.append(base.ProcessWitness(process.pid))
        require(all(event.wait(150)for event in ready),'project_concurrent_reads_missing');finish('two-protected-reads',independent_readback=True)
        begin('frozen-running-settings');files=[]
        for state in states:
            runs=list(state.glob('soup-wall-run-*'));require(len(runs)==1,'project_run_state_isolation')
            files.extend(p for p in runs[0].rglob('*')if p.is_file()and p.name in ('config.yaml','settings.json','host-settings.json','mcp.json'))
        frozen={str(p):base.sha(p)for p in files};require(files,'project_frozen_settings_missing')
        call(['remove','--name','one','--expected-version',call(['check','--name','one'])['digest'],'--apply'])
        require(frozen=={str(p):base.sha(p)for p in files},'project_running_settings_changed');finish('frozen-running-settings')
        begin('stop-one-sibling-continues');os.killpg(processes[0].pid,signal.SIGINT);processes[0].wait(timeout=45)
        require(processes[1].poll()is None,'project_sibling_stopped');release.set();processes[1].wait(timeout=120)
        require(processes[1].returncode==0 and continued.is_set(),'project_sibling_not_continued');finish('stop-one-sibling-continues',later_readback=True)
        begin('private-catalog');require(all(c.encode()not in catalog.read_bytes()for c in canaries),'project_catalog_contains_provider_input')
        for i in range(2):
            public=(args.output/('project-'+str(i)+'.out.private')).read_bytes()+(args.output/('project-'+str(i)+'.err.private')).read_bytes()
            require(all(c.encode()not in public for c in canaries),'project_run_output_canary')
            trace_raw=(args.output/('project-'+str(i)+'.trace.private')).read_bytes()
            require(canaries[1-i].encode()not in trace_raw,'project_provider_cross_contamination')
            installed.provider_exec_witness(args.output/('project-'+str(i)+'.trace.private'),args.claude,canaries[i],models[i].url)
        finish('private-catalog',credential_exec_witness=True)
        begin('owned-cleanup');cleanup=[w.finish()for w in witnesses];require(all(w['all_stopped']and w['descendant_count']>=3 for w in cleanup),'project_cleanup_unconfirmed')
        require(baseline==[q.snapshot(p)for p in (args.project,args.repository,second.project,second.repository)],'project_source_changed')
        require(receiver.count==0 and not(args.output/'forbidden-effect').exists(),'project_unapproved_receiver_effect')
        finish('owned-cleanup',all_stopped=True,sources_preserved=True,receiver_effects=0)
        evidence.update(status='passed',source_after=base.source());require(evidence['source_after']==evidence['source'],'project_source_identity_changed')
        require([r['id']for r in rows]==list(CASES)and all(r['attempted']and r['status']=='passed'for r in rows),'project_case_inventory_incomplete')
        report['cases'].extend({'case':r['id'],'passed':True}for r in rows)
    finally:
        release.set()
        for process in processes:
            if process.poll()is None:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=10)
        for witness in witnesses:witness.finish()
        for stream in streams:stream.close()
        for model in models:model.close()
