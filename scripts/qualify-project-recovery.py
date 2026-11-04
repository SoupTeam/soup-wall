# SPDX-License-Identifier: Apache-2.0
"""Installed declarative recovery controls, followed by the existing two-project runs."""
import json
import signal
import subprocess

CASES = ('private-export-consent', 'declarative-export', 'fresh-home-explicit-provider-inputs',
         'unresolved-preview-inert', 'stale-plan-refused', 'tampered-archive-refused',
         'changed-destination-catalog-refused', 'two-record-atomic-import',
         'duplicate-import-explicit', 'native-interruption-recovery', 'source-sibling-state-preserved')


def qualify(args, door, source_home, env, report, selections, states, versions, bindings, models, canaries, installed):
    require, base, q = installed.require, installed.BASE, installed.QUAL
    presets = installed.load('recovery_qualification_presets', 'pilot_project_presets.py')
    providers = installed.load('recovery_qualification_providers', 'pilot_provider_profiles.py')
    recovery = installed.load('recovery_qualification_format', 'pilot_project_recovery.py')
    rows = [{'id':name,'status':'incomplete','attempted':False}for name in CASES]
    evidence = {'format':'sw-installed-project-recovery-qualification/1','status':'incomplete',
                'source':base.source(),'expected':list(CASES),'cases':rows,'authority_restored':False}
    report['project_recovery'] = evidence
    home = args.output/'recovered-project-home'
    archive = args.output/'project-presets.tar'
    authority_canary = 'SOU230-OWNED-AUTHORITY-NEVER-EXPORTED'
    (source_home/'owned-authority-marker').write_text(authority_canary)
    source_catalog = (source_home/presets.DIRECTORY/'catalog.json').read_bytes()
    def begin(name):
        evidence['active_case']=name;rows[CASES.index(name)]['attempted']=True
    def finish(name,**facts):rows[CASES.index(name)].update(status='passed',**facts)
    def call(words, *, target=None, expected=0, trace=None):
        command=[str(args.agentfw),'pilot','--home',str(target or home),'project',*map(str,words)]
        if trace is not None:
            command=[str(args.strace),'-f','-qq','-s','256','-e','trace=execve,connect','-o',str(trace),*command]
        result=subprocess.run(command,cwd=door.cwd,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=180)
        require(len(result.stdout)<=65536 and len(result.stderr)<=16384,'project_recovery_output_bound')
        require(all(c.encode()not in result.stdout+result.stderr for c in [*canaries,authority_canary]),'project_recovery_output_canary')
        value=json.loads(result.stdout.splitlines()[-1])
        evidence['last_cli']={'action':words[0],'exit':result.returncode,'expected_exit':expected,
                              'status':value.get('status')}
        require(result.returncode==expected,'project_recovery_cli_exit')
        return value
    def fresh(target, label):
        target.mkdir(mode=0o700)
        command=[str(args.agentfw),'pilot-component','--home',str(target),'install',str(args.output/'component.tar'),
                 '--sha256',report['component']['archive_sha256'],'--python',str(args.component_python)]
        result=subprocess.run(command,cwd=door.cwd,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=180)
        require(result.returncode==0 and json.loads(result.stdout)['component']==report['component']['component'],
                'project_recovery_component_install_failed')
        specs={};new_versions=[];new_states=[];new_bindings=[]
        for i,name in enumerate(('one','two')):
            # Fresh explicit fixture credentials are supplied through the accepted
            # provider store, never read or restored from the project archive.
            with providers.Store(target,create=True)as provider:
                provider.create(name,{'model':'owned-initial','ANTHROPIC_BASE_URL':models[i].url},
                                {'ANTHROPIC_API_KEY':canaries[i]})
                index=provider.index();current='legacy'if index is None else index['profiles'][name]['current']
                provider.update(name,{'model':'claude-sonnet-4-20250514'},None,current)
                version=provider.index()['profiles'][name]['current'];new_versions.append(version)
            state=args.output/(label+'-state-'+name);state.mkdir(mode=0o700);new_states.append(state)
            specs[name]={'selection':str(selections[i]),'provider_name':name,'provider_version':version,
                         'state_root':str(state),'linux_budget':None,'budget_preset':None}
            new_bindings.append(['--name',name,'--selection',selections[i],'--provider-name',name,
                                 '--provider-version',version,'--state-root',state])
        path=args.output/(label+'-bindings.json')
        path.write_bytes(presets.encoded({'format':recovery.BINDINGS,'projects':specs}));path.chmod(0o600)
        return path,new_versions,new_states,new_bindings
    begin('private-export-consent')
    call(['export','--archive',archive],target=source_home,expected=2)
    require(not archive.exists(),'project_unconsented_export_created')
    finish('private-export-consent',published_archives=0)
    begin('declarative-export')
    exported=call(['export','--archive',archive,'--consent'],target=source_home)
    require(exported['status']=='exported'and exported['records']==2,'project_export_incomplete')
    require(all(c.encode()not in archive.read_bytes()for c in [*canaries,authority_canary]),'project_archive_contains_authority')
    finish('declarative-export',records=2,authority_or_credentials=False)
    begin('fresh-home-explicit-provider-inputs')
    binding_file,new_versions,new_states,new_bindings=fresh(home,'recovered')
    sentinel=home/'sibling-sentinel';sentinel.write_text('owned sibling must stay\n')
    preserved=q.snapshot(home)
    finish('fresh-home-explicit-provider-inputs',supplied_separately=True)
    begin('unresolved-preview-inert');trace=args.output/'project-import-preview.trace.private'
    unresolved=call(['import-preview','--archive',archive],trace=trace)
    require(not unresolved['ready']and not any(row['resolved']for row in unresolved['projects']), 'unresolved_project_became_usable')
    observed=q.executed(trace,{k:getattr(args,k)for k in q.SELECTED_PROGRAMS if getattr(args,k,None)is not None and k!='agentfw'})
    require(not observed['selected_started']and observed['inet_connects']==0
            and installed.agent_executions(trace,args.agentfw)==1 and q.snapshot(home)==preserved,'project_import_preview_had_effects')
    finish('unresolved-preview-inert',selected_started=0,network_connections=0,home_unchanged=True)
    common=['--archive',archive,'--bindings',binding_file]
    shown=call(['import-preview',*common]);require(shown['ready'],'project_import_binding_unresolved')
    begin('stale-plan-refused');call(['import',*common,'--confirm-plan','0'*64,'--apply'],expected=2)
    require(not(home/presets.DIRECTORY).exists(),'stale_project_plan_created_catalog')
    finish('stale-plan-refused',catalog_created=False)
    begin('tampered-archive-refused')
    bad=args.output/'tampered-project-presets.tar';raw=bytearray(archive.read_bytes());raw[1024]^=1;bad.write_bytes(raw);bad.chmod(0o600)
    call(['import','--archive',bad,'--bindings',binding_file,'--confirm-plan',shown['plan_sha256'],'--apply'],expected=2)
    require(not(home/presets.DIRECTORY).exists(),'tampered_project_archive_created_catalog')
    finish('tampered-archive-refused',catalog_created=False)
    begin('changed-destination-catalog-refused')
    kept=list(new_bindings[0]);kept[1]='kept';call(['create',*kept,'--apply'])
    old=(home/presets.DIRECTORY/'catalog.json').read_bytes()
    call(['import',*common,'--confirm-plan',shown['plan_sha256'],'--apply'],expected=2)
    require((home/presets.DIRECTORY/'catalog.json').read_bytes()==old,'stale_catalog_plan_mutated')
    finish('changed-destination-catalog-refused',existing_entry_preserved=True)
    begin('two-record-atomic-import')
    shown=call(['import-preview',*common]);require(shown['ready'],'fresh_project_plan_not_ready')
    result=call(['import',*common,'--confirm-plan',shown['plan_sha256'],'--apply'])
    require(result['status']=='imported'and not result['authority']and not result['executed'],'project_import_claimed_authority')
    current=json.loads((home/presets.DIRECTORY/'catalog.json').read_bytes())
    require(current['records']['kept']==json.loads(old)['records']['kept'],'project_import_overwrote_existing')
    source_records=json.loads(source_catalog)['records']
    require(all(current['records'][name]['version']!=source_records[name]['version']for name in ('one','two')),'project_import_reused_version')
    for name in ('one','two'):call(['check','--name',name])
    finish('two-record-atomic-import',records=2,fresh_versions=True,existing_entry_preserved=True)
    begin('duplicate-import-explicit');before=(home/presets.DIRECTORY/'catalog.json').read_bytes()
    duplicate=call(['import-preview',*common]);require(not duplicate['ready']and all(row['conflict']for row in duplicate['projects']),'duplicate_import_not_explicit')
    call(['import',*common,'--confirm-plan',duplicate['plan_sha256'],'--apply'],expected=2)
    require((home/presets.DIRECTORY/'catalog.json').read_bytes()==before,'duplicate_import_mutated')
    finish('duplicate-import-explicit',records_overwritten=0)
    begin('native-interruption-recovery')
    interrupted_home=args.output/'interrupted-project-home'
    interrupted_bindings,_,_,_=fresh(interrupted_home,'interrupted')
    common_interrupted=['--archive',archive,'--bindings',interrupted_bindings]
    plan=call(['import-preview',*common_interrupted],target=interrupted_home)
    trace=args.output/'project-import-interruption.trace.private'
    command=[str(args.strace),'-f','-qq','-s','256','-e','trace=execve,execveat,renameat',
             '-e','inject=renameat:signal=SIGKILL:when=1','-o',str(trace),
             str(args.agentfw),'pilot','--home',str(interrupted_home),'project','import',
             *map(str,common_interrupted),'--confirm-plan',plan['plan_sha256'],'--apply']
    process=subprocess.Popen(command,cwd=door.cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    witness=base.ProcessWitness(process.pid)
    try:
        out,err=process.communicate(timeout=180)
        require(len(out)<=65536 and len(err)<=16384,'project_interruption_output_bound')
        require(process.returncode in (-signal.SIGKILL,128+signal.SIGKILL),'project_import_not_interrupted')
        require(trace.stat().st_size<=256*1024 and b'.import-next-'in trace.read_bytes(),'project_import_interruption_not_calibrated')
        directory=interrupted_home/presets.DIRECTORY
        require(not(directory/'catalog.json').exists()and(directory/('.import-next-'+plan['plan_sha256'])).is_file(),
                'project_import_interruption_not_atomic')
        recovered=call(['import-recover',*common_interrupted,'--confirm-plan',plan['plan_sha256'],'--apply'],target=interrupted_home)
        require(recovered['status']=='imported'and recovered['recovered'],'project_import_recovery_failed')
        require(sorted(p.name for p in directory.iterdir())==['catalog.json'],'project_import_recovery_left_stage')
        for name in ('one','two'):call(['check','--name',name],target=interrupted_home)
        require(witness.finish()['all_stopped'],'project_interruption_process_remained')
        finish('native-interruption-recovery',initial_exit=process.returncode,
               initial_status='terminated_before_publication',recovered=True,owned_processes_stopped=True)
    finally:
        if process.poll()is None:process.kill();process.wait(timeout=10)
        witness.finish()
    begin('source-sibling-state-preserved')
    require((source_home/presets.DIRECTORY/'catalog.json').read_bytes()==source_catalog,'project_export_changed_source_catalog')
    require(sentinel.read_text()=='owned sibling must stay\n'and not(home/'owned-authority-marker').exists(),'project_import_changed_sibling_or_restored_authority')
    actual=q.snapshot(home)
    require(all(actual.get(name)==item for name,item in preserved.items()if name!='.'),
            'project_import_changed_existing_home_state')
    require(all(actual['.'][key]==preserved['.'][key]for key in ('mode','uid','inode')),
            'project_import_changed_home_identity')
    finish('source-sibling-state-preserved',source_catalog_unchanged=True,sibling_unchanged=True,authority_restored=False)
    versions[:],states[:],bindings[:]=new_versions,new_states,new_bindings
    require(all(row['attempted']and row['status']=='passed'for row in rows),'project_recovery_inventory_incomplete')
    evidence.update(status='passed',source_after=base.source())
    report['cases'].extend({'case':row['id'],'passed':True}for row in rows)
    return home
