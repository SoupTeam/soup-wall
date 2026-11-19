# SPDX-License-Identifier: Apache-2.0
"""Installed declarative recovery controls, followed by the existing two-project runs."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
import signal
import subprocess

CASES = ('private-export-consent', 'export-ancestor-symlink-refused', 'declarative-export', 'fresh-home-explicit-provider-inputs',
         'unresolved-preview-inert', 'stale-plan-refused', 'tampered-archive-refused',
         'changed-destination-catalog-refused', 'two-record-atomic-import',
         'duplicate-import-explicit', 'native-interruption-recovery', 'source-sibling-state-preserved')


def stage_fsync_observed(raw, stage):
    for line in raw.decode('utf-8', 'replace').splitlines():
        match = re.fullmatch(r'(?:[0-9]+\s+)?fsync\([0-9]+<([^>\n]+)>\)\s+= 0', line)
        if match and match[1] == str(stage):
            return True
    return False


def interrupt_before_publication(strace, command, trace, stage, catalog, *, cwd, env,
                                 diagnostics, witness_factory=None, timeout_seconds=120):
    """Observe durable staging, then kill only this owned fresh process group.

    Delaying the publication syscall gives the observer a bounded interruption
    window. Kernel syscall filtering avoids tracing every read/stat during the
    unchanged current-source checks; the early Linux fixture includes that load.
    Temporary output files avoid inherited-pipe EOF waits. Production
    code has no pause/fault environment option and its timeouts are unchanged.
    """
    def require(ok, code):
        if not ok:
            raise ValueError('project_interruption_' + code)
    def read_trace():
        fd=os.open(trace,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1
                    and info.st_size<=256*1024,'trace_bound')
            raw=os.read(fd,256*1024+1)
            require(len(raw)<=256*1024,'trace_bound')
            return raw
        finally:os.close(fd)
    require(not trace.exists() and not trace.is_symlink() and not stage.exists()
            and not stage.is_symlink() and not catalog.exists() and not catalog.is_symlink(),'fresh_fixture_required')
    words=[str(strace),'--seccomp-bpf','-f','-qq','-yy','-s','256','-e','trace=execve,execveat,fsync,renameat',
           '-e','inject=renameat:delay_enter=20000000:when=1','-o',str(trace),*map(str,command)]
    started=time.monotonic()
    diagnostics.update(phase='starting',stage_fsynced=False,publication_observed=False,
                       syscall_filter_requested=True)
    with tempfile.TemporaryFile(dir=trace.parent)as out,tempfile.TemporaryFile(dir=trace.parent)as err:
        process=subprocess.Popen(words,cwd=cwd,env=env,stdin=subprocess.DEVNULL,
                                 stdout=out,stderr=err,start_new_session=True)
        witness=None
        try:
            if witness_factory is not None:witness=witness_factory(process.pid)
            diagnostics['phase']='waiting_for_stage_fsync'
            deadline=time.monotonic()+timeout_seconds
            seen_size=-1;fsynced=False
            while time.monotonic()<deadline and process.poll()is None:
                if trace.exists():
                    size=trace.stat().st_size
                    require(size<=256*1024,'trace_bound')
                    if size!=seen_size:
                        seen_size=size;fsynced=fsynced or stage_fsync_observed(read_trace(),stage)
                if fsynced and stage.exists() and not catalog.exists() and not catalog.is_symlink():
                    info=stage.lstat()
                    require(stat.S_ISREG(info.st_mode)and info.st_uid==os.getuid()
                            and info.st_nlink==1 and 0<info.st_size<=128*1024,'stage_unsafe')
                    diagnostics['stage_fsynced']=True
                    break
                time.sleep(.02)
            require(diagnostics['stage_fsynced'],'stage_fsync_unobserved')
            require(process.poll()is None and os.getpgid(process.pid)==process.pid,'owned_group_changed')
            diagnostics['phase']='terminating_owned_group'
            os.killpg(process.pid,signal.SIGKILL)
            try:process.wait(timeout=10)
            except subprocess.TimeoutExpired:raise ValueError('project_interruption_exit_timeout')from None
            require(process.returncode==-signal.SIGKILL,'signal_not_observed')
            require(stage.is_file()and not catalog.exists()and not catalog.is_symlink(),'publication_raced')
            diagnostics.update(phase='terminated_before_publication',initial_exit=process.returncode)
        finally:
            if process.poll()is None:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                process.wait(timeout=10)
            diagnostics['elapsed_ms']=round((time.monotonic()-started)*1000)
            diagnostics['stdout_bytes']=os.fstat(out.fileno()).st_size
            diagnostics['stderr_bytes']=os.fstat(err.fileno()).st_size
            if trace.exists():
                raw=read_trace();diagnostics.update(trace_bytes=len(raw),trace_sha256=hashlib.sha256(raw).hexdigest(),
                    observed_fsync_calls=sum(re.match(rb'^(?:[0-9]+\s+)?fsync\(',line)is not None for line in raw.splitlines()),
                    stage_present=stage.exists(),catalog_present=catalog.exists(),
                    observed_exec_calls=sum(re.match(rb'^(?:[0-9]+\s+)?execve(?:at)?\(',line)is not None for line in raw.splitlines()),
                    observed_rename_calls=sum(re.match(rb'^(?:[0-9]+\s+)?renameat\(',line)is not None for line in raw.splitlines()))
            if witness is not None:diagnostics['owned_processes_stopped']=witness.finish()['all_stopped']
        require(diagnostics['stdout_bytes']<=65536 and diagnostics['stderr_bytes']<=16384,'output_bound')
        require(witness is None or diagnostics['owned_processes_stopped'],'cleanup_unconfirmed')
    return dict(diagnostics)


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
    begin('export-ancestor-symlink-refused')
    aliases=args.output/'project-export-aliases';aliases.mkdir(mode=0o700)
    roots={source_home}
    for record in json.loads(source_catalog)['records'].values():
        binding=record['binding']
        roots.update((Path(binding['selection']['path']).parent,Path(binding['state_root']['path'])))
        roots.update(Path(root['path'])for root in binding['workspaces'].values())
    for number,root in enumerate(sorted(roots)):
        alias=aliases/('root-'+str(number));alias.symlink_to(root.parent,target_is_directory=True)
        name='sou230-refused-export-'+str(number)+'.tar'
        require(not(root/name).exists()and not(root/name).is_symlink(),'project_export_control_not_fresh')
        try:
            refused=call(['export','--archive',alias/root.name/name,'--consent'],target=source_home,expected=2)
            require(refused['status']=='refused'and not(root/name).exists()
                    and not(root/name).is_symlink(),'project_export_followed_symlink_ancestor')
        finally:alias.unlink()
    finish('export-ancestor-symlink-refused',preserved_roots_checked=len(roots),created_archives=0)
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
    directory=interrupted_home/presets.DIRECTORY
    command=[str(args.agentfw),'pilot','--home',str(interrupted_home),'project','import',
             *map(str,common_interrupted),'--confirm-plan',plan['plan_sha256'],'--apply']
    diagnostics={};evidence['interruption_witness']=diagnostics
    observed=interrupt_before_publication(args.strace,command,trace,
        directory/('.import-next-'+plan['plan_sha256']),directory/'catalog.json',cwd=door.cwd,env=env,
        diagnostics=diagnostics,witness_factory=base.ProcessWitness)
    recovered=call(['import-recover',*common_interrupted,'--confirm-plan',plan['plan_sha256'],'--apply'],target=interrupted_home)
    require(recovered['status']=='imported'and recovered['recovered'],'project_import_recovery_failed')
    require(sorted(p.name for p in directory.iterdir())==['catalog.json'],'project_import_recovery_left_stage')
    for name in ('one','two'):call(['check','--name',name],target=interrupted_home)
    finish('native-interruption-recovery',initial_exit=observed['initial_exit'],
           initial_status='terminated_after_staged_fsync_before_publication',recovered=True,
           owned_processes_stopped=observed['owned_processes_stopped'],stage_fsynced=True,
           trace_sha256=observed['trace_sha256'])
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
