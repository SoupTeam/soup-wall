# SPDX-License-Identifier: Apache-2.0
"""Owned installed snapshot acceptance, independent of the multi-root extension."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess

CASES=('metadata-only-preview','exact-consented-private-capture','installed-storage-race-faults',
       'incomplete-generation-refusal','explicit-single-root-preparation','stable-original-read-after-source-change',
       'in-use-removal-refusal','healthy-continuation','new-generation-refresh','source-and-sibling-preservation',
       'owned-process-cleanup','explicit-removal')


def qualify(args,door,home,env,report,installed):
    q,base,require=installed.QUAL,installed.BASE,installed.require
    evidence=dict(format='sw-installed-workspace-snapshot-qualification/1',status='incomplete',source=base.source(),
                  cases=[dict(id=name,status='incomplete',attempted=False) for name in CASES])
    report['workspace_snapshot']=evidence
    def begin(name):evidence['active_case']=name;evidence['cases'][CASES.index(name)]['attempted']=True
    def passed(name,**facts):evidence['cases'][CASES.index(name)].update(status='passed',**facts)
    def cli(action,*words,success=True):
        result=subprocess.run([str(args.agentfw),'pilot','--home',str(home),'snapshot',action,*map(str,words)],
            cwd=door.cwd,env=env,stdin=subprocess.DEVNULL,capture_output=True,timeout=180)
        require(len(result.stdout)<=65536,'workspace_snapshot_output_bound')
        value=json.loads(result.stdout)
        evidence['last_cli']=dict(action=action,exit=result.returncode,status=value.get('status'),reason=value.get('reason'))
        require((result.returncode==0)==success,'workspace_snapshot_unexpected_cli_outcome')
        return value
    source=args.output/'capture-source';source.mkdir(mode=0o700)
    initial=b'Owned exact captured project bytes.\n'
    (source/'README.md').write_bytes(initial);(source/'notes').mkdir(mode=0o700)
    (source/'notes'/'continuation.md').write_text('Owned snapshot continuation.\n')
    generation=args.output/'captured-generation'
    begin('metadata-only-preview')
    before=q.snapshot(source)
    preview=cli('preview','--source',source,'--destination',generation)
    require(preview['content_copied'] is False and not generation.exists() and q.snapshot(source)==before,'workspace_snapshot_preview_effect')
    passed('metadata-only-preview',content_copied=False,executed=False,files=preview['files'],bytes=preview['bytes'])
    begin('exact-consented-private-capture')
    cli('create','--source',source,'--destination',generation,'--confirm','a'*64,success=False)
    require(not generation.exists(),'workspace_snapshot_unconfirmed_publication')
    captured=cli('create','--source',source,'--destination',generation,'--confirm',preview['confirmation'])
    binding=captured['binding'];require(q.snapshot(source)==before,'workspace_snapshot_capture_changed_source')
    require((generation/'workspace'/'README.md').read_bytes()==initial and generation.stat().st_mode&0o777==0o700
        and (generation/'workspace').stat().st_mode&0o777==0o500,'workspace_snapshot_private_exact_capture_missing')
    passed('exact-consented-private-capture',tree_sha256=binding['treeSha256'],workspace_identity=binding['workspaceIdentity'],source_unchanged=True)
    begin('installed-storage-race-faults')
    # Fault injection executes the SAME installed library from outside checkout;
    # no runner disk filling, source edits or installed-module mutation is used.
    scripts=home/'pilot-front-door/components'/report['component']['component']/'tree/scripts'
    component_before=q.snapshot(scripts)
    fault=args.output/'fault-controls';fault.mkdir(mode=0o700)
    harness=r'''
import errno,json,os,sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,sys.argv[1]);import pilot_workspace_snapshot as m
root=Path(sys.argv[2]);source=root/'source';source.mkdir(mode=0o700);file=source/'note';file.write_bytes(b'owned fault-control content')
checks={}
def expect(label,action):
    try:action()
    except (ValueError,OSError):checks[label]=True
    else:raise AssertionError(label)
def low():
    target=root/'low';confirm=m.preview(source,target)['confirmation']
    with patch.object(m.os,'fstatvfs',return_value=SimpleNamespace(f_bavail=0,f_frsize=4096)):m.create(source,target,confirm)
expect('low-space-before-copy',low)
def changed():
    target=root/'changed';confirm=m.preview(source,target)['confirmation'];read=os.read;once=[False]
    def raced(fd,n):
        raw=read(fd,n)
        if not once[0] and os.readlink('/proc/self/fd/'+str(fd))==str(file):
            once[0]=True;file.write_bytes(b'changed during capture')
        return raw
    with patch.object(m.os,'read',side_effect=raced):m.create(source,target,confirm)
expect('source-changed-during-copy',changed)
def partial():
    target=root/'partial';confirm=m.preview(source,target)['confirmation']
    with patch.object(m,'write_record',side_effect=OSError(errno.ENOSPC,'owned injected fault')):m.create(source,target,confirm)
expect('low-space-after-copy-before-publication',partial)
def collision():
    target=root/'winner';confirm=m.preview(source,target)['confirmation'];publish=m.publish
    def winner(parent,temporary,destination):
        target.mkdir(mode=0o700);(target/'marker').write_text('existing winner');publish(parent,temporary,destination)
    with patch.object(m,'publish',side_effect=winner):m.create(source,target,confirm)
expect('publication-collision',collision)
assert (root/'winner'/'marker').read_text()=='existing winner'
assert all(not (root/name).exists() for name in ('low','changed','partial')) and not list(root.glob('.snapshot-*'))
with m.Capture(source) as capture:
    source.rename(root/'retained-source');source.mkdir(mode=0o700)
    expect('source-root-replaced',capture.check)
print(json.dumps({'checks':checks,'partial_generations_selectable':False,'existing_winner_preserved':True,'installed_library':True}))
'''
    result=subprocess.run([str(args.component_python),'-I','-S','-B','-c',harness,str(scripts),str(fault)],
        cwd=door.cwd,env={},stdin=subprocess.DEVNULL,capture_output=True,timeout=120)
    evidence['fault_driver']=dict(exit=result.returncode,stdout_bytes=len(result.stdout),stderr_sha256=hashlib.sha256(result.stderr).hexdigest())
    require(result.returncode==0 and len(result.stdout)<=16384,'workspace_snapshot_installed_fault_driver_failed')
    require(q.snapshot(scripts)==component_before,'workspace_snapshot_fault_driver_changed_component')
    controls=json.loads(result.stdout);require(len(controls['checks'])==5 and all(controls['checks'].values()),'workspace_snapshot_incomplete_fault_controls')
    passed('installed-storage-race-faults',installed_component_unchanged=True,**controls)
    begin('incomplete-generation-refusal')
    complete=(generation/'complete.json').read_bytes();(generation/'complete.json').unlink()
    try:cli('inspect','--snapshot',generation,success=False)
    finally:
        (generation/'complete.json').write_bytes(complete);(generation/'complete.json').chmod(0o400)
    passed('incomplete-generation-refusal',never_selectable=True)
    # Deliberate, separately recorded source edit after capture. Snapshot retains
    # exact earlier bytes; this is not a source-preservation claim for that edit.
    (source/'README.md').write_text('Owned source edited after capture.\n')
    inspected=cli('inspect','--snapshot',generation)
    require(inspected['current_source']=='changed-since-capture' and inspected['binding']==binding,'workspace_snapshot_current_source_mislabeled')
    selected=argparse.Namespace(**vars(args));selected.prefix=args.output/'snapshot-prefix';selected.other_prefix=args.prefix
    selected.project=generation/'workspace';target=type(door)(selected,env,door.cwd,home)
    begin('explicit-single-root-preparation')
    def guided(action,*words,**kwargs):
        code,value,_=target.call(action,*words,**kwargs)
        evidence['last_guided']=dict(action=action,exit=code,status=value.get('status'),reason=value.get('reason'))
        require(code==0,'workspace_snapshot_guided_failed');return value
    plan=guided('preview','--workspace-snapshot',generation)
    require(plan['executed'] is False and plan['workspace_snapshot']['view'].startswith('snapshot'),'workspace_snapshot_preview_label_missing')
    prepared=guided('prepare','--apply','--workspace-snapshot',generation,timeout=3600)
    selection=Path(prepared['selection']);value=json.loads(selection.read_bytes())
    require(value.get('workspace_snapshot')==binding and value.get('filesystem_roots') is None,'workspace_snapshot_selection_changed')
    profile=json.loads((selection.parent/'filesystem-profile/profile.json').read_bytes())
    require(profile['format']=='sw-mcp/filesystem-readonly/1' and profile['workspaceSnapshot']==binding,'workspace_snapshot_original_profile_changed')
    reused=guided('prepare','--apply',inputs=False,timeout=900);require(reused['status']=='reused','workspace_snapshot_not_reused')
    passed('explicit-single-root-preparation',original_profile=True,fresh_workspace_identity=True,not_activated=True)
    baseline=[q.snapshot(p) for p in (source,args.project,args.repository,generation)]
    begin('stable-original-read-after-source-change');begin('in-use-removal-refusal')
    removed=[]
    def in_use(model):
        require(any(not r['is_error'] for r in model.results.values()),'workspace_snapshot_no_useful_original_read')
        value=cli('remove','--snapshot',generation,'--confirm',inspected['removal_confirmation'],success=False)
        require(value.get('reason')=='workspace_snapshot_in_use' and generation.exists(),'workspace_snapshot_in_use_removal_not_refused')
        removed.append(True)
    startup_trace=args.output/'snapshot-startup.private.trace'
    row,results,_=q.run_case(selected,target,report,'snapshot',[
        ('mcp__filesystem__read_text_file',{'path':'/workspace/README.md'}),
        ('mcp__filesystem__list_directory',{'path':'/workspace'}),
        ('mcp__filesystem__read_text_file',{'path':str(source/'README.md')}),
        ('mcp__filesystem__read_text_file',{'path':'/workspace/notes/continuation.md'})],after_useful=in_use,provider_trace=startup_trace,diagnostic_writes=True)
    evidence['runtime']={k:row.get(k) for k in ('exit','status','reason','live_status','process_cleanup')}
    if row['exit']!=0 and startup_trace.exists():
        with startup_trace.open('rb') as stream: raw=stream.read(32*1024*1024)
        evidence['startup_diagnostics']=dict(trace_private=True,
            codes=sorted(set(x.decode() for x in re.findall(rb'(?:workspace_snapshot|filesystem_roots|mcp_owner)_[a-z_]{1,80}',raw))),
            bind_mount_failed=b"Can't bind-mount" in raw,permission_denied=b'Permission denied' in raw,
            private_trace_sha256=hashlib.sha256(raw).hexdigest())
    evidence['results']={key:dict(is_error=value['is_error'],content_sha256=hashlib.sha256(json.dumps(value['content']).encode()).hexdigest()) for key,value in results.items()}
    ids=['toolu_front_snapshot_'+str(i) for i in range(4)]
    require(row['exit']==0 and row['live_status'].get('protection')=='observed-live' and set(results)==set(ids),'workspace_snapshot_original_host_incomplete')
    require(results[ids[0]]['is_error'] is False and initial.decode().strip() in json.dumps(results[ids[0]])
            and 'Owned source edited after capture' not in json.dumps(results[ids[0]]),'workspace_snapshot_original_bytes_unstable')
    passed('stable-original-read-after-source-change',original_bytes_sha256=hashlib.sha256(initial).hexdigest(),observed_live=True)
    require(removed==[True],'workspace_snapshot_in_use_control_missing');passed('in-use-removal-refusal',lease_held=True,source_untouched=True)
    begin('healthy-continuation')
    require(results[ids[2]]['is_error'] is True and results[ids[3]]['is_error'] is False
        and 'Owned snapshot continuation.' in json.dumps(results[ids[3]]),'workspace_snapshot_healthy_continuation_missing')
    passed('healthy-continuation',outside_path_refused=True)
    begin('source-and-sibling-preservation')
    require(baseline==[q.snapshot(p) for p in (source,args.project,args.repository,generation)],'workspace_snapshot_runtime_changed_inputs')
    passed('source-and-sibling-preservation',unchanged_after_deliberate_source_edit=True)
    begin('owned-process-cleanup');require(row['process_cleanup']['all_stopped'],'workspace_snapshot_process_cleanup_missing')
    passed('owned-process-cleanup',**row['process_cleanup'])
    begin('new-generation-refresh')
    refresh=args.output/'refreshed-generation'
    plan=cli('preview','--source',source,'--destination',refresh)
    fresh=cli('create','--source',source,'--destination',refresh,'--confirm',plan['confirmation'])
    require(fresh['binding']['treeSha256']!=binding['treeSha256'] and (generation/'workspace'/'README.md').read_bytes()==initial
        and json.loads(selection.read_bytes())['workspace_snapshot']==binding,'workspace_snapshot_refresh_mutated_running_selection')
    passed('new-generation-refresh',new_identity=True,old_content_stable=True,selection_unchanged=True)
    begin('explicit-removal')
    cli('remove','--snapshot',generation,'--confirm',inspected['removal_confirmation'])
    cli('remove','--snapshot',refresh,'--confirm',fresh['removal_confirmation'])
    require(not generation.exists() and not refresh.exists() and baseline[:3]==[q.snapshot(p) for p in (source,args.project,args.repository)],'workspace_snapshot_removal_changed_source_or_sibling')
    passed('explicit-removal',source_unchanged=True,no_active_processes=True)
    require(all(c['attempted'] and c['status']=='passed' for c in evidence['cases']),'workspace_snapshot_incomplete_cases')
    evidence['status']='passed'
