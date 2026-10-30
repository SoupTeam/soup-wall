#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in exact-source installed pilot removal on disposable owned Linux fixtures.

No default execution. Private paths, records, credentials and file contents never
enter the finite public report. Existing real host uses only the scripted model.
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
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('removal_edit', ROOT / 'scripts/qualify-installed-edit.py')
EDIT = importlib.util.module_from_spec(spec); spec.loader.exec_module(EDIT)
require, sha = EDIT.require, EDIT.sha
FORMAT = 'sw-installed-pilot-removal-qualification/1'
FAULTS = ('before-unlink', 'after-unlink', 'unlink-io', 'directory-sync')
CASES = ('installed-closure', 'genuine-completed-edit', 'preview-preserves-all', 'consent-required',
         'changed-selection', 'tampered-receipt', 'unexpected-entry', 'component-symlink', 'component-hardlink',
         'special-file', 'redirected-parent', 'changed-root', 'journal-overlap', 'active-read-only-owner',
         'active-edit-run', 'uncertain-run', 'unknown-journal', 'changed-journal',
         'actual-removal-preserves-user-data', 'already-removed', 'substitution-after-interruption', *FAULTS)


def passed(report):
    rows = report.get('cases', [])
    if not (report.get('format') == FORMAT and report.get('status') == 'passed'
            and report.get('expected') == list(CASES) and [r.get('id') for r in rows] == list(CASES)
            and all(r.get('attempted') is True and r.get('status') == 'passed' for r in rows)
            and report.get('paid_inference') is False and report.get('all_owned_stopped') is True
            and report.get('sibling_and_project_preserved') is True
            and type(report.get('operator_provider_requests')) is int and report['operator_provider_requests'] == 0):
        return False
    for key, count in [('source_commit', 40), ('source_tree', 40), ('agentfw_sha256', 64), ('helper_sha256', 64), ('component_sha256', 64), ('fault_sha256', 64)]:
        if not re.fullmatch('[0-9a-f]{'+str(count)+'}', str(report.get(key, ''))): return False
    if report.get('claude_sha256') != EDIT.CLAUDE: return False
    for name in FAULTS:
        row = next(r for r in rows if r['id'] == name)
        if row.get('actual_syscall_fault') is not True or row.get('preserved') is not True: return False
        if name in ('before-unlink', 'after-unlink') and row.get('fault_exit') != -signal.SIGKILL: return False
        if name in ('before-unlink', 'unlink-io') and row.get('explicit_retry_completed') is not True: return False
        if name in ('after-unlink', 'directory-sync') and row.get('uncertain_not_success') is not True: return False
    for name in ('genuine-completed-edit', 'actual-removal-preserves-user-data'):
        row = next(r for r in rows if r['id'] == name)
        if row.get('actual_installed_effect') is not True or row.get('preserved') is not True: return False
    return True


def witness(root):
    """Private independent finite identities, never a production crawl or report."""
    result = []
    for p in sorted([root, *root.rglob('*')]):
        m = p.lstat(); raw = b''
        if p.is_file() and not p.is_symlink():
            require(m.st_size <= 1024*1024, 'witness_file_bound'); raw = p.read_bytes()
        result.append((str(p.relative_to(root)), m.st_dev, m.st_ino, m.st_uid, m.st_gid,
                       m.st_mode, m.st_nlink, m.st_size, m.st_mtime_ns, sha(raw)))
        require(len(result) <= 4096, 'witness_entry_bound')
    return result


@contextlib.contextmanager
def replaced(path, *, link=None, fifo=False, raw=None):
    held = path.with_name(path.name + '.kept'); path.rename(held)
    try:
        if link is not None: path.symlink_to(link)
        elif fifo: os.mkfifo(path, 0o600)
        elif raw is not None: path.write_bytes(raw); path.chmod(0o400)
        yield
    finally:
        if path.exists() or path.is_symlink(): path.unlink()
        held.rename(path)


def qualify(args, report):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0, 'native_linux_user_required')
    suite = EDIT.Suite(args, report)
    archive = args.output / 'component.tar'
    build = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/build-pilot-front-door.py'), '--out', str(archive)],
                           cwd=ROOT, env=suite.env, capture_output=True, timeout=60)
    require(build.returncode == 0, 'component_build_failed'); built = json.loads(build.stdout.splitlines()[-1])
    installed = subprocess.run([str(suite.binary), 'pilot-component', '--home', str(suite.home), 'install', str(archive),
                                '--sha256', built['archive_sha256'], '--python', str(args.python)],
                               cwd=suite.work, env=suite.env, capture_output=True, timeout=60)
    require(installed.returncode == 0, 'component_install_failed')
    report.update(source_commit=built['commit'], source_tree=subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT, text=True).strip(),
                  component_sha256=built['component'], agentfw_sha256=sha(suite.binary.read_bytes()),
                  helper_sha256=sha(Path(__file__).read_bytes()), fault_sha256=sha(args.fault.read_bytes()), claude_sha256=EDIT.CLAUDE)
    def begin(name):
        row = report['cases'][CASES.index(name)]; row['attempted'] = True; suite.active = row
    def done(name, **fields): report['cases'][CASES.index(name)].update(status='passed', **fields)
    begin('installed-closure')
    for words in (['pilot', '--home', str(suite.home), 'help'], ['pilot-removal', '--help'],
                  *(['pilot-removal', action, '--help'] for action in ('preview', 'apply', 'status', 'resume'))):
        v = subprocess.run([str(suite.binary), *words], cwd=suite.work, env=suite.env, capture_output=True, timeout=20)
        require(v.returncode == 0, 'installed_startup_failed')
    done('installed-closure', installed_outside_checkout=True)
    begin('genuine-completed-edit')
    root, output, plan, code, prepared = suite.prepare('genuine-edit')
    require(code == 0, 'genuine_prepare_failed'); index = next(i for i,t in enumerate(prepared['profile']['targets']) if t['name']=='result.txt')
    native, seen, _ = suite.host('genuine-edit', root, output, plan, prepared,
        [(f'create_output_{index}', {'path':'result.txt','content':EDIT.NEW}), (f'read_output_{index}', {'path':'result.txt'})])
    require(native['exit'] == 0 and len(seen) == 2 and all(not r['is_error'] for r in seen.values())
            and output.read_text() == EDIT.NEW and native['process_cleanup']['all_stopped'], 'genuine_completed_edit_failed')
    completed_run = suite.last_run
    before_run = EDIT.private_state_witness(completed_run)
    done('genuine-completed-edit', actual_installed_effect=True, preserved=True, actual_native_approvals=native['approved'])
    journals = suite.work / 'recovery'; journals.mkdir(mode=0o700)
    project = suite.work / 'project'; project.mkdir(mode=0o700); (project/'user.txt').write_text('Owned project sentinel.\n')
    sibling = suite.work / 'sibling'; sibling.mkdir(mode=0o700)
    shutil.copytree(suite.home/'pilot-front-door', sibling/'pilot-front-door')
    protected = witness(project), witness(sibling), output.read_bytes(), EDIT.snapshot(suite.sentinel)
    trap = EDIT.HOST.ScriptedModel([])
    env = dict(suite.env, ANTHROPIC_BASE_URL=trap.url, ANTHROPIC_API_KEY='owned-removal-trap', HTTP_PROXY=trap.url, HTTPS_PROXY=trap.url)
    counter = 0
    def operator(action, words, extra=(), fault=None):
        selected_env = dict(env)
        if fault:
            selected_env.update(LD_PRELOAD=str(args.fault), SOU188_ROOT=str(words[words.index('--home')+1] / 'pilot-front-door'), SOU188_FAULT=fault)
        v = subprocess.run([str(suite.binary), 'pilot-removal', action, *map(str,words), *map(str,extra)],
                           cwd=suite.work, env=selected_env, stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
        require(len(v.stdout)<=512*1024 and len(v.stderr)<=8192 and not trap.requests, 'operator_effect_or_bound')
        for canary in (suite.secret_canary.encode(), EDIT.NEW.encode().strip(), b'owned-private-provider-credential'):
            require(canary not in v.stdout+v.stderr, 'operator_private_content_leak')
        suite.active['last_operator'] = EDIT.cli_observation(v.returncode, v.stdout, v.stderr)
        require(EDIT.private_state_witness(completed_run) == before_run, 'operator_changed_retained_tool_state')
        return v.returncode, json.loads(v.stdout) if v.stdout else None, v.stderr
    def fixture(name):
        nonlocal counter; counter += 1
        base = suite.work / f'fixture-{counter}'; base.mkdir(mode=0o700)
        home = base/'home'; home.mkdir(mode=0o700); prefix = base/'prefix'; prefix.mkdir(mode=0o700)
        installed=subprocess.run([str(suite.binary),'pilot-component','--home',str(home),'install',str(archive),'--sha256',built['archive_sha256'],'--python',str(args.python)],cwd=suite.work,env=suite.env,capture_output=True,timeout=30)
        require(installed.returncode==0,'fixture_component_install_failed')
        (home/'provider-credentials').write_text('owned-private-provider-credential'); (home/'provider-credentials').chmod(0o600)
        (prefix/'retained.txt').write_text('Prepared/user data remains.\n'); (prefix/'retained.txt').chmod(0o600)
        journal = journals/f'journal-{counter}'
        return home, prefix, journal, ['--home',home,'--prefix',prefix,'--state',suite.state,'--journal',journal]
    def preview(words):
        code, value, _ = operator('preview', words)
        require(code == 0 and value['status']=='preview' and value['executed'] is False and value['confirmation_sha256'], 'preview_failed')
        return value
    flags = ['--consent-remove', '--exclusive-maintenance']
    def apply(words,p,*,extra=flags,fault=None): return operator('apply',words,['--confirm',p['confirmation_sha256'],*extra],fault)
    def retained(j,p,ack=None):
        words=['--journal',j,'--expect-plan',p['confirmation_sha256']]
        return words + (['--success-ack',ack] if ack else [])
    try:
        begin('preview-preserves-all'); home,prefix,j,words=fixture('preview'); before=witness(home),witness(prefix),witness(journals)
        preview(words);require(before==(witness(home),witness(prefix),witness(journals)), 'preview_wrote_state');done('preview-preserves-all',preserved=True)
        begin('consent-required')
        for consent in ([],flags[:1],flags[1:]):
            home,prefix,j,words=fixture('consent');p=preview(words);before=witness(home)
            require(apply(words,p,extra=consent)[0]!=0 and witness(home)==before and not j.exists(),'consent_not_enforced')
        done('consent-required',refused_forms=3)
        for name in ('changed-selection','tampered-receipt','unexpected-entry','component-symlink','component-hardlink','special-file','redirected-parent','changed-root','journal-overlap'):
            begin(name);home,prefix,j,words=fixture(name);p=preview(words); component=home/'pilot-front-door'
            helper=component/'components'/built['component']/'tree/scripts/pilot.py'
            context=contextlib.nullcontext()
            if name=='changed-selection': (component/'current.json').write_bytes(b'{}')
            elif name=='tampered-receipt': (component/'components'/built['component']/'manifest.json').write_bytes(b'{}')
            elif name=='unexpected-entry': (component/'user-added').write_text('Retain unknown user file.')
            elif name=='component-symlink': context=replaced(helper,link=project/'user.txt')
            elif name=='component-hardlink': os.link(helper,home/'alias')
            elif name=='special-file': context=replaced(helper,fifo=True)
            elif name=='redirected-parent':
                held=home.with_name('held');home.rename(held);home.symlink_to(held)
            elif name=='changed-root':
                held=home/'held';component.rename(held);component.mkdir(mode=0o700)
            elif name=='journal-overlap': words[-1]=home/'journal'
            with context:
                before=witness(home if not home.is_symlink() else held),witness(prefix)
                code,_,_=apply(words,p)
                require(code!=0 and before==(witness(home if not home.is_symlink() else held),witness(prefix)) and not j.exists(),'unsafe_scope_not_refused')
            done(name,preserved=True,refused=True)
        begin('active-read-only-owner');home,prefix,j,words=fixture('active-read')
        hold=subprocess.Popen(['/bin/sleep','30'],cwd=home/'pilot-front-door',env=env)
        try:
            before=witness(home);code,v,_=operator('preview',words)
            require(code==0 and v['status']=='blocked' and not v['confirmation_sha256'] and witness(home)==before,'live_owner_not_refused')
        finally: hold.terminate();hold.wait(timeout=5)
        done('active-read-only-owner',actual_live_process=True,preserved=True)
        begin('active-edit-run'); root2,out2,plan2,code,prepared2=suite.prepare('active-edit');checked=[]
        index2=next(i for i,t in enumerate(prepared2['profile']['targets']) if t['name']=='result.txt')
        def active(run,row):
            if checked:return
            home,prefix,j,words=fixture('active-edit');before=witness(home)
            # Independent live writer updates its own leases; only the selected
            # completed witness remains invariant during this operator call.
            code,v,_=operator('preview',words);require(code==0 and v['status']=='blocked' and witness(home)==before,'active_edit_not_refused');checked.append(True)
        live,_,_=suite.host('active-edit',root2,out2,plan2,prepared2,[(f'create_output_{index2}',{'path':'result.txt','content':EDIT.NEW})],on_pending=active)
        require(checked==[True] and live['process_cleanup']['all_stopped'],'active_edit_control_missing')
        # The actual active run is now completed; pin its retained records too.
        completed_run=suite.last_run
        before_run=EDIT.private_state_witness(completed_run)
        done('active-edit-run',actual_live_process=True,preserved=True)
        begin('uncertain-run'); unknown=suite.state/'unrecognized-run';unknown.mkdir(mode=0o700)
        home,prefix,j,words=fixture('uncertain');code,v,_=operator('preview',words)
        require(code==0 and v['status']=='blocked' and not j.exists(),'uncertain_run_not_blocked');unknown.rmdir();done('uncertain-run',preserved=True)
        saved=[]
        for name in FAULTS:
            begin(name);home,prefix,j,words=fixture(name);p=preview(words);before=witness(prefix), (home/'provider-credentials').read_bytes()
            code,v,err=apply(words,p,fault=name)
            require(b'sou188_owned_fault_observed' in err,'actual_fault_not_observed')
            if name in ('before-unlink','after-unlink'):require(code==-signal.SIGKILL,'actual_kill_missing')
            if name=='unlink-io':require(code==0 and v['status']=='failed','unlink_failure_not_reported')
            if name=='directory-sync':require(code==0 and v['status']=='uncertain','sync_uncertainty_not_reported')
            code,state,_=operator('status',retained(j,p));require(code==0,'status_failed')
            if name in ('before-unlink','unlink-io'):
                code,resumed,_=operator('resume',retained(j,p),flags)
                require(code==0 and resumed['status']=='removed' and not (home/'pilot-front-door').exists(),'explicit_retry_failed')
                done(name,actual_syscall_fault=True,fault_exit=-9 if name=='before-unlink' else 0,explicit_retry_completed=True,preserved=True)
            else:
                require(state['status']=='uncertain','interruption_falsely_successful')
                before_component=witness(home/'pilot-front-door')
                require(operator('resume',retained(j,p),flags)[0]!=0 and witness(home/'pilot-front-door')==before_component,'uncertain_retry_changed_state')
                done(name,actual_syscall_fault=True,fault_exit=-9 if name=='after-unlink' else 0,uncertain_not_success=True,preserved=True)
            require(before==(witness(prefix),(home/'provider-credentials').read_bytes()),'fault_deleted_user_data')
            saved.append((home,prefix,j,words,p))
        begin('substitution-after-interruption');home,prefix,j,words=fixture('substitute');p=preview(words)
        require(apply(words,p,fault='before-unlink')[0]==-signal.SIGKILL,'substitution_fault_missing')
        (home/'pilot-front-door/current.json').write_text('Later user object.'); before=witness(home)
        require(operator('resume',retained(j,p),flags)[0]!=0 and witness(home)==before,'retry_deleted_replacement')
        done('substitution-after-interruption',preserved=True,refused=True)
        for name in ('unknown-journal','changed-journal'):
            begin(name);home,prefix,j,words=fixture(name);p=preview(words)
            require(apply(words,p,fault='before-unlink')[0]==-signal.SIGKILL,'journal_fault_missing')
            if name=='unknown-journal':(j/'unrecognized.json').write_text('{}')
            else:(j/'plan.json').write_text('{}')
            before=witness(home);require(operator('resume',retained(j,p),flags)[0]!=0 and witness(home)==before,'damaged_journal_not_refused');done(name,preserved=True)
        begin('actual-removal-preserves-user-data');home,prefix,j,words=fixture('positive')
        # Run against the exact installation about to be removed, not a copy of
        # another installation's runtime claim.
        suite.home=home
        usable=subprocess.run([str(suite.binary),'pilot','--home',str(home),'help'],cwd=suite.work,env=suite.env,capture_output=True,timeout=20)
        require(usable.returncode==0,'selected_installation_not_usable')
        own_root,own_output,own_plan,code,own_prepared=suite.prepare('selected-before-removal')
        require(code==0,'selected_installation_prepare_failed')
        own_index=next(i for i,t in enumerate(own_prepared['profile']['targets']) if t['name']=='result.txt')
        own_native,own_seen,_=suite.host('selected-before-removal',own_root,own_output,own_plan,own_prepared,
            [(f'create_output_{own_index}',{'path':'result.txt','content':EDIT.NEW}),(f'read_output_{own_index}',{'path':'result.txt'})])
        require(own_native['exit']==0 and all(not r['is_error'] for r in own_seen.values())
                and own_output.read_text()==EDIT.NEW and own_native['process_cleanup']['all_stopped'],'selected_installation_effect_failed')
        completed_run=suite.last_run;before_run=EDIT.private_state_witness(completed_run)
        p=preview(words)
        before=(home/'provider-credentials').read_bytes(),witness(prefix)
        code,removed,_=apply(words,p)
        require(code==0 and removed['status']=='removed' and all(r['status']=='removed' for r in removed['objects'])
                and not (home/'pilot-front-door').exists() and suite.binary.is_file()
                and before==((home/'provider-credentials').read_bytes(),witness(prefix)),'actual_removal_failed')
        code,status,_=operator('status',retained(j,p,removed['success_ack']));require(code==0 and status['status']=='removed','retained_recovery_unusable')
        done('actual-removal-preserves-user-data',actual_installed_effect=True,preserved=True,objects=len(removed['objects']))
        begin('already-removed');before=witness(home),witness(j)
        code,removed,_=operator('resume',retained(j,p,removed['success_ack']),flags)
        require(code==0 and removed['status']=='removed' and before==(witness(home),witness(j)),'already_removed_not_idempotent');done('already-removed',preserved=True)
        require(protected==(witness(project),witness(sibling),output.read_bytes(),EDIT.snapshot(suite.sentinel)) and not trap.requests,'sibling_or_project_changed')
        report.update(status='passed',operator_provider_requests=len(trap.requests),all_owned_stopped=True,sibling_and_project_preserved=True)
    finally: trap.close()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',action='store_true');p.add_argument('--agentfw',type=Path)
    p.add_argument('--claude',type=Path);p.add_argument('--python',type=Path,default=Path('/usr/bin/python3.12'))
    p.add_argument('--fault',type=Path);p.add_argument('--output',type=Path);args=p.parse_args()
    if not args.run:print(json.dumps({'format':FORMAT,'executed':False,'expected':list(CASES)}));return 0
    require(args.output and args.output.is_absolute() and not args.output.exists(),'new_private_output_required');args.output.mkdir(mode=0o700)
    report={'format':FORMAT,'status':'incomplete','paid_inference':False,'expected':list(CASES),
            'cases':[{'id':n,'attempted':False,'status':'incomplete'} for n in CASES]}
    try:qualify(args,report)
    except Exception as error:
        code=EDIT.failure_code(error);report.update(status='failed',failure=code,failure_type=type(error).__name__)
        row=next((r for r in report['cases'] if r['attempted'] and r['status']=='incomplete'),None)
        if row:row.update(status='failed',failure=code)
    report['inventory']={s:sum(r['status']==s for r in report['cases']) for s in ('passed','failed','incomplete')}
    (args.output/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'format':FORMAT,'status':report['status'],'inventory':report['inventory']}));return 0 if passed(report) else 1
if __name__=='__main__':raise SystemExit(main())
