#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in installed multi-file export controls; default is inert, no paid model."""
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
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('set_review', ROOT / 'scripts/qualify-edit-review.py')
REVIEW = importlib.util.module_from_spec(spec)
spec.loader.exec_module(REVIEW)
EDIT = REVIEW.EDIT
require, sha, snapshot = EDIT.require, EDIT.sha, EDIT.snapshot
FORMAT = 'sw-installed-edit-export-set-qualification/1'
CASES = ('installed-closure', 'genuine-two-file-run', 'genuine-eight-file-run',
         'two-file-preview-no-write', 'two-file-atomic-export', 'eight-file-atomic-export',
         'no-consent', 'tampered-confirmation', 'changed-destination', 'changed-selection',
         'duplicate-target', 'undeclared-target', 'changed-last-file', 'missing-last-file',
         'linked-last-file', 'hardlinked-last-file', 'fifo-last-file', 'device-link-last-file',
         'changed-profile', 'changed-terminal', 'active-run', 'cancelled-run',
         'existing-destination', 'concurrent-destination-create', 'changed-last-file-during-staging',
         'copy-io-failure', 'publication-io-failure', 'cancellation-during-staging',
         'injected-stage-entry-preserved', 'substituted-stage-name-preserved', 'parent-redirection')
FAULTS = {'concurrent-destination-create':'concurrent-destination',
          'changed-last-file-during-staging':'last-file-change', 'copy-io-failure':'copy-io',
          'publication-io-failure':'publish-io', 'cancellation-during-staging':'cancel',
          'injected-stage-entry-preserved':'extra-entry', 'substituted-stage-name-preserved':'swap-stage',
          'parent-redirection':'redirect-parent'}


def decode_response(result, diagnostic):
    # Capture the actual invocation before interpreting it. A parser refusal
    # has no product JSON and must never disappear behind a JSONDecodeError.
    diagnostic.update(exit_code=result.returncode,accepted=result.returncode == 0,
                      stdout_sha256=sha(result.stdout),stderr_sha256=sha(result.stderr))
    require(bool(result.stdout), 'set_response_missing_cli_refused_before_json')
    value=json.loads(result.stdout)
    diagnostic.update(status=value.get('status'),reason=value.get('reason'))
    require(value.get('format') == 'sw-installed-edit-export-set/1' and value.get('executed') is False
            and value.get('authority') is False, 'set_response_contract')
    return value


def passed_report(report):
    rows = report.get('cases', [])
    by = {r.get('id'):r for r in rows}
    return (report.get('format') == FORMAT and report.get('status') == 'passed'
            and report.get('paid_inference') is False and report.get('claude_sha256') == EDIT.CLAUDE
            and report.get('expected') == list(CASES) and [r.get('id') for r in rows] == list(CASES)
            and all(r.get('attempted') is True and r.get('status') == 'passed' for r in rows)
            and all(r.get('calls') for r in rows[3:])
            and all(by.get(n, {}).get('genuine_readback') is True for n in ('genuine-two-file-run','genuine-eight-file-run'))
            and all(by.get(n, {}).get('exact_manifest_and_bytes') is True for n in ('two-file-atomic-export','eight-file-atomic-export'))
            and all(by.get(n, {}).get('fault_observed') is True and by[n].get('no_partial_publication') is True for n in FAULTS)
            and all(r.get('source_preserved') is True for r in rows[3:])
            and all(type(c.get('accepted')) is bool and type(c.get('exit_code')) is int
                    and c.get('exit_code') == (0 if c.get('accepted') is True else 1)
                    for r in rows for c in r.get('calls', []))
            and all(r['calls'][-1].get('exit_code') == 1 and r['calls'][-1].get('status') == 'incomplete' for r in rows[6:])
            and all(by.get(n,{}).get('calls',[{}])[-1].get('status') == 'published' for n in ('two-file-atomic-export','eight-file-atomic-export'))
            and type(report.get('provider_requests_during_export')) is int and report['provider_requests_during_export'] == 0
            and report.get('sentinel_preserved') is True and report.get('all_owned_stopped') is True)


def qualify(args, report):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0, 'native_linux_operator_required')
    require(sha(args.claude.read_bytes()) == EDIT.CLAUDE and not args.output.is_relative_to(ROOT), 'genuine_installed_host_required')
    report['cases'][0]['attempted'] = True
    suite = EDIT.Suite(args, report)
    archive = args.output / 'component.tar'
    build = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/build-pilot-front-door.py'), '--out', str(archive)],
                           cwd=ROOT, env=suite.env, capture_output=True, timeout=60)
    require(build.returncode == 0, 'component_build_failed')
    built = json.loads(build.stdout.splitlines()[-1])
    install = subprocess.run([str(suite.binary), 'pilot-component', '--home', str(suite.home), 'install', str(archive),
                             '--sha256', built['archive_sha256'], '--python', str(args.python)],
                            cwd=suite.work, env=suite.env, capture_output=True, timeout=60)
    require(install.returncode == 0, 'component_install_failed')
    report.update(source_commit=built['commit'], source_tree=subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=ROOT,text=True).strip(),
                  component=built['component'], agentfw_sha256=sha(suite.binary.read_bytes()), claude_sha256=sha(suite.claude.read_bytes()))

    def begin(name):
        row = report['cases'][CASES.index(name)];row['attempted'] = True;suite.active = row
        return row

    def finish(name, **facts):
        report['cases'][CASES.index(name)].update(status='passed', **facts)

    finish('installed-closure', installed_outside_checkout=True)
    trap = EDIT.HOST.ScriptedModel([])
    env = dict(suite.env, ANTHROPIC_BASE_URL=trap.url, ANTHROPIC_API_KEY='owned-export-trap', HTTP_PROXY=trap.url, HTTPS_PROXY=trap.url)
    exports = args.output / 'exports';exports.mkdir(mode=0o700)
    try:
        def fixture(label, count, mode='approve', on_pending=None):
            root = suite.work / label;root.mkdir(mode=0o700)
            target = root / 'result.txt';target.write_text(EDIT.OLD);target.chmod(0o600)
            names = ['result.txt'] + [f'created-{i}.txt' for i in range(1,count)]
            plan = suite.work / (label + '-plan')
            words = ['prepare','--home',suite.home,'--root',root,'--claude',suite.claude,'--private-sole-writer',
                     '--max-mutations',str(count),'--max-write-bytes',str(count*4096),'--out',plan,'--apply']
            for name in names: words += ['--read',name,'--replace' if name == 'result.txt' else '--create',name]
            code, prepared = suite.cli(*words);require(code == 0, 'multi_prepare_failed')
            targets = prepared['profile']['targets'];proposals = []
            old_index = next(i for i,t in enumerate(targets) if t['name'] == 'result.txt')
            proposals.append((f'read_output_{old_index}', {'path':'result.txt'}))
            for i,t in enumerate(targets):
                payload = {'path':t['name'],'content':EDIT.NEW}
                if t.get('replacement'):
                    payload.update(old_identity=t['replacement']['identity'], old_sha256=t['replacement']['sha256'])
                proposals.append((('replace' if t.get('replacement') else 'create') + f'_output_{i}',payload))
            for i,t in enumerate(targets): proposals.append((f'read_output_{i}',{'path':t['name']}))
            if on_pending is not None: on_pending.prepared=prepared
            row, observed, _ = suite.host(label,root,target,plan,prepared,proposals,mode=mode,timeout=90,on_pending=on_pending)
            if mode == 'approve':
                require(row['exit'] == 0 and row['write_admissions'] == count and row['process_cleanup']['all_stopped'], 'multi_host_failed')
                for offset,t in enumerate(targets, start=1+count):
                    value = observed.get(f'toolu_edit_{offset}', {})
                    require(not value.get('is_error', True) and EDIT.NEW.strip() in json.dumps(value.get('content'))
                            and (root/t['name']).read_bytes() == EDIT.NEW.encode(), 'multi_independent_readback_failed')
            return root,plan,prepared,suite.last_run,sorted(names),row

        completed = []
        for name,count in [('genuine-two-file-run',2),('genuine-eight-file-run',8)]:
            begin(name);data = fixture(name,count);completed.append(data)
            finish(name,genuine_readback=True,host=data[-1],per_file=[{'name':n,'witness':snapshot(data[0]/n)}for n in data[4]])
        root,plan,prepared,run,names,_ = completed[1]

        def witness(data):
            root,plan,_,run,names,_ = data
            retained = (EDIT.private_state_witness(run,include_audit=False) if data[-1] is None
                        else REVIEW.selected_witness(suite,run,root/'result.txt',plan))
            plans=[]
            for name in ('profile.json','profile.sha256'):
                path=plan/name;meta=path.stat();raw=path.read_bytes();require(len(raw)<=128*1024,'plan_witness_cap')
                plans.append({'device':meta.st_dev,'inode':meta.st_ino,'mode':meta.st_mode,'bytes':meta.st_size,'sha256':sha(raw)})
            return {'retained':retained,'external_plan':plans,'files':{n:snapshot(root/n)for n in names}}

        def invoke(data, selected, out, confirmation=None, consent=True, selected_env=None):
            before=witness(data)
            words = [str(suite.binary),'edit-session','export-set','--run',str(data[3]),'--sha256',data[2]['profile_sha256'],'--out',str(out)]
            for n in selected: words += ['--include',n]
            if consent: words += ['--consent-private-content']
            if confirmation is not None: words += ['--apply','--confirm',confirmation]
            result = subprocess.run(words,cwd=suite.work,env=selected_env or env,stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
            require(len(result.stdout) <= 384*1024 and len(result.stderr) <= 8192, 'set_response_cap')
            require(suite.secret_canary.encode() not in result.stdout+result.stderr, 'set_prompt_leak')
            diagnostic = {'source_before':before,'source_after':witness(data),'destination_after':snapshot(out)}
            suite.active.setdefault('calls',[]).append(diagnostic)
            value=decode_response(result,diagnostic)
            return result.returncode,value

        def fresh(name):
            parent = exports/name;parent.mkdir(mode=0o700)
            return parent/'set'

        def preview(data, selected, out):
            before = witness(data);parent_before = sorted(p.name for p in out.parent.iterdir())
            code,value = invoke(data,selected,out)
            require(code == 0 and value['status'] == 'preview' and before == witness(data)
                    and parent_before == sorted(p.name for p in out.parent.iterdir()) and not out.exists(), 'preview_changed_state')
            require([f['name']for f in value['selection']['files']] == sorted(selected), 'preview_omitted_file')
            return value['confirmation_sha256']

        def exact(data, selected, out, digest):
            manifest = json.loads((out/'manifest.json').read_bytes())
            require(manifest['format'] == 'sw-installed-edit-private-result-set/1' and manifest['confirmation_sha256'] == digest
                    and sorted(p.name for p in out.iterdir()) == sorted(['manifest.json',*selected])
                    and [f['name']for f in manifest['files']] == sorted(selected) and stat.S_IMODE(out.stat().st_mode) == 0o700, 'set_manifest_not_exact')
            for item in manifest['files']:
                path = out/item['name'];source = data[0]/item['name']
                require(path.read_bytes() == source.read_bytes() and item['sha256'] == sha(path.read_bytes())
                        and item['bytes'] == path.stat().st_size and stat.S_IMODE(path.stat().st_mode) == 0o600
                        and item['identity']['inode'] == source.stat().st_ino, 'set_file_not_exact')
            require(set(manifest) == {'format','privacy','confirmation_sha256','run_sha256','profile_sha256','files'}
                    and stat.S_IMODE((out/'manifest.json').stat().st_mode) == 0o600, 'set_manifest_contains_unrelated_metadata')
            return [{'name':n,'source':snapshot(data[0]/n),'destination':snapshot(out/n)}for n in selected]

        begin('two-file-preview-no-write');preview(completed[0],completed[0][4],fresh('preview'))
        finish('two-file-preview-no-write',source_preserved=True)
        for name,data in [('two-file-atomic-export',completed[0]),('eight-file-atomic-export',completed[1])]:
            begin(name);out = fresh(name);before = witness(data);digest = preview(data,data[4],out)
            code,value = invoke(data,data[4],out,digest)
            require(code == 0 and value['status'] == 'published' and before == witness(data), 'allowed_set_export_failed')
            finish(name,source_preserved=True,exact_manifest_and_bytes=True,files=exact(data,data[4],out,digest))

        def negative(name, selected=None, consent=True, change_digest=None, change_out=False):
            begin(name);out = fresh(name);chosen = selected if selected is not None else names
            digest = preview(completed[1],names,out)
            if change_digest: digest = change_digest
            if change_out: out = out.with_name('different')
            # Apply without consent is already a Clap regression. Exercise the
            # executable preview refusal here, using valid runtime grammar.
            before = witness(completed[1]);code,value = invoke(completed[1],chosen,out,digest if consent else None,consent)
            require(code == 1 and value['status'] == 'incomplete' and not out.exists() and before == witness(completed[1])
                    and not list(out.parent.iterdir()), 'negative_set_effect_'+name)
            finish(name,source_preserved=True,no_partial_publication=True)
        negative('no-consent',consent=False)
        negative('tampered-confirmation',change_digest='0'*64)
        negative('changed-destination',change_out=True)
        negative('changed-selection',selected=names[:2])
        negative('duplicate-target',selected=[names[0],names[0]])
        negative('undeclared-target',selected=[names[0],'not-declared.txt'])
        for name,options in [('changed-last-file',{'raw':b'Changed before apply.\n'}),('missing-last-file',{}),
                             ('linked-last-file',{'link':suite.sentinel}),('fifo-last-file',{'fifo':True}),
                             ('device-link-last-file',{'link':'/dev/zero'})]:
            begin(name);out=fresh(name);digest=preview(completed[1],names,out)
            with REVIEW.replaced(root/names[-1],**options):
                before=witness(completed[1]);code,value=invoke(completed[1],names,out,digest)
                require(code == 1 and value['status'] == 'incomplete' and before == witness(completed[1]) and not list(out.parent.iterdir()), 'unsafe_last_file_exported')
            finish(name,source_preserved=True,no_partial_publication=True)
        begin('hardlinked-last-file');out=fresh('hardlinked-last-file');digest=preview(completed[1],names,out)
        link=args.output/'extra-hardlink';os.link(root/names[-1],link)
        try:
            before=witness(completed[1]);code,value=invoke(completed[1],names,out,digest)
            require(code == 1 and before == witness(completed[1]) and not list(out.parent.iterdir()), 'hardlinked_file_exported')
        finally: link.unlink()
        finish('hardlinked-last-file',source_preserved=True,no_partial_publication=True)
        for name,path,raw in [('changed-profile',run/'profile.json',b'{}'),('changed-terminal',run/'terminal.json',b'{}')]:
            begin(name);out=fresh(name);digest=preview(completed[1],names,out)
            with REVIEW.replaced(path,raw=raw):
                before=witness(completed[1]);code,value=invoke(completed[1],names,out,digest)
                require(code == 1 and before == witness(completed[1]) and not list(out.parent.iterdir()), 'changed_binding_exported')
            finish(name,source_preserved=True,no_partial_publication=True)

        begin('active-run');seen=[]
        def pending(active,_):
            if seen: return
            live=(suite.work/'cancelled-fixture',suite.work/'cancelled-fixture-plan',pending.prepared,active,['created-1.txt','result.txt'],None)
            before=witness(live);out=fresh('active-run');code,value=invoke(live,live[4],out)
            require(code == 1 and before == witness(live) and not list(out.parent.iterdir()), 'active_run_exported');seen.append(True)
        cancelled=fixture('cancelled-fixture',2,mode='cancel-pending',on_pending=pending)
        require(seen and cancelled[-1]['terminal']['reason'] == 'cancelled' and cancelled[-1]['process_cleanup']['all_stopped'], 'actual_cancel_missing')
        finish('active-run',source_preserved=True,actual_pending_run=True)
        begin('cancelled-run');before=witness(cancelled);out=fresh('cancelled-run');code,value=invoke(cancelled,cancelled[4],out)
        require(code == 1 and before == witness(cancelled) and not list(out.parent.iterdir()), 'cancelled_run_exported')
        finish('cancelled-run',source_preserved=True,actual_cancellation=True)
        begin('existing-destination');out=fresh('existing-destination');digest=preview(completed[1],names,out)
        out.mkdir(mode=0o700);(out/'sentinel').write_bytes(b'preserve');before=witness(completed[1]);old=snapshot(out/'sentinel')
        code,value=invoke(completed[1],names,out,digest)
        require(code == 1 and before == witness(completed[1]) and old == snapshot(out/'sentinel') and sorted(p.name for p in out.iterdir()) == ['sentinel'], 'existing_destination_changed')
        finish('existing-destination',source_preserved=True,no_partial_publication=True)

        for name,mode in FAULTS.items():
            begin(name);out=fresh(name);digest=preview(completed[1],names,out);before=witness(completed[1])
            last=root/names[-1];original=last.read_bytes();marker=args.output/(name+'.fault')
            fault_env=dict(env,LD_PRELOAD=str(args.fault),SOU186_FAULT=mode,SOU186_FAULT_WITNESS=str(marker),
                           SOU186_LAST_OUTPUT=str(last),SOU186_EXPORT_PARENT=str(out.parent))
            code,value=invoke(completed[1],names,out,digest,selected_env=fault_env)
            require(code == 1 and value['status'] == 'incomplete' and marker.read_bytes() == b'observed', 'fault_not_observed_'+name)
            if mode == 'last-file-change':
                after=witness(completed[1])
                require((before['retained'][0][1:],before['retained'][1:]) == (after['retained'][0][1:],after['retained'][1:]), 'last_file_fault_retained_state_changed')
                require(before['external_plan']==after['external_plan'],'last_file_fault_plan_changed')
                require(last.read_bytes() == b'Changed during staging.\n', 'last_file_fault_not_actual')
                last.write_bytes(original);last.chmod(0o600)
                require(all(snapshot(root/n) == before['files'][n]for n in names[:-1]) and not out.exists(), 'last_file_fault_peer_changed')
            else: require(before == witness(completed[1]), 'fault_changed_source_'+name)
            if mode == 'concurrent-destination': require(sorted(p.name for p in out.iterdir()) == ['unrelated-sentinel'] and (out/'unrelated-sentinel').read_bytes() == b'preserve', 'concurrent_destination_changed')
            else: require(not out.exists(), 'partial_set_published_'+name)
            stages=list(out.parent.glob('.agentfw-doctor-*'))
            if mode == 'extra-entry':
                require(len(stages) == 1 and sorted(p.name for p in stages[0].iterdir()) == ['unrelated-sentinel']
                        and (stages[0]/'unrelated-sentinel').read_bytes() == b'preserve', 'injected_entry_deleted')
            elif mode == 'swap-stage':
                require(len(stages) == 2 and sum((p/'unrelated-sentinel').is_file()for p in stages) == 1, 'substituted_stage_deleted')
                held=next(p for p in stages if p.name.endswith('.held'));exact(completed[1],names,held,digest)
            elif mode == 'redirect-parent':
                require(sorted(p.name for p in out.parent.iterdir()) == ['unrelated-sentinel'] and (out.parent/'unrelated-sentinel').read_bytes() == b'preserve'
                        and not list(out.parent.with_name(out.parent.name+'.held').iterdir()), 'redirected_parent_touched')
            else: require(not stages, 'owned_stage_not_cleaned_'+name)
            finish(name,source_preserved=True,fault_observed=True,no_partial_publication=True,
                   destination_witness=snapshot(out),retained_stage_names=[p.name for p in stages],
                   retained_stage_files=[{'stage':p.name,'files':[{'name':f.name,'identity':snapshot(f)}for f in p.iterdir()]}for p in stages])
        require(not trap.requests and snapshot(suite.sentinel) == suite.before_sentinel,'export_external_effect')
        report.update(status='passed',provider_requests_during_export=len(trap.requests),sentinel_preserved=True,all_owned_stopped=True)
    finally: trap.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',action='store_true')
    for name in ('agentfw','claude','python','fault','output'): parser.add_argument('--'+name,type=Path,default=Path('/usr/bin/python3.12')if name=='python'else None)
    args=parser.parse_args()
    if not args.run: print(json.dumps({'format':FORMAT,'executed':False,'expected':list(CASES)}));return 0
    require(args.output and args.output.is_absolute() and not args.output.exists(),'new_absolute_output_required')
    args.output.mkdir(mode=0o700)
    report={'format':FORMAT,'status':'incomplete','paid_inference':False,'expected':list(CASES),
            'cases':[{'id':n,'status':'incomplete','attempted':False}for n in CASES]}
    try: qualify(args,report)
    except Exception as error:
        code=EDIT.failure_code(error);report.update(status='failed',failure=code,failure_type=type(error).__name__)
        active=next((r for r in report['cases']if r['attempted'] and r['status']=='incomplete'),None)
        if active is not None: active.update(status='failed',failure=code)
    report['inventory']={s:sum(r['status']==s for r in report['cases'])for s in ('passed','failed','incomplete')}
    evidence=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode();(args.output/'report.json').write_bytes(evidence)
    summary={k:report[k]for k in ('format','status','inventory','failure','failure_type','source_commit','source_tree','component','agentfw_sha256','claude_sha256')if k in report}
    summary.update(evidence_sha256=sha(evidence),case_results=[{'id':r['id'],'status':r['status'],'attempted':r['attempted'],
        'witnesses':{k:v for k,v in r.items()if type(v)is bool}}for r in report['cases']])
    print(json.dumps(summary,sort_keys=True))
    return 0 if passed_report(report) else 1


if __name__ == '__main__': raise SystemExit(main())
