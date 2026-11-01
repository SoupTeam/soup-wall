# SPDX-License-Identifier: Apache-2.0
"""Owned installed multi-root original filesystem qualification, independent of Git worktrees."""
import argparse
import ast
import json
import re
import hashlib
from pathlib import Path
import subprocess

CASES = ('two-explicit-roots', 'inert-installed-preview', 'prepared-root-custody',
         'duplicate-overlap-alias-refusals', 'missing-replaced-root-refusals', 'cross-profile-refusal',
         'useful-original-read-list-search', 'whole-call-cross-root-refusals',
         'single-root-sibling-retained', 'source-preservation', 'owned-process-cleanup')


def reported_refusal_codes(text):
    """Bounded fixed-frame diagnostics, never an admission decision."""
    codes = set(re.findall(r'\b(?:native|filesystem|classifier|result|profile)_[a-z0-9_-]{1,100}\b', text))
    for framed in re.findall(r'Soup Wall withheld MCP (?:invocation|result) \(([^()]{1,512})\)', text):
        for code in framed.split(', '):
            if re.fullmatch(r'[a-z][a-z0-9_-]{0,99}', code):
                codes.add(code)
    return sorted(codes)[:16]


def qualify(args, door, home, env, report, installed):
    q, base, require = installed.QUAL, installed.BASE, installed.require
    binding_module = installed.load('filesystem_roots_binding', 'pilot_filesystem_roots.py')
    evidence = {'format': 'sw-installed-filesystem-roots-qualification/1', 'status': 'incomplete',
                'source': base.source(), 'cases': [{'id': name, 'attempted': False, 'status': 'incomplete'} for name in CASES]}
    report['filesystem_roots'] = evidence
    def begin(name):
        evidence['active_case'] = name
        evidence['cases'][CASES.index(name)]['attempted'] = True
    def passed(name, **facts):
        evidence['cases'][CASES.index(name)].update(status='passed', **facts)
    def call(target, action, *words, **options):
        code, value, _ = target.call(action, *words, **options)
        evidence['last_cli'] = {'action': action, 'exit': code, 'status': value.get('status'), 'reason': value.get('reason')}
        require(code == 0, 'filesystem_roots_installed_cli_failed')
        return value
    def select(pairs, output, success=True):
        words = [str(args.agentfw), 'pilot', '--home', str(home), 'filesystem-roots']
        for root_id, path in pairs:
            words.extend(['--root', root_id+'='+str(path)])
        result = subprocess.run([*words, '--output', str(output), '--apply'], cwd=door.cwd, env=env,
            stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        require(len(result.stdout) <= 65536, 'filesystem_roots_binding_output_bound')
        value = json.loads(result.stdout)
        require((result.returncode == 0) == success, 'filesystem_roots_binding_unexpected_result')
        if success:
            require(value['binding'] == binding_module.load(output), 'filesystem_roots_binding_changed')
            return value['binding']
        require(not output.exists() and value.get('executed') is False, 'filesystem_roots_refusal_wrote_manifest')

    roots = [args.output / name for name in ('root-alpha', 'root-beta')]
    third = args.output / 'unselected-third'
    for i, root in enumerate(roots):
        root.mkdir(mode=0o700)
        (root/'README.md').write_text('Owned independent read-only root '+str(i)+'.\n')
        (root/'notes').mkdir(mode=0o700)
        (root/'notes'/'fact.txt').write_text('Owned second file in root '+str(i)+'.\n')
    third.mkdir(mode=0o700)
    (third/'canary').write_text('SOU202-UNSELECTED-NEVER-READ')
    pairs = [('alpha', roots[0]), ('beta', roots[1])]
    manifest = args.output/'filesystem-roots-binding.json'
    begin('two-explicit-roots')
    binding = select(pairs, manifest)
    require(binding_module.arguments(binding) == ['/workspace/alpha', '/workspace/beta'], 'filesystem_roots_namespace_changed')
    passed('two-explicit-roots', each_scope='read-only', no_parent_authority=True)
    selected = argparse.Namespace(**vars(args))
    selected.prefix = args.output/'multi-root-prefix'
    selected.other_prefix = args.prefix
    selected.project = roots[0]
    target = type(door)(selected, env, door.cwd, home)
    begin('inert-installed-preview')
    trace = args.output/'filesystem-roots-preview.trace.private'
    value = call(target, 'preview', '--filesystem-roots-binding', manifest, trace=trace)
    observed = q.executed(trace, {k:getattr(args,k) for k in q.SELECTED_PROGRAMS
        if k!='agentfw' and getattr(args,k) is not None})
    require(value['executed'] is False and not value['missing'] and not selected.prefix.exists()
            and not observed['selected_started'] and observed['inet_connects']==0, 'filesystem_roots_preview_effect')
    passed('inert-installed-preview', selected_started=0, network_connections=0)
    begin('prepared-root-custody')
    first = call(target, 'prepare', '--apply', '--filesystem-roots-binding', manifest, timeout=3600)
    second = call(target, 'prepare', '--apply', inputs=False, timeout=900)
    selection = Path(first['selection'])
    require(second.get('status')=='reused' and second['selection']==str(selection)
            and json.loads(selection.read_bytes())['filesystem_roots']==binding, 'filesystem_roots_selection_changed')
    passed('prepared-root-custody', source_bound=True, original_pins_retained=True)
    begin('duplicate-overlap-alias-refusals')
    alias = args.output/'alias'; alias.symlink_to(third, target_is_directory=True)
    for i, invalid in enumerate((pairs+[('gamma',roots[0])], [('alpha',roots[0]),('beta',roots[0]/'notes')],
                                [('alpha',roots[0]),('alpha',roots[1])], [('alpha',roots[0]),('beta',alias)])):
        select(invalid, args.output/('refused-binding-'+str(i)+'.json'), success=False)
    alias.unlink()
    passed('duplicate-overlap-alias-refusals', original_started=False)
    def refused_run(label):
        trace = args.output/(label+'.trace.private')
        code,value,_=target.call('run','--state-root',args.state_root,inputs=False,trace=trace,timeout=180)
        observed=q.executed(trace,{k:getattr(args,k) for k in q.SELECTED_PROGRAMS if k!='agentfw' and getattr(args,k) is not None})
        require(code!=0 and not observed['selected_started'] and observed['inet_connects']==0,
                'filesystem_roots_stale_admission_executed')
    begin('missing-replaced-root-refusals')
    retained=args.output/'retained-beta'
    roots[1].rename(retained)
    try:
        refused_run('missing-root')
        roots[1].mkdir(mode=0o700)
        try: refused_run('replaced-root')
        finally: roots[1].rmdir()
    finally:
        retained.rename(roots[1])
    passed('missing-replaced-root-refusals', original_started=False)
    begin('cross-profile-refusal')
    profile=selection.parent/'filesystem-profile/profile.json'; raw=profile.read_bytes(); mode=profile.stat().st_mode&0o777
    profile.chmod(0o600)
    try:
        profile.write_bytes(raw.replace(binding_module.PROFILE.encode(),b'sw-mcp/filesystem-readonly/1'))
        refused_run('cross-profile')
    finally:
        profile.write_bytes(raw);profile.chmod(mode)
    passed('cross-profile-refusal', original_started=False)
    baseline=[q.snapshot(path) for path in (*roots,third,args.project,args.repository)]
    begin('useful-original-read-list-search')
    proposals=[
        ('mcp__filesystem__read_text_file',{'path':'/workspace/alpha/README.md'}),
        ('mcp__filesystem__read_text_file',{'path':'/workspace/beta/README.md'}),
        ('mcp__filesystem__list_directory',{'path':'/workspace/alpha'}),
        ('mcp__filesystem__list_directory',{'path':'/workspace/beta'}),
        ('mcp__filesystem__search_files',{'path':'/workspace/alpha','pattern':'**/*.txt'}),
        ('mcp__filesystem__search_files',{'path':'/workspace/beta','pattern':'**/*.txt'}),
        ('mcp__filesystem__read_multiple_files',{'paths':['/workspace/alpha/README.md','/workspace/beta/README.md']}),
        ('mcp__filesystem__read_multiple_files',{'paths':['/workspace/alpha/README.md','/workspace/unselected/canary']}),
        ('mcp__filesystem__read_text_file',{'path':str(third/'canary')}),
        ('mcp__filesystem__list_directory',{'path':'/workspace'}),
        ('mcp__filesystem__read_text_file',{'path':'/workspace/alpha/../beta/README.md'}),
        ('mcp__filesystem__read_text_file',{'path':'/workspace/beta/README.md'}),
    ]
    trace=args.output/'filesystem-roots-runtime.trace.private'
    trace.touch(mode=0o600,exist_ok=False)
    row,results,outcome=q.run_case(selected,target,report,'multi-roots',proposals,
                                  provider_trace=trace,diagnostic_writes=True)
    # This trace stays private. Only bounded stderr error chunks over these
    # synthetic inputs enter the public report; credential-bearing exec/HTTP
    # writes are never copied. Opaque tokens and owned host paths are redacted.
    collectors={}; tails={}
    with trace.open(errors='replace') as stream:
        for line in stream:
            pid=re.match(r'^\s*(\d+)\s+',line)
            if pid is None: continue
            pid=pid[1]
            if re.search(r'\bexecve(?:at)?\(',line) and '"mcp", "--id", "filesystem"' in line:
                collectors[pid]='filesystem'
            if pid not in collectors or not re.search(r'\bwrite(?:v)?\(2,',line): continue
            match=re.search(r'\bwrite\(2,\s*("(?:\\.|[^"\\])*")',line)
            fragments=[match[1]] if match else re.findall(r'iov_base=("(?:\\.|[^"\\])*")',line)
            for quoted in fragments:
                try: fragment=ast.literal_eval(quoted)
                except (ValueError,SyntaxError): continue
                tails[pid]=(tails.get(pid,'')+fragment)[-65536:]
    failures=[]
    for pid,text in tails.items():
        start=text.rfind('Error: ')
        if start < 0: continue
        text=text[start:start+2048]
        for path in (str(selected.prefix),str(args.output),str(args.agentfw)):
            text=text.replace(path,'<owned-input>')
        text=re.sub(r'[A-Za-z0-9_+/-]{32,}','<opaque>',text)
        failures.append({'server':collectors[pid],'error':text})
    evidence['collector_failures']=failures[:2]
    evidence['last_run']={key:row.get(key) for key in ('exit','status','reason','live_status','process_cleanup')}
    evidence['last_run']['stage']=outcome.get('stage')
    # Compare the accepted sibling even when a new-profile result fails, so an
    # existing transport failure cannot be mislabeled as a root-binding defect.
    begin('single-root-sibling-retained')
    sibling,sibling_results,_=q.run_case(args,door,report,'single-root-sibling',[
        ('mcp__filesystem__read_text_file',{'path':'/workspace/README.md'})])
    sibling_passed=(sibling['exit']==0 and sibling['live_status'].get('protection')=='observed-live'
        and sibling_results.get('toolu_front_single-root-sibling_0',{}).get('is_error') is False
        and q.README.strip() in json.dumps(sibling_results))
    evidence['sibling_control']={'passed':sibling_passed,'exit':sibling['exit'],
        'live_status':sibling['live_status'],'process_cleanup':sibling['process_cleanup'],
        'result_errors':{key:value['is_error'] for key,value in sibling_results.items()}}
    if sibling_passed: passed('single-root-sibling-retained', original_default=True, observed_live=True)
    begin('useful-original-read-list-search')
    labels = ('Soup Wall withheld MCP result', 'Soup Wall withheld MCP invocation',
              'MCP arguments violate the selected input profile', 'Filesystem resource root',
              'MCP path refused before execution', 'ENOENT', 'EACCES', 'ENOTDIR', 'EISDIR')
    evidence['result_boundaries'] = {}
    for identifier, result in results.items():
        text = json.dumps(result.get('content'), ensure_ascii=True)
        codes = reported_refusal_codes(text)
        evidence['result_boundaries'][identifier] = {
            'is_error':result['is_error'], 'fixed_messages':[label for label in labels if label in text],
            'reason_codes':codes[:16], 'content_sha256':hashlib.sha256(text.encode()).hexdigest()}
    evidence['owned_first_errors'] = {}
    for identifier in ('toolu_front_multi-roots_0','toolu_front_multi-roots_1','toolu_front_multi-roots_11'):
        if identifier in results and results[identifier]['is_error']:
            text=json.dumps(results[identifier]['content'],ensure_ascii=True)[:1024]
            for path in (str(selected.prefix),str(args.output)):
                text=text.replace(path,'<owned-input>')
            evidence['owned_first_errors'][identifier]=re.sub(r'[A-Za-z0-9_+/-]{32,}','<opaque>',text)
    evidence['post_run_sources_unchanged'] = baseline == [q.snapshot(path) for path in (*roots,third,args.project,args.repository)]
    evidence['processes_stopped'] = row['process_cleanup']['all_stopped'] and sibling['process_cleanup']['all_stopped']
    require(row['exit']==0 and row['live_status'].get('protection')=='observed-live', 'filesystem_roots_live_host_unverified')
    ids=['toolu_front_multi-roots_'+str(i) for i in range(len(proposals))]
    require(set(results)==set(ids), 'filesystem_roots_correlated_results_missing')
    for i in (*range(7),11):
        require(results[ids[i]]['is_error'] is False, 'filesystem_roots_useful_original_result_refused')
    for i in (0,1):
        require('Owned independent read-only root '+str(i) in json.dumps(results[ids[i]]), 'filesystem_roots_read_content_missing')
    for i in (2,3): require('README.md' in json.dumps(results[ids[i]]), 'filesystem_roots_list_content_missing')
    for i in (4,5): require('fact.txt' in json.dumps(results[ids[i]]), 'filesystem_roots_search_content_missing')
    require('Owned independent read-only root 0' in json.dumps(results[ids[6]])
            and 'Owned independent read-only root 1' in json.dumps(results[ids[6]]), 'filesystem_roots_multi_read_missing')
    passed('useful-original-read-list-search', observed_live=True, original_bytes=True)
    begin('whole-call-cross-root-refusals')
    for i in (7,8,9,10): require(results[ids[i]]['is_error'] is True, 'filesystem_roots_unselected_resource_accepted')
    require('Owned independent read-only root' not in json.dumps(results[ids[7]])
            and 'SOU202-UNSELECTED-NEVER-READ' not in json.dumps(results), 'filesystem_roots_partial_or_unselected_content_released')
    passed('whole-call-cross-root-refusals', no_partial_first_path=True, healthy_followup=True)
    require(evidence['sibling_control']['passed'], 'filesystem_roots_sibling_behavior_changed')
    begin('source-preservation')
    require(baseline==[q.snapshot(path) for path in (*roots,third,args.project,args.repository)],'filesystem_roots_source_changed')
    passed('source-preservation', selected_and_unselected_unchanged=True)
    begin('owned-process-cleanup')
    require(row['process_cleanup']['all_stopped'] and sibling['process_cleanup']['all_stopped'], 'filesystem_roots_cleanup_unverified')
    passed('owned-process-cleanup', all_stopped=True)
    evidence.update(status='passed',source_after=base.source())
    require(evidence['source']==evidence['source_after'] and all(row['attempted'] and row['status']=='passed'
            for row in evidence['cases']), 'filesystem_roots_incomplete_evidence')
    report['cases'].extend({'case':row['id'],'passed':True} for row in evidence['cases'])
