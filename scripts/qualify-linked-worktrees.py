# SPDX-License-Identifier: Apache-2.0
"""Owned installed linked-worktree qualification; never a shared Ready matrix."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import threading

CASES = ('two-explicit-bindings', 'inert-installed-preview', 'two-prepared-selections',
         'stale-head-refusal', 'redirected-gitfile-refusal', 'cross-profile-refusal',
         'concurrent-original-reads', 'correlated-cross-root-refusals', 'source-preservation',
         'owned-process-cleanup', 'default-selection-retained')


def namespace_observation(output):
    # libtest may print the test name and "... " before a nocapture JSON line.
    for line in output.splitlines():
        start=line.find('{')
        if start < 0: continue
        try: value=json.loads(line[start:])
        except ValueError: continue
        if isinstance(value,dict) and value.get('event')=='sou201_original_mcp_namespace_probe':
            return value
    return None


def qualify(args, door, home, env, report, installed):
    q, base, require = installed.QUAL, installed.BASE, installed.require
    linked = installed.load('linked_qualification_binding', 'pilot_linked_worktree.py')
    evidence = {'format': 'sw-installed-linked-worktrees-qualification/1', 'status': 'incomplete',
                'source': base.source(), 'cases': [{'id': n, 'attempted': False, 'status': 'incomplete'} for n in CASES]}
    report['linked_worktrees'] = evidence
    def begin(name):
        evidence['active_case'] = name
        evidence['cases'][CASES.index(name)]['attempted'] = True
    def passed(name, **facts):
        evidence['cases'][CASES.index(name)].update(status='passed', **facts)
    def command(*words):
        subprocess.run([str(args.git), *map(str, words)], cwd=door.cwd, env=env,
                       check=True, capture_output=True, timeout=30)
    def checked(target, action, *words, **options):
        code, value, _ = target.call(action, *words, **options)
        evidence['last_cli'] = {'action': action, 'exit': code, 'status': value.get('status'), 'reason': value.get('reason')}
        require(code == 0, 'linked_worktree_installed_cli_failed')
        return value

    primary = args.output / 'linked-common-repository'
    command('init', '-q', '-b', 'main', primary)
    (primary / 'tracked.txt').write_text('Owned common initial content.\n')
    command('-C', primary, 'add', 'tracked.txt')
    command('-C', primary, 'commit', '-qm', 'Owned common history')
    workspaces = [args.output / 'linked-one', args.output / 'linked-two']
    bindings = []; manifests = []; targets = []; roots = []; selections = []
    events = [threading.Event(), threading.Event()]
    class ConcurrentDoor(type(door)):
        def call(self, action, *words, **options):
            result = super().call(action, *words, **options)
            if action == 'status' and result[1].get('protection') == 'observed-live':
                events[self.ordinal].set()
                require(events[1-self.ordinal].wait(120), 'linked_worktree_concurrent_peer_missing')
            return result
    begin('two-explicit-bindings')
    for i, workspace in enumerate(workspaces):
        command('-C', primary, 'worktree', 'add', '-q', '-b', 'owned-'+str(i), workspace)
        (workspace / 'tracked.txt').write_text('Owned independent worktree '+str(i)+'.\n')
        command('-C', workspace, 'add', 'tracked.txt')
        command('-C', workspace, 'commit', '-qm', 'Owned independent branch '+str(i))
    # Bind only after all fixture writes, so either source changing later fails.
    for i, workspace in enumerate(workspaces):
        path = args.output / ('linked-binding-'+str(i)+'.json')
        result = subprocess.run([str(args.agentfw), 'pilot', '--home', str(home), 'worktree-selection',
            '--workspace', str(workspace), '--git-dir', str(primary / '.git/worktrees' / workspace.name),
            '--common-dir', str(primary / '.git'), '--output', str(path), '--apply'],
            cwd=door.cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        require(result.returncode == 0 and len(result.stdout) <= 16384, 'linked_worktree_installed_binding_failed')
        binding = json.loads(result.stdout)['binding']
        require(binding == linked.load(path, workspace), 'linked_worktree_installed_binding_mismatch')
        bindings.append(binding); manifests.append(path)
        state = args.output / ('linked-run-state-'+str(i)); state.mkdir(mode=0o700)
        selected = argparse.Namespace(**vars(args))
        selected.prefix = args.output / ('linked-prefix-'+str(i))
        selected.other_prefix = args.output / ('linked-prefix-'+str(1-i))
        selected.project = workspace; selected.repository = workspace; selected.state_root = state
        target = ConcurrentDoor(selected, env, door.cwd, home); target.ordinal = i
        targets.append(target); roots.append(selected)
    require(bindings[0]['inputsSha256'] != bindings[1]['inputsSha256'], 'linked_worktree_branch_binding_reused')
    passed('two-explicit-bindings', separate_index_and_head=True, explicit_common_root=True)
    begin('inert-installed-preview')
    for i, target in enumerate(targets):
        trace = args.output / ('linked-preview-'+str(i)+'.trace.private')
        value = checked(target, 'preview', '--git-profile', linked.ID, '--git-worktree-binding', manifests[i], trace=trace)
        observed = q.executed(trace, {k: getattr(args, k) for k in q.SELECTED_PROGRAMS if k != 'agentfw' and getattr(args, k) is not None})
        require(value['executed'] is False and not value['missing'] and not roots[i].prefix.exists()
                and not observed['selected_started'] and observed['inet_connects'] == 0, 'linked_worktree_preview_effect')
    passed('inert-installed-preview', selected_started=0, network_connections=0)
    begin('two-prepared-selections')
    for i, target in enumerate(targets):
        value = checked(target, 'prepare', '--apply', '--git-profile', linked.ID,
                        '--git-worktree-binding', manifests[i], timeout=3600)
        selections.append(Path(value['selection']))
        checked(target, 'prepare', '--apply', inputs=False)
        selection = json.loads(selections[-1].read_bytes())
        require(selection['linked_worktree'] == bindings[i], 'linked_worktree_selection_binding_changed')
    # The ordinary snapshot tests do not exercise the actual mount projection.
    # Probe that exact installed original MCP server before genuine host startup.
    probe_env=dict(env,SOU86_TEST_AGENTFW=str(args.agentfw),
                   SOU201_TEST_PROFILE=str(selections[0].parent/'git-profile/profile.json'))
    probe=subprocess.run([str(args.sandbox_tests),
        'mcp::server_profile::git::linked_worktree::original_mcp_probe::linked_worktree_original_mcp_initializes_inside_native_namespace',
        '--exact','--ignored','--nocapture','--test-threads=1'],cwd=door.cwd,env=probe_env,
        stdin=subprocess.DEVNULL,capture_output=True,timeout=120)
    # No credentials or real source data enter this test-only namespace probe.
    # It emits a bounded diagnostic over owned synthetic inputs only.
    probe_output=probe.stdout.decode('utf-8','replace')
    evidence['namespace_probe']={'exit':probe.returncode,'reported':False}
    observation=namespace_observation(probe_output)
    if observation is not None:
        evidence['namespace_probe'].update(reported=True,observation=observation)
    if probe.returncode != 0 and not evidence['namespace_probe']['reported']:
        diagnostic=(probe.stdout+probe.stderr)[:4096].decode('utf-8','replace')
        for path in (str(args.agentfw),str(args.sandbox_tests),str(selections[0].parent),
                     str(workspaces[0]),str(primary)):
            diagnostic=diagnostic.replace(path,'<owned-selected-input>')
        evidence['namespace_probe']['owned_probe_diagnostic']=diagnostic
    require(probe.returncode==0 and evidence['namespace_probe']['reported'], 'linked_worktree_original_namespace_startup_failed')
    passed('two-prepared-selections', source_bound=True, original_namespace_initialized=True)
    def refuse(name, path, mutation):
        begin(name)
        raw = path.read_bytes(); mode = path.stat().st_mode & 0o777
        path.chmod(0o600); path.write_bytes(mutation(raw))
        try:
            trace = args.output / (name+'.trace.private')
            code, value, _ = targets[0].call('run', '--state-root', roots[0].state_root,
                                            inputs=False, trace=trace, timeout=180)
            evidence['last_cli'] = {'action': 'refused-run', 'exit': code, 'reason': value.get('reason')}
            observed = q.executed(trace, {k: getattr(args, k) for k in q.SELECTED_PROGRAMS if k != 'agentfw' and getattr(args, k) is not None})
            require(code != 0 and not observed['selected_started'] and observed['inet_connects'] == 0,
                    'linked_worktree_stale_admission_executed')
        finally:
            path.write_bytes(raw); path.chmod(mode)
        passed(name, original_started=False, network_connections=0)
    refuse('stale-head-refusal', Path(bindings[0]['gitDir']['path'])/'HEAD', lambda _: b'ref: refs/heads/owned-1\n')
    refuse('redirected-gitfile-refusal', workspaces[0]/'.git', lambda _: b'gitdir: /unselected/never-open\n')
    refuse('cross-profile-refusal', selections[0].parent/'git-profile/profile.json',
           lambda raw: raw.replace(linked.PROFILE.encode(), b'sw-mcp/git-readonly/1'))
    baseline = [q.snapshot(p) for p in (primary, *workspaces, args.project, args.repository)]
    sentinel = args.output / 'unselected-sibling'; sentinel.mkdir(mode=0o700)
    (sentinel/'canary').write_text('SOU201-UNSELECTED-NEVER-READ')
    before_sibling = q.snapshot(sentinel)
    begin('concurrent-original-reads')
    def run(i):
        proposals = [
            ('mcp__git__git_status', {'repo_path': '/workspace'}),
            ('mcp__git__git_log', {'repo_path': '/workspace', 'max_count': 2}),
            ('mcp__git__git_show', {'repo_path': '/workspace', 'revision': 'HEAD'}),
            ('mcp__git__git_status', {'repo_path': str(workspaces[1-i])}),
            ('mcp__git__git_status', {'repo_path': str(sentinel)}),
            ('mcp__git__git_status', {'repo_path': '/workspace'}),
        ]
        return q.run_case(roots[i], targets[i], report, 'linked'+str(i), proposals)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run, i) for i in range(2)]
        runs = [f.result() for f in futures]
    evidence['last_runs'] = [{key: row.get(key) for key in ('case', 'exit', 'status', 'reason', 'cleanup', 'live_status', 'process_cleanup')}
                             | {'stage': outcome.get('stage'), 'host_started': outcome.get('host_started'),
                                'executed': outcome.get('executed')} for row, _, outcome in runs]
    for i, (row, results, outcome) in enumerate(runs):
        require(row['exit'] == 0 and row['live_status'].get('protection') == 'observed-live', 'linked_worktree_live_host_unverified')
        require(len(results) == 6, 'linked_worktree_correlated_results_missing')
        for index in (0, 1, 2, 5):
            require(results['toolu_front_linked'+str(i)+'_'+str(index)]['is_error'] is False,
                    'linked_worktree_useful_original_result_refused')
        require('owned-'+str(i) in json.dumps(results['toolu_front_linked'+str(i)+'_0']), 'linked_worktree_branch_status_missing')
        require('Owned independent branch '+str(i) in json.dumps(results['toolu_front_linked'+str(i)+'_1']), 'linked_worktree_log_content_missing')
        require('Owned independent worktree '+str(i) in json.dumps(results['toolu_front_linked'+str(i)+'_2']), 'linked_worktree_revision_content_missing')
        require('SOU201-UNSELECTED-NEVER-READ' not in json.dumps(results), 'linked_worktree_unselected_content_released')
    require(runs[0][2]['identity']['native_instance'] != runs[1][2]['identity']['native_instance'], 'linked_worktree_authority_reused')
    passed('concurrent-original-reads', two_observed_live=True, useful_status_log_revision=True)
    begin('correlated-cross-root-refusals')
    for i, (_, results, _) in enumerate(runs):
        for index in (3, 4):
            require(results['toolu_front_linked'+str(i)+'_'+str(index)]['is_error'] is True, 'linked_worktree_cross_authority_accepted')
    passed('correlated-cross-root-refusals', healthy_followup=True)
    begin('source-preservation')
    require(baseline == [q.snapshot(p) for p in (primary, *workspaces, args.project, args.repository)]
            and before_sibling == q.snapshot(sentinel), 'linked_worktree_source_changed')
    passed('source-preservation', common_and_worktrees_unchanged=True, unselected_sibling_unchanged=True)
    begin('owned-process-cleanup')
    require(all(row['process_cleanup']['all_stopped'] for row, _, _ in runs), 'linked_worktree_cleanup_unverified')
    passed('owned-process-cleanup', all_stopped=True)
    begin('default-selection-retained')
    previous = checked(door, 'status', '--state-root', args.state_root, inputs=False)
    require(previous['protection'] == 'configured-not-running', 'linked_worktree_default_selection_changed')
    passed('default-selection-retained', explicit_old_prefix_usable=True)
    evidence.update(status='passed', source_after=base.source())
    require(evidence['source'] == evidence['source_after'] and all(r['attempted'] and r['status'] == 'passed' for r in evidence['cases']),
            'linked_worktree_incomplete_evidence')
    report['cases'].extend({'case': r['id'], 'passed': True} for r in evidence['cases'])
