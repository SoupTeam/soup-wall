# SPDX-License-Identifier: Apache-2.0
"""Source-bound installed maintenance witnesses; owned synthetic inputs only."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

CASES = ('readonly-preview', 'useful-before-enter', 'existing-run-draining',
         'entered-new-run-refused', 'sibling-independent', 'stale-leave-refused',
         'fresh-leave', 'existing-useful-after-enter', 'new-useful-after-leave',
         'same-bytes-marker-replaced', 'partial-transition-refused', 'dead-owner-uncertain')


def passed(value):
    return (type(value) is dict and value.get('format') == 'sw-pilot-maintenance-qualification/1'
            and value.get('platform') == 'native-linux' and value.get('executed') is True
            and value.get('expected') == list(CASES)
            and re.fullmatch(r'[0-9a-f]{40}', value.get('source', '')) is not None
            and re.fullmatch(r'[0-9a-f]{64}', value.get('binary_sha256', '')) is not None
            and [r.get('id') for r in value.get('cases', [])] == list(CASES)
            and all(r.get('passed') is True and r.get('attempted') is True for r in value['cases'])
            and value.get('source_unchanged') is True and value.get('project_unchanged') is True
            and value.get('receiver_requests') == 0 and type(value.get('receiver_requests')) is int)


def qualify(args, door, home, env, report, *, guided, install_sibling, receiver, baseline):
    require = guided.require
    result = {'format': 'sw-pilot-maintenance-qualification/1', 'executed': True,
              'platform': 'native-linux', 'source': args.expected_commit,
              'binary_sha256': guided.BASE.sha(args.agentfw), 'expected': list(CASES), 'cases': []}
    report['maintenance'] = result
    observations = {}
    def record(label, **fields): observations[label] = dict(id=label, attempted=True, passed=True, **fields)

    def call(action, *extra, success=True, selected_home=home, trace=False):
        words = [str(args.agentfw), 'pilot', '--home', str(selected_home), 'maintenance', action,
                 '--prefix', str(args.prefix), '--state-root', str(args.state_root), *map(str, extra)]
        return invoke(words, success=success, trace=trace)

    def invoke(words, *, success, trace=False, run_env=None):
        trace_path = args.output / ('maintenance-' + str(len(list(args.output.glob('maintenance-*.trace.private')))) + '.trace.private')
        if trace:
            words = [str(args.strace), '-f', '-qq', '-s', '4096', '-e', 'trace=execve,connect', '-o', str(trace_path), *words]
        process = subprocess.run(words, cwd=door.cwd, env=run_env or env, stdin=subprocess.DEVNULL,
                                 capture_output=True, timeout=180)
        require((process.returncode == 0) is success, 'maintenance_unexpected_exit')
        value = json.loads(process.stdout.decode().splitlines()[-1])
        if trace:
            observed = guided.executed(trace_path, {k: getattr(args, k) for k in ('claude',)})
            agent_count = sum('execve("' + str(args.agentfw) + '"' in line for line in trace_path.read_text().splitlines())
            require(not observed['selected_started'] and observed['inet_connects'] == 0
                    and agent_count == 1, 'maintenance_refusal_executed_protected_process')
        return value

    def refused(label):
        before = receiver.count
        words = door.words('run', '--state-root', args.state_root, '--timeout-seconds', '120', inputs=False)
        value = invoke(words, success=False, trace=True)
        require(value.get('executed') is False and value.get('host_started') is not True
                and receiver.count == before, 'maintenance_refusal_effect')
        record(label, protected_process_starts=0, provider_connects=0)

    from_hash = guided.snapshot(home)
    preview = call('preview', '--operation', 'enter', trace=True)
    require(preview['mode'] == 'not-enrolled' and guided.snapshot(home) == from_hash,
            'maintenance_preview_mutated_home')
    record('readonly-preview', selected_starts=0, inet_connects=0)
    sibling = args.output / 'sibling-agent-home'; sibling.mkdir(mode=0o700)
    sibling_door = install_sibling(sibling)
    useful = [('mcp__filesystem__read_text_file', {'path': '/workspace/README.md'}),
              ('mcp__git__git_show', {'repo_path': '/workspace', 'revision': 'HEAD'})]
    errors = []
    def during(model):
        try:
            record('useful-before-enter', useful_results=len(model.results))
            old = call('preview', '--operation', 'leave')
            enter = call('preview', '--operation', 'enter')
            entered = call('enter', '--confirm', enter['confirmation_sha256'])
            require(entered['status'] == 'entered', 'maintenance_enter_failed')
            state = call('status')
            require(state['mode'] == 'entered' and state['drain'] == 'draining'
                    and state['inventory']['active'] >= 1, 'maintenance_false_drain')
            record('existing-run-draining', active=state['inventory']['active'])
            refused('entered-new-run-refused')
            row, results, _ = guided.run_case(args, sibling_door, report, 'maintenance_sibling', useful)
            require(row['exit'] == 0 and row['process_cleanup']['all_stopped']
                    and len(results) == 2 and all(not r['is_error'] for r in results.values()),
                    'maintenance_affected_sibling')
            record('sibling-independent', useful_results=2, all_stopped=True)
            call('leave', '--confirm', old['confirmation_sha256'], success=False)
            require(call('status')['mode'] == 'entered', 'maintenance_stale_leave_cleared_mode')
            record('stale-leave-refused')
            fresh = call('preview', '--operation', 'leave')
            require(call('leave', '--confirm', fresh['confirmation_sha256'])['status'] == 'left',
                    'maintenance_leave_failed')
            record('fresh-leave')
        except Exception:
            errors.append('maintenance_live_callback_failed')
            raise

    row, results, _ = guided.run_case(args, door, report, 'maintenance_old', useful, after_useful=during)
    require(not errors and row['exit'] == 0 and row['process_cleanup']['all_stopped'] and len(results) == 2
            and all(not r['is_error'] for r in results.values()), 'maintenance_existing_host_not_preserved')
    record('existing-useful-after-enter', useful_results=2, all_stopped=True)
    row, results, _ = guided.run_case(args, door, report, 'maintenance_restored', useful)
    require(row['exit'] == 0 and row['process_cleanup']['all_stopped'] and len(results) == 2
            and all(not r['is_error'] for r in results.values()), 'maintenance_leave_did_not_restore_useful_run')
    record('new-useful-after-leave', useful_results=2, all_stopped=True)

    marker = home / 'pilot-maintenance/marker.json'
    held = marker.with_name('marker.held.private'); marker.rename(held)
    marker.write_bytes(held.read_bytes()); marker.chmod(0o600)
    try: refused('same-bytes-marker-replaced')
    finally:
        marker.unlink(); held.rename(marker)
    pending = home / 'pilot-maintenance/pending.json'
    pending.write_bytes(b'{"partial":'); pending.chmod(0o600)
    try: refused('partial-transition-refused')
    finally: pending.unlink()

    # A real independent Linux process durably claims admission, then exits
    # without the accepted cleanup. No PID-list inference may clear that intent.
    current = json.loads(marker.read_bytes())
    bound = current['binding']
    crashed = args.state_root / 'soup-wall-run-crashed-owner'; crashed.mkdir(mode=0o700)
    tree = home / 'pilot-front-door/components' / report['component']['component'] / 'tree'
    program = '''import importlib.util,sys,os,json
from pathlib import Path
spec=importlib.util.spec_from_file_location('owned_crash_claim',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with m.M.Store(sys.argv[2]) as store,store.locked(exclusive=True):
 bound=json.loads((Path(sys.argv[2])/'pilot-maintenance/marker.json').read_bytes())['binding']
 m.claim(store,bound,Path(sys.argv[3]))
os._exit(97)
'''
    crashed_result = subprocess.run([str(args.component_python), '-I', '-B', '-c', program,
        str(tree / 'scripts/pilot_maintenance_launch.py'), str(home), str(crashed)],
        cwd=door.cwd, env=env, capture_output=True, timeout=30)
    require(crashed_result.returncode == 97, 'maintenance_crash_fixture_failed')
    state = call('status')
    require(state['drain'] == 'uncertain' and state['inventory']['uncertain'], 'maintenance_dead_owner_reported_drained')
    refused('dead-owner-uncertain')
    require(receiver.count == 0, 'maintenance_receiver_effect')
    result.update(cases=[observations[label] for label in CASES], receiver_requests=receiver.count,
                  source_unchanged=guided.BASE.source()['commit'] == args.expected_commit,
                  project_unchanged=guided.snapshot(args.project) == baseline['project']
                    and guided.snapshot(args.repository) == baseline['repository'])
    require(passed(result), 'maintenance_qualification_incomplete')
