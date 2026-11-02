# SPDX-License-Identifier: Apache-2.0
"""Owned installed Linux budget-preset qualification, called by the installed driver.

Everything runs through the installed `agentfw pilot` front door against owned synthetic
projects, a scripted loopback provider and a disposable delegated systemd service. The
qualifier never repairs delegation for the product: it creates the disposable roots itself
before any preset can name them.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import threading

CASES = ('inert-preview', 'two-independent-presets', 'bounds-refused', 'unverified-delegation-refused',
         'stale-update-refused', 'concurrent-update', 'damaged-store', 'two-budgeted-reads',
         'controller-limit-witness', 'update-during-run', 'stale-profile-zero-start',
         'unavailable-delegation-zero-start', 'root-replaced-refused', 'unnamed-run-preset',
         'unnamed-stale-zero-start', 'owned-cleanup')
LIMITS = {'memoryMaxBytes': 536_870_912, 'pidsMax': 128, 'cpuQuotaMicros': 100_000, 'wallMillis': 120_000}


def qualify(args, door, home, env, report, first, installed, receiver):
    q, base, require = installed.QUAL, installed.BASE, installed.require
    budgets = installed.load('qualification_budget_presets', 'pilot_budget_presets.py')
    profiles = installed.load('qualification_budget_providers', 'pilot_provider_profiles.py')
    resource = installed.load('qualification_budget_resources', 'verify-sou79-resource-budgets.py')
    env = {k: v for k, v in env.items() if k not in profiles.PROVIDER.KEYS}
    rows = [{'id': n, 'status': 'incomplete', 'attempted': False} for n in CASES]
    evidence = {'format': 'sw-installed-budget-presets-qualification/1', 'status': 'incomplete',
                'source': base.source(), 'expected': list(CASES), 'cases': rows}
    report['budget_presets'] = evidence

    def begin(name):
        evidence['active_case'] = name
        rows[CASES.index(name)]['attempted'] = True

    def finish(name, **facts):
        rows[CASES.index(name)].update(status='passed', **facts)

    def run_cli(group, words, expected=0, trace=None):
        command = [str(args.agentfw), 'pilot', '--home', str(home), group, *map(str, words)]
        if trace is not None:
            command = [str(args.strace), '-f', '-qq', '-s', '256', '-e', 'trace=execve,connect', '-o', str(trace), *command]
        result = subprocess.run(command, cwd=door.cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=180)
        require(len(result.stdout) <= 65536 and len(result.stderr) <= 16384, 'budget_cli_output_bound')
        require(all(c.encode() not in result.stdout + result.stderr for c in canaries), 'budget_public_output_canary')
        value = json.loads(result.stdout.splitlines()[-1])
        reason = value.get('reason')
        evidence['last_cli'] = {'group': group, 'action': words[0], 'exit': result.returncode, 'expected_exit': expected,
                                'reason': reason if isinstance(reason, str) and re.fullmatch(r'[a-z0-9_:-]{1,160}', reason) else None}
        require(result.returncode == expected, 'budget_cli_exit')
        return value

    def preset(words, expected=0, trace=None):
        return run_cli('budget-preset', words, expected, trace)

    def project(words, expected=0, trace=None):
        return run_cli('project', words, expected, trace)

    def limits_words(root, **override):
        values = dict(LIMITS, **override)
        return ['--agentfw', args.agentfw, '--root', root, '--memory-max-bytes', values['memoryMaxBytes'],
                '--pids-max', values['pidsMax'], '--cpu-quota-micros', values['cpuQuotaMicros'],
                '--wall-millis', values['wallMillis']]

    def config(root, **override):
        return dict({'format': budgets.CONFIG_FORMAT, 'delegationRoot': str(root)}, **dict(LIMITS, **override))

    def create(name, root, **override):
        sha = budgets.config_identity(config(root, **override))
        return preset(['create', '--name', name, *limits_words(root, **override), '--expected-config-sha256', sha, '--apply'])

    def no_selected_start(trace):
        observed = q.executed(trace, {k: getattr(args, k) for k in q.SELECTED_PROGRAMS
                                      if getattr(args, k, None) is not None and k != 'agentfw'})
        require(not observed['selected_started'] and observed['inet_connects'] == 0, 'budget_refusal_started_selected_program')
        return observed

    def leaves(root):
        return sorted(p for p in Path(root).iterdir() if p.is_dir())

    def empty(root):
        return not leaves(root) and not (Path(root) / 'cgroup.procs').read_text().strip()

    models = [base.DEMO.ScriptedModel([]), base.DEMO.ScriptedModel([])]
    canaries = ['SOU210-OWNED-PROVIDER-A-7c41', 'SOU210-OWNED-PROVIDER-B-2e9d']
    processes, witnesses, streams, release = [], [], [], threading.Event()
    try:
        # Disposable acceptance substrate: the product never creates roots or changes delegation.
        delegated, delegation = resource.prepare_delegation(args.budget_unit)
        require(delegation['unprivileged'] and delegation['controllers'] == ['cpu', 'memory', 'pids'], 'budget_delegation_unavailable')
        parent = delegated.parent
        roots = [delegated]
        for label in ('peer-budgets', 'third-budgets'):
            extra = parent / label
            extra.mkdir(mode=0o700)
            (extra / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
            roots.append(extra)
        undelegated = parent / 'undelegated'
        undelegated.mkdir(mode=0o700)

        second = argparse.Namespace(**vars(args))
        second.project = args.output / 'second-project'
        second.repository = args.output / 'second-repository'
        second.prefix = args.other_prefix
        q.make_projects(second, q.qualification_environment(args.output / 'home'), receiver)
        texts = ['Owned budget project A read witness.\n', 'Owned budget project B read witness.\n']
        for p, text in zip((args.project, second.project), texts):
            (p / 'README.md').write_text(text)
        other = type(door)(second, env, door.cwd, home)
        code, prepared, _ = other.call('prepare', '--apply', timeout=3600)
        require(code == 0 and prepared['status'] == 'prepared-not-active', 'second_project_prepare_failed')
        selections = [first, Path(prepared['selection'])]
        baseline = [q.snapshot(p) for p in (args.project, args.repository, second.project, second.repository)]
        states, versions, digests = [], [], {}
        for i, name in enumerate(('one', 'two')):
            state = args.output / ('budget-state-' + str(i))
            state.mkdir(mode=0o700)
            states.append(state)
            with profiles.Store(home, create=True) as provider:
                provider.create(name, {'model': 'owned-initial', 'ANTHROPIC_BASE_URL': models[i].url},
                                {'ANTHROPIC_API_KEY': canaries[i]})
                index = provider.index()
                current = 'legacy' if index is None else index['profiles'][name]['current']
                provider.update(name, {'model': 'claude-sonnet-4-20250514'}, None, current)
                versions.append(provider.index()['profiles'][name]['current'])

        def project_words(i, name, budget):
            return ['--name', name, '--selection', selections[i], '--provider-name', ('one', 'two')[i],
                    '--provider-version', versions[i], '--state-root', states[i], '--budget-preset', budget]

        begin('inert-preview')
        before = q.snapshot(home)
        trace = args.output / 'budget-preview.trace.private'
        sha = budgets.config_identity(config(roots[0]))
        preview = preset(['create', '--name', 'one', *limits_words(roots[0])], trace=trace)
        require(preview['status'] == 'preview' and preview['mutates'] is False and preview['new_config_sha256'] == sha
                and preview['authority'] is False and preview['observed_protection'] == 'not-observed', 'budget_preview_claims')
        no_selected_start(trace)
        # The wrapper plus its one strict-validator child; no probe, cgroup, host or network.
        require(installed.agent_executions(trace, args.agentfw) == 2 and before == q.snapshot(home)
                and not (home / budgets.DIRECTORY).exists() and empty(roots[0]), 'budget_preview_mutated')
        finish('inert-preview', selected_started=0, network_connections=0, validator_only=True)

        begin('two-independent-presets')
        saved = [create('one', roots[0]), create('two', roots[1])]
        require(all(s['status'] == 'saved' and s['delegation'] == 'verified-idle'
                    and s['states'] == {'configured': True, 'probed': False, 'witnessed_active': False} for s in saved), 'budget_create_claims')
        listing = {p['name']: p for p in preset(['inspect'])['presets']}
        require(listing['one']['root_identity'] != listing['two']['root_identity']
                and listing['one']['config_sha256'] != listing['two']['config_sha256'], 'budget_identities_not_independent')
        require(empty(roots[0]) and empty(roots[1]), 'budget_create_started_protection')
        finish('two-independent-presets', roots=2)

        begin('bounds-refused')
        for override, reason in (({'pidsMax': 15}, 'budget_preset_limit_out_of_range'),
                                 ({'memoryMaxBytes': 4096}, 'budget_preset_limit_out_of_range'),
                                 ({'wallMillis': 3_600_001}, 'budget_preset_limit_out_of_range')):
            value = preset(['create', '--name', 'bad', *limits_words(roots[2], **override)], 2)
            require(value['reason'] == reason, 'budget_bounds_wrong_refusal')
        value = preset(['create', '--name', 'bad', '--baseline', 'prepared-pilot-default',
                        *limits_words(roots[2], pidsMax=129, memoryMaxBytes=536_870_912)], 2)
        require(value['reason'] == 'budget_preset_limit_exceeds_baseline', 'budget_baseline_not_enforced')
        require('bad' not in {p['name'] for p in preset(['inspect'])['presets']}, 'budget_refused_value_stored')
        finish('bounds-refused')

        begin('unverified-delegation-refused')
        sha = budgets.config_identity(config(undelegated))
        value = preset(['create', '--name', 'bare', *limits_words(undelegated), '--expected-config-sha256', sha, '--apply'], 2)
        require(value['reason'] in ('budget_preset_delegation_unverified', 'budget_preset_delegation_busy'), 'budget_unverified_root_accepted')
        require('bare' not in {p['name'] for p in preset(['inspect'])['presets']}, 'budget_unverified_root_stored')
        finish('unverified-delegation-refused', reason=value['reason'])

        begin('stale-update-refused')
        current = preset(['check', '--name', 'one', '--agentfw', args.agentfw])
        require(current['resource_budget'] == 'selected-not-validated' and current['states']['witnessed_active'] is False, 'budget_check_claims')
        probed = preset(['check', '--name', 'one', '--agentfw', args.agentfw, '--probe'])
        require(probed['resource_budget'] == 'available-not-active', 'budget_probe_missing')
        preset(['update', '--name', 'one', *limits_words(roots[0], pidsMax=64), '--expected-version', '0' * 64,
                '--expected-config-sha256', budgets.config_identity(config(roots[0], pidsMax=64)), '--apply'], 2)
        finish('stale-update-refused')

        begin('concurrent-update')
        old = current['digest']
        sha64 = budgets.config_identity(config(roots[0], pidsMax=64))
        words = [str(args.agentfw), 'pilot', '--home', str(home), 'budget-preset', 'update', '--name', 'one',
                 *map(str, limits_words(roots[0], pidsMax=64)), '--expected-version', old,
                 '--expected-config-sha256', sha64, '--apply']
        contenders = [subprocess.Popen(words, cwd=door.cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        results = [(p.communicate(timeout=180), p.wait()) for p in contenders]
        require(sorted(r[1] for r in results) == [0, 2], 'budget_concurrent_update_not_cas')
        # Restore the run configuration deliberately, with a fresh exact confirmation.
        now = preset(['check', '--name', 'one', '--agentfw', args.agentfw])
        preset(['update', '--name', 'one', *limits_words(roots[0]), '--expected-version', now['digest'],
                '--expected-config-sha256', budgets.config_identity(config(roots[0])), '--apply'])
        finish('concurrent-update', one_writer=True)

        begin('damaged-store')
        catalog = home / budgets.DIRECTORY / 'catalog.json'
        raw = catalog.read_bytes()
        catalog.write_bytes(b'{}')
        try:
            preset(['inspect'], 2)
        finally:
            catalog.write_bytes(raw)
        finish('damaged-store')

        for i, name in enumerate(('one', 'two')):
            project(['create', *project_words(i, name, name), '--apply'])
        begin('two-budgeted-reads')
        ready = [threading.Event(), threading.Event()]
        continued = threading.Event()
        received = [{}, {}]

        def responder(i):
            def next_step(body):
                if not any(t.get('name') == 'mcp__filesystem__read_text_file' for t in body.get('tools', [])):
                    return [{'type': 'text', 'text': 'Owned auxiliary.'}]
                for message in body.get('messages', []):
                    for block in message.get('content', []) if isinstance(message.get('content'), list) else []:
                        if isinstance(block, dict) and block.get('type') == 'tool_result':
                            received[i][block['tool_use_id']] = block
                first_id = 'toolu_budget_' + str(i) + '_read'
                if first_id not in received[i]:
                    return [{'type': 'tool_use', 'id': first_id, 'name': 'mcp__filesystem__read_text_file',
                             'input': {'path': '/workspace/README.md'}}]
                require(texts[i].strip() in json.dumps(received[i][first_id]), 'budget_readback_missing')
                require(texts[1 - i].strip() not in json.dumps(received[i]), 'budget_cross_read')
                ready[i].set()
                require(release.wait(150), 'budget_release_deadline')
                if i == 1 and 'toolu_budget_1_later' not in received[i]:
                    return [{'type': 'tool_use', 'id': 'toolu_budget_1_later', 'name': 'mcp__filesystem__read_text_file',
                             'input': {'path': '/workspace/README.md'}}]
                if i == 1:
                    continued.set()
                return [{'type': 'text', 'text': 'Owned budgeted read completed.'}]
            return next_step

        for i, name in enumerate(('one', 'two')):
            models[i].next = responder(i)
            version = project(['check', '--name', name])
            require(version['resource_budget'] == 'selected-not-validated' and version['budget_preset']['preset'] == name,
                    'budget_project_check_claims')
            digests[name] = version['digest']
            out = (args.output / ('budget-' + str(i) + '.out.private')).open('wb')
            err = (args.output / ('budget-' + str(i) + '.err.private')).open('wb')
            streams.extend((out, err))
            command = [str(args.strace), '-f', '-qq', '-v', '-s', '131072', '-e', 'trace=execve,execveat',
                       '-o', str(args.output / ('budget-' + str(i) + '.trace.private')), str(args.agentfw), 'pilot',
                       '--home', str(home), 'project', 'run', '--name', name, '--expected-version', version['digest'],
                       '--apply', '--timeout-seconds', '180']
            process = subprocess.Popen(command, cwd=door.cwd, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       start_new_session=True)
            processes.append(process)
            witnesses.append(base.ProcessWitness(process.pid))
        require(all(event.wait(180) for event in ready), 'budget_concurrent_reads_missing')
        finish('two-budgeted-reads', independent_readback=True)

        begin('controller-limit-witness')
        witnessed = []
        for i, root in enumerate(roots[:2]):
            found = leaves(root)
            # One leaf per original server (filesystem and Git), each with the exact selected limits.
            require(len(found) >= 1, 'budget_leaf_inventory')
            for leaf in found:
                require((leaf / 'memory.max').read_text().strip() == str(LIMITS['memoryMaxBytes'])
                        and (leaf / 'pids.max').read_text().strip() == str(LIMITS['pidsMax'])
                        and (leaf / 'cpu.max').read_text().split() == [str(LIMITS['cpuQuotaMicros']), '100000']
                        and (leaf / 'memory.swap.max').read_text().strip() == '0', 'budget_leaf_limits_not_exact')
            witnessed.append(len(found))
        runs = []
        for state in states:
            found = list(state.glob('soup-wall-run-*'))
            require(len(found) == 1, 'budget_run_state_isolation')
            runs.append(found[0])
            snapshot = json.loads((found[0] / 'selected-linux-budget.json').read_bytes())
            require(budgets.config_identity(snapshot) == listing_sha(preset, ('one', 'two')[len(runs) - 1]), 'budget_frozen_config_differs')
        finish('controller-limit-witness', leaves=witnessed, limits='memory.max,pids.max,cpu.max,memory.swap.max')

        begin('update-during-run')
        frozen = [(r / 'selected-linux-budget.json').read_bytes() for r in runs]
        now = preset(['check', '--name', 'one', '--agentfw', args.agentfw])
        new_sha = budgets.config_identity(config(roots[0], pidsMax=96))
        updated = preset(['update', '--name', 'one', *limits_words(roots[0], pidsMax=96), '--expected-version', now['digest'],
                          '--expected-config-sha256', new_sha, '--apply'])
        require(updated['delegation'] == 'busy-root-unchanged', 'budget_busy_root_not_reported')
        require(frozen == [(r / 'selected-linux-budget.json').read_bytes() for r in runs], 'budget_running_snapshot_changed')
        for leaf in leaves(roots[0]):
            require((leaf / 'pids.max').read_text().strip() == str(LIMITS['pidsMax']), 'budget_running_limit_changed')
        require(all(p.poll() is None for p in processes), 'budget_update_stopped_a_run')
        finish('update-during-run', running_limits_unchanged=True, frozen_snapshots_unchanged=True)

        begin('stale-profile-zero-start')
        trace = args.output / 'budget-stale.trace.private'
        stale = project(['check', '--name', 'one'], 2)
        require(stale['reason'] == 'budget_preset_stale', 'budget_stale_profile_not_detected')
        project(['run', '--name', 'one', '--expected-version', digests['one'], '--apply'], 2, trace)
        no_selected_start(trace)
        finish('stale-profile-zero-start', selected_started=0, network_connections=0)

        os.killpg(processes[0].pid, signal.SIGINT)
        processes[0].wait(timeout=60)
        require(processes[1].poll() is None, 'budget_sibling_stopped')
        release.set()
        processes[1].wait(timeout=150)
        require(processes[1].returncode == 0 and continued.is_set(), 'budget_sibling_not_continued')

        # Re-select deliberately: the update made the project's selection stale, never silently newer.
        begin('unavailable-delegation-zero-start')
        require(all(empty(r) for r in roots[:2]), 'budget_roots_not_released')
        refreshed = preset(['check', '--name', 'two', '--agentfw', args.agentfw])
        reselected = project(['update', *project_words(1, 'two', 'two'), '--expected-version',
                              digests['two'], '--apply'])
        digests['two'] = reselected['digest']
        gone = roots[1]
        gone.rmdir()
        trace = args.output / 'budget-unavailable.trace.private'
        again = project(['check', '--name', 'two'], 2)
        require(again['reason'] in ('budget_preset_root_changed', 'budget_preset_root_invalid'), 'budget_missing_root_not_refused')
        project(['run', '--name', 'two', '--expected-version', digests['two'], '--apply'], 2, trace)
        no_selected_start(trace)
        finish('unavailable-delegation-zero-start', selected_started=0, network_connections=0, preset=refreshed['digest'][:12])

        begin('root-replaced-refused')
        gone.mkdir(mode=0o700)
        (gone / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        replaced = preset(['check', '--name', 'two', '--agentfw', args.agentfw], 2)
        require(replaced['reason'] == 'budget_preset_root_changed', 'budget_replaced_root_accepted')
        finish('root-replaced-refused')

        # The unnamed installed run is a second launch path: it resolves and enforces the same preset.
        begin('unnamed-run-preset')
        useful = [('mcp__filesystem__read_text_file', {'path': '/workspace/README.md'}),
                  ('mcp__git__git_show', {'repo_path': '/workspace', 'revision': 'HEAD'})]
        current = preset(['check', '--name', 'one', '--agentfw', args.agentfw])
        live = {}

        def during_unnamed(model):
            found = leaves(roots[0])
            require(found, 'budget_unnamed_leaf_missing')
            for leaf in found:
                require((leaf / 'memory.max').read_text().strip() == str(LIMITS['memoryMaxBytes'])
                        and (leaf / 'pids.max').read_text().strip() == '96'
                        and (leaf / 'cpu.max').read_text().split() == [str(LIMITS['cpuQuotaMicros']), '100000'],
                        'budget_unnamed_limits_not_exact')
            live['leaves'] = len(found)

        row, results, _ = q.run_case(args, door, report, 'budget_unnamed', useful, after_useful=during_unnamed,
                                          run_flags=['--budget-preset', 'one', '--budget-preset-digest', current['digest']])
        require(live and row['exit'] == 0 and row['process_cleanup']['all_stopped'] and len(results) == 2
                and all(not r['is_error'] for r in results.values()) and empty(roots[0]), 'budget_unnamed_run_not_enforced')
        finish('unnamed-run-preset', leaves=live['leaves'], limits='pids.max=96 from the updated preset', useful_results=2)

        begin('unnamed-stale-zero-start')
        trace = args.output / 'budget-unnamed-stale.trace.private'
        words = door.words('run', '--state-root', args.state_root, '--timeout-seconds', '120',
                           '--budget-preset', 'one', '--budget-preset-digest', '0' * 64, inputs=False)
        refused = subprocess.run([str(args.strace), '-f', '-qq', '-s', '256', '-e', 'trace=execve,connect', '-o', str(trace), *words],
                                 cwd=door.cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=180)
        require(refused.returncode != 0, 'budget_unnamed_stale_run_started')
        outcome = json.loads(refused.stdout.decode().splitlines()[-1])
        require(outcome.get('executed') is not True and outcome.get('reason') == 'budget_preset_stale', 'budget_unnamed_wrong_refusal')
        no_selected_start(trace)
        require(empty(roots[0]), 'budget_unnamed_stale_left_state')
        finish('unnamed-stale-zero-start', selected_started=0, network_connections=0)

        begin('owned-cleanup')
        cleanup = [w.finish() for w in witnesses]
        require(all(w['all_stopped'] and w['descendant_count'] >= 3 for w in cleanup), 'budget_cleanup_unconfirmed')
        require(all(empty(r) for r in roots), 'budget_owned_leaf_remains')
        require(baseline == [q.snapshot(p) for p in (args.project, args.repository, second.project, second.repository)],
                'budget_source_changed')
        require(receiver.count == 0 and not (args.output / 'forbidden-effect').exists(), 'budget_unapproved_receiver_effect')
        require(all(c.encode() not in catalog.read_bytes() for c in canaries), 'budget_catalog_contains_provider_input')
        for i in range(2):
            public = (args.output / ('budget-' + str(i) + '.out.private')).read_bytes() + \
                     (args.output / ('budget-' + str(i) + '.err.private')).read_bytes()
            require(all(c.encode() not in public for c in canaries), 'budget_run_output_canary')
            installed.provider_exec_witness(args.output / ('budget-' + str(i) + '.trace.private'), args.claude, canaries[i], models[i].url)
        finish('owned-cleanup', all_stopped=True, roots_empty=True, sources_preserved=True, receiver_effects=0)
        evidence.update(status='passed', source_after=base.source())
        require(evidence['source_after'] == evidence['source'], 'budget_source_identity_changed')
        require([r['id'] for r in rows] == list(CASES) and all(r['attempted'] and r['status'] == 'passed' for r in rows),
                'budget_case_inventory_incomplete')
        report['cases'].extend({'case': r['id'], 'passed': True} for r in rows)
    finally:
        release.set()
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
        for witness in witnesses:
            witness.finish()
        for stream in streams:
            stream.close()
        for model in models:
            model.close()


def listing_sha(preset, name):
    return {p['name']: p for p in preset(['inspect', '--name', name])['presets']}[name]['config_sha256']
