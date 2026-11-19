# SPDX-License-Identifier: Apache-2.0
"""Frozen v1 pilot scope qualification, called by the installed driver after its standard cases.

The driver has already previewed, prepared (with `--scope linux-v1`), reused and run the scope-selected prefix through
the installed commands: useful filesystem and Git reads, refused write/reset/send with independent witnesses, live status
and Ctrl-C cleanup. This module adds the scope-specific controls and checks that those standard cases really ran under
the scope. Single-use Ask and daemon loss reuse the existing `qualify-installed-pilot.py` command on the scope-selected
demo generation in a separate workflow command. Nothing here grants authority or certifies acceptance.
"""
import json
import re

CASES = ('scope-selected-through-preview-and-prepare', 'excluded-option-preview', 'standard-cases-ran-under-scope',
         'excluded-capability-refused', 'tampered-scope-refused', 'unselected-claims-nothing', 'status-never-claims-more',
         'owned-cleanup')
OTHER_PROFILE = 'git-readonly-local-refs-v1'


def qualify(args, door, home, env, report, *, guided, receiver, baseline, selection, load, agent_executions):
    require = guided.require
    scope = load('qualification_pilot_scope', 'pilot_scope.py')
    rows = [{'id': n, 'status': 'incomplete', 'attempted': False} for n in CASES]
    evidence = {'format': 'sw-installed-pilot-scope-qualification/1', 'status': 'incomplete',
                'source': guided.BASE.source(), 'expected': list(CASES), 'cases': rows}
    report['pilot_scope_qualification'] = evidence
    selected = {k: getattr(args, k) for k in guided.SELECTED_PROGRAMS if getattr(args, k, None) is not None and k != 'agentfw'}
    state_file = args.prefix / 'front-door.json'
    work = args.output / 'pilot-scope'
    work.mkdir(mode=0o700)

    def begin(name):
        evidence['active_case'] = name
        rows[CASES.index(name)]['attempted'] = True

    def finish(name, **facts):
        rows[CASES.index(name)].update(status='passed', **facts)

    def zero_starts(trace):
        observed = guided.executed(trace, selected)
        require(not observed['selected_started'] and observed['inet_connects'] == 0, 'scope_refusal_started_program_or_network')
        # Only the installed command itself (and its validator children) may start: never a daemon, host or server.
        return agent_executions(trace, args.agentfw)

    def call(*words, trace=None, prefix=None, inputs=True, timeout=900):
        code, value, _ = door.call(*words, trace=trace, prefix=prefix, inputs=inputs, timeout=timeout)
        evidence['last_cli'] = {'command': words[0], 'exit': code,
                                'reason': value.get('reason') if re.fullmatch(r'[a-z0-9_]{1,80}', str(value.get('reason', ''))) else None}
        return code, value

    def snapshot():
        return guided.snapshot(args.prefix)

    begin('scope-selected-through-preview-and-prepare')
    recorded = json.loads(state_file.read_bytes())
    document, document_sha = scope.load(scope.ROOT, scope.kit_from(load('qualification_pilot_scope_prep', 'prepare-installed-pilot.py')))
    require(recorded.get('scope') == {'id': 'linux-v1', 'document_sha256': document_sha}, 'scope_not_recorded_by_prepare')
    trace = work / 'preview.trace.private'
    before = snapshot()
    code, preview = call('preview', '--scope', 'linux-v1', trace=trace, timeout=600)
    starts = zero_starts(trace)
    require(code == 0 and preview['executed'] is False and preview['scope']['selected'] is True
            and preview['scope']['refused'] == [] and preview['scope']['document_sha256'] == document_sha
            and preview['scope']['acceptance'] == 'not-claimed-by-this-document' and preview['missing'] == []
            and snapshot() == before, 'scope_preview_claims_or_effects')
    finish('scope-selected-through-preview-and-prepare', document_sha256=document_sha[:12], agent_starts=starts)

    begin('excluded-option-preview')
    trace = work / 'excluded-preview.trace.private'
    code, preview = call('preview', '--scope', 'linux-v1', '--git-profile', OTHER_PROFILE, trace=trace, timeout=600)
    zero_starts(trace)
    require(code == 0 and [r['id'] for r in preview['scope']['refused']] == ['capability-git-profiles']
            and any('remove --git-profile' in item for item in preview['missing']) and snapshot() == before,
            'scope_excluded_preview_not_reported')
    finish('excluded-option-preview', refused=['capability-git-profiles'])

    begin('standard-cases-ran-under-scope')
    by_case = {row.get('case'): row for row in report['cases'] if isinstance(row, dict)}
    for name in ('useful', 'cancel'):
        row = by_case.get(name)
        require(row is not None and row.get('process_cleanup', {}).get('all_stopped') is True, 'scope_standard_case_missing')
        live = row['live_status']
        require(live.get('protection') == 'observed-live' and isinstance(live.get('scope'), dict)
                and live['scope']['state'] == 'conforming' and live['scope']['mode'] == 'enforce'
                and live['scope']['qualification'].startswith('unqualified') and 'never reported as protection' in live['scope']['shadow'],
                'scope_live_status_not_enforce_conforming')
    useful = by_case['useful']['results']
    require(len(useful) == 5 and sum(1 for r in useful.values() if r['is_error'] is False) == 2
            and sum(1 for r in useful.values() if r['is_error'] is True) == 3, 'scope_useful_or_refused_results_unexpected')
    code, status = call('status', '--state-root', str(args.state_root), inputs=False, timeout=120)
    require(code == 0 and status['protection'] == 'configured-not-running' and status['scope']['state'] == 'conforming'
            and status['scope']['mode'] == 'not-running', 'scope_status_after_runs')
    finish('standard-cases-ran-under-scope', useful_results=2, refused_results=3, live_scope_mode='enforce')

    begin('excluded-capability-refused')
    trace = work / 'excluded-prepare.trace.private'
    before = snapshot()
    pointer = guided.BASE.sha(state_file)
    code, refused = call('prepare', '--apply', '--scope', 'linux-v1', '--git-profile', OTHER_PROFILE, trace=trace, timeout=900)
    zero_starts(trace)
    require(code != 0 and refused.get('reason') == 'scope_excludes_capability' and snapshot() == before
            and guided.BASE.sha(state_file) == pointer and receiver.count == 0, 'scope_excluded_capability_not_refused')
    finish('excluded-capability-refused', reason='scope_excludes_capability', selected_started=0, network_connections=0,
           prefix_unchanged=True)

    begin('tampered-scope-refused')
    original = state_file.read_bytes()
    mode = state_file.stat().st_mode & 0o777
    value = json.loads(original)
    value['scope']['document_sha256'] = '0' * 64
    try:
        state_file.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
        state_file.chmod(0o600)
        code, status = call('status', '--state-root', str(args.state_root), inputs=False, timeout=120)
        require(code == 0 and status['scope']['state'] == 'document-changed' and status['protection'] != 'observed-live',
                'scope_tamper_not_reported_by_status')
        trace = work / 'tampered-run.trace.private'
        code, refused = call('run', '--state-root', str(args.state_root), '--timeout-seconds', '60', inputs=False, trace=trace)
        zero_starts(trace)
        require(code != 0 and refused.get('reason') == 'scope_document_changed' and refused.get('executed') is False,
                'scope_tampered_run_not_refused')
    finally:
        state_file.write_bytes(original)
        state_file.chmod(mode)
    code, status = call('status', '--state-root', str(args.state_root), inputs=False, timeout=120)
    require(code == 0 and status['scope']['state'] == 'conforming', 'scope_not_restored_after_tamper')
    finish('tampered-scope-refused', reason='scope_document_changed', selected_started=0)

    begin('unselected-claims-nothing')
    never = args.output / 'never-prepared-prefix'
    code, status = call('status', '--state-root', str(args.state_root), inputs=False, prefix=never, timeout=120)
    require(code == 0 and status['scope']['state'] == 'unselected' and status['scope']['selected'] is False
            and status['protection'] == 'not-configured' and not never.exists()
            and status['scope']['qualification'].startswith('unqualified'), 'scope_unselected_claimed_something')
    finish('unselected-claims-nothing', protection='not-configured')

    begin('status-never-claims-more')
    code, final = call('status', '--state-root', str(args.state_root), inputs=False, timeout=120)
    require(code == 0 and final['protection'] == 'configured-not-running' and final['scope']['mode'] == 'not-running'
            and final['scope']['qualification'].startswith('unqualified') and 'never reported as protection' in final['scope']['shadow'],
            'scope_status_claims_more_than_observed')
    require(preview['scope']['acceptance'] == 'not-claimed-by-this-document' and document['acceptance'] == 'not-claimed-by-this-document'
            and document['enforcement']['mode'] == 'enforce' and 'READY' not in json.dumps(final['scope']).replace('NOT_READY', ''),
            'scope_claims_acceptance')
    finish('status-never-claims-more', acceptance='not-claimed', enforce_only_when_observed_live=True)

    begin('owned-cleanup')
    require(receiver.count == 0 and guided.snapshot(args.project) == baseline['project']
            and guided.snapshot(args.repository) == baseline['repository'], 'scope_sources_or_receiver_changed')
    require(guided.BASE.source()['commit'] == args.expected_commit, 'scope_source_identity_changed')
    finish('owned-cleanup', sources_preserved=True, receiver_effects=0)
    evidence.update(status='passed', source_after=guided.BASE.source())
    require([r['id'] for r in rows] == list(CASES) and all(r['attempted'] and r['status'] == 'passed' for r in rows),
            'scope_case_inventory_incomplete')
    report['cases'].extend({'case': r['id'], 'passed': True} for r in rows)
