#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in installed run inventory and exact selection; genuine host, owned provider.

The default only prints the frozen inventory. No paid calls or external upload.
Retained-metadata faults are explicitly injected controls, not host outcomes.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('inventory_stop_driver', ROOT / 'scripts/qualify-installed-edit-stop.py')
STOP = importlib.util.module_from_spec(spec);spec.loader.exec_module(STOP)
EDIT = STOP.BASE
require, sha, snapshot = EDIT.require, EDIT.sha, EDIT.snapshot
FORMAT = 'sw-installed-edit-inventory-qualification/1'
CASES = ('installed-closure', 'completed-and-interrupted-history', 'two-live-zero-execution',
         'exact-status-and-stop-peer-preserved', 'exact-completed-review', 'stale-selection-refused',
         'unsafe-selector-refused', 'malformed-and-old-boot-history', 'linked-and-foreign-entry',
         'concurrent-disappearance', 'capacity-bound', 'helper-integrity')


def read_only_review(value):
    """The accepted CLI wraps execution/authority flags in its observation."""
    return (isinstance(value, dict) and value.get('format') == 'sw-installed-edit-review/1'
            and value.get('status') == 'reviewed'
            and isinstance(value.get('observation'), dict)
            and value.get('observation', {}).get('executed') is False
            and value.get('observation', {}).get('authority') is False)


def passed_report(report):
    rows = report.get('cases', [])
    by_id = {r.get('id'): r for r in rows}
    return (report.get('format') == FORMAT and report.get('status') == 'passed'
            and report.get('paid_inference') is False and report.get('claude_sha256') == EDIT.CLAUDE
            and report.get('expected') == list(CASES) and [r.get('id') for r in rows] == list(CASES)
            and all(r.get('attempted') is True and r.get('status') == 'passed' for r in rows)
            and by_id.get('two-live-zero-execution', {}).get('zero_provider_requests') is True
            and by_id.get('two-live-zero-execution', {}).get('zero_tool_calls') is True
            and by_id.get('two-live-zero-execution', {}).get('state_and_outputs_preserved') is True
            and by_id.get('exact-status-and-stop-peer-preserved', {}).get('peer_preserved') is True
            and by_id.get('exact-completed-review', {}).get('zero_provider_requests') is True
            and by_id.get('stale-selection-refused', {}).get('state_preserved') is True
            and by_id.get('linked-and-foreign-entry', {}).get('foreign_refused') is True
            and type(by_id.get('concurrent-disappearance', {}).get('moves')) is int
            and by_id['concurrent-disappearance']['moves'] > 0
            and by_id.get('concurrent-disappearance', {}).get('incomplete_observed') is True
            and by_id.get('capacity-bound', {}).get('rows') == 32
            and by_id.get('completed-and-interrupted-history', {}).get('genuine_readback') is True
            and by_id.get('exact-completed-review', {}).get('output_and_plan_preserved') is True
            and by_id.get('stale-selection-refused', {}).get('old_selection_refused') is True
            and by_id.get('unsafe-selector-refused', {}).get('explicit_actions_only') is True
            and by_id.get('malformed-and-old-boot-history', {}).get('unknown_preserved') is True
            and by_id.get('helper-integrity', {}).get('changed_helper_refused') is True
            and report.get('sentinel_preserved') is True and report.get('all_owned_stopped') is True)


def qualify(args, report):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0,
            'native_linux_operator_required')
    require(not args.output.is_relative_to(ROOT) and sha(args.claude.read_bytes()) == EDIT.CLAUDE,
            'outside_checkout_genuine_host_required')
    suite = EDIT.Suite(args, report)
    active = []
    report.update(agentfw_sha256=sha(suite.binary.read_bytes()), claude_sha256=EDIT.CLAUDE,
                  scope='installed_genuine_host_owned_scripted_provider')

    def begin(name):
        row = report['cases'][CASES.index(name)];row['attempted'] = True;suite.active = row;return row

    def done(row, **facts):
        require(snapshot(suite.sentinel) == suite.before_sentinel, 'inventory_sentinel_changed')
        row.update(status='passed', **facts)

    def cli(*words, expect=None):
        result = subprocess.run([str(suite.binary), 'edit-session', *map(str, words)], cwd=suite.work,
            env=suite.env, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        require(len(result.stdout) <= 128 * 1024 and len(result.stderr) <= 128 * 1024, 'inventory_cli_bound')
        suite.active['last_cli'] = EDIT.cli_observation(result.returncode, result.stdout, result.stderr)
        # Never retain a response until checking it for private state/name canaries.
        for canary in (str(args.output).encode(), b'owned-inventory-private-secret'):
            require(canary not in result.stdout, 'inventory_private_data_disclosed')
        try: value = json.loads(result.stdout) if result.stdout else None
        except ValueError: value = None
        if expect is not None: require(result.returncode == expect, 'inventory_unexpected_exit')
        return result.returncode, value

    def inventory(run=None, state=None, expect=0):
        words = ['inventory', '--home', suite.home, '--state', state or suite.state, '--json']
        if run is not None: words += ['--run-id', run.name.removeprefix('edit-')]
        code, value = cli(*words, expect=expect)
        require(type(value) is dict and value.get('format') == 'sw-installed-edit-inventory/1'
                and value.get('executed') is False and value.get('authority') is False, 'inventory_invalid_report')
        if run is not None and expect == 0:
            require(len(value['rows']) == 1 and value['rows'][0]['run_id'] == run.name[5:], 'inventory_wrong_exact_run')
        return value

    def selected(run, token, *words, expect=0):
        return cli('with-run', '--home', suite.home, '--state', suite.state, '--run-id', run.name[5:],
                   '--selection-sha256', token, '--', *words, expect=expect)[1]

    def records(run): return EDIT.private_state_witness(run, include_audit=False)
    def plan(run): return {n:snapshot(run.plan / n) for n in ('profile.json', 'profile.sha256')}

    def completed(label, rejected=False):
        run = STOP.Run(suite, label, active, hold=False, useful=True)
        pending = STOP.until(run.pending, 'inventory_completed_ask_missing')
        require(run.decision(pending, approve=not rejected)[0] == 0, 'inventory_ask_decision_failed')
        result = run.finish()
        if not rejected:
            require(run.target.read_text() == EDIT.NEW and run.observed.get('toolu_stop_2', {}).get('is_error') is False
                    and EDIT.NEW.strip() in json.dumps(run.observed['toolu_stop_2'].get('content')),
                    'inventory_genuine_readback_missing')
        return run, result

    def rewrite(path, raw):
        path.chmod(0o600);path.write_bytes(raw);path.chmod(0o400)

    try:
        row = begin('installed-closure')
        archive = args.output / 'component.tar'
        build = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/build-pilot-front-door.py'), '--out', str(archive)],
            env=suite.env, cwd=ROOT, capture_output=True, timeout=60)
        require(build.returncode == 0, 'inventory_component_build_failed')
        built = json.loads(build.stdout.splitlines()[-1])
        install = subprocess.run([str(suite.binary), 'pilot-component', '--home', str(suite.home), 'install', str(archive),
            '--sha256', built['archive_sha256'], '--python', str(args.python)], cwd=suite.work,
            env=suite.env, capture_output=True, timeout=60)
        require(install.returncode == 0, 'inventory_component_install_failed')
        report.update(source_commit=built['commit'], component=built['component'], source_tree=subprocess.check_output(
            ['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT, text=True).strip())
        done(row, installed_outside_checkout=True)

        row = begin('completed-and-interrupted-history')
        finished, finish_result = completed('inventory-completed')
        interrupted = STOP.Run(suite, 'inventory-interrupted', active)
        STOP.until(interrupted.pending, 'inventory_interrupted_ask_missing')
        code, stopped = interrupted.stop()
        require(STOP.stop_ok(code, stopped, 'stopped'), 'inventory_interrupted_stop_failed')
        stop_result = interrupted.finish(expected_exit=None)
        listed = inventory()
        outcomes = {r['run_id']:r['recorded_host_outcome'] for r in listed['rows']}
        require(outcomes[finished.run.name[5:]] == 'recorded_host_completed'
                and outcomes[interrupted.run.name[5:]] == 'recorded_operator_stop', 'inventory_history_conflated')
        done(row, genuine_readback=True, completed=finish_result, interrupted=stop_result)

        row = begin('two-live-zero-execution')
        live = []
        for label in ('inventory-live-one', 'inventory-live-two'):
            run = STOP.Run(suite, label, active)
            pending = STOP.until(run.pending, 'inventory_live_ask_missing')
            require(run.decision(pending)[0] == 0 and run.future_ready.wait(15), 'inventory_live_barrier_missing')
            live.append(run)
        before = [(records(r.run), snapshot(r.target), plan(r), len(r.model.requests), set(r.offered),
                   EDIT.live_audit_witness(r.run)) for r in live]
        listed = inventory()
        require(listed['verified_component'] == built['component'] and len(listed['rows']) == 4,
                'inventory_installed_binding_missing')
        expected_profiles = {r.run.name[5:]:r.prepared['profile_sha256'] for r in (finished, interrupted, *live)}
        require(all(r['profile_sha256'] == expected_profiles[r['run_id']]
                    and r['source_commit'] == built['commit'] and r['source_tree'] == report['source_tree']
                    and r['component_sha256'] == built['component'] for r in listed['rows']),
                'inventory_retained_identity_mismatch')
        for r, (state, target, immutable, requests, offered, audit) in zip(live, before):
            row_value = next(v for v in listed['rows'] if v['run_id'] == r.run.name[5:])
            require(row_value['recorded_host_outcome'] == 'terminal_not_recorded'
                    and row_value['owner_observation'] == 'identity_matches_liveness_not_established', 'inventory_live_overclaim')
            require(records(r.run) == state and snapshot(r.target) == target and plan(r) == immutable
                    and len(r.model.requests) == requests and r.offered == offered, 'inventory_mutated_or_executed')
            EDIT.live_audit_delta(audit, EDIT.live_audit_witness(r.run))
        done(row, zero_provider_requests=True, zero_tool_calls=True, state_and_outputs_preserved=True,
             active_runs=2, listed_rows=listed['rows'], report_sha256=sha(json.dumps(listed, sort_keys=True).encode()))

        row = begin('exact-status-and-stop-peer-preserved')
        chosen, peer = live
        peer_before = (records(peer.run), snapshot(peer.target), plan(peer), len(peer.model.requests))
        token = inventory(chosen.run)['rows'][0]['selection_sha256']
        status = selected(chosen.run, token, 'status', '--json')
        EDIT.require_indeterminate_status(status)
        require(status['identity']['profile_sha256'] == chosen.prepared['profile_sha256'], 'inventory_wrong_status_handoff')
        stopped = selected(chosen.run, token, 'stop', '--output', 'json-v1')
        require(STOP.stop_ok(0, stopped, 'stopped'), 'inventory_wrong_stop_handoff')
        selected_cleanup = chosen.finish(expected_exit=None)
        require(peer.process.poll() is None and (records(peer.run), snapshot(peer.target), plan(peer),
                len(peer.model.requests)) == peer_before, 'inventory_selected_peer_changed')
        done(row, peer_preserved=True, selected_cleanup=selected_cleanup)
        require(STOP.stop_ok(*peer.stop(), 'stopped'), 'inventory_peer_cleanup_failed')
        peer.finish(expected_exit=None)

        row = begin('exact-completed-review')
        token = inventory(finished.run)['rows'][0]['selection_sha256']
        before = (EDIT.private_state_witness(finished.run), snapshot(finished.target), plan(finished), len(finished.model.requests))
        review = selected(finished.run, token, 'review', '--sha256', finished.prepared['profile_sha256'])
        require(read_only_review(review)
                and (EDIT.private_state_witness(finished.run), snapshot(finished.target), plan(finished),
                     len(finished.model.requests)) == before, 'inventory_review_changed_or_executed')
        done(row, zero_provider_requests=True, output_and_plan_preserved=True)

        row = begin('stale-selection-refused')
        terminal = finished.run / 'terminal.json';raw = terminal.read_bytes()
        rewrite(terminal, raw + b' ')
        before = EDIT.private_state_witness(finished.run)
        selected(finished.run, token, 'status', '--json', expect=1)
        require(EDIT.private_state_witness(finished.run) == before, 'inventory_stale_selection_mutated')
        rewrite(terminal, raw)
        fresh = inventory(finished.run)['rows'][0]['selection_sha256']
        require(fresh != token, 'inventory_stale_identity_reused')
        selected(finished.run, fresh, 'status', '--json')
        done(row, state_preserved=True, old_selection_refused=True)

        row = begin('unsafe-selector-refused')
        for unsafe in ('../outside', '--help', '00000000', '00000000-0000-4000-8000-00000000000A'):
            cli('inventory', '--home', suite.home, '--state', suite.state, '--json', '--run-id=' + unsafe, expect=1)
        for action in ('run', 'ask', 'relay', 'prepare', 'with-run'):
            selected(finished.run, fresh, action, expect=1)
        done(row, explicit_actions_only=True)

        row = begin('malformed-and-old-boot-history')
        file = finished.run / 'run.json';raw = file.read_bytes()
        rewrite(file, b'{"private":"owned-inventory-private-secret"')
        unknown = inventory(expect=1)
        require(any(r['run_id'] == finished.run.name[5:] and r['status'] == 'unknown'
                and r['selection_sha256'] is None for r in unknown['rows']), 'inventory_malformed_promoted')
        rewrite(file, raw)
        file = finished.run / 'diagnostic-context.json';raw = file.read_bytes();value = json.loads(raw)
        value['owner']['boot_id'] = '00000000-0000-0000-0000-000000000000'
        rewrite(file, json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
        old = inventory(finished.run)['rows'][0]
        require(old['owner_observation'] == 'recorded_old_boot', 'inventory_old_boot_promoted')
        rewrite(file, raw)
        done(row, scope='explicitly injected retained metadata on genuine completed run', unknown_preserved=True)

        row = begin('linked-and-foreign-entry')
        link = suite.state / 'edit-90000000-0000-4000-8000-000000000001';link.symlink_to(finished.run)
        value = inventory(expect=1);link.unlink()
        require(next(r for r in value['rows'] if r['run_id'] == link.name[5:])['status'] == 'unknown', 'inventory_link_followed')
        require(args.foreign_state and any(p.stat().st_uid != os.geteuid() for p in args.foreign_state.iterdir()),
                'inventory_foreign_fixture_missing')
        value = inventory(state=args.foreign_state, expect=1)
        require(value['status'] == 'incomplete' and all(r['status'] == 'unknown' for r in value['rows']), 'inventory_foreign_accepted')
        done(row, foreign_refused=True, links_refused=True)

        row = begin('concurrent-disappearance')
        held = suite.work / 'inventory-held-run';stop = threading.Event();moves = []
        def move():
            try:
                while not stop.is_set():
                    finished.run.rename(held);moves.append(1);time.sleep(.002)
                    held.rename(finished.run);time.sleep(.002)
            finally:
                if held.exists(): held.rename(finished.run)
        mover = threading.Thread(target=move);mover.start()
        incomplete = False
        try:
            for _ in range(4):
                code, value = cli('inventory', '--home', suite.home, '--state', suite.state, '--json')
                if code != 0 and isinstance(value, dict) and value.get('status') in ('unknown', 'incomplete'):
                    incomplete = True;break
        finally: stop.set();mover.join(timeout=5)
        require(incomplete and moves and finished.run.is_dir() and not mover.is_alive(), 'inventory_concurrent_change_unobserved')
        inventory(finished.run)
        done(row, moves=len(moves), incomplete_observed=True, fixture='owned concurrent directory disappearance/restoration')

        row = begin('capacity-bound')
        capacity = suite.work / 'inventory-capacity';capacity.mkdir(mode=0o700)
        for index in range(33): (capacity / ('owned-inventory-private-secret-' + str(index))).mkdir(mode=0o700)
        value = inventory(state=capacity, expect=1)
        require(len(value['rows']) == 32 and value['reason'] == 'inventory_entry_limit', 'inventory_capacity_unbounded')
        done(row, rows=32, observed_status=value['status'])

        row = begin('helper-integrity')
        helper = suite.home / 'pilot-front-door/components' / built['component'] / 'tree/scripts/pilot.py'
        raw = helper.read_bytes();rewrite(helper, raw + b'\n# owned qualification change\n')
        cli('inventory', '--home', suite.home, '--state', suite.state, '--json', expect=1)
        rewrite(helper, raw)
        inventory(finished.run)
        done(row, changed_helper_refused=True)
        report.update(status='passed', sentinel_preserved=snapshot(suite.sentinel) == suite.before_sentinel)
    finally:
        for run in active: run.close()
        report['all_owned_stopped'] = all(r.process is None or r.process.poll() is not None for r in active)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--agentfw', type=Path);parser.add_argument('--claude', type=Path)
    parser.add_argument('--python', type=Path, default=Path('/usr/bin/python3.12'))
    parser.add_argument('--foreign-state', type=Path);parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'format':FORMAT, 'executed':False, 'expected':list(CASES)}));return 0
    require(args.output and args.output.is_absolute() and not args.output.exists(), 'new_absolute_output_required')
    args.output.mkdir(mode=0o700)
    report = {'format':FORMAT, 'status':'incomplete', 'paid_inference':False, 'expected':list(CASES),
              'cases':[{'id':n, 'status':'incomplete', 'attempted':False} for n in CASES]}
    try: qualify(args, report)
    except Exception as error:
        code = EDIT.failure_code(error);report.update(status='failed', failure=code, failure_type=type(error).__name__)
        current = next((r for r in report['cases'] if r['attempted'] and r['status'] == 'incomplete'), None)
        if current is not None: current.update(status='failed', failure=code)
    report['inventory'] = {s:sum(r['status'] == s for r in report['cases']) for s in ('passed', 'failed', 'incomplete')}
    evidence = (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()
    (args.output / 'report.json').write_bytes(evidence)
    # Content-free CI diagnostics remain usable if artifact transfer is unavailable.
    summary = {key:report[key] for key in ('format', 'status', 'inventory', 'failure', 'failure_type',
               'source_commit', 'source_tree', 'agentfw_sha256', 'component', 'claude_sha256') if key in report}
    summary['evidence_sha256'] = sha(evidence)
    summary['case_results'] = [{'id':r['id'], 'status':r['status'], 'attempted':r['attempted'],
        'witnesses':{key:value for key,value in r.items() if type(value) is bool and key != 'attempted'}}
        for r in report['cases']]
    print(json.dumps(summary, sort_keys=True))
    return 0 if passed_report(report) else 1


if __name__ == '__main__':
    raise SystemExit(main())
