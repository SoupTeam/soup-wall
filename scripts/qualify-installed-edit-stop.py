#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded, opt-in native installed edit stop qualification; no paid inference.

The existing SOU-161 installer, genuine host, scripted provider and independent
process witness are reused. This driver is never a production stop supervisor.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('edit_stop_base', ROOT / 'scripts/qualify-installed-edit.py')
BASE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(BASE)
require, sha, snapshot = BASE.require, BASE.sha, BASE.snapshot
FORMAT = 'sw-installed-edit-stop-qualification/1'
CASES = ('installed-identity', 'two-live-exact-stop', 'pending-replay-and-repeat',
         'rejected-ask-future-dispatch', 'publication-before-stop', 'publication-stop-race',
         'unsafe-records', 'foreign-birth-identity', 'old-control-replay',
         'daemon-unavailable', 'launcher-crash', 'fresh-useful-run')


def until(check, code, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(.02)
    raise ValueError(code)


def stop_ok(code, value, status):
    return (code == 0 and isinstance(value, dict)
            and value.get('format') == 'sw-installed-edit-stop-result/1'
            and value.get('status') == status and value.get('revocation_confirmed') is True
            and value.get('cleanup_confirmed') is True
            and value.get('effects_may_remain_committed') is True
            and value.get('running_effects_rolled_back') is False
            and value.get('automatic_retry') is False)


def passed(report):
    return (report.get('format') == FORMAT and report.get('status') == 'passed'
            and report.get('expected') == list(CASES)
            and report.get('claude_sha256') == BASE.CLAUDE
            and report.get('paid_inference') is False
            and [r.get('id') for r in report.get('cases', [])] == list(CASES)
            and all(r.get('status') == 'passed' and r.get('attempted') is True for r in report['cases'])
            and report.get('unrelated_process_preserved') is True)


class Run:
    def __init__(self, suite, label, active, hold=True, useful=False):
        self.suite, self.label = suite, label
        self.process = self.witness = self.model = self.out = self.err = None
        self.closed, self.future_release = threading.Event(), threading.Event()
        active.append(self)
        self.root, self.target, self.plan, code, self.prepared = suite.prepare(label, replacing=not useful)
        require(code == 0, 'stop_prepare_failed')
        self.before = snapshot(self.target)
        self.plan_before = sha((self.plan / 'profile.json').read_bytes())
        self.offered, self.observed = set(), {}
        self.future_ready, self.future_release = threading.Event(), threading.Event()
        self.future_offered = threading.Event()
        self.closed = threading.Event()
        self.model = BASE.HOST.ScriptedModel([])
        targets = self.prepared['profile']['targets']
        index = next(i for i, t in enumerate(targets) if t['name'] == 'result.txt')
        args = {'path': 'result.txt', 'content': BASE.NEW}
        if not useful:
            old = targets[index]['replacement']
            args.update(old_identity=old['identity'], old_sha256=old['sha256'])
        self.proposals = [(('create' if useful else 'replace') + f'_output_{index}', args),
                          (f'read_output_{index}', {'path': 'result.txt'})]
        if useful:
            source = next(i for i, t in enumerate(targets) if t['name'] == 'source.txt')
            self.proposals.insert(0, (f'read_output_{source}', {'path': 'source.txt'}))

        def next_step(body):
            names = {t.get('name') for t in body.get('tools', [])}
            if not any(n and n.startswith('mcp__private-output__') for n in names):
                return [{'type': 'text', 'text': 'Owned auxiliary request.'}]
            require(len(self.model.requests) <= 32, 'stop_provider_request_cap')
            for message in body.get('messages', []):
                blocks = message.get('content', [])
                for block in blocks if isinstance(blocks, list) else []:
                    if isinstance(block, dict) and block.get('type') == 'tool_result' and block.get('tool_use_id') in self.offered:
                        self.observed[block['tool_use_id']] = {'is_error': bool(block.get('is_error')), 'content': block.get('content')}
            for i, (tool, arguments) in enumerate(self.proposals):
                identity = 'toolu_stop_' + str(i)
                if identity not in self.observed:
                    if hold and i == 1:
                        self.future_ready.set()
                        require(self.future_release.wait(60), 'stop_provider_barrier_timeout')
                        if self.closed.is_set():
                            return [{'type': 'text', 'text': 'Owned provider closed.'}]
                        self.future_offered.set()
                    require(identity not in self.offered, 'stop_proposal_reissued')
                    self.offered.add(identity)
                    return [{'type': 'tool_use', 'id': identity, 'name': 'mcp__private-output__' + tool, 'input': arguments}]
            return [{'type': 'text', 'text': 'Owned useful sequence complete.'}]
        self.model.next = next_step
        env = dict(suite.env, ANTHROPIC_API_KEY=secrets.token_hex(32), ANTHROPIC_BASE_URL=self.model.url,
                   HTTP_PROXY='http://127.0.0.1:9', HTTPS_PROXY='http://127.0.0.1:9', NO_PROXY='localhost,127.0.0.1,::1')
        prompt = suite.work / (label + '-prompt.txt')
        prompt.write_text('Use only the selected private output tools for this owned sequence.')
        prompt.chmod(0o600)
        self.output = suite.work / (label + '-stdout.private')
        self.errors = suite.work / (label + '-stderr.private')
        self.out, self.err = self.output.open('wb'), self.errors.open('wb')
        self.process = subprocess.Popen([str(suite.binary), 'edit-session', 'run', '--plan', str(self.plan),
            '--sha256', self.prepared['profile_sha256'], '--state', str(suite.state), '--prompt-file', str(prompt),
            '--timeout-seconds', '60'], env=env, cwd=suite.work, stdin=subprocess.DEVNULL,
            stdout=self.out, stderr=self.err, start_new_session=True)
        self.witness = BASE.BASE.ProcessWitness(self.process.pid)
        self.run = until(self.record, 'stop_running_record_missing')
        self.home = BASE.run_home(self.run)
        self.control = json.loads((self.run / 'control.json').read_bytes())
        require(self.control['launcher_pid'] == self.process.pid
                and self.control['launcher_start'] == BASE.BASE.ProcessWitness.identity(self.process.pid)
                and self.control['profile_sha256'] == self.prepared['profile_sha256'], 'stop_owned_control_binding')

    def record(self):
        rows = self.output.read_bytes().splitlines()
        return Path(json.loads(rows[0])['run']) if rows else None

    def pending(self):
        code, value = self.suite.ask(self.run, 'list')
        return value[0] if code == 0 and isinstance(value, list) and value else None

    def decision(self, row, approve=True):
        # Suite.ask owns the native positional separator, including IDs that
        # begin with '-'. Supply its logical argument order, not CLI argv.
        words = ['approve', row['pending_id'], '--binding', row['binding_sha256']] if approve else ['reject', row['pending_id']]
        return self.suite.ask(self.run, *words)

    def stop(self):
        return self.suite.cli('stop', '--run', self.run, '--output', 'json-v1', timeout=16)

    def audit(self):
        data = (self.home / 'audit.jsonl').read_bytes()
        require(len(data) <= 2 * 1024 * 1024, 'stop_audit_cap')
        return [json.loads(line) for line in data.splitlines() if line.strip()], sha(data)

    def finish(self, expected_exit=0):
        self.process.wait(timeout=15)
        self.out.close();self.err.close()
        cleanup = self.witness.finish()
        require(cleanup['all_stopped'] and cleanup['descendant_count'] >= 2, 'stop_owned_cleanup_failed')
        if expected_exit is not None:
            require(self.process.returncode == expected_exit, 'stop_unexpected_launcher_exit')
        require(sha((self.plan / 'profile.json').read_bytes()) == self.plan_before, 'stop_changed_immutable_plan')
        require(not any(p.name.startswith('.soup-') for p in self.root.iterdir()), 'stop_staging_remains')
        raw = self.errors.read_bytes()
        require(b'"mutation_dispatches":1' not in raw and b'edit_adapter_mutation_dispatch' not in raw, 'stop_adapter_mutation')
        rows, audit_sha = self.audit()
        diagnosis = None
        terminal = json.loads((self.run / 'terminal.json').read_bytes()) if (self.run / 'terminal.json').exists() else None
        if terminal and terminal.get('reason') == 'operator_stop':
            before_state = BASE.private_state_witness(self.run)
            before_target, before_sentinel = snapshot(self.target), snapshot(self.suite.sentinel)
            code, observed = self.suite.cli('status', '--run', self.run, '--json', timeout=12)
            BASE.require_indeterminate_status(observed)
            require(code == 0 and observed.get('recorded_host_outcome') == 'recorded_operator_stop'
                    and observed.get('audit', {}).get('completeness') == 'selected_bounded_records_only',
                    'stop_diagnosis_lost_composed_audit')
            require(BASE.private_state_witness(self.run) == before_state
                    and snapshot(self.target) == before_target
                    and snapshot(self.suite.sentinel) == before_sentinel,
                    'stop_diagnosis_changed_owned_state')
            diagnosis = {'recorded_host_outcome': observed['recorded_host_outcome'],
                         'audit_completeness': observed['audit']['completeness'],
                         'effects': observed['effects'], 'state_unchanged': True,
                         'target_unchanged': True, 'sentinel_unchanged': True}
        return {'stop_diagnosis': diagnosis, 'process_cleanup': cleanup, 'exit': self.process.returncode,
                'profile_sha256': self.prepared['profile_sha256'],
                'instance_id': self.control['instance_id'], 'audit_sha256': audit_sha,
                'target_before': self.before, 'target_after': snapshot(self.target),
                'released_calls': sum(r.get('event') == 'native_call' and r.get('released') is True for r in rows),
                'publication_gates': sum(r.get('event') == 'native_publish' and r.get('released') is True for r in rows)}

    def close(self):
        self.closed.set();self.future_release.set()
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGCONT)
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL);self.process.wait(timeout=5)
        for stream in (self.out, self.err):
            if stream is not None: stream.close()
        if self.witness is not None: self.witness.finish()
        if self.model is not None: self.model.close()


def qualify(args, report):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0, 'native_linux_operator_required')
    require(sha(args.claude.read_bytes()) == BASE.CLAUDE and not args.output.is_relative_to(ROOT), 'outside_checkout_genuine_host_required')
    suite = BASE.Suite(args, report)
    active = []
    unrelated = subprocess.Popen(['/usr/bin/sleep', '600'], cwd=suite.work, env=suite.env)
    unrelated_start = BASE.BASE.ProcessWitness.identity(unrelated.pid)
    report.update(agentfw_sha256=sha(suite.binary.read_bytes()), claude_sha256=sha(suite.claude.read_bytes()),
                  scope='actual-native-installed-genuine-host-owned-scripted-provider', paid_inference=False)
    def begin(name):
        row = report['cases'][CASES.index(name)]
        row['attempted'] = True
        suite.active = row
        return row
    def done(row, **facts):
        require(unrelated.poll() is None and BASE.BASE.ProcessWitness.identity(unrelated.pid) == unrelated_start
                and snapshot(suite.sentinel) == suite.before_sentinel, 'stop_unrelated_witness_changed')
        row.update(facts, status='passed')
    def start(label, **kwargs):
        return Run(suite, label, active, **kwargs)
    try:
        row = begin('installed-identity')
        archive = args.output / 'component.tar'
        build = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/build-pilot-front-door.py'), '--out', str(archive)],
            env=suite.env, cwd=ROOT, capture_output=True, timeout=60)
        require(build.returncode == 0, 'stop_component_build_failed')
        built = json.loads(build.stdout.splitlines()[-1])
        install = subprocess.run([str(suite.binary), 'pilot-component', '--home', str(suite.home), 'install', str(archive),
            '--sha256', built['archive_sha256'], '--python', str(args.python)], env=suite.env, cwd=suite.work, capture_output=True, timeout=60)
        require(install.returncode == 0, 'stop_component_install_failed')
        report.update(source_commit=built['commit'], component=built['component'])
        done(row, source_commit=built['commit'], installed_outside_checkout=True)

        row = begin('two-live-exact-stop')
        selected = start('selected')
        pending = until(selected.pending, 'selected_pending_missing')
        selected_pending = dict(pending)
        peer = start('peer', hold=False, useful=True)
        peer_pending = until(peer.pending, 'peer_pending_missing')
        code, value = selected.stop()
        require(stop_ok(code, value, 'stopped'), 'selected_stop_not_confirmed')
        require(peer.process.poll() is None and snapshot(selected.target) == selected.before, 'selected_stop_affected_peer_or_target')
        selected_row = selected.finish()
        require(selected_row['publication_gates'] == 0, 'pending_stop_published')
        require(peer.decision(peer_pending)[0] == 0, 'peer_approval_failed')
        peer_row = peer.finish()
        require(peer.target.read_text() == BASE.NEW and len(peer.observed) == 3
                and all(not v['is_error'] for v in peer.observed.values()), 'peer_useful_sequence_failed')
        done(row, selected=selected_row, peer=peer_row, stop=value, peer_useful_read_edit_read=True)

        row = begin('pending-replay-and-repeat')
        require(selected.decision(pending)[0] != 0, 'stopped_pending_approved')
        require(not any((selected.home / 'native-pending').glob('*.json')), 'selected_pending_remains')
        require(not any((selected.home / 'native-grants').glob('*.json')), 'selected_unused_grant_remains')
        code, value = selected.stop()
        require(stop_ok(code, value, 'already_stopped') and snapshot(selected.target) == selected.before, 'repeat_stop_not_safe')
        done(row, stop=value, old_approval_refused=True)

        for label, approve in [('rejected-ask-future-dispatch', False), ('publication-before-stop', True)]:
            row = begin(label)
            run = start(label)
            pending = until(run.pending, label + '_pending_missing')
            require(run.decision(pending, approve)[0] == 0, 'stop_decision_failed')
            until(run.future_ready.is_set, 'post_result_provider_barrier_missing')
            require(run.observed['toolu_stop_0']['is_error'] is not approve, 'stop_decision_result_wrong')
            code, value = run.stop()
            require(stop_ok(code, value, 'stopped'), 'post_result_stop_unconfirmed')
            audit_before = run.audit()[1]
            run.future_release.set()
            until(run.future_offered.is_set, 'future_proposal_not_attempted')
            time.sleep(.15)
            facts = run.finish()
            require(run.audit()[1] == audit_before and 'toolu_stop_1' not in run.observed, 'dispatch_after_stop_confirmation')
            require(run.target.read_text() == (BASE.NEW if approve else BASE.OLD), 'post_stop_target_wrong')
            done(row, **facts, stop=value, future_proposal_attempted=True, no_post_confirmation_dispatch=True,
                 committed_effect_preserved=approve)

        row = begin('publication-stop-race')
        run = start('publication-race')
        pending = until(run.pending, 'race_pending_missing')
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            decision = pool.submit(run.decision, pending)
            stopping = pool.submit(run.stop)
            code, value = stopping.result(timeout=18)
            decision.result(timeout=18)
        require(stop_ok(code, value, 'stopped'), 'publication_race_stop_unconfirmed')
        facts = run.finish()
        require(run.target.read_text() in (BASE.OLD, BASE.NEW) and facts['publication_gates'] <= 1, 'publication_race_effect_wrong')
        before = run.audit()[1];time.sleep(.1)
        require(run.audit()[1] == before, 'publication_after_race_confirmation')
        done(row, **facts, stop=value, effect_may_have_committed=True, automatic_retry=False)

        row = begin('unsafe-records')
        run = start('record-controls')
        until(run.pending, 'record_control_pending_missing')
        path = run.run / 'control.json'
        original = path.read_bytes()
        results = []
        def refuse(label, mutate, restore):
            try:
                mutate()
                code, value = run.stop()
                require(code != 0 and value.get('cleanup_confirmed') is False and value.get('owner_verified') is False,
                        'unsafe_control_accepted_' + label)
                require(run.process.poll() is None and not (run.run / 'stop-request.json').exists(), 'unsafe_control_had_effect_' + label)
                results.append({'id': label, 'reason': value['reason'], 'effect': False})
            finally:
                restore()
        def write(raw):
            path.chmod(0o600);path.write_bytes(raw);path.chmod(0o400)
        for label, raw in [('malformed', b'{'), ('oversized', b'x' * 16385),
                           ('duplicate-field', original.replace(b'{', b'{"contract":"forged",', 1))]:
            refuse(label, lambda raw=raw: write(raw), lambda: write(original))
        saved = run.run / 'control.retained'
        def special(kind):
            path.rename(saved)
            if kind == 'fifo': os.mkfifo(path, 0o600)
            elif kind == 'symlink': path.symlink_to(saved)
            else: os.link(saved, path)
        def restore():
            path.unlink();saved.rename(path)
        for kind in ('fifo', 'symlink', 'hardlink'):
            refuse(kind, lambda kind=kind: special(kind), restore)
        refuse('public-mode', lambda: path.chmod(0o644), lambda: path.chmod(0o400))
        alias = run.run.with_name(run.run.name + '-alias')
        run.run.rename(alias);run.run.symlink_to(alias, target_is_directory=True)
        try:
            code, value = run.stop()
            require(code != 0 and value['owner_verified'] is False, 'linked_run_directory_accepted')
            results.append({'id': 'linked-run-directory', 'reason': value['reason'], 'effect': False})
        finally:
            run.run.unlink();alias.rename(run.run)
        done(row, controls=results, actual_cli=True)

        row = begin('foreign-birth-identity')
        results = []
        for label, fields in [('birth-mismatch', {'launcher_start': run.control['launcher_start'] + 1}),
                              ('foreign-pid', {'launcher_pid': unrelated.pid, 'launcher_start': unrelated_start}),
                              ('foreign-profile', {'profile_sha256': 'f' * 64}),
                              ('foreign-instance', {'instance_id': 'foreign-instance'})]:
            altered = dict(run.control, **fields)
            refuse(label, lambda altered=altered: write(json.dumps(altered).encode()), lambda: write(original))
        refuse('foreign-run-record', lambda: write((peer.run / 'control.json').read_bytes()), lambda: write(original))
        code, value = run.stop();require(stop_ok(code, value, 'stopped'), 'record_control_final_stop_failed')
        facts = run.finish()
        done(row, controls=results, **facts, pid_reuse_scope='controlled birth mismatch; no forced kernel PID reuse')

        row = begin('old-control-replay')
        fresh = start('replay-controls')
        until(fresh.pending, 'replay_control_pending_missing')
        require(fresh.decision(selected_pending)[0] != 0 and snapshot(fresh.target) == fresh.before,
                'old_approval_crossed_fresh_run')
        controls = []
        for name in ('stop-request.json', 'stop-receipt.json'):
            replay = fresh.run / name
            replay.write_bytes((selected.run / name).read_bytes());replay.chmod(0o600)
            code, value = fresh.stop()
            require(code != 0 and value['cleanup_confirmed'] is False and fresh.process.poll() is None, 'old_stop_control_replayed')
            controls.append({'id': name, 'reason': value['reason']})
            replay.unlink()
        code, value = fresh.stop();require(stop_ok(code, value, 'stopped'), 'fresh_control_stop_failed')
        done(row, controls=controls, **fresh.finish())

        row = begin('daemon-unavailable')
        unavailable = start('unavailable')
        until(unavailable.pending, 'unavailable_pending_missing')
        unavailable.process.send_signal(signal.SIGSTOP)
        try:
            code, value = unavailable.stop()
            require(code != 0 and value['reason'] == 'daemon_unverified' and value['cleanup_confirmed'] is False
                    and not (unavailable.run / 'stop-request.json').exists(), 'unresponsive_daemon_claimed_stopped')
        finally:
            unavailable.process.send_signal(signal.SIGCONT)
        code2, recovered = unavailable.stop();require(stop_ok(code2, recovered, 'stopped'), 'unresponsive_owner_recovery_failed')
        done(row, refusal=value, recovery=recovered, scope='actual suspended embedded daemon; no signal or intent on failed authentication', **unavailable.finish())

        row = begin('launcher-crash')
        crashed = start('crashed')
        until(crashed.pending, 'crash_pending_missing')
        crashed.process.kill();crashed.process.wait(timeout=5)
        code, value = crashed.stop()
        require(code != 0 and value['cleanup_confirmed'] is False and value['revocation_confirmed'] is False
                and not (crashed.run / 'stop-receipt.json').exists(), 'crash_was_false_confirmed')
        facts = crashed.finish(expected_exit=None)
        require(snapshot(crashed.target) == crashed.before, 'crash_mutated_pending_target')
        done(row, refusal=value, scope='actual SIGKILL; daemon shares launcher process; observed cleanup is not an owner receipt', **facts)

        row = begin('fresh-useful-run')
        fresh = start('fresh-useful', hold=False, useful=True)
        pending = until(fresh.pending, 'fresh_useful_pending_missing')
        require(fresh.decision(pending)[0] == 0, 'fresh_useful_approval_failed')
        facts = fresh.finish()
        require(fresh.target.read_text() == BASE.NEW and len(fresh.observed) == 3
                and all(not v['is_error'] for v in fresh.observed.values()), 'fresh_useful_sequence_failed')
        require(fresh.control['instance_id'] != selected.control['instance_id'], 'fresh_epoch_not_fresh')
        done(row, **facts, useful_read_edit_read=True)
        report.update(status='passed', unrelated_process_preserved=True)
        require(passed(report), 'stop_incomplete_inventory')
    finally:
        for run in active:
            run.close()
        unrelated.terminate();unrelated.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--agentfw', type=Path)
    parser.add_argument('--claude', type=Path)
    parser.add_argument('--python', type=Path, default=Path('/usr/bin/python3.12'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'format': FORMAT, 'executed': False, 'expected': list(CASES)}));return 0
    require(args.output and args.output.is_absolute() and not args.output.exists(), 'new_absolute_output_required')
    args.output.mkdir(mode=0o700)
    report = {'format': FORMAT, 'status': 'incomplete', 'paid_inference': False, 'expected': list(CASES),
              'cases': [{'id': name, 'status': 'incomplete', 'attempted': False} for name in CASES]}
    try:
        qualify(args, report)
    except Exception as error:
        report.update(status='failed', failure_type=type(error).__name__, failure=str(error)[:160])
        for row in report['cases']:
            if row['attempted'] and row['status'] == 'incomplete': row.update(status='failed', failure=str(error)[:160])
    report['inventory'] = {key: sum(row['status'] == key for row in report['cases']) for key in ('passed', 'failed', 'incomplete')}
    (args.output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'format': FORMAT, 'status': report['status'], 'inventory': report['inventory']}))
    return 0 if passed(report) else 1


if __name__ == '__main__':
    raise SystemExit(main())
