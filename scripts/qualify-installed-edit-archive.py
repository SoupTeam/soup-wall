#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in bounded installed edit archival qualification; no paid inference.

Genuine host flows use the accepted SOU-161 driver. Fault windows use the exact
installed archival helper with an explicitly reported qualification-only pause.
No fixture hook is added to the product CLI.
"""
import argparse
import errno
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
spec = importlib.util.spec_from_file_location('archive_native_base', ROOT / 'scripts/qualify-installed-edit.py')
B = importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
spec = importlib.util.spec_from_file_location('archive_stop_base', ROOT / 'scripts/qualify-installed-edit-stop.py')
STOP = importlib.util.module_from_spec(spec);spec.loader.exec_module(STOP)
spec = importlib.util.spec_from_file_location('archive_accepted_quota', ROOT / 'scripts/qualify-edit-quota.py')
Q = importlib.util.module_from_spec(spec);spec.loader.exec_module(Q)
require, sha, snapshot = B.require, B.sha, B.snapshot
FORMAT = 'sw-installed-edit-archive-qualification/1'
CASES = ('installed-identity', 'two-active-runs-refused', 'completed-archive-cleanup', 'interrupted-run-archive', 'stop-archive-cleanup',
         'unknown-crash-refused', 'changed-preview-refused', 'descriptive-snapshot-refusals', 'linked-and-special-state', 'foreign-owner-refused',
         'private-secret-canaries', 'native-low-space', 'interrupted-archive-before-publication',
         'interrupted-archive-after-publication', 'interrupted-removal-recovery', 'fresh-useful-run',
         'quota-v2-completed-archive-cleanup', 'quota-v2-malformed-refusals')
QUOTA_REFUSALS = {
    'profile-null': 'edit_quota_limits_invalid',
    'profile-version': 'edit_snapshot_profile_invalid',
    'terminal-null': 'edit_quota_usage_invalid',
    'terminal-missing': 'edit_quota_profile_mismatch',
    'terminal-extra': 'edit_quota_usage_invalid',
    'terminal-version': 'edit_quota_limits_invalid',
    'terminal-limits': 'edit_quota_profile_mismatch',
    'terminal-boolean': 'edit_quota_usage_invalid',
    'terminal-overflow': 'edit_quota_usage_invalid',
    'terminal-sum': 'edit_quota_usage_contradictory',
    'terminal-remaining': 'edit_quota_usage_contradictory',
    'terminal-unavailable': 'edit_quota_evidence_unavailable',
    'terminal-unsettled': 'edit_quota_evidence_indeterminate',
}


def until(check, code, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value: return value
        time.sleep(.02)
    raise ValueError(code)


def passed(report):
    rows = {row.get('id'): row for row in report.get('cases', [])}
    v1 = rows.get('completed-archive-cleanup', {})
    v2 = rows.get('quota-v2-completed-archive-cleanup', {})
    negatives = rows.get('quota-v2-malformed-refusals', {})
    return (report.get('format') == FORMAT and report.get('status') == 'passed'
            and report.get('expected') == list(CASES) and report.get('claude_sha256') == B.CLAUDE
            and report.get('paid_inference') is False and report.get('preserved') is True
            and [row.get('id') for row in report.get('cases', [])] == list(CASES)
            and all(row.get('status') == 'passed' and row.get('attempted') is True for row in report['cases'])
            and v1.get('profile_format') == Q.LEGACY_PROFILE
            and v2.get('profile_format') == Q.PROFILE
            and all(v2.get(key) is True for key in ('genuine_read_edit_read', 'exact_limits_bound',
                'source_retained_after_archive', 'output_preserved', 'immutable_plan_preserved', 'sentinel_preserved'))
            and v2.get('consent_refusal') == 'explicit_raw_evidence_loss_consent_required'
            and v2.get('cleanup_outcome') == 'archived_and_cleaned' and v2.get('repeat_outcome') == 'already_cleaned'
            and v2.get('quota_is_execution_proof') is False
            and negatives.get('source_retained') is True and negatives.get('preserved') is True
            and [r.get('id') for r in negatives.get('controls', [])] == list(QUOTA_REFUSALS)
            and all(type(r.get('exit_code')) is int and r['exit_code'] == 1
                    and r.get('reason') == QUOTA_REFUSALS[r['id']] and r.get('unchanged') is True
                    for r in negatives['controls']))


class Live:
    def __init__(self, suite, label, active):
        self.suite, self.process, self.model, self.witness = suite, None, None, None
        self.out = self.err = None
        self.release, self.ready = threading.Event(), threading.Event()
        active.append(self)
        self.root, self.target, self.plan, code, prepared = suite.prepare(label, replacing=True)
        require(code == 0, 'active_prepare_failed')
        self.before, self.plan_sha = snapshot(self.target), sha((self.plan / 'profile.json').read_bytes())
        self.model = B.HOST.ScriptedModel([])
        def proposal(body):
            if any(str(t.get('name', '')).startswith('mcp__private-output__') for t in body.get('tools', [])):
                self.ready.set();require(self.release.wait(170), 'active_provider_barrier_timeout')
            return [{'type': 'text', 'text': 'Owned qualification run finished.'}]
        self.model.next = proposal
        prompt = suite.work / (label + '-prompt');prompt.write_text('Use only the owned selected private tools.');prompt.chmod(0o600)
        output = suite.work / (label + '-stdout.private');errors = suite.work / (label + '-stderr.private')
        self.out, self.err = output.open('wb'), errors.open('wb')
        env = dict(suite.env, ANTHROPIC_API_KEY=secrets.token_hex(32), ANTHROPIC_BASE_URL=self.model.url,
                   HTTP_PROXY='http://127.0.0.1:9', HTTPS_PROXY='http://127.0.0.1:9', NO_PROXY='localhost,127.0.0.1,::1')
        self.process = subprocess.Popen([str(suite.binary), 'edit-session', 'run', '--plan', str(self.plan),
            '--sha256', prepared['profile_sha256'], '--state', str(suite.state), '--prompt-file', str(prompt),
            '--timeout-seconds', '180'], cwd=suite.work, env=env, stdin=subprocess.DEVNULL,
            stdout=self.out, stderr=self.err, start_new_session=True)
        self.witness = B.BASE.ProcessWitness(self.process.pid)
        def record():
            lines = output.read_bytes().splitlines()
            return Path(json.loads(lines[0])['run']) if lines else None
        self.run = until(record, 'active_run_record_missing')
        until(self.ready.is_set, 'genuine_active_provider_not_observed')

    def finish(self, crash=False):
        self.process.send_signal(signal.SIGKILL if crash else signal.SIGINT)
        self.process.wait(timeout=12);self.release.set()
        result = self.witness.finish()
        require(result['all_stopped'] and result['descendant_count'] >= 2, 'active_owned_cleanup_failed')
        require(snapshot(self.target) == self.before and sha((self.plan / 'profile.json').read_bytes()) == self.plan_sha,
                'active_target_or_plan_changed')
        return result

    def close(self):
        self.release.set()
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try: self.process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL);self.process.wait(timeout=5)
        if self.witness is not None: self.witness.finish()
        for stream in (self.out, self.err):
            if stream is not None: stream.close()
        if self.model is not None: self.model.close()


def qualify(args, report):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0, 'native_linux_operator_required')
    require(sha(args.claude.read_bytes()) == B.CLAUDE and not args.output.is_relative_to(ROOT), 'outside_checkout_genuine_host_required')
    suite = Q.Suite(args, report)
    active = [];preserved = []
    unrelated = subprocess.Popen(['/usr/bin/sleep', '600'], cwd=suite.work, env=suite.env)
    unrelated_birth = B.BASE.ProcessWitness.identity(unrelated.pid)
    def begin(name):
        row = report['cases'][CASES.index(name)];row['attempted'] = True;suite.active = row;return row
    def done(row, **facts):
        require(unrelated.poll() is None and B.BASE.ProcessWitness.identity(unrelated.pid) == unrelated_birth
                and snapshot(suite.sentinel) == suite.before_sentinel, 'unrelated_witness_changed')
        for target, before, plan, plan_before in preserved:
            require(snapshot(target) == before and plan_witness(plan) == plan_before, 'output_or_plan_changed')
        row.update(facts, status='passed')
    def plan_witness(plan):
        return {name: snapshot(plan / name) for name in ('profile.json', 'profile.sha256')}
    def snapshots(run, plan):
        names = ('profile.json', 'profile.sha256', 'diagnostic-context.json', 'host-process.json')
        result = {name: snapshot(run / name) for name in names}
        require(all(v['exists'] and v['links'] == 1 and v['mode'] & 0o777 == 0o400 for v in result.values())
                and (run / 'profile.json').read_bytes() == (plan / 'profile.json').read_bytes()
                and (run / 'profile.sha256').read_bytes() == (plan / 'profile.sha256').read_bytes(),
                'current_main_run_snapshot_missing_or_unbound')
        return result
    def cli(action, *words):
        return suite.cli('archive', '--home', suite.home, action, *words, timeout=35)
    def prepare_archive(run, label, destination=None):
        destination = destination or args.output / ('archives-' + label)
        if not destination.exists(): destination.mkdir(mode=0o700)
        code, plan = cli('preview', '--run', run, '--destination', destination)
        require(code == 0 and plan.get('full_forensic_backup') is False, 'archive_preview_failed_' + label)
        plan_path = suite.work / (label + '-archive-plan.json')
        plan_path.write_text(json.dumps(plan, sort_keys=True));plan_path.chmod(0o600)
        return plan, ['--plan', plan_path, '--confirm', plan['plan_sha256']]
    def useful(label):
        root, target, plan, code, prepared = suite.prepare(label, replacing=True)
        require(code == 0, 'useful_prepare_failed')
        index = next(i for i, t in enumerate(prepared['profile']['targets']) if t['name'] == 'result.txt')
        old = prepared['profile']['targets'][index]['replacement']
        proposals = [(f'read_output_{index}', {'path': 'result.txt'}),
            (f'replace_output_{index}', {'path': 'result.txt', 'content': B.NEW, 'old_identity': old['identity'], 'old_sha256': old['sha256']}),
            (f'read_output_{index}', {'path': 'result.txt'})]
        facts, observed, _ = suite.host(label, root, target, plan, prepared, proposals)
        require(facts['exit'] == 0 and target.read_text() == B.NEW and len(observed) == 3
                and all(not item['is_error'] for item in observed.values()), 'useful_installed_sequence_failed')
        require(B.NEW.strip() in json.dumps(observed['toolu_edit_2']['content']), 'useful_installed_readback_missing')
        preserved.append((target, snapshot(target), plan, plan_witness(plan)))
        return suite.last_run, facts
    def apply_archive(bound):
        code, value = cli('apply', *bound)
        require(code == 0 and value['outcome'] == 'archived_source_retained', 'sanitized_archive_not_verified')
        return value
    def completed_copy(label):
        # Fresh genuine completion, not fabricated terminal state.
        return useful(label)[0]
    try:
        row = begin('installed-identity')
        archive = args.output / 'component.tar'
        built = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/build-pilot-front-door.py'), '--out', str(archive)],
            cwd=ROOT, env=suite.env, capture_output=True, timeout=60)
        require(built.returncode == 0, 'component_build_failed')
        identity = json.loads(built.stdout.splitlines()[-1])
        installed = subprocess.run([str(suite.binary), 'pilot-component', '--home', str(suite.home), 'install', str(archive),
            '--sha256', identity['archive_sha256'], '--python', str(args.python)], cwd=suite.work, env=suite.env,
            capture_output=True, timeout=60)
        require(installed.returncode == 0, 'component_install_failed')
        report.update(source_commit=identity['commit'], component=identity['component'],
                      agentfw_sha256=sha(suite.binary.read_bytes()), claude_sha256=B.CLAUDE, paid_inference=False)
        done(row, installed_outside_checkout=True)

        row = begin('two-active-runs-refused')
        first, peer = Live(suite, 'active-first', active), Live(suite, 'active-peer', active)
        destination = args.output / 'active-archives';destination.mkdir(mode=0o700)
        refusals = []
        for run in (first, peer):
            code, value = cli('preview', '--run', run.run, '--destination', destination)
            require(code != 0 and value.get('reason') == 'edit_run_active' and run.process.poll() is None, 'active_run_archive_accepted')
            refusals.append(value['reason'])
        done(row, refusals=refusals, genuine_active_roots=2)

        row = begin('completed-archive-cleanup')
        run, facts = useful('completed')
        profile_format = json.loads((run / 'profile.json').read_bytes())['format']
        require(profile_format == Q.LEGACY_PROFILE, 'legacy_archive_witness_not_v1')
        descriptive = snapshots(run, preserved[-1][2])
        plan, bound = prepare_archive(run, 'completed')
        value = apply_archive(bound)
        require(run.exists() and first.process.poll() is None and peer.process.poll() is None, 'archive_touched_source_or_active_peer')
        code, refusal = cli('cleanup', *bound)
        require(code != 0 and refusal['reason'] == 'explicit_raw_evidence_loss_consent_required' and run.exists(), 'cleanup_without_consent')
        code, value = cli('cleanup', *bound, '--acknowledge-evidence-loss')
        require(code == 0 and value['outcome'] == 'archived_and_cleaned' and not run.exists(), 'exact_run_cleanup_failed')
        code, again = cli('cleanup', *bound, '--acknowledge-evidence-loss')
        require(code == 0 and again['outcome'] == 'already_cleaned', 'repeat_cleanup_not_bound_to_commit')
        done(row, process_cleanup=facts['process_cleanup'], reclaimed_bytes=plan['inventory']['bytes'],
             inventoried_files=len(plan['inventory']['files']), archive=value, repeat=again,
             profile_sha256=plan['run_record']['profile_sha256'], plan_sha256=plan['plan_sha256'],
             instance_sha256=sha(plan['run_record']['instance_id'].encode()),
             descriptive_snapshots=descriptive, output_preserved=True, immutable_plan_preserved=True,
             profile_format=profile_format)

        row = begin('interrupted-run-archive')
        cleanup = first.finish()
        plan, bound = prepare_archive(first.run, 'interrupted')
        require(plan['terminal']['state'] == 'failed' and plan['terminal']['reason'] == 'cancelled', 'interruption_was_relabelled')
        apply_archive(bound)
        code, value = cli('cleanup', *bound, '--acknowledge-evidence-loss')
        require(code == 0 and value['outcome'] == 'archived_and_cleaned', 'interrupted_terminal_cleanup_failed')
        done(row, process_cleanup=cleanup, terminal_state='failed', reason='cancelled')

        row = begin('stop-archive-cleanup')
        stopped = STOP.Run(suite, 'stop-archive', active)
        pending = until(stopped.pending, 'archive_stop_pending_missing')
        require(stopped.decision(pending)[0] == 0, 'archive_stop_approval_failed')
        until(stopped.future_ready.is_set, 'archive_stop_postcommit_barrier_missing')
        require(stopped.target.read_text() == B.NEW and stopped.observed['toolu_stop_0']['is_error'] is False,
                'archive_stop_useful_commit_missing')
        target_before, plan_before = snapshot(stopped.target), plan_witness(stopped.plan)
        descriptive = snapshots(stopped.run, stopped.plan)
        code, stop = stopped.stop()
        require(STOP.stop_ok(code, stop, 'stopped'), 'archive_stop_not_confirmed')
        stopped.future_release.set()
        facts = stopped.finish()
        require(facts['publication_gates'] == 1 and facts['stop_diagnosis']['state_unchanged'] is True,
                'archive_stop_publication_or_diagnosis_lost')
        preserved.append((stopped.target, target_before, stopped.plan, plan_before))
        plan, bound = prepare_archive(stopped.run, 'stop-archive')
        require(plan['terminal']['reason'] == 'operator_stop' and plan['terminal']['state'] == 'failed'
                and set(descriptive) <= set(plan['inventory']['files']), 'archive_stop_terminal_or_snapshot_lost')
        archived = apply_archive(bound)
        require(stopped.run.exists(), 'archive_stop_apply_removed_source')
        code, refusal = cli('cleanup', *bound)
        require(code != 0 and refusal['reason'] == 'explicit_raw_evidence_loss_consent_required'
                and stopped.run.exists(), 'archive_stop_cleanup_without_consent')
        code, cleaned = cli('cleanup', *bound, '--acknowledge-evidence-loss')
        require(code == 0 and cleaned['outcome'] == 'archived_and_cleaned' and not stopped.run.exists(),
                'archive_stopped_run_cleanup_failed')
        done(row, stop={k: stop[k] for k in ('status', 'revocation_confirmed', 'cleanup_confirmed',
             'effects_may_remain_committed', 'running_effects_rolled_back', 'automatic_retry')},
             terminal_reason='operator_stop', process_cleanup=facts['process_cleanup'],
             profile_sha256=facts['profile_sha256'], instance_sha256=sha(facts['instance_id'].encode()),
             plan_sha256=plan['plan_sha256'], descriptive_snapshots=descriptive,
             target_before=target_before, target_after=snapshot(stopped.target),
             immutable_plan_before=plan_before, immutable_plan_after=plan_witness(stopped.plan),
             archive_sha256=archived['archive_sha256'], consent_refusal=refusal['reason'],
             cleanup_outcome=cleaned['outcome'], sentinel_preserved=True, active_peer_preserved=peer.process.poll() is None)

        row = begin('unknown-crash-refused')
        crashed = Live(suite, 'unknown-crash', active);cleanup = crashed.finish(crash=True)
        code, value = cli('preview', '--run', crashed.run, '--destination', destination)
        require(code != 0 and not (crashed.run / 'terminal.json').exists() and crashed.run.exists(), 'missing_pid_was_completion')
        done(row, process_cleanup=cleanup, refusal=value, absent_pid_is_not_completion=True)

        row = begin('changed-preview-refused')
        run = completed_copy('changed-preview');plan, bound = prepare_archive(run, 'changed-preview')
        path = run / 'host-bun.toml';before = path.read_bytes();path.write_bytes(before + b'changed')
        code, value = cli('apply', *bound)
        require(code != 0 and run.exists(), 'changed_inventory_archived')
        done(row, refusal=value)

        row = begin('descriptive-snapshot-refusals')
        run = completed_copy('snapshot-refusals');results = []
        for name, field, invalid in [('diagnostic-context.json', 'instance_id', 'z' * 43),
                                     ('host-process.json', 'uid', os.getuid() + 1),
                                     ('profile.json', 'future_version', 2)]:
            path = run / name;original = path.read_bytes();value = json.loads(original);value[field] = invalid
            path.chmod(0o600);path.write_text(json.dumps(value));path.chmod(0o400)
            code, refusal = cli('preview', '--run', run, '--destination', destination)
            require(code != 0 and run.exists() and path.exists(), 'unbound_descriptive_snapshot_accepted')
            results.append({'id': name, 'reason': refusal.get('reason')})
            path.chmod(0o600);path.write_bytes(original);path.chmod(0o400)
        unknown = run / 'unknown-snapshot.json';unknown.write_bytes(b'{}');unknown.chmod(0o400)
        code, refusal = cli('preview', '--run', run, '--destination', destination)
        require(code != 0 and unknown.read_bytes() == b'{}', 'unknown_snapshot_removed_or_accepted')
        results.append({'id': 'unknown-snapshot.json', 'reason': refusal.get('reason')});unknown.unlink()
        done(row, controls=results, source_retained=True)

        row = begin('linked-and-special-state')
        run = completed_copy('linked-state');path = run / 'host-bun.toml';original = path.read_bytes()
        results = []
        for kind in ('symlink', 'fifo', 'hardlink'):
            path.unlink()
            if kind == 'symlink': path.symlink_to(suite.sentinel)
            elif kind == 'fifo': os.mkfifo(path, 0o600)
            else: os.link(suite.sentinel, path)
            code, value = cli('preview', '--run', run, '--destination', destination)
            require(code != 0 and run.exists(), 'linked_or_special_state_accepted')
            results.append({'id': kind, 'reason': value.get('reason')})
            path.unlink();path.write_bytes(original);path.chmod(0o644)
        for name in ('.git', 'profile.json', 'profile.sha256'):
            marker = run / 'host-home' / name
            marker.write_bytes(b'Owned nested project or immutable plan.');marker.chmod(0o600)
            before_marker = snapshot(marker)
            code, value = cli('preview', '--run', run, '--destination', destination)
            require(code != 0 and value.get('reason') == 'project_or_immutable_plan_retained'
                    and snapshot(marker) == before_marker, 'nested_project_or_plan_was_selected')
            results.append({'id': name, 'reason': value['reason']})
            marker.unlink()
        alias = run.parent.with_name(run.parent.name + '-alias');run.parent.rename(alias);run.parent.symlink_to(alias)
        try:
            code, value = cli('preview', '--run', run, '--destination', destination)
            require(code != 0, 'linked_parent_accepted');results.append({'id': 'linked-parent', 'reason': value.get('reason')})
        finally: run.parent.unlink();alias.rename(run.parent)
        done(row, controls=results)

        row = begin('foreign-owner-refused')
        run = completed_copy('foreign-state')
        require(args.foreign_record and args.foreign_record.stat().st_uid != os.getuid(), 'real_foreign_owner_fixture_required')
        foreign = run / 'host-home/foreign-record';args.foreign_record.rename(foreign)
        try:
            code, value = cli('preview', '--run', run, '--destination', destination)
            require(code != 0 and run.exists(), 'foreign_owner_accepted')
        finally: foreign.rename(args.foreign_record)
        done(row, refusal=value, kernel_foreign_uid=True, scope='trusted setup empty foreign-owned fixture')

        row = begin('private-secret-canaries')
        run = completed_copy('secret-canaries');home = B.run_home(run)
        canary = 'owned-raw-secret-' + secrets.token_hex(16)
        secret = run / 'host-home' / (canary + '.txt');secret.write_text(canary);secret.chmod(0o600)
        with (home / 'audit.jsonl').open('ab') as stream:
            stream.write(json.dumps({'event': 'native_call', 'verdict': 'allow', 'shadow': False,
                                    'session': canary, 'tool': canary, 'args': {'content': canary}}).encode() + b'\n')
        tokens = [(home / name).read_bytes() for name in ('token', 'native-token')]
        plan, bound = prepare_archive(run, 'secret-canaries');archived = apply_archive(bound)
        raw = (Path(plan['destination']) / archived['archive']).read_bytes()
        require(canary.encode() not in raw and all(token not in raw for token in tokens), 'sanitized_archive_exposed_secret')
        done(row, source_retained=run.exists(), canaries_excluded=True, full_forensic_backup=False,
             scope='genuine run plus explicitly injected owned raw canaries')

        row = begin('native-low-space')
        require(args.low_space and os.statvfs(args.low_space).f_blocks * os.statvfs(args.low_space).f_frsize <= 131072,
                'private_bounded_tmpfs_required')
        small = args.low_space / 'archives';small.mkdir(mode=0o700)
        run = completed_copy('low-space');plan, bound = prepare_archive(run, 'low-space', small)
        filler = args.low_space / 'owned-filler';observed_errno = None
        with filler.open('wb', buffering=0) as stream:
            try:
                for _ in range(64): stream.write(b'x' * 4096)
            except OSError as error: observed_errno = error.errno
        require(observed_errno == errno.ENOSPC, 'kernel_no_space_not_observed')
        code, value = cli('apply', *bound)
        require(code != 0 and run.exists() and not (small / ('edit-' + plan['plan_sha256'] + '.zip')).exists(), 'no_space_removed_source')
        done(row, refusal=value, kernel_errno='ENOSPC', source_retained=True)

        # Fault window wrappers import exact installed helper bytes. Only a
        # local pause is injected; the kernel performs the actual SIGKILL.
        tree = suite.home / 'pilot-front-door/components' / report['component'] / 'tree'
        helper = tree / 'scripts/edit-run-archive.py'
        require(helper.is_file(), 'installed_archive_helper_missing')
        for label, action, hook in [('interrupted-archive-before-publication', 'archive', 'before'),
                                   ('interrupted-archive-after-publication', 'archive', 'after'),
                                   ('interrupted-removal-recovery', 'cleanup', 'remove')]:
            row = begin(label);run = completed_copy(label);plan, bound = prepare_archive(run, label)
            if action == 'cleanup': apply_archive(bound)
            marker = suite.work / (label + '-barrier')
            wrapper = suite.work / (label + '-fault.py')
            wrapper.write_text('''import importlib.util,pathlib,sys,time
spec=importlib.util.spec_from_file_location("installed_archive_fault",sys.argv[1])
E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E)
marker=pathlib.Path(sys.argv[2]);mode=sys.argv[3]
def pause():
 marker.write_text("owned-fault-window");time.sleep(60)
if mode=="remove":
 original=E.A.remove_member
 def controlled(*args,**kwargs):
  result=original(*args,**kwargs);pause();return result
 E.A.remove_member=controlled
else:
 original=E.A.os.link
 def controlled(*args,**kwargs):
  if mode=="before":pause()
  result=original(*args,**kwargs)
  if mode=="after":pause()
  return result
 E.A.os.link=controlled
raise SystemExit(E.main(sys.argv[4:]))
''');wrapper.chmod(0o600)
            words = [str(args.python), '-I', '-B', str(wrapper), str(helper), str(marker), hook, action, *map(str, bound)]
            if action == 'cleanup': words.append('--acknowledge-evidence-loss')
            with (suite.work / (label + '-fault.private')).open('wb') as output:
                process = subprocess.Popen(words, cwd=suite.work, env=suite.env, stdout=output, stderr=output, start_new_session=True)
                try:
                    until(marker.exists, 'archive_fault_window_not_reached');process.kill();process.wait(timeout=5)
                finally:
                    if process.poll() is None: process.kill();process.wait(timeout=5)
            if action == 'archive':
                require(run.exists(), 'interrupted_archive_removed_source')
                code, value = cli('cleanup', *bound, '--acknowledge-evidence-loss')
                require(code != 0 and run.exists(), 'incomplete_archive_authorized_removal')
                done(row, source_retained=True, refusal=value, scope='exact installed helper; controlled pause and actual SIGKILL')
            else:
                journal = 'edit-cleanup-' + plan['plan_sha256'] + '.json'
                code, value = cli('recover', *bound, '--journal', journal)
                require(code == 2 and value['outcome'] == 'incomplete' and value['source'] == 'quarantined', 'interrupted_removal_was_success')
                done(row, recovery=value, scope='exact installed helper; controlled pause and actual SIGKILL')

        row = begin('fresh-useful-run');run, facts = useful('fresh-useful')
        done(row, process_cleanup=facts['process_cleanup'], useful_read_edit_read=True)
        peer_cleanup = peer.finish()

        # Keep the original active-run deadlines unchanged. Quota witnesses run
        # after both original active peers have been independently cleaned up.
        row = begin('quota-v2-completed-archive-cleanup')
        suite.limits = (2, 4096)
        run, facts = useful('quota-v2-completed')
        target, target_before, original_plan, plan_before = preserved[-1]
        descriptive = snapshots(run, original_plan)
        profile = json.loads((run / 'profile.json').read_bytes())
        terminal = json.loads((run / 'terminal.json').read_bytes())
        expected_limits = {'contract_version':Q.QUOTA, 'max_mutations':2, 'max_write_bytes':4096}
        usage = terminal['mutation_quota']
        require(profile['format'] == Q.PROFILE and profile['mutation_quota'] == usage['limits'] == expected_limits
                and terminal['state'] == 'host_completed' and usage['admitted_mutation_attempts'] == 1
                and usage['known_committed_mutations'] == 1
                and usage['known_committed_write_bytes'] == usage['charged_write_bytes'] == len(B.NEW.encode())
                and usage['pending_prepublication_attempts'] == usage['indeterminate_publications'] == 0,
                'genuine_v2_quota_witness_invalid')
        archive_plan, bound = prepare_archive(run, 'quota-v2-completed')
        require(archive_plan['terminal']['mutation_quota'] == usage
                and set(descriptive) <= set(archive_plan['inventory']['files']), 'v2_quota_inventory_lost')
        archived = apply_archive(bound)
        require(run.exists(), 'v2_archive_apply_removed_source')
        code, refusal = cli('cleanup', *bound)
        require(code == 1 and refusal['reason'] == 'explicit_raw_evidence_loss_consent_required'
                and run.exists(), 'v2_cleanup_without_consent')
        code, cleaned = cli('cleanup', *bound, '--acknowledge-evidence-loss')
        require(code == 0 and cleaned['outcome'] == 'archived_and_cleaned' and not run.exists(), 'v2_cleanup_failed')
        code, repeated = cli('cleanup', *bound, '--acknowledge-evidence-loss')
        require(code == 0 and repeated['outcome'] == 'already_cleaned', 'v2_repeat_cleanup_unconfirmed')
        done(row, profile_format=profile['format'], quota_snapshot=usage, quota_is_execution_proof=False,
             genuine_read_edit_read=True, exact_limits_bound=True, source_retained_after_archive=True,
             consent_refusal=refusal['reason'], cleanup_outcome=cleaned['outcome'], repeat_outcome=repeated['outcome'],
             descriptive_snapshots=descriptive, profile_sha256=archive_plan['run_record']['profile_sha256'],
             instance_sha256=sha(archive_plan['run_record']['instance_id'].encode()),
             archive_sha256=archived['archive_sha256'], process_cleanup=facts['process_cleanup'],
             target_before=target_before, target_after=snapshot(target), immutable_plan_before=plan_before,
             immutable_plan_after=plan_witness(original_plan), output_preserved=True,
             immutable_plan_preserved=True, sentinel_preserved=True)

        row = begin('quota-v2-malformed-refusals')
        run, facts = useful('quota-v2-negative')
        destination = args.output / 'quota-negative-archives';destination.mkdir(mode=0o700)
        profile_path, terminal_path = run / 'profile.json', run / 'terminal.json'
        original_profile, original_terminal = profile_path.read_bytes(), terminal_path.read_bytes()
        controls = []
        for label, expected_reason in QUOTA_REFUSALS.items():
            profile, terminal = json.loads(original_profile), json.loads(original_terminal)
            usage = terminal['mutation_quota']
            path, changed = terminal_path, terminal
            if label == 'profile-null': profile['mutation_quota'] = None
            elif label == 'profile-version': profile['format'] = 'sw-installed-edit-session/3'
            elif label == 'terminal-null': terminal['mutation_quota'] = None
            elif label == 'terminal-missing': terminal.pop('mutation_quota')
            elif label == 'terminal-extra': usage['future'] = 0
            elif label == 'terminal-version': usage['limits']['contract_version'] = 'future'
            elif label == 'terminal-limits': usage['limits']['max_mutations'] = 3;usage['remaining_mutations'] = 2
            elif label == 'terminal-boolean': usage['admitted_mutation_attempts'] = True
            elif label == 'terminal-overflow': usage['charged_write_bytes'] = 2**64
            elif label == 'terminal-sum': usage['known_committed_mutations'] = 0
            elif label == 'terminal-remaining': usage['remaining_write_bytes'] += 1
            elif label == 'terminal-unavailable':
                terminal['mutation_quota'] = {'error_code':'edit_quota_state_unavailable', 'counts_known':False}
            elif label == 'terminal-unsettled':
                usage.update(known_committed_mutations=0, known_committed_write_bytes=0, pending_prepublication_attempts=1)
            if label.startswith('profile-'): path, changed = profile_path, profile
            original = path.read_bytes()
            try:
                path.chmod(0o600);path.write_bytes(Q.canonical(changed));path.chmod(0o400)
                before = B.private_state_witness(run)
                code, refusal = cli('preview', '--run', run, '--destination', destination)
                require(code == 1 and refusal['outcome'] == 'refused' and refusal['reason'] == expected_reason
                        and B.private_state_witness(run) == before and run.exists() and not list(destination.iterdir()),
                        'quota_negative_control_failed_' + label)
                controls.append({'id':label, 'exit_code':code, 'reason':refusal['reason'], 'unchanged':True})
            finally:
                path.chmod(0o600);path.write_bytes(original);path.chmod(0o400)
        # The same genuine run with its original metadata must still preview.
        code, restored = cli('preview', '--run', run, '--destination', destination)
        require(code == 0 and restored['terminal']['mutation_quota'] == json.loads(original_terminal)['mutation_quota'],
                'restored_v2_run_not_accepted')
        done(row, controls=controls, source_retained=True, preserved=True,
             process_cleanup=facts['process_cleanup'], restored_preview=True,
             scope='genuine completed v2 run with explicitly mutated retained metadata')
        suite.limits = None
        report.update(preserved=True, status='passed', active_peer_cleanup=peer_cleanup)
        require(passed(report), 'archive_qualification_incomplete')
    finally:
        for run in active: run.close()
        unrelated.terminate();unrelated.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    for name in ('agentfw', 'claude', 'output', 'low-space', 'foreign-record'): parser.add_argument('--' + name, type=Path)
    parser.add_argument('--python', type=Path, default=Path('/usr/bin/python3.12'))
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'format': FORMAT, 'executed': False, 'expected': list(CASES)}));return 0
    require(args.output and args.output.is_absolute() and not args.output.exists(), 'new_private_output_required')
    args.output.mkdir(mode=0o700)
    report = {'format': FORMAT, 'status': 'incomplete', 'expected': list(CASES), 'paid_inference': False,
              'cases': [{'id': name, 'status': 'incomplete', 'attempted': False} for name in CASES]}
    try: qualify(args, report)
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
