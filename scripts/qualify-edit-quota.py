#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in installed native edit quotas using genuine Claude and an owned provider.

The default is inert. Execution uses accepted installation/broker/Ask commands
outside the checkout. Raw contents, prompts, credentials and grants stay private.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import copy
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('accepted_edit_quota_base', ROOT / 'scripts/qualify-installed-edit.py')
EDIT = importlib.util.module_from_spec(spec);spec.loader.exec_module(EDIT)
require, sha, snapshot = EDIT.require, EDIT.sha, EDIT.snapshot
FORMAT = 'sw-installed-edit-quota-qualification/1'
PROFILE = 'sw-installed-edit-session/2'
LEGACY_PROFILE = 'sw-installed-edit-session/1'
QUOTA = 'sw-installed-edit-mutation-quota/1'
TEXT = EDIT.NEW
SECOND = 'Another bounded report: nine green containers.\n'
UNICODE = 'Бюджет: семь образцов 🚀\n'
CASES = ('installed-closure', 'legacy-profile', 'inert-preview', 'invalid-limits',
         'useful-create', 'useful-replace', 'exact-byte-limit', 'one-byte-over',
         'one-operation-over', 'zero-mutations', 'empty-write-count', 'ask-reject',
         'no-approval', 'unselected-target', 'create-not-replace', 'stale-replay',
         'parallel-last-credit', 'postcommit-withheld-create', 'postcommit-withheld-replace',
         'postcommit-interrupted-create', 'postcommit-interrupted-replace',
         'fresh-run-recovery', 'independent-run')


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()


def passed_report(report):
    rows = report.get('cases', [])
    required = {r.get('id'): r for r in rows}
    return (report.get('format') == FORMAT and report.get('status') == 'passed'
            and report.get('paid_inference') is False and report.get('claude_sha256') == EDIT.CLAUDE
            and report.get('expected') == list(CASES) and [r.get('id') for r in rows] == list(CASES)
            and all(r.get('attempted') is True and r.get('status') == 'passed' for r in rows)
            and required.get('useful-create', {}).get('exact_readback') is True
            and required.get('useful-replace', {}).get('exact_readback') is True
            and required.get('fresh-run-recovery', {}).get('old_epoch_refused') is True
            and required.get('independent-run', {}).get('both_runs_preserved') is True
            and all(required.get(name, {}).get('execution', {}).get('externally_observed_commit') is True
                    and required.get(name, {}).get('execution', {}).get('actual_success_result_observed') is False
                    for name in ('postcommit-withheld-create', 'postcommit-withheld-replace',
                                 'postcommit-interrupted-create', 'postcommit-interrupted-replace'))
            and report.get('sentinel_preserved') is True and report.get('owned_cleanup') is True)


class Suite(EDIT.Suite):
    limits = None

    def cli(self, *words, **kwargs):
        words = list(words)
        if words[0] in ('prepare', 'preview') and self.limits is not None and not any(
                str(w).startswith(('--max-mutations', '--max-write-bytes')) for w in words):
            words += ['--max-mutations', self.limits[0], '--max-write-bytes', self.limits[1]]
        return super().cli(*words, **kwargs)

    def select(self, label, limits, create=('result.txt',), replace=(), apply=True, root=None):
        self.limits = limits
        if root is None:
            root = self.work / label;root.mkdir(mode=0o700)
            for name in replace:
                (root / name).write_text(EDIT.OLD);(root / name).chmod(0o600)
        target = root / 'result.txt'
        plan = self.work / (label + '-plan')
        words = ['prepare', '--home', self.home, '--root', root, '--claude', self.claude,
                 '--private-sole-writer', '--out', plan]
        for name in sorted(set(create) | set(replace)):
            words += ['--read', name]
        for name in create:
            words += ['--create', name]
        for name in replace:
            words += ['--replace', name]
        if apply:
            words += ['--apply']
        code, prepared = self.cli(*words)
        require(code == 0, 'prepare_failed_' + label)
        require(prepared['profile']['format'] == (PROFILE if limits is not None else LEGACY_PROFILE), 'profile_version')
        if limits is not None:
            require(prepared['profile']['mutation_quota'] == {'contract_version': QUOTA,
                    'max_mutations': limits[0], 'max_write_bytes': limits[1]}, 'selected_limits_changed')
        require(sha(canonical(prepared['profile'])) == prepared['profile_sha256'], 'canonical_plan_digest')
        return root, target, plan, prepared

    def write_proposal(self, prepared, name='result.txt', content=TEXT):
        targets = prepared['profile']['targets'];index = next(i for i, t in enumerate(targets) if t['name'] == name)
        target = targets[index];arguments = {'path': name, 'content': content}
        if target['replacement'] is not None:
            arguments.update(old_identity=target['replacement']['identity'], old_sha256=target['replacement']['sha256'])
        return (('replace' if target['replacement'] else 'create') + f'_output_{index}', arguments)

    def read_proposal(self, prepared, name='result.txt'):
        index = next(i for i, t in enumerate(prepared['profile']['targets']) if t['name'] == name)
        return f'read_output_{index}', {'path': name}

    def quota_run(self, label, root, target, plan, prepared, proposals, mode='approve', batch=False):
        self.active = {}
        row, observed, config = self.host(label, root, target, plan, prepared, proposals, mode,
                                           timeout=12 if mode == 'no-approval' else 40, batch=batch)
        events = []
        raw = (self.work / (label + '-stderr.private')).read_bytes()
        for line in raw.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict) and event.get('event') == 'edit_mutation_quota':
                events.append(event)
        for before, after in zip(events, events[1:]):
            require(before['usage']['admitted_mutation_attempts'] <= after['usage']['admitted_mutation_attempts']
                    and before['usage']['charged_write_bytes'] <= after['usage']['charged_write_bytes'], 'active_quota_refunded')
        usage = (row['terminal'] or {}).get('mutation_quota') or (events[-1]['usage'] if events else None)
        require(usage is not None, 'quota_observation_missing')
        limits = prepared['profile']['mutation_quota']
        require(usage['admitted_mutation_attempts'] <= limits['max_mutations']
                and usage['charged_write_bytes'] <= limits['max_write_bytes']
                and usage['known_committed_mutations'] <= usage['admitted_mutation_attempts']
                and usage['known_committed_write_bytes'] <= usage['charged_write_bytes'], 'quota_ceiling_violated')
        row.update(usage=usage, quota_events=events, profile=prepared['profile'], profile_sha256=prepared['profile_sha256'])
        return row, observed, config


def qualify(args, report):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0,
            'native_linux_operator_required')
    require(sha(args.claude.read_bytes()) == EDIT.CLAUDE, 'genuine_pinned_claude_required')
    require(not args.output.is_relative_to(ROOT), 'outside_checkout_required')
    report['cases'][0]['attempted'] = True
    suite = Suite(args, report)
    report.update(agentfw_sha256=sha(suite.binary.read_bytes()), claude_sha256=sha(suite.claude.read_bytes()))
    archive = args.output / 'component.tar'
    built_result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/build-pilot-front-door.py'), '--out', str(archive)],
                                  cwd=ROOT, env=suite.env, capture_output=True, timeout=60)
    require(built_result.returncode == 0, 'component_build_failed')
    built = json.loads(built_result.stdout.splitlines()[-1])
    installed = subprocess.run([str(suite.binary), 'pilot-component', '--home', str(suite.home), 'install', str(archive),
                                '--sha256', built['archive_sha256'], '--python', str(args.python)],
                               cwd=suite.work, env=suite.env, capture_output=True, timeout=60)
    require(installed.returncode == 0, 'component_install_failed')
    report.update(source_commit=built['commit'], source_tree=subprocess.check_output(
        ['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT, text=True).strip(), component=built['component'])

    def begin(name):
        r = report['cases'][CASES.index(name)];r['attempted'] = True;suite.active = r

    def finish(name, **values):
        report['cases'][CASES.index(name)].update(status='passed', **values)

    def run_refused(plan, digest, target, label, reasons=None):
        before = snapshot(target);runs = sorted(p.name for p in suite.state.iterdir())
        prompt = suite.work / (label + '-prompt');prompt.write_text('Use only the selected bounded output tools.');prompt.chmod(0o600)
        code, _ = suite.cli('run', '--plan', plan, '--sha256', digest, '--state', suite.state, '--prompt-file', prompt)
        require(code != 0 and snapshot(target) == before and sorted(p.name for p in suite.state.iterdir()) == runs,
                'invalid_plan_started_' + label)
        if reasons is not None:
            require(suite.last_cli['reason'] in reasons, 'invalid_budget_not_typed_' + label)
        return dict(suite.last_cli, target_before=before, target_after=snapshot(target), new_runs=0)

    finish('installed-closure', source=built['commit'], component=built['component'])
    begin('legacy-profile')
    root, target, plan, prepared = suite.select('legacy', None)
    require('mutation_quota' not in prepared['profile'], 'legacy_received_implicit_limits')
    finish('legacy-profile', profile_sha256=prepared['profile_sha256'], quota_absent=True,
           compatibility='original_23_installed_cases_also_run_unchanged')
    begin('inert-preview')
    root, target, plan, prepared = suite.select('preview', (2, 100), apply=False)
    require(not plan.exists() and not target.exists() and prepared['authority'] is False, 'preview_has_effect')
    finish('inert-preview', new_runs=0, authority=False, selected_quota=prepared['profile']['mutation_quota'])
    begin('invalid-limits')
    root, target, plan, prepared = suite.select('invalid-source', (2, 100))
    observations = []
    for index, invalid in enumerate((None, {}, {'contract_version': QUOTA, 'max_mutations': -1, 'max_write_bytes': 8},
            {'contract_version': QUOTA, 'max_mutations': 1.5, 'max_write_bytes': 8},
            {'contract_version': QUOTA, 'max_mutations': 2, 'max_write_bytes': 262145},
            {'contract_version': QUOTA, 'max_mutations': 65, 'max_write_bytes': 8},
            {'contract_version': QUOTA, 'max_mutations': '2', 'max_write_bytes': 8},
            {'contract_version': QUOTA, 'max_mutations': 2, 'max_write_bytes': 8, 'unlimited': True})):
        bad = copy.deepcopy(prepared['profile']);bad['mutation_quota'] = invalid
        path = suite.work / f'invalid-plan-{index}';path.mkdir(mode=0o700)
        raw = canonical(bad);digest = sha(raw)
        (path / 'profile.json').write_bytes(raw);(path / 'profile.json').chmod(0o400)
        (path / 'profile.sha256').write_text(digest);(path / 'profile.sha256').chmod(0o400)
        observations.append(run_refused(path, digest, target, f'invalid-{index}',
                                       ('plan_invalid', 'profile_contract', 'quota_limits_invalid')))
    for index, flags in enumerate((['--max-mutations', '1'], ['--max-write-bytes', '8'],
                                    ['--max-mutations', '-1', '--max-write-bytes', '8'],
                                    ['--max-mutations', '18446744073709551616', '--max-write-bytes', '8'])):
        code, _ = suite.cli('preview', '--home', suite.home, '--root', root, '--claude', suite.claude,
                            '--private-sole-writer', '--create', 'result.txt', *flags)
        require(code == 2 and not target.exists(), 'ambiguous_cli_budget_accepted')
        observations.append(dict(suite.last_cli))
    finish('invalid-limits', controls=observations, expected_controls=12, zero_effects=True)

    recovery = None
    for name in CASES[4:21]:
        begin(name)
        replacing = name in ('useful-replace', 'stale-replay', 'postcommit-withheld-replace', 'postcommit-interrupted-replace')
        names = ('result.txt', 'other.txt') if name in ('exact-byte-limit', 'one-byte-over', 'one-operation-over', 'empty-write-count', 'parallel-last-credit') else ('result.txt',)
        content = UNICODE if name in ('exact-byte-limit', 'one-byte-over') else ('' if name == 'empty-write-count' else TEXT)
        size = len(content.encode())
        limits = (2, size + 1)
        if name in ('one-operation-over', 'empty-write-count', 'parallel-last-credit'):
            limits = (1, 2 * size)
        elif name == 'exact-byte-limit':
            limits = (2, 2 * size)
        elif name == 'one-byte-over':
            limits = (2, 2 * size - 1)
        elif name == 'zero-mutations':
            limits = (0, size)
        elif name.startswith('postcommit-'):
            limits = (1, size)
        root, target, plan, prepared = suite.select(name, limits,
            create=() if replacing else names, replace=('result.txt',) if replacing else ())
        before = {leaf: snapshot(root / leaf) for leaf in names}
        if name == 'create-not-replace':
            target.write_text(TEXT);target.chmod(0o600)
            refusal = run_refused(plan, prepared['profile_sha256'], target, name)
            finish(name, refusal=refusal, operation_unchanged=True);continue
        write = suite.write_proposal(prepared, content=content)
        proposals = [write]
        if name in ('useful-create', 'useful-replace'):
            proposals += [suite.read_proposal(prepared)]
        if name == 'exact-byte-limit':
            proposals += [suite.write_proposal(prepared, 'other.txt', content),
                          suite.read_proposal(prepared), suite.read_proposal(prepared, 'other.txt')]
        elif name == 'one-byte-over':
            proposals += [suite.write_proposal(prepared, 'other.txt', content)]
        if name in ('one-operation-over', 'empty-write-count', 'parallel-last-credit'):
            proposals += [suite.write_proposal(prepared, 'other.txt', content)]
        if name == 'stale-replay':
            proposals += [(write[0], dict(write[1]))]
        if name == 'unselected-target':
            write[1]['path'] = '../unrelated.txt'
        mode = name if name in ('ask-reject', 'no-approval') else 'approve'
        original_env = suite.env
        if name.startswith('postcommit-'):
            library = args.faults / ('withheld.so' if '-withheld-' in name else 'interrupted.so')
            require(library.is_file(), 'quota_fault_library_missing')
            suite.env = dict(suite.env, LD_PRELOAD=str(library))
            if '-interrupted-' in name:
                mode = 'postcommit-stop'
        try:
            row, observed, _ = suite.quota_run(name, root, target, plan, prepared, proposals, mode,
                                               batch=name == 'parallel-last-credit')
        finally:
            suite.env = original_env
        usage = row['usage']
        if name in ('zero-mutations', 'ask-reject', 'no-approval', 'unselected-target'):
            require(usage['admitted_mutation_attempts'] == usage['known_committed_mutations'] == 0
                    and snapshot(target) == before['result.txt'], 'refused_work_spent_or_executed_' + name)
            if name == 'zero-mutations':
                require('edit_quota_mutation_limit' in json.dumps(observed), 'typed_quota_refusal_missing')
                require('remaining_mutations' in json.dumps(observed), 'remaining_budget_not_explained')
        elif name == 'one-byte-over':
            require(target.read_text() == content and not (root / 'other.txt').exists()
                    and usage['admitted_mutation_attempts'] == usage['known_committed_mutations'] == 1
                    and usage['charged_write_bytes'] == size and usage['remaining_write_bytes'] == size - 1
                    and observed['toolu_edit_1']['is_error']
                    and 'edit_quota_write_byte_limit' in json.dumps(observed), 'aggregate_one_byte_overrun_executed')
            row.update(individual_payload_bytes=size, combined_proposed_bytes=2 * size,
                       selected_byte_limit=2 * size - 1, second_target_preserved=True)
        elif name == 'parallel-last-credit':
            effects = sum((root / leaf).exists() for leaf in names)
            require(effects <= 1 and usage['admitted_mutation_attempts'] <= 1, 'concurrent_over_budget_execution')
            for leaf in names:
                if (root / leaf).exists():
                    require((root / leaf).read_text() == content, 'concurrent_wrong_bytes')
            row.update(host_issued_batch=2, maximum_effects=1, actual_effects=effects,
                       overlap_support='existing_resource_overlap_refusal_unchanged',
                       atomic_last_credit_proof='native_Rust_barrier_race_with_real_executor')
        else:
            expected_effects = 2 if name == 'exact-byte-limit' else 1
            require(target.read_text() == content and usage['admitted_mutation_attempts'] == expected_effects
                    and usage['charged_write_bytes'] == expected_effects * size, 'exact_budgeted_effect_missing_' + name)
            if name in ('one-operation-over', 'empty-write-count'):
                require(not (root / 'other.txt').exists() and 'edit_quota_mutation_limit' in json.dumps(observed),
                        'over_operation_executed_or_not_explained')
            if name.startswith('postcommit-interrupted-'):
                require(row['exit'] == -signal.SIGKILL and row['terminal'] is None
                        and usage['indeterminate_publications'] == 1 and usage['known_committed_mutations'] == 0,
                        'interrupted_commit_was_reported_as_known')
                row.update(externally_observed_commit=True, syscall_return_withheld=True,
                           automatic_replay=False, actual_success_result_observed=False)
                recovery = root, target, plan, prepared, suite.last_run
            else:
                require(usage['known_committed_mutations'] == expected_effects and usage['known_committed_write_bytes'] == expected_effects * size,
                        'committed_quota_not_retained_' + name)
            if name.startswith('postcommit-withheld-'):
                require(not any(not r['is_error'] for r in observed.values()), 'injected_lost_result_was_delivered')
                row.update(actual_success_result_observed=False, externally_observed_commit=True,
                           committed_charge_retained=True, automatic_replay=False)
            if name in ('useful-create', 'useful-replace', 'exact-byte-limit'):
                expected_results = 4 if name == 'exact-byte-limit' else 2
                read_id = 'toolu_edit_2' if name == 'exact-byte-limit' else 'toolu_edit_1'
                require(row['exit'] == 0 and len(observed) == expected_results and all(not r['is_error'] for r in observed.values())
                        and content.strip() in json.dumps(observed[read_id]['content'], ensure_ascii=False),
                        'useful_readback_missing_' + name)
                row['exact_readback'] = True
                if name == 'exact-byte-limit':
                    require(usage['remaining_mutations'] == usage['remaining_write_bytes'] == 0, 'boundary_not_exact')
                    require((root / 'other.txt').read_text() == content
                            and content.strip() in json.dumps(observed['toolu_edit_3']['content'], ensure_ascii=False),
                            'aggregate_second_readback_missing')
            if name == 'stale-replay':
                require(observed['toolu_edit_1']['is_error'] and row['approved'] == 1, 'stale_request_reauthorized')
        require(snapshot(suite.sentinel) == suite.before_sentinel, 'unrelated_sentinel_changed')
        finish(name, execution=row, before=before, after={leaf: snapshot(root / leaf) for leaf in names},
               exact_readback=row.get('exact_readback', False), expected_content_sha256=sha(content.encode()))

    begin('fresh-run-recovery')
    require(recovery is not None, 'interrupted_recovery_input_missing')
    root, target, old_plan, old, retired = recovery
    require(target.read_text() == TEXT, 'recovery_input_not_independently_read')
    refusal = run_refused(old_plan, old['profile_sha256'], target, 'stale-after-interruption')
    root, target, plan, prepared = suite.select('explicit-recovery', (1, len(SECOND.encode())), create=(),
                                                replace=('result.txt',), root=root)
    old_record = json.loads((retired / 'run.json').read_text())
    row, observed, _ = suite.quota_run('fresh-recovery', root, target, plan, prepared,
        [suite.write_proposal(prepared, content=SECOND), suite.read_proposal(prepared)], mode='restart-authority')
    new_record = json.loads((suite.last_run / 'run.json').read_text())
    require(row['retired_epoch_refused'] and old_record['instance_id'] != new_record['instance_id']
            and row['approved'] == 1 and target.read_text() == SECOND and row['usage']['known_committed_mutations'] == 1,
            'fresh_run_recovery_not_exactly_authorized')
    finish('fresh-run-recovery', old_epoch_refused=True, explicit_fresh_plan=True,
           old_plan_refusal=refusal, execution=row, target_after=snapshot(target))

    begin('independent-run')
    peers = []
    for index in range(2):
        peer = copy.copy(suite);peer.active = {};peer.last_run = None
        root, target, plan, prepared = peer.select(f'peer-{index}', (1, len(TEXT.encode())))
        peers.append((peer, root, target, plan, prepared))
    def peer_run(index):
        peer, root, target, plan, prepared = peers[index]
        row, _, _ = peer.quota_run(f'peer-{index}', root, target, plan, prepared,
                                   [peer.write_proposal(prepared), peer.read_proposal(prepared)])
        require(row['exit'] == 0 and target.read_text() == TEXT and row['usage']['known_committed_mutations'] == 1,
                'independent_run_changed_or_shared_budget')
        return row
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        rows = list(pool.map(peer_run, range(2)))
    require(snapshot(suite.sentinel) == suite.before_sentinel, 'peer_sentinel_changed')
    finish('independent-run', both_runs_preserved=True, executions=rows)
    report.update(sentinel_preserved=True, owned_cleanup=True, status='passed')
    require(passed_report(report), 'incomplete_quota_qualification')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', action='store_true');p.add_argument('--agentfw', type=Path)
    p.add_argument('--claude', type=Path);p.add_argument('--python', type=Path, default=Path('/usr/bin/python3.12'))
    p.add_argument('--faults', type=Path);p.add_argument('--output', type=Path)
    args = p.parse_args()
    if not args.run:
        print(json.dumps({'format': FORMAT, 'executed': False, 'expected': list(CASES)}));return 0
    require(args.output and args.output.is_absolute() and not args.output.exists(), 'new_absolute_output_required')
    args.output.mkdir(mode=0o700)
    report = {'format': FORMAT, 'status': 'incomplete', 'paid_inference': False,
              'scope': 'installed_genuine_host_owned_scripted_provider', 'expected': list(CASES),
              'cases': [{'id': n, 'status': 'incomplete', 'attempted': False} for n in CASES]}
    try:
        qualify(args, report)
    except Exception as error:
        report.update(status='failed', failure_type=type(error).__name__, failure=str(error)[:160])
        current = next((r for r in report['cases'] if r['attempted'] and r['status'] == 'incomplete'), None)
        if current is not None:
            current.update(status='failed', failure=str(error)[:160])
    report['inventory'] = {'expected': len(CASES), 'attempted': sum(r['attempted'] for r in report['cases']),
                           'passed': sum(r['status'] == 'passed' for r in report['cases']),
                           'failed': sum(r['status'] == 'failed' for r in report['cases']),
                           'incomplete': sum(r['status'] == 'incomplete' for r in report['cases'])}
    (args.output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'format': FORMAT, 'status': report['status'], 'inventory': report['inventory']}))
    return 0 if passed_report(report) else 1


if __name__ == '__main__':
    raise SystemExit(main())
