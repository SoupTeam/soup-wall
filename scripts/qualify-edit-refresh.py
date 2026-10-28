#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Finite opt-in installed Linux edit-plan refresh with a genuine restricted host.

No paid inference. Existing accepted installation/run/Ask entry points only.
The default is inert; raw file/provider/authority data never enters the report.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('accepted_installed_edit', ROOT / 'scripts/qualify-installed-edit.py')
EDIT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(EDIT)
require, sha, snapshot = EDIT.require, EDIT.sha, EDIT.snapshot
FORMAT = 'sw-installed-edit-refresh-qualification/1'
SECOND = 'Second independently authorized bounded report.\n'
CASES = ('installed-closure', 'useful-second-replacement', 'preview-inert', 'stale-plan',
         'old-digest', 'missing-confirmation', 'wrong-confirmation', 'changed-destination',
         'changed-target', 'root-replacement', 'symlink-target', 'hardlink-target',
         'altered-runtime-pin', 'altered-component-pin', 'altered-plan', 'create-cannot-become-replace',
         'create-stays-create', 'ask-reject', 'no-approval', 'active-run-stays-pinned',
         'concurrent-refresh', 'interrupted-publish', 'existing-destination')


def passed_report(report):
    rows = report.get('cases', [])
    useful = next((r for r in rows if r.get('id') == 'useful-second-replacement'), {})
    return (report.get('format') == FORMAT and report.get('status') == 'passed'
            and report.get('paid_inference') is False and report.get('claude_sha256') == EDIT.CLAUDE
            and report.get('expected') == list(CASES) and [r.get('id') for r in rows] == list(CASES)
            and all(r.get('attempted') is True and r.get('status') == 'passed' for r in rows)
            and useful.get('first_readback') is True and useful.get('second_readback') is True
            and useful.get('new_epoch') is True and useful.get('new_binding') is True
            and useful.get('retired_authority_refused') is True
            and report.get('sentinel_preserved') is True and report.get('all_owned_stopped') is True)


def plan_snapshot(plan):
    return {name: snapshot(plan / name) for name in ('profile.json', 'profile.sha256')}


class Suite(EDIT.Suite):
    def refresh(self, plan, prepared, out, apply=False, confirm=None, env=None):
        words = ['refresh', '--plan', plan, '--sha256', prepared['profile_sha256'], '--out', out]
        if apply:
            words += ['--apply']
        if confirm is not None:
            words += ['--confirm', confirm]
        return self.cli(*words, env=env)

    def proposals(self, prepared, content):
        targets = prepared['profile']['targets']
        index = next(i for i, t in enumerate(targets) if t['name'] == 'result.txt')
        baseline = targets[index]['replacement']
        args = {'path': 'result.txt', 'content': content, 'old_identity': baseline['identity'],
                'old_sha256': baseline['sha256']}
        return [(f'read_output_{index}', {'path': 'result.txt'}),
                (f'replace_output_{index}', args), (f'read_output_{index}', {'path': 'result.txt'})]


def qualify(args, report):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0,
            'native_linux_operator_required')
    require(sha(args.claude.read_bytes()) == EDIT.CLAUDE, 'genuine_pinned_claude_required')
    require(not args.output.is_relative_to(ROOT), 'outside_checkout_required')
    report['cases'][0]['attempted'] = True
    suite = Suite(args, report)
    report.update(agentfw_sha256=sha(suite.binary.read_bytes()), claude_sha256=sha(suite.claude.read_bytes()))
    archive = args.output / 'component.tar'
    result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/build-pilot-front-door.py'),
                             '--out', str(archive)], cwd=ROOT, env=suite.env, capture_output=True, timeout=60)
    require(result.returncode == 0, 'component_build_failed')
    built = json.loads(result.stdout.splitlines()[-1])
    result = subprocess.run([str(suite.binary), 'pilot-component', '--home', str(suite.home), 'install',
                             str(archive), '--sha256', built['archive_sha256'], '--python', str(args.python)],
                            cwd=suite.work, env=suite.env, capture_output=True, timeout=60)
    require(result.returncode == 0, 'component_install_failed')
    tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT, text=True).strip()
    report.update(source_commit=built['commit'], source_tree=tree, component=built['component'])

    def begin(name):
        row = report['cases'][CASES.index(name)]
        row['attempted'] = True
        suite.active = row
        return row

    def finish(name, **values):
        report['cases'][CASES.index(name)].update(status='passed', **values)

    def setup(name, create=False):
        root, target, plan, code, prepared = suite.prepare(name, replacing=not create)
        require(code == 0, 'prepare_failed_' + name)
        return root, target, plan, prepared

    def preview(plan, prepared, out):
        code, value = suite.refresh(plan, prepared, out)
        require(code == 0 and value['status'] == 'preview' and value['authority'] is False
                and value['executed'] is False and not out.exists(), 'refresh_preview_failed')
        require(value['proposal']['scope_unchanged'] is True
                and value['proposal']['prior_operation_outcome'] == 'unknown-not-inferred-from-current-bytes'
                and value['proposal']['requires_fresh_run_and_exact_ask'] is True,
                'refresh_claims_execution_or_authority')
        return value

    def apply(plan, prepared, out, proposal):
        code, value = suite.refresh(plan, prepared, out, True, proposal['confirmation_sha256'])
        require(code == 0 and value['status'] == 'prepared-not-active' and value['authority'] is False,
                'refresh_apply_failed')
        require(value['profile_sha256'] == proposal['profile_sha256'] != prepared['profile_sha256'],
                'refresh_did_not_bind_exact_new_plan')
        return {'profile': value['proposal']['after'], 'profile_sha256': value['profile_sha256']}

    def run_refused(plan, digest, target, name):
        before = snapshot(target)
        runs = sorted(p.name for p in suite.state.iterdir())
        prompt = suite.work / (name + '-prompt');prompt.write_text('Explicitly selected bounded edit.');prompt.chmod(0o600)
        code, _ = suite.cli('run', '--plan', plan, '--sha256', digest, '--state', suite.state, '--prompt-file', prompt)
        require(code != 0 and snapshot(target) == before
                and sorted(p.name for p in suite.state.iterdir()) == runs, 'invalid_plan_allocated_run_' + name)
        return dict(suite.last_cli)

    finish('installed-closure', component=built['component'], source=built['commit'])
    begin('useful-second-replacement')
    root, target, old_plan, old = setup('repeated')
    original_plan = plan_snapshot(old_plan)
    suite.active = {}
    first, observed, _ = suite.host('first', root, target, old_plan, old, suite.proposals(old, EDIT.NEW))
    require(first['exit'] == 0 and first['approved'] == first['write_admissions'] == 1
            and len(observed) == 3 and all(not r['is_error'] for r in observed.values())
            and EDIT.NEW.strip() in json.dumps(observed['toolu_edit_2']['content'])
            and target.read_text() == EDIT.NEW, 'first_replacement_not_read_back')
    first_run = suite.last_run
    first_record_raw = (first_run / 'run.json').read_bytes()
    first_record = json.loads(first_record_raw)
    after_first = snapshot(target)
    new_plan = suite.work / 'repeated-next-plan'
    previewed = preview(old_plan, old, new_plan)
    fresh = apply(old_plan, old, new_plan, previewed)
    require(snapshot(target) == after_first and plan_snapshot(old_plan) == original_plan,
            'refresh_mutated_output_or_original_plan')
    suite.active = {}
    second, observed, _ = suite.host('second', root, target, new_plan, fresh,
                                     suite.proposals(fresh, SECOND), mode='restart-authority')
    second_record = json.loads((suite.last_run / 'run.json').read_text())
    require(second['exit'] == 0 and second['approved'] == second['write_admissions'] == 1
            and second['publication_gates'] == 1 and len(observed) == 3
            and all(not r['is_error'] for r in observed.values())
            and SECOND.strip() in json.dumps(observed['toolu_edit_2']['content'])
            and target.read_text() == SECOND, 'second_replacement_not_read_back')
    new_epoch = first_record['instance_id'] != second_record['instance_id']
    new_binding = first['decisions'][0]['binding_sha256'] != second['decisions'][0]['binding_sha256']
    require(new_epoch and new_binding and second['retired_epoch_refused'], 'old_authority_not_isolated')
    require((first_run / 'run.json').read_bytes() == first_record_raw,
            'original_run_mutated')
    finish('useful-second-replacement', first_readback=True, second_readback=True, new_epoch=new_epoch,
           new_binding=new_binding, retired_authority_refused=True,
           first_plan_sha256=old['profile_sha256'], second_plan_sha256=fresh['profile_sha256'],
           source_profile=old['profile'], refreshed_profile=fresh['profile'],
           refresh_proposal=previewed['proposal'], confirmation_sha256=previewed['confirmation_sha256'],
           expected_first_sha256=sha(EDIT.NEW.encode()), expected_second_sha256=sha(SECOND.encode()),
           first=first, second=second, after_first=after_first, after_second=snapshot(target),
           source_plan_preserved=plan_snapshot(old_plan) == original_plan,
           refreshed_plan_sha256=sha((new_plan / 'profile.json').read_bytes()))

    begin('preview-inert')
    before = (snapshot(target), plan_snapshot(old_plan), sorted(p.name for p in suite.work.iterdir()),
              sorted(p.name for p in suite.state.iterdir()))
    preview(old_plan, old, suite.work / 'inert-new-plan')
    require(before == (snapshot(target), plan_snapshot(old_plan), sorted(p.name for p in suite.work.iterdir()),
                       sorted(p.name for p in suite.state.iterdir())), 'preview_changed_inventory')
    finish('preview-inert', authority=False, new_runs=0, new_plans=0)
    begin('stale-plan');finish('stale-plan', refusal=run_refused(old_plan, old['profile_sha256'], target, 'stale-plan'))
    begin('old-digest');finish('old-digest', refusal=run_refused(new_plan, old['profile_sha256'], target, 'old-digest'))

    for name in CASES[5:]:
        begin(name)
        root, target, plan, prepared = setup(name, create=name.startswith('create-'))
        out = suite.work / (name + '-next-plan')
        original = plan_snapshot(plan)
        if name == 'create-cannot-become-replace':
            target.write_text(EDIT.NEW);target.chmod(0o600)
            expected = snapshot(target)
            code, _ = suite.refresh(plan, prepared, out)
            require(code != 0 and snapshot(target) == expected and not out.exists(), 'create_converted_to_replace')
            finish(name, operation_preserved=True, authority=False);continue
        proposed = preview(plan, prepared, out)
        if name == 'create-stays-create':
            fresh = apply(plan, prepared, out, proposed)
            require(fresh['profile']['targets'] == prepared['profile']['targets'] and not target.exists(), 'create_scope_changed')
            finish(name, operation_preserved=True, authority=False);continue
        if name in ('ask-reject', 'no-approval'):
            fresh = apply(plan, prepared, out, proposed)
            expected = snapshot(target)
            row, observed, _ = suite.host(name, root, target, out, fresh, [suite.proposals(fresh, SECOND)[1]],
                                           mode=name, timeout=12 if name == 'no-approval' else 40)
            require(snapshot(target) == expected and row['approved'] == row['write_admissions'] == 0
                    and row['inspected_seen'] > 0, 'unapproved_new_mutation')
            if name == 'ask-reject':
                require(observed and all(r['is_error'] for r in observed.values()), 'reject_not_observed')
            finish(name, host=row, target_preserved=True);continue
        if name == 'active-run-stays-pinned':
            def during_pending(run, pending):
                original_record = (run / 'run.json').read_bytes()
                apply(plan, prepared, out, proposed)
                code, inspected = suite.ask(run, 'inspect', pending['pending_id'])
                require(code == 0 and inspected['binding_sha256'] == pending['binding_sha256']
                        and (run / 'run.json').read_bytes() == original_record,
                        'refresh_revoked_or_rebound_existing_run')
            row, observed, _ = suite.host(name, root, target, plan, prepared,
                                           suite.proposals(prepared, EDIT.NEW), on_pending=during_pending)
            require(row['exit'] == 0 and row['approved'] == 1 and target.read_text() == EDIT.NEW,
                    'existing_run_lost_its_original_exact_authority')
            finish(name, host=row, original_run_preserved=True);continue

        env = None
        confirm = proposed['confirmation_sha256']
        selected_out = out
        restore = None
        if name == 'missing-confirmation':
            confirm = None
        elif name == 'wrong-confirmation':
            confirm = '0' * 64
        elif name == 'changed-destination':
            selected_out = suite.work / 'different-destination'
        elif name == 'changed-target':
            target.write_text('Operator superseding result.\n')
        elif name == 'root-replacement':
            root.rename(suite.work / (name + '-retired-root'))
            root.mkdir(mode=0o700);target.write_text('New root sentinel.\n');target.chmod(0o600)
        elif name in ('symlink-target', 'hardlink-target'):
            alias = suite.work / (name + '-outside-alias')
            if name == 'symlink-target':
                target.rename(alias);target.symlink_to(alias)
            else:
                os.link(target, alias)
            alias_before = snapshot(alias)
        elif name in ('altered-runtime-pin', 'altered-component-pin'):
            damaged = suite.claude if name == 'altered-runtime-pin' else Path(prepared['profile']['component']['classifier']['path'])
            original_size, mode = damaged.stat().st_size, stat.S_IMODE(damaged.stat().st_mode)
            damaged.chmod(0o600)
            with damaged.open('ab') as f:
                f.write(b'\nchanged owned pin\n')
            damaged.chmod(mode)
            restore = (damaged, original_size, mode)
        elif name == 'altered-plan':
            damaged = plan / 'profile.json';damaged.chmod(0o600)
            with damaged.open('ab') as f:
                f.write(b' ')
            damaged.chmod(0o400)
            original = plan_snapshot(plan)
        elif name == 'interrupted-publish':
            require(args.publish_fault and args.publish_fault.is_file(), 'publish_fault_library_required')
            env = dict(suite.env, LD_PRELOAD=str(args.publish_fault))
        elif name == 'existing-destination':
            out.mkdir(mode=0o700)
            (out / 'sentinel').write_text('Existing destination stays intact.\n')
            destination_before = snapshot(out / 'sentinel')
        elif name == 'concurrent-refresh':
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: suite.refresh(plan, prepared, out, True, confirm), range(2)))
            require(sum(code == 0 for code, _ in results) == 1 and out.exists(), 'refresh_race_not_one_winner')
            require(sha((out / 'profile.json').read_bytes()) == proposed['profile_sha256']
                    and plan_snapshot(plan) == original, 'refresh_race_overwrote_plan')
            finish(name, successes=1, refusals=1, original_plan_preserved=True);continue
        expected = snapshot(target)
        before_runs = sorted(p.name for p in suite.state.iterdir())
        try:
            code, _ = suite.refresh(plan, prepared, selected_out, True, confirm, env)
            refusal = dict(suite.last_cli)
        finally:
            if restore:
                damaged, size, mode = restore;damaged.chmod(0o600)
                with damaged.open('r+b') as f:
                    f.truncate(size)
                damaged.chmod(mode)
        require(code != 0 and snapshot(target) == expected and plan_snapshot(plan) == original
                and sorted(p.name for p in suite.state.iterdir()) == before_runs,
                'refusal_changed_inventory_' + name)
        if name == 'existing-destination':
            require(snapshot(out / 'sentinel') == destination_before and len(list(out.iterdir())) == 1,
                    'existing_destination_overwritten')
        else:
            require(not selected_out.exists(), 'refused_plan_published_' + name)
        values = {'refusal': refusal, 'target_preserved': True, 'original_plan_preserved': True, 'new_runs': 0}
        if name in ('symlink-target', 'hardlink-target'):
            require(snapshot(alias) == alias_before, 'outside_alias_changed')
            values.update(outside_alias_before=alias_before, outside_alias_after=snapshot(alias))
        if name == 'interrupted-publish':
            require(code == -signal.SIGKILL, 'actual_publish_sigkill_not_observed')
            stages = [p for p in suite.work.iterdir() if p.name.startswith('edit-stage-')]
            require(len(stages) == 1 and {p.name for p in stages[0].iterdir()} == {'profile.json', 'profile.sha256'},
                    'interrupted_stage_not_retained')
            require(sha((stages[0] / 'profile.json').read_bytes()) == proposed['profile_sha256'], 'partial_stage_wrong_plan')
            values.update(actual_sigkill=True, unpublished_stage_retained=True, automatic_replay=False)
        finish(name, **values)
    require(snapshot(suite.sentinel) == suite.before_sentinel, 'unrelated_sentinel_changed')
    report.update(sentinel_preserved=True, all_owned_stopped=True, status='passed')
    require(passed_report(report), 'incomplete_qualification')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--agentfw', type=Path)
    parser.add_argument('--claude', type=Path)
    parser.add_argument('--python', type=Path, default=Path('/usr/bin/python3.12'))
    parser.add_argument('--publish-fault', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'format': FORMAT, 'executed': False, 'expected': list(CASES)}));return 0
    require(args.output and args.output.is_absolute() and not args.output.exists(), 'new_absolute_output_required')
    args.output.mkdir(mode=0o700)
    report = {'format': FORMAT, 'status': 'incomplete', 'paid_inference': False,
              'scope': 'native-installed-genuine-host-owned-scripted-provider', 'expected': list(CASES),
              'cases': [{'id': name, 'status': 'incomplete', 'attempted': False} for name in CASES]}
    try:
        qualify(args, report)
    except Exception as error:
        report.update(status='failed', failure_type=type(error).__name__, failure=str(error)[:160])
        current = next((r for r in report['cases'] if r.get('attempted') and r['status'] == 'incomplete'), None)
        if current is not None:
            current.update(status='failed', failure=str(error)[:160])
    report['inventory'] = {'expected': len(CASES), 'attempted': sum(bool(r.get('attempted')) for r in report['cases']),
                           'passed': sum(r['status'] == 'passed' for r in report['cases']),
                           'failed': sum(r['status'] == 'failed' for r in report['cases']),
                           'incomplete': sum(r['status'] == 'incomplete' for r in report['cases'])}
    (args.output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'format': FORMAT, 'status': report['status'], 'inventory': report['inventory']}))
    return 0 if passed_report(report) else 1


if __name__ == '__main__':
    raise SystemExit(main())
