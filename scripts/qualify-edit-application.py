#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in genuine installed edit -> offline single-file apply/revert qualification.

Only disposable owned fixtures and the existing scripted loopback provider are
used. Raw outputs, backups, command responses and authority stay private.
"""
from __future__ import annotations
import argparse
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('application_review', ROOT / 'scripts/qualify-edit-review.py')
REVIEW = importlib.util.module_from_spec(spec)
spec.loader.exec_module(REVIEW)
EDIT = REVIEW.EDIT
require, sha = EDIT.require, EDIT.sha
FORMAT = 'sw-installed-edit-application-qualification/1'
FAULTS = ('before-publication', 'after-publication', 'target-directory-sync', 'receipt-sync', 'after-receipt-sync')
CASES = ('installed-closure', 'genuine-create-apply-revert', 'genuine-replace-apply-revert',
         'read-only-preview', 'missing-consents', 'stale-confirmation', 'changed-target', 'changed-output',
         'duplicate-application', 'later-user-edit', 'stale-revert', 'backup-damage', 'journal-damage',
         'target-symlink', 'target-hardlink', 'target-fifo', 'target-oversize', 'target-mode',
         'output-symlink', 'output-hardlink', 'output-fifo', 'missing-output', 'run-profile-change',
         'foreign-run', 'source-plan-overlap', 'output-overlap', 'journal-overlap', 'parent-redirection',
         'root-substitution', 'unknown-record-fields', 'active-run', *FAULTS)


def snapshot(path):
    """Independent bounded fixture observation, including stale metadata."""
    try:
        m = path.lstat()
    except FileNotFoundError:
        return {'exists':False}
    row = {'exists':True, 'device':m.st_dev, 'inode':m.st_ino, 'mode':m.st_mode,
           'uid':m.st_uid, 'gid':m.st_gid, 'links':m.st_nlink, 'size':m.st_size,
           'mtime_ns':m.st_mtime_ns, 'ctime_ns':m.st_ctime_ns}
    if stat.S_ISREG(m.st_mode):
        require(m.st_size <= 8192, 'independent_witness_cap')
        row['sha256'] = sha(path.read_bytes())
    return row


def passed_report(report):
    rows = report.get('cases', [])
    if (report.get('format') != FORMAT or report.get('status') != 'passed'
            or report.get('expected') != list(CASES) or [r.get('id') for r in rows] != list(CASES)
            or not all(r.get('attempted') is True and r.get('status') == 'passed' for r in rows)
            or type(report.get('provider_requests_during_operator')) is not int
            or report['provider_requests_during_operator'] != 0
            or type(report.get('operator_tool_requests')) is not int
            or report['operator_tool_requests'] != 0
            or type(report.get('operator_state_checks')) is not int
            or report['operator_state_checks'] <= 0
            or report.get('all_owned_stopped') is not True or report.get('sentinel_preserved') is not True
            or report.get('paid_inference') is not False or report.get('claude_sha256') != EDIT.CLAUDE):
        return False
    for key in ('agentfw_sha256', 'component_sha256', 'helper_sha256', 'fault_sha256'):
        if not re.fullmatch(r'[0-9a-f]{64}', str(report.get(key, ''))):
            return False
    for key in ('source_commit', 'source_tree'):
        if not re.fullmatch(r'[0-9a-f]{40}', str(report.get(key, ''))):
            return False
    for name in ('genuine-create-apply-revert', 'genuine-replace-apply-revert'):
        row = next(r for r in rows if r['id'] == name)
        if not all(row.get(k) is True for k in ('genuine_host_readback', 'apply_readback', 'revert_readback', 'source_unchanged')):
            return False
    for name in FAULTS:
        row = next(r for r in rows if r['id'] == name)
        if (row.get('actual_syscall_fault') is not True or row.get('recovery_indeterminate') is not True
                or type(row.get('fault_exit')) is not int or row['fault_exit'] == 0):
            return False
        if name in ('before-publication', 'after-publication', 'after-receipt-sync') and row['fault_exit'] != -signal.SIGKILL:
            return False
    return True


@contextlib.contextmanager
def substituted(path, *, link=None, fifo=False, raw=None):
    kept = path.with_name(path.name + '.qualification-kept')
    path.rename(kept)
    try:
        if link is not None:
            path.symlink_to(link)
        elif fifo:
            os.mkfifo(path, 0o600)
        elif raw is not None:
            path.write_bytes(raw); path.chmod(0o600)
        yield
    finally:
        if path.exists() or path.is_symlink():
            path.unlink()
        kept.rename(path)


def qualify(args, report):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0,
            'native_linux_operator_required')
    require(not args.output.is_relative_to(ROOT) and sha(args.claude.read_bytes()) == EDIT.CLAUDE,
            'genuine_installed_host_required')
    suite = EDIT.Suite(args, report)

    def begin(name):
        row = report['cases'][CASES.index(name)]; row['attempted'] = True; suite.active = row
        return row

    def finish(name, **values):
        report['cases'][CASES.index(name)].update(status='passed', **values)

    begin('installed-closure')
    archive = args.output / 'component.tar'
    result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/build-pilot-front-door.py'), '--out', str(archive)],
                            cwd=ROOT, env=suite.env, capture_output=True, timeout=60)
    require(result.returncode == 0, 'component_build_failed')
    built = json.loads(result.stdout.splitlines()[-1])
    result = subprocess.run([str(suite.binary), 'pilot-component', '--home', str(suite.home), 'install', str(archive),
                             '--sha256', built['archive_sha256'], '--python', str(args.python)],
                            cwd=suite.work, env=suite.env, capture_output=True, timeout=60)
    require(result.returncode == 0 and (suite.home / 'pilot-front-door/current.json').is_file(), 'component_install_failed')
    report.update(source_commit=built['commit'], source_tree=subprocess.check_output(
        ['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT, text=True).strip(), component_sha256=built['component'],
        agentfw_sha256=sha(suite.binary.read_bytes()), claude_sha256=sha(suite.claude.read_bytes()),
        helper_sha256=sha(Path(__file__).read_bytes()), fault_sha256=sha(args.fault.read_bytes()))
    for words in (['--help'], ['edit-session', '--help'], ['edit-session', 'apply', '--help'],
                  *(['edit-session', 'apply', name, '--help'] for name in ('preview', 'commit', 'status', 'recover', 'revert-preview', 'revert'))):
        started = subprocess.run([str(suite.binary), *words], cwd=suite.work, env=suite.env,
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        require(started.returncode == 0, 'installed_cli_startup_failed')
    finish('installed-closure', installed_outside_checkout=True)
    journals = suite.work / 'application-journals'; journals.mkdir(mode=0o700)
    trap = EDIT.HOST.ScriptedModel([])
    operator_env = dict(suite.env, ANTHROPIC_BASE_URL=trap.url, ANTHROPIC_API_KEY='owned-operator-trap',
                        HTTP_PROXY=trap.url, HTTPS_PROXY=trap.url)
    sequence = 0
    completed = []
    operator_state_checks = 0

    def operator(command, *words, env=None):
        nonlocal operator_state_checks
        private_before = [EDIT.private_state_witness(run) for run, *_ in completed]
        result = subprocess.run([str(suite.binary), 'edit-session', 'apply', command, *map(str, words)],
                                cwd=suite.work, env=env or operator_env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=18)
        require(len(result.stdout) <= 128 * 1024 and len(result.stderr) <= 8192, 'operator_response_bound')
        require(not any(v and v in result.stdout + result.stderr for v in
                        (suite.secret_canary.encode(), EDIT.OLD.encode().strip(), EDIT.NEW.encode().strip())),
                'operator_content_leak')
        diagnostic = EDIT.cli_observation(result.returncode, result.stdout, result.stderr)
        for line in result.stderr.decode('utf-8', 'replace').splitlines():
            match = re.fullmatch(r'Error: edit_apply_refused: ([a-z][a-z0-9_]{0,95})', line)
            if match:
                diagnostic['reason'] = match[1]
        suite.active['last_operator'] = diagnostic
        value = json.loads(result.stdout) if result.returncode == 0 else None
        require(not trap.requests, 'operator_provider_request')
        require(private_before == [EDIT.private_state_witness(run) for run, *_ in completed],
                'operator_changed_tool_or_authority_state')
        operator_state_checks += 1
        return result.returncode, value, result.stderr

    def destination(run, plan, prepared, name='selected.txt'):
        nonlocal sequence
        sequence += 1
        root = suite.work / ('project-' + str(sequence)); root.mkdir(mode=0o700)
        target = root / name; target.write_text('Owned destination baseline.\n'); target.chmod(0o600)
        sentinel = root / 'unrelated.txt'; sentinel.write_text('Unrelated owned sentinel.\n'); sentinel.chmod(0o600)
        journal = journals / ('application-' + str(sequence))
        words = ['--run', run, '--plan', plan, '--sha256', prepared['profile_sha256'],
                 '--output', 'result.txt', '--root', root, '--target', name, '--journal', journal]
        return root, target, sentinel, journal, words

    def preview(words):
        code, value, _ = operator('preview', *words)
        require(code == 0 and value['status'] == 'preview' and value['executed'] is False
                and value['authority'] is False and value['private_backup_retained'] is False, 'apply_preview_failed')
        return value

    def commit(words, p, *, flags=None, env=None):
        return operator('commit', *words, '--confirm', p['confirmation_sha256'],
                        *(flags if flags is not None else ['--private-sole-writer', '--consent-private-backup']), env=env)

    def retained(journal, p, receipt=None):
        words = ['--journal', journal, '--expect-plan', p['confirmation_sha256']]
        if receipt:
            words += ['--receipt', receipt['receipt_sha256'], '--success-ack', receipt['success_ack']]
        return words

    def source_witness(run, output, plan):
        return REVIEW.selected_witness(suite, run, output, plan)

    try:
        for replacing in (False, True):
            name = 'genuine-replace-apply-revert' if replacing else 'genuine-create-apply-revert'; begin(name)
            root, output, plan, code, prepared = suite.prepare(name, replacing=replacing)
            require(code == 0, 'prepare_failed')
            targets = prepared['profile']['targets']
            index = next(i for i, t in enumerate(targets) if t['name'] == 'result.txt')
            before_name = 'result.txt' if replacing else 'source.txt'
            before_index = next(i for i, t in enumerate(targets) if t['name'] == before_name)
            payload = {'path':'result.txt', 'content':EDIT.NEW}
            if replacing:
                old = targets[index]['replacement']; payload.update(old_identity=old['identity'], old_sha256=old['sha256'])
            proposals = [(f'read_output_{before_index}', {'path':before_name}),
                         (('replace' if replacing else 'create') + f'_output_{index}', payload),
                         (f'read_output_{index}', {'path':'result.txt'})]
            native, seen, _ = suite.host(name, root, output, plan, prepared, proposals)
            require(native['exit'] == 0 and len(seen) == 3 and all(not v['is_error'] for v in seen.values())
                    and EDIT.NEW.strip() in json.dumps(seen['toolu_edit_2']['content'])
                    and native['approved'] >= 1 and native['process_cleanup']['all_stopped'], 'genuine_host_readback_missing')
            run = suite.last_run
            before_source = source_witness(run, output, plan)
            code, review = suite.cli('review', '--run', run, '--sha256', prepared['profile_sha256'], env=operator_env)
            require(code == 0 and review['observation']['authority'] is False, 'accepted_offline_review_failed')
            project, target, sentinel, journal, words = destination(run, plan, prepared,
                name='selected.txt' if replacing else 'résumé file.txt')
            old_target, old_sentinel = snapshot(target), snapshot(sentinel)
            p = preview(words)
            require(snapshot(target) == old_target and snapshot(sentinel) == old_sentinel and not journal.exists(), 'preview_wrote_state')
            code, applied, _ = commit(words, p)
            require(code == 0 and applied['status'] == 'applied' and target.read_bytes() == output.read_bytes(), 'apply_readback_failed')
            require(target.stat().st_ino != old_target['inode'] if isinstance(old_target, dict) else True, 'apply_inode_unchanged')
            code, state, _ = operator('status', *retained(journal, p, applied))
            require(code == 0 and state['status'] == 'applied', 'application_status_failed')
            code, reverse, _ = operator('revert-preview', *retained(journal, p, applied))
            require(code == 0 and reverse['executed'] is False, 'revert_preview_failed')
            code, undone, _ = operator('revert', *retained(journal, p, applied),
                '--confirm', reverse['confirmation_sha256'], '--private-sole-writer')
            require(code == 0 and undone['status'] == 'reverted' and target.read_text() == 'Owned destination baseline.\n', 'revert_readback_failed')
            require(source_witness(run, output, plan) == before_source and snapshot(sentinel) == old_sentinel
                    and (journal / 'preimage.bin').read_bytes() == target.read_bytes()
                    and (journal / 'applied.json').is_file(), 'operator_damaged_original_evidence')
            completed.append((run, output, plan, prepared))
            finish(name, genuine_host_readback=True, apply_readback=True, revert_readback=True, source_unchanged=True,
                   provider_requests=native['provider_requests'], actual_native_approvals=native['approved'],
                   independent_cleanup=True, plan_sha256=p['confirmation_sha256'],
                   application_receipt_sha256=applied['receipt_sha256'], revert_receipt_sha256=undone['receipt_sha256'])

        run, output, plan, prepared = completed[0]

        def refusal(name, change=None, *, stale=False, flags=None, arguments=None):
            begin(name)
            project, target, sentinel, journal, words = destination(run, plan, prepared)
            p = preview(words)
            context = change(project, target, journal, words) if change else contextlib.nullcontext()
            with context:
                before = snapshot(target) if target.is_file() and not target.is_symlink() else None
                original_source = source_witness(run, output, plan)
                outside = snapshot(suite.sentinel); local = snapshot(sentinel)
                if arguments:
                    words = arguments(words)
                code, _, _ = commit(words, p, flags=flags) if stale or flags is not None else operator('preview', *words)
                require(code != 0 and not journal.exists() and snapshot(sentinel) == local
                        and snapshot(suite.sentinel) == outside, 'unsafe_application_not_refused')
                if before is not None:
                    require(snapshot(target) == before, 'refused_application_changed_target')
                require(source_witness(run, output, plan) == original_source, 'refused_application_changed_source')
            finish(name, refused=True, no_publication=True, sentinel_preserved=True, source_unchanged=True)

        begin('read-only-preview')
        project, target, sentinel, journal, words = destination(run, plan, prepared)
        before = source_witness(run, output, plan), snapshot(target), snapshot(sentinel), sorted(journals.iterdir())
        preview(words)
        require(before == (source_witness(run, output, plan), snapshot(target), snapshot(sentinel), sorted(journals.iterdir()))
                and not journal.exists(), 'preview_changed_inputs')
        finish('read-only-preview', all_inputs_unchanged=True)
        begin('missing-consents')
        for flags in ([], ['--private-sole-writer'], ['--consent-private-backup']):
            project, target, sentinel, journal, words = destination(run, plan, prepared)
            p = preview(words); before = snapshot(target)
            require(commit(words, p, flags=flags)[0] != 0 and snapshot(target) == before and not journal.exists(), 'consent_not_enforced')
        finish('missing-consents', refused_forms=3)
        refusal('stale-confirmation', stale=True,
                arguments=lambda words: words[:words.index('--target') + 1] + ['unrelated.txt'] + words[words.index('--target') + 2:])
        refusal('changed-target', lambda project, target, journal, words: substituted(target, raw=b'Later user changes.\n'), stale=True)
        refusal('changed-output', lambda *unused: substituted(output, raw=b'Changed generated output.\n'), stale=True)

        def applied_fixture(name):
            begin(name)
            project, target, sentinel, journal, words = destination(run, plan, prepared)
            p = preview(words); before_source = source_witness(run, output, plan)
            code, applied, _ = commit(words, p)
            require(code == 0 and applied['status'] == 'applied', 'positive_application_fixture_failed')
            return project, target, sentinel, journal, words, p, applied, before_source

        project, target, sentinel, journal, words, p, applied, _ = applied_fixture('duplicate-application')
        before = snapshot(target), sorted(journal.iterdir())
        require(commit(words, p)[0] != 0 and before == (snapshot(target), sorted(journal.iterdir())), 'duplicate_apply_replayed')
        finish('duplicate-application', refused=True)
        project, target, sentinel, journal, words, p, applied, _ = applied_fixture('later-user-edit')
        target.write_text('Later user work.\n'); before = snapshot(target)
        require(operator('revert-preview', *retained(journal, p, applied))[0] != 0 and snapshot(target) == before,
                'later_user_change_overwritten')
        target.write_bytes(output.read_bytes()); before = snapshot(target)
        require(operator('revert-preview', *retained(journal, p, applied))[0] != 0 and snapshot(target) == before,
                'restored_bytes_forged_descriptor')
        finish('later-user-edit', changed_and_restored_bytes_refused=True)
        project, target, sentinel, journal, words, p, applied, _ = applied_fixture('stale-revert')
        code, reverse, _ = operator('revert-preview', *retained(journal, p, applied))
        require(code == 0, 'revert_preview_failed')
        target.write_text('Post-preview user work.\n'); before = snapshot(target)
        require(operator('revert', *retained(journal, p, applied), '--confirm', reverse['confirmation_sha256'],
                         '--private-sole-writer')[0] != 0 and snapshot(target) == before, 'stale_revert_overwrote_work')
        finish('stale-revert', refused=True)
        for name, leaf in [('backup-damage', 'preimage.bin'), ('journal-damage', 'identity.json'), ('unknown-record-fields', 'applied.json')]:
            project, target, sentinel, journal, words, p, applied, _ = applied_fixture(name)
            damaged = journal / leaf
            if name == 'unknown-record-fields':
                value = json.loads(damaged.read_bytes()); value['unrecognized'] = True
                damaged.write_text(json.dumps(value))
            else:
                damaged.write_bytes(b'damaged')
            before = snapshot(target)
            require(operator('revert-preview', *retained(journal, p, applied))[0] != 0
                    and snapshot(target) == before, 'damaged_journal_allowed_revert')
            finish(name, refused=True)

        refusal('target-symlink', lambda project, target, journal, words: substituted(target, link=suite.sentinel), stale=True)
        @contextlib.contextmanager
        def hardlinked(path):
            alias = path.with_name(path.name + '.qualification-hard')
            os.link(path, alias)
            try:
                yield
            finally:
                alias.unlink()
        refusal('target-hardlink', lambda project, target, journal, words: hardlinked(target), stale=True)
        refusal('target-fifo', lambda project, target, journal, words: substituted(target, fifo=True), stale=True)
        refusal('target-oversize', lambda project, target, journal, words: substituted(target, raw=b'x' * 4097), stale=True)
        @contextlib.contextmanager
        def public_mode(path):
            path.chmod(0o644)
            try:
                yield
            finally:
                path.chmod(0o600)
        refusal('target-mode', lambda project, target, journal, words: public_mode(target), stale=True)
        refusal('output-symlink', lambda *unused: substituted(output, link=suite.sentinel), stale=True)
        refusal('output-hardlink', lambda *unused: hardlinked(output), stale=True)
        refusal('output-fifo', lambda *unused: substituted(output, fifo=True), stale=True)
        refusal('missing-output', lambda *unused: substituted(output), stale=True)
        refusal('run-profile-change', lambda *unused: substituted(run / 'profile.json', raw=b'{}'), stale=True)
        foreign = suite.work / 'foreign'; foreign.mkdir(mode=0o700)
        refusal('foreign-run', stale=True, arguments=lambda words: [foreign if w == run else w for w in words])
        refusal('source-plan-overlap', arguments=lambda words: [plan if w == words[words.index('--root') + 1] else w for w in words])
        refusal('output-overlap', arguments=lambda words: [output.parent if w == words[words.index('--root') + 1] else w for w in words])
        refusal('journal-overlap', arguments=lambda words: [output.parent / 'forbidden-journal' if w == words[words.index('--journal') + 1] else w for w in words])
        @contextlib.contextmanager
        def redirected(project, target, journal, words):
            held = project.with_name(project.name + '-held'); project.rename(held); project.symlink_to(held)
            try:
                yield
            finally:
                project.unlink(); held.rename(project)
        refusal('parent-redirection', redirected, stale=True)
        @contextlib.contextmanager
        def replaced_root(project, target, journal, words):
            held = project.with_name(project.name + '-held'); project.rename(held); project.mkdir(mode=0o700)
            target.write_text('Replacement directory user file.\n'); target.chmod(0o600)
            try:
                yield
            finally:
                target.unlink(); project.rmdir(); held.rename(project)
        refusal('root-substitution', replaced_root, stale=True)

        begin('active-run')
        root, active_output, active_plan, code, active_prepared = suite.prepare('active-source')
        require(code == 0, 'active_prepare_failed'); checked = []
        def active_check(active_run, unused):
            if checked:
                return
            project, target, sentinel, journal, words = destination(active_run, active_plan, active_prepared)
            before = snapshot(target); audit_before = EDIT.live_audit_witness(active_run)
            require(operator('preview', *words)[0] != 0 and snapshot(target) == before and not journal.exists(), 'active_run_accepted')
            EDIT.live_audit_delta(audit_before, EDIT.live_audit_witness(active_run)); checked.append(True)
        targets = active_prepared['profile']['targets']; index = next(i for i, t in enumerate(targets) if t['name'] == 'result.txt')
        native, _, _ = suite.host('active-source', root, active_output, active_plan, active_prepared,
            [(f'create_output_{index}', {'path':'result.txt', 'content':EDIT.NEW})], on_pending=active_check)
        require(checked == [True] and native['process_cleanup']['all_stopped'], 'active_runtime_control_missing')
        finish('active-run', actual_live_owner=True, refused=True)

        for name in FAULTS:
            begin(name)
            project, target, sentinel, journal, words = destination(run, plan, prepared)
            p = preview(words); original = target.read_bytes(); before_source = source_witness(run, output, plan); outside = snapshot(sentinel)
            env = dict(operator_env, LD_PRELOAD=str(args.fault), SOU187_FAULT=name,
                       SOU187_TARGET_ROOT=str(project), SOU187_RECEIPT=str(journal / 'applied.json'))
            code, _, stderr = commit(words, p, env=env)
            fault_exit = code
            require(code != 0 and b'sou187_owned_fault_observed' in stderr, 'actual_publication_fault_not_observed')
            if name in ('before-publication', 'after-publication', 'after-receipt-sync'):
                require(code == -signal.SIGKILL, 'operator_not_killed_at_publication_boundary')
            expected = original if name == 'before-publication' else output.read_bytes()
            require(target.read_bytes() == expected and (journal / 'preimage.bin').read_bytes() == original
                    and source_witness(run, output, plan) == before_source and snapshot(sentinel) == outside, 'interrupted_publication_witness_failed')
            code, state, _ = operator('recover', *retained(journal, p))
            require(code == 0 and state['status'] == 'indeterminate' and state['local_operator_publication'] is False,
                    'interruption_falsely_became_success')
            before = snapshot(target)
            require(commit(words, p)[0] != 0 and snapshot(target) == before, 'interrupted_apply_blind_retry')
            fake = {'receipt_sha256':'a' * 64, 'success_ack':'A' * 43}
            if (journal / 'applied.json').is_file():
                # A visible receipt cannot reconstruct the acknowledgement
                # withheld by an interrupted command.
                raw = json.loads((journal / 'applied.json').read_bytes())
                fake['receipt_sha256'] = sha(b'agentfw/edit-application-receipt/v1\0' +
                    json.dumps(raw, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())
                code, recovered, _ = operator('recover', *retained(journal, p, fake))
                require(code == 0 and recovered['status'] == 'indeterminate', 'visible_receipt_forged_completion')
            require(operator('revert-preview', *retained(journal, p, fake))[0] != 0, 'uncertain_revert_allowed')
            finish(name, actual_syscall_fault=True, fault_exit=fault_exit, recovery_indeterminate=True, target_verified=True,
                   evidence_retained=True, no_retry=True, original_output_preserved=True)
        require(not trap.requests and EDIT.snapshot(suite.sentinel) == suite.before_sentinel, 'operator_external_effect')
        report.update(status='passed', provider_requests_during_operator=len(trap.requests), all_owned_stopped=True,
                      sentinel_preserved=True, operator_tool_requests=0, operator_state_checks=operator_state_checks)
    finally:
        trap.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run', action='store_true')
    p.add_argument('--agentfw', type=Path)
    p.add_argument('--claude', type=Path)
    p.add_argument('--python', type=Path, default=Path('/usr/bin/python3.12'))
    p.add_argument('--fault', type=Path)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    if not args.run:
        print(json.dumps({'format':FORMAT, 'executed':False, 'expected':list(CASES)})); return 0
    require(args.output and args.output.is_absolute() and not args.output.exists(), 'new_absolute_output_required')
    args.output.mkdir(mode=0o700)
    report = {'format':FORMAT, 'status':'incomplete', 'paid_inference':False, 'expected':list(CASES),
              'cases':[{'id':n, 'status':'incomplete', 'attempted':False} for n in CASES]}
    try:
        qualify(args, report)
    except Exception as error:
        code = EDIT.failure_code(error); report.update(status='failed', failure=code, failure_type=type(error).__name__)
        row = next((r for r in report['cases'] if r['attempted'] and r['status'] == 'incomplete'), None)
        if row is not None:
            row.update(status='failed', failure=code)
    report['inventory'] = {s:sum(r['status'] == s for r in report['cases']) for s in ('passed', 'failed', 'incomplete')}
    (args.output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'format':FORMAT, 'status':report['status'], 'inventory':report['inventory']}))
    return 0 if passed_report(report) else 1


if __name__ == '__main__':
    raise SystemExit(main())
