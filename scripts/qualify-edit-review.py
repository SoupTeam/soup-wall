#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in finite installed output review, with genuine host and owned local model.

Default only lists controls. Reports never contain private outputs or authority.
"""
from __future__ import annotations
import argparse
import concurrent.futures
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('review_installed_edit', ROOT / 'scripts/qualify-installed-edit.py')
EDIT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(EDIT)
require, sha, snapshot = EDIT.require, EDIT.sha, EDIT.snapshot
FORMAT = 'sw-installed-edit-review-qualification/1'
CASES = ('installed-closure', 'genuine-create-review', 'genuine-replace-review',
         'summary-without-content', 'escaped-content', 'terminal-controls-escaped', 'missing-baseline', 'explicit-baseline',
         'wrong-baseline', 'baseline-without-consent', 'content-without-consent', 'undeclared-target',
         'individual-private-export', 'export-without-consent', 'wrong-observation', 'changed-output',
         'symlink-output', 'fifo-output', 'device-link', 'hardlink-output', 'oversized-output', 'missing-output',
         'binary-summary', 'binary-display-refused', 'replaced-root', 'redirected-parent',
         'tampered-profile', 'missing-terminal', 'contradictory-terminal', 'missing-cleanup-receipt',
         'foreign-owner', 'stale-boot', 'active-run', 'cancelled-run', 'read-substitution-race',
         'failed-publication-cleanup', 'concurrent-create-new-export', 'existing-destination',
         'sanitized-support-separate')


def passed_report(report):
    rows = report.get('cases', [])
    positives = [next((r for r in rows if r.get('id') == name), {})
                 for name in ('genuine-create-review', 'genuine-replace-review')]
    return (report.get('format') == FORMAT and report.get('status') == 'passed'
            and report.get('paid_inference') is False and report.get('claude_sha256') == EDIT.CLAUDE
            and report.get('expected') == list(CASES) and [r.get('id') for r in rows] == list(CASES)
            and all(r.get('attempted') is True and r.get('status') == 'passed' for r in rows)
            and all(r.get('genuine_readback') is True and r.get('unchanged') is True for r in positives)
            and type(report.get('provider_requests_during_review')) is int
            and report['provider_requests_during_review'] == 0
            and report.get('sentinel_preserved') is True and report.get('all_owned_stopped') is True
            and report.get('exact_export_verified') is True)


def selected_witness(suite, run, target, plan):
    # Independent finite fixture witness. No discovery in the product.
    paths = [target, target.parent / 'source.txt', suite.sentinel,
             plan / 'profile.json', plan / 'profile.sha256',
             run / 'control.json', run / 'stop-receipt.json',
             run / 'host-settings.json', run / 'host-home/.claude/settings.json',
             suite.home / 'pilot-front-door/current.json',
             suite.home / 'pilot-front-door/previous.json',
             suite.home / 'config.yaml', suite.work / 'original-project.txt',
             suite.work / 'original-settings.json']
    values = []
    for path in paths:
        try:
            meta = path.lstat()
        except FileNotFoundError:
            values.append(None)
            continue
        raw = path.read_bytes() if stat.S_ISREG(meta.st_mode) else b''
        require(len(raw) <= 128 * 1024, 'witness_cap')
        values.append((meta.st_dev, meta.st_ino, meta.st_mode, meta.st_nlink, meta.st_size,
                       meta.st_mtime_ns, meta.st_ctime_ns, sha(raw)))
    return (values, EDIT.private_state_witness(run), sorted(p.name for p in suite.state.iterdir()))


@contextlib.contextmanager
def replaced(path, raw=None, link=None, fifo=False):
    kept = path.with_name(path.name + '.qualification-kept')
    path.rename(kept)
    try:
        if link is not None:
            path.symlink_to(link)
        elif fifo:
            os.mkfifo(path, 0o600)
        elif raw is not None:
            path.write_bytes(raw);path.chmod(0o600)
        yield
    finally:
        if path.exists() or path.is_symlink():
            path.unlink()
        kept.rename(path)


def qualify(args, report):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0,
            'native_linux_operator_required')
    require(sha(args.claude.read_bytes()) == EDIT.CLAUDE and not args.output.is_relative_to(ROOT),
            'genuine_installed_host_required')
    report['cases'][0]['attempted'] = True
    suite = EDIT.Suite(args, report)
    for name, raw in [('original-project.txt', b'Original project must stay unchanged.\n'),
                      ('original-settings.json', b'{"unchanged":true}\n')]:
        path = suite.work / name;path.write_bytes(raw);path.chmod(0o600)
    archive = args.output / 'component.tar'
    result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/build-pilot-front-door.py'), '--out', str(archive)],
                            cwd=ROOT, env=suite.env, capture_output=True, timeout=60)
    require(result.returncode == 0, 'component_build_failed')
    built = json.loads(result.stdout.splitlines()[-1])
    result = subprocess.run([str(suite.binary), 'pilot-component', '--home', str(suite.home), 'install', str(archive),
                             '--sha256', built['archive_sha256'], '--python', str(args.python)],
                            cwd=suite.work, env=suite.env, capture_output=True, timeout=60)
    require(result.returncode == 0, 'component_install_failed')
    require((suite.home / 'pilot-front-door/current.json').is_file(), 'active_component_pointer_missing')
    report.update(source_commit=built['commit'], source_tree=subprocess.check_output(
        ['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT, text=True).strip(), component=built['component'],
        agentfw_sha256=sha(suite.binary.read_bytes()), claude_sha256=sha(suite.claude.read_bytes()))

    def begin(name):
        row = report['cases'][CASES.index(name)];row['attempted'] = True;suite.active = row
        return row

    def finish(name, **values):
        report['cases'][CASES.index(name)].update(status='passed', **values)

    finish('installed-closure', installed_outside_checkout=True)
    trap = EDIT.HOST.ScriptedModel([])
    try:
        review_env = dict(suite.env, ANTHROPIC_BASE_URL=trap.url, ANTHROPIC_API_KEY='owned-review-trap',
                          HTTP_PROXY=trap.url, HTTPS_PROXY=trap.url)

        def review(run, prepared, *extra, env=None):
            result = subprocess.run([str(suite.binary), 'edit-session', 'review', '--run', str(run),
                '--sha256', prepared['profile_sha256'], *map(str, extra)], cwd=suite.work, env=env or review_env,
                stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
            require(len(result.stdout) <= 128 * 1024 and len(result.stderr) <= 8192, 'review_response_cap')
            require(suite.secret_canary.encode() not in result.stdout + result.stderr, 'review_prompt_leak')
            value = json.loads(result.stdout) if result.returncode == 0 else None
            if value:
                require(value['observation']['authority'] is False and value['observation']['executed'] is False,
                        'review_claimed_authority')
            return result.returncode, value, result.stdout

        finished = []
        for replacing in (False, True):
            name = 'genuine-replace-review' if replacing else 'genuine-create-review';begin(name)
            root, target, plan, code, prepared = suite.prepare(name, replacing=replacing)
            require(code == 0, 'prepare_failed')
            baseline = args.output / 'explicit-old.txt'
            if replacing:
                baseline.write_bytes(target.read_bytes());baseline.chmod(0o600)
            targets = prepared['profile']['targets'];index = next(i for i, t in enumerate(targets) if t['name'] == 'result.txt')
            payload = {'path':'result.txt', 'content':EDIT.NEW}
            if replacing:
                old = targets[index]['replacement'];payload.update(old_identity=old['identity'], old_sha256=old['sha256'])
            before_name = 'result.txt' if replacing else 'source.txt'
            before_index = next(i for i, t in enumerate(targets) if t['name'] == before_name)
            proposals = [(f'read_output_{before_index}', {'path':before_name}),
                         (('replace' if replacing else 'create') + f'_output_{index}', payload),
                         (f'read_output_{index}', {'path':'result.txt'})]
            row, observed, _ = suite.host(name, root, target, plan, prepared, proposals)
            require(row['exit'] == 0 and len(observed) == 3 and all(not r['is_error'] for r in observed.values())
                    and EDIT.NEW.strip() in json.dumps(observed['toolu_edit_2']['content']), 'genuine_readback_missing')
            run = suite.last_run
            before = selected_witness(suite, run, target, plan)
            code, value, _ = review(run, prepared)
            require(code == 0 and value['observation']['outputs'][0]['sha256'] == sha(EDIT.NEW.encode()), 'review_digest_wrong')
            require(before == selected_witness(suite, run, target, plan), 'review_changed_inputs')
            finish(name, genuine_readback=True, unchanged=True, observed_sha256=sha(target.read_bytes()),
                   observation_sha256=value['observation_sha256'], process_cleanup=row['process_cleanup'])
            finished.append((root, target, plan, prepared, run))
        root, target, plan, prepared, run = finished[1]

        def checked(name, *extra, success=False, check=None, env=None):
            begin(name);before = selected_witness(suite, run, target, plan)
            code, value, raw = review(run, prepared, *extra, env=env)
            require((code == 0) == success, 'unexpected_review_exit_' + name)
            if check:
                check(value, raw)
            require(before == selected_witness(suite, run, target, plan), 'review_changed_inputs_' + name)
            finish(name, unchanged=True, exit=code)
            return value

        current = checked('summary-without-content', success=True,
            check=lambda v, raw: require(not v['display'] and not v['comparison'] and EDIT.NEW.encode().strip() not in raw, 'summary_contains_content'))
        checked('escaped-content', '--show', 'result.txt', '--consent-private-content', success=True,
            check=lambda v, raw: require(v['display'][0]['text'] == EDIT.NEW.replace('\n', '\\n'), 'escaped_text_wrong'))
        with replaced(target, 'Untrusted \x1b[31m\u202e text.\n'.encode()):
            checked('terminal-controls-escaped', '--show', 'result.txt', '--consent-private-content', success=True,
                check=lambda v, raw: require(b'\x1b' not in raw and '\u202e'.encode() not in raw
                    and '\\u{1b}' in v['display'][0]['text'] and '\\u{202e}' in v['display'][0]['text'], 'terminal_controls_not_escaped'))
        checked('missing-baseline', success=True,
            check=lambda v, raw: require(v['observation']['outputs'][0]['baseline'] == 'baseline_unavailable', 'invented_baseline'))
        checked('explicit-baseline', '--baseline', f'result.txt={baseline}', '--consent-private-content', success=True,
            check=lambda v, raw: require(v['comparison'][0]['equal'] is False and v['comparison'][0]['baseline'] == 'verified_explicit_copy', 'baseline_not_verified'))
        wrong = args.output / 'wrong-old.txt';wrong.write_text('Unrelated baseline.');wrong.chmod(0o600)
        checked('wrong-baseline', '--baseline', f'result.txt={wrong}', '--consent-private-content')
        checked('baseline-without-consent', '--baseline', f'result.txt={baseline}')
        checked('content-without-consent', '--show', 'result.txt')
        checked('undeclared-target', '--show', '../native-token', '--consent-private-content')
        code, current, _ = review(run, prepared)
        require(code == 0, 'fresh_export_observation_failed')
        bundles = args.output / 'exports';bundles.mkdir(mode=0o700)
        out = bundles / 'selected'
        words = ('--export', out, '--include', 'result.txt', '--expect-observation', current['observation_sha256'], '--consent-private-content')
        checked('individual-private-export', *words, success=True)
        manifest = json.loads((out / 'manifest.json').read_bytes())
        require(sorted(p.name for p in out.iterdir()) == ['manifest.json', 'result.txt']
                and (out / 'result.txt').read_bytes() == target.read_bytes()
                and manifest['files'] == [{'name':'result.txt', 'bytes':len(EDIT.NEW.encode()), 'sha256':sha(target.read_bytes())}]
                and manifest['observation_sha256'] == current['observation_sha256']
                and stat.S_IMODE(out.stat().st_mode) == 0o700
                and all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in out.iterdir()), 'private_export_not_exact')
        report['exact_export_verified'] = True
        checked('export-without-consent', *words[:-1])
        checked('wrong-observation', '--export', bundles / 'wrong', '--include', 'result.txt', '--expect-observation', '0' * 64, '--consent-private-content')
        with replaced(target, b'Operator superseding current output.\n'):
            checked('changed-output', '--export', bundles / 'changed', '--include', 'result.txt', '--expect-observation', current['observation_sha256'], '--consent-private-content')
        with replaced(target, link=suite.sentinel): checked('symlink-output')
        with replaced(target, fifo=True): checked('fifo-output')
        with replaced(target, link='/dev/zero'): checked('device-link')
        hard = args.output / 'hardlink';os.link(target, hard)
        try: checked('hardlink-output')
        finally: hard.unlink()
        with replaced(target, b'x' * 4097):
            # The independent general witness has no 4096-byte observation cap.
            checked('oversized-output')
        with replaced(target):
            checked('missing-output', success=True,
                check=lambda v, raw: require(v['observation']['outputs'][0]['observation'] == 'absent'
                    and v['observation']['outputs'][0]['sha256'] is None, 'missing_output_invented'))
        with replaced(target, b'\xff\0private-binary'):
            checked('binary-summary', success=True, check=lambda v, raw: require(v['observation']['outputs'][0]['text'] is False and not v['display'], 'binary_displayed'))
            checked('binary-display-refused', '--show', 'result.txt', '--consent-private-content')
        held = root.with_name(root.name + '-kept');root.rename(held);root.mkdir(mode=0o700)
        try: checked('replaced-root')
        finally: root.rmdir();held.rename(root)
        root.rename(held);root.symlink_to(held, target_is_directory=True)
        try: checked('redirected-parent')
        finally: root.unlink();held.rename(root)
        with replaced(run / 'profile.json', b'{}'): checked('tampered-profile')
        with replaced(run / 'terminal.json'): checked('missing-terminal')
        terminal = json.loads((run / 'terminal.json').read_bytes());terminal['cleanup']['reaped'] = False
        with replaced(run / 'terminal.json', json.dumps(terminal).encode()): checked('contradictory-terminal')
        with replaced(run / 'stop-receipt.json'): checked('missing-cleanup-receipt')
        for name, field, value in [('foreign-owner', 'uid', os.geteuid()+1), ('stale-boot', 'boot_id', '0' * 8 + '-0000-0000-0000-' + '0' * 12)]:
            context = json.loads((run / 'diagnostic-context.json').read_bytes());context['owner'][field] = value
            with replaced(run / 'diagnostic-context.json', json.dumps(context).encode()): checked(name)
        # Real active run and actual cancellation; neither is a fabricated terminal.
        begin('active-run')
        cancel_root, cancel_target, cancel_plan, code, cancel_prepared = suite.prepare('cancelled', replacing=True)
        require(code == 0, 'cancel_prepare_failed')
        index = 0;old = cancel_prepared['profile']['targets'][index]['replacement'];seen = []
        def pending(active, _):
            if not seen:
                code, _, _ = review(active, cancel_prepared)
                require(code != 0, 'active_run_reviewed');seen.append(True)
        args_replace = {'path':'result.txt', 'content':EDIT.NEW, 'old_identity':old['identity'], 'old_sha256':old['sha256']}
        row, _, _ = suite.host('cancelled', cancel_root, cancel_target, cancel_plan, cancel_prepared,
                              [(f'replace_output_{index}', args_replace)], mode='cancel-pending', on_pending=pending)
        require(seen and row['terminal']['reason'] == 'cancelled' and row['process_cleanup']['all_stopped'], 'cancellation_not_actual')
        finish('active-run', actual_pending_run=True)
        begin('cancelled-run');before = selected_witness(suite, suite.last_run, cancel_target, cancel_plan)
        require(review(suite.last_run, cancel_prepared)[0] != 0 and before == selected_witness(suite, suite.last_run, cancel_target, cancel_plan), 'cancelled_run_reviewed')
        finish('cancelled-run', unchanged=True, actual_cancellation=True)
        begin('read-substitution-race');before_sentinel = snapshot(suite.sentinel)
        race_env = dict(review_env, LD_PRELOAD=str(args.fault), SOU179_RACE_TARGET=str(target), SOU179_RACE_OUTSIDE=str(suite.sentinel))
        try:
            require(review(run, prepared, env=race_env)[0] != 0 and target.is_symlink()
                    and snapshot(suite.sentinel) == before_sentinel, 'read_substitution_not_refused')
        finally:
            if target.is_symlink(): target.unlink()
            kept = target.with_name(target.name + '.kept')
            if kept.exists(): kept.rename(target)
        finish('read-substitution-race', actual_descriptor_read_race=True, outside_unchanged=True)
        # Race fixture changed ctime; require a fresh observation for new exports.
        code, current, _ = review(run, prepared);require(code == 0, 'post_race_review_failed')
        def export_args(path):
            return ('--export', path, '--include', 'result.txt', '--expect-observation', current['observation_sha256'], '--consent-private-content')
        before_inventory = sorted(p.name for p in bundles.iterdir())
        checked('failed-publication-cleanup', *export_args(bundles / 'io-failure'),
                env=dict(review_env, LD_PRELOAD=str(args.fault), SOU179_EXPORT_IO_FAILURE='1'))
        require(sorted(p.name for p in bundles.iterdir()) == before_inventory, 'failed_export_left_stage')
        begin('concurrent-create-new-export');before = selected_witness(suite, run, target, plan)
        concurrent_out = bundles / 'concurrent'
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: review(run, prepared, *export_args(concurrent_out))[0], range(2)))
        require(results.count(0) == 1 and before == selected_witness(suite, run, target, plan)
                and (concurrent_out / 'result.txt').read_bytes() == target.read_bytes(), 'concurrent_export_not_create_new')
        finish('concurrent-create-new-export', successes=1, unchanged=True)
        checked('existing-destination', *export_args(concurrent_out))
        require(not any(p.name.startswith('.agentfw-doctor-') for p in bundles.iterdir()), 'private_stage_remains')
        begin('sanitized-support-separate');support = bundles / 'sanitized';before = selected_witness(suite, run, target, plan)
        code, value = suite.cli('status', '--run', run, '--json', '--support-bundle', support)
        require(code == 0 and EDIT.NEW.encode().strip() not in (support / 'report.json').read_bytes()
                and sorted(p.name for p in support.iterdir()) == ['manifest.json', 'report.json']
                and before == selected_witness(suite, run, target, plan), 'sanitized_support_changed')
        finish('sanitized-support-separate', unchanged=True, no_private_content=True)
        require(not trap.requests and snapshot(suite.sentinel) == suite.before_sentinel, 'review_external_effect')
        report.update(status='passed', provider_requests_during_review=len(trap.requests),
                      sentinel_preserved=True, all_owned_stopped=True)
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
        print(json.dumps({'format':FORMAT, 'executed':False, 'expected':list(CASES)}));return 0
    require(args.output and args.output.is_absolute() and not args.output.exists(), 'new_absolute_output_required')
    args.output.mkdir(mode=0o700)
    report = {'format':FORMAT, 'status':'incomplete', 'paid_inference':False, 'expected':list(CASES),
              'cases':[{'id':n, 'status':'incomplete', 'attempted':False} for n in CASES]}
    try:
        qualify(args, report)
    except Exception as error:
        code = EDIT.failure_code(error);report.update(status='failed', failure=code, failure_type=type(error).__name__)
        current = next((r for r in report['cases'] if r['attempted'] and r['status'] == 'incomplete'), None)
        if current is not None: current.update(status='failed', failure=code)
    report['inventory'] = {s:sum(r['status'] == s for r in report['cases']) for s in ('passed', 'failed', 'incomplete')}
    (args.output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'format':FORMAT, 'status':report['status'], 'inventory':report['inventory']}))
    return 0 if passed_report(report) else 1


if __name__ == '__main__':
    raise SystemExit(main())
