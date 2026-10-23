#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact-source, same-host native Ask comparison; no timeout or authority changes."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('ask_metrics', ROOT / 'scripts/pilot_ask_latency.py')
METRICS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(METRICS)
NATIVE_SPEC = importlib.util.spec_from_file_location('ask_owned_group', ROOT / 'scripts/prepare-native-pilot-prerequisites.py')
NATIVE = importlib.util.module_from_spec(NATIVE_SPEC)
NATIVE_SPEC.loader.exec_module(NATIVE)
PROFILES = ('filesystem', 'git')
SHARED = ('claude', 'node', 'npm', 'bwrap', 'git', 'strace')


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def source(root, commit):
    require(re.fullmatch('[0-9a-f]{40}', commit or ''), 'full_source_sha_required')
    def git(*words):
        return subprocess.check_output(['git', '-C', str(root), *words], timeout=15)
    require(git('rev-parse', 'HEAD').decode().strip() == commit, 'source_head_changed')
    require(not git('status', '--porcelain', '--untracked-files=all'), 'source_dirty')
    names = [os.fsdecode(n) for n in git('ls-files', '-z').split(b'\0') if n]
    require('Cargo.lock' in names and 'scripts/qualify-pilot-ask.py' in names, 'source_inputs_missing')
    files = {name: sha(root / name) for name in names}
    return {'commit': commit, 'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
            'dirty': False, 'files_sha256': hashlib.sha256(json.dumps(files, sort_keys=True,
                separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()}


def json_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 16 * 1024 * 1024,
            'bounded_regular_report_required')
    return json.loads(path.read_text())


def validate_build(receipt, identity, selected):
    require(receipt.get('format') == 'sw-native-pilot-agent-source-build/1', 'build_receipt_contract')
    require(all(receipt.get('source', {}).get(k) == v for k, v in identity.items()),
            'build_source_mismatch')
    for role in ('agentfw', 'git_launcher'):
        require(receipt.get('binaries', {}).get(role, {}).get('sha256') == selected[role],
                'build_binary_mismatch')


def validate_report(report, expected_source, selected, samples, candidate):
    require(report.get('status') in ('pass', 'performance_blocker'), 'qualification_failed')
    require(report.get('real_host_executed') is True and report.get('scripted_owned_provider') is True
            and type(report.get('paid_api_calls')) is int and report['paid_api_calls'] == 0,
            'actual_owned_host_required')
    for key in ('source', 'source_after'):
        require(all(report.get(key, {}).get(k) == expected_source[k]
                    for k in ('commit', 'tree', 'dirty')), 'qualification_source_mismatch')
    require(report.get('workspace_unchanged') is True, 'workspace_changed')
    require(report.get('selected_sha256') == selected, 'qualification_binary_mismatch')
    rows = report.get('cases')
    require(isinstance(rows, list) and len(rows) == 2 * samples, 'complete_denominator_required')
    metrics = METRICS.summarize(rows, samples)
    for profile in PROFILES:
        m = metrics[profile]
        require(m['successful'] == samples and m['failed'] == m['incomplete'] == 0,
                'security_or_effect_sample_failed')
    for row in rows:
        require(row.get('profile') in PROFILES and row.get('case') == 'approve', 'unexpected_sample')
        if row['profile'] == 'filesystem':
            require(row.get('allow_peer_while_pending') is True
                    and row.get('cross_run_isolation_and_cleanup') is True, 'peer_progress_missing')
        if candidate:
            proof = row.get('verified_inputs_resume', {})
            require(proof.get('observer') == 'collector mcp_verified_inputs_resume', 'reuse_observer_missing')
            require(all(type(proof.get(k)) is int and proof[k] >= 0
                        for k in ('immutable_files', 'leased_files', 'rehashed_files')), 'reuse_counts_invalid')
            require(proof['immutable_files'] + proof['leased_files'] > 0, 'actual_reuse_missing')
    require(report.get('latency') == metrics, 'reported_metrics_disagree')
    return metrics


def run(args, report):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'native_linux_x86_64_required')
    roots = {side: getattr(args, side + '_root').resolve(strict=True) for side in ('baseline', 'candidate')}
    require(roots['candidate'] == ROOT and roots['baseline'] != ROOT, 'separate_exact_sources_required')
    output = args.output.absolute()
    require(not output.is_symlink() and all(not output.is_relative_to(p) for p in roots.values()),
            'output_outside_sources_required')
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(output.resolve() == output and output.stat().st_uid == os.getuid()
            and stat.S_IMODE(output.stat().st_mode) == 0o700 and not any(output.iterdir()),
            'empty_private_output_required')
    report['_output_ready'] = True
    common = {name: getattr(args, name).resolve(strict=True) for name in SHARED}
    shared_hashes = {k: sha(v) for k, v in common.items()}
    before = {side: source(root, getattr(args, side + '_commit')) for side, root in roots.items()}
    require(before['baseline']['commit'] != before['candidate']['commit'], 'distinct_before_after_required')
    report.update(source_before=before, shared_sha256=shared_hashes,
                  environment={'system': platform.system(), 'release': platform.release(),
                               'machine': platform.machine()}, samples_per_profile=args.samples, sides={})
    for side in ('baseline', 'candidate'):
        root = roots[side]
        private = output / (side + '-private')
        private.mkdir(mode=0o700)
        result_dir = output / side
        result_dir.mkdir(mode=0o700)
        selected_paths = {name: getattr(args, side + '_' + name).resolve(strict=True)
                          for name in ('agentfw', 'git_launcher')}
        selected = {k: sha(v) for k, v in selected_paths.items()} | shared_hashes
        validate_build(json_file(getattr(args, side + '_receipt')), before[side], selected)
        command = [sys.executable, '-B', str(root / 'scripts/qualify-pilot-ask.py'),
                   '--approval-samples', str(args.samples), '--output', str(result_dir)]
        for name, path in (selected_paths | common).items():
            command += ['--' + name.replace('_', '-'), str(path)]
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': 'C.UTF-8',
               'HOME': str(private), 'TMPDIR': str(private), 'PYTHONDONTWRITEBYTECODE': '1',
               'HTTP_PROXY': 'http://127.0.0.1:9', 'HTTPS_PROXY': 'http://127.0.0.1:9',
               'NO_PROXY': '127.0.0.1,localhost,::1'}
        exit_code = 0
        stage = 'comparison_' + side
        try:
            # Reuse the existing bounded log/cancellation/process-group owner.
            # This is a total measurement budget, not a host/call deadline.
            NATIVE.build(command, cwd=root, env=env, log=private / 'qualification.log',
                         seconds=3600, stage=stage)
        except NATIVE.Failure as error:
            if error.stage != stage or error.exit_code != 1:
                raise
            exit_code = 1  # Still requires a complete, honest report below.
        raw = json_file(result_dir / 'qualification.json')
        report['sides'][side] = {'exit_code': exit_code, 'qualification': raw}
        metrics = validate_report(raw, before[side], selected, args.samples, side == 'candidate')
        require(exit_code == (0 if raw['status'] == 'pass' else 1), 'qualification_exit_mismatch')
        report['sides'][side]['metrics'] = metrics
        require(source(root, before[side]['commit']) == before[side], 'source_changed_during_measurement')
        require(all(sha(p) == selected[k] for k, p in (selected_paths | common).items()), 'selected_asset_changed')
    report['source_after'] = {side: source(root, before[side]['commit']) for side, root in roots.items()}
    require(report['source_after'] == before, 'comparison_source_changed')
    report['status'] = ('passed' if report['sides']['candidate']['metrics']['status'] == 'target_met'
                        else 'performance_blocker')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for side in ('baseline', 'candidate'):
        for name in ('root', 'agentfw', 'git_launcher', 'receipt'):
            parser.add_argument('--' + side + '-' + name.replace('_', '-'), type=Path, required=True)
        parser.add_argument('--' + side + '-commit', required=True)
    for name in (*SHARED, 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--samples', type=int, default=20, choices=range(20, 101))
    args = parser.parse_args()
    report = {'format': 'sw-pilot-ask-comparison/1', 'status': 'incomplete', 'paid_api_calls': 0,
              'provider': 'owned-scripted-loopback', 'live_model_effectiveness': 'not_tested'}
    try:
        run(args, report)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, NATIVE.Failure) as error:
        report.update(status='failed', error_type=type(error).__name__)
        if isinstance(error, ValueError):
            report['error'] = str(error)[:160]
    if report.pop('_output_ready', False):
        with (args.output / 'comparison.json').open('x') as stream:
            json.dump(report, stream, indent=2, allow_nan=False)
            stream.write('\n')
    print(json.dumps({k: report.get(k) for k in ('status', 'error', 'error_type')}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
