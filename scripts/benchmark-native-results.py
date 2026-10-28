#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Finite old/candidate original-filesystem result trials; no deadline overrides.

Run inside a private loopback-only Linux namespace with immutable source and
writable owned scratch. Pre-fetch locked packages separately. The manifest binds
four actual binaries to their source/build identities. No model service is used.
Every planned trial is recorded even after a timeout/refusal. Never retry a row.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import statistics
import signal
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('large', ROOT / 'scripts/verify-large-results.py')
L = importlib.util.module_from_spec(spec)
spec.loader.exec_module(L)
require, sha, write = L.require, L.sha, L.write
PLAN = ROOT / 'docs/operations/evidence/sou-165/trial-plan.json'


def timing_rows(path, event):
    if not path.exists():
        return []
    require(path.stat().st_size <= 16 * 1024 * 1024, 'diagnostic log cap')
    rows = []
    for line in path.read_text(errors='strict').splitlines():
        if not line.startswith('{'):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get('event') == event:
            require(len(rows) < 1024, 'timing row cap')
            rows.append(row)
    return rows


def check_manifest(value):
    require(set(value) == {'instrumented-baseline', 'measured-candidate'}, 'two exact variants required')
    for variant, builds in value.items():
        require(set(builds) == {'dev', 'release'}, 'debug and distribution builds required')
        for profile, build in builds.items():
            require(set(build) == {'binary', 'binary_sha256', 'source', 'rustc', 'profile'}, 'build identity fields')
            require(build['profile'] == profile and len(build['source']) == 40
                    and all(c in '0123456789abcdef' for c in build['source']), 'build/source identity')
            path = Path(build['binary']).resolve(strict=True)
            require(path.is_file() and sha(path) == build['binary_sha256'], 'binary identity changed')
            require(isinstance(build['rustc'], str) and len(build['rustc']) < 256, 'compiler identity')
    return value


def trial(args, report, build, condition, variant, repeat, installed, workspace):
    label = f'{condition["name"]}-{repeat}-{variant}'
    row = {'trial': label, 'condition': condition['name'], 'repeat': repeat, 'variant': variant,
           'build': build, 'status': 'incomplete', 'responses': [], 'planned_responses': 9,
           'supported_exact': 0, 'oversized_refused': False, 'useful_continuation': False,
           'load_before': list(os.getloadavg()), 'workspace_before': L.BASE.snapshot(workspace)}
    report['trials'].append(row)  # Append BEFORE any process starts.
    local = SimpleNamespace(**vars(args))
    local.agentfw = Path(build['binary'])
    local.output = args.output
    context = {'phases': {}}
    phase = None
    loaders = []
    started = time.monotonic()
    def expired(_signal, _frame):
        raise TimeoutError('finite trial deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 90)
    try:
        row['stage'] = 'startup'
        phase = L.Phase(local, context, label, installed, workspace)
        phase.start()
        # Fixed warm-up matches the original warmed inspection path. Its audit
        # remains in the logs but it is not one of the nine measured responses.
        row['stage'] = 'warmup'
        _, warm, _, _, _ = phase.exchange('read_text_file', {'path': '/workspace/k120.txt'})
        require(L.response_text(warm).encode() == (workspace / 'k120.txt').read_bytes(), 'warmup bytes')
        for _ in range(condition['owned_cpu_loaders']):
            loaders.append(subprocess.Popen([sys.executable, '-I', '-c',
                'import time\nend=time.monotonic()+90\nwhile time.monotonic()<end: sum(range(20000))'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        ids = [phase.ident() for _ in range(9)]
        row['host_call_ids'] = ids
        frames = [L.BASE.call(i, {'path': '/workspace/k120.txt'}) for i in ids[:8]]
        frames.append(L.BASE.call(ids[8], {'path': '/workspace/m2.txt'}))
        supported_before, oversized_before = phase.reads('/workspace/k120.txt'), phase.reads('/workspace/m2.txt')
        burst_start = time.monotonic()
        row['stage'] = 'burst'
        phase.client.send(*frames)
        seen = set()
        for _ in ids:
            value, raw = phase.client.receive(timeout=max(0.1, 90 - (time.monotonic() - burst_start)))
            ident = value.get('id')
            require(ident in ids and ident not in seen, 'uncorrelated/duplicate original result')
            seen.add(ident)
            response = {'id': ident, 'elapsed_ms': (time.monotonic() - burst_start) * 1000,
                        'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
            row['responses'].append(response)
            if ident in ids[:8]:
                exact = L.response_text(value).encode() == (workspace / 'k120.txt').read_bytes()
                response['exact'] = exact
                row['supported_exact'] += int(exact)
            else:
                row['oversized_refused'] = value.get('error', {}).get('message') == L.budgets()['frame_message']
        row['burst_ms'] = (time.monotonic() - burst_start) * 1000
        row['original_read_effects'] = {
            'supported': phase.reads('/workspace/k120.txt') - supported_before,
            'oversized': phase.reads('/workspace/m2.txt') - oversized_before}
        require(row['original_read_effects']['supported'] >= 8 and row['original_read_effects']['oversized'] >= 1,
                'original server syscall witness missing')
        row['stage'] = 'useful_continuation'
        phase.useful(label)
        row['useful_continuation'] = True
        require(row['supported_exact'] == 8 and row['oversized_refused'], 'burst decisions/bytes changed')
        row['status'] = 'passed'
        row['stage'] = 'complete'
    except Exception as error:
        row['status'] = 'failed'
        row['error_type'] = type(error).__name__
        # No exception bodies: a parser error may contain the original bytes.
    finally:
        # Cleanup retains its existing bounded grace after the trial deadline.
        # This outer diagnostic guard never changes any native/collector timer.
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if phase is not None:
            for loader in loaders:
                loader.terminate()
                loader.wait(timeout=5)
            try:
                phase.stop()
            except Exception as error:
                row['cleanup_error_type'] = type(error).__name__
                row['status'] = 'failed'
            section = context['phases'].get(label, {})
            row['phase'] = section
            initial_memory = section.get('memory_after_initialize') or {}
            final_memory = section.get('memory_final') or {}
            if (not initial_memory or not final_memory
                    or final_memory['vm_hwm_kib'] - initial_memory['vm_rss_kib'] > 96 * 1024):
                row['status'] = 'failed'
            if (not section.get('daemon_cleanup', {}).get('all_stopped')
                    or not section.get('client', {}).get('process_cleanup', {}).get('all_stopped')
                    or section.get('client', {}).get('forced_cleanup') is not False
                    or section.get('client', {}).get('exit_code') != 0
                    or section.get('daemon_exit_code') not in (0, -15)
                    or section.get('cleanup_audit', {}).get('cleanup_verified') is not True):
                row['status'] = 'failed'
            row['native_timing'] = timing_rows(phase.root / 'daemon.log', 'native_admission_timing')
            observed = {r['sha256'] for r in row['responses']}
            row['burst_result_timing'] = [r for r in row['native_timing']
                                          if r.get('request_event') == 'result' and r.get('content_sha256') in observed]
            if row['status'] == 'passed' and (len(row['burst_result_timing']) != 9
                    or any(r.get('release_decision') is not True for r in row['burst_result_timing'])):
                row['status'] = 'failed'
            row['transport_timing'] = timing_rows(phase.root / 'collector.log', 'mcp_native_transport_timing')
            row['delivery_timing'] = timing_rows(phase.root / 'collector.log', 'mcp_original_result_delivery_timing')
        row['workspace_after'] = L.BASE.snapshot(workspace)
        row['elapsed_seconds'] = time.monotonic() - started
        row['load_after'] = list(os.getloadavg())
        if row['workspace_before'] != row['workspace_after']:
            row['status'] = 'failed'
        write(args.output / 'report.json', report)


def run(args, report):
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0,
            'native Linux x86-64 non-root required')
    plan = json.loads(PLAN.read_text())
    require(plan['maximum_burst_trials'] == 18 and plan['workload']['supported_reads'] == 8
            and plan['workload']['native_http_deadline_ms'] == 5000, 'frozen workload changed')
    report.update(plan=plan, plan_sha256=sha(PLAN), source=L.BASE.source(),
                  environment={'system': platform.system(), 'kernel': platform.release(),
                               'machine': platform.machine(), 'cpus': os.cpu_count(),
                               'affinity': sorted(os.sched_getaffinity(0)), 'load': list(os.getloadavg())},
                  python={'version': platform.python_version(), 'sha256': sha(Path(sys.executable).resolve())})
    builds = check_manifest(json.loads(args.manifest.read_text()))
    workspace = args.output / 'workspace'
    workspace.mkdir(mode=0o700)
    L.make_workspace(workspace, L.budgets()['text_bytes'])
    installed = args.output / 'installed'
    L.BASE.INSTALL.install(installed, workspace, args.node, args.bwrap, args.npm,
                          npm_cache=args.npm_cache, offline=True)
    report['runtime'] = {key: sha(getattr(args, key)) for key in ('node', 'npm', 'bwrap', 'strace', 'claude')}
    report['registry_sha256'], report['policy_sha256'] = sha(installed / 'registry.json'), sha(installed / 'policy.yaml')
    for condition in plan['conditions']:
        for repeat in range(condition['burst_repeats']):
            variants = plan['variants'] if repeat % 2 == 0 else list(reversed(plan['variants']))
            for variant in variants:
                trial(args, report, builds[variant][condition['profile']], condition, variant, repeat, installed, workspace)
    # The existing complete inventory is executed unchanged for BOTH variants.
    # It includes the original actual-Claude scripted-provider sequence.
    for variant in plan['variants']:
        out = args.output / ('inventory-' + variant)
        build = builds[variant]['dev']
        command = [sys.executable, '-B', str(ROOT / 'scripts/verify-large-results.py'), '--run', '--offline',
                   '--npm-cache', str(args.npm_cache), '--agentfw', build['binary'], '--output', str(out)]
        for key in ('node', 'npm', 'bwrap', 'strace', 'claude'):
            command += ['--' + key, str(getattr(args, key))]
        row = {'variant': variant, 'status': 'incomplete', 'build': build}
        report['inventories'].append(row)
        try:
            with (args.output / ('inventory-' + variant + '.log')).open('wb') as log:
                result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=300)
            value = json.loads((out / 'report.json').read_text())
            row.update(exit_code=result.returncode, status=value['status'], report_sha256=sha(out / 'report.json'))
        except Exception as error:
            row.update(status='incomplete', error_type=type(error).__name__)
        write(args.output / 'report.json', report)
    report['comparison'] = summarize(report['trials'])
    candidate = [r for r in report['trials'] if r['variant'] == 'measured-candidate']
    require(len(candidate) == 9 and all(r['status'] == 'passed' for r in candidate), 'candidate trial failure')
    require(len(report['inventories']) == 2 and report['inventories'][1]['status'] == 'passed', 'candidate inventory failed')
    report['status'] = 'passed'


def summarize(trials):
    rows = []
    for condition in ('debug-idle', 'debug-contended', 'distribution-idle'):
        for variant in ('instrumented-baseline', 'measured-candidate'):
            selected = [r for r in trials if r['condition'] == condition and r['variant'] == variant]
            passed = [r for r in selected if r['status'] == 'passed']
            rows.append({'condition': condition, 'variant': variant, 'planned': 3,
                         'attempted': len(selected), 'passed': len(passed),
                         'failed': sum(r['status'] == 'failed' for r in selected),
                         'incomplete': 3 - len(selected) + sum(r['status'] == 'incomplete' for r in selected),
                         'successful_burst_median_ms': statistics.median(r['burst_ms'] for r in passed) if passed else None,
                         'successful_tracking_median_us': statistics.median(sum(t['tracking_us'] for t in r['burst_result_timing']) for r in passed) if passed else None})
    return rows


def startup(args, report):
    """Cheap actual original-server preflight before three remaining builds."""
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and os.geteuid() != 0,
            'native Linux x86-64 non-root required')
    require(args.agentfw is not None, 'startup binary required')
    workspace=args.output/'workspace'; workspace.mkdir(mode=0o700)
    L.make_workspace(workspace, L.budgets()['text_bytes'])
    installed=args.output/'installed'
    L.BASE.INSTALL.install(installed,workspace,args.node,args.bwrap,args.npm,npm_cache=args.npm_cache,offline=True)
    report.update(phases={},binary_sha256=sha(args.agentfw))
    phase=L.Phase(args,report,'startup',installed,workspace)
    try:
        phase.start()
        phase.useful('startup')
        require(phase.reads('/workspace/notes.txt')>=1, 'original startup read witness missing')
    finally:
        phase.stop()
    section=report['phases']['startup']
    require(section['client']['exit_code']==0 and section['client']['forced_cleanup'] is False
            and section['client']['process_cleanup']['all_stopped'] and section['daemon_cleanup']['all_stopped']
            and section['cleanup_audit']['cleanup_verified'] is True, 'startup cleanup not verified')
    report['status']='passed'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', type=Path)
    p.add_argument('--agentfw', type=Path)
    p.add_argument('--startup-only', action='store_true')
    for key in ('node', 'npm', 'bwrap', 'strace', 'claude', 'npm-cache', 'output'):
        p.add_argument('--' + key, type=Path, required=True)
    args = p.parse_args()
    args.output = args.output.resolve()
    require(not args.output.exists() and not args.output.is_relative_to(ROOT), 'new scratch output outside checkout required')
    args.output.mkdir(mode=0o700, parents=True)
    report = {'format': 'sw-native-result-startup/1' if args.startup_only else 'sw-native-result-paired-benchmark/1', 'status': 'incomplete', 'trials': [], 'inventories': []}
    try:
        if args.startup_only:
            startup(args, report)
        else:
            require(args.manifest is not None, 'paired build manifest required')
            run(args, report)
    except Exception as error:
        report['error_type'] = type(error).__name__
    finally:
        report['denominator'] = {'planned': 0 if args.startup_only else 18, 'attempted': len(report['trials']),
            'passed': sum(r['status'] == 'passed' for r in report['trials']),
            'failed': sum(r['status'] == 'failed' for r in report['trials']),
            'incomplete': (0 if args.startup_only else 18) - len(report['trials']) + sum(r['status'] == 'incomplete' for r in report['trials'])}
        write(args.output / 'report.json', report)
    print(json.dumps({k: report.get(k) for k in ('status', 'denominator', 'error_type')}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
