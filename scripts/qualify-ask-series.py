#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-141 declared cold/warm original-server Ask latency series.

Runs the existing `qualify-pilot-ask.py --approval-samples N` workflow once per
entry of a plan declared before the first trial, records every attempt (also
failed, timed-out and unqualified ones) with its denominators, and summarizes
distributions without discarding the worst trial.  It never changes timeouts,
TTLs, scan bounds or authority, and it never turns an unavailable environment
(no cache drop, WSL2, missing reuse proof) into a success: such runs stay in the
report with an explicit label and are excluded from the cold/warm pools.
"""
import argparse
import datetime
import glob
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ('filesystem', 'git')
TOOLS = ('agentfw', 'git_launcher', 'claude', 'node', 'npm', 'bwrap', 'git', 'strace')
FORMAT = 'sw-ask-series/1'
MAX_RUNS = 6
STAGE_EVENT = 'mcp_asset_verification_timing'
EVENT_NAMES = (STAGE_EVENT, 'mcp_real_approval_timing', 'mcp_verified_inputs_resume')
WATCHED = ('host.stderr.private', 'daemon.private')


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def comparison():
    return load('ask_comparison', 'scripts/qualify-pilot-ask-comparison.py')


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_plan(text):
    plan = [word.strip() for word in text.split(',')]
    if not 1 <= len(plan) <= MAX_RUNS or any(word not in ('cold', 'warm') for word in plan):
        raise ValueError('plan_must_be_cold_or_warm_words')
    if plan[0] != 'cold':
        raise ValueError('plan_must_start_with_cold')
    return plan


def platform_kind():
    release = platform.release().lower()
    version = ''
    try:
        version = Path('/proc/version').read_text().lower()
    except OSError:
        pass
    if 'microsoft' in release or 'microsoft' in version:
        return 'wsl2' if 'wsl2' in release or 'wsl2' in version else 'wsl'
    return 'native_linux'


def nearest_rank(values, fraction):
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * fraction) - 1] if ordered else None


def distribution(values):
    values = [round(float(v), 3) for v in values]
    return {'n': len(values), 'p50': nearest_rank(values, .5), 'p95': nearest_rank(values, .95),
            'worst': max(values) if values else None}


def meminfo():
    fields = {}
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            key, _, rest = line.partition(':')
            if key in ('MemTotal', 'MemFree', 'MemAvailable', 'Buffers', 'Cached', 'SwapTotal', 'SwapFree'):
                fields[key + '_kb'] = int(rest.split()[0])
    except (OSError, ValueError, IndexError):
        pass
    return fields


def pressure(name):
    try:
        return Path('/proc/pressure/' + name).read_text().strip().splitlines()
    except OSError:
        return None


def conditions():
    try:
        load_average = Path('/proc/loadavg').read_text().split()[:3]
    except OSError:
        load_average = None
    return {'at': now(), 'loadavg': load_average, 'cpu_count': os.cpu_count(), 'meminfo': meminfo(),
            'pressure': {name: pressure(name) for name in ('cpu', 'memory', 'io')}}


def drop_caches():
    """Honest cache-drop attempt; success needs a measurable page-cache shrink or an empty cache."""
    before = meminfo()
    record = {'requested': True, 'performed': False, 'error': None,
              'cached_kb_before': before.get('Cached_kb'), 'cached_kb_after': None}
    command = ['sh', '-c', 'sync; echo 3 > /proc/sys/vm/drop_caches']
    if os.geteuid() != 0:
        command = ['sudo', '-n'] + command
    try:
        result = subprocess.run(command, capture_output=True, timeout=120, check=False)
        if result.returncode != 0:
            record['error'] = 'exit_' + str(result.returncode)
    except (OSError, subprocess.SubprocessError) as error:
        record['error'] = type(error).__name__
    after = meminfo()
    record['cached_kb_after'] = after.get('Cached_kb')
    before_kb, after_kb = record['cached_kb_before'], record['cached_kb_after']
    record['performed'] = (record['error'] is None and before_kb is not None and after_kb is not None
                           and (after_kb < before_kb or after_kb < 262144))
    return record


class Watcher(threading.Thread):
    """Copies only well-formed timing/reuse JSON events from private harness logs.

    Trace files and raw arguments stay private; escaped copies of the same words
    inside strace output are not JSON objects at line start and are ignored.
    """

    def __init__(self, pattern, sink):
        super().__init__(daemon=True)
        self.pattern, self.sink = pattern, sink
        self.stop_flag = threading.Event()
        self.offsets, self.launch_ids, self.sequence = {}, {}, 0

    def sweep(self):
        for path in sorted(glob.glob(self.pattern, recursive=True)):
            if os.path.basename(path) not in WATCHED:
                continue
            try:
                with open(path, 'rb') as stream:
                    stream.seek(self.offsets.get(path, 0))
                    data = stream.read()
            except OSError:
                continue
            cut = data.rfind(b'\n') + 1
            self.offsets[path] = self.offsets.get(path, 0) + cut
            launch = self.launch_ids.setdefault(path, len(self.launch_ids))
            for line in data[:cut].splitlines():
                if not line.startswith(b'{'):
                    continue
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if isinstance(event, dict) and event.get('event') in EVENT_NAMES:
                    self.sink.write(json.dumps({'launch': launch, 'source': os.path.basename(path),
                                                'seq': self.sequence, 'event': event},
                                               sort_keys=True, allow_nan=False) + '\n')
                    self.sequence += 1
        self.sink.flush()

    def run(self):
        while not self.stop_flag.is_set():
            self.sweep()
            time.sleep(0.1)

    def finish(self):
        self.stop_flag.set()
        self.join(timeout=5)
        self.sweep()


def profile_of(name):
    for profile in PROFILES:
        if isinstance(name, str) and profile in name:
            return profile
    return None


def stage_distributions(rows):
    """Per (profile, stage, pass-within-host-launch) elapsed_ms plus the pass-1 total per launch."""
    counters, values, first_pass = {}, {}, {}
    for row in rows:
        event = row.get('event', {})
        if event.get('event') != STAGE_EVENT:
            continue
        profile, stage, elapsed = profile_of(event.get('profile')), event.get('stage'), event.get('elapsed_ms')
        if profile is None or not isinstance(stage, str) or type(elapsed) not in (int, float) or not math.isfinite(elapsed):
            continue
        key = (row['launch'], profile, stage)
        counters[key] = counters.get(key, 0) + 1
        values.setdefault((profile, stage, counters[key]), []).append(elapsed)
        if counters[key] == 1:
            first_pass[(profile, row['launch'])] = first_pass.get((profile, row['launch']), 0) + elapsed
    out = {'asset_verification_by_pass': {}, 'first_pass_asset_verification_total_ms_proxy': {}}
    for (profile, stage, number), found in sorted(values.items()):
        out['asset_verification_by_pass'].setdefault(profile, {}).setdefault(stage, {})['pass_' + str(number)] = distribution(found)
    for profile in PROFILES:
        found = [v for (p, _), v in first_pass.items() if p == profile]
        if found:
            out['first_pass_asset_verification_total_ms_proxy'][profile] = distribution(found)
    out['events_seen'] = {}
    for row in rows:
        name = row.get('event', {}).get('event')
        out['events_seen'][name] = out['events_seen'].get(name, 0) + 1
    return out


def read_events(path):
    """Read driver JSONL rows or tab-separated `source<TAB>event` rows; the source column names the host launch."""
    rows, launches = [], {}
    if path and Path(path).is_file():
        for line in Path(path).read_text(errors='replace').splitlines():
            origin, rest = line.split('\t', 1) if '\t' in line else ('', line)
            if not rest.startswith('{'):
                continue
            try:
                row = json.loads(rest)
            except ValueError:
                continue
            if 'event' in row and 'launch' in row:
                rows.append(row)
            elif row.get('event') in EVENT_NAMES:
                rows.append({'launch': launches.setdefault(origin, len(launches)), 'event': row})
    return rows


def trial_table(cases, samples, metrics):
    table = {}
    for profile in PROFILES:
        rows = sorted((c for c in cases if c.get('profile') == profile and c.get('case') == 'approve'),
                      key=lambda c: c.get('sample_index', -1))
        table[profile] = {'continuation_ms_by_trial': [
            {'sample_index': c.get('sample_index'), 'passed': c.get('passed') is True,
             'decision_to_result_ms': c.get('decision_to_result_ms')} for c in rows],
            'reuse': [c.get('verified_inputs_resume') for c in rows]}
    return table


def run_summary(qualification, samples, events):
    cases = qualification.get('cases') if isinstance(qualification, dict) else None
    out = {'qualification_status': qualification.get('status') if isinstance(qualification, dict) else None}
    if isinstance(cases, list):
        metrics = load('ask_metrics', 'scripts/pilot_ask_latency.py').summarize(cases, samples)
        out['latency'] = metrics
        out['trials'] = trial_table(cases, samples, metrics)
        out['reported_latency_matches'] = qualification.get('latency') == metrics
    out['stages'] = stage_distributions(events)
    return out


def pool(runs, samples):
    pooled = {}
    for kind in ('cold', 'warm'):
        chosen = [r for r in runs if r.get('effective_kind') == kind and 'latency' in r.get('summary', {})]
        entry = {'runs_counted': [r['index'] for r in chosen]}
        for profile in PROFILES:
            values, planned, ok, failed, incomplete = [], 0, 0, 0, 0
            for r in chosen:
                m = r['summary']['latency'][profile]
                planned += m['planned']; ok += m['successful']; failed += m['failed']; incomplete += m['incomplete']
                values += [t['decision_to_result_ms'] for t in r['summary']['trials'][profile]['continuation_ms_by_trial']
                           if t['passed'] and isinstance(t['decision_to_result_ms'], (int, float))]
            entry[profile] = {'planned': planned, 'successful': ok, 'failed': failed, 'incomplete': incomplete,
                              'continuation_ms': distribution(values), 'target_ms': 3000,
                              'p95_target_met': bool(values) and nearest_rank(values, .95) <= 3000 and failed == incomplete == 0}
        pooled[kind] = entry
    return pooled


def series_status(plan, runs, samples):
    if len(runs) != len(plan):
        return 'incomplete'
    for declared, run in zip(plan, runs):
        if run.get('effective_kind') != declared or run.get('validated') is not True:
            return 'incomplete'
        latency = run.get('summary', {}).get('latency')
        if not latency or any(latency[p]['successful'] != samples or latency[p]['failed'] or latency[p]['incomplete']
                              for p in PROFILES):
            return 'incomplete'
    return 'complete'


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    with tmp.open('w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write('\n')
    tmp.replace(path)


def execute(args):
    cmp = comparison()
    plan = parse_plan(args.plan)
    require = cmp.require
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'linux_x86_64_required')
    kind = platform_kind()
    root = ROOT
    output = args.output.absolute()
    private_root = args.private_root.absolute()
    require(not output.exists() and not private_root.exists(), 'fresh_output_and_private_directories_required')
    require(not output.is_relative_to(root) and not private_root.is_relative_to(root)
            and not private_root.is_relative_to(output) and not output.is_relative_to(private_root),
            'output_and_private_must_be_separate_and_outside_source')
    source_before = cmp.source(root, args.expected_commit)
    tools = {name: getattr(args, name).resolve(strict=True) for name in TOOLS}
    selected = {name: cmp.sha(path) for name, path in tools.items()}
    offline = args.offline_inputs.resolve(strict=True)
    require(offline.is_dir() and all((offline / p).exists() for p in ('npm-cache', 'wheelhouse', 'python.tar.gz')),
            'offline_preparation_required')
    if args.receipt:
        cmp.validate_build(cmp.json_file(args.receipt), source_before, selected)
    output.mkdir(mode=0o700, parents=True)
    private_root.mkdir(mode=0o700, parents=True)
    manifest = {'format': FORMAT, 'declared_at': now(), 'plan': plan, 'samples_per_profile': args.samples,
                'platform_kind': kind, 'kernel': platform.release(), 'machine': platform.machine(),
                'source': source_before, 'selected_sha256': selected, 'require_verified_reuse': args.require_verified_reuse,
                'cold_definition': 'page cache dropped with sync + drop_caches immediately before the run; unqualified when the drop cannot be shown',
                'warm_definition': 'run started right after the previous complete run, no cache drop',
                'wsl_note': 'results are labeled by platform_kind and never stand in for native Linux' if kind != 'native_linux' else None,
                'metric': 'operator_attempt_to_correlated_original_result_monotonic', 'target_ms': 3000}
    write_json(output / 'manifest.json', manifest)
    runs = []
    for index, declared in enumerate(plan):
        run_dir = output / 'runs' / ('%02d-%s' % (index + 1, declared))
        private = private_root / ('%02d-%s' % (index + 1, declared))
        run_dir.mkdir(mode=0o700, parents=True)
        private.mkdir(mode=0o700)
        record = {'index': index + 1, 'declared_kind': declared, 'effective_kind': declared, 'validated': False}
        cache = None
        if declared == 'cold':
            cache = drop_caches()
            record['cache_drop'] = cache
            if not cache['performed']:
                record['effective_kind'] = 'cold_unavailable'
        record['conditions_before'] = conditions()
        command = [sys.executable, '-B', str(args.qualifier), '--offline-inputs', str(offline),
                   '--output', str(run_dir / 'qualification'), '--approval-samples', str(args.samples)]
        if args.require_verified_reuse:
            command += ['--require-verified-reuse']
        for name, path in tools.items():
            command += ['--' + name.replace('_', '-'), str(path)]
        env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': 'C.UTF-8', 'HOME': str(private),
               'TMPDIR': str(private), 'PYTHONDONTWRITEBYTECODE': '1',
               'HTTP_PROXY': 'http://127.0.0.1:9', 'HTTPS_PROXY': 'http://127.0.0.1:9',
               'NO_PROXY': '127.0.0.1,localhost,::1'}
        events_path = run_dir / 'stage-events.jsonl'
        started = time.monotonic()
        exit_code, failure = 0, None
        with events_path.open('w') as sink:
            watcher = Watcher(str(private / '**' / '*.private'), sink)
            watcher.start()
            try:
                cmp.NATIVE.build(command, cwd=root, env=env, log=private / 'qualification.log',
                                 seconds=args.run_timeout, stage='series_' + str(index + 1))
            except cmp.NATIVE.Failure as error:
                exit_code, failure = error.exit_code, error.reason[:160]
            finally:
                watcher.finish()
        record.update(exit_code=exit_code, failure=failure, wall_seconds=round(time.monotonic() - started, 1),
                      conditions_after=conditions())
        qualification = None
        report = run_dir / 'qualification' / 'qualification.json'
        if report.is_file():
            try:
                qualification = cmp.json_file(report)
            except (ValueError, OSError) as error:
                record['failure'] = 'qualification_unreadable_' + type(error).__name__
        if qualification is not None:
            try:
                cmp.validate_report(qualification, source_before, selected, args.samples, args.require_verified_reuse)
                record['validated'] = True
            except (ValueError, KeyError, TypeError) as error:
                record['validation_error'] = str(error)[:160]
            record['summary'] = run_summary(qualification, args.samples, read_events(events_path))
        else:
            record['summary'] = {'stages': stage_distributions(read_events(events_path))}
            record.setdefault('failure', 'qualification_missing')
        runs.append(record)
        write_json(run_dir / 'run.json', record)
        if cmp.source(root, args.expected_commit) != source_before or any(cmp.sha(p) != selected[n] for n, p in tools.items()):
            record['validated'] = False
            record['validation_error'] = 'source_or_assets_changed_during_series'
            write_json(run_dir / 'run.json', record)
            break
    status = series_status(plan, runs, args.samples)
    summary = {'format': FORMAT, 'status': status, 'platform_kind': kind, 'plan': plan, 'runs_recorded': len(runs),
               'samples_per_profile': args.samples, 'source': source_before, 'pooled': pool(runs, args.samples),
               'runs': [{k: v for k, v in r.items() if k != 'summary'} | {'summary': r.get('summary')} for r in runs],
               'performance_blockers': [{'run': r['index'], 'kind': r['effective_kind'], 'profile': p, 'p95_ms': r['summary']['latency'][p]['p95_ms']}
                                       for r in runs if 'latency' in r.get('summary', {})
                                       for p in PROFILES if not r['summary']['latency'][p]['target_met']]}
    write_json(output / 'summary.json', summary)
    print(json.dumps({'status': status, 'runs': len(runs), 'blockers': len(summary['performance_blockers'])}))
    if status != 'complete':
        return 1
    return 2 if args.fail_on_blocker and summary['performance_blockers'] else 0


def summarize_existing(args):
    """Retroactive summary of already finished runs; labels are explicit, nothing is validated here."""
    rows = []
    for index, spec in enumerate(args.run, start=1):
        label, _, rest = spec.partition('=')
        kind, _, rest = rest.partition(':')
        path, _, events = rest.partition(':')
        qualification = json.loads(Path(path).read_text())
        record = {'index': index, 'label': label, 'declared_kind': kind, 'effective_kind': kind, 'validated': False,
                  'qualification_sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                  'summary': run_summary(qualification, args.samples, read_events(events) if events else [])}
        env_file = Path(path).parent.parent / ('env-before-' + label + '.txt')
        if env_file.is_file():
            record['conditions_before_text'] = env_file.read_text(errors='replace').splitlines()
        rows.append(record)
    out = {'format': FORMAT + '-retroactive', 'platform_kind': args.platform_kind, 'samples_per_profile': args.samples,
           'note': args.note, 'pooled': pool(rows, args.samples), 'runs': rows}
    write_json(args.output, out)
    print(json.dumps({'runs': len(rows)}))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    run = sub.add_parser('run')
    run.add_argument('--plan', required=True)
    run.add_argument('--samples', type=int, default=20, choices=range(20, 101))
    run.add_argument('--output', type=Path, required=True)
    run.add_argument('--private-root', type=Path, required=True)
    run.add_argument('--expected-commit', required=True)
    run.add_argument('--offline-inputs', type=Path, required=True)
    run.add_argument('--receipt', type=Path)
    run.add_argument('--require-verified-reuse', action='store_true')
    run.add_argument('--fail-on-blocker', action='store_true')
    run.add_argument('--run-timeout', type=int, default=3600)
    run.add_argument('--qualifier', type=Path, default=ROOT / 'scripts/qualify-pilot-ask.py', help=argparse.SUPPRESS)
    for name in TOOLS:
        run.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    old = sub.add_parser('summarize')
    old.add_argument('--run', action='append', required=True, help='label=kind:qualification.json[:events]')
    old.add_argument('--samples', type=int, default=20)
    old.add_argument('--platform-kind', required=True, choices=('wsl2', 'native_linux'))
    old.add_argument('--note', default='')
    old.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        return execute(args) if args.command == 'run' else summarize_existing(args)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'failed', 'error': str(error)[:160], 'error_type': type(error).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
