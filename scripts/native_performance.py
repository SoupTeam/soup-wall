#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-203 offline, source-bound comparison of retained native Ask performance reports.

Reads `sw-ask-series/1` series summaries (SOU-141, `scripts/qualify-ask-series.py`) and
their manifests, verifies what can be verified from local git objects, normalizes every
planned trial into `sw-native-performance-observation/1`, reproduces the published
aggregates from the retained per-trial values, and classifies a comparison as
`compatible`, `stratified-only`, `incomplete` or `non-comparable`.

It is read-only: no measurement is run, no producer is changed, no network is used.
It is not a security, protection, task-effectiveness or readiness qualification, and
it approves no budget. Percentiles are nearest rank, as in `pilot_ask_latency.py`.
No confidence interval is computed (see `inference`).
"""
from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
OBSERVATION = 'sw-native-performance-observation/1'
COMPARISON = 'sw-native-performance-comparison/1'
SERIES_FORMAT = 'sw-ask-series/1'
RETROACTIVE_FORMAT = 'sw-ask-series/1-retroactive'
RECEIPT_FORMAT = 'sw-native-pilot-agent-source-build/1'
LIMITS = {'report_bytes': 8 * 1024 * 1024, 'manifest_bytes': 64 * 1024, 'receipt_bytes': 1024 * 1024,
          'json_depth': 32, 'runs': 6, 'samples_per_profile': 100, 'trials': 1200,
          'output_bytes': 8 * 1024 * 1024, 'git_seconds': 60}
PROFILES = ('filesystem', 'git')
STATUSES = ('measured', 'failed', 'timed_out', 'incomplete', 'not_run')
LATENCY_METRIC = 'operator_attempt_to_correlated_original_result_monotonic'
CONTINUATION_TARGET_MS = 3000
PENDING_BOUND_MS = 5000
MIN_EFFECTIVE_CLUSTERS = 10  # DEC-SOU153-20261027 minimum; that approval does not cover performance
HARNESS = ('scripts/qualify-pilot-ask.py', 'scripts/pilot_ask_latency.py')
CONDITIONS = {'cold': 'post_cache_drop_setup_rewarmed', 'warm': 'warm',
              'cold_unavailable': 'cold_unavailable', 'undeclared': 'undeclared'}
STATUS_MAPPING = {
    'measured': 'trial row present, passed is true, finite non-negative decision_to_result_ms',
    'failed': 'trial row present, passed is not true (the producer counts it in `failed`)',
    'timed_out': 'no trial row, and the run failed with the series `series_<n>_timeout` reason',
    'incomplete': 'no trial row in a recorded run (the producer counts it in `incomplete`)',
    'not_run': 'the planned run was never recorded',
}
ENDPOINTS = {
    'continuation_ms': {
        'metric': LATENCY_METRIC, 'start': 'operator approval attempt', 'end': 'correlated original-server result',
        'clock': 'qualifier_harness_monotonic', 'observer': 'scripts/qualify-pilot-ask.py harness', 'unit': 'ms',
        'source_field': 'decision_to_result_ms', 'role': 'continuation engineering criterion (p95 <= 3000 ms)'},
    'first_pending_asset_verification_ms': {
        'metric': 'collector_pass_1_asset_verification_sum', 'start': 'collector pass-1 asset verification start',
        'end': 'pass-1 asset verification end, before the pending approval is published',
        'clock': 'collector_monotonic', 'observer': 'collector mcp_asset_verification_timing', 'unit': 'ms',
        'source_field': 'sum of pass-1 runtime_and_libraries, package_tree, selected_profile (same clock, sequential)',
        'role': 'lower bound of the operator-visible first-pending wait; never the 5 s pending measurement'},
    'post_observed_total_ms': {
        'metric': 'collector_post_observed_total', 'start': 'collector observation of the approval',
        'end': 'result inspection complete', 'clock': 'collector_monotonic',
        'observer': 'collector mcp_real_approval_timing', 'unit': 'ms', 'source_field': 'post_observed_ms',
        'role': 'internal verification after approval; never a substitute for continuation'},
}
STAGE_CLOCK = {'clock': 'collector_monotonic', 'unit': 'ms',
               'observer': 'collector mcp_asset_verification_timing / mcp_real_approval_timing'}
NOT_RETAINED = {
    'preparation_elapsed': 'qualifier setup is inside run wall_seconds only; no per-trial setup clock is retained',
    'first_observable_pending': 'host-visible pending time is measured by SOU-105 acceptance, not by this series',
    'cleanup': 'cleanup is inside run wall_seconds only',
    'external_build_time': 'not part of the series',
    'raw_stage_events': 'stage-events.jsonl is not retained; `stages` aggregates are reported, not reproduced',
    'trace_observed': 'the qualification report (and its actual strace mode) is not retained in the summary',
}
PERCENTILE = ('nearest rank: the value at rank ceil(q * n) of the ascending sample, unrounded '
              '(pilot_ask_latency.summarize). Published sw-ask-series/1 distributions round to 0.001 ms first; '
              'reproduction uses that producer convention.')
SCOPE = [
    'Engineering latency diagnostics for recorded native Ask series only.',
    'Not a security or protection qualification, not task effectiveness, not product or pilot readiness.',
    'Trace-on is the only observer mode of this producer; no trace-off result exists here, and none would '
    'qualify protection.',
    'The 3000 ms continuation p95 criterion and the 5000 ms first-pending bound are existing engineering '
    'criteria, reported separately; no new budget is approved.',
    'A same-report identity control proves the comparator, not a performance change between revisions.',
]


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SERIES = _load('ask_series_producer', 'scripts/qualify-ask-series.py')
LATENCY = _load('ask_latency_metrics', 'scripts/pilot_ask_latency.py')


class Rejected(Exception):
    """Invalid or contradicted evidence. Stable `code`; no comparison is produced."""

    def __init__(self, code, role, detail):
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', code):
            raise ValueError('static_reason_code_required')
        super().__init__(f'{code}: {detail}')
        self.code, self.role, self.detail = code, role, detail

    def as_dict(self):
        return {'code': self.code, 'role': self.role, 'detail': self.detail}


def require(ok, code, role, detail):
    if not ok:
        raise Rejected(code, role, detail)


# ------------------------------------------------------------------ bounded strict input

def read_bounded(path, limit, role):
    path = Path(path)
    try:
        info = os.lstat(path)
    except OSError as error:
        raise Rejected('unreadable_input', role, type(error).__name__) from None
    require(not stat.S_ISLNK(info.st_mode), 'symlink_input_refused', role, path.name)
    require(stat.S_ISREG(info.st_mode), 'regular_file_required', role, path.name)
    require(info.st_size <= limit, 'input_too_large', role, f'{info.st_size} bytes exceeds {limit}')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, 'rb') as stream:
            raw = stream.read(limit + 1)
    except OSError as error:
        raise Rejected('unreadable_input', role, type(error).__name__) from None
    require(len(raw) <= limit, 'input_too_large', role, 'file grew while reading')
    return raw


def parse_strict(raw, role):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate_json_key', role, key[:64])
            value[key] = item
        return value

    def constant(name):
        raise Rejected('nonfinite_number', role, name)
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique, parse_constant=constant)
    except UnicodeDecodeError:
        raise Rejected('malformed_json', role, 'invalid UTF-8') from None
    except RecursionError:
        raise Rejected('json_too_deep', role, 'recursion limit') from None
    except ValueError as error:
        raise Rejected('malformed_json', role, str(error)[:120]) from None
    pending = [(value, 1)]
    while pending:
        item, depth = pending.pop()
        require(depth <= LIMITS['json_depth'], 'json_too_deep', role, f'depth > {LIMITS["json_depth"]}')
        if isinstance(item, float):
            require(math.isfinite(item), 'nonfinite_number', role, 'overflowing literal')
        elif isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    require(isinstance(value, dict), 'json_object_required', role, type(value).__name__)
    return value


def portable_name(path):
    """Repository-relative POSIX path when inside the repository, otherwise the basename."""
    try:
        return Path(path).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return Path(path).name


# ------------------------------------------------------------------ git witnesses (local, offline)

class Git:
    """Read-only local git object access. Missing git or objects is `unverified`, never a pass."""

    def __init__(self, repository):
        self.repository = Path(repository)
        self.cache = {}

    def run(self, *words, data=None):
        try:
            result = subprocess.run(['git', '-C', str(self.repository), *words], input=data,
                                    capture_output=True, timeout=LIMITS['git_seconds'], check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        return result.stdout if result.returncode == 0 else None

    def blob_commit(self, data):
        """The first commit on HEAD that introduced exactly these bytes, or None."""
        oid = hashlib.sha1(b'blob %d\0' % len(data) + data).hexdigest()
        if self.run('cat-file', '-e', oid) is None:
            return oid, None
        found = self.run('log', '--format=%H', '--find-object=' + oid, 'HEAD')
        commits = found.decode().split() if found else []
        return oid, (commits[-1] if commits else None)

    def tree_of(self, commit):
        out = self.run('rev-parse', '--verify', '--quiet', commit + '^{tree}')
        return out.decode().strip() if out else None

    def files_sha256(self, commit):
        """Recompute `qualify-pilot-ask-comparison.source()` files_sha256 from committed blobs."""
        if ('files', commit) in self.cache:
            return self.cache[('files', commit)]
        listing = self.run('ls-tree', '-r', '-z', '--full-tree', commit)
        if listing is None:
            return None
        entries = []
        for record in listing.split(b'\0'):
            if record:
                meta, name = record.split(b'\t', 1)
                mode, kind, oid = meta.split()
                if kind == b'blob':
                    entries.append((os.fsdecode(name), mode, oid.decode()))
        if any(mode == b'120000' for _, mode, _ in entries):
            return None  # a tracked symlink is hashed through its target by the producer; not reproducible here
        blobs = self.blobs([oid for _, _, oid in entries])
        if blobs is None:
            return None
        files = {name: hashlib.sha256(blobs[oid]).hexdigest() for name, _, oid in entries}
        value = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                                          allow_nan=False).encode()).hexdigest()
        self.cache[('files', commit)] = value
        return value

    def blobs(self, oids):
        out = self.run('cat-file', '--batch', data=''.join(o + '\n' for o in oids).encode())
        if out is None:
            return None
        found, offset = {}, 0
        for oid in oids:
            end = out.index(b'\n', offset)
            header = out[offset:end].split()
            if len(header) != 3 or header[1] != b'blob':
                return None
            size = int(header[2])
            found[oid] = out[end + 1:end + 1 + size]
            offset = end + 2 + size
        return found

    def file_sha256(self, commit, name):
        out = self.run('cat-file', 'blob', f'{commit}:{name}')
        return hashlib.sha256(out).hexdigest() if out is not None else None


def custody(raw, git, role):
    """Original-artifact digest. A CRLF checkout copy is accepted only when its LF bytes are a committed blob."""
    candidates = [('none', raw)]
    if b'\r\n' in raw:
        candidates.append(('crlf_to_lf_checkout', raw.replace(b'\r\n', b'\n')))
    for normalization, data in candidates:
        oid, commit = git.blob_commit(data)
        if commit:
            return data, {'status': 'committed_blob', 'git_blob': oid, 'introduced_by': commit,
                          'normalization': normalization, 'original_sha256': hashlib.sha256(data).hexdigest(),
                          'bytes': len(data), 'method': 'local git object store: blob id of the bytes read'}
    return raw, {'status': 'unverified_not_in_repository_history', 'git_blob': None, 'introduced_by': None,
                 'normalization': 'none', 'original_sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
                 'method': 'none: the bytes are not a committed blob reachable from HEAD'}


def verify_source(source, git, role):
    require(isinstance(source, dict), 'source_identity_missing', role, 'source')
    commit, tree, files = source.get('commit'), source.get('tree'), source.get('files_sha256')
    require(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}', commit)
            and isinstance(tree, str) and re.fullmatch('[0-9a-f]{40}', tree)
            and isinstance(files, str) and re.fullmatch('[0-9a-f]{64}', files),
            'source_identity_malformed', role, 'full commit, tree and files_sha256 required')
    require(source.get('dirty') is False, 'source_dirty', role, 'source.dirty must be false')
    actual_tree = git.tree_of(commit)
    if actual_tree is None:
        return {'status': 'unverified_commit_not_in_repository', 'commit': commit, 'tree': tree,
                'files_sha256': files, 'method': None}
    require(actual_tree == tree, 'source_identity_contradiction', role, 'source.tree differs from git commit tree')
    recomputed = git.files_sha256(commit)
    if recomputed is None:
        return {'status': 'commit_tree_verified_files_unverified', 'commit': commit, 'tree': tree,
                'files_sha256': files, 'method': 'git rev-parse <commit>^{tree}'}
    require(recomputed == files, 'source_identity_contradiction', role,
            'source.files_sha256 differs from the committed blobs')
    return {'status': 'verified_git_objects', 'commit': commit, 'tree': tree, 'files_sha256': files,
            'method': 'git commit tree equality and files_sha256 recomputed from every committed blob'}


# ------------------------------------------------------------------ sw-ask-series/1 adapter

def _plain(value, kind):
    return type(value) is kind


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def _mismatch(published, recomputed, path=''):
    """First path where a published value is absent from, or differs from, the recomputation."""
    if isinstance(published, dict) and isinstance(recomputed, dict):
        for key in sorted(published):
            if key not in recomputed:
                return f'{path}.{key}'.lstrip('.') + ' (unreproducible field)'
            found = _mismatch(published[key], recomputed[key], f'{path}.{key}')
            if found:
                return found
        return None
    if isinstance(published, list) and isinstance(recomputed, list):
        if len(published) != len(recomputed):
            return f'{path} (length)'.lstrip('.')
        for index, (a, b) in enumerate(zip(published, recomputed)):
            found = _mismatch(a, b, f'{path}[{index}]')
            if found:
                return found
        return None
    if type(published) is not type(recomputed) and not (_number(published) and _number(recomputed)):
        return path.lstrip('.') + ' (type)'
    return None if published == recomputed else path.lstrip('.')


def _check(published, recomputed, role, path):
    found = _mismatch(published, recomputed, path)
    require(found is None, 'published_distribution_not_reproduced', role, found or path)


nearest_rank = SERIES.nearest_rank  # accepted SOU-141 primitive: rank ceil(q * n), unrounded


def latency_from_trials(rows, samples):
    """`pilot_ask_latency.summarize` fields recomputed from the retained per-trial table."""
    measured = sorted(r['decision_to_result_ms'] for r in rows if r['passed'] is True
                      and _number(r['decision_to_result_ms']) and r['decision_to_result_ms'] >= 0)
    failed, incomplete = len(rows) - len(measured), samples - len(rows)
    p95 = nearest_rank(measured, .95)
    return {'planned': samples, 'successful': len(measured), 'failed': failed, 'incomplete': incomplete,
            'p50_ms': nearest_rank(measured, .5), 'p95_ms': p95, 'metric': LATENCY_METRIC,
            'target_ms': CONTINUATION_TARGET_MS,
            'target_met': failed == incomplete == 0 and p95 is not None and p95 <= CONTINUATION_TARGET_MS}


def _cache_drop_shown(drop):
    """The producer's `drop_caches` success predicate, re-evaluated on the retained record."""
    before, after = drop.get('cached_kb_before'), drop.get('cached_kb_after')
    return (drop.get('requested') is True and drop.get('error') is None and _plain(before, int)
            and _plain(after, int) and (after < before or after < 262144))


def _run_conditions(run):
    found = {}
    for when in ('conditions_before', 'conditions_after'):
        value = run.get(when)
        if isinstance(value, dict):
            mem = value.get('meminfo') if isinstance(value.get('meminfo'), dict) else {}
            pressure = value.get('pressure') if isinstance(value.get('pressure'), dict) else {}
            found[when] = {'cpu_count': value.get('cpu_count'), 'mem_total_kb': mem.get('MemTotal_kb'),
                           'cached_kb': mem.get('Cached_kb'), 'loadavg': value.get('loadavg'),
                           'cpu_pressure': pressure.get('cpu')}
    return found


def _trial_rows(run, profile, samples, role, index):
    table = run.get('summary', {}).get('trials', {}).get(profile)
    if table is None:
        return [], []
    rows, reuse = table.get('continuation_ms_by_trial'), table.get('reuse')
    require(isinstance(rows, list) and isinstance(reuse, list) and len(rows) == len(reuse),
            'trial_table_malformed', role, f'runs[{index}].{profile}')
    require(len(rows) <= samples, 'unexpected_trial_id', role, f'runs[{index}].{profile}: more rows than planned')
    seen = set()
    for row in rows:
        require(isinstance(row, dict) and set(row) == {'sample_index', 'passed', 'decision_to_result_ms'},
                'trial_table_malformed', role, f'runs[{index}].{profile}')
        sample = row['sample_index']
        require(_plain(sample, int) and 0 <= sample < samples, 'unexpected_trial_id', role,
                f'runs[{index}].{profile}.sample_index={sample!r}')
        require(sample not in seen, 'duplicate_trial_id', role, f'runs[{index}].{profile}.sample_index={sample}')
        seen.add(sample)
        require(_plain(row['passed'], bool), 'trial_table_malformed', role, 'passed must be boolean')
        value = row['decision_to_result_ms']
        if row['passed']:
            require(_number(value), 'nonfinite_or_missing_duration', role,
                    f'runs[{index}].{profile}[{sample}] passed without a finite duration')
            require(value >= 0, 'negative_duration', role, f'runs[{index}].{profile}[{sample}]')
    require([r['sample_index'] for r in rows] == sorted(seen), 'trial_order_invalid', role, f'runs[{index}].{profile}')
    return rows, reuse


def normalize(role, summary_path, manifest_path=None, receipt_path=None, git=None):
    """Read one retained series (+ manifest, + optional build receipt) into the observation contract."""
    try:
        return _normalize(role, summary_path, manifest_path, receipt_path, git or Git(ROOT))
    except (KeyError, TypeError, AttributeError, IndexError, ValueError) as error:
        if isinstance(error, Rejected):
            raise
        # Structurally malformed evidence is a stable rejection, never a partial comparison.
        raise Rejected('report_shape_invalid', role, type(error).__name__) from None


def _normalize(role, summary_path, manifest_path, receipt_path, git):
    raw = read_bounded(summary_path, LIMITS['report_bytes'], role)
    data, held = custody(raw, git, role)
    summary = parse_strict(data, role)
    fmt = summary.get('format')
    require(fmt in (SERIES_FORMAT, RETROACTIVE_FORMAT), 'unsupported_report_format', role, repr(fmt)[:64])
    retroactive = fmt == RETROACTIVE_FORMAT
    samples = summary.get('samples_per_profile')
    require(_plain(samples, int) and 20 <= samples <= LIMITS['samples_per_profile'], 'sample_plan_invalid', role,
            'samples_per_profile')
    runs = summary.get('runs')
    require(isinstance(runs, list) and 1 <= len(runs) <= LIMITS['runs'], 'run_list_invalid', role, 'runs')
    plan = summary.get('plan') if not retroactive else [r.get('declared_kind') for r in runs]
    require(isinstance(plan, list) and len(runs) <= len(plan) <= LIMITS['runs'], 'run_list_invalid', role, 'plan')
    require(len(plan) * len(PROFILES) * samples <= LIMITS['trials'], 'trial_limit_exceeded', role, 'plan')
    platform_kind = summary.get('platform_kind')
    require(isinstance(platform_kind, str) and platform_kind, 'environment_missing', role, 'platform_kind')
    if not retroactive:
        require(summary.get('runs_recorded') == len(runs), 'run_list_invalid', role, 'runs_recorded')
        require(all(k in ('cold', 'warm') for k in plan) and plan[0] == 'cold', 'run_list_invalid', role, 'plan')

    manifest = manifest_held = None
    if manifest_path is not None:
        manifest_raw = read_bounded(manifest_path, LIMITS['manifest_bytes'], role + '_manifest')
        manifest_data, manifest_held = custody(manifest_raw, git, role + '_manifest')
        manifest = parse_strict(manifest_data, role + '_manifest')
        for key in ('format', 'plan', 'samples_per_profile', 'platform_kind', 'source'):
            require(manifest.get(key) == summary.get(key), 'manifest_summary_mismatch', role, key)
        require(manifest.get('metric') == LATENCY_METRIC, 'endpoint_substitution', role, 'manifest.metric')
        require(manifest.get('target_ms') == CONTINUATION_TARGET_MS, 'manifest_summary_mismatch', role, 'target_ms')
        require(manifest.get('cold_ask_trials_claimed', False) is False, 'true_cold_claim_unsupported', role,
                'the producer re-reads inputs before every timed trial; no cold Ask trial can be claimed')
        selected = manifest.get('selected_sha256')
        require(isinstance(selected, dict) and set(selected) == set(SERIES.TOOLS)
                and all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in selected.values()),
                'invalid_digest', role, 'manifest.selected_sha256')

    source = None
    if not retroactive:
        source = verify_source(summary.get('source'), git, role)
    harness = None
    if source and source['status'] != 'unverified_commit_not_in_repository':
        harness = {name: git.file_sha256(source['commit'], name) for name in HARNESS}

    build = {'status': 'not_retained', 'profile': None, 'receipt_sha256': None,
             'detail': 'no sw-native-pilot-agent-source-build/1 receipt was supplied'}
    binaries = {'status': 'unavailable', 'sha256': None}
    if manifest is not None:
        binaries = {'status': 'declared_only', 'sha256': manifest['selected_sha256'],
                    'detail': 'manifest self-declaration; the binaries are not retained'}
    if receipt_path is not None:
        require(manifest is not None, 'build_receipt_needs_manifest', role, 'receipt binds manifest digests')
        receipt_raw = read_bounded(receipt_path, LIMITS['receipt_bytes'], role + '_receipt')
        receipt = parse_strict(receipt_raw, role + '_receipt')
        require(receipt.get('format') == RECEIPT_FORMAT, 'unsupported_report_format', role + '_receipt',
                repr(receipt.get('format'))[:64])
        require(receipt.get('source') == summary.get('source'), 'build_receipt_binding_mismatch', role, 'source')
        for name in ('agentfw', 'git_launcher'):
            entry = receipt.get('binaries', {}).get(name)
            require(isinstance(entry, dict) and entry.get('sha256') == manifest['selected_sha256'][name],
                    'build_receipt_binding_mismatch', role, f'binaries.{name}')
        commands = receipt.get('commands')
        require(isinstance(commands, list) and commands and all(isinstance(c, list) for c in commands),
                'build_receipt_binding_mismatch', role, 'commands')
        build_command = next((c for c in commands if len(c) > 1 and c[1] == 'build'), None)
        require(build_command is not None, 'build_receipt_binding_mismatch', role, 'no cargo build command')
        profile = 'release' if '--release' in build_command else 'dev'
        if '--profile' in build_command:
            position = build_command.index('--profile') + 1
            require(position < len(build_command), 'build_receipt_binding_mismatch', role, '--profile')
            profile = build_command[position]
        build = {'status': 'receipt_bound', 'profile': profile,
                 'receipt_sha256': hashlib.sha256(receipt_raw).hexdigest(),
                 'detail': 'cargo profile from the receipt build command; receipt source and agentfw/git_launcher '
                           'digests equal the summary source and manifest'}
        binaries = dict(binaries, status='receipt_bound',
                        detail='agentfw and git_launcher bound by the build receipt; other tools manifest-declared')

    trials, run_records, cases_by_run = [], [], {}
    trace_basis = []
    for position, run in enumerate(runs):
        require(isinstance(run, dict) and run.get('index') == position + 1, 'run_list_invalid', role,
                f'runs[{position}].index')
        declared, effective = run.get('declared_kind'), run.get('effective_kind')
        require(declared == plan[position], 'run_list_invalid', role, f'runs[{position}].declared_kind')
        if retroactive:
            require(run.get('validated') is False, 'run_list_invalid', role, 'retroactive runs are unvalidated')
            require(effective == declared and effective in CONDITIONS, 'run_list_invalid', role,
                    f'runs[{position}].effective_kind')
            qualified, reason = False, 'retroactive_unvalidated'
        else:
            require(effective == declared or (declared == 'cold' and effective == 'cold_unavailable'),
                    'run_list_invalid', role, f'runs[{position}].effective_kind')
            require(_plain(run.get('exit_code'), int) and _plain(run.get('validated'), bool)
                    and (run.get('failure') is None or isinstance(run.get('failure'), str)),
                    'run_list_invalid', role, f'runs[{position}] execution fields')
            if declared == 'cold':
                drop = run.get('cache_drop')
                require(isinstance(drop, dict), 'cold_evidence_missing', role, f'runs[{position}].cache_drop')
                shown = _cache_drop_shown(drop)
                require(shown == (effective == 'cold') and drop.get('performed') is shown,
                        'cold_evidence_contradiction', role, f'runs[{position}].cache_drop vs effective_kind')
                require(run.get('cold_scope') in (None, 'pre_run_cache_drop_only_setup_rewarmed'),
                        'true_cold_claim_unsupported', role, f'runs[{position}].cold_scope')
            reason = SERIES.disqualification(run)
            qualified = reason is None
            if qualified:
                trace_basis.append(run['index'])
        timed_out = isinstance(run.get('failure'), str) and re.match(r'series_\d+_timeout', run['failure'])
        # A retroactive summary records no cache drop, so its declared kind stays unverified.
        condition = ('declared_%s_unverified' % effective if retroactive and effective != 'undeclared'
                     else CONDITIONS[effective])
        cases = []
        for profile in PROFILES:
            rows, reuse = _trial_rows(run, profile, samples, role, position)
            if qualified:
                require(len(rows) == samples, 'missing_required_trial', role,
                        f'runs[{position}].{profile}: {len(rows)} of {samples} rows in a qualified run')
            if 'latency' in run.get('summary', {}):
                _check(run['summary']['latency'][profile], latency_from_trials(rows, samples), role,
                       f'runs[{position}].summary.latency.{profile}')
            elif rows:
                raise Rejected('published_distribution_not_reproduced', role, f'runs[{position}].summary.latency')
            by_index = {r['sample_index']: (r, proof) for r, proof in zip(rows, reuse)}
            for sample in range(samples):
                row, proof = by_index.get(sample, (None, None))
                if row is not None:
                    cases.append({'case': 'approve', 'profile': profile, 'sample_index': sample,
                                  'passed': row['passed'], 'decision_to_result_ms': row['decision_to_result_ms'],
                                  'verified_inputs_resume': proof})
                    status = 'measured' if row['passed'] else 'failed'
                    why = None if row['passed'] else 'producer_trial_failed'
                else:
                    status = 'timed_out' if timed_out else 'incomplete'
                    why = 'run_timeout' if timed_out else 'trial_not_recorded'
                trials.append({'id': f'r{position + 1:02d}/{profile}/{sample:03d}', 'run': position + 1,
                               'profile': profile, 'sample_index': sample, 'condition': condition,
                               'run_qualified': qualified, 'status': status, 'reason': why,
                               'endpoints': {'continuation_ms': row['decision_to_result_ms']
                                             if status == 'measured' else None,
                                             'first_pending_asset_verification_ms': None,
                                             'post_observed_total_ms': None},
                               'stages': {}})
        if 'diagnostic_samples' in run.get('summary', {}):
            recomputed = SERIES.diagnostic_samples(cases)
            published = run['summary']['diagnostic_samples']
            require(isinstance(published, list) and all(isinstance(s, dict) for s in published),
                    'trial_table_malformed', role, f'runs[{position}].summary.diagnostic_samples')
            # The producer keeps its qualification case order; compare by trial identity, not position.
            order = lambda s: (str(s.get('profile')), s.get('sample_index') if _plain(s.get('sample_index'), int) else -1)
            _check(sorted(published, key=order), sorted(recomputed, key=order), role,
                   f'runs[{position}].summary.diagnostic_samples')
            _check(run['summary']['diagnostics'], SERIES.diagnostic_distributions(recomputed), role,
                   f'runs[{position}].summary.diagnostics')
            index = {(t['profile'], t['sample_index']): t for t in trials if t['run'] == position + 1}
            for sample in recomputed:
                trial = index[(sample['profile'], sample['sample_index'])]
                pending, post = sample['first_pending_asset_verification_ms'], sample['post_observed_ms']
                continuation = trial['endpoints']['continuation_ms']
                require(continuation is None or (continuation != pending and continuation != post),
                        'endpoint_substitution', role, f'{trial["id"]}: continuation equals a collector endpoint')
                trial['endpoints'].update(first_pending_asset_verification_ms=pending, post_observed_total_ms=post)
                trial['stages'] = {**{'asset/' + k: v for k, v in sorted(sample['assets_ms'].items())},
                                   **{'approval/' + k: v for k, v in sorted(sample['approval_stage_ms'].items())}}
        cases_by_run[position + 1] = cases
        run_records.append({'index': position + 1, 'declared_kind': declared, 'condition': condition,
                            'qualified': qualified, 'disqualification': reason,
                            'exit_code': run.get('exit_code'), 'failure': run.get('failure'),
                            'wall_seconds': run.get('wall_seconds'), 'cache_drop': run.get('cache_drop'),
                            'conditions': _run_conditions(run)})
    for position in range(len(runs), len(plan)):
        for profile in PROFILES:
            for sample in range(samples):
                trials.append({'id': f'r{position + 1:02d}/{profile}/{sample:03d}', 'run': position + 1,
                               'profile': profile, 'sample_index': sample,
                               'condition': CONDITIONS[plan[position]], 'run_qualified': False,
                               'status': 'not_run', 'reason': 'run_not_recorded',
                               'endpoints': dict.fromkeys(ENDPOINTS), 'stages': {}})
        run_records.append({'index': position + 1, 'declared_kind': plan[position],
                            'condition': CONDITIONS[plan[position]], 'qualified': False,
                            'disqualification': 'not_run', 'exit_code': None, 'failure': None,
                            'wall_seconds': None, 'cache_drop': None, 'conditions': {}})

    reproduced = ['runs[].summary.latency']
    if not retroactive:
        published_runs = [r for r in runs if 'summary' in r]
        _check(summary.get('pooled'), SERIES.pool(published_runs, samples), role, 'pooled')
        _check(summary.get('status'), SERIES.series_status(plan, runs, samples), role, 'status')
        blockers = [{'run': r['index'], 'kind': r['effective_kind'], 'profile': p,
                     'p95_ms': r['summary']['latency'][p]['p95_ms']}
                    for r in runs if 'latency' in r.get('summary', {})
                    for p in PROFILES if not r['summary']['latency'][p]['target_met']]
        _check(summary.get('performance_blockers'), blockers, role, 'performance_blockers')
        reproduced += ['pooled', 'status', 'performance_blockers']
        if 'attempts' in summary:
            _check(summary['attempts'], SERIES.attempt_ledger(plan, runs), role, 'attempts')
            reproduced.append('attempts')
        if any('diagnostic_samples' in r.get('summary', {}) for r in runs):
            reproduced += ['runs[].summary.diagnostic_samples', 'runs[].summary.diagnostics']
    else:
        _check(summary.get('pooled'), SERIES.pool(runs, samples, qualified_only=False), role, 'pooled')
        reproduced.append('pooled')
    conditions = [r['conditions'].get('conditions_before', {}) for r in run_records if r['conditions']]
    environment = {
        'platform_kind': platform_kind,
        'kernel': manifest.get('kernel') if manifest else None,
        'machine': manifest.get('machine') if manifest else None,
        'cpu_count': sorted({c.get('cpu_count') for c in conditions if c.get('cpu_count') is not None}),
        'mem_total_kb': sorted({c.get('mem_total_kb') for c in conditions if c.get('mem_total_kb') is not None}),
        'host_instance': {'status': 'not_retained',
                          'detail': 'all runs of one series ran in one dispatch; the runner instance is not recorded'},
    }
    evidence = [held['original_sha256'], manifest_held and manifest_held['original_sha256'], build['receipt_sha256']]
    observation = {
        'contract': OBSERVATION,
        'role': role,
        'input': {'name': portable_name(summary_path), 'producer': 'scripts/qualify-ask-series.py',
                  'evidence_sha256': hashlib.sha256(json.dumps(evidence).encode()).hexdigest(),
                  'producer_format': fmt, 'custody': held,
                  'manifest': None if manifest is None else {'name': portable_name(manifest_path),
                                                             'custody': manifest_held,
                                                             'declared_at': manifest.get('declared_at')}},
        'provenance': {
            'source': source or {'status': 'unavailable', 'detail': 'retroactive summaries carry no source'},
            'binaries': binaries, 'build': build,
            'workload': {'definition': 'qualify-pilot-ask.py --approval-samples N, approve case, profiles '
                                       + ','.join(PROFILES),
                         'harness_sha256_at_source': harness,
                         'status': 'verified_git_objects' if harness and all(harness.values()) else 'unverified'},
            'profiles_and_policy': {'status': 'bound_via_source_tree' if source and source['status'] ==
                                    'verified_git_objects' else 'unverified',
                                    'detail': 'profiles/ and policies are tracked files under source.files_sha256'},
        },
        'environment': environment,
        'trace': {'requested': LATENCY.trace_request() if trace_basis else None,
                  'requested_basis': ('the producer accepted only qualification reports whose trace_requested equals '
                                      'this value (validate_report); qualified runs '
                                      + str(trace_basis)) if trace_basis else 'unverified: no validated run',
                  'observed': 'not_retained'},
        'endpoints': copy.deepcopy(ENDPOINTS), 'stage_clock': dict(STAGE_CLOCK), 'not_retained': dict(NOT_RETAINED),
        'design': {'plan': plan, 'samples_per_profile': samples, 'profiles': list(PROFILES),
                   'pairing_design': None, 'cluster_unit': 'run (one qualifier process per run)',
                   'host_unit': 'one dispatch / runner per report'},
        'status_mapping': dict(STATUS_MAPPING),
        'runs': run_records,
        'trials': trials,
        'reproduction': {'status': 'reproduced_from_retained_trials', 'checked': reproduced,
                         'not_reproduced': ['runs[].summary.stages (raw stage-events.jsonl not retained)']},
    }
    return observation


# ------------------------------------------------------------------ statistics (pure)

def describe(values):
    """n, nearest-rank p50/p95 on unrounded values, min and max; never drops an observation."""
    ordered = sorted(values)
    return {'n': len(ordered), 'p50': nearest_rank(ordered, .5), 'p95': nearest_rank(ordered, .95),
            'min': ordered[0] if ordered else None, 'max': ordered[-1] if ordered else None}


def stratum_side(observation, key):
    profile, condition = key
    rows = [t for t in observation['trials'] if t['profile'] == profile and t['condition'] == condition]
    included = [t for t in rows if t['run_qualified']]
    counts = {s: sum(t['status'] == s for t in included) for s in STATUSES}
    measured = [t for t in included if t['status'] == 'measured']
    runs = sorted({t['run'] for t in included})
    continuation = [t['endpoints']['continuation_ms'] for t in measured]
    highest = sorted(measured, key=lambda t: (-t['endpoints']['continuation_ms'], t['id']))[:3]
    stages = {}
    for t in measured:
        for name, value in t['stages'].items():
            stages.setdefault(name, []).append(value)
    pending = [t['endpoints']['first_pending_asset_verification_ms'] for t in measured
               if t['endpoints']['first_pending_asset_verification_ms'] is not None]
    post = [t['endpoints']['post_observed_total_ms'] for t in measured
            if t['endpoints']['post_observed_total_ms'] is not None]
    complete = bool(included) and counts['measured'] == len(included)
    dist = describe(continuation)
    if not complete or dist['p95'] is None:
        target = 'not_evaluable_incomplete_denominator' if included else 'not_evaluable_no_qualified_run'
    else:
        target = 'met' if dist['p95'] <= CONTINUATION_TARGET_MS else 'not_met'
    return {
        'planned': len(rows), 'qualified_run_trials': len(included),
        'attempted': sum(t['status'] != 'not_run' for t in rows),
        'status_counts_all_runs': {s: sum(t['status'] == s for t in rows) for s in STATUSES},
        'excluded_unqualified_run_trials': len(rows) - len(included),
        'excluded_runs': sorted({t['run'] for t in rows if not t['run_qualified']}),
        'status_counts': counts, 'complete_denominator': complete,
        'runs': runs, 'independent_clusters': len(runs),
        'continuation_ms': dist,
        'continuation_highest': [{'trial': t['id'], 'ms': t['endpoints']['continuation_ms']} for t in highest],
        'continuation_by_run': {str(r): describe([t['endpoints']['continuation_ms'] for t in measured
                                                  if t['run'] == r]) for r in runs},
        'first_trial_per_run_ms': [{'trial': t['id'], 'ms': t['endpoints']['continuation_ms']}
                                   for t in measured if t['sample_index'] == 0],
        'first_pending_asset_verification_ms': describe(pending),
        'post_observed_total_ms': describe(post),
        'stages_ms': {name: describe(values) for name, values in sorted(stages.items())},
        'engineering_targets': {
            'continuation_p95_le_3000_ms': target,
            'first_pending_le_5000_ms': 'not_evaluated_by_this_evidence (SOU-105 acceptance owns it); '
                                        'collector lower-bound max ' + (f'{max(pending):.3f} ms' if pending else 'n/a'),
        },
    }


def strata_keys(observation):
    return sorted({(t['profile'], t['condition']) for t in observation['trials']})


# ------------------------------------------------------------------ compatibility

def _reason(code, dimension, fields, detail):
    return {'code': code, 'dimension': dimension, 'fields': fields, 'detail': detail}


def dimensions(base, cand):
    """Global compatibility dimensions: `match`, `differs_allowed`, `contradiction` or `unverified`."""
    # Identity control only for the same summary, manifest and receipt bytes (input.evidence_sha256).
    identity = base['input']['evidence_sha256'] == cand['input']['evidence_sha256']
    found = []

    def add(name, status, fields, code=None, detail=None, values=None):
        found.append({'dimension': name, 'status': status, 'fields': fields, 'code': code, 'detail': detail,
                      'baseline': None if values is None else values[0],
                      'candidate': None if values is None else values[1]})

    def pick(observation, path):
        value = observation
        for part in path.split('.'):
            value = value.get(part) if isinstance(value, dict) else None
        return value

    def equal(name, path, code, detail='differs'):
        a, b = pick(base, path), pick(cand, path)
        if a is None or b is None or a == [] or b == []:
            add(name, 'unverified', [path], name + '_unverified', 'not retained on one side', (a, b))
        elif a != b:
            add(name, 'contradiction', [path], code, detail, (a, b))
        else:
            add(name, 'match', [path], values=(a, b))

    add('evidence_identity', 'match' if identity else 'differs_allowed', ['input.evidence_sha256'],
        values=(base['input']['evidence_sha256'], cand['input']['evidence_sha256']))
    for side in (base, cand):
        if side['input']['custody']['status'] != 'committed_blob':
            add('custody', 'unverified', ['input.custody'], 'custody_unverified', side['role'] + ' original bytes '
                'are not a committed blob')
    if base['input']['producer_format'] != cand['input']['producer_format']:
        add('producer_format', 'contradiction', ['input.producer_format'], 'producer_format_mismatch', 'differs',
            (base['input']['producer_format'], cand['input']['producer_format']))
    for name, path in (('platform', 'environment.platform_kind'), ('kernel', 'environment.kernel'),
                       ('machine', 'environment.machine')):
        equal(name, path, 'environment_mismatch')
    # Any difference is verified evidence of different host instances; no tolerance is approved.
    for name, path in (('cpu_count', 'environment.cpu_count'), ('memory', 'environment.mem_total_kb')):
        equal(name, path, 'host_environment_differs', 'differs: the runs did not share one host')
    hosts = [side['environment']['host_instance'] for side in (base, cand)]
    if identity:
        add('host_instance', 'match', ['environment.host_instance'], detail='same original evidence')
    elif all(h.get('status') == 'verified' for h in hosts):
        same = hosts[0].get('id') == hosts[1].get('id')
        add('host_instance', 'match' if same else 'contradiction', ['environment.host_instance.id'],
            None if same else 'host_instance_mismatch', None if same else 'different verified hosts',
            (hosts[0].get('id'), hosts[1].get('id')))
    else:
        add('host_instance', 'unverified', ['environment.host_instance'], 'host_instance_unverified',
            'neither report retains its host instance; same-host conditions cannot be established')
    for name in ENDPOINTS:
        a, b = base['endpoints'].get(name), cand['endpoints'].get(name)
        if a != b:
            code = 'unit_mismatch' if a and b and a.get('unit') != b.get('unit') else 'endpoint_mismatch'
            add('endpoint:' + name, 'contradiction', ['endpoints.' + name], code, 'endpoint definition differs', (a, b))
    if base['stage_clock'] != cand['stage_clock']:
        add('stage_clock', 'contradiction', ['stage_clock'],
            'unit_mismatch' if base['stage_clock'].get('unit') != cand['stage_clock'].get('unit')
            else 'endpoint_mismatch', 'stage clock differs', (base['stage_clock'], cand['stage_clock']))
    for side in (base, cand):
        trace = side['trace']
        if trace['requested'] is not None and trace['observed'] not in ('not_retained', trace['requested']):
            raise Rejected('trace_state_contradiction', side['role'], 'observed trace differs from requested')
    equal('trace_requested', 'trace.requested', 'trace_state_mismatch')
    equal('design', 'design.samples_per_profile', 'trial_design_mismatch')
    if base['design']['profiles'] != cand['design']['profiles']:
        add('profiles', 'contradiction', ['design.profiles'], 'trial_design_mismatch', 'differs',
            (base['design']['profiles'], cand['design']['profiles']))
    if identity:
        for name in ('source', 'binaries', 'build', 'workload'):
            add(name, 'match', ['provenance.' + name], detail='same original evidence')
        return identity, found
    a, b = base['provenance'], cand['provenance']
    for name in ('source', 'workload'):
        if a[name]['status'] != 'verified_git_objects' or b[name]['status'] != 'verified_git_objects':
            add(name, 'unverified', ['provenance.' + name + '.status'], name + '_unverified',
                'independent verification unavailable', (a[name]['status'], b[name]['status']))
    if a['workload']['status'] == b['workload']['status'] == 'verified_git_objects':
        if a['workload']['harness_sha256_at_source'] != b['workload']['harness_sha256_at_source']:
            add('workload', 'contradiction', ['provenance.workload.harness_sha256_at_source'],
                'workload_or_harness_changed', 'measurement harness differs between sources',
                (a['workload']['harness_sha256_at_source'], b['workload']['harness_sha256_at_source']))
        else:
            add('workload', 'match', ['provenance.workload.harness_sha256_at_source'])
    if a['source']['status'] == b['source']['status'] == 'verified_git_objects':
        same = a['source']['commit'] == b['source']['commit']
        add('source', 'match' if same else 'differs_allowed', ['provenance.source.commit'],
            None if same else 'source_revision_differs', None if same else 'compared revisions (verified)',
            (a['source']['commit'], b['source']['commit']))
    if a['build']['status'] == b['build']['status'] == 'receipt_bound':
        if a['build']['profile'] != b['build']['profile']:
            add('build', 'contradiction', ['provenance.build.profile'], 'build_profile_mismatch', 'differs',
                (a['build']['profile'], b['build']['profile']))
        else:
            add('build', 'match', ['provenance.build.profile'], values=(a['build']['profile'], b['build']['profile']))
    else:
        add('build', 'unverified', ['provenance.build.status'], 'build_profile_unverified',
            'build profile is not bound to the measured binaries', (a['build']['status'], b['build']['status']))
    if a['binaries']['status'] == b['binaries']['status'] == 'receipt_bound':
        add('binaries', 'differs_allowed' if a['binaries']['sha256'] != b['binaries']['sha256'] else 'match',
            ['provenance.binaries.sha256'])
    else:
        add('binaries', 'unverified', ['provenance.binaries.status'], 'binary_identity_unverified',
            'binary digests are not independently bound', (a['binaries']['status'], b['binaries']['status']))
    return identity, found


def pairing(base, cand, identity, requested):
    if identity:
        return {'basis': 'identical_original_evidence', 'valid': True, 'reason': None}
    design = base['design']['pairing_design']
    if design is not None and design == cand['design']['pairing_design']:
        a = {t['id'] for t in base['trials']}
        b = {t['id'] for t in cand['trials']}
        if a != b:
            return {'basis': 'declared_paired_design', 'valid': False, 'reason': 'pairing_trial_set_mismatch'}
        return {'basis': 'declared_paired_design', 'valid': True, 'reason': None}
    return {'basis': None, 'valid': False,
            'reason': 'pairing_design_absent' if requested else 'not_requested_no_paired_design'}


def paired_differences(base, cand, key):
    profile, condition = key
    index = {t['id']: t for t in cand['trials']}
    diffs = []
    for t in base['trials']:
        other = index.get(t['id'])
        if (t['profile'], t['condition']) == key and t['run_qualified'] and t['status'] == 'measured' \
                and other and other['run_qualified'] and other['status'] == 'measured':
            diffs.append(other['endpoints']['continuation_ms'] - t['endpoints']['continuation_ms'])
    result = describe(diffs)
    result.update(kind='distribution_of_paired_differences', direction='candidate_minus_baseline', unit='ms',
                  all_zero=bool(diffs) and all(d == 0 for d in diffs))
    return result


def marginal_differences(a, b):
    def diff(x, y):
        return None if x is None or y is None else y - x
    out = {'kind': 'difference_of_marginal_percentiles_not_percentile_of_paired_differences',
           'direction': 'candidate_minus_baseline', 'unit': 'ms',
           'continuation_ms': {q: diff(a['continuation_ms'][q], b['continuation_ms'][q]) for q in ('p50', 'p95', 'max')},
           'stages_ms': {}}
    for name in sorted(set(a['stages_ms']) & set(b['stages_ms'])):
        out['stages_ms'][name] = {q: diff(a['stages_ms'][name][q], b['stages_ms'][name][q]) for q in ('p50', 'p95')}
    out['stages_one_side_only'] = sorted(set(a['stages_ms']) ^ set(b['stages_ms']))
    return out


def compare(base, cand, requested_pairing=False):
    identity, dims = dimensions(base, cand)
    pair = pairing(base, cand, identity, requested_pairing)
    reasons = [_reason(d['code'], d['dimension'], d['fields'], d['detail'])
               for d in dims if d['status'] in ('contradiction', 'unverified')]
    if requested_pairing and not pair['valid']:
        reasons.append(_reason(pair['reason'], 'pairing', ['design.pairing_design'],
                               'paired inference requested without a valid pairing basis'))
    contradiction = any(d['status'] == 'contradiction' for d in dims) or pair['reason'] == 'pairing_trial_set_mismatch'
    unverified = any(d['status'] == 'unverified' for d in dims) or (requested_pairing and not pair['valid'])
    strata = []
    for key in sorted(set(strata_keys(base)) | set(strata_keys(cand))):
        entry = {'profile': key[0], 'condition': key[1],
                 'baseline': stratum_side(base, key) if key in strata_keys(base) else None,
                 'candidate': stratum_side(cand, key) if key in strata_keys(cand) else None}
        why = []
        if entry['baseline'] is None or entry['candidate'] is None:
            why.append('stratum_unmatched')
        else:
            for role in ('baseline', 'candidate'):
                side = entry[role]
                if side['qualified_run_trials'] == 0:
                    why.append(role + '_no_qualified_run')
                elif not side['complete_denominator']:
                    why.append(role + '_incomplete_denominator')
        entry['comparable'] = not why and not contradiction and not unverified
        entry['reasons'] = why
        if entry['comparable']:
            entry['marginal_differences'] = marginal_differences(entry['baseline'], entry['candidate'])
            entry['paired_differences'] = paired_differences(base, cand, key) if pair['valid'] else None
        strata.append(entry)
    usable = [s for s in strata if s['comparable']]
    if contradiction:
        classification = 'non-comparable'
    elif unverified:
        classification = 'incomplete'
    elif usable and len(usable) == len(strata):
        classification = 'compatible'
    elif usable:
        classification = 'stratified-only'
        reasons.append(_reason('global_comparison_mixes_conditions', 'strata', ['trials[].condition'],
                               'only the listed comparable strata may be read; unmatched strata stay listed'))
    else:
        classification = 'incomplete'
        reasons.append(_reason('no_comparable_stratum', 'strata', ['trials[].status'], 'no complete matched stratum'))
    clusters = sorted({len(s[r]['runs']) for s in strata for r in ('baseline', 'candidate') if s[r]})
    return {
        'contract': COMPARISON, 'status': 'evaluated', 'classification': classification,
        'basis': 'identity_control' if identity else 'two_reports',
        'reasons': sorted(reasons, key=lambda r: (r['code'], r['dimension'])),
        'dimensions': dims, 'pairing': pair, 'strata': strata,
        'global_pooled_comparison': None,
        'global_pooled_comparison_reason': 'never computed: profiles and conditions are separate strata',
        'inference': {
            'status': 'descriptive_only',
            'independent_clusters_per_stratum': clusters,
            'hosts': 1 if identity else 'unknown (2 dispatches, host instance not retained)',
            'reasons': ['independent_clusters_below_minimum: at most %s runs per stratum, minimum %d effective '
                        'clusters (DEC-SOU153-20261027)' % (max(clusters) if clusters else 0, MIN_EFFECTIVE_CLUSTERS),
                        'no_accepted_performance_cluster_method: the SOU-153 bootstrap is approved only for '
                        'AgentDojo semantic families',
                        'repeated_trials_within_a_run_are_dependent: one qualifier process and host per run'],
            'intervals': None},
        'engineering_targets': {'continuation_p95_ms': CONTINUATION_TARGET_MS, 'first_pending_ms': PENDING_BOUND_MS,
                                'note': 'existing criteria, evaluated per side and stratum only; not a comparison '
                                        'verdict, not protection, effectiveness or readiness'},
        'percentile_definition': PERCENTILE, 'scope': SCOPE,
        'observations': {'baseline': summary_of(base), 'candidate': summary_of(cand)},
    }


def summary_of(observation):
    """Observation header without the trial list (trials go to trials.csv)."""
    return {k: v for k, v in observation.items() if k != 'trials'} | {
        'trial_count': len(observation['trials']),
        'status_counts': {s: sum(t['status'] == s for t in observation['trials']) for s in STATUSES}}


# ------------------------------------------------------------------ outputs

def dumps(value):
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + '\n'


def render_csv(rows, header):
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue()


def trials_csv(observations):
    rows = []
    for role, observation in observations:
        for t in observation['trials']:
            e = t['endpoints']
            rows.append([role, t['id'], t['run'], t['profile'], t['condition'], t['run_qualified'], t['status'],
                         t['reason'] or '', _fmt(e['continuation_ms']), _fmt(e['first_pending_asset_verification_ms']),
                         _fmt(e['post_observed_total_ms'])])
    return render_csv(rows, ['role', 'trial_id', 'run', 'profile', 'condition', 'run_qualified', 'status', 'reason',
                             'continuation_ms', 'first_pending_asset_verification_lb_ms', 'post_observed_total_ms'])


def strata_csv(result):
    rows = []
    for s in result['strata']:
        for role in ('baseline', 'candidate'):
            side = s[role]
            if side is None:
                rows.append([s['profile'], s['condition'], role, 'absent'] + [''] * 11)
                continue
            c, d = side['status_counts'], side['continuation_ms']
            rows.append([s['profile'], s['condition'], role, 'comparable' if s['comparable'] else 'not_comparable',
                         side['planned'], side['qualified_run_trials'], c['measured'], c['failed'], c['timed_out'],
                         c['incomplete'], c['not_run'], side['independent_clusters'], _fmt(d['p50']), _fmt(d['p95']),
                         _fmt(d['max'])])
    return render_csv(rows, ['profile', 'condition', 'role', 'stratum', 'planned', 'qualified_run_trials', 'measured',
                             'failed', 'timed_out', 'incomplete', 'not_run', 'runs', 'continuation_p50_ms',
                             'continuation_p95_ms', 'continuation_max_ms'])


def _fmt(value):
    return '' if value is None else repr(value)


def _ms(value):
    return 'n/a' if value is None else f'{value:.1f}'


def render_markdown(result):
    lines = ['# Native performance comparison', '']
    if result['status'] == 'rejected':
        r = result['rejection']
        return '\n'.join(lines + [f"**Rejected** (`{r['code']}`, {r['role']}): {r['detail']}", '',
                                  'No comparison, distribution or verdict was produced.', '']) + '\n'
    o = result['observations']
    lines += [f"Classification: **{result['classification']}** ({result['basis']}).", '',
              '| Role | Input | Original SHA-256 | Custody | Source | Binaries | Build |', '|---|---|---|---|---|---|---|']
    for role in ('baseline', 'candidate'):
        x = o[role]
        p = x['provenance']
        lines.append(f"| {role} | `{x['input']['name']}` | `{x['input']['custody']['original_sha256'][:16]}…` | "
                     f"{x['input']['custody']['status']} | {p['source']['status']} | {p['binaries']['status']} | "
                     f"{p['build']['status']} |")
    lines += ['', '## Reasons', '']
    lines += [f"- `{r['code']}` ({r['dimension']}): {r['detail']}" for r in result['reasons']] or ['- none']
    lines += ['', '## Strata (continuation, ms)', '',
              'Status counts cover trials of qualified runs; trials of unqualified runs are excluded and counted.', '',
              '| Profile | Condition | Role | Planned | Excluded (unqualified runs) | Measured / failed / timed out / '
              'incomplete / not run | Runs | p50 | p95 | max | 3000 ms p95 |',
              '|---|---|---|---:|---:|---|---:|---:|---:|---:|---|']
    for s in result['strata']:
        for role in ('baseline', 'candidate'):
            side = s[role]
            if side is None:
                lines.append(f"| {s['profile']} | {s['condition']} | {role} | – | – | absent | – | – | – | – | – |")
                continue
            c, d = side['status_counts'], side['continuation_ms']
            lines.append(f"| {s['profile']} | {s['condition']} | {role} | {side['planned']} | "
                         f"{side['excluded_unqualified_run_trials']} | {c['measured']} / {c['failed']} / {c['timed_out']} / {c['incomplete']} / {c['not_run']} | "
                         f"{side['independent_clusters']} | {_ms(d['p50'])} | {_ms(d['p95'])} | {_ms(d['max'])} | "
                         f"{side['engineering_targets']['continuation_p95_le_3000_ms']} |")
    lines += ['', '## Differences (candidate minus baseline, ms)', '']
    shown = False
    for s in result['strata']:
        if not s['comparable']:
            continue
        shown = True
        m = s['marginal_differences']['continuation_ms']
        text = (f"- {s['profile']} / {s['condition']}: marginal percentile differences p50 {_ms(m['p50'])}, "
                f"p95 {_ms(m['p95'])}, max {_ms(m['max'])}")
        p = s['paired_differences']
        if p:
            text += (f"; paired differences (n={p['n']}) p50 {_ms(p['p50'])}, p95 {_ms(p['p95'])}, "
                     f"min {_ms(p['min'])}, max {_ms(p['max'])}, all zero: {p['all_zero']}")
        lines.append(text)
    if not shown:
        lines.append('- none: no comparable stratum. No speed-up, merged p95 or verdict is reported.')
    lines += ['', '## Limits', '', f"- Percentiles: {result['percentile_definition']}",
              '- Inference: descriptive only. ' + ' '.join(result['inference']['reasons']),
              '- Not retained: ' + ', '.join(sorted(NOT_RETAINED)) + '.']
    lines += [f'- {line}' for line in result['scope']]
    return '\n'.join(lines) + '\n'


def rejection(error):
    return {'contract': COMPARISON, 'status': 'rejected', 'classification': None, 'rejection': error.as_dict(),
            'scope': SCOPE}


def prepare_out_dir(path):
    path = Path(path)
    if path.is_symlink():
        raise Rejected('unsafe_output_destination', 'output', 'symlink')
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise Rejected('unsafe_output_destination', 'output', 'output directory must be new or empty')
    else:
        path.mkdir(mode=0o700, parents=True)
    return path


def write_text(out_dir, name, text):
    data = text.encode('utf-8')
    if len(data) > LIMITS['output_bytes']:
        raise Rejected('output_limit_exceeded', 'output', name)
    handle = tempfile.NamedTemporaryFile('wb', dir=out_dir, delete=False, suffix='.tmp')
    with handle:
        handle.write(data)
    os.replace(handle.name, out_dir / name)


def run_comparison(args, git=None):
    """Returns (exit_code, result, observations)."""
    git = git or Git(args.repository)
    try:
        base = normalize('baseline', args.baseline, args.baseline_manifest, args.baseline_receipt, git)
        cand = normalize('candidate', args.candidate, args.candidate_manifest, args.candidate_receipt, git)
        result = compare(base, cand, requested_pairing=args.paired)
    except Rejected as error:
        return 2, rejection(error), []
    code = 0 if result['classification'] in ('compatible', 'stratified-only') else 1
    return code, result, [('baseline', base), ('candidate', cand)]


def write_outputs(out_dir, result, observations):
    write_text(out_dir, 'comparison.json', dumps(result))
    write_text(out_dir, 'report.md', render_markdown(result))
    if observations:
        write_text(out_dir, 'trials.csv', trials_csv(observations))
        write_text(out_dir, 'strata.csv', strata_csv(result))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    for role in ('baseline', 'candidate'):
        parser.add_argument('--' + role, type=Path, required=True, help='sw-ask-series/1 summary.json')
        parser.add_argument(f'--{role}-manifest', type=Path, help='manifest.json declared before the first trial')
        parser.add_argument(f'--{role}-receipt', type=Path, help=RECEIPT_FORMAT + ' build receipt')
    parser.add_argument('--paired', action='store_true', help='require trial-level paired differences')
    parser.add_argument('--repository', type=Path, default=ROOT, help='local git repository used as witness')
    parser.add_argument('--out-dir', type=Path, required=True, help='new or empty private output directory')
    try:
        args = parser.parse_args(argv)
    except SystemExit as error:
        return 3 if error.code else 0
    try:
        out_dir = prepare_out_dir(args.out_dir)
    except Rejected as error:
        print(json.dumps({'status': 'usage_error', 'code': error.code, 'detail': error.detail}))
        return 3
    code, result, observations = run_comparison(args)
    try:
        write_outputs(out_dir, result, observations)
    except Rejected as error:
        print(json.dumps({'status': 'rejected', 'code': error.code}))
        return 2
    print(json.dumps({'status': result['status'], 'classification': result.get('classification'),
                      'rejection': result.get('rejection', {}).get('code')}, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
