#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-203 offline, source-bound comparison of retained native Ask performance reports.

Reads `sw-ask-series/1` series summaries (SOU-141, `scripts/qualify-ask-series.py`) with
their manifests, and single `sw-pilot-ask-acceptance/1` Ask qualification reports
(`scripts/qualify-pilot-ask.py`, SOU-124). Installed-host (`sw-installed-pilot-matched/1`)
and preparation reports are not supported (see the guide). It verifies what can be verified from local git objects, normalizes every
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
ASK_FORMAT = 'sw-pilot-ask-acceptance/1'
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
PERCENTILE = ('nearest rank: the value at rank ceil(q * n) of the ascending sample of measured trials, '
              'unrounded (pilot_ask_latency.summarize); failed, timed-out, incomplete and not-run trials are '
              'counted, never imputed.')
SCOPE = [
    'Engineering performance diagnostics for the recorded reports only.',
    'Not a security or protection qualification, not task effectiveness, not product or pilot readiness.',
    'No new budget or threshold is approved.',
    'A same-report identity control proves the comparator, not a performance change between revisions.',
]
_ASK = {
    'scope': ['Ask: trace-on (strace seccomp-bpf) is the only observer mode of this producer; no trace-off '
              'result exists here, and none would qualify protection.'],
    'observer': {'timing': 'qualify-pilot-ask.py harness monotonic clock; collector monotonic clock for stages',
                 'trace': 'strace seccomp-bpf requested (fallback possible); the observed mode is not retained'},
    'dependence': 'Ask: trials within a run share one qualifier process and one host',
    'criteria': {'continuation_p95_ms': CONTINUATION_TARGET_MS, 'first_pending_ms': PENDING_BOUND_MS,
                 'note': 'existing Ask criteria, evaluated per side and stratum; the first-pending bound is owned '
                         'by SOU-105 and only a collector lower bound is shown'},
}
FAMILIES = {
    'sw-ask-series/1': dict(_ASK, percentile='Ask series: published distributions round to 0.001 ms first; '
                                              'reproduction uses that producer convention.'),
    'sw-ask-series/1-retroactive': dict(_ASK, percentile='Ask series: published distributions round to 0.001 ms '
                                                          'first; reproduction uses that producer convention.'),
    'sw-pilot-ask-acceptance/1': dict(_ASK, percentile='Ask qualification: published p50/p95 are nearest rank on '
                                                        'unrounded values.'),
    'sw-installed-pilot-matched/1': {
        'scope': ['Installed host: row status and the gate are producer development outcomes; protected refusals '
                  'are producer-witnessed, never independently observed protection.'],
        'observer': {'timing': 'qualify-installed-pilot.py driver monotonic clock around a fresh Claude Code host per '
                               'arm and a scripted loopback provider',
                     'trace': 'no trace or observer mode is recorded by this producer'},
        'percentile': 'Installed host: the published gate uses agentdojo_protocol.distribution (median = mean of the '
                      'two middle values for even n); SOU-203 reports nearest-rank p50, so it can differ from a '
                      'published median. Per-call distributions count calls, not arms.',
        'dependence': 'Installed host: calls within an arm share one host process; all arms of a report share one '
                      'runner and dispatch; the control arm always runs first',
        'criteria': {'note': 'none approved: the producer records latency_threshold_approved false'},
    },
    'sw-native-pilot-prerequisites/1': {
        'scope': ['Preparation: stage time is preparation cost only, never an Ask or host latency.'],
        'observer': {'timing': 'prepare-native-pilot-prerequisites.py monotonic stage timers (seconds)',
                     'trace': 'not applicable: preparation runs no Ask or MCP observer'},
        'percentile': 'Preparation: one value per stage and receipt; percentiles of n=1 are that value.',
        'dependence': 'Preparation: both stages of a receipt share one preparation on one host',
        'criteria': {'note': 'none approved for preparation stage time'},
    },
}


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


def verify_source(source, git, role, files_optional=False):
    require(isinstance(source, dict), 'source_identity_missing', role, 'source')
    commit, tree, files = source.get('commit'), source.get('tree'), source.get('files_sha256')
    require(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}', commit)
            and isinstance(tree, str) and re.fullmatch('[0-9a-f]{40}', tree)
            and ((files is None and files_optional) or (isinstance(files, str) and re.fullmatch('[0-9a-f]{64}', files))),
            'source_identity_malformed', role, 'full commit, tree and files_sha256 required')
    require(source.get('dirty') is False, 'source_dirty', role, 'source.dirty must be false')
    actual_tree = git.tree_of(commit)
    if actual_tree is None:
        return {'status': 'unverified_commit_not_in_repository', 'commit': commit, 'tree': tree,
                'files_sha256': files, 'method': None}
    require(actual_tree == tree, 'source_identity_contradiction', role, 'source.tree differs from git commit tree')
    if files is None:
        return {'status': 'commit_tree_verified_files_not_declared', 'commit': commit, 'tree': tree,
                'files_sha256': None, 'method': 'git rev-parse <commit>^{tree}; the report declares no files_sha256'}
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


def _same(a, b):
    """Exact JSON equality: unlike ==, a boolean never equals 0 or 1, at any depth."""
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def _hex(value, size=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % size, value) is not None


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
            # cpu_count and MemTotal_kb decide compatibility: integers (or absent), never other JSON types.
            require(all(v is None or (_plain(v, int) and v > 0) for v in (value.get('cpu_count'), mem.get('MemTotal_kb'))),
                    'report_shape_invalid', 'run_conditions', f'{when}: cpu_count and MemTotal_kb must be integers')
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
    if 'format' not in summary and summary.get('contract_version') == ASK_FORMAT:
        require(manifest_path is None and receipt_path is None, 'input_not_applicable', role,
                'an Ask qualification report carries its own binary digests; no manifest or receipt applies')
        return _normalize_ask(role, summary_path, summary, held, git)
    fmt = summary.get('format')
    if fmt in (INSTALLED_FORMAT, PREPARATION_FORMAT):
        require(manifest_path is None and receipt_path is None, 'input_not_applicable', role,
                'this report family carries its own identities; no manifest or receipt applies')
        adapter = _normalize_installed if fmt == INSTALLED_FORMAT else _normalize_preparation
        return adapter(role, summary_path, summary, held, git)
    require(fmt != PREPARATION_MARKER, 'no_performance_endpoints', role,
            'sw-pilot-preparation/1 is a completion marker without timing fields')
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
            require(_same(manifest.get(key), summary.get(key)), 'manifest_summary_mismatch', role, key)
        require(manifest.get('metric') == LATENCY_METRIC, 'endpoint_substitution', role, 'manifest.metric')
        require(manifest.get('target_ms') == CONTINUATION_TARGET_MS, 'manifest_summary_mismatch', role, 'target_ms')
        require(manifest.get('cold_ask_trials_claimed', False) is False, 'true_cold_claim_unsupported', role,
                'the producer re-reads inputs before every timed trial; no cold Ask trial can be claimed')
        require(all(manifest.get(k) is None or isinstance(manifest[k], str) for k in ('kernel', 'machine')),
                'report_shape_invalid', role, 'manifest kernel and machine must be strings')
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
        require(_same(receipt.get('source'), summary.get('source')), 'build_receipt_binding_mismatch', role, 'source')
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
                  'requested_status': 'producer_declared' if trace_basis else 'unverified',
                  'requested_basis': ('self-declared: the summary marks runs ' + str(trace_basis) + ' validated, and '
                                      'the producer validates only qualification reports whose trace_requested equals '
                                      'this value; the qualification reports themselves are not retained')
                  if trace_basis else 'unverified: no validated run',
                  'observed': 'not_retained'},
        'endpoints': copy.deepcopy(ENDPOINTS), 'stage_clock': dict(STAGE_CLOCK), 'not_retained': dict(NOT_RETAINED),
        'primary_endpoint': 'continuation_ms',
        'design': {'plan': plan, 'samples_per_profile': samples, 'profiles': list(PROFILES),
                   'trial_plan': {'samples_per_profile': samples},
                   'pairing_design': None, 'cluster_unit': 'run (one qualifier process per run)',
                   'host_unit': 'one dispatch / runner per report'},
        'status_mapping': dict(STATUS_MAPPING),
        'runs': run_records,
        'trials': trials,
        'reproduction': {'status': 'reproduced_from_retained_trials', 'checked': reproduced,
                         'not_reproduced': ['runs[].summary.stages (raw stage-events.jsonl not retained)']},
    }
    return observation


def _ask_success(row):
    """The `pilot_ask_latency.summarize` success predicate; latency reproduction keeps both in agreement."""
    elapsed = row.get('decision_to_result_ms')
    return (row.get('passed') is True and row.get('approved') is True and row.get('released') is True
            and _plain(row.get('dispatched'), int) and row['dispatched'] == 1
            and _plain(row.get('kernel_effects'), int) and row['kernel_effects'] == 1
            and _number(elapsed) and elapsed >= 0)


def _normalize_ask(role, path, report, held, git):
    """One `qualify-pilot-ask.py --approval-samples N` report: a single run, no declared cold/warm condition."""
    latency, cases = report.get('latency'), report.get('cases')
    require(isinstance(latency, dict) and all(isinstance(latency.get(p), dict) for p in PROFILES),
            'sample_plan_invalid', role, 'latency.<profile>.planned is required for a performance report')
    samples = latency[PROFILES[0]].get('planned')
    require(_plain(samples, int) and 20 <= samples <= LIMITS['samples_per_profile']
            and all(latency[p].get('planned') == samples for p in PROFILES), 'sample_plan_invalid', role, 'planned')
    require(isinstance(cases, list) and len(cases) <= len(PROFILES) * samples
            and all(isinstance(c, dict) for c in cases), 'trial_table_malformed', role, 'cases')
    seen = set()
    for row in cases:
        sample = row.get('sample_index')
        require(row.get('profile') in PROFILES and row.get('case') == 'approve' and _plain(sample, int)
                and 0 <= sample < samples, 'unexpected_trial_id', role, f'{row.get("profile")!r}/{sample!r}')
        require((row['profile'], sample) not in seen, 'duplicate_trial_id', role, f'{row["profile"]}/{sample}')
        seen.add((row['profile'], sample))
        if row.get('passed') is True:
            value = row.get('decision_to_result_ms')
            require(_number(value), 'nonfinite_or_missing_duration', role, f'{row["profile"]}/{sample}')
            require(value >= 0, 'negative_duration', role, f'{row["profile"]}/{sample}')
    _check(latency, LATENCY.summarize(cases, samples), role, 'latency')
    status = report.get('status')
    require(status in ('pass', 'performance_blocker', 'failed', 'incomplete') and isinstance(status, str),
            'report_shape_invalid', role, 'status')
    for name in ('real_host_executed', 'workspace_unchanged'):
        require(report.get(name) is None or _plain(report.get(name), bool), 'report_shape_invalid', role,
                f'{name} must be a JSON boolean')
    require(_plain(report.get('paid_api_calls'), int), 'report_shape_invalid', role, 'paid_api_calls must be an integer')
    require(report.get('error_type') is None or isinstance(report.get('error_type'), str), 'report_shape_invalid',
            role, 'error_type must be a string')
    trace = report.get('trace_requested')
    # The accepted producer writes exactly LATENCY.trace_request(); older reports omit the field.
    require(trace is None or _same(trace, LATENCY.trace_request()), 'trace_mode_unsupported', role,
            'trace_requested must be absent or exactly the accepted strace request')
    checks = {'qualification_status': status in ('pass', 'performance_blocker'),
              'real_host_executed': report.get('real_host_executed') is True,
              'no_paid_calls': _plain(report.get('paid_api_calls'), int) and report['paid_api_calls'] == 0,
              'workspace_unchanged': report.get('workspace_unchanged') is True,
              'source_unchanged': _same(report.get('source'), report.get('source_after'))}
    failed_checks = [name for name, ok in checks.items() if not ok]
    qualified = not failed_checks
    if qualified:
        require(len(cases) == len(PROFILES) * samples, 'missing_required_trial', role,
                f'{len(cases)} of {len(PROFILES) * samples} cases in a qualified report')
    source = verify_source(report.get('source'), git, role, files_optional=True)
    harness = None
    if source['status'] != 'unverified_commit_not_in_repository':
        harness = {name: git.file_sha256(source['commit'], name) for name in HARNESS}
    selected = report.get('selected_sha256')
    require(isinstance(selected, dict) and selected
            and all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in selected.values()),
            'invalid_digest', role, 'selected_sha256')
    timed_out = 'timeout' in (report.get('error_type') or '').lower()
    by_key = {(c['profile'], c['sample_index']): c for c in cases}
    trials = []
    for profile in PROFILES:
        for sample in range(samples):
            row = by_key.get((profile, sample))
            if row is None:
                state, why = ('timed_out', 'report_timeout') if timed_out else ('incomplete', 'trial_not_recorded')
            elif _ask_success(row):
                state, why = 'measured', None
            else:
                state, why = 'failed', 'producer_trial_failed'
            trials.append({'id': f'r01/{profile}/{sample:03d}', 'run': 1, 'profile': profile, 'sample_index': sample,
                           'condition': 'undeclared', 'run_qualified': qualified, 'status': state, 'reason': why,
                           'endpoints': {'continuation_ms': row['decision_to_result_ms'] if state == 'measured'
                                         else None, 'first_pending_asset_verification_ms': None,
                                         'post_observed_total_ms': None}, 'stages': {}})
    index = {(t['profile'], t['sample_index']): t for t in trials}
    for sample in SERIES.diagnostic_samples(cases):  # present only with --require-verified-reuse proofs
        trial = index[(sample['profile'], sample['sample_index'])]
        pending, post = sample['first_pending_asset_verification_ms'], sample['post_observed_ms']
        continuation = trial['endpoints']['continuation_ms']
        require(continuation is None or (continuation != pending and continuation != post),
                'endpoint_substitution', role, f'{trial["id"]}: continuation equals a collector endpoint')
        if trial['status'] == 'measured':
            trial['endpoints'].update(first_pending_asset_verification_ms=pending, post_observed_total_ms=post)
            trial['stages'] = {**{'asset/' + k: v for k, v in sorted(sample['assets_ms'].items())},
                               **{'approval/' + k: v for k, v in sorted(sample['approval_stage_ms'].items())}}
    return {
        'contract': OBSERVATION, 'role': role,
        'input': {'name': portable_name(path), 'producer': 'scripts/qualify-pilot-ask.py', 'producer_format': ASK_FORMAT,
                  'evidence_sha256': hashlib.sha256(json.dumps([held['original_sha256'], None, None]).encode()).hexdigest(),
                  'custody': held, 'manifest': None, 'workflow_run': report.get('workflow_run')},
        'provenance': {
            'source': source,
            'binaries': {'status': 'declared_only', 'sha256': selected,
                         'detail': 'qualification report self-declaration; the binaries are not retained'},
            'build': {'status': 'not_retained', 'profile': None, 'receipt_sha256': None,
                      'detail': 'an Ask qualification report carries no build receipt'},
            'workload': {'definition': 'qualify-pilot-ask.py --approval-samples N, approve case, profiles '
                                       + ','.join(PROFILES), 'harness_sha256_at_source': harness,
                         'status': 'verified_git_objects' if harness and all(harness.values()) else 'unverified'},
            'profiles_and_policy': {'status': 'declared_only', 'detail': 'per-case policy_sha256 is self-declared; '
                                    'no files_sha256 binds the source tree contents'
                                    if source['files_sha256'] is None else 'bound via source.files_sha256'},
        },
        'environment': {'platform_kind': None, 'kernel': None, 'machine': None, 'cpu_count': [], 'mem_total_kb': [],
                        'host_instance': {'status': 'not_retained', 'detail': 'the report records no host'}},
        'trace': {'requested': trace, 'requested_status': 'producer_declared' if trace is not None else 'not_retained',
                  'requested_basis': 'self-declared trace_requested in the report' if trace is not None
                  else 'this report predates the trace_requested field', 'observed': 'not_retained'},
        'endpoints': copy.deepcopy(ENDPOINTS), 'stage_clock': dict(STAGE_CLOCK),
        'not_retained': {
            'preparation_elapsed': 'not recorded by the qualification report',
            'first_observable_pending': 'cases carry wall-clock pending and decision timestamps; no accepted '
                                        'first-pending endpoint is derived from them (SOU-105 owns that bound)',
            'cleanup': 'per-case cleanup evidence is retained without a duration',
            'raw_stage_events': 'not part of an Ask qualification report',
            'trace_observed': 'the report records at most the requested trace mode'},
        'primary_endpoint': 'continuation_ms',
        'design': {'plan': ['undeclared'], 'samples_per_profile': samples, 'profiles': list(PROFILES),
                   'trial_plan': {'samples_per_profile': samples},
                   'pairing_design': None, 'cluster_unit': 'run (one qualifier process)', 'host_unit': 'one report'},
        'status_mapping': dict(STATUS_MAPPING, measured='case present and the pilot_ask_latency.summarize success '
                               'predicate holds', timed_out='no case, and the report error_type names a timeout',
                               not_run='not applicable: a single report is one run'),
        'runs': [{'index': 1, 'declared_kind': 'undeclared', 'condition': 'undeclared', 'qualified': qualified,
                  'disqualification': None if qualified else 'failed_checks:' + ','.join(failed_checks),
                  'exit_code': None, 'failure': report.get('error_type'), 'wall_seconds': None, 'cache_drop': None,
                  'conditions': {}}],
        'trials': trials,
        'reproduction': {'status': 'reproduced_from_retained_trials', 'checked': ['latency'], 'not_reproduced': []},
    }


# ------------------------------------------------------------------ sw-installed-pilot-matched/1 adapter

INSTALLED_FORMAT = 'sw-installed-pilot-matched/1'
INSTALLED_HARNESS = {'driver_sha256': 'scripts/qualify-installed-pilot.py',
                     'extension_sha256': 'scripts/pilot_measurement.py'}
INSTALLED_GATE = ('scripts/pilot_qualification.py', 'scripts/benchmarks/agentdojo_protocol.py')
INSTALLED_WORKLOADS = ('scripts/benchmarks/installed-pilot-workload-v2.json',
                       'scripts/benchmarks/installed-pilot-workload-v1.json')
INSTALLED_CLOCK = {'clock': 'installed_driver_monotonic', 'unit': 'ms',
                   'observer': 'scripts/qualify-installed-pilot.py Pilot.host (scripted loopback provider)'}
INSTALLED_ENDPOINTS = {
    'host_elapsed_ms': dict(INSTALLED_CLOCK, metric='installed_host_arm_elapsed', start='host process spawn',
                            end='host process exit', source_field='rows[].host_elapsed_ms',
                            role='whole fresh-host arm: start, every call and shutdown'),
    'host_start_ms': dict(INSTALLED_CLOCK, metric='installed_host_start', start='host process spawn',
                          end='first scripted tool proposal served', source_field='rows[].host_start_ms',
                          role='host start only; never a call latency'),
}
INSTALLED_STATUS_MAPPING = {
    'measured': 'row status passed (the gate requires actual host, cleanup and finite call timings)',
    'failed': 'row status failed for a non-timeout reason',
    'timed_out': 'row status failed with a reason naming a timeout or deadline',
    'incomplete': 'row status incomplete after execution started or was cancelled',
    'not_run': 'row status incomplete with reason not_executed (the arm never started)',
}
INSTALLED_OUTCOMES = ('Row status and the gate are the producer\'s development workflow outcomes. A protected refusal '
                      'is witnessed by the producer\'s own repository witness (effect_observed, original_opens) and is '
                      'not re-observed here. No status is security or protection effectiveness evidence.')


def _git_json(git, commit, name):
    data = git.run('cat-file', 'blob', f'{commit}:{name}')
    return data, (json.loads(data) if data is not None else None)


def _normalize_installed(role, path, report, held, git):
    rows, identity = report.get('rows'), report.get('identity')
    require(isinstance(rows, list) and 1 <= len(rows) <= LIMITS['trials'] and all(isinstance(r, dict) for r in rows),
            'trial_table_malformed', role, 'rows')
    require(isinstance(identity, dict) and isinstance(identity.get('selected'), dict), 'source_identity_missing',
            role, 'identity')
    for row in rows:
        require(_same(row.get('identity'), identity), 'paired_identity_drift', role, f'{row.get("case")}/{row.get("arm")}')
        require(row.get('arm') in ('control', 'protected') and isinstance(row.get('case'), str)
                and row.get('status') in ('passed', 'failed', 'incomplete'), 'trial_table_malformed', role,
                f'{row.get("case")!r}/{row.get("arm")!r}')
    selected = identity['selected']
    require(all(isinstance(v, str) and re.fullmatch('[0-9a-f]{64}', v) for v in selected.values()),
            'invalid_digest', role, 'identity.selected')
    require(all(_hex(identity.get(k)) for k in ('policy_sha256', 'driver_sha256', 'extension_sha256'))
            and _hex(report.get('workload_file_sha256')) and _hex(report.get('workload_sha256')),
            'invalid_digest', role, 'identity and workload digests')
    for name in ('source_unchanged', 'cleanup'):
        require(_plain(report.get(name), bool), 'report_shape_invalid', role, f'{name} must be a JSON boolean')
    budgets = report.get('engineering_budgets')
    require(isinstance(budgets, dict) and _plain(budgets.get('latency_threshold_approved'), bool),
            'report_shape_invalid', role, 'engineering_budgets.latency_threshold_approved must be a JSON boolean')
    for row in rows:
        where = f'{row["case"]}/{row["arm"]}'
        require(row.get('reason') is None or isinstance(row['reason'], str), 'report_shape_invalid', role,
                where + '.reason must be a string')
        require(row.get('cancelled') is None or _plain(row['cancelled'], bool), 'report_shape_invalid', role,
                where + '.cancelled must be a JSON boolean')
        if row['status'] == 'passed':
            # A passed arm is measured only with the producer's own host and cleanup attestations.
            require(row.get('actual_host') is True and row.get('cleanup') is True, 'installed_attestation_invalid',
                    role, where + ': passed without actual_host and cleanup true')
    require(identity.get('policy_sha256') == selected.get('policy'), 'policy_identity_contradiction', role,
            'identity.policy_sha256 differs from identity.selected.policy')
    source = verify_source(identity.get('source'), git, role)
    commit = source['commit']
    available = source['status'] != 'unverified_commit_not_in_repository'
    harness = {}
    if available:
        for field, name in INSTALLED_HARNESS.items():
            harness[name] = git.file_sha256(commit, name)
            require(harness[name] is None or harness[name] == identity.get(field), 'harness_identity_contradiction',
                    role, f'identity.{field} differs from {name} at the source commit')
    workload = workload_name = None
    if available:
        present = False
        for name in INSTALLED_WORKLOADS:
            data, value = _git_json(git, commit, name)
            present = present or bool(data)
            if data is not None and hashlib.sha256(data).hexdigest() == report.get('workload_file_sha256'):
                workload, workload_name = value, name
                break
        # The source commit is in the repository and has a workload file: a non-matching digest contradicts it.
        require(workload is not None or not present, 'workload_identity_contradiction', role,
                'workload_file_sha256 matches no workload file at the source commit')
    conditions = report.get('conditions')
    require(isinstance(conditions, dict) and isinstance(conditions.get('os_cache'), str), 'report_shape_invalid',
            role, 'conditions.os_cache must be a string')
    require(conditions['os_cache'].startswith('uncontrolled'), 'true_cold_claim_unsupported', role,
            'conditions.os_cache')
    keys = [(r['case'], r['arm']) for r in rows]
    require(len(set(keys)) == len(keys), 'duplicate_trial_id', role, 'rows (case, arm)')
    reproduced, not_reproduced = [], []
    if workload is not None:
        gate = _load('installed_gate', 'scripts/pilot_qualification.py')
        require(gate.digest(workload) == report.get('workload_sha256') == identity.get('model_script_sha256'),
                'workload_identity_contradiction', role, 'workload_sha256')
        expected = [(c['id'], arm) for c in workload['cases'] for arm in ('control', 'protected')]
        require(not set(keys) - set(expected), 'unexpected_trial_id', role, str(sorted(set(keys) - set(expected))[:3]))
        require(set(keys) == set(expected), 'missing_required_trial', role, str(sorted(set(expected) - set(keys))[:3]))
        require(keys == expected, 'trial_order_invalid', role, 'rows')
        cases = {c['id']: c for c in workload['cases']}
        for row in rows:
            require(row.get('operation_sha256') == gate.digest(cases[row['case']]['batches']),
                    'workload_identity_contradiction', role, f'{row["case"]}/{row["arm"]}.operation_sha256')
        _check(report.get('conditions'), workload['conditions'], role, 'conditions')
        # Older producer revisions did not write required_arms; it is checked only where it was published.
        require(report.get('required_arms') in (None, len(expected)), 'published_distribution_not_reproduced', role,
                'required_arms')
        reproduced += ['rows (case, arm) plan', 'rows[].operation_sha256', 'conditions']
        if report.get('required_arms') is not None:
            reproduced.append('required_arms')
    else:
        require(report.get('required_arms') in (None, len(rows)), 'missing_required_trial', role, 'required_arms')
        not_reproduced.append('trial plan and gate: the workload at the source commit is unavailable')
    report_failures = report.get('failures')
    require(isinstance(report_failures, list) and all(isinstance(f, str) for f in report_failures),
            'trial_table_malformed', role, 'failures')
    checks = {'source_unchanged': report.get('source_unchanged') is True
              and _same(report.get('source_after'), identity.get('source')),
              'cleanup': report.get('cleanup') is True, 'no_run_failures': not report_failures}
    failed_checks = [name for name, ok in checks.items() if not ok]
    qualified = not failed_checks
    condition = 'fresh_host_per_arm_os_cache_uncontrolled'
    kinds = {c['id']: c['kind'] for c in workload['cases']} if workload else {}
    batches = {c['id']: c['batches'] for c in workload['cases']} if workload else {}
    trials = []
    for row in rows:
        reason = row.get('reason')
        if row['status'] == 'passed':
            state = 'measured'
        elif row['status'] == 'failed':
            state = 'timed_out' if reason and re.search('timeout|deadline', reason) else 'failed'
        else:
            state = 'not_run' if reason == 'not_executed' and row.get('cancelled') is not True else 'incomplete'
        endpoints = dict.fromkeys(INSTALLED_ENDPOINTS)
        stages = {}
        if state == 'measured':
            for name in INSTALLED_ENDPOINTS:
                value = row.get(name)
                if value is None and name == 'host_elapsed_ms':
                    continue  # not written by older producer revisions; host_start_ms is required by every gate
                require(_number(value), 'nonfinite_or_missing_duration', role, f'{row["case"]}/{row["arm"]}.{name}')
                require(value >= 0, 'negative_duration', role, f'{row["case"]}/{row["arm"]}.{name}')
                endpoints[name] = value
            calls = row.get('latencies_ms')
            require(isinstance(calls, dict) and all(_number(v) and v >= 0 for v in calls.values()),
                    'nonfinite_or_missing_duration', role, f'{row["case"]}/{row["arm"]}.latencies_ms')
            elapsed = endpoints['host_elapsed_ms']
            # Same driver clock, nested boundaries: start and each call lie inside the host lifetime.
            require(elapsed is None or (endpoints['host_start_ms'] < elapsed
                                        and all(v <= elapsed for v in calls.values())),
                    'endpoint_substitution', role, f'{row["case"]}/{row["arm"]}: endpoint outside the host lifetime')
            if row['case'] in batches:
                total, first = sum(map(len, batches[row['case']])), len(batches[row['case']][0])
                require(set(calls) == {f'toolu_pilot_{i}' for i in range(total)}, 'call_denominator_mismatch', role,
                        f'{row["case"]}/{row["arm"]}')
                stages = {'call/first_batch_ms': [calls[f'toolu_pilot_{i}'] for i in range(first)],
                          'call/steady_state_ms': [calls[f'toolu_pilot_{i}'] for i in range(first, total)]}
            else:
                stages = {'call/unsplit_ms': [calls[k] for k in sorted(calls)]}
        label = f"{row['arm']}/{kinds.get(row['case'], 'unknown_kind')}"
        trials.append({'id': f"r01/{row['case']}/{row['arm']}", 'run': 1, 'profile': label, 'sample_index': None,
                       'case': row['case'], 'arm': row['arm'], 'condition': condition, 'run_qualified': qualified,
                       'status': state, 'reason': None if state == 'measured' else (reason or row['status']),
                       'endpoints': endpoints, 'stages': stages})
    if workload is not None:
        # The gate is reproduced (after every trial value is validated) only with the exact gate code that produced it.
        same_gate = all(git.run('cat-file', 'blob', f'{commit}:{name}') ==
                        (ROOT / name).read_bytes().replace(b'\r\n', b'\n') for name in INSTALLED_GATE)
        if same_gate:
            body = {k: v for k, v in report.items() if k not in ('gate', 'negative_gate_control')}
            sys.path.insert(0, str(ROOT / 'scripts'))
            try:
                recomputed = gate.matched_gate(workload, body)
            except (ValueError, KeyError, TypeError) as error:
                recomputed = {'status': 'failed', 'failures': [getattr(error, 'code', 'invalid_gate_evidence')]}
            finally:
                sys.path.remove(str(ROOT / 'scripts'))
            if report.get('failures') and 'metrics' in recomputed:
                recomputed = dict(recomputed, status='failed', failures=recomputed['failures'] + report['failures'])
            _check(report.get('gate'), recomputed, role, 'gate')
            reproduced.append('gate (pilot_qualification.matched_gate, identical gate code at the source commit)')
        else:
            not_reproduced.append('gate: the gate code at the source commit differs from the accepted primitive')
    report_endpoints = {}
    for name, boundary in (('preparation_ms', 'run start through selection verification, asset install and daemon '
                                              'preparation'),
                           ('source_and_selection_verification_ms', 'run start to verified source and selection'),
                           ('asset_install_and_daemon_prepare_ms', 'asset install and daemon preparation only')):
        value = report.get(name)
        require(value is None or (_number(value) and value >= 0), 'negative_duration', role, name)
        report_endpoints[name] = dict(INSTALLED_CLOCK, value=value, boundary=boundary,
                                      observer='scripts/pilot_measurement.py run_matched')
    report_endpoints['external_build_time'] = {'value': report.get('external_build_time'), 'unit': 'none',
                                               'boundary': 'not measured by this producer', 'clock': None}
    report_endpoints['observable_ask_latency'] = {'value': 'not_applicable', 'unit': 'none', 'clock': None,
                                                  'boundary': 'the workload has no operator Ask decision'}
    gate = report.get('gate') if isinstance(report.get('gate'), dict) else {}
    profiles = sorted({t['profile'] for t in trials})
    return {
        'contract': OBSERVATION, 'role': role,
        'input': {'name': portable_name(path), 'producer': 'scripts/pilot_measurement.py (qualify-installed-pilot.py)',
                  'producer_format': INSTALLED_FORMAT, 'custody': held, 'manifest': None,
                  'evidence_sha256': hashlib.sha256(json.dumps([held['original_sha256'], None, None]).encode()).hexdigest()},
        'provenance': {
            'source': source,
            'binaries': {'status': 'declared_only', 'sha256': selected,
                         'detail': 'identity.selected self-declaration; the binaries are not retained'},
            'build': {'status': 'not_retained', 'profile': None, 'receipt_sha256': None,
                      'detail': 'prebuilt selected binaries; ' + str(report.get('external_build_time'))},
            'workload': {'definition': workload_name or 'unavailable at the source commit',
                         'harness_sha256_at_source': dict(harness, workload_file=report.get('workload_file_sha256')),
                         'status': 'verified_git_objects' if workload is not None and harness
                         and all(harness.values()) else 'unverified'},
            'profiles_and_policy': {'status': 'declared_only',
                                    'detail': 'identity.profiles, policy_sha256 and registry_sha256 are self-declared '
                                              '(policy_sha256 agrees with identity.selected.policy)'},
        },
        'environment': {'platform_kind': None, 'kernel': None, 'machine': None, 'cpu_count': [], 'mem_total_kb': [],
                        'host_instance': {'status': 'not_retained', 'detail': 'one fresh host process per arm on '
                                          'an unrecorded runner'}},
        'trace': {'requested': None, 'requested_status': 'not_recorded', 'observed': 'not_retained',
                  'requested_basis': 'the installed-host report records no observer or trace mode'},
        'primary_endpoint': 'host_start_ms',
        'endpoints': copy.deepcopy(INSTALLED_ENDPOINTS), 'stage_clock': dict(INSTALLED_CLOCK),
        'report_endpoints': report_endpoints,
        'engineering_criteria': 'none approved: engineering_budgets.latency_threshold_approved is false'
        if budgets['latency_threshold_approved'] is False
        else 'the producer declares an approved threshold; SOU-203 does not evaluate it',
        'outcome_semantics': INSTALLED_OUTCOMES,
        'gate': {'status': gate.get('status'), 'failures': gate.get('failures'),
                 'scope': 'producer development gate; not security, effectiveness or readiness'},
        'within_report_pairing': {
            'basis': 'control and protected arm of the same case with the same input_sha256, fresh host each, '
                     'control first (order bias retained)',
            'published_call_overhead_ms': (gate.get('metrics') or {}).get('call_overhead_ms'),
            'reproduced': any(item.startswith('gate') for item in reproduced),
            'use': 'reported only; never used to pair two reports'},
        'not_retained': {'trace_observed': 'this producer records no trace or observer mode',
                         'host_instance': 'the runner is not recorded',
                         'failed_arm_timings': 'kept in the original report; failed arms carry no measured value here',
                         **({} if all(t['endpoints']['host_elapsed_ms'] is not None for t in trials
                                      if t['status'] == 'measured')
                            else {'host_elapsed_ms': 'not written by this producer revision'})},
        'design': {'plan': ['single_run'], 'samples_per_profile': None, 'profiles': profiles,
                   'trial_plan': {'workload_sha256': report.get('workload_sha256'), 'arms': ['control', 'protected'],
                                  'cases': len({k[0] for k in keys})},
                   'pairing_design': None, 'cluster_unit': 'report (one dispatch)', 'host_unit': 'fresh host per arm'},
        'status_mapping': dict(INSTALLED_STATUS_MAPPING),
        'runs': [{'index': 1, 'declared_kind': 'single_run', 'condition': condition, 'qualified': qualified,
                  'disqualification': None if qualified else 'failed_checks:' + ','.join(failed_checks),
                  'exit_code': None, 'failure': report_failures or None, 'wall_seconds': None, 'cache_drop': None,
                  'conditions': {}}],
        'trials': trials,
        'reproduction': {'status': 'reproduced_from_retained_trials' if not not_reproduced else 'partial',
                         'checked': reproduced, 'not_reproduced': not_reproduced},
    }


# ------------------------------------------------------------------ sw-native-pilot-prerequisites/1 adapter

PREPARATION_FORMAT = 'sw-native-pilot-prerequisites/1'
PREPARATION_MARKER = 'sw-pilot-preparation/1'
PREPARATION_STAGES = ('git', 'bwrap')
# Exactly the receipt fields written by prepare-native-pilot-prerequisites.py (accepted producer contract).
PREPARATION_KEYS = {'format', 'source_commit', 'archives', 'tools', 'execution_inputs', 'flags', 'binaries',
                    'generation_tree_sha256', 'stages', 'status'}
PREPARATION_ENDPOINTS = {'stage_seconds': {
    'metric': 'native_prerequisite_stage_elapsed', 'clock': 'preparation_monotonic', 'unit': 's',
    'observer': 'scripts/prepare-native-pilot-prerequisites.py', 'source_field': 'stages.<stage>.seconds',
    'start': 'stage start after archive extraction',
    'end': 'git: build, verify and checkpoint publish (or verified reuse); bwrap: meson setup and compile',
    'role': 'preparation cost only; never an Ask or host latency'}}


def _normalize_preparation(role, path, receipt, held, git):
    """One successful prerequisite receipt: one trial per stage. A failed preparation writes no receipt."""
    require(set(receipt) == PREPARATION_KEYS, 'report_shape_invalid', role,
            'fields differ from the accepted receipt: ' + ','.join(sorted(set(receipt) ^ PREPARATION_KEYS)))
    commit, stages = receipt.get('source_commit'), receipt.get('stages')
    require(isinstance(commit, str) and re.fullmatch('[0-9a-f]{40}', commit), 'source_identity_malformed', role,
            'source_commit')
    require(receipt.get('status') == 'built-not-qualified', 'receipt_stage_contradiction', role, 'status')
    require(isinstance(stages, dict) and set(stages) == set(PREPARATION_STAGES), 'missing_required_trial', role,
            'stages')
    binaries = receipt.get('binaries')
    require(isinstance(binaries, dict) and set(binaries) == set(PREPARATION_STAGES)
            and all(isinstance(b, dict) and isinstance(b.get('sha256'), str)
                    and re.fullmatch('[0-9a-f]{64}', b['sha256']) for b in binaries.values()),
            'invalid_digest', role, 'binaries')
    archives, flags = receipt.get('archives'), receipt.get('flags')
    require(isinstance(archives, dict) and set(archives) == set(PREPARATION_STAGES)
            and all(isinstance(a, dict) and isinstance(a.get('url'), str) and _hex(a.get('sha256'))
                    for a in archives.values()), 'report_shape_invalid', role, 'archives')
    require(isinstance(flags, dict) and set(flags) == set(PREPARATION_STAGES)
            and all(isinstance(f, list) and all(isinstance(x, str) for x in f) for f in flags.values()),
            'report_shape_invalid', role, 'flags')
    require(isinstance(receipt.get('tools'), dict) and isinstance(receipt.get('execution_inputs'), dict),
            'report_shape_invalid', role, 'tools and execution_inputs must be objects')
    require(_hex(receipt.get('generation_tree_sha256')), 'invalid_digest', role, 'generation_tree_sha256')
    trials = []
    for stage in PREPARATION_STAGES:
        entry = stages[stage]
        require(isinstance(entry, dict), 'trial_table_malformed', role, f'stages.{stage}')
        expected_keys = {'status', 'seconds', 'checkpoint_sha256'} if stage == 'git' else {'status', 'seconds'}
        require(set(entry) == expected_keys, 'report_shape_invalid', role, f'stages.{stage} fields')
        require(stage != 'git' or _hex(entry['checkpoint_sha256']), 'invalid_digest', role,
                'stages.git.checkpoint_sha256')
        allowed = ('built', 'reused') if stage == 'git' else ('built',)
        require(entry.get('status') in allowed, 'receipt_stage_contradiction', role,
                f'stages.{stage}.status={entry.get("status")!r} in a completed receipt')
        value = entry.get('seconds')
        require(_number(value), 'nonfinite_or_missing_duration', role, f'stages.{stage}.seconds')
        require(value >= 0, 'negative_duration', role, f'stages.{stage}.seconds')
        trials.append({'id': f'r01/{stage}', 'run': 1, 'profile': stage, 'sample_index': 0,
                       'condition': 'reused_verified_checkpoint' if entry['status'] == 'reused' else 'built_from_source',
                       'run_qualified': True, 'status': 'measured', 'reason': None,
                       'endpoints': {'stage_seconds': value}, 'stages': {}})
    tree = git.tree_of(commit)
    source = {'status': 'commit_verified_tree_not_declared' if tree else 'unverified_commit_not_in_repository',
              'commit': commit, 'tree': None, 'files_sha256': None,
              'method': 'git rev-parse <commit>^{tree}' if tree else None}
    harness = {'scripts/prepare-native-pilot-prerequisites.py':
               git.file_sha256(commit, 'scripts/prepare-native-pilot-prerequisites.py')} if tree else None
    return {
        'contract': OBSERVATION, 'role': role,
        'input': {'name': portable_name(path), 'producer': 'scripts/prepare-native-pilot-prerequisites.py',
                  'producer_format': PREPARATION_FORMAT, 'custody': held, 'manifest': None,
                  'evidence_sha256': hashlib.sha256(json.dumps([held['original_sha256'], None, None]).encode()).hexdigest()},
        'provenance': {
            'source': source,
            'binaries': {'status': 'declared_only', 'sha256': {k: v['sha256'] for k, v in binaries.items()},
                         'detail': 'receipt self-declaration of the built git and bubblewrap binaries'},
            'build': {'status': 'declared_flags', 'profile': None, 'receipt_sha256': held['original_sha256'],
                      'detail': 'make/meson flags are declared in the receipt; no cargo profile applies'},
            'workload': {'definition': 'git and bubblewrap prerequisite build stages', 'harness_sha256_at_source': harness,
                         'status': 'verified_git_objects' if harness and all(harness.values()) else 'unverified'},
            'profiles_and_policy': {'status': 'not_applicable', 'detail': 'preparation builds prerequisites only'},
        },
        'environment': {'platform_kind': None, 'kernel': None, 'machine': None, 'cpu_count': [], 'mem_total_kb': [],
                        'host_instance': {'status': 'not_retained', 'detail': 'the receipt records no host'}},
        'trace': {'requested': None, 'requested_status': 'not_applicable', 'observed': 'not_applicable',
                  'requested_basis': 'preparation runs no Ask observer'},
        'primary_endpoint': 'stage_seconds',
        'endpoints': copy.deepcopy(PREPARATION_ENDPOINTS),
        'stage_clock': {'clock': 'preparation_monotonic', 'unit': 's', 'observer': PREPARATION_ENDPOINTS[
            'stage_seconds']['observer']},
        'engineering_criteria': 'none approved for preparation stage time',
        'not_retained': {'failed_preparation': 'a failed preparation writes no receipt; its stages exist only in '
                                               'the command output', 'host_instance': 'not recorded'},
        'design': {'plan': ['single_run'], 'samples_per_profile': 1, 'profiles': list(PREPARATION_STAGES),
                   'trial_plan': {'stages': list(PREPARATION_STAGES)}, 'pairing_design': None,
                   'cluster_unit': 'receipt (one preparation)', 'host_unit': 'one receipt'},
        'status_mapping': {'measured': 'completed stage with finite non-negative seconds',
                           'failed': 'not representable: a completed receipt with a failed stage is rejected',
                           'timed_out': 'not representable in a receipt', 'incomplete': 'not representable',
                           'not_run': 'not representable'},
        'runs': [{'index': 1, 'declared_kind': 'single_run', 'condition': 'mixed', 'qualified': True,
                  'disqualification': None, 'exit_code': None, 'failure': None, 'wall_seconds': None,
                  'cache_drop': None, 'conditions': {}}],
        'trials': trials,
        'reproduction': {'status': 'no_published_aggregates', 'checked': [],
                         'not_reproduced': ['the receipt publishes no aggregate to reproduce']},
    }


# ------------------------------------------------------------------ statistics (pure)

def describe(values):
    """n, nearest-rank p50/p95 on unrounded values, min and max; never drops an observation."""
    ordered = sorted(values)
    return {'n': len(ordered), 'p50': nearest_rank(ordered, .5), 'p95': nearest_rank(ordered, .95),
            'min': ordered[0] if ordered else None, 'max': ordered[-1] if ordered else None}


def stratum_side(observation, key):
    profile, condition = key
    primary = observation['primary_endpoint']
    rows = [t for t in observation['trials'] if t['profile'] == profile and t['condition'] == condition]
    included = [t for t in rows if t['run_qualified']]
    counts = {s: sum(t['status'] == s for t in included) for s in STATUSES}
    measured = [t for t in included if t['status'] == 'measured']
    runs = sorted({t['run'] for t in included})
    values = [t['endpoints'][primary] for t in measured]
    highest = sorted(measured, key=lambda t: (-t['endpoints'][primary], t['id']))[:3]
    stages = {}
    for t in measured:
        for name, value in t['stages'].items():
            stages.setdefault(name, []).extend(value if isinstance(value, list) else [value])
    endpoints = {name: describe([t['endpoints'][name] for t in measured if t['endpoints'].get(name) is not None])
                 for name in sorted(observation['endpoints'])}
    complete = bool(included) and counts['measured'] == len(included)
    dist = describe(values)
    if primary != 'continuation_ms':
        targets = {'primary': observation.get('engineering_criteria', 'no approved criterion for ' + primary)}
    else:
        if not complete or dist['p95'] is None:
            target = 'not_evaluable_incomplete_denominator' if included else 'not_evaluable_no_qualified_run'
        else:
            target = 'met' if dist['p95'] <= CONTINUATION_TARGET_MS else 'not_met'
        pending = [t['endpoints'].get('first_pending_asset_verification_ms') for t in measured]
        pending = [v for v in pending if v is not None]
        targets = {'continuation_p95_le_3000_ms': target,
                   'first_pending_le_5000_ms': 'not_evaluated_by_this_evidence (SOU-105 acceptance owns it); '
                                               'collector lower-bound max '
                                               + (f'{max(pending):.3f} ms' if pending else 'n/a')}
    return {
        'planned': len(rows), 'qualified_run_trials': len(included),
        'attempted': sum(t['status'] != 'not_run' for t in rows),
        'status_counts_all_runs': {s: sum(t['status'] == s for t in rows) for s in STATUSES},
        'excluded_unqualified_run_trials': len(rows) - len(included),
        'excluded_runs': sorted({t['run'] for t in rows if not t['run_qualified']}),
        'status_counts': counts, 'complete_denominator': complete,
        'runs': runs, 'independent_clusters': len(runs),
        'primary_endpoint': primary, 'unit': observation['endpoints'][primary]['unit'],
        'primary': dist,
        'primary_highest': [{'trial': t['id'], 'value': t['endpoints'][primary]} for t in highest],
        'primary_by_run': {str(r): describe([t['endpoints'][primary] for t in measured if t['run'] == r])
                           for r in runs},
        'first_trial_per_run': [{'trial': t['id'], 'value': t['endpoints'][primary]}
                                for t in measured if t['sample_index'] == 0],
        'endpoints': endpoints,
        'stages': {name: describe(found) for name, found in sorted(stages.items())},
        'engineering_targets': targets,
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
    equal('cpu_count', 'environment.cpu_count', 'cpu_count_differs', 'reported CPU count differs')
    # A reported MemTotal can differ between boots of one host as well as between hosts, and no materiality
    # tolerance is approved. A difference leaves same-host conditions unestablished; it is neither a
    # contradiction nor proof of different hosts.
    a_mem, b_mem = base['environment']['mem_total_kb'], cand['environment']['mem_total_kb']
    if a_mem and b_mem and a_mem != b_mem:
        add('memory', 'unverified', ['environment.mem_total_kb'], 'mem_total_differs_materiality_unassessed',
            'reported MemTotal_kb differs; same-boot/same-host conditions are not established and no tolerance '
            'is approved', (a_mem, b_mem))
    else:
        equal('memory', 'environment.mem_total_kb', 'mem_total_differs_materiality_unassessed')
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
    if base['primary_endpoint'] != cand['primary_endpoint']:
        add('primary_endpoint', 'contradiction', ['primary_endpoint'], 'endpoint_mismatch', 'different primary endpoint',
            (base['primary_endpoint'], cand['primary_endpoint']))
    for name in sorted(set(base['endpoints']) | set(cand['endpoints'])):
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
    equal('design', 'design.trial_plan', 'trial_design_mismatch')
    if base['design']['profiles'] != cand['design']['profiles']:
        add('profiles', 'contradiction', ['design.profiles'], 'trial_design_mismatch', 'differs',
            (base['design']['profiles'], cand['design']['profiles']))
    # Identical evidence is checked for provenance like any other pair: being the same bytes proves neither
    # the source nor the binaries nor the build profile.
    a, b = base['provenance'], cand['provenance']
    for name in ('source', 'workload'):
        if a[name]['status'] != 'verified_git_objects' or b[name]['status'] != 'verified_git_objects':
            if name == 'source' and 'commit_tree_verified' in a[name]['status'] + b[name]['status']:
                add(name, 'unverified', ['provenance.source.files_sha256'], 'source_contents_unverified',
                    'commit and tree verified; tracked file contents are not bound by a declared files_sha256',
                    (a[name]['status'], b[name]['status']))
                continue
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
    primary = base['primary_endpoint']
    index = {t['id']: t for t in cand['trials']}
    diffs = []
    for t in base['trials']:
        other = index.get(t['id'])
        if (t['profile'], t['condition']) == key and t['run_qualified'] and t['status'] == 'measured' \
                and other and other['run_qualified'] and other['status'] == 'measured':
            diffs.append(other['endpoints'][primary] - t['endpoints'][primary])
    result = describe(diffs)
    result.update(kind='distribution_of_paired_differences', direction='candidate_minus_baseline',
                  endpoint=primary, unit=base['endpoints'][primary]['unit'],
                  all_zero=bool(diffs) and all(d == 0 for d in diffs))
    return result


def marginal_differences(a, b):
    def diff(x, y):
        return None if x is None or y is None else y - x
    out = {'kind': 'difference_of_marginal_percentiles_not_percentile_of_paired_differences',
           'direction': 'candidate_minus_baseline', 'endpoint': a['primary_endpoint'], 'unit': a['unit'],
           'primary': {q: diff(a['primary'][q], b['primary'][q]) for q in ('p50', 'p95', 'max')},
           'stages': {}}
    for name in sorted(set(a['stages']) & set(b['stages'])):
        out['stages'][name] = {q: diff(a['stages'][name][q], b['stages'][name][q]) for q in ('p50', 'p95')}
    out['stages_one_side_only'] = sorted(set(a['stages']) ^ set(b['stages']))
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
    control = None
    if identity:
        control = {'evidence_identical': True,
                   'meaning': 'comparator control only: identical evidence must give zero paired differences. It '
                              'establishes no provenance, no compatibility and no performance change.',
                   'strata': [{'profile': key[0], 'condition': key[1],
                               'paired_differences': paired_differences(base, cand, key)}
                              for key in strata_keys(base)]}
        control['paired_trials'] = sum(s['paired_differences']['n'] for s in control['strata'])
        control['all_zero'] = control['paired_trials'] > 0 and all(
            s['paired_differences']['all_zero'] for s in control['strata'] if s['paired_differences']['n'])
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
    families = sorted({base['input']['producer_format'], cand['input']['producer_format']})
    return {
        'contract': COMPARISON, 'status': 'evaluated', 'classification': classification,
        'basis': 'identity_control' if identity else 'two_reports',
        'reasons': sorted(reasons, key=lambda r: (r['code'], r['dimension'])),
        'dimensions': dims, 'pairing': pair, 'strata': strata, 'identity_control': control,
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
                        *('repeated_trials_are_dependent: ' + FAMILIES[f]['dependence'] for f in families)],
            'intervals': None},
        'engineering_targets': {f: FAMILIES[f]['criteria'] for f in families},
        'observer_semantics': {role: FAMILIES[o['input']['producer_format']]['observer']
                               for role, o in (('baseline', base), ('candidate', cand))},
        'percentile_definition': ' '.join([PERCENTILE] + [FAMILIES[f]['percentile'] for f in families]),
        'scope': SCOPE + [line for f in families for line in FAMILIES[f]['scope']],
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
    names = sorted({name for _, observation in observations for name in observation['endpoints']})
    rows = []
    for role, observation in observations:
        for t in observation['trials']:
            rows.append([role, t['id'], t['run'], t['profile'], t['condition'], t['run_qualified'], t['status'],
                         t['reason'] or '', *(_fmt(t['endpoints'].get(name)) for name in names)])
    return render_csv(rows, ['role', 'trial_id', 'run', 'stratum', 'condition', 'run_qualified', 'status', 'reason',
                             *names])


def strata_csv(result):
    rows = []
    for s in result['strata']:
        for role in ('baseline', 'candidate'):
            side = s[role]
            if side is None:
                rows.append([s['profile'], s['condition'], role, 'absent'] + [''] * 20)
                continue
            c, a, d = side['status_counts'], side['status_counts_all_runs'], side['primary']
            rows.append([s['profile'], s['condition'], role, 'comparable' if s['comparable'] else 'not_comparable',
                         side['planned'], side['attempted'], side['excluded_unqualified_run_trials'],
                         *(a[k] for k in STATUSES), side['qualified_run_trials'], *(c[k] for k in STATUSES),
                         side['independent_clusters'], side['primary_endpoint'], side['unit'],
                         _fmt(d['p50']), _fmt(d['p95']), _fmt(d['max'])])
    return render_csv(rows, ['stratum', 'condition', 'role', 'comparability', 'planned', 'attempted',
                             'excluded_unqualified_run_trials', *('all_runs_' + k for k in STATUSES),
                             'qualified_run_trials', *('qualified_' + k for k in STATUSES), 'runs',
                             'primary_endpoint', 'unit', 'primary_p50', 'primary_p95', 'primary_max'])


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
    units = sorted({f"{x['primary_endpoint']} ({x['endpoints'][x['primary_endpoint']]['unit']})" for x in o.values()})
    lines += ['', '## Strata (primary endpoint: ' + ', '.join(units) + ')', '',
              'Counts are measured / failed / timed out / incomplete / not run. Distributions use qualified runs '
              'only; trials of unqualified runs stay counted under all runs.', '',
              '| Stratum | Condition | Role | Planned | All runs | Excluded (unqualified runs) | Qualified runs | Runs | '
              'p50 | p95 | max | Engineering criterion |',
              '|---|---|---|---:|---|---:|---|---:|---:|---:|---:|---|']
    for s in result['strata']:
        for role in ('baseline', 'candidate'):
            side = s[role]
            if side is None:
                lines.append(f"| {s['profile']} | {s['condition']} | {role} | – | absent | – | – | – | – | – | – | – |")
                continue
            c, d, a = side['status_counts'], side['primary'], side['status_counts_all_runs']
            lines.append(f"| {s['profile']} | {s['condition']} | {role} | {side['planned']} | "
                         f"{' / '.join(str(a[k]) for k in STATUSES)} | "
                         f"{side['excluded_unqualified_run_trials']} | {c['measured']} / {c['failed']} / {c['timed_out']} / {c['incomplete']} / {c['not_run']} | "
                         f"{side['independent_clusters']} | {_ms(d['p50'])} | {_ms(d['p95'])} | {_ms(d['max'])} | "
                         f"{side['engineering_targets'].get('continuation_p95_le_3000_ms', 'none approved')} |")
    control = result.get('identity_control')
    if control:
        lines += ['', '## Identity control', '', f"Identical evidence on both sides: {control['paired_trials']} trial "
                  f"pairs, all paired differences zero: **{control['all_zero']}**. {control['meaning']}"]
    for role in ('baseline', 'candidate'):
        report_level = o[role].get('report_endpoints')
        if report_level:
            lines += ['', f'## Report-level endpoints ({role}, single values, never compared)', '']
            lines += [f"- `{name}`: {_ms(e['value']) if isinstance(e['value'], (int, float)) else e['value']} "
                      f"{e['unit']} ({e['boundary']})" for name, e in sorted(report_level.items())]
    lines += ['', '## Differences (candidate minus baseline, primary endpoint)', '']
    shown = False
    for s in result['strata']:
        if not s['comparable']:
            continue
        shown = True
        m = s['marginal_differences']['primary']
        text = (f"- {s['profile']} / {s['condition']}: marginal percentile differences p50 {_ms(m['p50'])}, "
                f"p95 {_ms(m['p95'])}, max {_ms(m['max'])}")
        p = s['paired_differences']
        if p:
            text += (f"; paired differences (n={p['n']}) p50 {_ms(p['p50'])}, p95 {_ms(p['p95'])}, "
                     f"min {_ms(p['min'])}, max {_ms(p['max'])}, all zero: {p['all_zero']}")
        lines.append(text)
    if not shown:
        lines.append('- none: no comparable stratum. No speed-up, merged p95 or verdict is reported.')
    lines += ['', '## Observer and trace semantics', '']
    lines += [f"- {role}: timing {s['timing']}; trace {s['trace']}"
              for role, s in sorted(result['observer_semantics'].items())]
    lines += ['', '## Limits', '', f"- Percentiles: {result['percentile_definition']}",
              '- Inference: descriptive only. ' + ' '.join(result['inference']['reasons']),
              '- Not retained: ' + ', '.join(sorted({k for x in o.values() for k in x['not_retained']})) + '.']
    lines += ['- Outcomes: ' + text for text in sorted({x['outcome_semantics'] for x in o.values()
                                                        if x.get('outcome_semantics')})]
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
        try:
            path.mkdir(mode=0o700, parents=True)
        except OSError as error:  # an environment/destination failure, never an evidence verdict
            raise Rejected('output_destination_unavailable', 'output', type(error).__name__) from None
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
        parser.add_argument('--' + role, type=Path, required=True,
                            help='one report: sw-ask-series/1 summary, sw-pilot-ask-acceptance/1 Ask qualification, '
                                 'sw-installed-pilot-matched/1 installed host or sw-native-pilot-prerequisites/1 '
                                 'preparation receipt')
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
    except OSError as error:
        print(json.dumps({'status': 'usage_error', 'code': 'output_destination_unavailable',
                          'detail': type(error).__name__}))
        return 3
    print(json.dumps({'status': result['status'], 'classification': result.get('classification'),
                      'rejection': result.get('rejection', {}).get('code')}, sort_keys=True))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
