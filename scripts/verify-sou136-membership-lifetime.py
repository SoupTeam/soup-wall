#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused disposable Ubuntu qualification for SOU-136; no retry or mock fallback.

Only --run starts processes. Original selected filesystem/Git churn is separate
from explicitly owned resource/membership calibration. Every attempted case is
checkpointed before launch; only the final grader can publish a passing run.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('sou136_selected', ROOT / 'scripts/verify-sou89-selected-liveness.py')
SELECTED = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SELECTED)
SOU86, RESOURCE, BASE = SELECTED.SOU86, SELECTED.RESOURCE, SELECTED.BASE
require, sha, digest = SOU86.require, SOU86.sha, SOU86.digest

FORMAT = 'sou136-linux-membership-lifetime/1'
PROFILES = ('filesystem', 'git')
CYCLES = 70
SIBLING_INTERVAL = 10
CONTROL_NAMES = ('memory', 'pids', 'membership')
REQUIRED_ATTEMPTS = CYCLES * 2 + 2 * 2 + len(CONTROL_NAMES)
REPORT_BYTES = 16 * 1024 * 1024
HASH = re.compile(r'[0-9a-f]{64}')
STAGES = frozenset({'planned', 'create', 'initialize', 'useful', 'sibling_before', 'crash',
                    'cleanup', 'sibling_after', 'reclaim', 'dispatch', 'inject', 'complete'})
FAILURES = frozenset({'case_failed', 'collector_closed_before_response', 'cancelled',
                      'cleanup_failed', 'qualification_failed', 'prerequisite_failed'})
# Extend only the private imported observer's finite diagnostic projection.
# This does not change its kernel observation or enforcement grading.
RESOURCE.MEMBERSHIP_PHASES |= frozenset({
    'proc_root_open', 'proc_root_fs', 'proc_namespace', 'member_pidfd_open', 'member_pidfd_poll',
    'member_proc_open', 'member_proc_fs', 'member_proc_type', 'member_identity_read',
    'member_identity_parse', 'member_identity_changed', 'member_cgroup_open', 'member_cgroup_read',
    'member_departure_still_listed', 'member_departure_live', 'member_departure_reused',
    'member_departure_unverified', 'member_cgroup_parse',
})
DEPENDENCIES = (
    'scripts/verify-sou89-selected-liveness.py', 'scripts/verify-sou86-crash-supervision.py',
    'scripts/verify-sou79-resource-budgets.py', 'scripts/verify-sou62-real-mcp.py',
    'scripts/verify-sou68-real-mcp.py', 'scripts/install-sou62-filesystem-profile.py',
    'scripts/install-sou68-git-profile.py', 'scripts/mcp-admission-demo.py',
    'rule_baseline/rule_baseline.py', 'rule_baseline/git_readonly_v1/rule_baseline.py',
)
DEFAULT_LIMITS = dict(SELECTED.DEFAULT_BUDGET)
PEER_LIMITS = dict(DEFAULT_LIMITS, wallMillis=SOU86.PEER_WALL_MILLIS)
CONTROL_LIMITS = {
    'memory': dict(DEFAULT_LIMITS, memoryMaxBytes=128 * 1024 * 1024),
    'pids': dict(DEFAULT_LIMITS, pidsMax=32),
    'membership': dict(DEFAULT_LIMITS),
}


# Register observer objects before their __init__ can start a thread. These are
# private imported qualification helpers, not runtime or application globals.
OBSERVERS = []


def tracked_observer(base):
    class Owned(base):
        def __new__(cls, *args, **kwargs):
            instance = super().__new__(cls)
            OBSERVERS.append(instance)
            return instance

        def finish(self):
            if not hasattr(self, '_owned_finish'):
                self._owned_finish = super().finish()
            return self._owned_finish
    return Owned


RESOURCE.KernelObserver = tracked_observer(RESOURCE.KernelObserver)
RESOURCE.Capture = tracked_observer(RESOURCE.Capture)
BASE.ProcessWitness = tracked_observer(BASE.ProcessWitness)


def owned_client(factory, rig, *args, **kwargs):
    # Register before constructor effects; parent finalization can inspect a
    # partial instance even if acquisition/health observation raises.
    if not isinstance(factory, type):
        return factory(rig, *args, **kwargs)  # mocked orchestration controls
    instance = object.__new__(factory)
    if not hasattr(rig, '_owned_clients'):
        rig._owned_clients = []
    rig._owned_clients.append(instance)
    factory.__init__(instance, rig, *args, **kwargs)
    return instance


def cleanup_partial(instance):
    errors = []
    process = getattr(instance, 'process', getattr(instance, 'daemon', None))
    if process is not None:
        try:
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
            BASE.DEMO.stop(process)
            process.wait(timeout=10)
        except Exception:
            errors.append('owned_process_cleanup_failed')
        for stream in ('stdin', 'stdout', 'stderr'):
            value = getattr(process, stream, None)
            if value is not None:
                try: value.close()
                except Exception: errors.append('owned_stream_cleanup_failed')
    return errors


def close_rig(rig):
    result = {'clients': []}
    errors = []
    seen = set()
    for client in [*getattr(rig, '_owned_clients', []), *getattr(rig, 'clients', [])]:
        if id(client) in seen:
            continue
        seen.add(id(client))
        try: result['clients'].append(client.close())
        except Exception:
            errors.append('client_cleanup_failed')
            errors.extend(cleanup_partial(client))
    # Every owned daemon/observer receives cleanup even after an earlier error.
    daemon = getattr(rig, 'daemon', None)
    if daemon is not None:
        try:
            BASE.DEMO.stop(daemon)
            daemon.wait(timeout=10)
        except Exception: errors.append('daemon_cleanup_failed')
    for key, attribute in [('daemon_process', 'daemon_witness'),
                           ('daemon_stdout', 'daemon_stdout'), ('daemon_stderr', 'daemon_stderr')]:
        observer = getattr(rig, attribute, None)
        if observer is None:
            errors.append('daemon_observation_missing')
            continue
        try: result[key] = observer.finish()
        except Exception: errors.append('daemon_observation_failed')
    try: result['audit'] = rig.audit()
    except Exception: errors.append('audit_observation_failed')
    if errors: result['error'] = 'cleanup_failed'
    return result


class RunCancelled(Exception):
    """Finite cancellation classification; never persist a signal payload."""


def identity_projection(value):
    result = {k: v for k, v in value.items() if k in {
        'pid', 'start_time_ticks', 'parent_pid', 'process_group', 'session', 'cpu_ticks'
    } and type(v) is int and 0 <= v < 2**64}
    if type(value.get('parent_process')) is bool:
        result['parent_process'] = value['parent_process']
    for key, allowed in (('state', {'R', 'S', 'D', 'Z', 'X', 'x', 'T', 't', 'I'}),
                         ('trusted_role', {'owner', 'pid1'}),
                         ('fixture_role', {'direct', 'detached'}),
                         ('worker_role', {'memory', 'cpu', 'sleep'})):
        if value.get(key) is None or value.get(key) in allowed:
            result[key] = value.get(key)
    for key in ('signal_delivered', 'detached_session_verified'):
        if type(value.get(key)) is bool:
            result[key] = value[key]
    return result


def stream_projection(value):
    result = {k: value[k] for k in ('bytes', 'buffer_peak', 'marker_leak', 'thread_stopped') if k in value}
    if HASH.fullmatch(str(value.get('sha256', ''))):
        result['sha256'] = value['sha256']
    # Observer errors originate in a fixed local enum, not arbitrary exceptions.
    result['error'] = value.get('error') if value.get('error') in {
        None, 'protocol_line_limit', 'protocol_observation_failed', 'stream_read_failed',
        'partial_protocol_eof', 'protocol_queue_limit'
    } else 'stream_read_failed'
    records = value.get('records', [])
    require(len(records) <= 256, 'protocol_record_limit')
    result['records'] = [{k: row[k] for k in ('id', 'sha256', 'bytes', 'successful_result')
                          if k in row and (k != 'id' or type(row[k]) is int)} for row in records]
    result['events'] = [event for row in value.get('events', [])[:128]
                        if (event := RESOURCE.safe_event(row)) is not None]
    result['refusals'] = [code for code in value.get('refusals', [])[:16] if code in RESOURCE.STATIC_REFUSALS]
    return result


def client_projection(value, limits):
    """Persist accepted finite metadata, never budget paths or raw streams."""
    result = {k: value[k] for k in ('exit_code', 'forced_cleanup', 'budgeted', 'direct_original_control',
                                   'profile_sha256', 'budget_sha256') if k in value}
    result['budget'] = dict(limits)
    if isinstance(value.get('epoch'), str) and len(value['epoch']) <= 128:
        result['epoch_sha256'] = digest(value['epoch'].encode())
    if (owner := SOU86.safe_owner(value.get('owner'))) is not None:
        result['owner'] = owner
    process = value.get('process', {})
    result['process'] = {k: process.get(k) for k in ('all_stopped', 'descendant_count')}
    for key in ('observed', 'remaining'):
        require(len(process.get(key, [])) <= 256, 'process_witness_limit')
        result['process'][key] = [identity_projection(row) for row in process.get(key, [])]
    for key in ('stdout', 'stderr'):
        result[key] = stream_projection(value.get(key, {}))
    kernel = copy.deepcopy(value.get('kernel'))
    if isinstance(kernel, dict):
        # KernelObserver already retains only controls, counters and identities.
        # Whitelist its keys so future observer additions cannot expose paths.
        kernel = {k: kernel[k] for k in (
            'leaf', 'inode', 'first', 'last', 'samples', 'memory_peak_bytes', 'tasks_peak',
            'counter_max', 'remaining', 'members', 'leaf_removed', 'error', 'thread_stopped',
            'error_phase', 'error_errno', 'controller_loss_seen', 'shutdown_read',
            'leaf_duration_millis', 'elapsed_millis') if k in kernel}
        for key in ('members', 'remaining'):
            require(len(kernel.get(key, [])) <= 256, 'kernel_witness_limit')
            kernel[key] = [identity_projection(row) for row in kernel.get(key, [])]
    result['kernel'] = kernel
    return result


def crash_projection(value, limits):
    keys = ('case', 'server_kind', 'signal_target', 'signal', 'guardian_stop_observed',
            'armed_before_signal', 'in_flight', 'startup', 'cleanup_race',
            'stdin_held_open_at_injection', 'observation_bound_millis',
            'protected_work_stopped_within_bound', 'all_identities_gone_within_bound',
            'leaf_removed_within_bound', 'process_stop_millis', 'identities_gone_millis',
            'leaf_remove_millis', 'protection_acceptance', 'previous_effects_rolled_back',
            'native_retirement', 'immediate_native_retirement_claimed', 'budgeted',
            'acceptance_fallback_used')
    result = {k: value[k] for k in keys if k in value}
    result['owner'] = SOU86.safe_owner(value.get('owner'))
    result['target'] = identity_projection(value.get('target', {}))
    for key in ('observed_processes', 'live_at_deadline', 'identities_present_at_deadline'):
        require(len(value.get(key, [])) <= 256, 'crash_witness_limit')
        result[key] = [identity_projection(row) for row in value.get(key, [])]
    result['client'] = client_projection(value['client'], limits)
    return result


def checkpoint(path, report):
    require(len(report['attempts']) <= REQUIRED_ATTEMPTS, 'attempt_ledger_limit')
    require(all(row['stage'] in STAGES for row in report['attempts']), 'invalid_attempt_stage')
    require(all(row.get('failure_code') is None or row['failure_code'] in FAILURES
                for row in report['attempts']), 'invalid_failure_code')
    report['passed'] = sum(row['status'] == 'pass' for row in report['attempts'])
    failed_attempts = sum(row['status'] == 'fail' for row in report['attempts'])
    report['failed'] = max(failed_attempts, int('error_code' in report))
    report['incomplete'] = REQUIRED_ATTEMPTS - report['passed'] - failed_attempts
    snapshot = copy.deepcopy(report)
    raw = json.dumps(snapshot, ensure_ascii=True, separators=(',', ':')).encode() + b'\n'
    require(len(raw) <= REPORT_BYTES, 'report_byte_limit')
    require(not any(marker in raw for marker in RESOURCE.MARKERS), 'unsafe_evidence_payload')
    temporary = path.with_suffix('.checkpoint.tmp')
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def begin_attempt(report, save, kind, profile, cycle=None):
    require(kind in {'churn', 'sibling', 'capacity', 'control'}, 'invalid_attempt_kind')
    require(profile in PROFILES and len(report['attempts']) < REQUIRED_ATTEMPTS, 'invalid_attempt_profile')
    require((kind == 'churn' and type(cycle) is int and 1 <= cycle <= CYCLES)
            or (kind == 'control' and profile == 'filesystem' and cycle in CONTROL_NAMES)
            or (kind in {'sibling', 'capacity'} and cycle is None), 'invalid_attempt_cycle')
    case = f'{kind}-{profile}' + (f'-{cycle}' if cycle is not None else '')
    require(not any(row['case'] == case for row in report['attempts']), 'duplicate_attempt')
    row = {'case': case, 'kind': kind, 'profile': profile, 'cycle': cycle,
           'stage': 'planned', 'stages': ['planned'], 'status': 'incomplete',
           'unexpected_closure': False, 'failure_code': None, 'client': None}
    row['server_origin'] = 'owned-calibration-fixture' if kind == 'control' else 'original-selected'
    if kind == 'control':
        row['control'] = cycle
    report['attempts'].append(row)
    save()
    return row


def stage(row, save, name):
    require(name in STAGES and row['status'] == 'incomplete', 'invalid_stage_transition')
    row['stage'] = name
    if row['stages'][-1] != name:
        row['stages'].append(name)
    save()


def fail_attempt(row, error, client=None):
    code = 'cancelled' if isinstance(error, (RunCancelled, KeyboardInterrupt)) else 'case_failed'
    if str(error) == 'collector_closed_before_correlated_response':
        code = 'collector_closed_before_response'
    row['status'], row['failure_code'] = 'fail', code
    row['unexpected_closure'] = code == 'collector_closed_before_response' or (
        client is not None and row['stage'] not in {'crash', 'cleanup', 'complete'}
        and client.process.poll() is not None)
    row['failure_type'] = ('cancelled' if code == 'cancelled' else 'io' if isinstance(error, OSError)
                           else 'validation' if isinstance(error, ValueError) else 'other')
    number = getattr(error, 'errno', None)
    row['failure_errno'] = number if type(number) is int and 0 < number < 4096 else None


def useful_witness(client, expected=None, fixture=False):
    identifier = client.next_id if not fixture else 10
    semantic = (RESOURCE.useful(client, identifier=identifier, expected_hash=expected) if fixture
                else SELECTED.useful(client, expected_hash=expected))
    records = [row for row in client.stdout.records if row.get('id') == identifier
               and row.get('successful_result') is True]
    require(len(records) == 1, 'useful_wire_record_missing')
    return {'id': identifier, 'semantic_sha256': semantic, 'wire_sha256': records[0]['sha256']}


def grade_useful(witness, client):
    require(isinstance(witness, dict) and type(witness.get('id')) is int
            and HASH.fullmatch(str(witness.get('semantic_sha256', '')))
            and HASH.fullmatch(str(witness.get('wire_sha256', ''))), 'useful_identity_missing')
    require(any(row.get('id') == witness['id'] and row.get('sha256') == witness['wire_sha256']
                and row.get('successful_result') is True for row in client['stdout']['records']),
            'useful_wire_record_missing')


def grade_client(client, limits, *, crashed=False, failed=False):
    require(client.get('budget') == limits, 'fixed_budget_changed')
    SELECTED.grade_client_close(client, 'sou136', expect_failure=failed or crashed,
                                expected_signal=signal.SIGKILL if crashed else None,
                                require_kernel=True, budget=limits)
    RESOURCE.grade_kernel(client)
    for key in ('stdout', 'stderr'):
        RESOURCE.clean_stream(client[key])


def grade_control(row):
    name, client = row['control'], row['client']
    require(row['server_origin'] == 'owned-calibration-fixture', 'fixture_mislabeled_original')
    if name == 'membership':
        witness = row.get('violation', {})
        require(witness.get('event') == 'sou136_membership_calibration'
                and witness.get('passed') is True
                and witness.get('phase') == 'member_outside_leaf'
                and all(witness.get(key) is True for key in ('leader_same_lifetime',
                    'limits_unchanged', 'owned_child_reaped', 'leaf_removed', 'quarantine_removed'))
                and witness.get('production_transport_claimed') is False
                and HASH.fullmatch(str(row.get('native_control_log_sha256', ''))),
                'native_membership_control_unverified')
        return
    grade_client(client, CONTROL_LIMITS[name], failed=True)
    grade_useful(row['useful'], client)
    require(row.get('pending_dispatched') is True, 'pending_work_not_dispatched')
    require(not any(item.get('id') == 40 and item.get('successful_result') is True
                    for item in client['stdout']['records']), 'late_unadmitted_result_released')
    events = [event for event in client['stderr']['events'] if event['event'] == 'mcp_real_budget_end']
    reason = {'memory': 'mcp_budget_memory_exhausted', 'pids': 'mcp_budget_pids_exhausted',
              'membership': 'mcp_budget_membership_unverified'}[name]
    require(len(events) == 1 and events[0].get('observed_failure') is True
            and events[0].get('cleanup_verified') is True, 'budget_failure_event_missing')
    metadata = events[0].get('budget', {})
    require(metadata.get('reason') == reason and metadata.get('failed') is True
            and metadata.get('cleanup_verified') is True
            and metadata.get('budget_sha256') == client['budget_sha256']
            and metadata.get('leaf') == client['kernel']['leaf'], 'budget_failure_identity_mismatch')
    if name in ('memory', 'pids'):
        counter = 'oom_kill' if name == 'memory' else 'pids_max'
        role = 'memory' if name == 'memory' else 'sleep'
        require(client['kernel']['counter_max'][counter] > 0, 'real_pressure_counter_missing')
        require(len([m for m in client['kernel']['members'] if m.get('worker_role') == role])
                >= (2 if name == 'memory' else 1), 'actual_pressure_workers_missing')


def grade(report):
    require(report['format'] == FORMAT and report.get('failed') == 0
            and report.get('incomplete') == 0 and report.get('skipped') == 0,
            'qualification_incomplete')
    require(report.get('status') in {'incomplete', 'pass'} and 'error_code' not in report,
            'failed_run_cannot_be_promoted')
    require(report.get('scope') == 'focused-sou136-native' and report.get('retry_count') == 0,
            'qualification_scope_or_retry_changed')
    require(report.get('required_attempts') == report.get('passed') == REQUIRED_ATTEMPTS
            and report.get('cycles_per_original_profile') == CYCLES
            and report.get('sibling_probe_interval_cycles') == SIBLING_INTERVAL, 'qualification_denominator_changed')
    before = report.get('source_before', {})
    require(before == report.get('source_after') and before.get('dirty') is False
            and before.get('commit') == report.get('runtime_source_commit')
            and re.fullmatch(r'[0-9a-f]{40}', str(before.get('commit', '')))
            and re.fullmatch(r'[0-9a-f]{40}', str(before.get('tree', '')))
            and report.get('binaries_unchanged') is True, 'source_or_binary_changed')
    identities = report.get('identities', {})
    for name in ('agentfw', 'git_launcher', 'node', 'npm', 'bwrap', 'git', 'python', 'driver', 'fixture', 'sandbox_test_binary'):
        require(HASH.fullmatch(str(identities.get(name, ''))), 'runtime_identity_missing')
    require(set(identities.get('dependencies', {})) == set(DEPENDENCIES)
            and all(HASH.fullmatch(str(v)) for v in identities['dependencies'].values()), 'driver_identity_missing')
    require(report.get('delegation_removed') is True and report.get('cleanup_verified') is True,
            'owned_cleanup_incomplete')
    for profile in PROFILES:
        installation = report.get('installations', {}).get(profile, {})
        require(all(HASH.fullmatch(str(installation.get(key, ''))) for key in (
            'profile_sha256', 'registry_sha256', 'policy_sha256', 'package_tree_sha256', 'config_sha256')),
                'selected_installation_identity_missing')
        require(report.get('original_unchanged', {}).get(profile) is True
                and report.get('workspace_unchanged', {}).get(profile) is True, 'selected_inventory_changed')
    attempts = report['attempts']
    require(len(attempts) == REQUIRED_ATTEMPTS and len({a['case'] for a in attempts}) == REQUIRED_ATTEMPTS,
            'required_attempts_missing_or_duplicated')
    require(all(a.get('status') == 'pass' and a.get('stage') == 'complete'
                and a.get('failure_code') is None and a.get('unexpected_closure') is False
                and a.get('stages') and a['stages'][0] == 'planned' for a in attempts), 'attempt_failed_or_incomplete')
    controls = [a for a in attempts if a['kind'] == 'control']
    require({a.get('control') for a in controls} == set(CONTROL_NAMES)
            and len(controls) == len(CONTROL_NAMES), 'required_calibrations_missing')
    owners, epochs, leaves = set(), set(), set()
    last_sibling_ids = {}
    for profile in PROFILES:
        cycles = [a for a in attempts if a['kind'] == 'churn' and a['profile'] == profile]
        require(len(cycles) == CYCLES and [a['cycle'] for a in cycles] == list(range(1, CYCLES + 1)),
                'required_original_cycles_missing_or_duplicated')
        siblings = [a for a in attempts if a['kind'] == 'sibling' and a['profile'] == profile]
        restored = [a for a in attempts if a['kind'] == 'capacity' and a['profile'] == profile]
        require(len(siblings) == len(restored) == 1, 'sibling_or_restoration_missing')
        sibling, capacity = siblings[0], restored[0]
        for row in (sibling, capacity, *cycles):
            require(row.get('server_origin') == 'original-selected', 'original_replaced_with_fixture')
            grade_useful(row['useful'], row['client'])
            require(row['client'].get('profile_sha256') == report['installations'][profile]['profile_sha256'],
                    'original_profile_identity_mismatch')
            epoch = row['client'].get('epoch_sha256')
            owner = row['client'].get('owner', {}).get('instance')
            leaf = row['client']['kernel']['leaf']
            require(HASH.fullmatch(str(epoch or '')) and re.fullmatch(r'[0-9a-f]{32}', str(owner or ''))
                    and RESOURCE.LEAF.fullmatch(str(leaf)) and epoch not in epochs
                    and owner not in owners and leaf not in leaves, 'independent_session_identity_reused')
            epochs.add(epoch)
            owners.add(owner)
            leaves.add(leaf)
        grade_client(sibling['client'], PEER_LIMITS)
        grade_client(capacity['client'], DEFAULT_LIMITS)
        require(capacity.get('after_cycle') == CYCLES and capacity.get('reclamation_wait_millis') == 2500,
                'restored_capacity_not_fresh')
        require(capacity['useful']['semantic_sha256'] == sibling['useful']['semantic_sha256'],
                'restored_useful_work_changed')
        require(attempts.index(capacity) > attempts.index(cycles[-1]), 'restoration_precedes_churn')
        previous_probe = sibling['useful']['id']
        for row in cycles:
            SELECTED.grade_crash_observation(row['crash'], 'sou136', budget=DEFAULT_LIMITS)
            grade_client(row['client'], DEFAULT_LIMITS, crashed=True)
            require(row['crash']['client'] == row['client'], 'crash_client_identity_mismatch')
            require('sibling_before' not in row, 'unexpected_sibling_probe')
            if row['cycle'] % SIBLING_INTERVAL == 0:
                followup = row['sibling_after']
                grade_useful(followup, sibling['client'])
                require(followup['semantic_sha256'] == sibling['useful']['semantic_sha256'],
                        'surviving_sibling_useful_changed')
                require(followup['id'] > previous_probe, 'sibling_followup_not_fresh')
                previous_probe = followup['id']
            else:
                require('sibling_after' not in row, 'unexpected_sibling_probe')
        last_sibling_ids[profile] = previous_probe
    sibling_fs = next(a for a in attempts if a['kind'] == 'sibling' and a['profile'] == 'filesystem')
    for row in controls:
        grade_control(row)
        grade_useful(row['sibling_after'], sibling_fs['client'])
        require(row['sibling_after']['semantic_sha256'] == sibling_fs['useful']['semantic_sha256'],
                'calibration_harmed_sibling')
        require(row['sibling_after']['id'] > last_sibling_ids['filesystem'], 'calibration_sibling_probe_replayed')
        last_sibling_ids['filesystem'] = row['sibling_after']['id']


def finish_client(row, client, limits, save, *, failed=False):
    if client is not None:
        try:
            row['client'] = client_projection(client.close(expect_failure=failed), limits)
        except Exception:
            row['cleanup_error'] = 'cleanup_failed'
            row['status'] = 'fail'
            row['failure_code'] = 'cleanup_failed'
        save()


def run_case(report, save, kind, profile, create, exercise, *, cycle=None, limits=None):
    row = begin_attempt(report, save, kind, profile, cycle)
    client = None
    limits = limits or DEFAULT_LIMITS
    try:
        stage(row, save, 'create')
        client = create()
        row['server_origin'] = 'owned-calibration-fixture' if kind == 'control' else 'original-selected'
        stage(row, save, 'initialize')
        client.initialize()
        exercise(row, client)
        stage(row, save, 'cleanup')
        finish_client(row, client, limits, save, failed=kind == 'control')
        require(row['status'] != 'fail', 'case_cleanup_failed')
        grade_client(row['client'], limits, crashed=kind == 'churn', failed=kind == 'control')
        stage(row, save, 'complete')
        row['status'] = 'pass'
        save()
        return row
    except (Exception, KeyboardInterrupt) as error:
        fail_attempt(row, error, client)
        finish_client(row, client, limits, save)
        save()
        raise


MEMBERSHIP_TEST = ('mcp::linux_budget::linux::process_record_tests::'
                   'native_sou136_membership_violation_refuses_owned_child')


def native_membership_witness(completed):
    raw = completed.stdout + completed.stderr
    require(completed.returncode == 0 and len(raw) <= 65536,
            'native_membership_control_failed')
    # libtest's single-threaded pretty formatter can put the fixed test name
    # before its first stdout line. Accept only that exact known prefix, not
    # arbitrary JSON substrings or panic text. Quiet output has no such prefix.
    prefix = ('test ' + MEMBERSHIP_TEST + ' ... ').encode()
    events = []
    for line in completed.stdout.splitlines():
        if line.startswith(prefix):
            line = line[len(prefix):]
        try: event = json.loads(line)
        except (ValueError, UnicodeError): continue
        if isinstance(event, dict) and event.get('event') == 'sou136_membership_calibration':
            events.append(event)
    require(len(events) == 1 and b'1 passed; 0 failed' in raw,
            'native_membership_control_missing')
    allowed = {'event', 'passed', 'phase', 'leader_same_lifetime', 'limits_unchanged',
               'owned_child_reaped', 'leaf_removed', 'quarantine_removed',
               'production_transport_claimed'}
    require(set(events[0]) == allowed, 'native_membership_control_shape')
    return events[0], digest(raw)


def membership_control(report, save, rig, sibling, expected, args):
    row = begin_attempt(report, save, 'control', 'filesystem', 'membership')
    try:
        stage(row, save, 'inject')
        command = [str(args.sandbox_test_binary), '--exact', MEMBERSHIP_TEST,
                   '--ignored', '--nocapture', '--test-threads=1', '--quiet']
        # The Rust control owns and retains its direct Child until reaping;
        # no foreign numeric PID is ever migrated by the Python observer.
        completed = subprocess.run(command, capture_output=True, timeout=15,
            env=dict(os.environ, SOU136_DELEGATION_ROOT=str(rig.delegation)))
        row['native_control_exit_code'] = completed.returncode
        row['native_control_log_bytes'] = len(completed.stdout) + len(completed.stderr)
        row['native_control_log_sha256'] = digest(completed.stdout + completed.stderr)
        row['violation'], row['native_control_log_sha256'] = native_membership_witness(completed)
        grade_control(row)
        stage(row, save, 'sibling_after')
        row['sibling_after'] = useful_witness(sibling, expected)
        stage(row, save, 'complete')
        row['status'] = 'pass'
        save()
    except (Exception, KeyboardInterrupt) as error:
        fail_attempt(row, error)
        save()
        raise


def profile_churn(report, save, rig, profile, args, *, resource_controls=False):
    sibling_row = begin_attempt(report, save, 'sibling', profile)
    sibling = None
    try:
        stage(sibling_row, save, 'create')
        # The accepted peer-isolation label selects its existing 600000 ms wall
        # budget; ordinary churn subjects keep their 120000 ms wall budget.
        sibling = owned_client(SELECTED.SelectedLivenessClient, rig, 'peer-isolation', lease_secs=10)
        sibling_row['server_origin'] = 'original-selected'
        stage(sibling_row, save, 'initialize')
        sibling.initialize()
        stage(sibling_row, save, 'useful')
        sibling_row['useful'] = useful_witness(sibling)
        expected = sibling_row['useful']['semantic_sha256']
        save()

        def cycle_exercise(row, client):
            stage(row, save, 'useful')
            row['useful'] = useful_witness(client, expected)
            stage(row, save, 'crash')
            observed = SOU86.observe_crash(client, 'collector', args.bwrap.resolve())
            row['crash'] = crash_projection(observed, DEFAULT_LIMITS)
            row['client'] = row['crash']['client']
            save()
            SELECTED.grade_crash_observation(row['crash'], 'sou136', budget=DEFAULT_LIMITS)
            grade_client(row['client'], DEFAULT_LIMITS, crashed=True)
            if row['cycle'] % SIBLING_INTERVAL == 0:
                stage(row, save, 'sibling_after')
                row['sibling_after'] = useful_witness(sibling, expected)

        for number in range(1, CYCLES + 1):
            run_case(report, save, 'churn', profile,
                     lambda n=number: owned_client(SELECTED.SelectedLivenessClient, rig, f'churn-{profile}-{n}', lease_secs=2),
                     cycle_exercise, cycle=number)
            if number % 14 == 0:
                time.sleep(2.5)
        time.sleep(2.5)

        def restored_exercise(row, client):
            row.update(after_cycle=CYCLES, reclamation_wait_millis=2500)
            stage(row, save, 'useful')
            row['useful'] = useful_witness(client, expected)

        restored = run_case(report, save, 'capacity', profile,
                            lambda: owned_client(SELECTED.SelectedLivenessClient, rig, f'restored-{profile}', lease_secs=4),
                            restored_exercise)
        grade_client(restored['client'], DEFAULT_LIMITS)
        if resource_controls:
            for name in ('memory', 'pids'):
                run_control(report, save, rig, name, sibling, expected)
            membership_control(report, save, rig, sibling, expected, args)
        stage(sibling_row, save, 'cleanup')
        finish_client(sibling_row, sibling, PEER_LIMITS, save)
        require(sibling_row['status'] != 'fail', 'sibling_cleanup_failed')
        grade_client(sibling_row['client'], PEER_LIMITS)
        stage(sibling_row, save, 'complete')
        sibling_row['status'] = 'pass'
        save()
    except (Exception, KeyboardInterrupt) as error:
        fail_attempt(sibling_row, error, sibling)
        finish_client(sibling_row, sibling, PEER_LIMITS, save)
        save()
        raise


def run_control(report, save, rig, name, sibling, expected):
    require(name in ('memory', 'pids'), 'pressure_control_required')
    def create():
        return owned_client(RESOURCE.Client, rig, 'sou136-' + name, rig.fixture,
                            RESOURCE.budget(rig.delegation, **CONTROL_LIMITS[name]))

    def exercise(row, client):
        row['control'] = name
        stage(row, save, 'useful')
        row['useful'] = useful_witness(client, fixture=True)
        stage(row, save, 'dispatch')
        client.send(RESOURCE.call(40, '/workspace/sou79-' + name))
        RESOURCE.wait_dispatched(client, 40)
        row['pending_dispatched'] = True
        stage(row, save, 'cleanup')
        row['client'] = client_projection(client.close(expect_failure=True), CONTROL_LIMITS[name])
        grade_control(row)
        stage(row, save, 'sibling_after')
        row['sibling_after'] = useful_witness(sibling, expected)

    run_case(report, save, 'control', 'filesystem', create,
             exercise, cycle=name, limits=CONTROL_LIMITS[name])


def installation_identity(rig):
    return {**{key: rig.installation[key] for key in ('profile_sha256', 'registry_sha256', 'policy_sha256')},
            'package_tree_sha256': rig.original['packageTreeSha256'],
            'config_sha256': sha(rig.home / '.agentfw/config.yaml')}


def initial_report(args):
    execution = {key: value if re.fullmatch(r'[0-9]{1,24}', value) else None for key, value in (
        ('github_run_id', os.environ.get('GITHUB_RUN_ID', '')),
        ('github_run_attempt', os.environ.get('GITHUB_RUN_ATTEMPT', '')))}
    return {'format': FORMAT, 'scope': 'focused-sou136-native', 'status': 'incomplete',
            'execution': execution,
            'runtime_source_commit': args.runtime_source_commit, 'retry_count': 0,
            'passed': 0, 'failed': 0, 'incomplete': REQUIRED_ATTEMPTS, 'skipped': 0,
            'required_attempts': REQUIRED_ATTEMPTS, 'cycles_per_original_profile': CYCLES,
            'sibling_probe_interval_cycles': SIBLING_INTERVAL,
            'attempts': [], 'installations': {}, 'original_unchanged': {}, 'workspace_unchanged': {},
            'cleanup_verified': False, 'delegation_removed': False,
            'live_model_efficacy_measured': False, 'final_admission_or_main_merge': False}


def run(args):
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), 'fresh_output_outside_source_required')
    output.mkdir(mode=0o700, parents=True)
    path = output / 'report.json'
    report = initial_report(args)
    save = lambda: checkpoint(path, report)
    save()
    rigs, delegation, baseline = {}, None, {}
    files = {name: getattr(args, name).resolve() for name in ('agentfw', 'node', 'npm', 'bwrap', 'git', 'git_launcher', 'sandbox_test_binary')}
    try:
        require(platform.system() == 'Linux' and platform.machine() == 'x86_64'
                and os.geteuid() != 0, 'unprivileged_native_linux_required')
        require(hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'), 'pidfd_prerequisite_missing')
        require(all(file.is_file() and os.access(file, os.X_OK) for file in files.values()), 'runtime_prerequisite_missing')
        report['source_before'] = BASE.source()
        require(report['source_before']['dirty'] is False
                and report['source_before']['commit'] == args.expected_commit == args.runtime_source_commit,
                'clean_exact_source_required')
        report['identities'] = {name: sha(file) for name, file in files.items()}
        report['identities'].update(python=sha(Path(sys.executable)), driver=sha(Path(__file__)),
                                    fixture=digest(RESOURCE.FIXTURE.encode()),
                                    dependencies={name: sha(ROOT / name) for name in DEPENDENCIES})
        require(report['identities']['git'] == args.git_sha256, 'pinned_git_identity_mismatch')
        save()
        delegation, delegated = SOU86.prepare_delegation(args.disposable_systemd_unit)
        report['delegation'] = {k: delegated[k] for k in ('unprivileged', 'manager_membership_verified', 'controllers', 'capabilities')}
        with tempfile.TemporaryDirectory(prefix='sou136-owned-') as temporary:
            private = Path(temporary).resolve()
            require(not private.is_relative_to(ROOT), 'private_runtime_outside_source_required')
            try:
                for profile, constructor in (('filesystem', SELECTED.SelectedLivenessRig),
                                             ('git', SELECTED.SelectedLivenessGitRig)):
                    directory = private / profile
                    directory.mkdir(mode=0o700)
                    rigs[profile] = object.__new__(constructor)
                    constructor.__init__(rigs[profile], args, directory, delegation, lease_secs=4, maint_interval_ms=100)
                    report['installations'][profile] = installation_identity(rigs[profile])
                    baseline[profile] = BASE.snapshot(rigs[profile].workspace)
                    save()
                # Keep RESOURCE.FIXTURE intact; SOU86.install_fixture would
                # replace its memory/PID calibration commands.
                for profile in PROFILES:
                    profile_churn(report, save, rigs[profile], profile, args,
                                  resource_controls=profile == 'filesystem')
            finally:
                cleanup_ok = True
                for profile, rig in rigs.items():
                    try:
                        cleaned = close_rig(rig)
                        SELECTED.grade_rig_cleanup_result(cleaned, profile)
                        for key in ('daemon_stdout', 'daemon_stderr'):
                            RESOURCE.clean_stream(cleaned[key])
                        report.setdefault('daemon_cleanup', {})[profile] = {
                            'all_stopped': cleaned['daemon_process']['all_stopped'],
                            'remaining_count': len(cleaned['daemon_process']['remaining']),
                            'stdout_sha256': cleaned['daemon_stdout']['sha256'],
                            'stderr_sha256': cleaned['daemon_stderr']['sha256']}
                        report['workspace_unchanged'][profile] = BASE.snapshot(rig.workspace) == baseline[profile]
                        report['original_unchanged'][profile] = (
                            BASE.INSTALL.tree_sha(Path(rig.original['packageRoot'])) == rig.original['packageTreeSha256'])
                    except Exception:
                        cleanup_ok = False
                        report.setdefault('cleanup_errors', {})[profile] = 'cleanup_failed'
                # Partial constructors may own a thread before its containing
                # instance receives the attribute. The acquisition registry is
                # independent of rig/client close and drains every such handle.
                for observer in OBSERVERS:
                    try: observer.finish()
                    except Exception:
                        cleanup_ok = False
                        report.setdefault('cleanup_errors', {})['partial_observer'] = 'cleanup_failed'
                report['cleanup_verified'] = cleanup_ok and set(rigs) == set(PROFILES)
                save()
        require(not any(child.is_dir() for child in delegation.iterdir()), 'owned_budget_leaves_survived')
        delegation.rmdir()
        report['delegation_removed'] = not delegation.exists()
        report['source_after'] = BASE.source()
        report['binaries_unchanged'] = all(sha(file) == report['identities'][name] for name, file in files.items())
        report.update(passed=sum(row['status'] == 'pass' for row in report['attempts']), failed=0, incomplete=0)
        grade(report)
        report['status'] = 'pass'
    except (Exception, KeyboardInterrupt) as error:
        report['status'] = 'incomplete' if isinstance(error, (RunCancelled, KeyboardInterrupt)) else 'fail'
        report['error_code'] = 'cancelled' if report['status'] == 'incomplete' else 'qualification_failed'
        report['failed'] = max(1, sum(row['status'] == 'fail' for row in report['attempts']))
    finally:
        # The disposable systemd service is the final emergency boundary. Do
        # not repair witnesses with harness kills or turn a failed run green.
        save()
    print(json.dumps(summary(report), indent=2))
    return 0 if report['status'] == 'pass' else 1


def summary(report):
    return {key: report.get(key) for key in ('format', 'scope', 'status', 'error_code', 'passed', 'failed',
        'incomplete', 'skipped', 'required_attempts', 'cycles_per_original_profile', 'retry_count',
        'source_before', 'source_after', 'binaries_unchanged', 'identities', 'installations',
        'cleanup_verified', 'delegation_removed')} | {
        'attempted': {profile: sum(row['kind'] == 'churn' and row['profile'] == profile
                                  for row in report['attempts']) for profile in PROFILES},
        'unexpected_closures': sum(row['unexpected_closure'] for row in report['attempts']),
        'failed_attempts': [{key: row.get(key) for key in ('case', 'stage', 'status', 'failure_code',
                            'failure_type', 'failure_errno', 'unexpected_closure')}
                            for row in report['attempts'] if row['status'] != 'pass']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    for name in ('agentfw', 'node', 'npm', 'bwrap', 'git', 'git-launcher', 'sandbox-test-binary', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('expected-commit', 'runtime-source-commit', 'git-sha256', 'disposable-systemd-unit'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({'format': FORMAT, 'status': 'plan', 'executed': False,
                          'required_attempts': REQUIRED_ATTEMPTS, 'original_cycles_per_profile': CYCLES,
                          'required_native_linux': True, 'retry_count': 0,
                          'calibrations': list(CONTROL_NAMES), 'raw_output_capture': False}))
        return 0

    def cancel(_number, _frame):
        raise RunCancelled()

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    return run(args)


if __name__ == '__main__':
    raise SystemExit(main())
