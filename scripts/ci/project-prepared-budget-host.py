#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Finite parent projection of the partial native prepared-budget slice.

Raw reports remain private. Passing this slice never claims pressure or final
SOU-142 acceptance: those missing controls remain explicit in every projection.
"""
import argparse
import json
from pathlib import Path
import re

CASES = ('plan', 'occupied-port', 'stale-source', 'changed-selection',
         'useful-refusal', 'ask', 'default', 'cancel', 'daemon-loss', 'host-crash', 'timeout')
HOST = CASES[4:]
COUNTERS = frozenset(('memory_current_bytes', 'memory_peak_bytes', 'memory_oom', 'memory_oom_kill',
    'pids_current', 'pids_peak', 'pids_peak_kernel', 'pids_max_events', 'cpu_usage_micros',
    'cpu_periods', 'cpu_throttled_periods'))
GAPS = ('original-memory-pid-wall-calibration',
        'owner-loss-before-descriptor-handback')


class Invalid(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Invalid(reason)


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'digest_invalid')
    return value


def number(value):
    need(type(value) is int and 0 <= value <= 2**63 - 1, 'counter_invalid')
    return value


def cleanup(value):
    need(type(value) is dict and type(value.get('observed')) is list
         and 1 < len(value['observed']) <= 4096 and value.get('remaining') == []
         and value.get('all_stopped') is True, 'owned_cleanup_unverified')
    identities, parents = set(), 0
    for row in value['observed']:
        need(type(row) is dict and set(row) == {'pid', 'start_time_ticks', 'parent_process'}
             and type(row['parent_process']) is bool, 'process_observation_invalid')
        identity = (number(row['pid']), number(row['start_time_ticks']))
        need(all(identity) and identity not in identities, 'process_identity_invalid')
        identities.add(identity)
        parents += row['parent_process']
    need(parents == 1 and value.get('descendant_count') == len(identities) - 1,
         'process_denominator_invalid')
    return {'observed_process_count': len(identities), 'remaining_count': 0, 'all_stopped': True}


def budget(value, expected, success):
    need(type(value) is dict and value.get('format') == 'sw-prepared-pilot-budget/1'
         and digest(value.get('budget_sha256')) == expected
         and value.get('scope') == 'per-original-server-process-tree', 'budget_binding_unverified')
    rows = value.get('observations')
    need(type(rows) is list and 2 <= len(rows) <= 64
         and number(value.get('observed_children')) == len(rows), 'budget_denominator_invalid')
    failed, unresolved = number(value.get('failed_children')), number(value.get('unresolved_children'))
    need(failed <= len(rows) and unresolved <= len(rows), 'budget_count_invalid')
    need(value.get('status') in ('closed-enforced', 'refused', 'unresolved'), 'terminal_budget_status_invalid')
    if success:
        need(value['status'] == 'closed-enforced' and failed == unresolved == 0, 'budget_cleanup_unverified')
    observations, servers = [], set()
    for row in rows:
        server, phase, reason = row.get('server_id'), row.get('phase'), row.get('reason')
        need(server in ('filesystem', 'git')
             and phase in ('preparing', 'active-at-attachment', 'closed', 'unresolved')
             and ((reason is None and phase in ('preparing', 'unresolved'))
                  or (type(reason) is str and re.fullmatch('[a-z0-9_]{1,100}', reason))),
             'budget_observation_invalid')
        counters = row.get('counters')
        need(type(counters) is dict and set(counters) <= COUNTERS, 'budget_counter_inventory_invalid')
        projected = {}
        for key, count in counters.items():
            if key == 'pids_peak_kernel':
                need(type(count) is bool, 'budget_counter_invalid')
                projected[key] = count
            else:
                projected[key] = number(count)
        if success:
            need(phase == 'closed' and reason == 'mcp_budget_enforced', 'closed_budget_receipt_unverified')
        servers.add(server)
        observations.append({'server': server, 'phase': phase, 'reason': reason, 'counters': projected})
    need(servers == {'filesystem', 'git'}, 'both_original_budget_receipts_required')
    return {'budget_sha256': expected, 'status': value['status'], 'observed_children': len(rows),
            'failed_children': failed, 'unresolved_children': unresolved, 'observations': observations}


def pressure(value, attempt):
    """Finite original-runtime pressure observations; absence never proves refusal."""
    if value is None:
        return {'status': 'unavailable', 'reason': 'original_pressure_not_observed', 'attempts': []}
    need(type(value) is dict and value.get('format') == 'sou142-original-pressure/1'
         and value.get('status') in ('passed', 'incomplete')
         and value.get('workspace_unchanged') is True
         and value.get('raw_process_metadata_exported') is False
         and value.get('observer_cleanup_performed') is False, 'pressure_inventory_unverified')
    rows = value.get('attempts')
    identities = [(server, kind) for server in ('filesystem', 'git') for kind in ('memory', 'pids', 'wall')]
    need(type(rows) is list and len(rows) == 6 and
         [(row.get('server'), row.get('resource')) for row in rows] == identities, 'pressure_denominator_invalid')
    projected = []
    for row, (server, kind) in zip(rows, identities):
        limits = {'memoryMaxBytes': 64 * 1024 * 1024 if kind == 'memory' else 512 * 1024 * 1024,
                  'pidsMax': 16 if kind == 'pids' else 64, 'cpuQuotaMicros': 100000,
                  'wallMillis': 1000 if kind == 'wall' else 120000}
        need(row.get('limits') == limits and row.get('server_origin') == 'pinned-original'
             and row.get('status') in ('passed', 'incomplete') and row.get('forced_cleanup') is False,
             'pressure_limits_or_cleanup_unverified')
        item = {'server': server, 'resource': kind, 'status': row['status'],
                'limits': limits, 'budget_sha256': digest(row.get('budget_sha256'))}
        reasons = ('original_resource_refusal_verified', 'original_resource_refusal_unproven',
                   'bounded_calibration_attempt_incomplete')
        need(row.get('reason') in reasons, 'pressure_reason_invalid')
        item['reason'] = row['reason']
        calibration = row.get('calibration')
        if calibration is not None:
            need(type(calibration) is dict and type(calibration.get('target_advertised')) is bool,
                 'pressure_calibration_invalid')
            item['calibration'] = {'target_advertised': calibration['target_advertised'], **{
                key:number(calibration.get(key)) for key in
                ('provider_requests','offered_calls','correlated_results','error_results')}}
        git_counts = row.get('pinned_git_exec_counts')
        refusals = row.get('calibration_refusals')
        if refusals is not None:
            need(type(refusals) is dict and set(refusals) ==
                 {'policy_unconfirmed_ask','policy_denied','classifier_error'}, 'pressure_refusal_counts_invalid')
            item['calibration_refusals'] = {key:number(count) for key,count in refusals.items()}
        if git_counts is not None:
            need(type(git_counts) is dict and set(git_counts) ==
                 {'status','diff','diff-tree','log','show','version','other'}, 'pressure_git_counts_invalid')
            item['pinned_git_exec_counts'] = {key:number(count) for key,count in git_counts.items()}
        observations = row.get('kernel_observations', [])
        need(type(observations) is list and len(observations) <= 64, 'pressure_kernel_inventory_invalid')
        item['kernel_observations'] = []
        for observed in observations:
            need(type(observed) is dict and type(observed.get('counter_max')) is dict
                 and set(observed['counter_max']) == {'oom', 'oom_kill', 'pids_max', 'throttled'},
                 'pressure_counter_inventory_invalid')
            counters = {key: number(count) for key, count in observed['counter_max'].items()}
            item['kernel_observations'].append({'counter_max': counters,
                **{key: number(observed.get(key)) for key in
                   ('memory_peak_bytes', 'tasks_peak', 'leaf_duration_millis')},
                'removed': observed.get('removed') is True})
            if row['status'] == 'passed':
                need(observed.get('removed') is True and observed.get('errors') == []
                     and observed.get('incomplete_reasons') == [], 'pressure_leaf_cleanup_unverified')
        if row['status'] == 'passed':
            need(row.get('reason') == 'original_resource_refusal_verified'
                 and row.get('original_runtime_observed') is True and observations
                 and row.get('owned_cleanup_verified') is True
                 and row.get('peer_useful_after_subject') is True
                 and row.get('peer_survived_kernel_refusal') is True
                 and row.get('fresh_prepared_recovery_useful') is True
                 and number(row.get('observed_children')) >= 2, 'pressure_runtime_or_recovery_unverified')
            counter = 'oom_kill' if kind == 'memory' else 'pids_max'
            need(any(number(item.get('leaf_duration_millis')) > 0 if kind == 'wall'
                     else number(item['counter_max'].get(counter)) > 0 for item in observations),
                 'pressure_exhaustion_unverified')
            receipts = row.get('target_receipts')
            expected_reason = {'memory': 'mcp_budget_memory_exhausted',
                'pids': 'mcp_budget_pids_exhausted', 'wall': 'mcp_budget_wall_expired'}[kind]
            need(type(receipts) is list and 1 <= len(receipts) <= 64 and any(
                 receipt.get('server_id') == server and receipt.get('phase') == 'closed'
                 and receipt.get('reason') == expected_reason for receipt in receipts), 'pressure_refusal_receipt_unverified')
            item.update(trace_sha256=digest(row.get('trace_sha256')), original_runtime_observed=True,
                owned_cleanup_verified=True, peer_useful_after_subject=True, fresh_prepared_recovery_useful=True,
                peer_budget=budget(row.get('peer_budget'), digest(attempt.get('peer_budget_sha256')), True),
                recovery_budget=budget(row.get('recovery_budget'), digest(attempt.get('budget_sha256')), True),
                refusal_reason=expected_reason)
        projected.append(item)
    passed = all(row['status'] == 'passed' for row in projected)
    need((value['status'] == 'passed') == passed, 'pressure_status_inconsistent')
    return {'status': 'passed' if passed else 'incomplete', 'workspace_unchanged': True,
            'observer_cleanup_performed': False, 'attempts': projected}


def project_pressure(attempt, expected, exit_code):
    """Independent bounded pressure phase; never substitutes for baseline proof."""
    result = {'format': 'sou142-prepared-pressure-host-evidence/1', 'status': 'failed',
              'source_commit': expected, 'full_sou142_qualification': False, 'acceptance_pass': False}
    try:
        need(type(expected) is str and re.fullmatch('[0-9a-f]{40}', expected), 'source_identity_invalid')
        need(type(attempt) is dict and exit_code == 0 and attempt.get('phase') == 'pressure'
             and attempt.get('format') == 'sou142-offline-budget-host-attempt/1'
             and attempt.get('status') == 'partial-runtime-completed-pending-parent-projection'
             and attempt.get('source_commit') == expected and attempt.get('source_read_only') is True
             and attempt.get('actual_original_host_covered') is False
             and attempt.get('provider') == 'owned-scripted-loopback'
             and type(attempt.get('paid_api_calls')) is int and attempt['paid_api_calls'] == 0
             and attempt.get('reused_binaries_read_only') is True
             and attempt.get('network') == 'private-loopback-only'
             and attempt.get('owned_budget_root_empty') is True
             and attempt.get('owned_peer_budget_root_empty') is True, 'pressure_phase_unverified')
        selected = attempt.get('selected_sha256')
        need(type(selected) is dict and set(selected) == {'agentfw', 'git_launcher', 'sandbox_tests',
             'python', 'node', 'bwrap_source', 'git', 'claude'}, 'selected_identity_missing')
        result['selected_sha256'] = {key: digest(value) for key, value in selected.items()}
        result['selection_sha256'] = digest(attempt.get('selection_sha256'))
        result['original_pressure'] = pressure(attempt.get('original_pressure'), attempt)
        need(result['original_pressure']['status'] == 'passed', 'original_pressure_incomplete')
        result.update(status='pressure-slice-passed', owned_budget_root_empty=True,
                      owned_peer_budget_root_empty=True, baseline_required_separately=True)
    except (Invalid, KeyError, TypeError) as error:
        result['reason'] = str(error) if isinstance(error, Invalid) else 'malformed_private_report'
    return result


def project(attempt, raw, expected, exit_code):
    output = {'format': 'sou142-prepared-budget-host-evidence/1', 'status': 'failed',
              'source_commit': expected, 'full_sou142_qualification': False,
              'acceptance_pass': False, 'remaining_gaps': list(GAPS), 'cases': [],
              'owner_controls': [], 'raw_process_metadata_or_logs_exported': False}
    if type(attempt) is not dict or type(raw) is not dict:
        output['reason'] = 'malformed_private_report'
        return output
    # Failure observations use a separate finite schema, even when no successful
    # terminal receipt exists. Raw private process identities never escape.
    diagnostics = []
    section = raw.get('emergency_stop', {})
    if type(section) is dict:
        cases = section.get('cases', [])
        for row in cases[:4] if type(cases) is list else []:
            if type(row) is not dict:
                continue
            observations = row.get('failure_observations', [row.get('failure_observation')])
            for observed in observations[:2] if type(observations) is list else []:
                if type(observed) is not dict:
                    continue
                value = {}
                enums = {'entry_status': {'completed', 'failed', 'stopped'},
                    'entry_reason': {'restricted_launcher_failed', 'pilot_timeout', 'pilot_cancelled',
                        'owned_daemon_lost', 'resource_budget_unconfirmed', 'resource_budget_refused',
                        'owned_stop_unconfirmed', 'provider_unavailable'},
                    'budget_status': {'closed-enforced', 'unresolved', 'refused', 'active-at-attachment',
                        'configured-not-observed'}}
                for key, allowed in enums.items():
                    item = observed.get(key)
                    if type(item) is str and item in allowed:
                        value[key] = item
                for key in ('entry_returncode', 'provider_request_count', 'budget_failed_children',
                            'budget_unresolved_children'):
                    item = observed.get(key)
                    if type(item) is int and -255 <= item <= 65536:
                        value[key] = item
                if value:
                    diagnostics.append(value)
    if diagnostics:
        output['failure_observations'] = diagnostics
    try:
        need(type(expected) is str and re.fullmatch('[0-9a-f]{40}', expected), 'source_identity_invalid')
        need(exit_code == 0 and attempt.get('status') == 'partial-runtime-completed-pending-parent-projection'
             and attempt.get('format') == 'sou142-offline-budget-host-attempt/1'
             and attempt.get('source_commit') == expected and attempt.get('owned_budget_root_empty') is True
             and attempt.get('actual_original_host_covered') is True, 'runtime_slice_unverified')
        selected = attempt.get('selected_sha256')
        need(type(selected) is dict and set(selected) == {'agentfw', 'git_launcher', 'sandbox_tests',
             'python', 'node', 'bwrap_source', 'git', 'claude'}, 'selected_identity_missing')
        output['selected_sha256'] = {key: digest(value) for key, value in selected.items()}
        output['selection_sha256'] = digest(attempt.get('selection_sha256'))
        expected_budget = digest(attempt.get('budget_sha256'))
        controls = attempt.get('owner_controls')
        need(type(controls) is list and len(controls) == 4, 'owner_control_denominator_invalid')
        seen = set()
        for row in controls:
            identity = (row.get('server'), row.get('stage'))
            need(identity not in seen and identity[0] in ('filesystem', 'git')
                 and identity[1] in ('prepared-before-owner', 'prepared-handback-before-adoption-ack'),
                 'owner_control_identity_invalid')
            need(row.get('status') == 'pass' and row.get('original_started') is False
                 and type(row.get('owned_members')) is int and row['owned_members'] == 0
                 and row.get('production_cleanup_verified') is True
                 and row.get('witness_cleanup_attempted') is False
                 and row.get('budget_sha256') == expected_budget
                 and row.get('binary_sha256') == selected['sandbox_tests']
                 and row.get('owner_binary_sha256') == selected['agentfw'], 'owner_cleanup_unverified')
            need(row.get('leaf_created') is (identity[1] == 'prepared-handback-before-adoption-ack'),
                 'owner_control_stage_invalid')
            seen.add(identity)
            output['owner_controls'].append({'server': identity[0], 'stage': identity[1],
                'status': 'passed', 'production_cleanup_verified': True, 'witness_cleanup_attempted': False})
        source = raw.get('source_before', {})
        need(raw.get('format') == 'sw-prepared-pilot-acceptance/1' and raw.get('status') == 'passed'
             and source.get('commit') == expected and source.get('dirty') is False
             and raw.get('source_after') == source and raw.get('unrelated_preserved') is True
             and raw.get('workspace_unchanged') is True and raw.get('selected_assets_unchanged') is True,
             'original_host_inventory_unverified')
        actual_selected = raw.get('selected_sha256')
        need(type(actual_selected) is dict and all(actual_selected.get('bwrap' if key == 'bwrap_source' else key)
             == value for key, value in selected.items()), 'original_host_selected_identity_changed')
        rows = raw.get('cases')
        need(type(rows) is list and [row.get('case') for row in rows] == list(CASES), 'host_case_denominator_invalid')
        for row in rows:
            name = row['case']
            need(row.get('status') == 'passed', 'host_case_failed')
            result = {'case': name, 'status': 'passed', 'trace_sha256': digest(row.get('trace_sha256'))}
            if name in HOST:
                success = name in ('useful-refusal', 'ask', 'default')
                need(row.get('outcome') == ('completed' if success else 'failed')
                     and row.get('cleanup') == 'owned_processes_stopped_audit_retained', 'host_terminal_invalid')
                result['resource_budget'] = budget(row.get('resource_budget'), expected_budget, success)
                result['process_cleanup'] = cleanup(row.get('process_cleanup'))
                if success:
                    dispatches = {'useful-refusal': [1, 1, 0], 'ask': [1, 1, 1], 'default': [1, 0]}[name]
                    need(row.get('exact_once_kernel_read') is True and row.get('dispatch_counts') == dispatches
                         and row.get('explicit_harness_decisions') == (2 if name == 'ask' else 0),
                         'original_host_effect_or_authority_unverified')
                    if name == 'useful-refusal':
                        need(row.get('kernel_git_status_count') == 1, 'original_git_execution_unverified')
                    result.update(exact_once_kernel_read=True, dispatch_counts=dispatches,
                                  explicit_harness_decisions=2 if name == 'ask' else 0)
            else:
                need(type(row.get('selected_execution')) is int and row['selected_execution'] == 0,
                     'preflight_execution_observed')
                result['selected_execution'] = 0
            output['cases'].append(result)
        section = raw.get('emergency_stop', {})
        need(attempt.get('budgeted_emergency_stop_qualified') is True
             and attempt.get('owned_peer_budget_root_empty') is True
             and section.get('status') == 'passed' and section.get('source_commit') == expected,
             'budgeted_stop_incomplete')
        stops = section.get('cases', [])
        need([row.get('case') for row in stops] == ['two-prepared-runs', 'interrupted-stop',
             'daemon-loss-stop', 'unconfirmed-namespace-stop'], 'stop_case_denominator_invalid')
        output['emergency_stop'] = []
        for row in stops:
            name = row['case']
            need(row.get('status') == 'passed' and row.get('future_dispatches') == 0,
                 'stop_future_dispatch_or_failure')
            current = row.get('selected') if name == 'two-prepared-runs' else row
            result = {'case': name, 'resource_budget': budget(current.get('resource_budget'),
                expected_budget, name in ('two-prepared-runs', 'interrupted-stop')),
                'process_cleanup': cleanup(current.get('process_cleanup')), 'future_dispatches': 0}
            if name == 'two-prepared-runs':
                peer = row.get('peer', {})
                need(row.get('peer_useful_after_stop') is True
                     and row.get('peer_original_dispatches_after_stop') == 2
                     and row.get('unrelated_process_identity_preserved') is True
                     and row.get('unrelated_listener_preserved') is True, 'stop_peer_or_inventory_unverified')
                result['peer_resource_budget'] = budget(peer.get('resource_budget'),
                    digest(attempt.get('peer_budget_sha256')), True)
                result['peer_process_cleanup'] = cleanup(peer.get('process_cleanup'))
                result['peer_useful_after_stop'] = True
            output['emergency_stop'].append(result)
        output['original_pressure'] = pressure(attempt.get('original_pressure'), attempt)
        output.update(status='partial-slice-passed', owned_budget_root_empty=True)
    except (Invalid, KeyError, TypeError) as error:
        output['reason'] = str(error) if isinstance(error, Invalid) else 'malformed_private_report'
    return output


def read(path):
    need(path.stat().st_size <= 4 * 1024 * 1024, 'private_report_bound')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate_private_report_key')
            result[key] = value
        return result
    result = json.loads(path.read_bytes(), object_pairs_hook=pairs)
    need(type(result) is dict, 'private_report_object_required')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', choices=('all', 'baseline', 'pressure'), default='all')
    parser.add_argument('--raw', type=Path)
    for name in ('attempt', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--exit-code', type=int, required=True)
    args = parser.parse_args()
    try:
        if args.phase == 'pressure':
            result = project_pressure(read(args.attempt), args.expected_commit, args.exit_code)
        else:
            need(args.raw is not None, 'baseline_report_required')
            result = project(read(args.attempt), read(args.raw), args.expected_commit, args.exit_code)
    except (OSError, ValueError):
        result = {'format': 'sou142-prepared-budget-host-evidence/1', 'status': 'failed',
                  'acceptance_pass': False, 'full_sou142_qualification': False,
                  'reason': 'bounded_private_report_unavailable', 'remaining_gaps': list(GAPS)}
    rendered = json.dumps(result, indent=2) + '\n'
    need(len(rendered.encode()) <= 128 * 1024, 'finite_public_report_bound')
    args.output.write_text(rendered)
    return 0 if result['status'] in ('partial-slice-passed', 'pressure-slice-passed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
