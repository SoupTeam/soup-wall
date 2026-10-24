#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Trusted parent-side finite projection; raw qualification reports stay private."""
import argparse
import hashlib
import json
from pathlib import Path
import re

HOST_SHA = 'fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7'
PREFLIGHT = ('plan', 'occupied-port', 'stale-source', 'changed-selection', 'provider-unavailable')
CASES = PREFLIGHT + ('provider-reject',
         'useful-refusal', 'ask', 'default', 'cancel', 'daemon-loss', 'host-crash', 'timeout')
STOP_CASES = ('two-prepared-runs', 'interrupted-stop', 'daemon-loss-stop', 'unconfirmed-namespace-stop')
FORGERY_CASES = ('forged-run', 'stale-start', 'foreign-live-pid', 'foreign-pid-reused-start', 'forged-stopped-receipt')
ROLES = ('entry', 'host', 'daemon', 'launcher', 'collector', 'diagnostic', 'original', 'classifier', 'other')
REQUIRED = ('entry', 'host', 'daemon', 'launcher', 'collector', 'diagnostic', 'original')


class Invalid(Exception):
    pass


def need(value, reason):
    if not value:
        raise Invalid(reason)


def count(value, maximum=2**31):
    need(type(value) is int and 0 <= value <= maximum, 'invalid_bounded_observation_count')
    return value


def digest(value):
    need(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value), 'invalid_evidence_digest')
    return value


def source(value, expected):
    need(isinstance(value, dict) and value.get('commit') == expected and value.get('dirty') is False,
         'clean_exact_source_unproven')
    return {'commit': expected, 'files_sha256': digest(value.get('files_sha256'))}


def cleanup(value):
    need(isinstance(value, dict) and type(value.get('observed')) is list
         and type(value.get('remaining')) is list, 'process_cleanup_observation_missing')
    identities = set()
    parents = 0
    for row in value['observed']:
        need(type(row) is dict and set(row) == {'pid', 'start_time_ticks', 'parent_process'}
             and type(row['parent_process']) is bool, 'invalid_owned_process_observation')
        identity = (count(row['pid']), count(row['start_time_ticks'], 2**63 - 1))
        need(all(identity) and identity not in identities, 'duplicate_or_invalid_owned_process_identity')
        identities.add(identity)
        parents += row['parent_process']
    result = {'observed_process_count': count(len(value['observed'])),
              'descendant_count': count(value.get('descendant_count')),
              'remaining_count': count(len(value['remaining'])),
              'all_stopped': value.get('all_stopped') is True}
    need(parents == 1 and result['descendant_count'] == result['observed_process_count'] - 1
         and result['descendant_count'] > 0
         and result['remaining_count'] == 0 and result['all_stopped'], 'owned_cleanup_unproven')
    return result


def stop_roles(value):
    rows = value.get('observed_owned_roles')
    need(type(rows) is list and len(rows) == 7, 'stop_role_denominator_missing')
    observed = value['process_cleanup']['observed']
    identities = {(row['pid'], row['start_time_ticks']): row['parent_process'] for row in observed}
    selected, servers = set(), set()
    counts = {'host': 0, 'collector': 0, 'owner': 0, 'pid1': 0}
    for row in rows:
        need(type(row) is dict and row.get('role') in counts, 'stop_role_identity_invalid')
        role = row['role']
        need(set(row) == ({'pid', 'start_time_ticks', 'role', 'server'} if role == 'collector'
                          else {'pid', 'start_time_ticks', 'role'}), 'stop_role_identity_invalid')
        identity = (count(row['pid']), count(row['start_time_ticks'], 2**63 - 1))
        need(identity in identities and identities[identity] is False and identity not in selected,
             'stop_role_not_bound_to_owned_descendant')
        selected.add(identity)
        counts[role] += 1
        if role == 'collector':
            need(row['server'] in ('filesystem', 'git') and row['server'] not in servers,
                 'stop_collector_server_identity_missing')
            servers.add(row['server'])
    need(counts == {'host': 1, 'collector': 2, 'owner': 2, 'pid1': 2}
         and servers == {'filesystem', 'git'}, 'stop_role_denominator_missing')
    return counts


def provider(value, rejected=False):
    routing, protocol = value.get('provider_routing'), value.get('provider_protocol')
    logs, retained = value.get('provider_private_logs'), value.get('provider_retained_artifacts')
    need(all(isinstance(item, dict) for item in (routing, protocol, logs, retained)), 'provider_observations_missing')
    counts = routing.get('successful_exec_counts')
    need(type(counts) is dict and set(counts) == set(ROLES), 'provider_role_counts_missing')
    counts = {role: count(counts[role]) for role in ROLES}
    required = ('entry', 'host', 'daemon', 'launcher', 'diagnostic') if rejected else REQUIRED
    need(all(counts[role] > 0 for role in required), 'provider_required_role_unobserved')
    need(routing.get('observation_stage') == ('first-request-authentication-refusal' if rejected
         else 'original-server-runtime'), 'provider_observation_stage_unproven')
    need(routing.get('all_seven_inputs_in_intended_host') is True
         and count(routing.get('unrelated_provider_values')) == 0
         and count(routing.get('provider_values_in_argv')) == 0
         and routing.get('raw_environment_exported') is False, 'provider_isolation_unproven')
    requests = count(protocol.get('owned_loopback_requests'))
    need(requests > 0 and protocol.get('expected_synthetic_authentication_seen') is True
         and protocol.get('credential_values_exported') is False, 'provider_authenticated_protocol_unproven')
    writes = count(logs.get('successful_private_log_writes'))
    logbytes = count(logs.get('private_log_bytes'), 4 * 1024 * 1024)
    need(writes > 0 and logbytes > 0 and logs.get('all_selected_values_and_json_forms_absent') is True
         and logs.get('raw_log_exported') is False, 'provider_private_log_redaction_unproven')
    need(logs.get('owned_rejection_redaction_observed') is rejected, 'provider_rejection_log_control_unproven')
    entries = count(retained.get('retained_entries_checked'), 4096)
    retained_bytes = count(retained.get('retained_bytes_checked'), 16 * 1024 * 1024)
    need(entries > 0 and retained.get('intentional_observer_and_input_exclusions') == 2
         and retained.get('all_selected_values_and_json_forms_absent') is True
         and retained.get('artifact_contents_exported') is False, 'provider_retained_artifact_check_unproven')
    return {'successful_exec_counts': counts, 'observation_stage': routing['observation_stage'],
            'all_seven_inputs_in_intended_host': True,
            'unrelated_provider_values': 0, 'provider_values_in_argv': 0,
            'owned_loopback_requests': requests, 'authenticated_owned_request_observed': True,
            'successful_private_log_writes': writes, 'private_log_bytes_checked': logbytes,
            'owned_rejection_redaction_observed': rejected, 'retained_entries_checked': entries,
            'retained_bytes_checked': retained_bytes, 'all_selected_values_and_json_forms_absent': True,
            'raw_environment_log_and_artifact_contents_exported': False}


def observed_run(value, rejected=False, stop=False):
    need(type(value) is dict, 'owned_run_observation_missing')
    result = {'provider': provider(value, rejected), 'process_cleanup': cleanup(value.get('process_cleanup')),
              'trace_sha256': digest(value.get('trace_sha256'))}
    if stop:
        result['observed_owned_role_counts'] = stop_roles(value)
    return result


def terminal(value, status, reasons=None, stop=False):
    need(value.get('entry_status' if stop else 'outcome') == status, 'owned_run_terminal_outcome_wrong')
    expected_cleanup = 'owned_processes_stopped_state_retained' if stop and status != 'completed' else \
        'owned_processes_stopped_audit_retained'
    need(value.get('cleanup') == expected_cleanup, 'owned_run_cleanup_outcome_wrong')
    if reasons is not None:
        need(value.get('entry_reason' if stop else 'failure_reason') in reasons, 'owned_run_failure_reason_wrong')


def project(raw, expected, exit_code):
    public = {'format': 'sou143-prepared-host-public/1', 'status': 'failed',
              'source_commit': expected, 'provider': 'owned-scripted-loopback', 'paid_api_calls': 0,
              'original_report_status': raw.get('status') if raw.get('status') in ('passed', 'failed') else 'unpublished',
              'qualifier_exit_code': exit_code, 'cases': [], 'emergency_stop': [],
              'raw_process_metadata_exported': False, 'raw_environments_or_logs_exported': False}
    errors = []
    try:
        need(raw.get('format') == 'sw-prepared-pilot-acceptance/1', 'raw_report_format_unavailable')
        public['source'] = source(raw.get('source_before'), expected)
        need(raw.get('source_after') == raw.get('source_before'), 'closing_source_identity_unproven')
        selected = raw.get('selected_sha256')
        need(type(selected) is dict and set(selected) == {'agentfw', 'git_launcher', 'sandbox_tests', 'node', 'npm',
             'bwrap', 'git', 'claude', 'python', 'filesystem_classifier', 'git_classifier', 'policy'},
             'selected_asset_identity_missing')
        public['selected_sha256'] = {key: digest(value) for key, value in selected.items()}
        need(selected['claude'] == HOST_SHA, 'pinned_actual_claude_identity_unproven')
        need(raw.get('unrelated_preserved') is True and raw.get('workspace_unchanged') is True
             and raw.get('selected_assets_unchanged') is True, 'inventory_preservation_unproven')
        rows = raw.get('cases')
        need(type(rows) is list and len(rows) <= len(CASES), 'case_ledger_invalid')
        need([row.get('case') for row in rows] == list(CASES), 'required_cases_missing_or_reordered')
    except Invalid as error:
        errors.append(str(error))
        rows = raw.get('cases', []) if type(raw.get('cases')) is list else []
    classifiers = 0
    for row in rows:
        name = row.get('case')
        if name not in CASES:
            errors.append('unknown_case_refused')
            continue
        result = {'case': name, 'status': 'failed'}
        public['cases'].append(result)
        try:
            need(row.get('status') == 'passed', 'case_not_passed')
            if name in PREFLIGHT:
                need(count(row.get('selected_execution')) == 0, 'refused_or_plan_execution_not_zero')
                if name in ('occupied-port', 'provider-unavailable'):
                    need(row.get('reason') == {'occupied-port': 'occupied_port_refused',
                         'provider-unavailable': 'provider_unavailable'}[name], 'preflight_refusal_reason_wrong')
                result['selected_execution'] = 0
                result['trace_sha256'] = digest(row.get('trace_sha256'))
            else:
                failures = {'provider-reject': {'restricted_launcher_failed'}, 'cancel': {'pilot_cancelled'},
                            'daemon-loss': {'owned_daemon_lost'}, 'host-crash': {'restricted_launcher_failed'},
                            'timeout': {'restricted_launcher_failed', 'pilot_timeout'}}
                terminal(row, 'failed' if name in failures else 'completed', failures.get(name))
                result.update(observed_run(row, rejected=name == 'provider-reject'))
                classifiers += result['provider']['successful_exec_counts']['classifier']
            result['status'] = 'passed'
        except Invalid as error:
            errors.append(str(error))
    section = raw.get('emergency_stop')
    try:
        need(type(section) is dict and section.get('status') == 'passed'
             and section.get('source_commit') == expected and section.get('paid_api_calls') == 0,
             'emergency_stop_evidence_unproven')
        stops = section.get('cases')
        need(type(stops) is list and [row.get('case') for row in stops] == list(STOP_CASES),
             'emergency_stop_case_denominator_missing')
    except Invalid as error:
        errors.append(str(error))
        stops = section.get('cases', []) if type(section) is dict and type(section.get('cases')) is list else []
    for row in stops:
        name = row.get('case')
        if name not in STOP_CASES:
            errors.append('unknown_stop_case_refused')
            continue
        result = {'case': name, 'status': 'failed'}
        public['emergency_stop'].append(result)
        try:
            need(row.get('status') == 'passed' and count(row.get('future_dispatches')) == 0, 'stop_case_not_proven')
            if name == 'two-prepared-runs':
                need(row.get('peer_original_dispatches_after_stop') == 2 and row.get('peer_useful_after_stop') is True
                     and row.get('future_kernel_reads') == 0 and row.get('unrelated_listener_preserved') is True
                     and row.get('unrelated_process_identity_preserved') is True
                     and row.get('running_effects_rolled_back') is False, 'stop_sibling_independence_unproven')
                controls = row.get('record_controls')
                need(type(controls) is list and [control.get('case') for control in controls] == list(FORGERY_CASES)
                     and all(control.get('status') == 'passed' and control.get('operator_refused') is True
                             for control in controls), 'stop_forgery_control_denominator_missing')
                terminal(row.get('selected', {}), 'stopped', stop=True)
                terminal(row.get('peer', {}), 'completed', stop=True)
                result['selected'] = observed_run(row.get('selected', {}), stop=True)
                result['peer'] = observed_run(row.get('peer', {}), stop=True)
                result['forgery_controls_passed'] = len(FORGERY_CASES)
                result.update(peer_original_dispatches_after_stop=2, peer_useful_after_stop=True,
                              future_kernel_reads=0, unrelated_listener_and_process_preserved=True)
            else:
                terminal(row, 'stopped' if name == 'interrupted-stop' else 'failed',
                         None if name == 'interrupted-stop' else
                         {'owned_daemon_lost'} if name == 'daemon-loss-stop' else {'restricted_launcher_failed'}, stop=True)
                result.update(observed_run(row, stop=True))
                if name == 'interrupted-stop':
                    need(row.get('interrupted_operator') is True, 'interrupted_stop_control_missing')
                else:
                    need(row.get('terminal_success_refused') is True, 'uncertain_stop_claimed_success')
            result.update(status='passed', future_dispatches=0)
        except Invalid as error:
            errors.append(str(error))
    if classifiers == 0:
        errors.append('provider_classifier_unobserved')
    if raw.get('status') != 'passed' or exit_code != 0:
        errors.append('qualifier_not_completed_successfully')
    public['verification_errors'] = sorted(set(errors))
    if not errors:
        public['status'] = 'passed'
    return public


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--raw', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--expected-commit', required=True)
    p.add_argument('--exit-code', type=int, required=True)
    a = p.parse_args()
    need(re.fullmatch(r'[0-9a-f]{40}', a.expected_commit), 'full_source_sha_required')
    if a.raw.exists() and a.raw.stat().st_size <= 4 * 1024 * 1024:
        rawbytes = a.raw.read_bytes()
        def pairs(items):
            value = {}
            for key, item in items:
                need(key not in value, 'duplicate_report_key')
                value[key] = item
            return value
        try:
            raw = json.loads(rawbytes, object_pairs_hook=pairs)
            need(type(raw) is dict, 'raw_report_object_required')
            public = project(raw, a.expected_commit, a.exit_code)
        except (ValueError, Invalid, TypeError, KeyError, AttributeError):
            public = {'format': 'sou143-prepared-host-public/1', 'status': 'failed',
                      'source_commit': a.expected_commit, 'verification_errors': ['raw_report_invalid']}
        public['private_report_sha256'] = hashlib.sha256(rawbytes).hexdigest()
    else:
        public = {'format': 'sou143-prepared-host-public/1', 'status': 'incomplete',
                  'source_commit': a.expected_commit, 'verification_errors': ['raw_report_missing_or_over_limit']}
    rendered = json.dumps(public, sort_keys=True, indent=2).encode() + b'\n'
    need(len(rendered) <= 128 * 1024, 'public_projection_bound')
    a.output.write_bytes(rendered)
    print(json.dumps({'status': public['status'], 'verification_errors': public['verification_errors']}))
    return 0 if public['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
