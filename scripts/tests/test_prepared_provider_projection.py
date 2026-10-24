# SPDX-License-Identifier: Apache-2.0
"""Mutation controls for public evidence; synthetic schema is not runtime proof."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('provider_projection', ROOT / 'scripts/ci/project-prepared-provider-host.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
SHA = 'b' * 64
COMMIT = 'a' * 40


def observation(rejected=False, stopped=False):
    processes = [{'pid': 910000 + i, 'start_time_ticks': 900001 + i, 'parent_process': i == 0} for i in range(8)]
    value = {'provider_routing': {'successful_exec_counts': {key: 1 for key in P.ROLES},
        'observation_stage': 'first-request-authentication-refusal' if rejected else 'original-server-runtime',
        'all_seven_inputs_in_intended_host': True, 'unrelated_provider_values': 0,
        'provider_values_in_argv': 0, 'raw_environment_exported': False},
        'provider_protocol': {'owned_loopback_requests': 2, 'expected_synthetic_authentication_seen': True,
            'credential_values_exported': False},
        'provider_private_logs': {'successful_private_log_writes': 2, 'private_log_bytes': 80,
            'all_selected_values_and_json_forms_absent': True, 'raw_log_exported': False,
            'owned_rejection_redaction_observed': rejected},
        'provider_retained_artifacts': {'retained_entries_checked': 2, 'retained_bytes_checked': 90,
            'intentional_observer_and_input_exclusions': 2, 'all_selected_values_and_json_forms_absent': True,
            'artifact_contents_exported': False},
        'process_cleanup': {'observed': processes, 'remaining': [], 'descendant_count': 7, 'all_stopped': True},
        'trace_sha256': SHA, 'observed_owned_roles': [dict(row, role=role, **({'server': server} if role == 'collector' else {}))
            for row, role, server in zip(processes[1:], ['host', 'collector', 'collector', 'owner', 'owner', 'pid1', 'pid1'],
                                        [None, 'filesystem', 'git', None, None, None, None])]}
    for row in value['observed_owned_roles']:
        row.pop('parent_process')
    value['private-marker'] = 'owned-private-do-not-export'
    value.update(outcome='completed', entry_status='stopped' if stopped else 'completed',
                 cleanup='owned_processes_stopped_state_retained' if stopped else 'owned_processes_stopped_audit_retained')
    return value


def fixture():
    source = {'commit': COMMIT, 'files_sha256': SHA, 'dirty': False}
    result = {'format': 'sw-prepared-pilot-acceptance/1', 'status': 'passed',
        'source_before': source, 'source_after': source.copy(),
        'selected_sha256': {key: P.HOST_SHA if key == 'claude' else SHA for key in
            ('agentfw', 'git_launcher', 'sandbox_tests', 'node', 'npm', 'bwrap', 'git', 'claude', 'python',
             'filesystem_classifier', 'git_classifier', 'policy')},
        'unrelated_preserved': True, 'workspace_unchanged': True, 'selected_assets_unchanged': True, 'cases': []}
    reasons = {'occupied-port': 'occupied_port_refused', 'provider-unavailable': 'provider_unavailable'}
    failures = {'provider-reject': 'restricted_launcher_failed', 'cancel': 'pilot_cancelled',
                'daemon-loss': 'owned_daemon_lost', 'host-crash': 'restricted_launcher_failed', 'timeout': 'pilot_timeout'}
    for name in P.CASES:
        row = {'case': name, 'status': 'passed'}
        if name in P.PREFLIGHT:
            row.update(selected_execution=0, trace_sha256=SHA, reason=reasons.get(name))
        else:
            row.update(observation(name == 'provider-reject'))
            if name in failures:
                row.update(outcome='failed', failure_reason=failures[name])
        result['cases'].append(row)
    stops = []
    for name in P.STOP_CASES:
        row = {'case': name, 'status': 'passed', 'future_dispatches': 0}
        if name == 'two-prepared-runs':
            row.update(selected=observation(stopped=True), peer=observation(), peer_original_dispatches_after_stop=2,
                peer_useful_after_stop=True, future_kernel_reads=0, unrelated_listener_preserved=True,
                unrelated_process_identity_preserved=True, running_effects_rolled_back=False,
                record_controls=[{'case': case, 'status': 'passed', 'operator_refused': True} for case in P.FORGERY_CASES])
        else:
            row.update(observation(stopped=True))
            if name == 'interrupted-stop':
                row['interrupted_operator'] = True
            else:
                row.update(entry_status='failed', terminal_success_refused=True,
                    entry_reason='owned_daemon_lost' if name == 'daemon-loss-stop' else 'restricted_launcher_failed')
        stops.append(row)
    result['emergency_stop'] = {'status': 'passed', 'source_commit': COMMIT, 'paid_api_calls': 0, 'cases': stops}
    return result


class FiniteEvidence(unittest.TestCase):
    def test_complete_schema_projects_counts_without_private_bytes(self):
        public = P.project(fixture(), COMMIT, 0)
        self.assertEqual(public['status'], 'passed', public['verification_errors'])
        rendered = json.dumps(public)
        for value in ('910000', '900001', 'owned-private-do-not-export', 'start_time_ticks'):
            self.assertNotIn(value, rendered)

    def test_missing_or_contradictory_witnesses_cannot_pass(self):
        cases = []
        raw = fixture(); raw['cases'].pop(); cases.append(raw)
        raw = fixture(); raw['emergency_stop']['cases'].pop(); cases.append(raw)
        raw = fixture(); raw['cases'][5]['provider_routing']['successful_exec_counts']['host'] = 0; cases.append(raw)
        raw = fixture(); raw['cases'][5]['provider_protocol']['expected_synthetic_authentication_seen'] = False; cases.append(raw)
        raw = fixture(); raw['cases'][5]['process_cleanup']['remaining'] = [{'private': 'synthetic'}]; cases.append(raw)
        raw = fixture(); raw['cases'][5]['provider_private_logs']['owned_rejection_redaction_observed'] = False; cases.append(raw)
        raw = fixture(); raw['emergency_stop']['cases'][0]['record_controls'].pop(); cases.append(raw)
        raw = fixture(); raw['cases'][5]['outcome'] = 'completed'; cases.append(raw)
        for index, raw in enumerate(cases):
            with self.subTest(index=index):
                self.assertNotEqual(P.project(raw, COMMIT, 0)['status'], 'passed')
        self.assertNotEqual(P.project(fixture(), COMMIT, 1)['status'], 'passed')

    def test_first_authentication_refusal_cannot_stand_in_for_original_runtime(self):
        raw = fixture()
        for role in ('original', 'collector', 'classifier'):
            raw['cases'][5]['provider_routing']['successful_exec_counts'][role] = 0
        self.assertEqual(P.project(raw, COMMIT, 0)['status'], 'passed')
        raw['cases'][6]['provider_routing']['successful_exec_counts']['original'] = 0
        self.assertNotEqual(P.project(raw, COMMIT, 0)['status'], 'passed')
