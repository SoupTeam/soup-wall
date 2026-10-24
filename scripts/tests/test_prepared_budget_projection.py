# SPDX-License-Identifier: Apache-2.0
"""Mutation controls for finite evidence. These fixtures are not runtime proof."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('budget_projection', ROOT / 'scripts/ci/project-prepared-budget-host.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
SHA, COMMIT = 'b' * 64, 'a' * 40


def fixture():
    selected = {key: SHA for key in ('agentfw', 'git_launcher', 'sandbox_tests', 'python',
                                    'node', 'bwrap_source', 'git', 'claude')}
    attempt = {'format': 'sou142-offline-budget-host-attempt/1',
        'status': 'partial-runtime-completed-pending-parent-projection', 'source_commit': COMMIT,
        'selected_sha256': selected, 'selection_sha256': SHA, 'budget_sha256': SHA,
        'peer_budget_sha256': SHA, 'owned_peer_budget_root_empty': True,
        'budgeted_emergency_stop_qualified': True,
        'owned_budget_root_empty': True, 'actual_original_host_covered': True, 'owner_controls': []}
    for server in ('filesystem', 'git'):
        for handoff in (False, True):
            attempt['owner_controls'].append({'server': server, 'status': 'pass',
                'stage': 'prepared-handback-before-adoption-ack' if handoff else 'prepared-before-owner',
                'leaf_created': handoff, 'original_started': False, 'owned_members': 0,
                'production_cleanup_verified': True, 'witness_cleanup_attempted': False,
                'budget_sha256': SHA, 'binary_sha256': SHA, 'owner_binary_sha256': SHA})
    source = {'commit': COMMIT, 'dirty': False}
    raw = {'format': 'sw-prepared-pilot-acceptance/1', 'status': 'passed',
        'source_before': source, 'source_after': source.copy(), 'unrelated_preserved': True,
        'workspace_unchanged': True, 'selected_assets_unchanged': True, 'cases': [],
        'selected_sha256': {'bwrap' if key == 'bwrap_source' else key: value for key, value in selected.items()}}
    for name in P.CASES:
        row = {'case': name, 'status': 'passed', 'trace_sha256': SHA}
        if name not in P.HOST:
            row['selected_execution'] = 0
        else:
            success = name in ('useful-refusal', 'ask', 'default')
            row.update(outcome='completed' if success else 'failed', cleanup='owned_processes_stopped_audit_retained',
                process_cleanup={'observed': [
                    {'pid': 910001, 'start_time_ticks': 921001, 'parent_process': True},
                    {'pid': 910002, 'start_time_ticks': 921002, 'parent_process': False}],
                    'remaining': [], 'all_stopped': True, 'descendant_count': 1},
                resource_budget={'format': 'sw-prepared-pilot-budget/1', 'budget_sha256': SHA,
                    'scope': 'per-original-server-process-tree', 'observed_children': 2,
                    'failed_children': 0, 'unresolved_children': 0, 'status': 'closed-enforced',
                    'observations': [{'server_id': server, 'phase': 'closed', 'reason': 'mcp_budget_enforced',
                        'counters': {'memory_peak_bytes': 1024, 'pids_peak_kernel': True}}
                        for server in ('filesystem', 'git')]})
            if success:
                row.update(exact_once_kernel_read=True,
                    dispatch_counts={'useful-refusal': [1, 1, 0], 'ask': [1, 1, 1], 'default': [1, 0]}[name],
                    explicit_harness_decisions=2 if name == 'ask' else 0)
                if name == 'useful-refusal':
                    row['kernel_git_status_count'] = 1
        raw['cases'].append(row)
    stops = []
    for name in ('two-prepared-runs', 'interrupted-stop', 'daemon-loss-stop', 'unconfirmed-namespace-stop'):
        row = copy.deepcopy(raw['cases'][4])
        row.update(case=name, future_dispatches=0)
        if name == 'two-prepared-runs':
            row = {'case': name, 'status': 'passed', 'future_dispatches': 0,
                'selected': row, 'peer': copy.deepcopy(row), 'peer_useful_after_stop': True,
                'peer_original_dispatches_after_stop': 2, 'unrelated_process_identity_preserved': True,
                'unrelated_listener_preserved': True}
        stops.append(row)
    raw['emergency_stop'] = {'status': 'passed', 'source_commit': COMMIT, 'cases': stops}
    raw['private-marker'] = 'private-owned-do-not-export'
    return attempt, raw


class Projection(unittest.TestCase):
    def test_slice_never_becomes_full_acceptance_or_exports_private_observations(self):
        a, r = fixture()
        result = P.project(a, r, COMMIT, 0)
        self.assertEqual(result['status'], 'partial-slice-passed')
        self.assertIs(result['acceptance_pass'], False)
        self.assertIs(result['full_sou142_qualification'], False)
        self.assertEqual(result['remaining_gaps'], list(P.GAPS))
        rendered = json.dumps(result)
        for private in ('910001', '921002', 'private-owned-do-not-export', 'start_time_ticks'):
            self.assertNotIn(private, rendered)

    def test_missing_controls_cleanup_identity_effects_or_receipts_cannot_pass(self):
        a, r = fixture()
        mutations = [
            lambda x, y: x['owner_controls'].pop(),
            lambda x, y: x.update(owned_budget_root_empty=False),
            lambda x, y: x['owner_controls'][0].update(witness_cleanup_attempted=True),
            lambda x, y: x['owner_controls'][1].update(owner_binary_sha256='c' * 64),
            lambda x, y: y['cases'].pop(),
            lambda x, y: y['cases'][4]['resource_budget'].update(budget_sha256='c' * 64),
            lambda x, y: y['cases'][4]['resource_budget']['observations'].pop(),
            lambda x, y: y['cases'][4]['resource_budget']['observations'][1].update(server_id='filesystem'),
            lambda x, y: y['cases'][4]['process_cleanup']['remaining'].append({'pid': 999}),
            lambda x, y: y['cases'][4].update(exact_once_kernel_read=False),
            lambda x, y: y['cases'][4].update(kernel_git_status_count=0),
            lambda x, y: y['cases'][5].update(explicit_harness_decisions=0),
            lambda x, y: y['selected_sha256'].update(agentfw='c' * 64),
            lambda x, y: x.update(owned_peer_budget_root_empty=False),
            lambda x, y: y['emergency_stop']['cases'][0].update(peer_useful_after_stop=False),
            lambda x, y: y['emergency_stop']['cases'].pop(),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                x, y = copy.deepcopy((a, r))
                mutate(x, y)
                self.assertEqual(P.project(x, y, COMMIT, 0)['status'], 'failed')
        self.assertEqual(P.project(a, r, COMMIT, 1)['status'], 'failed')

    def test_failure_diagnostics_are_finite_even_for_malformed_reports(self):
        a, r = fixture()
        r['emergency_stop']['cases'][0]['failure_observations'] = [
            {'entry_status': 'failed', 'entry_reason': 'private_marker_do_not_publish',
             'budget_status': 'unresolved', 'pid': 910001, 'start_time_ticks': 921002}]
        result = P.project(a, r, COMMIT, 1)
        self.assertEqual(result['failure_observations'], [{'entry_status': 'failed', 'budget_status': 'unresolved'}])
        for malformed in (None, [], True):
            self.assertEqual(P.project(a, malformed, COMMIT, 1)['status'], 'failed')
        r['emergency_stop']['cases'] = True
        self.assertEqual(P.project(a, r, COMMIT, 1)['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
