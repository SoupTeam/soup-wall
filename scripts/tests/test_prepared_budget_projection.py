# SPDX-License-Identifier: Apache-2.0
"""Mutation controls for finite evidence. These fixtures are not runtime proof."""
import ast
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
            if name == 'provider-unavailable':
                row['reason'] = 'provider_unavailable'
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
        row = copy.deepcopy(next(row for row in raw['cases'] if row['case'] == 'useful-refusal'))
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
    def test_case_inventory_matches_actual_default_producer(self):
        source = ast.parse((ROOT / 'scripts/qualify-prepared-pilot-run.py').read_text())
        qualify = next(node for node in source.body if isinstance(node, ast.FunctionDef) and node.name == 'qualify')
        preflight = next(node for node in ast.walk(qualify) if isinstance(node, ast.For)
                         and isinstance(node.target, ast.Name) and node.target.id == 'control')
        runtime = next(node for node in ast.walk(qualify) if isinstance(node, ast.Assign)
                       and any(isinstance(target, ast.Name) and target.id == 'cases' for target in node.targets))
        self.assertEqual(P.CASES, ast.literal_eval(preflight.iter) + ast.literal_eval(runtime.value))
        self.assertEqual(len(P.CASES), 12)
        self.assertEqual(len(P.HOST), 7)

    def test_provider_preflight_is_mandatory_and_cannot_claim_execution(self):
        a, r = fixture()
        self.assertEqual(P.project(a, r, COMMIT, 0)['status'], 'partial-slice-passed')
        for mutation in ('missing', 'duplicate', 'execution', 'reason'):
            with self.subTest(mutation=mutation):
                altered = copy.deepcopy(r)
                row = next(row for row in altered['cases'] if row['case'] == 'provider-unavailable')
                if mutation == 'missing':
                    altered['cases'].remove(row)
                elif mutation == 'duplicate':
                    altered['cases'].insert(4, copy.deepcopy(row))
                elif mutation == 'execution':
                    row['selected_execution'] = 1
                else:
                    row['reason'] = 'owned_secret_never_export'
                result = P.project(a, altered, COMMIT, 0)
                self.assertEqual(result['status'], 'failed')
                self.assertNotIn('owned_secret_never_export', json.dumps(result))

    def test_owner_loss_is_an_explicit_unsupported_negative_control(self):
        attempt, _ = fixture()
        attempt.update(phase='owner-loss', status='owner-loss-unsupported-fail-closed',
            source_read_only=True, reused_binaries_read_only=True,
            network='private-loopback-only', provider='owned-scripted-loopback',
            paid_api_calls=0, actual_original_host_covered=False,
            full_sou142_qualification=False, remaining_gaps=list(P.GAPS))
        attempt['owner_controls'] = [
            {'server': server, 'status': 'unsupported-fail-closed',
             'stage': 'owner-loss-before-descriptor-handback', 'leaf_created': True,
             'original_started': False, 'owned_members': 0,
             'owner_held_leaf_descriptor': True,
             'collector_had_no_leaf_descriptor': True,
             'production_cleanup_verified': False, 'witness_cleanup_attempted': True,
             'inventory_restored': True, 'budget_sha256': SHA,
             'binary_sha256': SHA, 'owner_binary_sha256': SHA}
            for server in ('filesystem', 'git')]
        observed = P.project_owner_loss(attempt, COMMIT, 0)
        self.assertEqual(observed['status'], 'unsupported-fail-closed-observed')
        self.assertIs(observed['acceptance_pass'], False)
        self.assertIs(observed['full_sou142_qualification'], False)
        self.assertIn('owner-loss-before-descriptor-handback', observed['remaining_gaps'])
        for mutate in (
            lambda x: x['owner_controls'].pop(),
            lambda x: x['owner_controls'][0].update(original_started=True),
            lambda x: x['owner_controls'][0].update(production_cleanup_verified=True),
            lambda x: x['owner_controls'][0].update(witness_cleanup_attempted=False),
            lambda x: x['owner_controls'][0].update(owned_members=1),
            lambda x: x['owner_controls'][0].update(owner_held_leaf_descriptor=False),
            lambda x: x['owner_controls'][0].update(collector_had_no_leaf_descriptor=False),
            lambda x: x['owner_controls'][0].update(owner_binary_sha256='c' * 64),
            lambda x: x.update(owned_budget_root_empty=False),
            lambda x: x.update(full_sou142_qualification=True),
            lambda x: x.update(remaining_gaps=[]),
            lambda x: x.update(source_commit='c' * 40),
        ):
            invalid = copy.deepcopy(attempt)
            mutate(invalid)
            self.assertEqual(P.project_owner_loss(invalid, COMMIT, 0)['status'], 'failed')
        self.assertEqual(P.project_owner_loss(attempt, COMMIT, 1)['status'], 'failed')

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

    def test_pressure_requires_original_kernel_refusal_and_fresh_peer_recovery(self):
        a, raw = fixture()
        rows = []
        normal_budget = next(row for row in raw['cases'] if row['case'] == 'useful-refusal')['resource_budget']
        for server in ('filesystem', 'git'):
            for kind in ('memory', 'pids', 'wall'):
                rows.append({'server':server, 'resource':kind, 'status':'passed',
                    'budget_sha256':SHA, 'forced_cleanup':False, 'server_origin':'pinned-original',
                    'limits':{'memoryMaxBytes':64*1024*1024 if kind=='memory' else 512*1024*1024,
                        'pidsMax':16 if kind=='pids' else 64, 'cpuQuotaMicros':100000,
                        'wallMillis':1000 if kind=='wall' else 120000},
                    'reason':'original_resource_refusal_verified', 'original_runtime_observed':True,
                    'owned_cleanup_verified':True, 'peer_useful_after_subject':True, 'peer_survived_kernel_refusal':True,
                    'fresh_prepared_recovery_useful':True, 'observed_children':2,
                    'kernel_observations':[{'counter_max':{'oom':1,'oom_kill':1,'pids_max':1,'throttled':0},
                        'memory_peak_bytes':1000,'tasks_peak':16,'leaf_duration_millis':5,'removed':True,
                        'errors':[],'incomplete_reasons':[]}],
                    'target_receipts':[{'server_id':server,'phase':'closed','reason':{
                        'memory':'mcp_budget_memory_exhausted','pids':'mcp_budget_pids_exhausted',
                        'wall':'mcp_budget_wall_expired'}[kind]}],
                    'trace_sha256':SHA,'peer_budget':copy.deepcopy(normal_budget),
                    'recovery_budget':copy.deepcopy(normal_budget), 'private-marker':'never-publish'})
        value={'format':'sou142-original-pressure/1','status':'passed','workspace_unchanged':True,
            'raw_process_metadata_exported':False,'observer_cleanup_performed':False,'attempts':rows}
        self.assertEqual(P.pressure(value,a)['status'],'passed')
        self.assertNotIn('never-publish',json.dumps(P.pressure(value,a)))
        separate=copy.deepcopy(a)
        separate.update(phase='pressure', original_pressure=copy.deepcopy(value), source_read_only=True,
            reused_binaries_read_only=True, network='private-loopback-only', provider='owned-scripted-loopback',
            paid_api_calls=0, actual_original_host_covered=False,
            git_calibration_fixture={'tracked_head':True,'index_entries':30001,
                'config_unchanged':True,'test_workers_or_runtime_changes':False})
        public=P.project_pressure(separate,COMMIT,0)
        self.assertEqual(public['status'],'pressure-slice-passed',public)
        self.assertIs(public['baseline_required_separately'],True)
        self.assertIs(public['acceptance_pass'],False)
        self.assertNotEqual(P.project(separate,raw,COMMIT,0)['status'],'partial-slice-passed')
        for change in (lambda v:v.update(phase='baseline'), lambda v:v.update(source_read_only=False),
                       lambda v:v.update(source_commit='c'*40), lambda v:v.update(owned_peer_budget_root_empty=False),
                       lambda v:v.update(original_pressure=None), lambda v:v.update(paid_api_calls=1),
                       lambda v:v['git_calibration_fixture'].update(tracked_head=False),
                       lambda v:v['git_calibration_fixture'].update(test_workers_or_runtime_changes=True),
                       lambda v:v.update(actual_original_host_covered=True),
                       lambda v:v['original_pressure']['attempts'].pop()):
            bad=copy.deepcopy(separate);change(bad)
            self.assertNotEqual(P.project_pressure(bad,COMMIT,0)['status'],'pressure-slice-passed')
        self.assertNotEqual(P.project_pressure(separate,COMMIT,1)['status'],'pressure-slice-passed')
        for mutate in [lambda v:v['attempts'].pop(),
            lambda v:v['attempts'][0].update(original_runtime_observed=False),
            lambda v:v['attempts'][0].update(fresh_prepared_recovery_useful=False),
            lambda v:v['attempts'][0]['kernel_observations'][0]['counter_max'].update(oom_kill=0),
            lambda v:v['attempts'][1]['kernel_observations'][0]['counter_max'].update(pids_max=0),
            lambda v:v['attempts'][0]['target_receipts'][0].update(phase='active-at-attachment'),
            lambda v:v['attempts'][0].update(forced_cleanup=True)]:
            changed=copy.deepcopy(value); mutate(changed)
            with self.assertRaises(P.Invalid):P.pressure(changed,a)
        self.assertEqual(P.pressure(None,a)['status'],'unavailable')
        value['status']='incomplete'; value['attempts'][0]['status']='incomplete'
        value['attempts'][0]['reason']='original_resource_refusal_unproven'
        self.assertEqual(P.pressure(value,a)['status'],'incomplete')

    def test_missing_controls_cleanup_identity_effects_or_receipts_cannot_pass(self):
        a, r = fixture()
        mutations = [
            lambda x, y: x['owner_controls'].pop(),
            lambda x, y: x.update(owned_budget_root_empty=False),
            lambda x, y: x['owner_controls'][0].update(witness_cleanup_attempted=True),
            lambda x, y: x['owner_controls'][1].update(owner_binary_sha256='c' * 64),
            lambda x, y: y['cases'].pop(),
            lambda x, y: next(row for row in y['cases'] if row['case'] == 'useful-refusal')['resource_budget'].update(budget_sha256='c' * 64),
            lambda x, y: next(row for row in y['cases'] if row['case'] == 'useful-refusal')['resource_budget']['observations'].pop(),
            lambda x, y: next(row for row in y['cases'] if row['case'] == 'useful-refusal')['resource_budget']['observations'][1].update(server_id='filesystem'),
            lambda x, y: next(row for row in y['cases'] if row['case'] == 'useful-refusal')['process_cleanup']['remaining'].append({'pid': 999}),
            lambda x, y: next(row for row in y['cases'] if row['case'] == 'useful-refusal').update(exact_once_kernel_read=False),
            lambda x, y: next(row for row in y['cases'] if row['case'] == 'useful-refusal').update(kernel_git_status_count=0),
            lambda x, y: next(row for row in y['cases'] if row['case'] == 'ask').update(explicit_harness_decisions=0),
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
