# SPDX-License-Identifier: Apache-2.0
"""Pure grader and mocked orchestration controls; never launch a native target."""
import copy
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, mock_open, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('sou136_controls', ROOT / 'scripts/verify-sou136-membership-lifetime.py')
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


def useful(identifier=10, semantic='c' * 64):
    return {'id': identifier, 'semantic_sha256': semantic, 'wire_sha256': 'a' * 64}


def stream():
    return {'bytes': 200, 'sha256': 'a' * 64, 'marker_leak': False, 'error': None,
            'buffer_peak': 200, 'thread_stopped': True,
            'records': [{'id': number, 'sha256': 'a' * 64, 'bytes': 100, 'successful_result': True}
                        for number in range(1, 161)], 'events': [], 'refusals': []}


def client(number, limits=None, profile='filesystem', exit_code=0):
    limits = limits or V.DEFAULT_LIMITS
    owner = {'format': V.SOU86.OWNER_FORMAT, 'instance': f'{number:032x}',
             'owner_pid': number * 10 + 1, 'owner_start_ticks': 100,
             'sandbox_pid': number * 10 + 2, 'sandbox_start_ticks': 101,
             'pid1_pid': number * 10 + 3, 'pid1_start_ticks': 102}
    members = [{'pid': owner[key], 'start_time_ticks': owner[ticks], 'worker_role': None}
               for key, ticks in (('owner_pid', 'owner_start_ticks'),
                                   ('sandbox_pid', 'sandbox_start_ticks'), ('pid1_pid', 'pid1_start_ticks'))]
    first = {'memory.max': limits['memoryMaxBytes'], 'memory.swap.max': 0, 'memory.oom.group': 1,
             'pids.max': limits['pidsMax'], 'cpu.max': [limits['cpuQuotaMicros'], 100000]}
    return {'exit_code': exit_code, 'forced_cleanup': False, 'budgeted': True,
            'direct_original_control': False, 'budget': dict(limits),
            'profile_sha256': ('f' if profile == 'filesystem' else 'e') * 64,
            'budget_sha256': f'{number:064x}', 'epoch_sha256': f'{number:064x}', 'owner': owner,
            'process': {'all_stopped': True, 'remaining': [], 'observed': copy.deepcopy(members), 'descendant_count': 3},
            'stdout': stream(), 'stderr': dict(stream(), records=[]),
            'kernel': {'leaf': f'agentfw-mcp-{number:032x}', 'inode': number,
                       'first': first, 'last': copy.deepcopy(first), 'samples': 12,
                       'memory_peak_bytes': 1000000, 'tasks_peak': 3,
                       'counter_max': {'oom': 0, 'oom_kill': 0, 'pids_max': 0, 'throttled': 0},
                       'members': members, 'remaining': [], 'leaf_removed': True, 'error': None,
                       'thread_stopped': True, 'shutdown_read': None}}


def crash(cp, label):
    return {'case': label, 'server_kind': 'filesystem', 'signal_target': 'collector', 'signal': 'SIGKILL',
            'owner': copy.deepcopy(cp['owner']), 'target': {'pid': 500, 'start_time_ticks': 99, 'signal_delivered': True},
            'client': copy.deepcopy(cp), 'armed_before_signal': True,
            'protection_acceptance': True, 'observation_bound_millis': V.SOU86.ACCEPTANCE_MILLIS,
            'observed_processes': copy.deepcopy(cp['kernel']['members']),
            'stdin_held_open_at_injection': True, 'live_at_deadline': [], 'identities_present_at_deadline': [],
            'protected_work_stopped_within_bound': True, 'all_identities_gone_within_bound': True,
            'leaf_removed_within_bound': True, 'process_stop_millis': 30, 'identities_gone_millis': 40,
            'leaf_remove_millis': 50, 'acceptance_fallback_used': False, 'cleanup_race': False,
            'previous_effects_rolled_back': False, 'immediate_native_retirement_claimed': False,
            'native_retirement': 'existing_300s_idle_expiry_on_next_authenticated_event',
            'in_flight': False, 'budgeted': True}


def attempt(kind, profile, number, *, cycle=None, limits=None, failed=False):
    label = f'{kind}-{profile}' + (f'-{cycle}' if cycle is not None else '')
    return {'case': label, 'kind': kind, 'profile': profile, 'cycle': cycle,
            'stage': 'complete', 'stages': ['planned', 'create', 'initialize', 'useful', 'complete'],
            'status': 'pass', 'failure_code': None, 'unexpected_closure': False,
            'server_origin': 'owned-calibration-fixture' if kind == 'control' else 'original-selected',
            'client': client(number, limits, profile, exit_code=1 if failed else 0),
            'useful': useful(semantic=('c' if profile == 'filesystem' else 'd') * 64)}


def control(name, number):
    row = attempt('control', 'filesystem', number, cycle=name, limits=V.CONTROL_LIMITS[name], failed=True)
    row.update(control=name, pending_dispatched=True, sibling_after=useful(152 + V.CONTROL_NAMES.index(name)))
    row['client']['stdout']['records'] = [record for record in row['client']['stdout']['records'] if record['id'] != 40]
    metadata = {'format': V.RESOURCE.BUDGET_FORMAT, 'failed': True, 'cleanup_verified': True,
                'budget_sha256': row['client']['budget_sha256'], 'leaf': row['client']['kernel']['leaf'],
                'reason': {'memory': 'mcp_budget_memory_exhausted', 'pids': 'mcp_budget_pids_exhausted',
                           'membership': 'mcp_budget_membership_unverified'}[name]}
    row['client']['stderr']['events'] = [{'event': 'mcp_real_budget_end', 'mode': 'enforced',
                                          'observed_failure': True, 'cleanup_verified': True, 'budget': metadata}]
    if name == 'memory':
        row['client']['kernel']['counter_max']['oom_kill'] = 1
        for member in row['client']['kernel']['members'][:2]:
            member['worker_role'] = 'memory'
    elif name == 'pids':
        row['client']['kernel']['counter_max']['pids_max'] = 1
        row['client']['kernel']['members'][0]['worker_role'] = 'sleep'
    else:
        row['violation'] = {'event':'sou136_membership_calibration','passed':True,
            'phase':'member_outside_leaf','leader_same_lifetime':True,'limits_unchanged':True,
            'owned_child_reaped':True,'leaf_removed':True,'quarantine_removed':True,
            'production_transport_claimed':False}
        row['native_control_log_sha256'] = 'a' * 64
    return row


def complete_report():
    args = SimpleNamespace(runtime_source_commit='b' * 40)
    report = V.initial_report(args)
    source = {'commit': 'b' * 40, 'tree': 'c' * 40, 'dirty': False}
    report.update(status='pass', passed=V.REQUIRED_ATTEMPTS, failed=0, incomplete=0,
                  source_before=source, source_after=copy.deepcopy(source), binaries_unchanged=True,
                  cleanup_verified=True, delegation_removed=True)
    report['identities'] = {name: 'a' * 64 for name in ('agentfw', 'git_launcher', 'node', 'npm', 'bwrap',
                                                      'git', 'python', 'driver', 'fixture', 'sandbox_test_binary')}
    report['identities']['dependencies'] = {name: 'a' * 64 for name in V.DEPENDENCIES}
    number = 1
    for profile in V.PROFILES:
        report['installations'][profile] = {key: 'a' * 64 for key in ('profile_sha256', 'registry_sha256',
            'policy_sha256', 'package_tree_sha256', 'config_sha256')}
        report['installations'][profile]['profile_sha256'] = ('f' if profile == 'filesystem' else 'e') * 64
        report['original_unchanged'][profile] = report['workspace_unchanged'][profile] = True
        report['attempts'].append(attempt('sibling', profile, number, limits=V.PEER_LIMITS))
        number += 1
        for cycle in range(1, V.CYCLES + 1):
            row = attempt('churn', profile, number, cycle=cycle)
            row['client']['exit_code'] = -V.signal.SIGKILL
            row['crash'] = crash(row['client'], row['case'])
            row['sibling_before'] = useful(10 + cycle * 2, row['useful']['semantic_sha256'])
            row['sibling_after'] = useful(11 + cycle * 2, row['useful']['semantic_sha256'])
            report['attempts'].append(row)
            number += 1
        row = attempt('capacity', profile, number)
        row.update(after_cycle=V.CYCLES, reclamation_wait_millis=2500)
        report['attempts'].append(row)
        number += 1
        if profile == 'filesystem':
            for name in V.CONTROL_NAMES:
                report['attempts'].append(control(name, number))
                number += 1
    return report


class GraderControls(unittest.TestCase):
    def test_complete_focused_witness_passes_accepted_graders(self):
        V.grade(complete_report())

    def assert_refused(self, mutate):
        report = complete_report()
        mutate(report)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            V.grade(report)

    def test_missing_duplicate_and_unordered_original_cycles_refuse(self):
        self.assert_refused(lambda r: r['attempts'].pop(53))
        self.assert_refused(lambda r: r['attempts'].append(copy.deepcopy(r['attempts'][53])))
        self.assert_refused(lambda r: r['attempts'][53].update(cycle=52))
        self.assert_refused(lambda r: r['attempts'][53].update(case=r['attempts'][52]['case']))

    def test_failure_cannot_be_replaced_by_a_later_pass_or_count(self):
        for changes in ({'status': 'fail', 'failure_code': 'case_failed'},
                        {'status': 'incomplete'}, {'unexpected_closure': True}, {'stage': 'initialize'}):
            self.assert_refused(lambda r, change=changes: r['attempts'][53].update(change))
        self.assert_refused(lambda r: r.update(retry_count=1))
        self.assert_refused(lambda r: r.update(error_code='qualification_failed'))

    def test_original_profile_and_independent_session_identities_required(self):
        self.assert_refused(lambda r: r['attempts'][1].update(server_origin='owned-calibration-fixture'))
        self.assert_refused(lambda r: r['attempts'][1]['client'].update(profile_sha256='0' * 64))
        self.assert_refused(lambda r: r['attempts'][2]['client'].update(epoch_sha256=r['attempts'][1]['client']['epoch_sha256']))
        self.assert_refused(lambda r: r['attempts'][2]['client']['owner'].update(instance=r['attempts'][1]['client']['owner']['instance']))
        self.assert_refused(lambda r: r['attempts'][1]['client']['budget'].update(wallMillis=120001))

    def test_restored_capacity_requires_fresh_useful_wire_result(self):
        def capacity(r):
            return next(row for row in r['attempts'] if row['kind'] == 'capacity')
        self.assert_refused(lambda r: capacity(r).update(after_cycle=69))
        self.assert_refused(lambda r: capacity(r).update(reclamation_wait_millis=3000))
        self.assert_refused(lambda r: capacity(r)['client']['stdout'].update(records=[]))
        self.assert_refused(lambda r: capacity(r)['useful'].update(semantic_sha256='0' * 64))

    def test_persistent_sibling_requires_correlated_fresh_work_each_cycle(self):
        self.assert_refused(lambda r: r['attempts'][1]['sibling_after'].update(id=999))
        self.assert_refused(lambda r: r['attempts'][1].update(sibling_after=copy.deepcopy(r['attempts'][1]['sibling_before'])))
        self.assert_refused(lambda r: r['attempts'][0]['client']['stdout'].update(records=[]))

    def test_missing_pressure_counters_workers_or_withheld_result_refuse(self):
        def find(r, name):
            return next(row for row in r['attempts'] if row.get('control') == name)
        self.assert_refused(lambda r: find(r, 'memory')['client']['kernel']['counter_max'].update(oom_kill=0))
        self.assert_refused(lambda r: find(r, 'pids')['client']['kernel']['counter_max'].update(pids_max=0))
        self.assert_refused(lambda r: find(r, 'memory')['client']['kernel'].update(members=[]))
        self.assert_refused(lambda r: find(r, 'pids')['client']['stdout']['records'].append(
            {'id': 40, 'successful_result': True, 'sha256': 'a' * 64}))
        self.assert_refused(lambda r: find(r, 'memory').update(server_origin='original-selected'))

    def test_membership_calibration_requires_owned_unreaped_lifetime_and_cleanup(self):
        def find(r):
            return next(row for row in r['attempts'] if row.get('control') == 'membership')
        for field in ('passed','leader_same_lifetime','limits_unchanged','owned_child_reaped',
                      'leaf_removed','quarantine_removed'):
            self.assert_refused(lambda r,key=field:find(r)['violation'].update({key:False}))
        self.assert_refused(lambda r:find(r)['violation'].update(production_transport_claimed=True))
        self.assert_refused(lambda r:find(r).update(native_control_log_sha256='missing'))
        self.assert_refused(lambda r:find(r)['violation'].update(phase='member_open'))

    def test_independent_cleanup_and_source_identity_cannot_be_omitted(self):
        self.assert_refused(lambda r: r.update(cleanup_verified=False))
        self.assert_refused(lambda r: r.update(delegation_removed=False))
        self.assert_refused(lambda r: r['source_after'].update(tree='d' * 40))
        self.assert_refused(lambda r: r.update(binaries_unchanged=False))
        self.assert_refused(lambda r: r['identities'].pop('driver'))
        self.assert_refused(lambda r: r['installations']['git'].pop('config_sha256'))
        for change in ({'samples': 0}, {'error': 'kernel_observation_failed'}, {'leaf_removed': False},
                       {'remaining': [{'pid': 1}]}, {'thread_stopped': False}):
            self.assert_refused(lambda r, c=change: r['attempts'][1]['client']['kernel'].update(c))


class OrchestrationControls(unittest.TestCase):
    def test_attempt_checkpoint_precedes_constructor_and_retains_failure(self):
        report = V.initial_report(SimpleNamespace(runtime_source_commit='a' * 40))
        snapshots = []
        save = lambda: snapshots.append(copy.deepcopy(report))

        def create():
            self.assertEqual(report['attempts'][0]['stage'], 'create')
            self.assertEqual(snapshots[0]['attempts'][0]['stage'], 'planned')
            raise ValueError('/private/secret token must never persist')

        with self.assertRaises(ValueError):
            V.run_case(report, save, 'churn', 'git', create, Mock(), cycle=53)
        row = report['attempts'][0]
        self.assertEqual(row['status'], 'fail')
        self.assertEqual(row['stage'], 'create')
        self.assertEqual(row['failure_code'], 'case_failed')
        self.assertNotIn('/private', str(snapshots))
        self.assertEqual(row['client'], None)

    def test_initialize_closure_is_retained_with_available_cleanup_witness(self):
        report = V.initial_report(SimpleNamespace(runtime_source_commit='a' * 40))
        cp = client(1)
        target = SimpleNamespace(process=SimpleNamespace(poll=lambda: 1),
                                 initialize=Mock(side_effect=ValueError('collector_closed_before_correlated_response')),
                                 close=Mock(return_value=cp))
        with self.assertRaises(ValueError):
            V.run_case(report, Mock(), 'churn', 'git', lambda: target, Mock(), cycle=53)
        row = report['attempts'][0]
        self.assertTrue(row['unexpected_closure'])
        self.assertEqual(row['failure_code'], 'collector_closed_before_response')
        self.assertEqual(row['stage'], 'initialize')
        self.assertIsNotNone(row['client']['kernel'])

    def test_churn_stops_on_first_unexpected_failure(self):
        report = V.initial_report(SimpleNamespace(runtime_source_commit='a' * 40))
        target = SimpleNamespace(initialize=Mock(), process=SimpleNamespace(poll=lambda: None),
                                 close=Mock(return_value=client(1, V.PEER_LIMITS)))
        args = SimpleNamespace(bwrap=Path('/missing/bwrap'))
        with patch.object(V.SELECTED, 'SelectedLivenessClient', return_value=target), \
             patch.object(V, 'useful_witness', return_value=useful()), \
             patch.object(V, 'run_case', side_effect=ValueError('first_case_failed')) as run_case, \
             patch.object(V.time, 'sleep') as sleep:
            with self.assertRaises(ValueError):
                V.profile_churn(report, Mock(), SimpleNamespace(), 'git', args)
        self.assertEqual(run_case.call_count, 1)
        sleep.assert_not_called()
        self.assertEqual(report['attempts'][0]['status'], 'fail')

    def test_projection_drops_raw_streams_paths_exception_bodies_and_unknown_phases(self):
        cp = client(1)
        cp.update(epoch='private-epoch', raw_stderr='/private/token', budget={'delegationRoot': '/private/path'})
        cp['process']['observed'][0]['cmdline'] = 'secret-token'
        cp['stderr'].update(raw='/private/secret', exception='secret-token')
        cp['stderr']['events'] = [{'event': 'mcp_real_budget_end', 'raw': '/private/secret',
            'budget': {'format': V.RESOURCE.BUDGET_FORMAT, 'membership_failure': {
                'phase': '/private/path', 'pid': 1, 'errno': 3}}}]
        projected = V.client_projection(cp, V.DEFAULT_LIMITS)
        rendered = str(projected)
        for secret in ('/private', 'secret-token', 'private-epoch', 'cmdline', 'raw_stderr'):
            self.assertNotIn(secret, rendered)
        self.assertEqual(projected['epoch_sha256'], V.digest(b'private-epoch'))

    def test_reviewed_finite_new_membership_phase_survives_projection(self):
        diagnostic = {'phase': 'member_pidfd_open', 'pid': 123, 'errno': 3}
        event = V.stream_projection(dict(stream(), events=[{'event': 'mcp_real_budget_end', 'budget': {
            'format': V.RESOURCE.BUDGET_FORMAT, 'membership_failure': diagnostic}}]))
        self.assertEqual(event['events'][0]['budget']['membership_failure'], diagnostic)

    def test_atomic_checkpoint_keeps_failed_and_unattempted_denominators(self):
        report = V.initial_report(SimpleNamespace(runtime_source_commit='a' * 40))
        V.begin_attempt(report, Mock(), 'churn', 'git', 53)
        V.fail_attempt(report['attempts'][0], ValueError('private error'))
        report.update(status='fail', error_code='qualification_failed')
        output = io.BytesIO()
        context = MagicMock()
        context.__enter__.return_value = SimpleNamespace(write=output.write, flush=Mock(), fileno=lambda: 10)
        path = MagicMock()
        temporary = path.with_suffix.return_value
        with patch.object(V.os, 'open', return_value=10), patch.object(V.os, 'fdopen', return_value=context), \
             patch.object(V.os, 'fsync'), patch.object(V.os, 'replace') as replace:
            V.checkpoint(path, report)
        self.assertEqual(report['failed'], 1)
        self.assertEqual(report['incomplete'], V.REQUIRED_ATTEMPTS - 1)
        replace.assert_called_once_with(temporary, path)
        temporary.unlink.assert_called_once_with(missing_ok=True)
        self.assertNotIn(b'private error', output.getvalue())

    def test_native_control_accepts_real_libtest_prefix_and_quiet_output(self):
        witness = control('membership', 9)['violation']
        encoded = json.dumps(witness, sort_keys=True, separators=(',', ':')).encode()
        for prefix in (b'', ('test ' + V.MEMBERSHIP_TEST + ' ... ').encode()):
            output = b'\nrunning 1 test\n' + prefix + encoded + b'\nok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 686 filtered out; finished in 0.01s\n\n'
            completed = SimpleNamespace(returncode=0, stdout=output, stderr=b'')
            event, hashed = V.native_membership_witness(completed)
            self.assertEqual(event, witness)
            self.assertEqual(hashed, V.digest(output))

    def test_native_control_cannot_cherry_pick_panic_or_ambiguous_json(self):
        witness = control('membership', 9)['violation']
        encoded = json.dumps(witness).encode()
        marker = b'1 passed; 0 failed'
        for code, output in ((101, encoded + b'\n' + marker),
                             (0, b'arbitrary prefix ' + encoded + b'\n' + marker),
                             (0, encoded + b'\n' + encoded + b'\n' + marker),
                             (0, encoded + b'\n0 passed; 1 failed'),
                             (0, b' ' * 65536 + encoded + marker)):
            with self.assertRaises(ValueError):
                V.native_membership_witness(SimpleNamespace(returncode=code, stdout=output, stderr=b''))

    def test_partial_constructor_is_registered_before_effects(self):
        rig=SimpleNamespace(_owned_clients=[])
        class Failed:
            def __init__(self,owner,label):
                self.owned=True
                raise ValueError('fixture-construction-failure')
        with self.assertRaises(ValueError):V.owned_client(Failed,rig,'owned')
        self.assertEqual(len(rig._owned_clients),1)
        self.assertTrue(rig._owned_clients[0].owned)

    def test_close_failure_does_not_skip_other_clients_or_daemon(self):
        first=Mock();first.close.side_effect=ValueError('private-error')
        second=Mock();second.close.return_value={'owned':'closed'}
        rig=SimpleNamespace(_owned_clients=[first,second],clients=[second],daemon=Mock(),
            daemon_witness=Mock(),daemon_stdout=Mock(),daemon_stderr=Mock(),audit=Mock(return_value={}))
        with patch.object(V,'cleanup_partial',return_value=[]),patch.object(V.BASE.DEMO,'stop') as stop:
            closed=V.close_rig(rig)
        second.close.assert_called_once();stop.assert_called_once_with(rig.daemon)
        rig.daemon.wait.assert_called_once_with(timeout=10)
        self.assertEqual(closed['error'],'cleanup_failed')
        self.assertNotIn('private-error',json.dumps(closed,default=str))


if __name__ == '__main__':
    unittest.main()
