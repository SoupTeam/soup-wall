# SPDX-License-Identifier: Apache-2.0
"""Independent crash-oracle negative controls; inventory never means containment."""
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('sou86_controls', ROOT / 'scripts/verify-sou86-crash-supervision.py')
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


def complete_inventory():
    stream = {'thread_stopped': True, 'error': None, 'marker_leak': False, 'buffer_peak': 0,
              'records': [], 'bytes': 0, 'sha256': 'b' * 64}
    rows = []
    for name in sorted(V.INVENTORY_CASES):
        fixture = name.startswith('owned-')
        restart = name.endswith('-restart')
        output = copy.deepcopy(stream)
        output['records'] = [{'id': 10, 'successful_result': True, 'sha256': 'a' * 64}]
        rows.append({'case': name, 'client': {'exit_code': 0 if restart else -9, 'forced_cleanup': False,
                     'stdout': output, 'stderr': copy.deepcopy(stream),
                     'kernel': {'leaf_removed': restart, 'samples': 10, 'thread_stopped': True, 'error': None,
                                'members': [{'pid': 101, 'start_time_ticks': 5}]}},
                     'in_flight': fixture, 'signal_target': 'collector' if 'collector' in name else 'wrapper',
                     'stdin_held_open_at_injection': True, 'observed_processes': [
                         {'pid': 101, 'start_time_ticks': 5, 'fixture_role': 'direct' if fixture else None},
                         {'pid': 102, 'start_time_ticks': 6, 'fixture_role': 'detached' if fixture else None}],
                     'observation_bound_millis': V.INVENTORY_MILLIS, 'target': {'pid': 101, 'start_time_ticks': 5},
                     'leaf_removed_within_bound': restart, 'useful_wire_sha256': 'a' * 64})
    return {'format': V.FORMAT, 'mode': 'baseline-inventory', 'runtime_source_commit': V.ACCEPTED,
            'failed': 0, 'skipped': 0, 'required_cases': len(V.INVENTORY_CASES),
            'source_before': {'commit': 'c' * 40, 'dirty': False},
            'source_after': {'commit': 'c' * 40, 'dirty': False}, 'binary_unchanged': True,
            'delegation': {'unprivileged': True, 'manager_membership_verified': True},
            'original_unchanged': True, 'workspace_unchanged': True, 'delegation_removed': True,
            'protection_acceptance': False, 'inventory': rows,
            'stream_calibration': {'stderr': {'marker_leak': True, 'thread_stopped': True,
                                             'sha256': V.digest(V.RESOURCE.CALIBRATION_BYTES)}},
            'cleanup': {'daemon_process': {'all_stopped': True}, 'daemon_stdout': copy.deepcopy(stream),
                        'daemon_stderr': copy.deepcopy(stream), 'audit': {'marker_leak': False}}}


def complete_acceptance():
    report = complete_inventory()
    report.update(mode='acceptance', protection_acceptance=True, runtime_source_commit='c' * 40,
                  required_cases=len(V.CASES),
                  git_original_unchanged=True, git_workspace_unchanged=True, original_controls=[],
                  acceptance=[], startup_inventory={'protection_acceptance': False, 'empty_at_deadline': True,
                                                    'live_at_deadline': []})
    report['git_cleanup'] = copy.deepcopy(report['cleanup'])
    for key in ('binary_sha256', 'driver_sha256', 'fixture_sha256', 'fixture_package_tree_sha256',
                'config_sha256', 'git_config_sha256', 'git_binary_sha256', 'git_launcher_sha256'):
        report[key] = 'a' * 64
    for key in ('original_server', 'original_git_server'):
        report[key] = dict(profile_sha256='a' * 64, registry_sha256='a' * 64, policy_sha256='a' * 64,
                           profile={'packageTreeSha256': 'a' * 64})
    template = complete_inventory()['inventory'][0]['client']
    template['process'] = {'all_stopped': True, 'remaining': []}
    template['kernel'].update(leaf_removed=True, remaining=[])
    for index, name in enumerate(sorted(V.CASES), 1):
        fixture = name.startswith('owned-') or name.startswith('repeat-')
        ordinary = name.endswith('-useful') or name in ('fixture-private-boundary', 'restart-after-crash', 'peer-isolation')
        owner = {'format': V.OWNER_FORMAT, 'instance': f'{index:032x}',
                 'owner_pid': 101, 'owner_start_ticks': 5, 'sandbox_pid': 102, 'sandbox_start_ticks': 6,
                 'pid1_pid': 103, 'pid1_start_ticks': 7}
        client = copy.deepcopy(template)
        client.update(exit_code=0 if ordinary else -9, server_kind='git' if 'original-git' in name else 'filesystem',
                      budgeted='unbudgeted' not in name, owner=owner, epoch=f'mcp:epoch-{index}',
                      direct_original_control=False)
        client['stderr']['events'] = [{'event': 'mcp_real_server_end', 'cleanup_verified': True}]
        row = {'case': name, 'client': client, 'protection_acceptance': True}
        if not ordinary:
            row.update(armed_before_signal=True, observation_bound_millis=V.ACCEPTANCE_MILLIS,
                stdin_held_open_at_injection=True, protected_work_stopped_within_bound=True,
                all_identities_gone_within_bound=True, leaf_removed_within_bound=True,
                live_at_deadline=[], identities_present_at_deadline=[], acceptance_fallback_used=False,
                process_stop_millis=5, identities_gone_millis=8, leaf_remove_millis=7,
                owner=owner, target={'signal_delivered': True}, cleanup_race=name == 'cleanup-race',
                signal_target='owner' if 'owner' in name else 'collector', signal='SIGSTOP' if name == 'owned-owner-stop' else 'SIGKILL',
                guardian_stop_observed=name == 'owned-owner-stop', in_flight=fixture,
                immediate_native_retirement_claimed=False, previous_effects_rolled_back=False,
                native_retirement='existing_300s_idle_expiry_on_next_authenticated_event',
                observed_processes=[{'pid': 101, 'start_time_ticks': 5, 'fixture_role': 'direct' if fixture else None},
                                    {'pid': 102, 'start_time_ticks': 6, 'fixture_role': 'detached' if fixture else None},
                                    {'pid': 103, 'start_time_ticks': 7, 'fixture_role': None}])
        if name.endswith('-useful') or name == 'restart-after-crash':
            row['useful_wire_sha256'] = 'a' * 64
        if name == 'cancel-crash':
            row['cancellation'] = {'independent_inflight_fifo_readers': 8, 'cancelled_ids': [28, 20],
                                    'queued_reader_absent': True, 'bytes_written_before_crash': 0}
        if name == 'fixture-private-boundary':
            row['private_boundary'] = {'private_lease_absent': True, 'host_control_fds_absent': True,
                                       'pid1_private_fds_denied': True, 'pid1_memory_denied': True}
        report['acceptance'].append(row)
    peer = next(row for row in report['acceptance'] if row['case'] == 'peer-isolation')
    peer_cases = {row['case'] for row in report['acceptance'] if row.get('signal_target')} | {'restart-after-crash', 'prearm-startup-inventory'}
    report['peer_checks'] = []
    for index, name in enumerate(sorted(peer_cases), 1):
        before, after = {'id': 100 + index * 2, 'sha256': 'a' * 64}, {'id': 101 + index * 2, 'sha256': 'a' * 64}
        report['peer_checks'].append({'case': name, 'before': before, 'after': after})
        peer['client']['stdout']['records'].extend([{**item, 'successful_result': True} for item in (before, after)])
    peer['useful_followups'] = len(peer_cases)
    for kind in ('filesystem', 'git'):
        client = copy.deepcopy(template)
        client.update(direct_original_control=True, exit_code=0)
        report['original_controls'].append({'kind': kind, 'wire_sha256': 'a' * 64, 'client': client})
    return report


class InventoryControls(unittest.TestCase):
    def test_zombie_cmdline_cannot_erase_witnessed_detached_identity(self):
        original = {'pid': 102, 'start_time_ticks': 6, 'fixture_role': 'detached', 'trusted_role': None,
                    'state': 'S', 'session': 102, 'process_group': 102}
        observed = {}
        V.merge_members(observed, {(102, 6): original})
        zombie = dict(original, state='Z', fixture_role=None)
        V.merge_members(observed, {(102, 6): zombie})
        self.assertEqual(observed[(102, 6)]['state'], 'Z')
        self.assertEqual(observed[(102, 6)]['fixture_role'], 'detached')
        self.assertTrue(observed[(102, 6)]['detached_session_verified'])
        reused = dict(zombie, start_time_ticks=7, session=100, process_group=100)
        V.merge_members(observed, {(102, 7): reused})
        self.assertIsNone(observed[(102, 7)]['fixture_role'])
        self.assertFalse(observed[(102, 7)]['detached_session_verified'])

    def test_complete_inventory_retains_explicit_non_acceptance(self):
        report = complete_inventory()
        V.grade_inventory(report)
        self.assertEqual(len(report['checks']), len(V.INVENTORY_CASES))
        self.assertTrue(all(row['protection_acceptance'] is False for row in report['checks']))

    def test_inventory_cannot_be_promoted_to_protection_or_wrong_baseline(self):
        for changes in ({'protection_acceptance': True}, {'runtime_source_commit': 'd' * 40}, {'mode': 'acceptance'}):
            report = complete_inventory()
            report.update(changes)
            with self.assertRaises(ValueError):
                V.grade_inventory(report)

    def test_every_required_case_and_no_duplicates_are_required(self):
        for index in range(len(V.INVENTORY_CASES)):
            report = complete_inventory()
            report['inventory'].pop(index)
            with self.assertRaisesRegex(ValueError, 'inventory_cases_missing'):
                V.grade_inventory(report)
        report = complete_inventory()
        report['inventory'].append(copy.deepcopy(report['inventory'][0]))
        with self.assertRaisesRegex(ValueError, 'inventory_cases_missing'):
            V.grade_inventory(report)

    def test_inventory_requires_observed_gap_before_any_harness_recovery(self):
        report = complete_inventory()
        for row in report['inventory']:
            row['leaf_removed_within_bound'] = True
        with self.assertRaisesRegex(ValueError, 'accepted_gap_not_reproduced'):
            V.grade_inventory(report)

    def test_both_direct_and_detached_descendants_must_be_independently_observed(self):
        report = complete_inventory()
        fixture = next(row for row in report['inventory'] if row['in_flight'])
        fixture['observed_processes'] = fixture['observed_processes'][:1]
        with self.assertRaisesRegex(ValueError, 'owned_descendant_inventory_missing'):
            V.grade_inventory(report)

    def test_crash_must_keep_input_open_and_have_bound_signal_identity(self):
        for change in (lambda row: row.update(stdin_held_open_at_injection=False),
                       lambda row: row.update(observed_processes=[]),
                       lambda row: row.update(observation_bound_millis=1),
                       lambda row: row.update(target={'pid': 101, 'start_time_ticks': 0})):
            report = complete_inventory()
            change(next(row for row in report['inventory'] if row['case'] != 'original-filesystem-restart'))
            with self.assertRaises(ValueError):
                V.grade_inventory(report)

    def test_late_inflight_success_is_rejected(self):
        report = complete_inventory()
        row = next(row for row in report['inventory'] if row['in_flight'])
        row['client']['stdout']['records'].append({'id': 40, 'successful_result': True})
        with self.assertRaisesRegex(ValueError, 'late_fixture_result_released'):
            V.grade_inventory(report)

    def test_observer_failure_zero_samples_or_missing_members_cannot_pass(self):
        for changes in ({'error': 'read_failed'}, {'samples': 0}, {'members': []}, {'thread_stopped': False}):
            report = complete_inventory()
            report['inventory'][0]['client']['kernel'].update(changes)
            with self.assertRaisesRegex(ValueError, 'independent_inventory_observer_incomplete'):
                V.grade_inventory(report)

    def test_useful_work_requires_independent_wire_record(self):
        report = complete_inventory()
        report['inventory'][0]['client']['stdout']['records'] = []
        with self.assertRaisesRegex(ValueError, 'original_useful_work_not_observed'):
            V.grade_inventory(report)

    def test_source_changes_fallback_kill_or_missing_restart_fail_inventory(self):
        for change in (lambda report: report['source_after'].update(commit='d' * 40),
                       lambda report: report.update(binary_unchanged=False),
                       lambda report: report['inventory'][0]['client'].update(forced_cleanup=True),
                       lambda report: next(row for row in report['inventory'] if row['case'].endswith('-restart'))['client'].update(exit_code=1)):
            report = complete_inventory()
            change(report)
            with self.assertRaises(ValueError):
                V.grade_inventory(report)

    def test_plan_executes_nothing_and_declares_real_nonempty_inventory(self):
        command = [sys.executable, '-B', str(ROOT / 'scripts/verify-sou86-crash-supervision.py'),
                   '--agentfw', '/missing', '--node', '/missing', '--npm', '/missing', '--bwrap', '/missing',
                   '--expected-commit', 'a' * 40, '--runtime-source-commit', V.ACCEPTED,
                   '--output', '/missing', '--disposable-systemd-unit', 'sou86-1-1.service']
        value = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(value.returncode, 0)
        report = json.loads(value.stdout)
        self.assertFalse(report['executed'])
        self.assertFalse(report['protection_acceptance'])
        self.assertEqual(report['required_cases'], len(V.INVENTORY_CASES))
        self.assertGreater(report['required_cases'], 0)

    def test_non_linux_execution_fails_instead_of_skip(self):
        with patch.object(V.platform, 'system', return_value='Darwin'):
            with self.assertRaisesRegex(ValueError, 'required_linux_x86_64_missing'):
                V.run(None)

    def test_bootstrap_rejects_root_unowned_unit_and_wrong_platform(self):
        with patch.object(V.platform, 'system', return_value='Darwin'):
            with self.assertRaisesRegex(ValueError, 'unprivileged_linux_required'):
                V.prepare_delegation('sou86-1-1.service')
        with patch.object(V.platform, 'system', return_value='Linux'), patch.object(V.os, 'geteuid', return_value=0, create=True):
            with self.assertRaisesRegex(ValueError, 'unprivileged_linux_required'):
                V.prepare_delegation('sou86-1-1.service')
        with patch.object(V.platform, 'system', return_value='Linux'), patch.object(V.os, 'geteuid', return_value=1000, create=True):
            for unit in ('ssh.service', 'sou79-1-1.service', '../sou86-1-1.service', 'sou86-1-1.service/child'):
                with self.assertRaisesRegex(ValueError, 'owned_disposable_unit_required'):
                    V.prepare_delegation(unit)

    def test_identity_distinguishes_live_zombie_disappeared_and_reused_pid(self):
        original = {'pid': 101, 'start_time_ticks': 5}
        for current, same, live in ((None, False, False),
                                    ({'pid': 101, 'start_time_ticks': 6, 'state': 'R'}, False, False),
                                    ({'pid': 101, 'start_time_ticks': 5, 'state': 'Z'}, True, False),
                                    ({'pid': 101, 'start_time_ticks': 5, 'state': 'R'}, True, True)):
            with patch.object(V, 'identity', return_value=current):
                self.assertEqual(V.same_process(original), same)
                self.assertEqual(V.alive(original), live)

    def test_summary_never_copies_raw_stream_or_protocol_payload(self):
        report = complete_inventory()
        report['inventory'][0]['client']['stdout']['accidental_raw'] = 'must-not-be-public'
        report['inventory'][0]['client']['stderr']['accidental_raw'] = 'must-not-be-public'
        rendered = json.dumps(V.summary(report))
        self.assertNotIn('must-not-be-public', rendered)
        self.assertNotIn('records', rendered)

    def test_evidence_writer_refuses_private_child_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'unsafe_evidence_payload'):
                V.write(Path(temporary) / 'report.json', {'raw': V.RESOURCE.MARKERS[0].decode()})


class AcceptanceControls(unittest.TestCase):
    def test_failed_unappended_client_retains_only_bounded_static_terminal_diagnostics(self):
        value = {'cleanup': {'clients': [{'case': 'peer-isolation', 'exit_code': 1, 'stderr': {
            'refusals': ['mcp_budget_wall_expired', 'raw-private-error'],
            'events': [{'event': 'mcp_real_budget_end', 'mode': 'enforced', 'source': 'raw-private-output'},
                       {'event': 'mcp_real_server_end', 'cleanup_verified': True, 'path': '/private/secret'}]}}]}}
        result = V.summary(value)['failure_clients']
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['case'], 'peer-isolation')
        self.assertEqual(result[0]['refusals'], ['mcp_budget_wall_expired'])
        self.assertEqual(result[0]['last_budget_end'], {'event': 'mcp_real_budget_end', 'mode': 'enforced'})
        self.assertEqual(result[0]['last_server_end'], {'event': 'mcp_real_server_end', 'cleanup_verified': True})
        self.assertNotIn('raw-private', json.dumps(result))
        self.assertNotIn('/private/secret', json.dumps(result))
        value['cleanup']['clients'] *= 100
        self.assertEqual(len(V.summary(value)['failure_clients']), 32)

    def test_only_long_lived_peer_gets_larger_finite_wall_budget(self):
        root = Path('/sys/fs/cgroup/owned/budgets')
        ordinary = V.RESOURCE.budget(root)
        self.assertEqual(V.acceptance_budget(root, 'peer-isolation'), ordinary | {'wallMillis': 600000})
        for label in (V.CASES - {'peer-isolation'}) | {'prearm-startup-inventory'}:
            self.assertEqual(V.acceptance_budget(root, label), ordinary)
        self.assertEqual(V.ACCEPTANCE_MILLIS, 10000)

    def test_one_identity_read_keeps_liveness_and_presence_consistent_during_exit(self):
        original = {'pid': 101, 'start_time_ticks': 5, 'state': 'R', 'fixture_role': 'detached'}
        observed = {(101, 5): original}
        with patch.object(V, 'identity', side_effect=[dict(original), None]) as read:
            live, present = V.process_snapshot(observed)
            self.assertEqual(read.call_count, 1)
            self.assertEqual(live, present)
            self.assertEqual(len(present), 1)
            self.assertEqual(V.process_snapshot(observed), ([], []))
            self.assertEqual(read.call_count, 2)

    def test_single_snapshot_distinguishes_zombie_and_reused_process_without_role_loss(self):
        original = {'pid': 101, 'start_time_ticks': 5, 'state': 'R', 'fixture_role': 'detached'}
        with patch.object(V, 'identity', return_value=dict(original, state='Z', fixture_role=None)) as read:
            live, present = V.process_snapshot({(101, 5): original})
            self.assertEqual(live, [])
            self.assertEqual(present, [dict(original, state='Z')])
            self.assertEqual(read.call_count, 1)
        with patch.object(V, 'identity', return_value=dict(original, start_time_ticks=6)):
            self.assertEqual(V.process_snapshot({(101, 5): original}), ([], []))

    def test_nested_bubblewrap_arguments_do_not_identify_outer_process_as_trusted_helper(self):
        for role, flag in (('owner', b'--agentfw-mcp-owner-v1'), ('pid1', b'--agentfw-mcp-pid1-v1')):
            self.assertEqual(V.trusted_command_role([b'/mcp-runtime/agentfw', flag, b'8']), role)
            self.assertIsNone(V.trusted_command_role([b'/proc/self/fd/9', b'--die-with-parent',
                b'--as-pid-1', b'--', b'/mcp-runtime/agentfw', flag, b'8']))

    def test_no_failed_skipped_or_empty_denominators_count_as_complete(self):
        for key, value in (('failed', 1), ('skipped', 1), ('required_cases', 0)):
            for builder, grader in ((complete_acceptance, V.grade_acceptance), (complete_inventory, V.grade_inventory)):
                report = builder()
                report[key] = value
                with self.assertRaises(ValueError):
                    grader(report)

    def test_unexpected_guardian_wrapper_pid1_failure_cannot_return_success(self):
        for name in ('owned-owner-kill', 'owned-wrapper-kill', 'owned-pid1-kill', 'owned-owner-stop'):
            report = complete_acceptance()
            next(row for row in report['acceptance'] if row['case'] == name)['client']['exit_code'] = 0
            with self.assertRaisesRegex(ValueError, 'unexpected_owner_failure_reported_success'):
                V.grade_acceptance(report)

    def test_complete_candidate_requires_all_nonempty_protected_cases(self):
        report = complete_acceptance()
        V.grade_acceptance(report)
        self.assertEqual(len(report['checks']), 22)
        self.assertTrue(all(row['protection_acceptance'] for row in report['checks']))

    def test_baseline_inventory_cannot_count_as_candidate_acceptance(self):
        with self.assertRaisesRegex(ValueError, 'required_protection_acceptance_missing'):
            V.grade_acceptance(complete_inventory())

    def test_missing_crash_case_and_either_original_server_control_fail(self):
        for change in (lambda report: report['acceptance'].pop(), lambda report: report['original_controls'].pop()):
            report = complete_acceptance()
            change(report)
            with self.assertRaises(ValueError):
                V.grade_acceptance(report)

    def test_no_parent_fallback_or_incomplete_cleanup_can_pass(self):
        for change in (lambda row: row.update(live_at_deadline=[{'pid': 101}]),
                       lambda row: row.update(identities_present_at_deadline=[{'pid': 101}]),
                       lambda row: row.update(leaf_removed_within_bound=False),
                       lambda row: row.update(acceptance_fallback_used=True),
                       lambda row: row.update(all_identities_gone_within_bound=False),
                       lambda row: row.update(identities_gone_millis=10001),
                       lambda row: row.update(armed_before_signal=False)):
            report = complete_acceptance()
            change(next(row for row in report['acceptance'] if row.get('signal_target')))
            with self.assertRaises(ValueError):
                V.grade_acceptance(report)

    def test_guardian_stop_must_be_independently_observed_and_recovered(self):
        report = complete_acceptance()
        stopped = next(row for row in report['acceptance'] if row['case'] == 'owned-owner-stop')
        stopped['guardian_stop_observed'] = False
        with self.assertRaisesRegex(ValueError, 'guardian_liveness_failure_not_exercised'):
            V.grade_acceptance(report)

    def test_signal_delivery_and_all_trusted_process_identities_required(self):
        for change in (lambda row: row['target'].update(signal_delivered=False),
                       lambda row: row['observed_processes'].pop()):
            report = complete_acceptance()
            change(next(row for row in report['acceptance'] if row['case'] == 'owned-owner-kill'))
            with self.assertRaises(ValueError):
                V.grade_acceptance(report)

    def test_cleanup_never_claims_rollback_or_immediate_authority_retirement(self):
        for key in ('immediate_native_retirement_claimed', 'previous_effects_rolled_back'):
            report = complete_acceptance()
            next(row for row in report['acceptance'] if row.get('signal_target'))[key] = True
            with self.assertRaisesRegex(ValueError, 'process_cleanup_misrepresented_as_authority_or_rollback'):
                V.grade_acceptance(report)

    def test_restart_cannot_reuse_owner_instance_or_native_epoch(self):
        for key in ('epoch', 'owner'):
            report = complete_acceptance()
            rows = report['acceptance']
            rows[1]['client'][key] = copy.deepcopy(rows[0]['client'][key])
            with self.assertRaises(ValueError):
                V.grade_acceptance(report)

    def test_unaffected_peer_requires_wire_witness_before_and_after_each_crash(self):
        for change in (lambda report: report['peer_checks'].pop(),
                       lambda report: report['peer_checks'][0]['after'].update(sha256='b' * 64)):
            report = complete_acceptance()
            change(report)
            with self.assertRaises(ValueError):
                V.grade_acceptance(report)

    def test_private_leaked_fd_or_accessible_pid1_memory_cannot_pass(self):
        for key in ('private_lease_absent', 'host_control_fds_absent', 'pid1_private_fds_denied', 'pid1_memory_denied'):
            report = complete_acceptance()
            next(row for row in report['acceptance'] if row['case'] == 'fixture-private-boundary')['private_boundary'][key] = False
            with self.assertRaisesRegex(ValueError, 'private_owner_lease_boundary_failed'):
                V.grade_acceptance(report)

    def test_zero_samples_lost_cgroup_or_missing_source_identity_fail(self):
        for change in (lambda report: report['acceptance'][0]['client']['kernel'].update(samples=0),
                       lambda report: report['acceptance'][0]['client']['kernel'].update(leaf_removed=False),
                       lambda report: report.update(git_launcher_sha256=None)):
            report = complete_acceptance()
            change(report)
            with self.assertRaises(ValueError):
                V.grade_acceptance(report)

    def test_safe_owner_metadata_discards_any_source_path_and_invalid_identity(self):
        owner = V.safe_owner({'format': V.OWNER_FORMAT, 'instance': 'a' * 32, 'owner_pid': 101,
                              'owner_start_ticks': 5, 'source': 'must-not-copy', 'path': '/private/secret',
                              'reason': 'arbitrary-child-error', 'cleanup': {'format': V.OWNER_FORMAT}})
        self.assertEqual(owner, {'format': V.OWNER_FORMAT, 'instance': 'a' * 32, 'owner_pid': 101,
                                 'owner_start_ticks': 5, 'cleanup': {'format': V.OWNER_FORMAT}})
        self.assertIsNone(V.safe_owner({'format': 'arbitrary'}))


if __name__ == '__main__':
    unittest.main()
