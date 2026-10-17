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
            'source_before': {'commit': 'c' * 40, 'dirty': False},
            'source_after': {'commit': 'c' * 40, 'dirty': False}, 'binary_unchanged': True,
            'delegation': {'unprivileged': True, 'manager_membership_verified': True},
            'original_unchanged': True, 'workspace_unchanged': True, 'delegation_removed': True,
            'protection_acceptance': False, 'inventory': rows,
            'stream_calibration': {'stderr': {'marker_leak': True, 'thread_stopped': True,
                                             'sha256': V.digest(V.RESOURCE.CALIBRATION_BYTES)}},
            'cleanup': {'daemon_process': {'all_stopped': True}, 'daemon_stdout': copy.deepcopy(stream),
                        'daemon_stderr': copy.deepcopy(stream), 'audit': {'marker_leak': False}}}


class InventoryControls(unittest.TestCase):
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
        with patch.object(V.platform, 'system', return_value='Linux'), patch.object(V.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(ValueError, 'unprivileged_linux_required'):
                V.prepare_delegation('sou86-1-1.service')
        with patch.object(V.platform, 'system', return_value='Linux'), patch.object(V.os, 'geteuid', return_value=1000):
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


if __name__ == '__main__':
    unittest.main()
