# SPDX-License-Identifier: Apache-2.0
"""Negative controls for independent resource-budget evidence and bounded output."""
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import mock_open, patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('sou79_controls', ROOT / 'scripts/verify-sou79-resource-budgets.py')
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


def kernel():
    config = V.budget(Path('/sys/fs/cgroup/owned/budgets'))
    first = {'memory.max': config['memoryMaxBytes'], 'memory.swap.max': 0, 'memory.oom.group': 1,
             'pids.max': config['pidsMax'], 'cpu.max': [config['cpuQuotaMicros'], 100000]}
    return {'budget': config, 'kernel': {'first': first, 'last': copy.deepcopy(first), 'samples': 12,
            'memory_peak_bytes': 1000000, 'tasks_peak': 10, 'thread_stopped': True, 'error': None,
            'leaf_removed': True, 'remaining': [], 'members': [{'pid': 101, 'start_time_ticks': 5}]}}


class ObserverControls(unittest.TestCase):
    def test_complete_independent_kernel_witness_is_accepted(self):
        V.grade_kernel(kernel())

    def test_every_effective_control_must_match_operator_request(self):
        for name in ('memory.max', 'memory.swap.max', 'memory.oom.group', 'pids.max', 'cpu.max'):
            with self.subTest(name=name):
                value = kernel()
                value['kernel']['first'][name] = [1, 100000] if name == 'cpu.max' else -1
                with self.assertRaisesRegex(ValueError, 'effective_kernel_limits_not_requested'):
                    V.grade_kernel(value)

    def test_observer_samples_process_membership_and_disappearance_are_required(self):
        for change in (lambda r: r.update(samples=0), lambda r: r.update(error='read_failed'),
                       lambda r: r.update(thread_stopped=False), lambda r: r.update(leaf_removed=False),
                       lambda r: r.update(members=[]), lambda r: r.update(remaining=[{'pid': 101}])):
            value = kernel()
            change(value['kernel'])
            with self.assertRaises(ValueError):
                V.grade_kernel(value)

    def test_task_limits_and_declared_memory_overshoot_are_checked(self):
        for key, number in [('tasks_peak', 65), ('tasks_peak', 0), ('memory_peak_bytes', 0),
                            ('memory_peak_bytes', 600 * 1024 * 1024)]:
            value = kernel()
            value['kernel'][key] = number
            with self.assertRaises(ValueError):
                V.grade_kernel(value)

    def capture(self, chunks, protocol=False):
        read, write = os.pipe()
        def emit():
            try:
                for chunk in chunks:
                    offset = 0
                    while offset < len(chunk):
                        offset += os.write(write, chunk[offset:])
            finally:
                os.close(write)
        with os.fdopen(read, 'rb', buffering=0) as stream:
            capture = V.Capture(stream, protocol)
            worker = threading.Thread(target=emit)
            worker.start()
            worker.join(timeout=10)
            self.assertFalse(worker.is_alive())
            result = capture.finish()
        return result

    def test_scanner_detects_split_synthetic_markers_without_raw_storage(self):
        for marker in V.MARKERS:
            value = self.capture([marker[:4], marker[4:]])
            self.assertTrue(value['marker_leak'])
            self.assertNotIn(marker.decode(errors='replace'), json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'unsafe_or_incomplete_stream_observer'):
                V.clean_stream(value)

    def test_no_newline_stream_has_fixed_buffer_and_full_hash(self):
        raw = b'x' * (1024 * 1024)
        value = self.capture([raw])
        self.assertEqual(value['sha256'], V.digest(raw))
        self.assertEqual(value['bytes'], len(raw))
        self.assertLessEqual(value['buffer_peak'], 4096)
        V.clean_stream(value)

    def test_partial_invalid_and_oversized_protocol_fail_closed(self):
        for raw in (b'{"id":40', b'[]\n', b'x' * 262145 + b'\n'):
            value = self.capture([raw], True)
            self.assertIsNotNone(value['error'])
            self.assertLessEqual(value['buffer_peak'], 262144)

    def test_late_unconsumed_result_remains_in_independent_records(self):
        raw = b'{"jsonrpc":"2.0","id":40,"result":{"content":[]}}\n'
        value = self.capture([raw], True)
        self.assertEqual(value['records'][0]['id'], 40)
        self.assertTrue(value['records'][0]['successful_result'])
        self.assertEqual(value['records'][0]['sha256'], V.digest(raw))

    def test_child_source_and_path_strings_are_not_safe_metadata(self):
        event = V.safe_event({'event': 'mcp_real_server_end', 'cleanup_verified': True,
                             'source': V.MARKERS[0].decode(), 'path': V.MARKERS[1].decode(),
                             'mode': 'arbitrary-source', 'budget': {'raw': V.MARKERS[0].decode()}})
        self.assertEqual(event, {'event': 'mcp_real_server_end', 'cleanup_verified': True})
        self.assertIsNone(V.safe_event({'event': V.MARKERS[0].decode()}))

    def test_fixed_membership_diagnostic_survives_actual_stream_capture(self):
        diagnostic = {'phase': 'member_open', 'pid': 123, 'errno': 13}
        event = {'event': 'mcp_real_budget_end', 'budget': {
            'format': V.BUDGET_FORMAT, 'reason': 'mcp_budget_membership_unverified',
            'failed': True, 'membership_failure': diagnostic}}
        captured = self.capture([json.dumps(event).encode() + b'\n'])
        self.assertEqual(captured['events'][0]['budget']['membership_failure'], diagnostic)
        self.assertEqual(captured['events'][0]['budget']['reason'], 'mcp_budget_membership_unverified')

    def test_membership_diagnostics_reject_unbounded_or_untrusted_fields(self):
        valid = {'phase': 'leader_absent_from_snapshot', 'pid': 123, 'errno': None}
        for change in ({'phase': '/private/host/path'}, {'pid': True}, {'pid': -1},
                       {'pid': 2**32}, {'errno': True}, {'errno': -1}, {'errno': 4096},
                       {'raw': 'arbitrary child output'}):
            with self.subTest(change=change):
                value = {'format': V.BUDGET_FORMAT, 'membership_failure': {**valid, **change}}
                self.assertNotIn('membership_failure', V.safe_budget(value))

    def test_no_membership_failure_and_absent_old_field_remain_distinct(self):
        self.assertEqual(V.safe_budget({'format': V.BUDGET_FORMAT, 'membership_failure': None})[
            'membership_failure'], None)
        self.assertNotIn('membership_failure', V.safe_budget({'format': V.BUDGET_FORMAT}))

    def test_evidence_writer_refuses_raw_child_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            for marker in V.MARKERS[:2]:
                with self.assertRaisesRegex(ValueError, 'unsafe_evidence_payload'):
                    V.write(Path(directory) / 'report.json', {'accident': marker.decode()})

    def test_bootstrap_refuses_non_linux_root_and_unowned_unit(self):
        with patch.object(V.platform, 'system', return_value='Darwin'):
            with self.assertRaisesRegex(ValueError, 'unprivileged_linux_required'):
                V.prepare_delegation('sou79-1-1.service')
        with patch.object(V.platform, 'system', return_value='Linux'), patch.object(V.os, 'geteuid', return_value=0, create=True):
            with self.assertRaisesRegex(ValueError, 'unprivileged_linux_required'):
                V.prepare_delegation('sou79-1-1.service')
        with patch.object(V.platform, 'system', return_value='Linux'), patch.object(V.os, 'geteuid', return_value=1000, create=True):
            for unit in ('ssh.service', '../sou79-1-1.service', 'sou79-1-1.service/child'):
                with self.assertRaisesRegex(ValueError, 'owned_disposable_unit_required'):
                    V.prepare_delegation(unit)

    def test_missing_linux_is_failure_instead_of_skip(self):
        with patch.object(V.platform, 'system', return_value='Darwin'):
            with self.assertRaisesRegex(ValueError, 'required_linux_x86_64_missing'):
                V.run(None)

    def test_plan_starts_no_process_and_declares_nonempty_required_runtime(self):
        command = [sys.executable, '-B', str(ROOT / 'scripts/verify-sou79-resource-budgets.py'),
                   '--agentfw', '/missing', '--node', '/missing', '--npm', '/missing', '--bwrap', '/missing',
                   '--expected-commit', '1' * 40, '--output', '/missing', '--disposable-systemd-unit', 'sou79-1-1.service']
        value = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(value.returncode, 0)
        report = json.loads(value.stdout)
        self.assertFalse(report['executed'])
        self.assertEqual(report['required_cases'], len(V.CASES))
        self.assertGreater(len(V.CASES), 0)

    def test_canonical_budget_hash_is_independent_of_indentation(self):
        value = V.budget(Path('/sys/fs/cgroup/owned/budgets'))
        canonical = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        reparsed = json.loads(json.dumps(value, indent=2))
        self.assertEqual(V.digest(canonical), V.digest(json.dumps(reparsed, sort_keys=True, separators=(',', ':')).encode()))
        self.assertNotEqual(V.digest(canonical), V.digest(json.dumps(value, indent=2).encode()))

    def test_actual_terminal_controller_reason_and_safe_limits_are_preserved(self):
        event = V.safe_event({'event': 'mcp_real_budget_end', 'mode': 'enforced', 'observed_failure': True,
            'budget': {'format': V.BUDGET_FORMAT, 'budget_sha256': 'a' * 64, 'leaf': 'agentfw-mcp-' + 'b' * 32,
                       'reason': 'mcp_budget_controller_unavailable', 'limits': {'pids_max': 32, 'raw': 'must disappear'},
                       'stats': {'memory_peak_bytes': 100, 'source': 'must disappear'}, 'failed': True}})
        self.assertEqual(event['budget']['reason'], 'mcp_budget_controller_unavailable')
        self.assertEqual(event['budget']['limits'], {'pids_max': 32})
        self.assertEqual(event['budget']['stats'], {'memory_peak_bytes': 100})

    def test_pending_dispatch_barrier_requires_exact_id_and_actual_dispatch(self):
        class Client:
            class Stderr:
                events = [{'host_call_id': 40, 'state': 'inflight', 'execution_dispatched': True}]
            stderr = Stderr()
        V.wait_dispatched(Client(), 40)
        Client.stderr.events = [{'host_call_id': 41, 'state': 'inflight', 'execution_dispatched': True}]
        with patch.object(V.time, 'monotonic', side_effect=[0, 11]), self.assertRaisesRegex(ValueError, 'pending_dispatched_work_not_observed'):
            V.wait_dispatched(Client(), 40)
        Client.stderr.events = [{'host_call_id': 40, 'state': 'inflight', 'execution_dispatched': False}]
        with patch.object(V.time, 'monotonic', side_effect=[0, 11]), self.assertRaisesRegex(ValueError, 'pending_dispatched_work_not_observed'):
            V.wait_dispatched(Client(), 40)

    def test_static_refusal_is_captured_across_fragmented_reads(self):
        value = self.capture([b'Err', b'or: mcp_budget_', b'delegation_invalid\n'])
        self.assertEqual(value['refusals'], ['mcp_budget_delegation_invalid'])
        self.assertFalse(value['marker_leak'])
        value = self.capture([b'  MCP sandbox runtime asset digest mismatch  \n'])
        self.assertEqual(value['refusals'], ['selected_sandbox_asset_digest_mismatch'])

    def test_static_refusal_parser_never_copies_prefix_suffix_path_or_marker(self):
        for raw in (b'Error: mcp_budget_new_unrecognized_code', b'Error: mcp_budget_setup_failed: /private/secret',
                    b'prefix mcp_budget_setup_failed', b'/tmp/mcp_budget_setup_failed',
                    b'Error: ' + V.MARKERS[0], b'\xffError: mcp_budget_setup_failed'):
            self.assertIsNone(V.static_refusal(raw))
        value = self.capture([b'Error: mcp_budget_setup_failed: ' + V.MARKERS[1] + b'\n'])
        self.assertTrue(value['marker_leak'])
        self.assertEqual(value['refusals'], [])
        self.assertNotIn(V.MARKERS[1].decode(), json.dumps(value))

    def test_capability_probe_reports_absence_without_claiming_runtime_and_removes_itself(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capabilities = V.delegation_capabilities(root)
            self.assertEqual(set(capabilities), {'cgroup.kill', 'memory.peak', 'memory.swap.max', 'memory.oom.group',
                                                 'cpu.max', 'pids.max', 'pids.peak', 'cpu.max.burst'})
            self.assertTrue(all(value is False for value in capabilities.values()))
            self.assertEqual(list(root.iterdir()), [])

    def test_mismatched_membership_is_normal_only_after_same_process_confirmed_exited(self):
        live = {'start': 5, 'state': b'R', 'cpu_ticks': 12}
        zombie = dict(live, state=b'Z')
        path = Path('/sys/fs/cgroup/owned/leaf')
        for ending in (None, zombie, dict(live, start=6)):
            with patch.object(V, 'process_stat', side_effect=[live, live, ending]), patch.object(V.Path, 'open', mock_open(read_data=b'0::/deleted\n')):
                self.assertIsNone(V.process_member(101, path))
        with patch.object(V, 'process_stat', side_effect=[live, live, live]), patch.object(V.Path, 'open', mock_open(read_data=b'0::/outside\n')):
            with self.assertRaisesRegex(ValueError, 'member_escaped_owned_leaf'):
                V.process_member(101, path)

    def test_procfs_exit_errno_requires_confirmed_disappearance_and_live_errors_fail(self):
        live = {'start': 5, 'state': b'R', 'cpu_ticks': 12}
        for code in (errno.ENOENT, errno.ESRCH):
            with patch.object(V, 'process_stat', side_effect=[live, None]), patch.object(V.Path, 'open', side_effect=OSError(code, 'private text')):
                self.assertIsNone(V.process_member(101, Path('/sys/fs/cgroup/owned/leaf')))
            with patch.object(V, 'process_stat', side_effect=[live, live]), patch.object(V.Path, 'open', side_effect=OSError(code, 'private text')):
                with self.assertRaises(OSError):
                    V.process_member(101, Path('/sys/fs/cgroup/owned/leaf'))
        with patch.object(V, 'process_stat', return_value=live), patch.object(V.Path, 'open', side_effect=OSError(errno.EACCES, 'private text')):
            with self.assertRaises(PermissionError):
                V.process_member(101, Path('/sys/fs/cgroup/owned/leaf'))

    def test_leaf_read_race_requires_actual_removal_and_rejects_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'leaf'
            path.mkdir()
            descriptor = os.open(path, os.O_RDONLY)
            try:
                info = os.fstat(descriptor)
                identity = (info.st_dev, info.st_ino)
                for code in (errno.ENOENT, errno.ENODEV):
                    self.assertFalse(V.removed_leaf_read(OSError(code, 'private text'), path, identity))
                path.rmdir()
                for code in (errno.ENOENT, errno.ENODEV):
                    self.assertTrue(V.removed_leaf_read(OSError(code, 'private text'), path, identity))
                self.assertFalse(V.removed_leaf_read(OSError(errno.EACCES, 'private text'), path, identity))
                path.mkdir()
                with self.assertRaisesRegex(ValueError, 'owned_leaf_identity_changed'):
                    V.removed_leaf_read(OSError(errno.ENODEV, 'private text'), path, identity)
            finally:
                os.close(descriptor)

    def test_only_explicit_cpu_fault_can_observe_missing_cpu_interface(self):
        def read(path):
            if path.name == 'cpu.max':
                raise FileNotFoundError(errno.ENOENT, 'private text')
            if path.name in ('memory.events', 'pids.events', 'cpu.stat', 'cgroup.events'):
                return 'max 0\n'
            if path.name == 'cgroup.procs':
                return ''
            return '1\n'
        with patch.object(V.Path, 'read_text', autospec=True, side_effect=read), patch.object(V.Path, 'exists', return_value=False):
            with self.assertRaises(FileNotFoundError):
                V.kernel_values(Path('/owned'))
            self.assertIsNone(V.kernel_values(Path('/owned'), expected_cpu_loss=True)['cpu.max'])
        def missing_memory(path):
            if path.name == 'memory.peak':
                raise FileNotFoundError(errno.ENOENT, 'private text')
            return read(path)
        with patch.object(V.Path, 'read_text', autospec=True, side_effect=missing_memory), patch.object(V.Path, 'exists', return_value=False):
            with self.assertRaises(FileNotFoundError):
                V.kernel_values(Path('/owned'), expected_cpu_loss=True)

    def test_shutdown_read_quarantine_resolves_only_removed_leaf_within_fixed_bound(self):
        pending = V.ShutdownRead(errno.ENODEV, 10)
        self.assertEqual(pending.advance(False, 10.05), 'pending')
        self.assertEqual(pending.advance(True, 10.1), 'resolved')
        self.assertEqual(pending.metadata()['errno'], errno.ENODEV)
        self.assertTrue(pending.metadata()['resolved_within_deadline'])
        self.assertEqual(pending.metadata()['deadline_millis'], 250)

    def test_live_or_late_disappearance_cannot_extend_or_repair_shutdown_deadline(self):
        pending = V.ShutdownRead(errno.ENODEV, 10)
        deadline = pending.deadline
        for now in (10.01, 10.1, 10.24):
            self.assertEqual(pending.advance(False, now), 'pending')
            self.assertEqual(pending.deadline, deadline)
        self.assertEqual(pending.advance(False, 10.25), 'failed')
        self.assertEqual(pending.advance(True, 10.26), 'failed')
        self.assertFalse(pending.metadata()['resolved_within_deadline'])
        late = V.ShutdownRead(errno.ENOENT, 10)
        self.assertEqual(late.advance(True, 10.251), 'failed')

    def test_pending_shutdown_replacement_is_fatal_even_when_final_cleanup_later_happens(self):
        observer = V.KernelObserver.__new__(V.KernelObserver)
        observer.path, observer.device, observer.inode = Path('/owned/leaf'), 1, 2
        observer.shutdown_read = V.ShutdownRead(errno.ENODEV, 10)
        with patch.object(V, 'leaf_state', side_effect=ValueError('owned_leaf_identity_changed')), patch.object(V.time, 'monotonic', return_value=10.01):
            with self.assertRaisesRegex(ValueError, 'owned_leaf_identity_changed'):
                observer.settle_shutdown_read()
        self.assertEqual(observer.shutdown_read.status, 'failed')
        self.assertEqual(observer.shutdown_read.advance(True, 10.02), 'failed')

    def test_failed_or_late_shutdown_metadata_never_passes_kernel_grading(self):
        pending = V.ShutdownRead(errno.ENODEV, 10)
        pending.advance(True, 10.1)
        value = kernel()
        value['kernel']['shutdown_read'] = pending.metadata()
        V.grade_kernel(value)
        for change in ({'status': 'pending'}, {'status': 'failed'}, {'elapsed_millis': 251},
                       {'deadline_millis': 300}, {'errno': errno.EACCES}, {'resolved_within_deadline': False}):
            candidate = copy.deepcopy(value)
            candidate['kernel']['shutdown_read'].update(change)
            with self.assertRaisesRegex(ValueError, 'kernel_shutdown_uncertainty_unresolved'):
                V.grade_kernel(candidate)


if __name__ == '__main__':
    unittest.main()
