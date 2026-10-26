# SPDX-License-Identifier: Apache-2.0
"""Fail closed when native evidence is partial, crossed, repeated or forged."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import os
import re
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GATE = load('sou155_gate', 'scripts/ci/project-verified-execution.py')
DRIVER = load('sou155_driver', 'scripts/ci/native-verified-execution.py')
SOURCE = 'a' * 40


def complete():
    metadata = []
    for index in range(13):
        row = {name: 'b' * 64 for name in GATE.META if name.endswith('_sha256')}
        generation = 0 if index < 11 else index - 10
        row.update(contract='sw-mcp/verified-original-execution/1',
                   daemon_instance_id=str(generation), native_call_id=str(index),
                   invocation_sha256=f'{index + 1:064x}',
                   process_generation_sha256=f'{generation + 1:064x}',
                   channel_generation_sha256=f'{generation + 1:064x}',
                   original_result_bytes=100, domain_witness=None)
        metadata.append(row)
    cases = [dict(case=name, status='passed') for name in sorted(GATE.CASES)]
    by_name = {row['case']: row for row in cases}
    by_name['actual-alternate-process-identical-bytes-remains-unattested'].update(
        byte_identical=True, baseline_release=True, execution_metadata=False)
    by_name['actual-owner-loss-refuses-old-channel-and-retains-cleanup-obligation'].update(
        owner_generation_verified=True, old_channel_closed=True, controller_cleanup_verified=False,
        host_relaunch_refused=True, observer_generations_stopped=True, owned_budget_removed=True)
    by_name['concurrent-original-call-correlation']['calls'] = 4
    by_name['actual-original-cancel-with-useful-followup'].update(
        original_reader_seen=True, cancelled_result_released=False, effects_rolled_back=False)
    by_name['exact-original-ask-approved-once']['approval_replay_refused'] = True
    for name in ('strong-body-refusal-with-useful-followup','bounded-evidence-overflow-with-useful-followup'):
        by_name[name].update(refused=True, useful_followup=True)
    by_name['bounded-evidence-overflow-with-useful-followup']['incomplete_deny'] = True
    for name in ('executable-replacement-before-capture',
                 'identical-schema-alternate-formatter-with-new-tree-hash'):
        by_name[name]['endpoint_started'] = False
    report = dict(format='sou155-native-execution/1', source_commit=SOURCE,
                  status='passed', acceptance_pass=True, model_calls=0,
                  source_read_only=True, network='private-loopback-only',
                  writes='isolated-scratch-and-owned-delegation-only',
                  binary_sha256='c' * 64, cleanup_verified=True, owned_root_empty_final=True,
                  cases=cases, execution_records=metadata, original_results=13)
    build = dict(source_commit=SOURCE, status='passed', runtime_qualification=False,
                 binary_sha256='c' * 64, steps=[dict(label=name, status='passed', exit_code=0)
                 for name in ('native-build', 'native-closure-unit', 'native-execution-unit',
                              'native-owner-unit', 'native-clippy')])
    return report, build


class NativeEvidence(unittest.TestCase):
    def test_owner_signal_pins_before_observation_and_never_uses_numeric_kill(self):
        owner = dict(owner_pid=424242, owner_start_ticks=73, original=dict(namespace_pid=2))
        events = []
        fields = ['S', '1234'] + ['0'] * 17 + ['73']
        def read(path, *args, **kwargs):
            events.append(('read', str(path)))
            return '424242 (owner) ' + ' '.join(fields) if str(path).endswith('/stat') else 'owned-cgroup\n'
        with patch.object(DRIVER.os, 'pidfd_open', create=True, side_effect=lambda *a: events.append(('pin', a)) or 87), \
             patch.object(DRIVER.select, 'select', return_value=([], [], [])), \
             patch.object(Path, 'read_text', read), \
             patch.object(DRIVER.signal, 'pidfd_send_signal', create=True, side_effect=lambda *a: events.append(('signal', a))), \
             patch.object(DRIVER.os, 'kill') as numeric, patch.object(DRIVER.os, 'close') as close:
            DRIVER.kill_owned_owner(owner, 1234, 'owned-cgroup')
            self.assertEqual(events[0], ('pin', (424242, 0)))
            self.assertEqual(events[-1], ('signal', (87, DRIVER.signal.SIGKILL)))
            numeric.assert_not_called()
            close.assert_called_once_with(87)

    def test_owner_signal_rejects_wrong_parent_generation_cgroup_and_exited_pin(self):
        owner = dict(owner_pid=424242, owner_start_ticks=73, original=dict(namespace_pid=2))
        for parent, ticks, cgroup, ready in [(999, 73, 'owned', [[], []]),
                                            (1234, 74, 'owned', [[], []]),
                                            (1234, 73, 'other', [[], []]),
                                            (1234, 73, 'owned', [[87]]),
                                            (1234, 73, 'owned', [[], [87]])]:
            fields = ['S', str(parent)] + ['0'] * 17 + [str(ticks)]
            def read(path, *args, **kwargs):
                return '424242 (owner) ' + ' '.join(fields) if str(path).endswith('/stat') else cgroup
            with self.subTest(parent=parent, ticks=ticks, cgroup=cgroup, ready=ready), \
                 patch.object(DRIVER.os, 'pidfd_open', create=True, return_value=87), \
                 patch.object(DRIVER.select, 'select', side_effect=[(row, [], []) for row in ready]), \
                 patch.object(Path, 'read_text', read), \
                 patch.object(DRIVER.signal, 'pidfd_send_signal', create=True) as signal, \
                 patch.object(DRIVER.os, 'kill') as numeric, patch.object(DRIVER.os, 'close') as close:
                with self.assertRaises(RuntimeError):
                    DRIVER.kill_owned_owner(owner, 1234, 'owned')
                signal.assert_not_called()
                numeric.assert_not_called()
                close.assert_called_once_with(87)

    @unittest.skipUnless(hasattr(os, 'pidfd_open') and hasattr(DRIVER.signal, 'pidfd_send_signal'), 'Linux pidfd required')
    def test_owner_signal_stops_only_real_owned_child(self):
        child = subprocess.Popen(['/bin/sleep', '30'])
        try:
            fields = Path(f'/proc/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()
            owner = dict(owner_pid=child.pid, owner_start_ticks=int(fields[19]), original=dict(namespace_pid=2))
            group = Path(f'/proc/{child.pid}/cgroup').read_text().strip()
            DRIVER.kill_owned_owner(owner, os.getpid(), group)
            self.assertEqual(child.wait(timeout=3), -DRIVER.signal.SIGKILL)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)

    def test_full_host_focus_gate_accepts_every_supported_slice_and_refuses_others(self):
        source = (ROOT / '.github/workflows/sou79-resource-budgets.yml').read_text()
        gate = source.split('- name: Validate explicit full-host selection', 1)[1]
        script = re.search(r'(?ms)^        run: \|\n(.*?)(?=^      - name:)', gate)[1]
        script = textwrap.dedent(script)
        for focus in ('142', '143', '155', '', 'off', '999', '155; echo unexpected'):
            result = subprocess.run(['/bin/bash', '-c', script],
                                    env={'PATH': os.defpath, 'SOU_FOCUS': focus},
                                    capture_output=True, timeout=5)
            with self.subTest(focus=focus):
                self.assertEqual(result.returncode == 0, focus in ('142', '143', '155'))
                self.assertEqual(result.stdout, b'')

    def test_candidate_report_read_is_bounded_and_refuses_ambiguous_or_linked_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / 'report.json'
            for raw in (b'{"status":"failed","status":"passed"}', b'{"number":NaN}', b' ' * 131073):
                report.write_bytes(raw)
                with self.assertRaises(ValueError):
                    GATE.read(report)
            link = root / 'linked.json'
            link.symlink_to(report)
            with self.assertRaises(OSError):
                GATE.read(link)

    def test_complete_finite_projection(self):
        report, build = complete()
        self.assertTrue(GATE.project(report, build, SOURCE, 0)['acceptance_pass'])

    def test_missing_case_or_repeated_case_does_not_pass(self):
        for repeated in (False, True):
            report, build = complete()
            report['cases'].pop()
            if repeated:
                report['cases'].append(copy.deepcopy(report['cases'][0]))
            with self.assertRaises(ValueError):
                GATE.project(report, build, SOURCE, 0)

    def test_malformed_candidate_rows_are_explicit_incomplete_errors(self):
        for field in ('cases', 'execution_records'):
            report, build = complete()
            report[field][0] = 'not an evidence record'
            with self.subTest(field=field), self.assertRaises(ValueError):
                GATE.project(report, build, SOURCE, 0)
        report, build = complete()
        build['steps'][0] = 'not a build record'
        with self.assertRaises(ValueError):
            GATE.project(report, build, SOURCE, 0)

    def test_crossed_source_binary_exit_and_cleanup_do_not_pass(self):
        for field, value in (('source_commit', 'd' * 40), ('binary_sha256', 'e' * 64),
                             ('cleanup_verified', False), ('owned_root_empty_final', False),
                             ('original_results', 8), ('source_read_only', False)):
            report, build = complete()
            report[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                GATE.project(report, build, SOURCE, 0)
        report, build = complete()
        with self.assertRaises(ValueError):
            GATE.project(report, build, SOURCE, 1)

    def test_missing_repeated_or_reconstructed_result_does_not_pass(self):
        for mutation in (lambda rows: rows.pop(),
                         lambda rows: rows.__setitem__(1, copy.deepcopy(rows[0])),
                         lambda rows: rows[0].update(domain_witness={'unreviewed': True}),
                         lambda rows: rows[0].update(original_result_bytes=0),
                         lambda rows: rows[0].update(untrusted=True),
                         lambda rows: [row.update(channel_generation_sha256='f' * 64) for row in rows]):
            report, build = complete()
            mutation(report['execution_records'])
            with self.assertRaises(ValueError):
                GATE.project(report, build, SOURCE, 0)

    def test_failed_missing_or_repeated_build_control_does_not_pass(self):
        for mutation in (lambda steps: steps.pop(),
                         lambda steps: steps.append(copy.deepcopy(steps[0])),
                         lambda steps: steps[0].update(exit_code=1)):
            report, build = complete()
            mutation(build['steps'])
            with self.assertRaises(ValueError):
                GATE.project(report, build, SOURCE, 0)

    def test_fixture_budget_is_selected_by_actual_cli_contract(self):
        import json
        selection = dict(format='sw-prepared-pilot-budget/1', status='selected-not-active',
                         protected_children_started=False, scope='per-original-server-process-tree',
                         budget_sha256='a' * 64)
        with patch.object(DRIVER.subprocess, 'run', return_value=subprocess.CompletedProcess(
                [], 0, json.dumps(selection).encode(), b'')) as run:
            self.assertEqual(DRIVER.selected_budget('/candidate', Path('/budget'), {}), selection)
            self.assertEqual(run.call_args.args[0], ['/candidate', 'pilot-budget', '--config', '/budget'])
        for field, value in (('format', 'sw-pilot-linux-budget/1'),
                             ('protected_children_started', True), ('status', 'active')):
            invalid = {**selection, field: value}
            with patch.object(DRIVER.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(invalid).encode(), b'')), self.assertRaises(RuntimeError):
                DRIVER.selected_budget('/candidate', Path('/budget'), {})


if __name__ == '__main__':
    unittest.main()
