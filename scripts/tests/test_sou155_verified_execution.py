# SPDX-License-Identifier: Apache-2.0
"""Fail closed when native evidence is partial, crossed, repeated or forged."""
import copy
import importlib.util
from pathlib import Path
import subprocess
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
    for index in range(9):
        row = {name: 'b' * 64 for name in GATE.META if name.endswith('_sha256')}
        generation = 0 if index < 7 else index - 6
        row.update(contract='sw-mcp/verified-original-execution/1',
                   daemon_instance_id=str(generation), native_call_id=str(index),
                   invocation_sha256=f'{index + 1:064x}',
                   process_generation_sha256=f'{generation + 1:064x}',
                   channel_generation_sha256=f'{generation + 1:064x}',
                   original_result_bytes=100, domain_witness=None)
        metadata.append(row)
    cases = [dict(case=name, status='passed') for name in sorted(GATE.CASES)]
    by_name = {row['case']: row for row in cases}
    by_name['concurrent-original-call-correlation']['calls'] = 4
    by_name['actual-original-cancel-with-useful-followup'].update(
        original_reader_seen=True, cancelled_result_released=False, effects_rolled_back=False)
    by_name['exact-original-ask-approved-once']['approval_replay_refused'] = True
    for name in ('executable-replacement-before-capture',
                 'identical-schema-alternate-formatter-with-new-tree-hash'):
        by_name[name]['endpoint_started'] = False
    report = dict(format='sou155-native-execution/1', source_commit=SOURCE,
                  status='passed', acceptance_pass=True, model_calls=0,
                  source_read_only=True, network='private-loopback-only',
                  writes='isolated-scratch-and-owned-delegation-only',
                  binary_sha256='c' * 64, cleanup_verified=True, owned_root_empty_final=True,
                  cases=cases, execution_records=metadata, original_results=9)
    build = dict(source_commit=SOURCE, status='passed', runtime_qualification=False,
                 binary_sha256='c' * 64, steps=[dict(label=name, status='passed', exit_code=0)
                 for name in ('native-build', 'native-closure-unit', 'native-execution-unit',
                              'native-owner-unit', 'native-clippy')])
    return report, build


class NativeEvidence(unittest.TestCase):
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
