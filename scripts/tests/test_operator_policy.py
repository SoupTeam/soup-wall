# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('operator_policy', Path(__file__).resolve().parents[1] / 'qualify-operator-policy.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Grading(unittest.TestCase):
    def report(self):
        return {'format': module.FORMAT, 'expected': list(module.CASES), 'source': 'a'*40,
                'executed': True, 'platform': 'native-linux', 'network_syscalls': 0, 'child_execs': 0, 'traced_commands': 1,
                'binary_sha256': 'b'*64, 'source_unchanged': True, 'binary_unchanged': True,
                'cases': [{'id': name, 'attempted': True, 'status': 'passed', 'network_syscalls': 0,
                           'child_execs': 0, 'active_unchanged': True, 'project_unchanged': True,
                           'sibling_unchanged': True} for name in module.CASES]}

    def test_nonempty_complete_exact_cases_only(self):
        value = self.report()
        self.assertTrue(module.passed(value))
        for mutate in [lambda r: r['cases'].pop(), lambda r: r['cases'].reverse(),
                       lambda r: r['cases'][0].update(status='incomplete'),
                       lambda r: r['cases'][0].update(attempted=False),
                       lambda r: r.update(source='dirty'), lambda r: r.update(source_unchanged=False)]:
            bad = copy.deepcopy(value); mutate(bad)
            self.assertFalse(module.passed(bad))

    def test_execution_network_boolean_and_missing_witness_refuse(self):
        for key in ['network_syscalls', 'child_execs']:
            for value in [1, False, None]:
                bad = self.report(); bad['cases'][0][key] = value
                self.assertFalse(module.passed(bad))
        for key in ['active_unchanged', 'project_unchanged', 'sibling_unchanged']:
            bad = self.report(); bad['cases'][0].pop(key)
            self.assertFalse(module.passed(bad))
