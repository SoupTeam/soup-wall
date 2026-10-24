# SPDX-License-Identifier: Apache-2.0
"""Observer failure controls over owned ordinary files, not cgroup proof."""
import importlib.util
from pathlib import Path
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

O = load('prepared_observer_control', 'scripts/prepared_budget_observer.py')
R = load('prepared_observer_resource', 'scripts/verify-sou79-resource-budgets.py')


class Observer(unittest.TestCase):
    def test_unknown_directory_fails_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'cgroup.procs').write_text('')
            observer = O.BudgetObserver(root, R)
            foreign = root / 'operator-owned'
            foreign.mkdir()
            marker = foreign / 'marker'
            marker.write_text('must survive')
            deadline = time.monotonic() + 1
            while not observer.snapshot()['errors'] and time.monotonic() < deadline:
                time.sleep(.005)
            observer.finish()
            self.assertEqual(marker.read_text(), 'must survive')
            self.assertEqual(observer.snapshot()['status'], 'failed')

    def test_root_replacement_is_preserved_and_cannot_be_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / 'selected'
            root.mkdir(mode=0o700)
            (root / 'cgroup.procs').write_text('')
            observer = O.BudgetObserver(root, R)
            root.rename(parent / 'original')
            root.mkdir(mode=0o700)
            (root / 'operator-marker').write_text('replacement')
            deadline = time.monotonic() + 1
            while not observer.snapshot()['errors'] and time.monotonic() < deadline:
                time.sleep(.005)
            observer.finish()
            self.assertEqual(observer.snapshot()['status'], 'failed')
            self.assertEqual((root / 'operator-marker').read_text(), 'replacement')
            self.assertTrue((parent / 'original/cgroup.procs').exists())

    def test_duplicate_counters_and_boolean_counter_are_not_proof(self):
        with self.assertRaises(O.ObservationError):
            O.BudgetObserver._keyed('max 1\nmax 2\n', ('max',))
        with self.assertRaises(O.ObservationError):
            O.BudgetObserver._project({'memory.peak': True})


if __name__ == '__main__':
    unittest.main()
