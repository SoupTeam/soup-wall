# SPDX-License-Identifier: Apache-2.0
"""Coordinator and measurement controls; never substituted for runtime evidence."""
import importlib.util
from pathlib import Path
import unittest
import math

ROOT = Path(__file__).resolve().parents[2]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ASK = load('sou145_ask_controls', 'qualify-pilot-ask.py')
RUN = load('sou145_coordinator', 'qualify-sou145-readiness.py')


class ReadinessControls(unittest.TestCase):
    def test_original_first_pending_bound_is_conservative_and_not_a_wait_change(self):
        for value, expected in [(0, True), (5000, True), (5000.001, False),
                                (None, False), (True, False), (-1, False),
                                (math.inf, False), (math.nan, False)]:
            row = {'case': 'approve', 'passed': True, 'first_pending_ms': value}
            ASK.enforce_pending_bound([row])
            self.assertEqual(row['passed'], expected)
            self.assertTrue(row['runtime_controls_passed'])
            self.assertEqual(row['first_pending_bound_ms'], 5000)
        row = {'case': 'reject', 'passed': False, 'first_pending_ms': 1}
        ASK.enforce_pending_bound([row])
        self.assertFalse(row['passed'])
        default = {'case': 'default', 'passed': True}
        ASK.enforce_pending_bound([default])
        self.assertEqual(default, {'case': 'default', 'passed': True})

    def test_all_seven_producers_use_one_selection_and_distinct_outputs(self):
        paths = {name: Path('/owned/' + name) for name in
                 ('agentfw', 'git_launcher', 'claude', 'node', 'npm', 'bwrap', 'git')}
        commands = RUN.commands(Path('/owned/selection.json'), 'a' * 40,
                                Path('/usr/bin/strace'), Path('/owned/offline'), Path('/owned/results'), paths)
        self.assertEqual(tuple(row[0] for row in commands), RUN.STAGES)
        self.assertEqual(len({str(row[2]) for row in commands}), 7)
        for stage, command, report in commands:
            self.assertIn('--output', command)
            self.assertIn('/owned/results/' + stage, command)
            if stage == 'ask':
                self.assertIn('--complete-inventory', command)
                self.assertIn('--require-five-second-pending', command)
            else:
                self.assertIn('/owned/selection.json', command)
                self.assertIn('a' * 40, command)
            if stage != 'prepared':
                self.assertIn('--offline-inputs', command)
        matched = next(row[1] for row in commands if row[0] == 'matched')
        self.assertIn('--matched-development', matched)
        for project in ('docs-code', 'unicode-spaces', 'local-history'):
            command = next(row[1] for row in commands if row[0] == project)
            self.assertEqual(command[command.index('--project-fixture') + 1], project)


if __name__ == '__main__':
    unittest.main()
