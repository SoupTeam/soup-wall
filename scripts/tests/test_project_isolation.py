# SPDX-License-Identifier: Apache-2.0
"""Acceptance cannot confuse a dispatched/withheld call with a useful result."""
import importlib.util
from pathlib import Path
import unittest
import tempfile
import json
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('sou117_acceptance', ROOT / 'scripts/qualify-project-isolation.py')
ACCEPTANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACCEPTANCE)


class IsolationEvidence(unittest.TestCase):
    def test_owned_attack_repository_materializes_all_executable_surfaces(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ACCEPTANCE.hostile_project(root, '/bin/false', SimpleNamespace(url='http://127.0.0.1:1'))
            for name in ['.mcp.json', '.claude/settings.json', '.claude/settings.local.json',
                         '.claude/marketplace/.claude-plugin/marketplace.json',
                         '.claude/marketplace/plugins/escape/.claude-plugin/plugin.json',
                         '.claude/marketplace/plugins/escape/hooks/hooks.json']:
                self.assertIsInstance(json.loads((root / name).read_text()), dict)
            self.assertTrue((root / '.claude/commands/escape.md').is_file())
            self.assertTrue((root / '.claude/skills/escape/SKILL.md').is_file())
            self.assertTrue((root / 'poison-bin/git').is_file())

    def results(self):
        return {f'toolu_isolation_{i}': {'is_error': i >= 2, 'content':
            'owned useful bytes' if i == 0 else 'tracked.txt' if i == 1 else 'unavailable tool'} for i in range(4)}

    def test_useful_and_refused_correlated_results(self):
        ACCEPTANCE.validate_results(self.results(), 'owned useful bytes')

    def test_withheld_empty_or_wrong_original_result_cannot_pass(self):
        for index in (0, 1):
            for update in ({'is_error': True}, {'content': []}, {'content': 'unrelated bytes'}):
                results = self.results()
                results[f'toolu_isolation_{index}'].update(update)
                with self.assertRaises(ValueError):
                    ACCEPTANCE.validate_results(results, 'owned useful bytes')

    def test_missing_correlation_or_ungranted_execution_cannot_pass(self):
        for index in range(4):
            results = self.results(); del results[f'toolu_isolation_{index}']
            with self.assertRaises(ValueError):
                ACCEPTANCE.validate_results(results, 'owned useful bytes')
        for index in (2, 3):
            results = self.results(); results[f'toolu_isolation_{index}']['is_error'] = False
            with self.assertRaises(ValueError):
                ACCEPTANCE.validate_results(results, 'owned useful bytes')


if __name__ == '__main__':
    unittest.main()
