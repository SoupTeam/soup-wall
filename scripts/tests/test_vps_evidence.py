# SPDX-License-Identifier: Apache-2.0
"""Zero, skipped and failed executions cannot be reported as VPS acceptance."""
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('vps_counts', Path(__file__).resolve().parents[1] / 'ci/vps_counts.py')
counts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(counts)


class OutcomeContract(unittest.TestCase):
    def test_actual_passes_remain_separate_from_skips_and_expected_failures(self):
        self.assertEqual(counts.test_counts('unittest', 'Ran 5 tests in 1.2s\nOK (skipped=2, expected failures=1)', None),
                         {'passed': 2, 'failed': 0, 'skipped': 2, 'expected_failed': 1})

    def test_zero_skipped_failed_and_ambiguous_runs_are_refused(self):
        for text in ['Ran 0 tests in 0.1s\nOK', 'Ran 2 tests in 0.1s\nOK (skipped=2)',
                     'Ran 3 tests in 0.1s\nFAILED (failures=1)', 'no execution',
                     'Ran 3 tests in 0.1s\nOK (unknown outcome)',
                     'Ran 3 tests in 0.1s\nOK (skipped=1, skipped=1)',
                     'Ran 2 tests in 0.1s\nOK\nRan 2 tests in 0.1s\nOK']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                counts.test_counts('unittest', text, None)

    def test_source_identity_must_be_complete_and_allowlisted(self):
        counts.validate_target('soup-wall', 'a' * 40)
        for repo, sha in [('other', 'a' * 40), ('soup-wall', 'main'), ('soup-wall', 'a' * 40 + '\n')]:
            with self.subTest(repo=repo, sha=sha), self.assertRaises(ValueError):
                counts.validate_target(repo, sha)


if __name__ == '__main__':
    unittest.main()
