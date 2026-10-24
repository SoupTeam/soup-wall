# SPDX-License-Identifier: Apache-2.0
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('report', Path(__file__).parents[1] / 'report-qwen-separated-full.py')
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)


class RetainedEvidenceTests(unittest.TestCase):
    def row(self):
        return {'request_id': 'r0041', 'input_sha256': 'abc',
                'classification': {'status': 'valid', 'value': {'assessment': 'data', 'uncertainty': .1}, 'elapsed_ms': 10},
                'evidence': {'status': 'error', 'error': 'ValueError: unverifiable quote', 'elapsed_ms': 20}}

    def test_missed_attack_not_hidden_by_invalid_quote(self):
        metrics = report.summarize([{'reference': {'expected': 'attack'}, 'observation': self.row()}])
        self.assertEqual(metrics['semantic_miss_ids'], ['r0041'])
        self.assertEqual(metrics['diagnostic_unknown_count'], 1)
        self.assertEqual(metrics['classification_counts'], {'attack->data': 1})
        self.assertEqual(metrics['latency']['both_stages']['total_ms'], 30)

    def test_classification_must_be_durable_before_evidence(self):
        rows = [self.row()]
        journal = report.journal_expected(rows)
        report.validate_journal(rows, journal)
        journal[1], journal[2] = journal[2], journal[1]
        with self.assertRaisesRegex(ValueError, 'journal'):
            report.validate_journal(rows, journal)

    def test_mutated_stage_is_not_accepted(self):
        rows = [self.row()]
        journal = copy.deepcopy(report.journal_expected(rows))
        journal[1]['result']['value']['assessment'] = 'instruction'
        with self.assertRaisesRegex(ValueError, 'journal'):
            report.validate_journal(rows, journal)

    def test_not_run_has_no_fabricated_evidence_start(self):
        row = self.row()
        row['classification'] = {'status': 'error', 'elapsed_ms': 5}
        row['evidence'] = {'status': 'not_run_classification_error'}
        journal = report.journal_expected([row])
        self.assertEqual(len(journal), 3)
        self.assertEqual(journal[-1]['state'], 'not_run')
        with self.assertRaisesRegex(ValueError, 'journal'):
            report.validate_journal([row], journal[:-1])

    def test_claimed_oversize_must_have_sufficient_token_count(self):
        row = {'status': 'error', 'error': 'ValueError: full context exceeds limit; no prefix accepted', 'prompt_tokens': 12}
        with self.assertRaisesRegex(ValueError, 'non-response'):
            report.validate_stage(row, {}, 'classification')


if __name__ == '__main__':
    unittest.main()
