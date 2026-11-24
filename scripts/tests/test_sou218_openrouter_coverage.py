import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('coverage_report', Path(__file__).parents[1] / 'sou218-openrouter-coverage.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class CoverageTests(unittest.TestCase):
    def fixture(self, root):
        corpus = root / 'corpus'
        corpus.mkdir()
        sessions = [root / 'one', root / 'two']
        for p in sessions:
            p.mkdir()
        for i in range(30):
            b = {'case_id': str(i), 'source': 'source ' + str(i),
                 'request': {'systemInstruction': {'parts': [{'text': 'frozen prompt'}]},
                             'contents': [{'parts': [{'text': 'source ' + str(i)}]}],
                             'generationConfig': {'responseJsonSchema': {'type': 'object'}}}}
            (corpus / (str(i) + '.json')).write_text(json.dumps(b))
            if i < 2:
                (sessions[i] / 'job-test.json').write_text(json.dumps(b))
        return corpus, sessions

    def audit(self, directory):
        b = json.loads((directory / 'job-test.json').read_text())
        return {'rows': [{'case_id': b['case_id'], 'source_sha256': c.a.digest(b['source'].encode()),
                          'job': 'job-test', 'response_sha256': 'retained',
                          'offline_validation': {'state': 'invalid_response'}}]}

    def test_invalid_responses_count_as_evidence_not_success_and_no_network(self):
        with tempfile.TemporaryDirectory() as d:
            corpus, sessions = self.fixture(Path(d))
            with patch.object(c.report, 'audit_session', side_effect=self.audit), patch.object(c.a, 'fetch', side_effect=AssertionError('network')):
                result = c.combine(sessions, [], corpus)
            self.assertEqual(result['responses'], 2)
            self.assertEqual(result['structurally_valid'], 0)
            self.assertEqual(len(result['missing_responses']), 28)
            self.assertFalse(result['semantic_acceptance'])

    def test_duplicate_case_and_changed_prompt_are_refused(self):
        with tempfile.TemporaryDirectory() as d:
            corpus, sessions = self.fixture(Path(d))
            with patch.object(c.report, 'audit_session', side_effect=self.audit):
                with self.assertRaisesRegex(ValueError, 'duplicate_case'):
                    c.combine([sessions[0], sessions[0]], [], corpus)
                path = sessions[1] / 'job-test.json'
                b = json.loads(path.read_text())
                b['request']['systemInstruction']['parts'][0]['text'] = 'different prompt'
                path.write_text(json.dumps(b))
                with self.assertRaisesRegex(ValueError, 'mixed_request_profiles'):
                    c.combine(sessions, [], corpus)
                result = c.combine(sessions, [], corpus, allow_mixed_inventory=True)
                self.assertFalse(result['single_profile'])
                self.assertIsNone(result['profile_sha256'])
                self.assertEqual(sorted(result['profile_counts'].values()), [1, 1])
                self.assertFalse(result['semantic_acceptance'])
                with self.assertRaisesRegex(ValueError, 'duplicate_case'):
                    c.combine([sessions[0], sessions[0]], [], corpus, allow_mixed_inventory=True)


if __name__ == '__main__':
    unittest.main()
