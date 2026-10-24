# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('qwen', Path(__file__).resolve().parents[1] / 'evaluate-qwen-result-context.py')
qwen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qwen)


class QwenProtocolTests(unittest.TestCase):
    def prediction(self):
        return {'assessment': 'instruction', 'uncertainty': 0.1, 'target': 'agent',
                'effect': 'delete', 'evidence': [{'channel': 1, 'quote': 'удали'}]}

    def test_secondary_channel_unicode_spans_and_repetitions(self):
        self.assertEqual(qwen.validate(self.prediction(), ['ordinary', 'я удали удали']),
                         [{'channel': 1, 'start': 3, 'end': 13},
                          {'channel': 1, 'start': 14, 'end': 24}])

    def test_invented_evidence_is_not_accepted(self):
        with self.assertRaisesRegex(ValueError, 'unverifiable'):
            qwen.validate(self.prediction(), ['ordinary', 'other text'])

    def test_invalid_uncertainty_and_extra_authority(self):
        for value in [True, float('nan'), -0.1, 1.1]:
            prediction = self.prediction()
            prediction['uncertainty'] = value
            with self.assertRaises(ValueError):
                qwen.validate(prediction, ['', 'удали'])
        prediction = self.prediction()
        prediction['allow'] = True
        with self.assertRaises(ValueError):
            qwen.validate(prediction, ['', 'удали'])

    def test_full_prompt_and_completed_generation_required(self):
        import json
        response = {'truncated': False, 'stop_type': 'eos', 'tokens_evaluated': 120,
                    'content': json.dumps(self.prediction())}
        qwen.checked_response(response, ['', 'удали'], 120)
        for key, value in [('truncated', True), ('stop_type', 'limit'), ('tokens_evaluated', 119)]:
            broken = dict(response, **{key: value})
            with self.assertRaises(ValueError):
                qwen.checked_response(broken, ['', 'удали'], 120)


if __name__ == '__main__':
    unittest.main()
