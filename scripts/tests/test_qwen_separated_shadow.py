# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('separated', Path(__file__).resolve().parents[1] / 'evaluate-qwen-separated-shadow.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SeparatedTests(unittest.TestCase):
    def test_channels_keep_complete_bytes_and_schema_enumerates_exact_ids(self):
        payload = {'evaluation_task': 'summarize', 'untrusted_text_channels': ['α\n', 'a' * 10000 + 'TAIL']}
        packaged = module.package(payload)
        self.assertEqual([c['text'] for c in packaged['untrusted_channels']], payload['untrusted_text_channels'])
        self.assertEqual([c['channel_id'] for c in packaged['untrusted_channels']], ['c0', 'c1'])
        self.assertEqual(module.evidence_schema(payload)['properties']['evidence']['items']['properties']['channel_id']['enum'], ['c0', 'c1'])

    def test_bad_id_wrong_channel_or_invented_quote_rejected(self):
        payload = {'untrusted_text_channels': ['first', 'second']}
        for channel, quote in [('c2', 'first'), ('c1', 'first'), ('c0', 'invented'), (0, 'first')]:
            with self.assertRaises(ValueError):
                module.validate_evidence({'target': '', 'effect': '', 'evidence': [{'channel_id': channel, 'quote': quote}]}, payload)

    def test_secondary_channel_utf8_span(self):
        spans = module.validate_evidence({'target': '', 'effect': '', 'evidence': [{'channel_id': 'c1', 'quote': 'β'}]}, {'untrusted_text_channels': ['x', 'αβ']})
        self.assertEqual(spans, [{'channel': 1, 'start': 2, 'end': 4}])

    def test_classification_does_not_require_or_accept_quotes(self):
        value = {'assessment': 'data', 'uncertainty': 0.1}
        module.validate_class(value)
        with self.assertRaises(ValueError): module.validate_class(dict(value, evidence=[]))
        with self.assertRaises(ValueError): module.validate_class(dict(value, uncertainty=True))
        # A later evidence failure must not rewrite an observed semantic miss.
        with self.assertRaises(ValueError): module.validate_evidence({}, {'untrusted_text_channels': ['x']})
        self.assertEqual(value['assessment'], 'data')

    def test_truncation_token_mismatch_duplicate_keys_fail(self):
        base = {'truncated': False, 'stop_type': 'eos', 'tokens_evaluated': 10,
                'content': json.dumps({'assessment': 'unknown', 'uncertainty': 1})}
        module.decode(base, 10)
        for change in [{'truncated': True}, {'tokens_evaluated': 9}, {'stop_type': 'limit'},
                       {'content': '{"assessment":"data","assessment":"unknown"}'}]:
            with self.assertRaises(ValueError): module.decode(dict(base, **change), 10)


if __name__ == '__main__': unittest.main()
