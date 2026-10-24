# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock
import tempfile
import zipfile

spec = importlib.util.spec_from_file_location('separated', Path(__file__).resolve().parents[1] / 'evaluate-qwen-separated-shadow.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SeparatedTests(unittest.TestCase):
    def test_remaining_selection_rejects_hash_mismatch_and_replayed_input(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            report, manifest = root / 'report.json', root / 'manifest.json'
            rows = [{'request_id': f'r{i:04d}', 'input_sha256': str(i),
                     'input': {'untrusted_text_channels': ['α']}} for i in range(58)]
            refs = [{'request_id': row['request_id'], 'expected': 'benign', 'origin': 'synthetic-test'} for row in rows]
            report.write_text(json.dumps({'cases': [{'reference': {'request_id': key}} for key in module.IDS]}))
            selected = [row for row in rows if row['request_id'] not in module.IDS]
            plan = {'completed_eight_report_sha256': module.previous.sha(report),
                    'excluded_completed_ids': list(module.IDS), 'proposed_cases': [
                        {'request_id': row['request_id'], 'input_sha256': row['input_sha256'],
                         'expected': 'benign', 'origin': 'synthetic-test', 'full_channel_bytes': [2]} for row in selected]}
            manifest.write_text(json.dumps(plan))
            self.assertEqual(module.select_remaining(rows, refs, manifest, report), selected)
            plan['proposed_cases'][0]['request_id'] = module.IDS[0]
            manifest.write_text(json.dumps(plan))
            with self.assertRaisesRegex(ValueError, 'identity mismatch'):
                module.select_remaining(rows, refs, manifest, report)
            report.write_text(report.read_text() + '\n')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                module.select_remaining(rows, refs, manifest, report)

    def test_main_preserves_classification_when_evidence_is_interrupted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            assets, prepared, output = root / 'assets', root / 'prepared', root / 'output'
            assets.mkdir(); prepared.mkdir()
            with zipfile.ZipFile(assets / 'llama-b11852-bin-win-cpu-x64.zip', 'w'): pass
            rows = [{'request_id': key, 'input_sha256': key, 'input': {
                'evaluation_task': 'summarize', 'untrusted_text_channels': ['untrusted']}} for key in module.IDS]
            (prepared / 'requests.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in rows))
            hashes = {'Qwen3.5-9B-Q4_K_M.gguf': module.previous.MODEL_SHA,
                      'llama-b11852-bin-win-cpu-x64.zip': module.previous.RUNTIME_SHA,
                      'requests.jsonl': module.previous.REQUEST_SHA,
                      'references.jsonl': module.previous.REFERENCE_SHA}
            prediction = {'status': 'valid', 'value': {'assessment': 'data', 'uncertainty': 0.1}}
            process = mock.Mock()
            process.poll.return_value = None
            health = mock.MagicMock()
            health.__enter__.return_value.status = 200
            def infer(*args):
                if args[1] == module.CLASSIFY: return prediction
                persisted = [json.loads(s) for s in (output / 'stages.jsonl').read_text().splitlines()]
                self.assertEqual(persisted[1]['result'], prediction)
                self.assertEqual(persisted[2]['state'], 'started')
                raise KeyboardInterrupt()
            argv = ['runner', '--assets', str(assets), '--prepared', str(prepared), '--output', str(output)]
            with mock.patch('sys.argv', argv), mock.patch.object(module.previous, 'sha', side_effect=lambda p: hashes[p.name]), \
                 mock.patch.object(module.subprocess, 'Popen', return_value=process), \
                 mock.patch.object(module.urllib.request, 'urlopen', return_value=health), \
                 mock.patch.object(module.socket, 'socket'), mock.patch.object(module, 'stage', side_effect=infer):
                with self.assertRaises(KeyboardInterrupt): module.main()
            persisted = [json.loads(s) for s in (output / 'stages.jsonl').read_text().splitlines()]
            self.assertEqual(persisted[1]['result'], prediction)
            self.assertEqual(persisted[-1]['state'], 'interrupted')
            self.assertEqual(persisted[-1]['phase'], 'evidence')
            self.assertFalse((output / 'observations.jsonl').exists())
            process.terminate.assert_called_once()
            process.wait.assert_called_once_with(timeout=15)

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
