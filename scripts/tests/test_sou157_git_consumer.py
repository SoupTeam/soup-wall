import importlib.util
import json
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('consumer', Path(__file__).parents[1] / 'sou157_git_consumer.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class ConsumerBoundaries(unittest.TestCase):
    def test_failed_http_mode_retains_partial_outcome_and_cleanup(self):
        row = {'controls': {}}
        saved = []
        def save():
            saved.append(json.loads(json.dumps(row)))
        def fail(record):
            record['stage'] = 'original_execution'
            record['http_outcomes'].append({'http_status': 409, 'stage': 'original_execution',
                'finite_code': 'native_git_execution_incomplete'})
            try:
                raise ValueError('original_execution_failed')
            finally:
                record['cleanup'] = {'all_stopped': True, 'observed': []}
        with self.assertRaisesRegex(ValueError, 'original_execution_failed'):
            C.retain_mode(row, 'allow', save, fail)
        self.assertEqual(saved[0]['controls']['allow']['status'], 'incomplete')
        failed = saved[-1]['controls']['allow']
        self.assertEqual(failed['status'], 'failed')
        self.assertEqual(failed['http_outcomes'][0]['http_status'], 409)
        self.assertTrue(failed['cleanup']['all_stopped'])
        self.assertNotIn('execution', failed)
        self.assertNotIn('release', failed)

    def test_unknown_exception_text_is_not_retained(self):
        row = {'controls': {}}
        def fail(record):
            raise ValueError('secret request body and token')
        with self.assertRaises(ValueError):
            C.retain_mode(row, 'allow', lambda: None, fail)
        self.assertNotIn('secret', json.dumps(row))
        self.assertEqual(row['controls']['allow']['finite_code'], 'qualification_failed')

    def setUp(self):
        self.profile = {'format': 'sw-mcp/git-readonly/1', 'workspace': '/owned'}
        self.frame = json.dumps({'jsonrpc': '2.0', 'id': 10, 'result': {
            'content': [{'type': 'text', 'text': 'original\n'}], 'isError': False}})
        self.call = {'call_id': 'one', 'binding_sha256': 'a' * 64}
        self.value = {'completed': True, 'profile_sha256': C.sha(C.canonical(self.profile)),
                      'frame': self.frame, 'receipt': {'release': True, 'verdict': 'Allow',
                      'content_sha256': C.sha(self.frame.encode())}}

    def check(self, value=None, expected=b'original\n', release=True):
        return C.validate_reply(value or self.value, self.call, self.profile, 10, expected, release)

    def test_matching_body_does_not_excuse_profile_channel_or_completion_mismatch(self):
        self.check()
        for field, value in [('completed', False), ('completed', 1), ('profile_sha256', '0' * 64)]:
            with self.assertRaises(ValueError):
                self.check({**self.value, field: value})
        with self.assertRaises(ValueError):
            self.check({**self.value, 'receipt': {**self.value['receipt'], 'content_sha256': '0' * 64}})

    def test_changed_original_bytes_never_count_as_delivery(self):
        for expected in (b'original', b'original\r\n', b'Original\n', b'original\n\n'):
            with self.assertRaises(ValueError):
                self.check(expected=expected)

    def test_correlated_single_text_frame_required(self):
        value = json.loads(self.frame)
        for identifier in ('10', True, 11, None):
            with self.assertRaises(ValueError):
                C.frame_text(json.dumps({**value, 'id': identifier}), 10)
        for result in ({'isError': True, 'content': value['result']['content']},
                       {'content': []}, {'content': value['result']['content'] * 2}):
            with self.assertRaises(ValueError):
                C.frame_text(json.dumps({**value, 'result': result}), 10)

    def test_refusal_cannot_expose_original_frame(self):
        refused = {**self.value, 'frame': None, 'receipt': {'release': False, 'verdict': 'Deny'}}
        self.check(refused, release=False)
        with self.assertRaises(ValueError):
            self.check({**refused, 'frame': self.frame}, release=False)
        with self.assertRaises(ValueError):
            self.check(refused)
        with self.assertRaises(ValueError):
            self.check({**refused, 'receipt': {'release': False, 'verdict': 'Ask'}}, release=False)


if __name__ == '__main__':
    unittest.main()
