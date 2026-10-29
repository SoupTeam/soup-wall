import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pilot_git_outcomes as outcomes


class GitOutcomesTests(unittest.TestCase):
    def test_admission_and_profile_observations_do_not_claim_delivery(self):
        row = {'event': 'mcp_call_outcome', 'version': 1, 'stage': 'call_admission',
               'request_sha256': 'a' * 64, 'host_call_sha256': 'b' * 64,
               'response_sha256': 'c' * 64, 'authority': False, 'released': False,
               'reason_codes_sha256': 'd' * 64, 'response': None}
        self.assertIsNotNone(outcomes.project(row))
        self.assertNotIn('written', outcomes.project(row))
        row['reason_codes_sha256'] = 'private-rule-name'
        self.assertIsNone(outcomes.project(row))
        row.pop('reason_codes_sha256')
        row.pop('released')
        row.update(stage='profile_validation', accepted=False,
                   response={'rpc_error': False, 'tool_error': None, 'rpc_code': None})
        self.assertIsNotNone(outcomes.project(row))
        self.assertNotIn('released', outcomes.project(row))

    def test_existing_delivery_witness_retains_failure_without_timing_or_payloads(self):
        row = {'event': 'mcp_original_result_delivery_timing', 'version': 1,
               'host_call_sha256': 'b' * 64, 'request_sha256': 'a' * 64,
               'response_sha256': 'c' * 64, 'elapsed_us': 120, 'written': False, 'authority': False}
        observed = outcomes.project(row)
        self.assertEqual(observed['stage'], 'host_delivery')
        self.assertIs(observed['written'], False)
        self.assertNotIn('elapsed_us', observed)
        row['payload'] = 'private'
        self.assertIsNone(outcomes.project(row))

    def test_original_rpc_ids_bind_results_instead_of_model_tool_ids(self):
        import hashlib
        import json
        arguments = {'repo_path': '/workspace', 'revision': 'HEAD'}
        arg_hash = hashlib.sha256(b'{"repo_path":"/workspace","revision":"HEAD"}').hexdigest()
        calls = [{'pid': 101, 'tool': 'git_show', 'args_sha256': arg_hash, 'id': 17},
                 {'pid': 102, 'tool': 'git_show', 'args_sha256': arg_hash, 'id': 'foreign'}]
        hashes = outcomes.call_hashes(calls, {101: 'git', 102: 'filesystem'}, 'git', 'git_show', arguments)
        self.assertEqual(hashes, {hashlib.sha256(b'17').hexdigest()})
        self.assertEqual(outcomes.call_hashes(calls, {101: 'git'}, 'git', 'git_status', arguments), set())
        calls[0]['id'] = '\u03b1'
        self.assertEqual(outcomes.call_hashes(calls, {101: 'git'}, 'git', 'git_show', arguments),
                         {hashlib.sha256(b'"\xce\xb1"').hexdigest()})

    def test_negative_controls_require_an_actual_error_response(self):
        results = {'toolu_existing_12': {'is_error': True, 'content': 'private-content'},
                   'toolu_existing_13': {'is_error': False, 'content': 'private-content'}}
        rows = outcomes.negative_results(results, (12, 13, 14))
        self.assertEqual([row['passed'] for row in rows], [True, False, False])
        self.assertEqual([row['result_present'] for row in rows], [True, True, False])
        self.assertNotIn('private-content', str(rows))

    def test_protocol_errors_and_tool_errors_stay_distinct_without_private_text(self):
        row = {'event': 'mcp_call_outcome', 'version': 1, 'stage': 'original_response',
               'request_sha256': 'a' * 64, 'host_call_sha256': 'b' * 64,
               'response_sha256': 'c' * 64, 'authority': False,
               'response': {'rpc_error': False, 'tool_error': True, 'rpc_code': None}}
        self.assertEqual(outcomes.project(row), row)
        row['response']['message'] = 'private-secret'
        self.assertIsNone(outcomes.project(row))

    def test_unknown_stages_and_authority_claims_are_not_evidence(self):
        self.assertIsNone(outcomes.project({'event': 'mcp_call_outcome', 'stage': 'private-input'}))

    def test_syscall_projection_keeps_only_fixed_schema(self):
        import json
        row = {'event': 'mcp_call_outcome', 'version': 1, 'stage': 'result_inspection',
               'request_sha256': 'a' * 64, 'host_call_sha256': 'b' * 64,
               'response_sha256': 'c' * 64, 'released': False, 'authority': False,
               'response': {'rpc_error': False, 'tool_error': False, 'rpc_code': None}}
        raw = json.dumps(row) + '\n'
        trace = '123 write(2, ' + json.dumps(raw) + f', {len(raw)}) = {len(raw)}\n'
        self.assertEqual(outcomes.collect(trace), [row])
        self.assertEqual(outcomes.collect('123 write(2, "private-secret", 14) = 14'), [])
        nested = '[' * 1100 + ']' * 1100 + '\n'
        bad = '123 write(2, ' + json.dumps(nested) + f', {len(nested)}) = {len(nested)}\n'
        self.assertEqual(outcomes.collect(bad + trace), [row])

    def test_partial_and_interleaved_writes_preserve_collector_identity(self):
        import json
        row = {'event': 'mcp_call_outcome', 'version': 1, 'stage': 'original_response',
               'request_sha256': 'a' * 64, 'host_call_sha256': 'b' * 64,
               'response_sha256': 'c' * 64, 'authority': False,
               'response': {'rpc_error': False, 'tool_error': True, 'rpc_code': None}}
        raw = json.dumps(row) + '\n'
        left, right = raw[:40], raw[40:]
        def write(pid, text, fd=2, written=None):
            return f'{pid} write({fd}, {json.dumps(text)}, {len(text)}) = {len(text) if written is None else written}\n'
        trace = write(123, left) + write(999, raw) + write(123, right)
        self.assertEqual(outcomes.collect(trace, pids={123}), [row])
        self.assertEqual(outcomes.collect(write(123, raw, fd=1), pids={123}), [])
        self.assertEqual(outcomes.collect(write(123, raw, written=0), pids={123}), [])
        oversized = write(123, 'x' * 5000) + write(123, raw)
        self.assertEqual(outcomes.collect(oversized, pids={123}), [])
        self.assertEqual(outcomes.collect(oversized + write(123, raw), pids={123}), [row])
