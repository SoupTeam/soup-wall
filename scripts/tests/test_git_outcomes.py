import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pilot_git_outcomes as outcomes


class GitOutcomesTests(unittest.TestCase):
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
        trace = '123 write(2, ' + json.dumps(json.dumps(row) + '\n') + ', 400) = 400\n'
        self.assertEqual(outcomes.collect(trace), [row])
        self.assertEqual(outcomes.collect('123 write(2, "private-secret", 14) = 14'), [])
