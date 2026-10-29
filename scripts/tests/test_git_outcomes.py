import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pilot_git_outcomes as outcomes


class GitOutcomesTests(unittest.TestCase):
    def test_client_error_classes_are_finite_observations_without_exception_text(self):
        value = {'is_error': True, 'content': 'MCP arguments violate the selected input profile private-value'}
        row = outcomes.negative_results({'toolu_existing_12': value}, (12,))[0]
        self.assertEqual(row['client_error_class'], 'input_profile_refused')
        self.assertNotIn('private-value', str(row))
        value['is_error'] = False
        self.assertIsNone(outcomes.negative_results({'toolu_existing_12': value}, (12,))[0]['client_error_class'])

    def test_negative_inventory_contains_an_actual_object_id_and_missing_file(self):
        controls = outcomes.negative_calls('a' * 40)
        self.assertEqual([row[0] for row in controls], ['missing_git_revision', 'unsupported_git_path',
                         'unsupported_git_expression', 'unsupported_git_tree', 'missing_workspace_file'])
        self.assertEqual(controls[3][1:], ('git', 'git_show', {'repo_path': '/workspace', 'revision': 'a' * 40}))
        self.assertEqual(controls[4][1:], ('filesystem', 'read_text_file', {'path': '/workspace/sou177-nonexistent-path'}))
        for value in (None, 'HEAD^{tree}', 'a' * 39, '../private'):
            with self.assertRaises(ValueError):
                outcomes.negative_calls(value)

    def test_rpc_ids_reused_by_two_servers_cannot_mix_observations(self):
        import hashlib
        import json
        identifier = hashlib.sha256(b'17').hexdigest()
        row = {'event': 'mcp_call_outcome', 'version': 1, 'stage': 'original_response',
               'request_sha256': 'a' * 64, 'host_call_sha256': identifier,
               'response_sha256': 'c' * 64, 'authority': False,
               'response': {'rpc_error': False, 'tool_error': False, 'rpc_code': None}}
        text = json.dumps(dict(row, collector_server='filesystem')) + '\n'
        trace = ''.join(f'{pid} write(2, {json.dumps(text)}, {len(text)}) = {len(text)}\n'
                        for pid in (101, 102))
        rows = outcomes.collect(trace, pids={101: 'git', 102: 'filesystem'})
        self.assertEqual([r['collector_server'] for r in rows], ['git', 'filesystem'])
        arguments = {'repo_path': '/workspace', 'revision': 'HEAD'}
        calls = [{'pid': 101, 'id': 17, 'tool': 'git_show', 'request_sha256': 'a' * 64,
                  'args_sha256': hashlib.sha256(b'{"repo_path":"/workspace","revision":"HEAD"}').hexdigest()}]
        rows.append(dict(rows[0], request_sha256='e' * 64))
        self.assertEqual(outcomes.operation_indices(rows, calls, {101: 'git'}, 'git', 'git_show', arguments), [0])
        self.assertEqual(outcomes.operation_indices([row], calls, {101: 'git'}, 'git', 'git_show', arguments), [])

    def test_full_observation_budget_is_retained_below_the_existing_file_limit(self):
        import hashlib
        import json
        import tempfile
        row = {'event': 'mcp_call_outcome', 'version': 1, 'stage': 'result_inspection',
               'request_sha256': 'a' * 64, 'host_call_sha256': 'b' * 64,
               'response_sha256': 'c' * 64, 'reason_codes_sha256': 'd' * 64,
               'authority': False, 'released': False, 'collector_server': 'filesystem',
               'response': {'rpc_error': True, 'tool_error': True, 'rpc_code': -(2 ** 63)}}
        def writer(path, value):
            raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
            self.assertLessEqual(len(raw), 65536)
            path.write_bytes(raw)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = outcomes.persist([row] * 256, root, 'initial', writer)
            restored = []
            self.assertEqual(record['records'], 256)
            self.assertLessEqual(len(record['files']), 8)
            for item in record['files']:
                data = (root / item['path']).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), item['sha256'])
                part = json.loads(data)
                self.assertEqual(part['offset'], len(restored))
                restored.extend(part['records'])
            self.assertEqual(restored, [row] * 256)
            for case, rows in (('../escape', [row]), ('initial', [row] * 257),
                               ('initial', [dict(row, payload='private')]), ('initial', [None])):
                with self.assertRaises(ValueError):
                    outcomes.persist(rows, root, case, writer)

    def test_failure_boundaries_require_observed_failures_not_missing_records(self):
        base = {'event': 'mcp_call_outcome', 'version': 1,
                'request_sha256': 'a' * 64, 'host_call_sha256': 'b' * 64,
                'response_sha256': 'c' * 64, 'authority': False,
                'response': {'rpc_error': False, 'tool_error': False, 'rpc_code': None}}
        original = dict(base, stage='original_response')
        self.assertEqual(outcomes.failure_boundaries([]), [])
        self.assertEqual(outcomes.failure_boundaries([original]), [])
        refused = dict(base, stage='result_inspection', released=False)
        self.assertEqual(outcomes.failure_boundaries([original, refused]), ['result_inspection_refused'])
        upstream = dict(original, response={'rpc_error': False, 'tool_error': True, 'rpc_code': None})
        self.assertEqual(outcomes.failure_boundaries([upstream, refused]),
                         ['original_tool_error', 'result_inspection_refused'])
        self.assertEqual(outcomes.failure_boundaries([dict(refused, authority=True)]), [])

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
        calls = [{'pid': 101, 'tool': 'git_show', 'args_sha256': arg_hash, 'id': 17, 'request_sha256': 'c' * 64},
                 {'pid': 102, 'tool': 'git_show', 'args_sha256': arg_hash, 'id': 'foreign', 'request_sha256': 'd' * 64}]
        hashes = outcomes.call_bindings(calls, {101: 'git', 102: 'filesystem'}, 'git', 'git_show', arguments)
        self.assertEqual(hashes, {(hashlib.sha256(b'17').hexdigest(), 'c' * 64)})
        self.assertEqual(outcomes.call_bindings(calls, {101: 'git'}, 'git', 'git_status', arguments), set())
        calls[0]['id'] = '\u03b1'
        self.assertEqual(outcomes.call_bindings(calls, {101: 'git'}, 'git', 'git_show', arguments),
                         {(hashlib.sha256(b'"\xce\xb1"').hexdigest(), 'c' * 64)})

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
