# SPDX-License-Identifier: Apache-2.0
"""Adversarial controls for retained benchmark proof, not performance evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('ask_comparison', Path(__file__).resolve().parents[1] / 'qualify-pilot-ask-comparison.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class ComparisonProof(unittest.TestCase):
    def setUp(self):
        self.source = dict(commit='a' * 40, tree='b' * 40, dirty=False, files_sha256='c' * 64)
        self.selected = {key: 'd' * 64 for key in (*C.SHARED, 'agentfw', 'git_launcher')}
        rows = [dict(profile=p, case='approve', sample_index=i, passed=True,
                     approved=True, released=True, dispatched=1, kernel_effects=1,
                     decision_to_result_ms=100, allow_peer_while_pending=True,
                     cross_run_isolation_and_cleanup=True,
                     verified_inputs_resume=dict(immutable_files=0, leased_files=1,
                         rehashed_files=2, observer='collector mcp_verified_inputs_resume'))
                for p in C.PROFILES for i in range(20)]
        self.report = dict(status='pass', real_host_executed=True, scripted_owned_provider=True,
                           paid_api_calls=0, source=self.source.copy(), source_after=self.source.copy(),
                           workspace_unchanged=True, selected_sha256=self.selected.copy(), cases=rows,
                           latency=C.METRICS.summarize(rows, 20))

    def validate(self, row=None, candidate=True):
        return C.validate_report(row or self.report, self.source, self.selected, 20, candidate)

    def test_complete_real_proofs_and_either_verity_or_lease_are_accepted(self):
        self.assertEqual(self.validate()['status'], 'target_met')
        for row in self.report['cases']:
            row['verified_inputs_resume'].update(immutable_files=1, leased_files=0)
        self.assertEqual(self.validate()['status'], 'target_met')

    def test_slow_complete_baseline_is_retained_and_candidate_target_remains_blocking(self):
        self.report['status'] = 'performance_blocker'
        for row in self.report['cases']:
            row['decision_to_result_ms'] = 3001
            row.pop('verified_inputs_resume')
        self.report['latency'] = C.METRICS.summarize(self.report['cases'], 20)
        self.assertEqual(self.validate(candidate=False)['status'], 'performance_blocker')
        with self.assertRaisesRegex(ValueError, 'reuse_observer_missing'):
            self.validate()

    def test_missing_failed_and_duplicate_samples_never_become_a_smaller_denominator(self):
        for change in ('missing', 'failed', 'duplicate', 'effect'):
            row = copy.deepcopy(self.report)
            if change == 'missing': row['cases'].pop()
            elif change == 'failed': row['cases'][0]['passed'] = False
            elif change == 'effect': row['cases'][0]['kernel_effects'] = 0
            else: row['cases'][-1] = row['cases'][-2]
            with self.subTest(change=change), self.assertRaises(ValueError): self.validate(row)

    def test_source_restart_peer_loss_or_wrong_binary_refuses(self):
        for field, value in (('source_after', dict(self.source, commit='f' * 40)),
                             ('selected_sha256', {}), ('workspace_unchanged', False),
                             ('real_host_executed', False), ('paid_api_calls', False)):
            row = copy.deepcopy(self.report); row[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.validate(row)
        self.report['cases'][0]['allow_peer_while_pending'] = False
        with self.assertRaisesRegex(ValueError, 'peer_progress_missing'): self.validate()

    def test_claimed_reuse_and_claimed_percentiles_are_not_proof(self):
        for proof in ({}, dict(observer='mtime cache', immutable_files=1, leased_files=0, rehashed_files=0),
                      dict(observer='collector mcp_verified_inputs_resume', immutable_files=False, leased_files=1, rehashed_files=0),
                      dict(observer='collector mcp_verified_inputs_resume', immutable_files=0, leased_files=0, rehashed_files=2)):
            row = copy.deepcopy(self.report); row['cases'][0]['verified_inputs_resume'] = proof
            with self.subTest(proof=proof), self.assertRaises(ValueError): self.validate(row)
        self.report['latency']['filesystem']['p95_ms'] = 1
        with self.assertRaisesRegex(ValueError, 'reported_metrics_disagree'): self.validate()

    def test_build_receipt_requires_exact_source_and_actual_binary_digest(self):
        receipt = dict(format='sw-native-pilot-agent-source-build/1', source=self.source,
                       binaries={role: dict(sha256=self.selected[role]) for role in ('agentfw', 'git_launcher')})
        C.validate_build(receipt, self.source, self.selected)
        for change in ('source', 'binary', 'format'):
            bad = copy.deepcopy(receipt)
            if change == 'source': bad['source']['files_sha256'] = 'e' * 64
            elif change == 'binary': bad['binaries']['agentfw']['sha256'] = 'e' * 64
            else: bad['format'] = 'other'
            with self.subTest(change=change), self.assertRaises(ValueError):
                C.validate_build(bad, self.source, self.selected)


if __name__ == '__main__':
    unittest.main()
