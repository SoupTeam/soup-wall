# SPDX-License-Identifier: Apache-2.0
"""Negative report-grading and focused lane controls, not native acceptance."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('configuration_backup_qualification',
    ROOT / 'scripts/qualify-configuration-backup.py')
Q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(Q)


def synthetic_report():
    report = {'format': Q.FORMAT, 'status': 'passed',
        'cases': [{'id': name, 'status': 'passed', 'evidence': {'synthetic': True}} for name in Q.CASES],
        'source_before': {'commit': 'a' * 40, 'tree': 'b' * 40, 'dirty': False},
        'source_after': {'commit': 'a' * 40, 'tree': 'b' * 40, 'dirty': False},
        'counts': {'passed': len(Q.CASES), 'failed': 0, 'incomplete': 0},
        'provider': 'owned-scripted-loopback', 'paid_api_calls': 0, 'actual_publication_attempts': 0,
        'fresh_authority_created': True, 'old_authority_accepted': False, 'forbidden_effects': 0,
        'old_installation_preserved': True, 'operator_commands_outside_checkout': True,
        'all_owned_processes_stopped': True}
    evidence = {row['id']: row['evidence'] for row in report['cases']}
    evidence['exact-installed-inputs'].update(installed_component_verified=True)
    evidence['inventory-zero-effects'].update(writes=0)
    evidence['private-secret-free-backup'].update(secret_canaries_present=0, old_tokens_present=0)
    evidence['restore-preview-no-authority'].update(writes=0, redirected_destination_refused=True)
    evidence['confirmed-fresh-restore'].update(authority='not_restored')
    evidence['fresh-daemon-authority'].update(actual_restored_config_consumed=True)
    evidence['original-server-calibration'].update(actual_original_write=True, fifo_reader_observed=True)
    evidence['genuine-host-useful-read'].update(actual_host=True, actual_original_server_read=True,
                                              owned_host_processes_stopped=True)
    evidence['calibrated-refusal-zero-effects'].update(calibrated_fifo_reader_seen=False,
                                                       forbidden_bytes=0, useful_continuation=True)
    evidence['old-authority-refused'].update(old_bearer_http=401, old_grant_http=409,
                                           old_grant_error='native_child_authority_bad_signature')
    evidence['active-sibling-preserved'].update(same_active_sibling_useful=True)
    evidence['concurrent-source-change-refused'].update(published_archives=0)
    evidence['interrupted-restore-recovered'].update(initial_status='incomplete', recovery='restored')
    evidence['published-restore-recovered'].update(recovery='restored')
    evidence['source-workspace-preservation'].update(workspaces_unchanged=True)
    evidence['owned-cleanup'].update(private_test_state_removed=True)
    return report


class ReportGrading(unittest.TestCase):
    def test_complete_synthetic_grader_control(self):
        self.assertTrue(Q.passed(synthetic_report()))

    def test_every_missing_attempt_is_rejected_even_with_passed_summary(self):
        for index in range(len(Q.CASES)):
            with self.subTest(case=Q.CASES[index]):
                value = synthetic_report()
                value['cases'].pop(index)
                self.assertFalse(Q.passed(value))

    def test_required_original_effect_authority_and_cleanup_witnesses_cannot_be_removed(self):
        original = synthetic_report()
        for index, row in enumerate(original['cases']):
            for key in set(row['evidence']) - {'synthetic'}:
                with self.subTest(case=row['id'], witness=key):
                    report = copy.deepcopy(original)
                    del report['cases'][index]['evidence'][key]
                    self.assertFalse(Q.passed(report))

    def test_false_green_unknown_or_reordered_attempts_are_not_qualified(self):
        for fault in ('status', 'source', 'effect', 'old_authority', 'cleanup', 'order', 'provider'):
            report = synthetic_report()
            if fault == 'status':
                report['cases'][1]['status'] = 'incomplete'
            elif fault == 'source':
                report['source_after']['commit'] = 'c' * 40
            elif fault == 'effect':
                report['forbidden_effects'] = 1
            elif fault == 'old_authority':
                report['old_authority_accepted'] = True
            elif fault == 'cleanup':
                report['all_owned_processes_stopped'] = False
            elif fault == 'order':
                report['cases'].reverse()
            else:
                report['provider'] = 'not-owned'
            with self.subTest(fault=fault):
                self.assertFalse(Q.passed(report))


class LiveSourcePreservation(unittest.TestCase):
    def fixture(self, home):
        (home / 'config.yaml').write_bytes(b'owned source configuration\n')
        prefix = (json.dumps({'event': 'native_liveness_enrolled', 'session_id': 'owned-id',
                              'session': 'owned-epoch'}) + '\n').encode()
        (home / 'audit.jsonl').write_bytes(prefix)
        return Q.snapshot(home), prefix

    def renewal(self):
        return (json.dumps({'at_ms': 1, 'event': 'native_liveness_renewed', 'session': 'owned-epoch',
            'session_id': 'owned-id', 'lease_seq': 1, 'released': True}) + '\n').encode()

    def test_active_sibling_renewal_keeps_complete_non_audit_tree_and_evidence_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            baseline, prefix = self.fixture(home)
            with (home / 'audit.jsonl').open('ab') as stream:
                stream.write(self.renewal())
            self.assertEqual(Q.unchanged_live_source(home, baseline, prefix), 1)

    def test_mutation_rewrite_unexpected_activity_and_renewal_replay_are_refused(self):
        for fault in ('configuration', 'prefix', 'event', 'identity', 'replay'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                baseline, prefix = self.fixture(home)
                if fault == 'configuration':
                    (home / 'config.yaml').write_bytes(b'changed\n')
                elif fault == 'prefix':
                    (home / 'audit.jsonl').write_bytes(b'{}\n')
                else:
                    row = json.loads(self.renewal())
                    if fault == 'event':
                        row['event'] = 'native_session_end'
                    elif fault == 'identity':
                        row['session_id'] = 'other-id'
                    raw = (json.dumps(row) + '\n').encode()
                    with (home / 'audit.jsonl').open('ab') as stream:
                        stream.write(raw * (2 if fault == 'replay' else 1))
                with self.assertRaises(Q.QUAL.Failure):
                    Q.unchanged_live_source(home, baseline, prefix)


if __name__ == '__main__':
    unittest.main()
