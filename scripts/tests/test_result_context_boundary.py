import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('context_probe', ROOT / 'scripts/probe-result-context-boundary.py')
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class ContextBoundaryTests(unittest.TestCase):
    def test_every_control_preserves_frozen_bytes_outside_declared_edit(self):
        manifest = PROBE.DIAG.corpus.load_manifest(ROOT / 'eval/sou123/manifest.json')
        cases, payloads = PROBE.prepare(manifest, ROOT / 'eval/sou123/payloads')
        self.assertEqual(len(cases), 30)
        self.assertEqual(sum(c['expected'] == 'attack' for c in cases), 24)
        for case in cases:
            original = (ROOT / 'eval/sou123/payloads' / (case['source_case'] + '.txt')).read_bytes()
            edit = case['edit']
            self.assertEqual(payloads[case['case_id']], original[:edit['start']] + edit['replacement'].encode('utf-8') + original[edit['end']:])
            if case['variant'] == 'original':
                self.assertEqual(payloads[case['case_id']], original)
            elif case['source_case'] in PROBE.MARKERS:
                self.assertEqual(original[edit['start']:edit['end']].decode('utf-8'), PROBE.MARKERS[case['source_case']])
            else:
                self.assertEqual(edit['start'], len(original))
                self.assertEqual(edit['end'], len(original))
            self.assertEqual(PROBE.hashlib.sha256(original).hexdigest(), case['source_sha256'])
            self.assertEqual(PROBE.hashlib.sha256(payloads[case['case_id']]).hexdigest(), case['sha256'])

    def test_missing_result_and_utf8_split_cannot_be_graded(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'control.txt').write_bytes('я'.encode('utf-8'))
            cases = [{'case_id': 'control', 'expected': 'attack'}]
            with self.assertRaises(ValueError):
                PROBE.grade(cases, [], directory)
            row = {'case_id': 'control', 'status': 'inspected', 'verdict': 'Deny',
                   'findings': [{'label': 'split', 'span': {'start': 1, 'end': 2}}]}
            with self.assertRaises(UnicodeDecodeError):
                PROBE.grade(cases, [row], directory)

    def test_incomplete_deny_is_not_a_caught_attack_and_unattested_change_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'control.txt').write_text('text', encoding='utf-8')
            cases = [{'case_id': 'control', 'expected': 'attack'}]
            row = {'case_id': 'control', 'status': 'evidence_budget_not_inspected', 'verdict': 'Deny', 'findings': []}
            report = PROBE.grade(cases, [row], directory)
            self.assertEqual(report['attack_controls_refused'], 0)
            self.assertEqual(report['incomplete_controls'], 1)
            self.assertIsNone(report['cases'][0]['useful_original_server_delivery'])
            row['status'] = 'inspected'
            with self.assertRaises(ValueError):
                PROBE.grade(cases, [row], directory)
            row['policy_shadow'] = {'comparison': {'original': 'Deny', 'candidate': 'Allow',
                                                   'original_findings': [], 'candidate_findings': []}}
            with self.assertRaises(ValueError):
                PROBE.grade(cases, [row], directory)
            row['policy_shadow']['comparison']['candidate'] = 'Deny'
            report = PROBE.grade(cases, [row], directory)
            self.assertEqual(report['attack_controls_refused'], 1)
            self.assertFalse(report['task_complete'])


if __name__ == '__main__':
    unittest.main()
