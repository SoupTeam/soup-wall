import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('prep', Path(__file__).parents[1] / 'prepare-sou157-git.py')
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)


class MappedGitPreparation(unittest.TestCase):
    def test_inventory_mapping_changes_only_namespace_and_never_claims_custody(self):
        rows = [PREP.mapped_case(c) for c in PREP.inventory()]
        self.assertEqual(len(rows), 8)
        self.assertEqual(sum(r['label'] == 'attack' for r in rows), 4)
        for row in rows:
            self.assertEqual(row['mapped_arguments'], {'repo_path': '/workspace', 'revision': 'HEAD'})
            self.assertNotEqual(row['original_arguments_sha256'], row['mapped_arguments_sha256'])
            self.assertFalse(row['exact_frozen_invocation'])
            self.assertFalse(row['live_custody'])
            self.assertFalse(row['original_returned_bytes_verified'])

    def test_byte_equality_rejects_newline_header_and_unicode_changes(self):
        for case in PREP.inventory():
            original = (PREP.ROOT / 'eval/sou123/payloads' / (case['case_id'] + '.txt')).read_bytes()
            equal = PREP.compare_original_text(case, original)
            self.assertTrue(equal['comparable'])
            self.assertFalse(equal['live_custody'])
            self.assertFalse(equal['production_authority'])
            for changed in (original + b'\n', original.replace(b'\n', b'\r\n'),
                            b'commit ' + b'0' * 40 + original[47:], original + 'я'.encode()):
                self.assertFalse(PREP.compare_original_text(case, changed)['comparable'])
            with self.assertRaisesRegex(ValueError, 'must_be_bytes'):
                PREP.compare_original_text(case, original.decode())

    def test_original_construction_reproduces_all_eight_commit_ids(self):
        git = shutil.which('git')
        self.assertIsNotNone(git, 'Git is required, not a skipped reproduction')
        git = Path(git).resolve()
        with tempfile.TemporaryDirectory(prefix='sou157-preparation-test-') as root:
            out = Path(root) / 'cases'
            report = PREP.prepare_repositories(out, git, PREP.sha(git.read_bytes()))
            self.assertEqual(report['native_executions'], 0)
            self.assertEqual(report['frozen_false_refusals'], 10)
            self.assertTrue(all(r['commit_matches_frozen_header'] for r in report['cases']),
                            json.dumps(report['cases']))
            marker = out / 'keep.txt'
            marker.write_bytes(b'existing data')
            with self.assertRaises(FileExistsError):
                PREP.prepare_repositories(out, git, PREP.sha(git.read_bytes()))
            self.assertEqual(marker.read_bytes(), b'existing data')
            self.assertTrue(all(value == 'not_executed' for value in report['required_native_controls'].values()))

    def test_wrong_git_pin_creates_nothing(self):
        git = Path(shutil.which('git')).resolve()
        with tempfile.TemporaryDirectory(prefix='sou157-pin-test-') as root:
            out = Path(root) / 'cases'
            with self.assertRaisesRegex(ValueError, 'pinned_git_mismatch'):
                PREP.prepare_repositories(out, git, '0' * 64)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
