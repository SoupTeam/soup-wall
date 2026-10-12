# SPDX-License-Identifier: Apache-2.0
"""Export scope checks on isolated synthetic files; no dataset or sealed test."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sou13gold.export import load_verifier


class ExportPathScope(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.parent = Path(self.temporary.name)
        self.root = self.parent / 'export'
        self.root.mkdir()
        self.verifier = load_verifier()

    def tearDown(self):
        self.temporary.cleanup()

    def test_parent_reference_never_hashes_outside_file(self):
        outside = self.parent / 'outside-unit-fixture.txt'
        outside.write_text('SYNTHETIC UNIT FIXTURE ONLY', encoding='utf-8')
        manifest = {'files_sha256': {'../outside-unit-fixture.txt': self.verifier.fsha(outside)}}
        with mock.patch.object(self.verifier, 'fsha', side_effect=AssertionError('outside read')):
            self.assertTrue(self.verifier.file_errors(self.root, manifest))

    def test_absolute_and_noncanonical_members_are_refused_before_hashing(self):
        paths = (str(self.parent / 'outside.txt'), '/outside.txt', 'C:/outside.txt',
                 r'\\server\share\outside.txt', 'nested/../outside.txt', 'nested//file', './file', r'nested\file')
        for rel in paths:
            with self.subTest(rel=rel), mock.patch.object(self.verifier, 'fsha',
                                                         side_effect=AssertionError('unsafe content read')):
                errors = self.verifier.file_errors(self.root, {'files_sha256': {rel: '0' * 64}})
                self.assertTrue(errors)

    def test_addendum_and_authorization_references_are_scoped(self):
        for field, value in (('addenda', [{'file': '../outside.json'}]),
                             ('authorization', {'file': '../outside.json'})):
            with self.subTest(field=field):
                self.assertTrue(self.verifier.file_errors(self.root, {'files_sha256': {}, field: value}))

    def test_metadata_reference_must_be_in_file_manifest(self):
        (self.root / 'unlisted.json').write_text('{}', encoding='utf-8')
        self.assertTrue(self.verifier.file_errors(
            self.root, {'files_sha256': {}, 'addenda': [{'file': 'unlisted.json'}]}))

    def test_regular_nested_member_passes(self):
        path = self.root / 'labels' / 'train.jsonl'
        path.parent.mkdir()
        path.write_text('SYNTHETIC UNIT FIXTURE ONLY', encoding='utf-8')
        self.assertEqual(self.verifier.file_errors(
            self.root, {'files_sha256': {'labels/train.jsonl': self.verifier.fsha(path)}}), [])

    def test_file_link_is_refused_before_hashing_even_when_unlisted(self):
        path = self.root / 'linked.txt'
        path.write_text('SYNTHETIC UNIT FIXTURE ONLY', encoding='utf-8')
        # Simulate the lstat result on Windows without needing symlink privileges.
        with mock.patch.object(self.verifier, 'is_link', side_effect=lambda p: p == path), \
                mock.patch.object(self.verifier, 'fsha', side_effect=AssertionError('linked file read')):
            errors = self.verifier.file_errors(self.root, {'files_sha256': {'linked.txt': '0' * 64}})
        self.assertTrue(any('symlink' in error for error in errors))

    def test_link_directory_is_pruned_before_contents_are_hashed(self):
        directory = self.root / 'linked-directory'
        directory.mkdir()
        (directory / 'data.txt').write_text('SYNTHETIC UNIT FIXTURE ONLY', encoding='utf-8')
        with mock.patch.object(self.verifier, 'is_link', side_effect=lambda p: p == directory), \
                mock.patch.object(self.verifier, 'fsha', side_effect=AssertionError('linked directory read')):
            errors = self.verifier.file_errors(self.root, {'files_sha256': {}})
        self.assertTrue(any('symlink' in error for error in errors))

    def test_manifest_link_fails_before_loading_json(self):
        with mock.patch.object(self.verifier, 'is_link', return_value=True), \
                mock.patch.object(self.verifier.Path, 'read_bytes', side_effect=AssertionError('linked manifest read')):
            self.assertEqual(self.verifier.verify(self.root)['result'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
