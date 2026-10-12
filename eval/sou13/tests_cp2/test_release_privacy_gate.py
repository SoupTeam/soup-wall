# SPDX-License-Identifier: Apache-2.0
"""Privacy gate rules on synthetic temporary trees and repositories (no dataset, network or sealed material).

Sensitive-looking literals are assembled at run time so that this file itself passes the gate."""
import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts_cp2 import check_release_privacy as gate
from scripts_cp2.check_release_privacy import deny_digests, git_prospective, inspect, inspect_files

PUBLIC = frozenset({'fam.read.http_get'})
FAKE_ID = 'S13C2-' + '0' * 32


class Tree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, rel, data):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        (p.write_bytes if isinstance(data, bytes) else p.write_text)(data)
        return p

    def issues(self, **kw):
        return inspect(self.root, **kw)


class PathAndContentRules(Tree):
    def test_public_python_module_is_allowed(self):
        self.put('sou13cp2/semantics.py', 'OPS = {"read": {}}\nFAMILY = "fam.read.http_get"\n')
        self.assertEqual(self.issues(families=PUBLIC), [])

    def test_sealed_path_is_denied(self):
        self.put('cp2_sealed/test_labels.jsonl', '{}')
        self.assertTrue(self.issues())

    def test_private_key_is_denied(self):
        self.put('private.txt', '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----')
        self.assertTrue(any('private-key marker' in i for i in self.issues()))

    def test_review_csv_and_jsonl_need_manual_approval(self):
        self.put('case_level_review.csv', 'id,label\n')
        self.put('exports/train.jsonl', '{}\n')
        self.assertEqual(len(self.issues()), 2)

    def test_literal_case_id_is_denied_but_the_pattern_text_is_not(self):
        self.put('notes.md', 'ID pattern: S13C2-[0-9A-F]{32}\n')
        self.assertEqual(self.issues(), [])
        self.put('notes.md', f'see {FAKE_ID}\n')
        self.assertTrue(any('literal CP2 case id' in i for i in self.issues()))

    def test_owner_absolute_paths_are_denied(self):
        for text in ('D:' + '\\SOU13_CP2\\data', 'C:' + '/Us' + 'ers/someone/x', '/mnt' + '/data/x'):
            with self.subTest(text=text):
                self.put('doc.md', text)
                self.assertTrue(any('owner absolute path' in i for i in self.issues()), text)

    def test_label_row_outside_code_and_schema_is_denied(self):
        row = json.dumps({'id': 'S13V03-DEV-01', 'per_action_targets': {'read': True}})
        self.put('schema/x.schema.json', '{"properties": {"per_action_targets": {}}, "id": "S13V03-DEV-01"}')
        self.assertEqual(self.issues(), [])
        self.put('report.json', row)
        self.assertTrue(any('label row' in i for i in self.issues()))

    def test_family_id_outside_public_taxonomy_is_denied(self):
        self.put('a.py', 'X = "fam.read.http_get"; fam.get("k")\n')
        self.assertEqual(self.issues(families=PUBLIC), [])
        self.put('b.md', 'fam.read.' + 'unlisted_probe')
        self.assertTrue(any('outside the public taxonomy' in i for i in self.issues(families=PUBLIC)))

    def test_registered_family_id_is_allowed_only_in_its_own_files(self):
        synthetic = 'fam.delete.' + 'syn_one'
        self.put('tests_cp2/test_near_duplicates.py', f'A = "{synthetic}"\n')
        self.assertEqual(self.issues(families=PUBLIC), [])
        self.put('tests_cp2/test_other.py', f'A = "{synthetic}"\n')
        issues = self.issues(families=PUBLIC)
        self.assertEqual(len(issues), 1)
        self.assertTrue(issues[0].startswith('tests_cp2/test_other.py: family ids outside the public taxonomy'))

    def test_unconfirmed_registry_entry_fails_even_in_its_own_file(self):
        probe = 'fam.unknown.' + 'probe_pending'
        registry = {probe: dict(files=('tests_cp2/t.py',), confirmed=False, provenance='TEST-ONLY')}
        self.put('tests_cp2/t.py', f'A = "{probe}"\n')
        with mock.patch.dict(gate.FILE_SCOPED_FAMILY_IDS, registry):
            self.assertTrue(any('awaiting owner provenance confirmation' in i
                                for i in self.issues(families=PUBLIC)))
            registry[probe]['confirmed'] = True
            self.assertEqual(self.issues(families=PUBLIC), [])

    def test_dangling_symlink_is_not_treated_as_a_deletion(self):
        link = self.root / 'candidate.txt'
        try:
            link.symlink_to('missing-target.txt')
        except OSError as exc:
            self.skipTest(f'symlink creation unavailable: {exc}')
        self.assertFalse(link.exists())
        self.assertTrue(link.is_symlink())
        self.assertTrue(any('not a regular file' in issue for issue in self.issues()))

    def test_binary_content_fails_closed(self):
        self.put('blob.bin', b'\x00\x01')
        self.assertTrue(any('binary' in i for i in self.issues()))

    def test_byte_identical_private_data_is_denied_even_if_renamed(self):
        data = b'{"id": "x"}\n'
        self.put('freeze.json', json.dumps({'files_sha256': {
            'data/dev16.jsonl': hashlib.sha256(data).hexdigest(),
            'sou13/build.py': hashlib.sha256(b'code').hexdigest()}}))
        digests = deny_digests([self.root / 'freeze.json'])
        self.assertEqual(digests, {hashlib.sha256(data).hexdigest()})  # code digests are not denied
        self.put('innocent.txt', data.replace(b'\n', b'\r\n'))  # LF-normalised match too
        self.assertTrue(any('byte-identical' in i for i in inspect_files(self.root, ['innocent.txt'],
                                                                          digests=digests)))

    def test_custodian_commitments_are_denied(self):
        sealed = b'sealed bytes'
        self.put('MANIFEST.json', json.dumps({'test_commitments': {
            'test_labels_file_sha256': hashlib.sha256(sealed).hexdigest(), 'note': 'n'}}))
        digests = deny_digests([self.root / 'MANIFEST.json'])
        self.put('copy.dat', sealed)
        self.assertTrue(inspect_files(self.root, ['copy.dat'], digests=digests))


@unittest.skipUnless(shutil.which('git'), 'git is required for prospective-diff discovery')
class GitProspectiveDiff(Tree):
    def git(self, *args):
        subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True)

    def setUp(self):
        super().setUp()
        self.git('init', '-q')
        self.git('config', 'user.email', 'gate-test@example.test')
        self.git('config', 'user.name', 'gate test')
        self.put('.gitignore', 'private/\n')
        self.put('tracked.md', 'v1\n')
        self.git('add', '.')
        self.git('commit', '-q', '-m', 'base')

    def test_every_kind_of_prospective_file_is_listed(self):
        self.put('tracked.md', 'v2\n')            # modified tracked
        self.put('staged.md', 'x\n')
        self.git('add', 'staged.md')              # staged new file
        self.put('intent.md', 'x\n')
        self.git('add', '--intent-to-add', 'intent.md')
        self.put('untracked.md', 'x\n')           # untracked, not ignored
        self.put('private/secret.md', 'x\n')      # ignored: a commit cannot contain it without -f
        self.assertEqual(git_prospective(self.root), ['intent.md', 'staged.md', 'tracked.md', 'untracked.md'])

    def test_untracked_and_intent_to_add_content_is_inspected(self):
        self.put('untracked.md', f'{FAKE_ID}\n')
        self.put('intent.md', '-----BEGIN ' + 'PRIVATE KEY-----')
        self.git('add', '--intent-to-add', 'intent.md')
        issues = inspect_files(self.root, git_prospective(self.root))
        self.assertTrue(any(i.startswith('untracked.md') for i in issues), issues)
        self.assertTrue(any(i.startswith('intent.md') for i in issues), issues)

    def test_force_added_ignored_file_is_inspected(self):
        self.put('private/leak.jsonl', '{}\n')
        self.git('add', '-f', 'private/leak.jsonl')
        self.assertTrue(inspect_files(self.root, git_prospective(self.root)))

    def test_deleted_file_carries_no_content(self):
        (self.root / 'tracked.md').unlink()
        self.assertEqual(inspect_files(self.root, git_prospective(self.root)), [])


if __name__ == '__main__':
    unittest.main()
