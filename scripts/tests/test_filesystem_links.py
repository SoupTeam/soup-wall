# SPDX-License-Identifier: Apache-2.0
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pilot_filesystem_roots as roots
import pilot_filesystem_links as links


@unittest.skipUnless(os.name == 'posix', 'POSIX ownership required')
class Links(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.a, self.b = [self.base / name for name in ('alpha', 'beta')]
        for root in (self.a, self.b):
            root.mkdir(mode=0o700); (root/'note.txt').write_bytes(b'owned exact bytes\n')
        self.pairs = [('alpha', self.a), ('beta', self.b)]

    def test_explicit_profile_chains_and_default_strict(self):
        (self.a/'one').symlink_to('note.txt'); (self.a/'two').symlink_to('one')
        with self.assertRaises(ValueError): roots.inventory(self.pairs)
        value = roots.inventory(self.pairs, internal_file_links=True)
        self.assertEqual(links.FORMAT, value['format'])
        self.assertEqual(2, len(value['links']))
        self.assertEqual(['two','one'], [x['path'] for x in value['links'][1]['chain']])
        self.assertEqual(value, roots.verify(value))
        self.assertEqual(links.PROFILE, roots.profile(value))
        self.assertEqual('filesystem-multi-root-file-links-readonly-v1', roots.profile_id(value))

    def test_cross_root_absolute_directory_missing_cycles_and_bounds_refuse(self):
        for target in ('../beta/note.txt', str(self.b/'note.txt'), 'missing', '.', 'link'):
            link=self.a/'link'; link.symlink_to(target)
            with self.subTest(target=target), self.assertRaises(ValueError): links.inventory(self.pairs)
            link.unlink()
        for i in range(9): (self.a/('x'+str(i))).symlink_to('note.txt' if i==8 else 'x'+str(i+1))
        with self.assertRaisesRegex(ValueError,'chain_bound'): links.inventory(self.pairs)

    def test_ancestor_file_link_and_target_replacement_are_bound(self):
        (self.a/'link').symlink_to('note.txt'); value=links.inventory(self.pairs)
        (self.a/'note.txt').rename(self.a/'old'); (self.a/'note.txt').write_text('replacement')
        with self.assertRaisesRegex(ValueError,'selected_object_changed'): roots.verify(value)
        (self.a/'link').unlink(); (self.a/'link').symlink_to('old')
        with self.assertRaisesRegex(ValueError,'selected_object_changed'): roots.verify(value)
        (self.a/'bad').symlink_to('link/child')
        with self.assertRaises(ValueError): links.inventory(self.pairs)

    def test_cli_opt_in_private_receipt_and_no_implicit_combination(self):
        (self.a/'link').symlink_to('note.txt'); output=self.base/'binding.json'
        words=['--root','alpha='+str(self.a),'--root','beta='+str(self.b),'--internal-file-links','--output',str(output)]
        with contextlib.redirect_stdout(io.StringIO()) as log: roots.main(words)
        self.assertFalse(output.exists()); self.assertFalse(json.loads(log.getvalue())['executed'])
        with contextlib.redirect_stdout(io.StringIO()): roots.main(words+['--apply'])
        self.assertEqual(0o600,output.stat().st_mode&0o777)
        binding=roots.load(output)
        self.assertEqual(links.FORMAT,binding['format'])
        for extra in ('git', 'snapshot', 'extra'):
            changed=dict(binding, **{extra:True})
            with self.assertRaises(ValueError): roots.verify(changed)

    def test_original_registry_pins_and_schemas_are_preserved(self):
        spec=importlib.util.spec_from_file_location('links_installer',Path(__file__).resolve().parents[1]/'install-sou62-filesystem-profile.py')
        installer=importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)
        manifest=json.loads((installer.ASSETS/'upstream-tools-list.json').read_bytes())
        (self.a/'link').symlink_to('note.txt'); binding=links.inventory(self.pairs)
        before, after = installer.registry(manifest), installer.registry(manifest,filesystem_roots=binding)
        for a,b in zip(before['tools'],after['tools']):
            self.assertEqual({k:v for k,v in a.items() if k!='mcp_result_profile'}, {k:v for k,v in b.items() if k!='mcp_result_profile'})
        self.assertEqual(links.PROFILE,next(t['mcp_result_profile'] for t in after['tools'] if t['name']=='read_text_file'))

    def test_bounds_and_no_source_writes(self):
        (self.a/'link').symlink_to('note.txt'); before=(self.a/'note.txt').stat()
        with patch.object(links,'MAX_FILES',0), self.assertRaises(ValueError): links.inventory(self.pairs)
        links.inventory(self.pairs)
        after=(self.a/'note.txt').stat()
        self.assertEqual((before.st_ino,before.st_mtime_ns,before.st_mode),(after.st_ino,after.st_mtime_ns,after.st_mode))

if __name__ == '__main__': unittest.main()
