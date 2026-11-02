# SPDX-License-Identifier: Apache-2.0
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pilot_workspace_snapshot as M


@unittest.skipUnless(os.name=='posix','POSIX descriptors required')
class Snapshot(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name).resolve()
        self.source=self.base/'source';self.source.mkdir(mode=0o700)
        (self.source/'README.md').write_bytes(b'owned snapshot bytes\n')
        (self.source/'nested').mkdir();(self.source/'nested'/'note.txt').write_bytes('owned café\n'.encode())
        self.dest=self.base/'snapshot'
    def tearDown(self):
        for path,_,_ in os.walk(self.base,followlinks=False):os.chmod(path,0o700)
        self.tmp.cleanup()
    def confirmation(self):return M.preview(self.source,self.dest)['confirmation']
    def made(self):
        value=M.create(self.source,self.dest,self.confirmation())
        self.assertEqual('complete-snapshot',value['status']);return value

    def test_preview_is_metadata_only_and_zero_effect(self):
        read=os.read
        def no_content(fd,n):
            self.assertFalse(stat.S_ISREG(os.fstat(fd).st_mode),'preview read file content')
            return read(fd,n)
        before={str(p):p.lstat() for p in [self.source,*self.source.rglob('*')]}
        with patch.object(M.os,'read',side_effect=no_content):value=M.preview(self.source,self.dest)
        self.assertEqual(2,value['files']);self.assertEqual(2,value['directories'])
        self.assertFalse(value['content_copied']);self.assertFalse(self.dest.exists())
        self.assertEqual(64,len(value['confirmation']))
        self.assertEqual({k:(m.st_ino,m.st_mtime_ns,m.st_mode) for k,m in before.items()},
                         {k:(Path(k).lstat().st_ino,Path(k).lstat().st_mtime_ns,Path(k).lstat().st_mode) for k in before})

    def test_links_hardlinks_special_shared_write_and_installation_state_refuse(self):
        link=self.source/'alias';link.symlink_to('README.md')
        with self.assertRaises(ValueError):M.preview(self.source,self.dest)
        link.unlink();os.link(self.source/'README.md',link)
        with self.assertRaises(ValueError):M.preview(self.source,self.dest)
        link.unlink();os.mkfifo(link)
        with self.assertRaises(ValueError):M.preview(self.source,self.dest)
        link.unlink();(self.source/'README.md').chmod(0o666)
        with self.assertRaises(ValueError):M.preview(self.source,self.dest)
        (self.source/'README.md').chmod(0o600);(self.source/'selection.json').write_text('{}')
        with self.assertRaises(ValueError):M.preview(self.source,self.dest)

    def test_canonical_scope_protected_roots_and_finite_bounds(self):
        alias=self.base/'alias';alias.symlink_to(self.source,target_is_directory=True)
        with self.assertRaises(ValueError):M.preview(alias,self.dest)
        for dest,protected in [(self.source/'copy',()),(self.dest,[self.base]),(self.base/'nested'/'copy',())]:
            with self.assertRaises((OSError,ValueError)):M.preview(self.source,dest,protected)
        for name in ('MAX_FILES','MAX_BYTES','MAX_DEPTH','MAX_ENTRIES'):
            with patch.object(M,name,0),self.assertRaises(ValueError):M.preview(self.source,self.dest)

    def test_retained_source_descriptor_substitution_refuses(self):
        with M.Capture(self.source) as source:
            (self.source/'README.md').rename(self.source/'retained')
            (self.source/'README.md').write_text('replacement')
            with self.assertRaises(ValueError):source.check()
        with M.Capture(self.source) as source:
            self.source.rename(self.base/'old-source');self.source.mkdir(mode=0o700)
            with self.assertRaises(ValueError):source.check()

    @unittest.skipUnless(sys.platform=='linux','real Linux publication and inotify required')
    def test_complete_private_snapshot_stays_stable_and_never_claims_live(self):
        value=self.made();binding=value['binding']
        self.assertEqual(0o700,self.dest.stat().st_mode&0o777)
        self.assertEqual(0o500,(self.dest/'workspace').stat().st_mode&0o777)
        self.assertEqual(0o400,(self.dest/'workspace'/'README.md').stat().st_mode&0o777)
        original=(self.dest/'workspace'/'README.md').read_bytes()
        (self.source/'README.md').write_text('source changed after capture')
        changed=M.inspect(self.dest)
        self.assertEqual('changed-since-capture',changed['current_source'])
        self.assertEqual(original,(self.dest/'workspace'/'README.md').read_bytes())
        self.assertEqual(binding,M.load(self.dest));self.assertIn('snapshot',changed['view'])
        M.remove(self.dest,changed['removal_confirmation'])
        self.assertFalse(self.dest.exists());self.assertEqual('source changed after capture',(self.source/'README.md').read_text())

    @unittest.skipUnless(sys.platform=='linux','Linux ancestor observer')
    def test_temporary_ancestor_move_and_restore_is_sticky(self):
        container=self.base/'container';container.mkdir(mode=0o700)
        nested=container/'source';nested.mkdir(mode=0o700);(nested/'note').write_text('owned')
        with M.Capture(nested) as capture:
            moved=self.base/'moved-container';container.rename(moved);moved.rename(container)
            with self.assertRaisesRegex(ValueError,'source_changed_during_capture'):capture.check()

    @unittest.skipUnless(sys.platform=='linux','Linux publication')
    def test_exact_confirmation_low_space_and_capture_change_never_publish(self):
        with self.assertRaisesRegex(ValueError,'exact_confirmation'):M.create(self.source,self.dest,'a'*64)
        with patch.object(M.os,'fstatvfs',return_value=SimpleNamespace(f_bavail=0,f_frsize=4096)),self.assertRaisesRegex(ValueError,'insufficient_space'):
            M.create(self.source,self.dest,self.confirmation())
        self.assertFalse(self.dest.exists());self.assertFalse(list(self.base.glob('.snapshot-*')))
        confirmation=self.confirmation();read=os.read;mutated=False
        def changed(fd,n):
            nonlocal mutated
            block=read(fd,n)
            if not mutated and os.readlink('/proc/self/fd/'+str(fd))==str(self.source/'README.md'):
                mutated=True;(self.source/'README.md').write_text('concurrent change')
            return block
        with patch.object(M.os,'read',side_effect=changed),self.assertRaises(ValueError):M.create(self.source,self.dest,confirmation)
        self.assertTrue(mutated);self.assertFalse(self.dest.exists());self.assertFalse(list(self.base.glob('.snapshot-*')))

    @unittest.skipUnless(sys.platform=='linux','Linux exclusive rename')
    def test_publication_collision_never_deletes_existing_winner(self):
        rename=M.publish
        def collision(parent,temporary,destination):
            self.dest.mkdir(mode=0o700);(self.dest/'winner').write_text('existing winner')
            rename(parent,temporary,destination)
        with patch.object(M,'publish',side_effect=collision),self.assertRaises(OSError):
            M.create(self.source,self.dest,self.confirmation())
        self.assertEqual('existing winner',(self.dest/'winner').read_text());self.assertFalse(list(self.base.glob('.snapshot-*')))

    @unittest.skipUnless(sys.platform=='linux','Linux runtime lease')
    def test_in_use_removal_refuses_and_incomplete_or_modified_content_is_unselectable(self):
        value=self.made()
        with M.hold(value['binding']),self.assertRaisesRegex(ValueError,'in_use'):
            M.remove(self.dest,value['removal_confirmation'])
        self.assertTrue(self.dest.exists())
        (self.dest/'complete.json').unlink()
        with self.assertRaisesRegex(ValueError,'incomplete_generation'):M.load(self.dest)
        self.assertTrue(self.dest.exists())

    @unittest.skipUnless(sys.platform=='linux','Linux capture')
    def test_snapshot_tamper_and_credential_material_refuse(self):
        (self.source/'README.md').write_text('owned synthetic marker sk-ant-api'+'x'*30)
        with self.assertRaisesRegex(ValueError,'credential_material'):M.create(self.source,self.dest,self.confirmation())
        self.assertFalse(self.dest.exists());self.assertFalse(list(self.base.glob('.snapshot-*')))
        (self.source/'README.md').write_text('ordinary owned content');self.made()
        file=self.dest/'workspace'/'README.md';size=file.stat().st_size
        file.chmod(0o600);file.write_bytes(b'X'*size);file.chmod(0o400)
        with self.assertRaisesRegex(ValueError,'content_changed'):M.load(self.dest)

    def test_new_profile_combinations_refuse_before_preparation_effects(self):
        spec=importlib.util.spec_from_file_location('snapshot_preparation',Path(__file__).resolve().parents[1]/'prepare-installed-pilot.py')
        prep=importlib.util.module_from_spec(spec);spec.loader.exec_module(prep)
        for requested,fs_roots,profile in [(None,None,prep.GIT_PROFILES.DEFAULT),({}, {},prep.GIT_PROFILES.DEFAULT),({},None,'git-readonly-local-refs-v1')]:
            with self.assertRaisesRegex(ValueError,'combination_unsupported'):
                prep.requested_snapshot(SimpleNamespace(workspace_snapshot=self.dest,git_profile=profile),requested,fs_roots)

if __name__=='__main__':unittest.main()
