# SPDX-License-Identifier: Apache-2.0
"""Private archive and atomic catalog boundaries; real launch is qualified natively."""
import argparse
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import stat
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
P = load('project_recovery_presets_tests', 'pilot_project_presets.py')
R = load('project_recovery_tests', 'pilot_project_recovery.py')
PROFILES = load('project_recovery_provider_tests', 'pilot_provider_profiles.py')

@unittest.skipUnless(os.name == 'posix', 'POSIX descriptor/CAS controls; installed qualification is Linux-only')
class Recovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700)
        self.source, self.home = self.root/'source', self.root/'fresh'
        self.source.mkdir(mode=0o700); self.home.mkdir(mode=0o700)
        self.canary = 'owned-provider-secret-SOU230-never-export'
        self.versions = {}
        for home in (self.source, self.home):
            with PROFILES.Store(home, create=True) as provider:
                provider.create('owned', {'model':'owned-initial'}, {'ANTHROPIC_API_KEY':self.canary})
                provider.update('owned', {'model':'owned-current'}, None, 'legacy')
                self.versions[home] = provider.index()['profiles']['owned']['current']
        self.front = types.SimpleNamespace(PROG='owned', PROJECT_HOME=self.home, INSTALLED_HOME=self.home,
            platform_reason=lambda:None, provider_profiles=lambda:PROFILES,
            PREP=types.SimpleNamespace(root_identity=self.root_identity),
            load=lambda name, filename: R if filename=='pilot_project_recovery.py' else load(name, filename))
        self.specs, self.originals = {}, {}
        for name in ('one','two'):
            selection=self.root/(name+'.json');selection.write_text('{}');selection.chmod(0o600)
            for suffix in ('filesystem','git','state'):(self.root/(name+'-'+suffix)).mkdir(mode=0o700)
            spec={'selection':str(selection),'provider_name':'owned','provider_version':self.versions[self.home],
                  'state_root':str(self.root/(name+'-state')),'linux_budget':None,'budget_preset':None}
            self.specs[name]=spec
            original=dict(spec,provider_version=self.versions[self.source])
            binding=self.snapshot(argparse.Namespace(**original,agent_home=self.source),self.front,PROFILES)
            with P.Store(self.source,PROFILES,create=True)as store:self.originals[name]=store.write('create',name,binding)
        self.archive=self.root/'projects.tar';self.bindings=self.root/'bindings.json'
        self.doc=R.document(self.originals,P,PROFILES)
        self.archive.write_bytes(R.archive_bytes(self.doc,P));self.archive.chmod(0o600)
        self.write_bindings()
        self.mock=patch.object(P,'snapshot',side_effect=self.snapshot);self.mock.start();self.addCleanup(self.mock.stop)

    def root_identity(self,path):
        info=Path(path).stat()
        return {'path':str(path),'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid}

    def snapshot(self,args,_front,profiles):
        selection=P.reference(args.selection,profiles)
        name=Path(args.selection).stem
        roots={}
        for kind in ('filesystem','git'):
            path=self.root/(name+'-'+kind);info=path.stat()
            roots[kind]={'path':str(path),'device':info.st_dev,'inode':info.st_ino,'uid':info.st_uid}
        _,provider=P.provider_reference(args.agent_home,args.provider_name,args.provider_version,None,profiles)
        state={'path':str(args.state_root),'identity':P.directory_identity(args.state_root,profiles)}
        return {'selection':selection,'commit':'a'*40,'tree':'b'*40,'workspaces':roots,
                'runtime_profiles_sha256':'c'*64,'snapshot_sha256':P.digest(P.encoded([selection,roots])),
                'provider':provider,'budget':None if args.linux_budget is None else P.reference(args.linux_budget,profiles),
                'state_root':state}

    def write_bindings(self):
        self.bindings.write_bytes(P.encoded({'format':R.BINDINGS,'projects':self.specs}));self.bindings.chmod(0o600)

    def preview(self):
        return R.preview(self.archive,self.bindings,self.home,self.front,PROFILES,P)[0]

    def apply(self,token,recovery=False):
        return R.apply(self.archive,self.bindings,self.home,token,self.front,PROFILES,P,recovery=recovery)

    def catalog(self):
        with P.Store(self.home,PROFILES)as store:return store.read()

    def baseline(self):
        return {str(p.relative_to(self.root)):(p.stat().st_mode&0o777,p.read_bytes())
                for p in self.root.rglob('*')if p.is_file()and not p.is_symlink()}

    def test_project_catalog_uses_its_declared_cap_without_changing_provider_limits(self):
        binding=copy.deepcopy(self.originals['one']['binding'])
        binding['selection']['path']='/'+'x'*3000
        with P.Store(self.home,PROFILES,create=True)as store:
            for i in range(16):store.write('create','p'+str(i),binding)
            raw=(self.home/P.DIRECTORY/'catalog.json').read_bytes()
            self.assertGreater(len(raw),PROFILES.MAX_FILE);self.assertLess(len(raw),P.CAP)
            self.assertEqual(len(store.read()['records']),16)
        with self.assertRaises(ValueError):PROFILES.strict(raw)

    def test_archive_contains_only_declarations_and_fixed_identity_metadata(self):
        doc,_=R.load_archive(self.archive,PROFILES,P)
        self.assertEqual(doc,self.doc)
        with tarfile.open(self.archive,mode='r:')as archive:self.assertEqual(archive.getnames(),list(R.MEMBERS))
        self.assertNotIn(self.canary.encode(),self.archive.read_bytes())
        for excluded in ('credentials','grants','approvals','run-and-session-state','workspace-contents'):
            self.assertIn(excluded,doc['excluded'])
        forged=copy.deepcopy(self.doc);forged['records']['one']['binding']['credential']=self.canary
        self.archive.write_bytes(R.archive_bytes(forged,P))
        with self.assertRaises(ValueError):R.load_archive(self.archive,PROFILES,P)

    def test_preview_without_explicit_bindings_remains_unapplied_and_inert(self):
        before=self.baseline()
        with patch.object(subprocess,'run',side_effect=AssertionError('child')),patch.object(os,'mkdir',side_effect=AssertionError('mkdir')):
            shown,_=R.preview(self.archive,None,self.home,self.front,PROFILES,P)
        self.assertFalse(shown['ready']);self.assertEqual(shown['write_attempts'],0)
        self.assertTrue(all(not row['resolved']and not row['explicit_binding']for row in shown['projects']))
        self.assertEqual(before,self.baseline());self.assertFalse((self.home/P.DIRECTORY).exists())

    def test_two_records_merge_atomically_with_fresh_versions_and_existing_entry_unchanged(self):
        with P.Store(self.home,PROFILES,create=True)as store:kept=store.write('create','kept',self.originals['one']['binding'])
        token=self.preview()['plan_sha256'];result=self.apply(token)
        self.assertEqual(result['status'],'imported');self.assertFalse(result['authority']);self.assertFalse(result['executed'])
        actual=self.catalog()['records'];self.assertEqual(actual['kept'],kept)
        for name in ('one','two'):
            self.assertNotEqual(actual[name]['version'],self.originals[name]['version'])
            P.verify(actual[name]['binding'],self.home,self.front,PROFILES)
        self.assertEqual(len(set(r['version']for r in actual.values())),3)
        with self.assertRaises(ValueError):self.apply(token)
        self.assertEqual(self.catalog()['records'],actual)

    def test_duplicate_and_conflicting_names_are_explicit_and_never_overwritten(self):
        with P.Store(self.home,PROFILES,create=True)as store:
            before=store.write('create','one',self.originals['one']['binding'])
        shown=self.preview();self.assertFalse(shown['ready']);self.assertEqual(shown['projects'][0]['conflict'],'duplicate')
        with self.assertRaises(ValueError):self.apply(shown['plan_sha256'])
        self.assertEqual(self.catalog()['records'],{'one':before})
        with P.Store(self.home,PROFILES)as store:
            changed=store.write('update','one',self.originals['two']['binding'],P.digest(P.encoded(before)))
        self.assertEqual(self.preview()['projects'][0]['conflict'],'name_conflict')
        self.assertEqual(self.catalog()['records']['one'],changed)

    def test_capacity_and_unresolved_inputs_refuse_without_partial_records(self):
        with P.Store(self.home,PROFILES,create=True)as store:
            for i in range(15):store.write('create','p'+str(i),self.originals['one']['binding'])
        shown=self.preview();self.assertFalse(shown['capacity_available'])
        with self.assertRaises(ValueError):self.apply(shown['plan_sha256'])
        self.assertEqual(len(self.catalog()['records']),15)
        self.specs.pop('two');self.write_bindings();shown=self.preview()
        self.assertFalse(shown['ready']);self.assertFalse(shown['projects'][1]['resolved'])

    def test_stale_confirmation_archive_and_binding_changes_have_zero_catalog_effects(self):
        token=self.preview()['plan_sha256']
        with self.assertRaises(ValueError):self.apply('0'*64)
        self.assertFalse((self.home/P.DIRECTORY).exists())
        # Valid bytes replaced by a distinct inode still invalidate the reviewed input.
        replacement=self.root/'replacement';replacement.write_bytes(self.archive.read_bytes());replacement.chmod(0o600)
        os.replace(replacement,self.archive)
        with self.assertRaises(ValueError):self.apply(token)
        token=self.preview()['plan_sha256'];self.bindings.write_bytes(self.bindings.read_bytes()+b' ')
        with self.assertRaises(ValueError):self.apply(token)
        self.assertFalse((self.home/P.DIRECTORY).exists())

    def test_changed_selection_provider_budget_workspace_and_state_are_diagnosed(self):
        shown=self.preview();self.assertTrue(shown['ready'])
        self.assertEqual(shown['projects'][0]['inputs']['provider'],'changed')
        selection=Path(self.specs['one']['selection']);selection.write_text('{"changed":true}')
        shown=self.preview();self.assertEqual(shown['projects'][0]['inputs']['selection'],'changed')
        state=Path(self.specs['one']['state_root']);held=state.with_name('held-state');state.rename(held);state.mkdir(mode=0o700)
        shown=self.preview();self.assertEqual(shown['projects'][0]['inputs']['state_root'],'changed')
        workspace=self.root/'one-filesystem';workspace.rename(self.root/'held-filesystem');workspace.mkdir(mode=0o700)
        self.assertEqual(self.preview()['projects'][0]['inputs']['workspaces'],'changed')
        self.specs['one']['linux_budget']=str(self.root/'missing-budget');self.write_bindings()
        shown=self.preview();self.assertEqual(shown['projects'][0]['inputs']['budget'],'unavailable');self.assertFalse(shown['ready'])
        with PROFILES.Store(self.home)as provider:
            provider.update('owned',{'model':'rotated'},None,self.versions[self.home])
        shown=self.preview();self.assertFalse(shown['ready']);self.assertEqual(shown['projects'][0]['inputs']['provider'],'unavailable')

    def test_changed_catalog_and_substituted_destination_invalidate_plan(self):
        token=self.preview()['plan_sha256']
        with P.Store(self.home,PROFILES,create=True)as store:kept=store.write('create','kept',self.originals['one']['binding'])
        with self.assertRaises(ValueError):self.apply(token)
        self.assertEqual(self.catalog()['records'],{'kept':kept})
        token=self.preview()['plan_sha256'];old=self.home/'held-store';(self.home/P.DIRECTORY).rename(old)
        (self.home/P.DIRECTORY).mkdir(mode=0o700)
        target=self.home/P.DIRECTORY/'catalog.json';target.write_bytes((old/'catalog.json').read_bytes());target.chmod(0o600)
        with self.assertRaises(ValueError):self.apply(token)
        self.assertEqual(target.read_bytes(),(old/'catalog.json').read_bytes())

    def test_renamed_destination_home_needs_a_new_plan(self):
        token=self.preview()['plan_sha256'];renamed=self.root/'renamed-home'
        self.home.rename(renamed);self.home=renamed;self.front.PROJECT_HOME=renamed
        with self.assertRaises(ValueError):self.apply(token)
        self.assertFalse((self.home/P.DIRECTORY).exists())

    def test_catalog_change_at_publication_boundary_is_preserved(self):
        with P.Store(self.home,PROFILES,create=True)as store:
            original=store.write('create','kept',self.originals['one']['binding'])
        token=self.preview()['plan_sha256'];path=self.home/P.DIRECTORY/'catalog.json'
        def concurrent(point):
            if point=='before_publication':
                value=json.loads(path.read_bytes());value['records']['kept']['version']='f'*32
                path.write_bytes(P.encoded(value))
        with patch.object(R,'fault',side_effect=concurrent):result=self.apply(token)
        self.assertEqual(result['status'],'incomplete')
        self.assertEqual(set(json.loads(path.read_bytes())['records']),{'kept'})
        self.assertNotEqual(json.loads(path.read_bytes())['records']['kept'],original)
        with self.assertRaises(ValueError):self.apply(token,recovery=True)

    def test_changed_input_at_last_check_retains_original_catalog_and_stage(self):
        token=self.preview()['plan_sha256']
        def changed(point):
            if point=='before_publication':Path(self.specs['one']['selection']).write_text('{"changed":true}')
        with patch.object(R,'fault',side_effect=changed):result=self.apply(token)
        self.assertEqual(result['status'],'incomplete')
        self.assertFalse((self.home/P.DIRECTORY/'catalog.json').exists())
        self.assertTrue((self.home/P.DIRECTORY/('.import-next-'+token)).is_file())
        with self.assertRaises(ValueError):self.apply(token,recovery=True)

    def test_interruptions_before_and_after_publication_recover_with_same_plan(self):
        for point in ('stage_published','before_publication','after_publication'):
            with self.subTest(point=point):
                self.home=self.root/('recover-'+point);self.home.mkdir(mode=0o700)
                # Keep provider input resolution deliberately at the existing home;
                # native qualification covers freshly supplied destination providers.
                with PROFILES.Store(self.home,create=True)as provider:
                    provider.create('owned',{'model':'owned-initial'},{'ANTHROPIC_API_KEY':self.canary})
                    provider.update('owned',{'model':'owned-current'},None,'legacy')
                    version=provider.index()['profiles']['owned']['current']
                for spec in self.specs.values():spec['provider_version']=version
                self.write_bindings();self.front.PROJECT_HOME=self.home
                token=self.preview()['plan_sha256']
                def interrupted(selected):
                    if selected==point:raise OSError('owned interruption')
                with patch.object(R,'fault',side_effect=interrupted):result=self.apply(token)
                self.assertEqual(result['status'],'incomplete')
                exists=(self.home/P.DIRECTORY/'catalog.json').exists()
                self.assertEqual(exists,point=='after_publication')
                result=self.apply(token,recovery=True);self.assertEqual(result['status'],'imported');self.assertTrue(result['recovered'])
                self.assertEqual(set(self.catalog()['records']),{'one','two'})
                self.assertEqual([p.name for p in (self.home/P.DIRECTORY).iterdir()],['catalog.json'])

    def test_concurrent_import_conflict_keeps_one_atomic_result(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        token=self.preview()['plan_sha256'];staged=threading.Event();release=threading.Event()
        def pause(point):
            if point=='stage_published':
                staged.set();self.assertTrue(release.wait(5))
        with ThreadPoolExecutor(max_workers=1)as pool,patch.object(R,'fault',side_effect=pause):
            first=pool.submit(self.apply,token)
            try:
                self.assertTrue(staged.wait(5))
                with self.assertRaises((ValueError,BlockingIOError)):self.apply(token)
            finally:release.set()
            self.assertEqual(first.result(timeout=5)['status'],'imported')
        self.assertEqual(set(self.catalog()['records']),{'one','two'})

    def test_tampering_stage_at_final_boundary_never_publishes_it(self):
        token=self.preview()['plan_sha256'];stage=self.home/P.DIRECTORY/('.import-next-'+token)
        def tamper(point):
            if point=='before_publication':stage.write_bytes(stage.read_bytes()+b' ')
        with patch.object(R,'fault',side_effect=tamper):self.assertEqual(self.apply(token)['status'],'incomplete')
        self.assertFalse((stage.parent/'catalog.json').exists());self.assertTrue(stage.exists())

    def test_tampered_interrupted_stage_is_retained_without_publication(self):
        token=self.preview()['plan_sha256']
        with patch.object(R,'fault',side_effect=OSError('interrupt')):self.assertEqual(self.apply(token)['status'],'incomplete')
        stage=self.home/P.DIRECTORY/('.import-next-'+token);stage.write_bytes(stage.read_bytes()+b' ')
        before=stage.read_bytes()
        with self.assertRaisesRegex(ValueError,'recovery_stage_changed'):self.apply(token,recovery=True)
        self.assertEqual(stage.read_bytes(),before);self.assertFalse((stage.parent/'catalog.json').exists())

    def test_linked_archives_bindings_and_retained_stages_refuse(self):
        raw=self.archive.read_bytes();other=self.root/'archive-original';self.archive.rename(other);self.archive.symlink_to(other)
        with self.assertRaises(ValueError):self.preview()
        self.archive.unlink();self.archive.write_bytes(raw);self.archive.chmod(0o600)
        token=self.preview()['plan_sha256']
        with patch.object(R,'fault',side_effect=OSError('interrupt')):self.apply(token)
        stage=self.home/P.DIRECTORY/('.import-next-'+token);held=self.root/'held-stage';stage.rename(held);stage.symlink_to(held)
        with self.assertRaises(ValueError):self.apply(token,recovery=True)
        self.assertEqual(held.read_bytes(),R.new_catalog({'format':P.FORMAT,'records':{}},R.inputs(self.archive,self.bindings,self.home,self.front,PROFILES,P)[0],token,self.doc,P)[1])

    def test_oversized_traversal_links_duplicate_members_and_trailing_data_refuse(self):
        original=self.archive.read_bytes()
        variants=[original+b'x'*512,b'x'*(R.MAX_ARCHIVE+1)]
        for name,kind in (('../escape',tarfile.REGTYPE),('manifest.json',tarfile.SYMTYPE),('manifest.json',tarfile.LNKTYPE)):
            out=io.BytesIO()
            with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT)as archive:
                member=tarfile.TarInfo(name);member.type=kind;member.mode=0o600
                if kind==tarfile.REGTYPE:member.size=2;archive.addfile(member,io.BytesIO(b'{}'))
                else:member.linkname='/owned/never';archive.addfile(member)
            variants.append(out.getvalue())
        for raw in variants:
            self.archive.write_bytes(raw)
            with self.assertRaises((ValueError,tarfile.TarError)):R.load_archive(self.archive,PROFILES,P)
        self.assertFalse((self.root/'escape').exists())

    def test_export_requires_consent_before_writes_and_refuses_workspace_destination(self):
        with self.assertRaisesRegex(ValueError,'consent_required'):
            R.export(self.source,self.root/'out.tar',False,self.front,PROFILES,P)
        target=Path(self.originals['one']['binding']['workspaces']['filesystem']['path'])/'out.tar'
        with self.assertRaisesRegex(ValueError,'overlaps_preserved_state'):
            R.export(self.source,target,True,self.front,PROFILES,P)
        self.assertFalse(target.exists())

    def export_fixture(self):
        selections=self.root/'export-selections';selections.mkdir(mode=0o700)
        with P.Store(self.source,PROFILES)as store:
            for name,record in list(self.originals.items()):
                selected=selections/(name+'.json');selected.write_text('{}');selected.chmod(0o600)
                binding=copy.deepcopy(record['binding']);binding['selection']=P.reference(selected,PROFILES)
                self.originals[name]=store.write('update',name,binding,P.digest(P.encoded(record)))
        outside=self.root/'outside';outside.mkdir(mode=0o700)
        (outside/'private').mkdir(mode=0o700)
        with patch.object(sys,'path',[str(ROOT/'scripts'),*sys.path]):
            exchange=load('project_export_destination_exchange_tests','pilot_prerequisite_cache_exchange.py')
        original=self.front.load
        self.front.load=lambda name,filename:exchange if filename=='pilot_prerequisite_cache_exchange.py'else original(name,filename)
        return outside,exchange

    def test_export_rejects_symlink_ancestors_for_every_preserved_root(self):
        outside,_=self.export_fixture()
        roots={self.source}
        for record in self.originals.values():
            binding=record['binding']
            roots.update((Path(binding['selection']['path']).parent,Path(binding['state_root']['path'])))
            roots.update(Path(root['path'])for root in binding['workspaces'].values())
        before=self.baseline()
        for number,root in enumerate(sorted(roots)):
            with self.subTest(root=root.name):
                private=root/'private-export-control';private.mkdir(mode=0o700)
                alias=outside/('alias-'+str(number));alias.symlink_to(root,target_is_directory=True)
                try:
                    with self.assertRaisesRegex(ValueError,'canonical_directory_required'):
                        R.export(self.source,alias/private.name/'refused.tar',True,self.front,PROFILES,P)
                    self.assertFalse((private/'refused.tar').exists())
                finally:
                    alias.unlink()
                    if not any(private.iterdir()):private.rmdir()
        self.assertEqual(before,self.baseline())

    def test_export_rejects_alias_even_when_its_real_parent_is_outside_preserved_state(self):
        outside,_=self.export_fixture();alias=self.root/'allowed-alias'
        alias.symlink_to(outside,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'canonical_directory_required'):
            R.export(self.source,alias/'private'/'refused.tar',True,self.front,PROFILES,P)
        self.assertFalse((outside/'private'/'refused.tar').exists())

    @unittest.skipUnless(sys.platform.startswith('linux')and hasattr(os,'O_TMPFILE'),'real Linux private publication')
    def test_export_publishes_only_a_new_canonical_private_archive(self):
        outside,exchange=self.export_fixture();archive=outside/'private'/'out.tar'
        result=R.export(self.source,archive,True,self.front,PROFILES,P)
        self.assertEqual(result['status'],'exported');self.assertEqual(result['records'],2)
        self.assertEqual(stat.S_IMODE(archive.stat().st_mode),0o600)
        self.assertEqual(archive.stat().st_nlink,1)
        document,_=R.load_archive(archive,PROFILES,P)
        self.assertEqual(document['records'],self.originals);self.assertNotIn(self.canary.encode(),archive.read_bytes())
        before=archive.read_bytes()
        with self.assertRaisesRegex(exchange.Refusal,'destination_exists'):
            R.export(self.source,archive,True,self.front,PROFILES,P)
        self.assertEqual(archive.read_bytes(),before)

    @unittest.skipUnless(sys.platform.startswith('linux')and hasattr(os,'O_TMPFILE'),'real Linux private publication')
    def test_export_rejects_ancestor_redirect_before_publisher_opens_the_directory(self):
        outside,exchange=self.export_fixture();held=self.root/'held-outside'
        workspace=Path(self.originals['one']['binding']['workspaces']['filesystem']['path'])
        (workspace/'private').mkdir(mode=0o700)
        opening=exchange._private_dir_fd
        def redirected(path):
            outside.rename(held);outside.symlink_to(workspace,target_is_directory=True)
            return opening(path)
        before=(self.source/P.DIRECTORY/'catalog.json').read_bytes()
        with patch.object(exchange,'_private_dir_fd',side_effect=redirected):
            with self.assertRaisesRegex(ValueError,'canonical_directory_required'):
                R.export(self.source,outside/'private'/'refused.tar',True,self.front,PROFILES,P)
        self.assertFalse((workspace/'private'/'refused.tar').exists())
        self.assertFalse((held/'private'/'refused.tar').exists())
        self.assertEqual((self.source/P.DIRECTORY/'catalog.json').read_bytes(),before)

    @unittest.skipUnless(sys.platform.startswith('linux')and hasattr(os,'O_TMPFILE'),'real Linux private publication')
    def test_export_rechecks_ancestor_binding_at_publication_even_when_the_leaf_inode_is_unchanged(self):
        outside,exchange=self.export_fixture()
        workspace=Path(self.originals['one']['binding']['workspaces']['filesystem']['path'])
        moved=workspace/'moved-export';sync=os.fsync;changed=False
        before=(self.source/P.DIRECTORY/'catalog.json').read_bytes()
        def redirected(fd):
            nonlocal changed
            sync(fd)
            if not changed and stat.S_ISREG(os.fstat(fd).st_mode):
                changed=True;outside.rename(moved);outside.symlink_to(moved,target_is_directory=True)
        with patch.object(exchange.os,'fsync',side_effect=redirected):
            with self.assertRaisesRegex(ValueError,'canonical_directory_required'):
                R.export(self.source,outside/'private'/'refused.tar',True,self.front,PROFILES,P)
        self.assertTrue(changed)
        self.assertFalse((moved/'private'/'refused.tar').exists())
        self.assertEqual((self.source/P.DIRECTORY/'catalog.json').read_bytes(),before)

    @unittest.skipUnless(sys.platform.startswith('linux')and hasattr(os,'O_TMPFILE'),'real Linux private publication')
    def test_export_rejects_replaced_private_directory_before_publication(self):
        outside,exchange=self.export_fixture();parent=outside/'private';held=outside/'held-private'
        sync=os.fsync;changed=False
        def replaced(fd):
            nonlocal changed
            sync(fd)
            if not changed and stat.S_ISREG(os.fstat(fd).st_mode):
                changed=True;parent.rename(held);parent.mkdir(mode=0o700)
        with patch.object(exchange.os,'fsync',side_effect=replaced):
            with self.assertRaisesRegex(exchange.Refusal,'directory_changed'):
                R.export(self.source,parent/'refused.tar',True,self.front,PROFILES,P)
        self.assertTrue(changed)
        self.assertFalse((parent/'refused.tar').exists());self.assertFalse((held/'refused.tar').exists())

    def test_dispatch_apply_requires_both_current_plan_and_explicit_apply(self):
        import contextlib
        token=self.preview()['plan_sha256'];out=io.StringIO()
        with contextlib.redirect_stdout(out):
            code=P.main(['import','--archive',str(self.archive),'--bindings',str(self.bindings),'--confirm-plan',token],self.front)
        self.assertEqual(code,2);self.assertEqual(json.loads(out.getvalue())['reason'],'project_import_apply_required')
        self.assertFalse((self.home/P.DIRECTORY).exists())

if __name__=='__main__':unittest.main()
