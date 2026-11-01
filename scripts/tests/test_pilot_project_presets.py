# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value
P = load('preset_tests', 'pilot_project_presets.py')
PROFILES = load('preset_profiles_tests', 'pilot_provider_profiles.py')

class StoreBoundaries(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.home = Path(temp.name).resolve() / 'owned'; self.home.mkdir(mode=0o700)
        self.b = {'selection': {'path': '/owned/selection.json', 'sha256': 'a'*64},
                  'commit': 'b'*40, 'tree':'b'*40, 'runtime_profiles_sha256':'c'*64,
                  'workspaces':{k:{'path':'/owned/'+k,'device':1,'inode':2,'uid':os.getuid()}for k in ('filesystem','git')},
                  'snapshot_sha256': 'c'*64,
                  'provider': {'name':'owned', 'version':'d'*32, 'sha256':'e'*64},
                  'budget':None, 'state_root':{'path':'/owned/runs','identity':[1,2,os.getuid()]}}

    def test_empty_inspection_is_inert(self):
        before = list(self.home.iterdir())
        with P.Store(self.home, PROFILES) as store: self.assertEqual(store.read()['records'], {})
        self.assertEqual(list(self.home.iterdir()), before)

    def test_exact_update_and_remove_preserve_sibling_and_frozen_binding(self):
        with P.Store(self.home, PROFILES, create=True) as store:
            a = store.write('create','one',self.b); b = store.write('create','two',self.b)
            before = json.loads(json.dumps(a))
            changed = dict(self.b, snapshot_sha256='f'*64)
            current = store.write('update','one',changed,P.digest(P.encoded(a)))
            self.assertNotEqual(current['version'],a['version']); self.assertEqual(a,before)
            self.assertEqual(store.read()['records']['two'],b)
            with self.assertRaisesRegex(ValueError,'version_stale'):
                store.write('remove','one',expected=P.digest(P.encoded(a)))
            store.write('remove','one',expected=P.digest(P.encoded(current)))
            self.assertEqual(store.read()['records'],{'two':b})

    def test_duplicate_capacity_unsafe_names_and_unknown_schema_refuse(self):
        with P.Store(self.home, PROFILES, create=True) as store:
            for i in range(16): store.write('create','p'+str(i),self.b)
            for name in ('p0','extra'):
                with self.assertRaisesRegex(ValueError,'exists_or_limit'):store.write('create',name,self.b)
            for name in ('../other','UPPER','a b',''):
                with self.assertRaisesRegex(ValueError,'name_invalid'):store.write('create',name,self.b)
        path = self.home/P.DIRECTORY/'catalog.json'; value = json.loads(path.read_bytes());value['extra']=True
        path.write_bytes(P.encoded(value))
        with P.Store(self.home,PROFILES) as store:
            with self.assertRaisesRegex(ValueError,'store_invalid'):store.read()

    def test_missing_linked_hardlinked_and_oversize_catalog_refuse(self):
        with P.Store(self.home,PROFILES,create=True) as store:store.write('create','one',self.b)
        path = self.home/P.DIRECTORY/'catalog.json'; raw = path.read_bytes();path.unlink()
        with P.Store(self.home,PROFILES) as store:
            with self.assertRaisesRegex(ValueError,'catalog_missing'):store.read()
        outside=self.home/'outside';outside.write_bytes(raw);outside.chmod(0o600)
        for kind in ('link','hardlink','large'):
            if kind=='link':path.symlink_to(outside)
            elif kind=='hardlink':os.link(outside,path)
            else:path.write_bytes(b'x'*(P.CAP+1));path.chmod(0o600)
            with P.Store(self.home,PROFILES) as store:
                with self.assertRaisesRegex(ValueError,'private_file_required'):store.read()
            path.unlink()
        self.assertEqual(outside.read_bytes(),raw)

    def test_redirected_parent_refuses_without_touching_other_store(self):
        with P.Store(self.home,PROFILES,create=True) as store:
            store.write('create','one',self.b)
            old=self.home/P.DIRECTORY; moved=self.home/'held';old.rename(moved);old.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError,'store_changed'):store.read()
            self.assertEqual(list(old.iterdir()),[])

    def test_public_catalog_never_contains_provider_material(self):
        marker='owned-untrusted-provider-marker'
        with P.Store(self.home,PROFILES,create=True) as store:store.write('create','one',self.b)
        self.assertNotIn(marker,(self.home/P.DIRECTORY/'catalog.json').read_text())
        damaged=dict(self.b,credential=marker)
        with self.assertRaisesRegex(ValueError,'binding_invalid'):P.validate_binding(damaged)

    def test_explicit_provider_version_does_not_select_or_fall_back(self):
        with PROFILES.Store(self.home,create=True) as provider:
            provider.create('first',{'model':'owned-model'}, {'ANTHROPIC_API_KEY':'owned-fixture-one'})
            provider.update('first',{'model':'owned-v2'},None,'legacy')
            version=provider.index()['profiles']['first']['current']
            _,bound=provider.profile('first',version)
            self.assertIsNone(provider.selected())
        value,ref=P.provider_reference(self.home,'first',version,bound,PROFILES)
        self.assertEqual(value['public']['model'],'owned-v2')
        self.assertEqual(ref,{'name':'first','version':version,'sha256':bound})
        with PROFILES.Store(self.home) as provider:
            self.assertIsNone(provider.selected())
            provider.update('first',{'model':'owned-v3'},None,version)
        with self.assertRaisesRegex(ValueError,'provider_version_changed'):
            P.provider_reference(self.home,'first',version,bound,PROFILES)

    def test_last_input_change_refuses_and_preview_never_spawns(self):
        import types
        import contextlib
        import io
        binding=dict(self.b)
        with P.Store(self.home,PROFILES,create=True) as store:store.write('create','one',binding)
        front=types.SimpleNamespace(PROG='owned', PROJECT_HOME=self.home, provider_profiles=lambda:PROFILES)
        out=io.StringIO()
        with patch.object(P.sys,'platform','linux'), patch.object(P,'snapshot',side_effect=[binding,dict(binding,snapshot_sha256='f'*64)]), \
                patch.object(P.os,'execve',side_effect=AssertionError('execution during check')),contextlib.redirect_stdout(out):
            self.assertEqual(P.main(['check','--name','one'],front),2)
        result=json.loads(out.getvalue());self.assertEqual(result['reason'],'project_inputs_changed')
        self.assertIs(result['executed'],False);self.assertIs(result['authority'],False)

    def test_conflicting_updates_only_one_can_use_a_record_digest(self):
        with P.Store(self.home,PROFILES,create=True) as store:
            old=store.write('create','one',self.b)
        expected=P.digest(P.encoded(old))
        with P.Store(self.home,PROFILES) as first, P.Store(self.home,PROFILES) as second:
            first.write('update','one',self.b,expected)
            with self.assertRaisesRegex(ValueError,'version_stale'):second.write('update','one',self.b,expected)
