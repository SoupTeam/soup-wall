# SPDX-License-Identifier: Apache-2.0
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('filesystem_roots', Path(__file__).resolve().parents[1] / 'pilot_filesystem_roots.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


@unittest.skipUnless(os.name == 'posix', 'POSIX descriptor ownership required')
class Roots(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.a, self.b, self.c = [self.base / name for name in ('alpha', 'beta', 'canary')]
        for root in (self.a, self.b, self.c):
            root.mkdir(mode=0o700)
            (root / 'note.txt').write_text(root.name)
        self.pairs = [('beta', self.b), ('alpha', self.a)]

    def test_qualification_refusal_witness_retains_hyphenated_codes(self):
        path = Path(__file__).resolve().parents[1] / 'qualify-filesystem-roots.py'
        spec = importlib.util.spec_from_file_location('filesystem_roots_qualification', path)
        qualification = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(qualification)
        message = json.dumps([{'type': 'text', 'text':
            'Soup Wall withheld MCP invocation (taint-history-incomplete, native_approval_cancelled)'}])
        self.assertEqual(['native_approval_cancelled', 'taint-history-incomplete'],
                         qualification.reported_refusal_codes(message))
        self.assertEqual([], qualification.reported_refusal_codes(
            'Soup Wall withheld MCP invocation (arbitrary untrusted prose)'))
        self.assertLessEqual(len(qualification.reported_refusal_codes(' '.join(
            'native_reason_' + str(i) for i in range(100)))), 16)

    def test_two_through_four_explicit_sorted_root_identities(self):
        value = M.inventory(self.pairs)
        self.assertEqual(['alpha', 'beta'], [r['id'] for r in value['roots']])
        self.assertEqual(['/workspace/alpha', '/workspace/beta'], M.arguments(value))
        self.assertEqual(value, M.verify(value, self.a))
        self.assertEqual('read-only', value['roots'][1]['scope'])
        self.assertNotIn(str(self.c), json.dumps(value))
        d = self.base / 'four'; d.mkdir()
        self.assertEqual(4, len(M.inventory(self.pairs + [('third', self.c), ('fourth', d)])['roots']))

    def test_explicit_inventory_never_modifies_any_root(self):
        before = {str(p): (p.read_bytes(), p.stat()) for root in (self.a,self.b,self.c) for p in root.iterdir()}
        M.inventory(self.pairs)
        for name, (raw, metadata) in before.items():
            path = Path(name)
            self.assertEqual(raw, path.read_bytes())
            self.assertEqual(metadata.st_mtime_ns, path.stat().st_mtime_ns)
            self.assertEqual(metadata.st_mode, path.stat().st_mode)

    def test_duplicate_ids_identity_overlap_and_extra_roots_refuse(self):
        for pairs in ([('one',self.a)], self.pairs + [('alpha',self.c)],
                      self.pairs + [('alias',self.a)], [('a',self.a),('b',self.a/'nested')],
                      self.pairs + [('c'+str(i),self.c) for i in range(3)]):
            (self.a/'nested').mkdir(exist_ok=True)
            with self.assertRaises(ValueError): M.inventory(pairs)

    def test_stale_missing_or_replaced_root_never_transfers_binding(self):
        value = M.inventory(self.pairs)
        self.b.rename(self.base/'old-beta')
        with self.assertRaises(FileNotFoundError): M.verify(value)
        self.b.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'selected_root_changed'): M.verify(value)

    def test_symlink_alias_and_unselected_escape_refuse(self):
        alias = self.base/'alias'; alias.symlink_to(self.a, target_is_directory=True)
        with self.assertRaises(ValueError): M.inventory([('a',alias),('b',self.b)])
        (self.a/'escape').symlink_to(self.c, target_is_directory=True)
        with self.assertRaises(ValueError): M.inventory(self.pairs)
        self.assertEqual('canary', (self.c/'note.txt').read_text())

    def test_shared_write_hardlink_and_special_file_refuse(self):
        file = self.a/'note.txt'; file.chmod(0o666)
        with self.assertRaises(ValueError): M.inventory(self.pairs)
        file.chmod(0o600)
        os.link(file, self.c/'alias')
        with self.assertRaises(ValueError): M.inventory(self.pairs)
        (self.c/'alias').unlink()
        os.mkfifo(self.a/'fifo')
        with self.assertRaises(ValueError): M.inventory(self.pairs)

    def test_schema_scope_unknown_duplicate_and_cross_profile_refuse(self):
        original = M.inventory(self.pairs)
        for mutate in (lambda x:x.update(extra=True), lambda x:x.update(format='sw-pilot-linked-worktree/1'),
                       lambda x:x['roots'][0].update(scope='read-write'),
                       lambda x:x['roots'][0]['identity'].update(uid=True),
                       lambda x:x['roots'].reverse()):
            value=copy.deepcopy(original); mutate(value)
            with self.assertRaises(ValueError): M.verify(value)
        with self.assertRaises(ValueError): M.strict('{"format":1,"format":2}')
        with self.assertRaises(ValueError): M.verify(original,self.b)

    def test_every_root_excludes_runtime_cache_and_output(self):
        value=M.inventory(self.pairs)
        for path in (self.a/'cache',self.b/'state',self.base):
            with self.assertRaises(ValueError): M.outside([path],value)
        M.outside([self.c/'private',None],value)

    def test_preview_is_inert_apply_is_private_create_new_and_verified(self):
        output = self.base/'binding.json'
        words=['--root','beta='+str(self.b),'--root','alpha='+str(self.a),'--output',str(output)]
        with contextlib.redirect_stdout(io.StringIO()) as text:
            self.assertEqual(0,M.main(words))
        self.assertFalse(output.exists())
        self.assertFalse(json.loads(text.getvalue())['executed'])
        with contextlib.redirect_stdout(io.StringIO()): M.main(words+['--apply'])
        self.assertEqual(0o600,output.stat().st_mode&0o777)
        self.assertEqual(M.inventory(self.pairs),M.load(output,self.a))
        with self.assertRaises(FileExistsError): M.main(words+['--apply'])
        output.chmod(0o644)
        with self.assertRaises(ValueError): M.load(output)

    def test_output_inside_root_or_symlink_parent_never_writes(self):
        words=['--root','alpha='+str(self.a),'--root','beta='+str(self.b),'--apply','--output']
        with self.assertRaises(ValueError): M.main(words+[str(self.b/'selection.json')])
        alias=self.base/'alias'; alias.symlink_to(self.c, target_is_directory=True)
        with self.assertRaises(ValueError): M.main(words+[str(alias/'selection.json')])
        self.assertFalse((self.c/'selection.json').exists())

    def module(self, filename):
        spec=importlib.util.spec_from_file_location('roots_test_'+filename,Path(__file__).resolve().parents[1]/filename)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_preparation_refuses_cache_in_second_root_before_output_or_selected_process(self):
        prep=self.module('prepare-installed-pilot.py')
        manifest=self.base/'binding.json';manifest.write_text(json.dumps(M.inventory(self.pairs)));manifest.chmod(0o600)
        output=self.base/'uncreated-prefix'
        values={role:None for role in prep.PILOT.ROLES}
        values.update(git_profile=prep.GIT_PROFILES.DEFAULT,wsl_root=None,expected_commit='a'*40,
            filesystem_workspace=self.a,git_workspace=self.c,filesystem_roots_binding=manifest,
            node_archive=None,python_archive=None,wheelhouse=None,npm_cache=self.b/'never-cache',output=output)
        with patch.object(prep,'supported_platform'),patch.object(prep.PILOT,'source',return_value={'commit':'a'*40,'dirty':False}), \
                patch.object(prep.subprocess,'Popen') as spawn:
            with self.assertRaisesRegex(ValueError,'state_or_runtime_overlaps_root'):prep.prepare(SimpleNamespace(**values))
            spawn.assert_not_called()
        self.assertFalse(output.exists());self.assertFalse((self.b/'never-cache').exists())

    def test_run_state_inside_second_root_refuses_before_process_or_private_state(self):
        runner=self.module('pilot-run.py')
        selected={'filesystem_roots':M.inventory(self.pairs)}
        args=SimpleNamespace(port=0,selection=self.base/'selection.json',state_root=self.b)
        with patch.object(runner.PREP,'supported_platform'),patch.object(runner.PROVIDER,'selected',return_value={}), \
                patch.object(runner.PROVIDER,'require_access'),patch.object(runner,'selected',return_value=(selected,{},{})), \
                patch.object(runner.subprocess,'Popen') as spawn:
            with self.assertRaisesRegex(runner.Failure,'state_inside_filesystem_root'):runner.run(args,{})
            spawn.assert_not_called()
        self.assertFalse(any(self.b.glob('soup-wall-run-*')))

    def test_new_registry_keeps_original_schemas_actions_egress_and_default(self):
        installer=self.module('install-sou62-filesystem-profile.py')
        manifest=json.loads((installer.ASSETS/'upstream-tools-list.json').read_bytes())
        original=installer.registry(manifest);selected=installer.registry(manifest,filesystem_roots=True)
        self.assertEqual(original['registry_id'],'filesystem-readonly-v1')
        self.assertEqual(selected['registry_id'],M.ID)
        for before,after in zip(original['tools'],selected['tools']):
            self.assertEqual({k:v for k,v in before.items() if k!='mcp_result_profile'},
                             {k:v for k,v in after.items() if k!='mcp_result_profile'})
        self.assertEqual(installer.FORMAT,'sw-mcp/filesystem-readonly/1')

    def test_topology_is_bounded(self):
        for bound in ('MAX_DIRECTORIES','MAX_ENTRIES'):
            with patch.object(M,bound,1):
                with self.assertRaisesRegex(ValueError,'tree_bound'): M.inventory(self.pairs)


if __name__=='__main__': unittest.main()
