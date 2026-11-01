# SPDX-License-Identifier: Apache-2.0
"""Real owned Git layouts; no selected original server is replaced by a mock."""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pilot_linked_worktree as linked
import pilot_git_profiles as profiles


@unittest.skipUnless(os.name == 'posix' and shutil.which('git'), 'POSIX directory bindings and fixture Git required')
class Selection(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / 'source'
        self.one = self.root / 'one'
        self.two = self.root / 'two'
        self.git('init', '-q', '-b', 'main', self.repo)
        (self.repo / 'note').write_text('Owned initial content\n')
        self.git('-C', self.repo, 'add', 'note')
        self.git('-C', self.repo, '-c', 'user.name=Owned', '-c', 'user.email=owned@example.invalid', 'commit', '-qm', 'Owned initial history')
        self.git('-C', self.repo, 'worktree', 'add', '-q', '-b', 'branch-one', self.one)
        self.git('-C', self.repo, 'worktree', 'add', '-q', '-b', 'branch-two', self.two)
        self.common = self.repo / '.git'
        self.admin = self.common / 'worktrees/one'

    def git(self, *words):
        env = {**os.environ, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
        return subprocess.check_output(['git', *map(str, words)], env=env, stderr=subprocess.PIPE)

    def binding(self, workspace=None, admin=None):
        return linked.inventory(workspace or self.one, admin or self.admin, self.common)

    def test_real_gitfile_gitdir_commondir_are_explicit_and_side_effect_free(self):
        before = {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        one = self.binding()
        two = self.binding(self.two, self.common / 'worktrees/two')
        self.assertEqual(one['gitDir']['path'], str(self.admin))
        self.assertNotEqual(one['inputsSha256'], two['inputsSha256'])
        self.assertEqual(one['commonDir'], two['commonDir'])
        self.assertEqual(before, {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_missing_or_sibling_selection_never_follows_repository_path_strings(self):
        with self.assertRaisesRegex(ValueError, 'selection_mismatch'):
            self.binding(self.one, self.common / 'worktrees/two')
        with self.assertRaises((ValueError, OSError)):
            linked.inventory(self.one, self.root / 'missing', self.common)
        (self.one / '.git').write_text('gitdir: /unselected/never-read\n')
        with self.assertRaisesRegex(ValueError, 'selection_mismatch'):
            self.binding()

    def test_changed_head_index_and_common_object_inputs_refuse(self):
        binding = self.binding()
        for path in (self.admin / 'HEAD', self.admin / 'index', self.common / 'config'):
            raw = path.read_bytes()
            path.write_bytes(raw + b'changed')
            with self.assertRaisesRegex(ValueError, 'selected_inputs_changed'):
                linked.verify(binding)
            path.write_bytes(raw)
        self.assertEqual(linked.verify(binding), binding)

    def test_replaced_external_root_and_cross_workspace_binding_refuse(self):
        binding = self.binding()
        with self.assertRaisesRegex(ValueError, 'workspace_mismatch'):
            linked.verify(binding, self.two)
        old = self.common / 'worktrees/retained'
        self.admin.rename(old)
        shutil.copytree(old, self.admin)
        with self.assertRaisesRegex(ValueError, 'selected_inputs_changed'):
            linked.verify(binding)

    def test_symlink_hardlink_shared_permissions_and_oversize_inputs_refuse(self):
        path = self.admin / 'HEAD'
        original = path.read_bytes()
        path.unlink()
        outside = self.root / 'outside'
        outside.write_bytes(original)
        path.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'unsafe_file'):
            self.binding()
        path.unlink()
        os.link(outside, path)
        with self.assertRaisesRegex(ValueError, 'unsafe_file'):
            self.binding()
        path.unlink()
        path.write_bytes(original)
        path.chmod(0o666)
        with self.assertRaisesRegex(ValueError, 'unsafe_file'):
            self.binding()
        path.chmod(0o600)
        path.write_bytes(b'x' * 257)
        with self.assertRaisesRegex(ValueError, 'unsafe_file'):
            self.binding()
        self.assertEqual(outside.read_bytes(), original)

    def test_unknown_binding_fields_duplicates_and_wrong_scope_refuse(self):
        binding = self.binding()
        bad = copy.deepcopy(binding)
        bad['grant'] = 'never-authority'
        with self.assertRaisesRegex(ValueError, 'binding_schema'):
            linked.verify(bad)
        with self.assertRaisesRegex(ValueError, 'duplicate_field'):
            linked.strict('{"format":1,"format":2}')
        bad = copy.deepcopy(binding)
        bad['gitDir']['identity']['uid'] += 1
        with self.assertRaisesRegex(ValueError, 'selected_inputs_changed'):
            linked.verify(bad)
        path = self.root / 'binding.json'
        path.write_text(json.dumps(binding))
        path.chmod(0o600)
        self.assertEqual(linked.load(path, self.one), binding)

    def test_binding_creation_is_new_private_and_refuses_redirected_parent(self):
        output = self.root / 'selected.json'
        words = ['--workspace', str(self.one), '--git-dir', str(self.admin), '--common-dir', str(self.common),
                 '--output', str(output)]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(linked.main(words), 0)
            self.assertFalse(output.exists())
            self.assertEqual(linked.main([*words, '--apply']), 0)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(linked.load(output), self.binding())
        alias = self.root / 'alias'
        alias.symlink_to(self.common, target_is_directory=True)
        redirected = words[:-1] + [str(alias / 'never-written')]
        with self.assertRaisesRegex(ValueError, 'canonical_root_required'), contextlib.redirect_stdout(io.StringIO()):
            linked.main([*redirected, '--apply'])
        self.assertFalse((self.common / 'never-written').exists())

    def test_separate_profile_retains_pinned_schemas_policy_and_revision_grammar(self):
        selected = profiles.binding(linked.ID)
        self.assertEqual(selected['profile_format'], linked.PROFILE)
        self.assertEqual(selected['classifier_sha256'], profiles.binding(profiles.DEFAULT)['classifier_sha256'])
        self.assertEqual(selected['policy_sha256'], profiles.binding(profiles.DEFAULT)['policy_sha256'])
        original = profiles.registry(profiles.DEFAULT)
        extra = profiles.registry(linked.ID)
        for before, after in zip(original['tools'], extra['tools']):
            self.assertEqual({k: v for k, v in before.items() if k != 'mcp_result_profile'},
                             {k: v for k, v in after.items() if k != 'mcp_result_profile'})
        self.assertEqual(profiles.DEFAULT, 'git-readonly-v1')
