# SPDX-License-Identifier: Apache-2.0
"""Verify real synthetic Git setup before the Linux-only pinned installation."""
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'sou89_git_setup', ROOT / 'scripts/verify-sou89-selected-liveness.py')
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class GitLivenessSetup(unittest.TestCase):
    def test_real_repository_and_correct_pinned_installer_arguments(self):
        git = shutil.which('git')
        self.assertIsNotNone(git, 'real Git is required for the setup contract')
        git = Path(git).resolve()
        args = SimpleNamespace(agentfw=Path('/owned/agentfw'), git=git,
                               git_sha256='a' * 64, bwrap=Path('/owned/bwrap'),
                               git_launcher=Path('/owned/agentfw-git-sandbox'))
        rig = DRIVER.SelectedLivenessGitRig.__new__(DRIVER.SelectedLivenessGitRig)

        class InstallationBoundary(Exception):
            pass

        with tempfile.TemporaryDirectory(prefix='sou89-git-contract-') as temporary:
            private = Path(temporary)

            def installer(destination, workspace, selected_git, selected_sha, bwrap, launcher):
                self.assertTrue((workspace / '.git').is_dir(), 'synthetic standalone repository not prepared')
                self.assertEqual(rig.kind, 'git')
                self.assertEqual(selected_git, git)
                self.assertEqual(selected_sha, args.git_sha256)
                self.assertEqual(bwrap, args.bwrap)
                self.assertEqual(launcher, args.git_launcher)
                self.assertEqual(rig.env['GIT_PYTHON_GIT_EXECUTABLE'], str(git))
                self.assertEqual(rig.env['GIT_CONFIG_GLOBAL'], '/dev/null')
                self.assertEqual(rig.env['GIT_CONFIG_NOSYSTEM'], '1')
                self.assertEqual(rig.env['GIT_TERMINAL_PROMPT'], '0')
                message = subprocess.check_output(
                    [str(git), 'log', '-1', '--format=%s'], cwd=workspace,
                    env=rig.env, text=True, timeout=5)
                self.assertEqual(message.strip(), 'SOU-68 synthetic initial commit')
                raise InstallationBoundary

            with patch.object(DRIVER.GIT.INSTALL, 'install', installer):
                with self.assertRaises(InstallationBoundary):
                    rig.__init__(args, private, None)
        # This contract stops before Linux package installation; it never claims
        # selected execution or substitutes for the required real runner.
