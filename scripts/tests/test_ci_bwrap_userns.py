"""Provision only a disposable job's exact sandbox; preserve foreign root state."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ci_bwrap_userns', ROOT / 'scripts/ci_bwrap_userns.py')
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


class ProvisioningBoundary(unittest.TestCase):
    def env(self):
        return {'GITHUB_ACTIONS': 'true', 'CI': 'true', 'SOUP_CI_RUNNER_ENVIRONMENT': 'github-hosted',
                'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64', 'GITHUB_RUN_ID': '1234',
                'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_JOB': 'mcp-real-filesystem--native-ubuntu-2404'}

    def test_rejects_local_shared_and_injected_job_identities(self):
        good = self.env()
        for change in ({'SOUP_CI_RUNNER_ENVIRONMENT': 'self-hosted'}, {'CI': 'false'},
                       {'RUNNER_OS': 'Windows'}, {'GITHUB_RUN_ID': '../etc'},
                       {'GITHUB_RUN_ATTEMPT': '1/../../'}, {'GITHUB_JOB': 'job"\nuserns,'}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                ci.identity(good | change)
        name, directory, profile = ci.identity(good)
        self.assertEqual(directory.parent, Path('/usr/lib'))
        self.assertEqual(profile.parent, Path('/etc/apparmor.d'))
        self.assertEqual(profile.name, name)
        self.assertNotEqual(ci.identity(good | {'GITHUB_RUN_ATTEMPT': '3'})[0], name)
        self.assertNotEqual(ci.identity(good | {'GITHUB_JOB': 'other'})[0], name)

    def test_denied_environment_never_invokes_sudo(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(ci, 'sudo') as sudo:
            with self.assertRaises(RuntimeError):
                ci.install(argparse.Namespace())
            sudo.assert_not_called()

    def test_digest_mismatch_precedes_any_root_write(self):
        with tempfile.TemporaryDirectory() as work:
            source = Path(work) / 'bwrap'
            source.write_bytes(b'\x7fELFchanged')
            targets = ('owned', Path(work) / 'root', Path(work) / 'profile')
            with patch.object(ci, 'guard', return_value=targets), patch.object(ci, 'sudo') as sudo:
                with self.assertRaisesRegex(RuntimeError, 'source_bwrap_digest_mismatch'):
                    ci.install(argparse.Namespace(source=source, sha256='0' * 64))
                sudo.assert_not_called()

    def test_symlink_source_is_not_privileged_input(self):
        if os.name == 'nt':
            self.skipTest('Linux symlink boundary')
        with tempfile.TemporaryDirectory() as work:
            target = Path(work) / 'target'
            target.write_bytes(b'\x7fELF')
            link = Path(work) / 'bwrap'
            link.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, 'unsafe_regular_file'):
                ci.regular(link)

    def test_foreign_root_entries_and_modified_profile_prevent_cleanup(self):
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work) / 'owned'
            directory.mkdir()
            binary = directory / 'bwrap'
            binary.write_bytes(b'owned')
            receipt = {'format': 'sou111-ci-userns/1', 'job': 'test',
                       'sha256': hashlib.sha256(b'owned').hexdigest()}
            (directory / 'owner.json').write_text(json.dumps(receipt))
            policy = Path(work) / 'profile'
            policy.write_bytes(ci.profile('test', binary))
            regular = ci.regular
            with patch.object(ci, 'guard', return_value=('test', directory, policy)), \
                    patch.object(ci, 'root_parent'), \
                    patch.object(ci, 'regular', side_effect=lambda path, owner=None: regular(path)), \
                    patch.object(ci, 'sudo') as sudo:
                foreign = directory / 'operator-file'
                foreign.write_text('preserve')
                with self.assertRaisesRegex(RuntimeError, 'foreign_cleanup_file'):
                    ci.cleanup(argparse.Namespace())
                foreign.unlink()
                policy.write_bytes(ci.profile('test', binary) + b'# operator edit\n')
                with self.assertRaisesRegex(RuntimeError, 'changed_cleanup_profile'):
                    ci.cleanup(argparse.Namespace())
                sudo.assert_not_called()
                self.assertEqual(binary.read_bytes(), b'owned')

    @unittest.skipUnless(os.name == 'posix' and shutil.which('apparmor_parser'), 'AppArmor parser required')
    def test_exact_single_executable_profile_compiles_without_loading_kernel_policy(self):
        name, directory, _ = ci.identity(self.env())
        with tempfile.TemporaryDirectory() as work:
            source = Path(work) / 'profile'
            source.write_bytes(ci.profile(name, directory / 'bwrap'))
            result = subprocess.run(['apparmor_parser', '-Q', '-T', '-K', '-o',
                                     str(Path(work) / 'compiled'), str(source)],
                                    capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertGreater((Path(work) / 'compiled').stat().st_size, 0)


if __name__ == '__main__':
    unittest.main()
