# SPDX-License-Identifier: Apache-2.0
"""Exercise Git ownership refusal without root, globals or service changes."""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / 'ci'
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location('wall_python_linux', SCRIPTS / 'wall_python_linux.py')
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class CloneOwnershipBoundary(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='soup-clone-control-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'verified source'
        self.env = os.environ.copy()
        self.env.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                         'GIT_TERMINAL_PROMPT': '0', 'LC_ALL': 'C'})
        self.git(['init', '--quiet', str(self.source)])
        (self.source / 'fixture.txt').write_text('immutable source fixture\n')
        self.git(['-C', str(self.source), 'add', 'fixture.txt'])
        self.git(['-C', str(self.source), '-c', 'user.name=CI fixture',
                  '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
                  'commit', '--quiet', '-m', 'fixture'])
        self.env['GIT_TEST_ASSUME_DIFFERENT_OWNER'] = '1'

    def git(self, args):
        return subprocess.run(['git', *args], env=self.env, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)

    def test_verified_source_and_git_directory_can_clone_without_global_trust(self):
        result = subprocess.run(helper.clone_command(self.source, self.root / 'clone'),
                                env=helper.source_clone_environment(self.source, self.root / 'source-trust.config', self.env),
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_transport_keeps_exact_trust_when_command_parameters_are_removed(self):
        environment = helper.source_clone_environment(self.source, self.root / 'transport.config', self.env)
        environment.pop('GIT_CONFIG_PARAMETERS', None)
        result = subprocess.run(['git', 'clone', '--no-hardlinks', '--no-checkout', str(self.source / '.git'),
                                 str(self.root / 'child clone')],
                                env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 0, result.stdout.decode(errors='replace'))
        self.assertEqual(self.env['GIT_CONFIG_GLOBAL'], os.devnull)

    def test_trust_is_command_scoped_and_does_not_allow_another_repository(self):
        args = helper.clone_command(self.source, self.root / 'clone')
        # Swap the requested repository while keeping the approved safe paths.
        self.env.pop('GIT_TEST_ASSUME_DIFFERENT_OWNER')
        other = self.root / 'unapproved source'
        self.git(['clone', '--quiet', '--no-hardlinks', str(self.source), str(other)])
        self.env['GIT_TEST_ASSUME_DIFFERENT_OWNER'] = '1'
        args[-2] = str(other)
        scoped_environment = helper.source_clone_environment(self.source, self.root / 'source-trust.config', self.env)
        for command, environment in [(args, scoped_environment),
                (['git', 'clone', '--no-hardlinks', str(self.source),
                  str(self.root / 'no persistent exception')], self.env)]:
            with self.subTest(command=command):
                result = subprocess.run(command, env=environment, text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('dubious ownership', result.stdout)


if __name__ == '__main__':
    unittest.main()
