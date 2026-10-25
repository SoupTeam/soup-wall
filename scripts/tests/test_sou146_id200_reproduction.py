# SPDX-License-Identifier: Apache-2.0
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

spec=importlib.util.spec_from_file_location('id200_repro',Path(__file__).parents[1]/'reproduce-sou146-id200.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


@unittest.skipUnless(os.name=='posix' and Path('/usr/bin/git').exists(),'Linux direct original Git fixture')
class GitEnvironmentBoundary(unittest.TestCase):
    def test_caller_git_environment_cannot_redirect_owned_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);owned=root/'owned';owned.mkdir()
            victim=root/'foreign.git';victim.mkdir();sentinel=victim/'config';sentinel.write_bytes(b'foreign sentinel\n')
            with mock.patch.dict(os.environ,{'GIT_DIR':str(victim),'GIT_WORK_TREE':str(root),
                'GIT_CONFIG_COUNT':'1','GIT_CONFIG_KEY_0':'core.hooksPath','GIT_CONFIG_VALUE_0':str(root/'hooks'),
                'GIT_ALTERNATE_OBJECT_DIRECTORIES':str(root/'objects')}):
                env=r.original_environment(Path('/usr/bin/git'))
            for key in ('GIT_DIR','GIT_WORK_TREE','GIT_CONFIG_COUNT','GIT_CONFIG_KEY_0','GIT_CONFIG_VALUE_0','GIT_ALTERNATE_OBJECT_DIRECTORIES'):
                self.assertNotIn(key,env)
            subprocess.run(['/usr/bin/git','init','--initial-branch=main','--template='],cwd=owned,env=env,
                           check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            location=subprocess.check_output(['/usr/bin/git','rev-parse','--git-dir'],cwd=owned,env=env,timeout=10).decode().strip()
            self.assertEqual(location,'.git')
            self.assertEqual(sentinel.read_bytes(),b'foreign sentinel\n')
            self.assertEqual(sorted(p.name for p in victim.iterdir()),['config'])


if __name__=='__main__':unittest.main()
