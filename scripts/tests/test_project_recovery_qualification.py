# SPDX-License-Identifier: Apache-2.0
"""Real Linux calibration of the owned interruption witness, separate from product acceptance."""
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('project_interruption_qualification_tests',ROOT/'scripts/qualify-project-recovery.py')
Q=importlib.util.module_from_spec(spec);spec.loader.exec_module(Q)

class PhaseParsing(unittest.TestCase):
    def test_only_a_successful_fsync_of_the_exact_staged_file_proves_the_phase(self):
        stage=Path('/owned/.import-next-'+'a'*64)
        self.assertTrue(Q.stage_fsync_observed(('123 fsync(5<'+str(stage)+'>) = 0\n').encode(),stage))
        for raw in (b'123 fsync(5</owned/other>) = 0\n',
                    ('123 fsync(5<'+str(stage)+'>) = -1 EIO\n').encode(),
                    ('123 execve("/owned/fsync(5<'+str(stage)+'>) = 0", [], 0x0) = 0\n').encode()):
            self.assertFalse(Q.stage_fsync_observed(raw,stage))

@unittest.skipUnless(sys.platform.startswith('linux')and shutil.which('strace'),'native Linux strace calibration')
class NativeInterruption(unittest.TestCase):
    def run_fixture(self,fsync,timeout,validation_calls=0):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name).resolve();root.chmod(0o700)
        directory=root/'store';stage=directory/('.import-next-'+'a'*64);catalog=directory/'catalog.json'
        code=('import os,sys,collections;from pathlib import Path;'
              'root=Path(sys.argv[1]);root.mkdir(mode=0o700);'
              'fd=os.open(root/sys.argv[2],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);'
              'os.write(fd,b"{\\\"owned\\\":true}");'+
              'collections.deque((os.fstat(fd) for _ in range('+str(validation_calls)+')),maxlen=0);'+
              ('os.fsync(fd);'if fsync else'')+
              'os.close(fd);directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY);'
              'os.replace(sys.argv[2],"catalog.json",src_dir_fd=directory,dst_dir_fd=directory);os.close(directory)')
        diagnostics={};self.last_diagnostics=diagnostics
        value=Q.interrupt_before_publication(shutil.which('strace'),
            [sys.executable,'-I','-B','-c',code,str(directory),stage.name],root/'trace.private',stage,catalog,
            cwd=root,env={'PATH':'/usr/bin:/bin'},diagnostics=diagnostics,timeout_seconds=timeout)
        return value,stage,catalog

    def test_durable_stage_is_interrupted_before_publication_without_waiting_for_pipe_eof(self):
        observed,stage,catalog=self.run_fixture(True,5)
        self.assertEqual(observed['initial_exit'],-signal.SIGKILL)
        self.assertEqual(observed['phase'],'terminated_before_publication')
        self.assertTrue(observed['stage_fsynced']);self.assertTrue(stage.is_file());self.assertFalse(catalog.exists())
        self.assertRegex(observed['trace_sha256'],r'^[0-9a-f]{64}$')

    def test_syscall_heavy_validation_still_reaches_durable_staging_within_the_same_bound(self):
        observed,stage,catalog=self.run_fixture(True,5,500000)
        self.assertTrue(observed['syscall_filter_requested'])
        self.assertTrue(observed['stage_fsynced']);self.assertTrue(stage.is_file())
        self.assertFalse(catalog.exists())

    def test_file_existence_without_fsync_never_passes_calibration(self):
        with self.assertRaisesRegex(ValueError,'stage_fsync_unobserved'):self.run_fixture(False,2)
        self.assertTrue(self.last_diagnostics['stage_present'])
        self.assertFalse(self.last_diagnostics['stage_fsynced'])
        self.assertFalse(self.last_diagnostics['catalog_present'])

if __name__=='__main__':unittest.main()
