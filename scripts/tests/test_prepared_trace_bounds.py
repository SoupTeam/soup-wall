# SPDX-License-Identifier: Apache-2.0
"""Overflow/incomplete/dispatch controls for the real prepared Ask witness."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('bounded_prepared_trace', ROOT / 'scripts/qualify-prepared-pilot-run.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def wire(pid, method, arguments=None):
    frame = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method,
        'params': {'name': 'read_text_file', 'arguments': arguments}}) + '\n'
    return f'{pid} write(9, {json.dumps(frame)}, {len(frame)}) = {len(frame)}\n'


def discovery():
    return ''.join(f'{pid} execve("/owned/agentfw", ["agentfw", "mcp", "--id", "{role}"], 0x0) = 0\n'
                   + wire(pid, 'tools/list') for pid, role in ((101, 'filesystem'), (102, 'git')))


class BoundedTrace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'trace.private'
        self.args = {'path': '/workspace/credentials.txt'}
        self.digest = M.BASE.hashlib.sha256(json.dumps(self.args,sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def observe(self, text):
        self.path.write_text(text)
        return M.no_original_dispatch(self.path, Path('/owned/agentfw'), 'read_text_file', self.digest)

    def test_only_complete_calibrated_zero_allows_decision(self):
        self.assertIsNone(M.no_original_dispatch(self.path,Path('/owned/agentfw'),'read_text_file',self.digest))
        self.assertIsNone(self.observe(''))
        self.assertIsNone(self.observe(discovery().rstrip('\n')))
        self.assertTrue(self.observe(discovery()))
        self.assertTrue(self.observe(discovery()+wire(101,'tools/call',{'path':'/workspace/notes.txt'})))

    def test_real_target_dispatch_fails_immediately_not_as_timeout(self):
        with self.assertRaisesRegex(ValueError,'^prepared_dispatch_before_approval$'):
            self.observe(discovery()+wire(101,'tools/call',self.args))

    def test_partial_frame_and_unfinished_channel_never_prove_zero(self):
        for suffix in ('101 write(9, "part", 4) = 4\n',
                       '101 write(9, "part", 4 <unfinished ...>\n'):
            self.assertIsNone(self.observe(discovery()+suffix))

    def test_truncated_single_vector_and_frame_overflow_are_not_retried(self):
        for suffix in ('101 write(9, "secret"..., 1000) = 1000\n',
                       '101 writev(9, [{iov_base="short"..., iov_len=1000}], 1) = 1000\n',
                       '101 write(9, "short", 1000) = 1000\n'):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.observe(discovery()+suffix)

    def test_sparse_oversize_is_detected_before_read_and_not_swallowed(self):
        with self.path.open('wb') as stream:
            stream.truncate(M.ASK.SELECTED.TRACE_LIMIT+1)
        with patch.object(os,'fdopen',wraps=os.fdopen) as opened:
            with self.assertRaisesRegex(ValueError,'^private_trace_limit$'):
                M.no_original_dispatch(self.path,Path('/owned/agentfw'),'read_text_file',self.digest)
        self.assertEqual(opened.call_count,1)
        with self.assertRaisesRegex(ValueError,'^private_trace_limit$'):
            M.ASK.SELECTED.trace_effects(self.path,'filesystem')

    def test_limit_is_unchanged_and_exact_boundary_is_accepted(self):
        self.assertEqual(M.ASK.SELECTED.TRACE_LIMIT,32*1024*1024)
        with self.path.open('wb') as stream:
            stream.truncate(M.ASK.SELECTED.TRACE_LIMIT)
        self.assertEqual(len(M.ASK.SELECTED.read_private_trace(self.path)),32*1024*1024)

    @unittest.skipUnless(hasattr(os,'O_NOFOLLOW'),'requires no-follow file opens')
    def test_symlink_and_non_regular_witnesses_are_not_zero(self):
        target=self.path.with_name('target');target.write_text(discovery())
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            M.ASK.SELECTED.read_private_trace(self.path)
        self.path.unlink()
        os.mkfifo(self.path)
        with self.assertRaisesRegex(ValueError,'^private_trace_not_regular$'):
            M.ASK.SELECTED.read_private_trace(self.path)

    def test_invalid_encoding_is_finite_and_not_an_incomplete_zero(self):
        self.path.write_bytes(b'PRIVATE_OWNED_CANARY\xff\n')
        with self.assertRaisesRegex(ValueError,'^private_trace_encoding$'):
            M.no_original_dispatch(self.path,Path('/owned/agentfw'),'read_text_file',self.digest)


STRACE = os.environ.get('SOU_TEST_STRACE') or shutil.which('strace')


@unittest.skipUnless(sys.platform=='linux' and STRACE,'requires Linux strace; parser tests are separate')
class ActualCapture(unittest.TestCase):
    def test_bulk_preparation_does_not_hide_complete_or_truncated_wire(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'mcp').write_text('''import os,json,sys
fd=int(sys.argv[1])
for method in ('tools/list','tools/call'):
 frame=json.dumps({'method':method,'params':{'name':'read_text_file','arguments':{'path':'x'*int(sys.argv[2])}}})+'\\n'
 os.write(fd,frame.encode())
''')
            (root/'driver.py').write_text('''import os,subprocess,sys
with open('bulk','wb') as f:
 for _ in range(12):f.write(bytes(range(256))*4096)
from pathlib import Path
noise=Path.cwd()
for _ in range(12):
 noise=noise/('n'*180);noise.mkdir(exist_ok=True)
noise=noise/'input';noise.write_bytes(b'owned')
for _ in range(15000):os.close(os.open(noise,os.O_RDONLY))
invalid=os.fsencode(noise)+b'.\\xff-owned'
os.close(os.open(invalid,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)) if not os.path.exists(invalid) else None
for role in ('filesystem','git'):
 r,w=os.pipe()
 child=subprocess.Popen([sys.executable,'mcp',str(w),sys.argv[1],'--id',role],pass_fds=(w,))
 os.close(w)
 while os.read(r,65536):pass
 os.close(r);assert child.wait()==0
''')
            for length,passes in ((5,True),(M.TRACE_STRING_BYTES+100,False)):
                trace=root/f'trace-{length}'
                capture=M.CAPTURE.Capture(trace)
                command=[STRACE,'-f','--seccomp-bpf','-qq','-s',str(M.TRACE_STRING_BYTES),'-e',
                    'trace=execve,openat,close,write,writev,clone,clone3,vfork,fork','-o',str(capture.fifo),
                    sys.executable,'driver.py',str(length)]
                try:
                    subprocess.run(command,cwd=root,check=True,timeout=20,capture_output=True)
                finally:
                    capture.finish()
                self.assertLess(trace.stat().st_size,M.ASK.SELECTED.TRACE_LIMIT)
                self.assertGreater(capture.summary()['input_bytes'],M.ASK.SELECTED.TRACE_LIMIT)
                raw=M.read_trace_text(trace)
                if passes:
                    observed=M.LAUNCH.collector_dispatches(raw,Path(sys.executable),strict=False)
                    self.assertEqual(len(observed['calls']),2)
                    old=root/'old-trace'
                    old_command=command.copy()
                    old_command[old_command.index('-s')+1]='1048576'
                    old_command[old_command.index('-o')+1]=str(old)
                    subprocess.run(old_command,cwd=root,check=True,timeout=20,capture_output=True)
                    self.assertGreater(old.stat().st_size,M.ASK.SELECTED.TRACE_LIMIT)
                    with self.assertRaisesRegex(ValueError,'^private_trace_limit$'):
                        M.read_trace_text(old)
                else:
                    with self.assertRaises(ValueError):
                        M.LAUNCH.collector_dispatches(raw,Path(sys.executable),strict=False)


if __name__=='__main__':
    unittest.main()
