# SPDX-License-Identifier: Apache-2.0
"""Preserve complete independent effects/wire/log proof under metadata noise."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('prepared_projection_test',ROOT/'scripts/qualify-prepared-pilot-run.py')
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
P=M.CAPTURE


def project(text):
    projection=P.Projection()
    return b''.join(projection.line(row) for row in text.splitlines(keepends=True)) + projection.remainder()


class ProjectionControls(unittest.TestCase):
    def test_targets_and_interleaved_resumptions_remain_exact(self):
        raw=(b'1 openat(AT_FDCWD, "/unrelated", O_RDONLY) = 5\n'
             b'2 openat(AT_FDCWD, "/workspace/credentials.txt", O_RDONLY|O_CLOEXEC <unfinished ...>\n'
             b'1 close(5 <unfinished ...>\n'
             b'2 <... openat resumed>) = 7\n1 <... close resumed>) = 0\n'
             b'2 close(7) = 0\n'
             b'3 openat(AT_FDCWD, "/workspace/notes.txt", O_RDONLY) = -1 EACCES (Permission denied)\n')
        filtered=project(raw)
        self.assertNotIn(b'/unrelated',filtered)
        self.assertIn(b'<... openat resumed>',filtered)
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'trace'
            for text in (raw,filtered):
                path.write_bytes(text)
                self.assertEqual(M.ASK.SELECTED.trace_effects(path,'filesystem',target='/workspace/credentials.txt'),1)

    def test_pending_target_and_unknown_success_never_prove_zero(self):
        p=P.Projection()
        p.line(b'1 openat(AT_FDCWD, "/workspace/credentials.txt", O_RDONLY <unfinished ...>\n')
        self.assertTrue(p.target_pending())
        p.line(b'1 <... openat resumed>) = 4\n')
        self.assertFalse(p.target_pending())
        for row in (b'1 openat(AT_FDCWD, 0x123, O_RDONLY) = 4\n',
                    b'1 <... openat resumed>) = 4\n'):
            with self.assertRaises(P.Invalid):P.Projection().line(row)

    def test_private_log_descriptor_reuse_is_preserved(self):
        values={key:'owned-'+key for key in M.PROVIDER_WITNESS.KEYS}
        raw=(b'1 openat(AT_FDCWD, "/owned/run/host.private.log", O_WRONLY|O_CREAT|O_EXCL, 0600) = 4\n'
             b'1 openat(AT_FDCWD, "/owned/run/daemon.private.log", O_WRONLY|O_CREAT|O_EXCL, 0600) = 5\n'
             b'1 write(4, "safe", 4) = 4\n'
             b'1 openat(AT_FDCWD, "/unrelated", O_RDONLY <unfinished ...>\n'
             b'1 <... openat resumed>) = 4\n'
             b'1 close(5) = 0\n'
             b'1 openat(AT_FDCWD, "/different", O_RDONLY) = 5\n'
             b'1 write(4, "owned-ANTHROPIC_API_KEY", 23) = 23\n')
        proofs=[]
        for text in (raw,project(raw)):
            proofs.append(M.PROVIDER_WITNESS.private_log_writes(text.decode(),Path('/owned/run'),1,values,M.LAUNCH.normalized_syscalls))
        self.assertEqual(proofs[0],proofs[1])
        self.assertIn(b'/unrelated',project(raw))
        self.assertNotIn(b'/different',project(raw))

    def test_failed_close_does_not_erase_secret_in_log_evidence(self):
        raw=(b'1 openat(AT_FDCWD, "/owned/run/host.private.log", O_WRONLY|O_CREAT|O_EXCL, 0600) = 4\n'
             b'1 openat(AT_FDCWD, "/owned/run/daemon.private.log", O_WRONLY|O_CREAT|O_EXCL, 0600) = 5\n'
             b'1 close(4) = -1 EINTR (Interrupted system call)\n'
             b'1 write(4, "owned-ANTHROPIC_API_KEY", 23) = 23\n')
        values={key:'owned-'+key for key in M.PROVIDER_WITNESS.KEYS}
        for text in (raw,project(raw)):
            with self.assertRaises(ValueError):
                M.PROVIDER_WITNESS.private_log_writes(text.decode(),Path('/owned/run'),1,values,M.LAUNCH.normalized_syscalls)

    def test_unfinished_unrelated_supervisor_metadata_still_refuses_final_proof(self):
        raw=(b'1 openat(AT_FDCWD, "/owned/run/host.private.log", O_WRONLY|O_CREAT|O_EXCL, 0600) = 4\n'
             b'1 openat(AT_FDCWD, "/owned/run/daemon.private.log", O_WRONLY|O_CREAT|O_EXCL, 0600) = 5\n'
             b'1 write(4, "safe", 4) = 4\n1 close(4) = 0\n1 close(5) = 0\n'
             b'1 openat(AT_FDCWD, "/unrelated", O_RDONLY <unfinished ...>\n')
        values={key:'owned-'+key for key in M.PROVIDER_WITNESS.KEYS}
        for text in (raw,project(raw)):
            with self.assertRaisesRegex(ValueError,'provider_private_log_write_unproven'):
                M.PROVIDER_WITNESS.private_log_writes(text.decode(),Path('/owned/run'),1,values,M.LAUNCH.normalized_syscalls)


@unittest.skipUnless(sys.platform=='linux','private FIFO collector is Linux-only')
class CaptureControls(unittest.TestCase):
    def produce(self,capture,rows):
        errors=[]
        def writer():
            try:
                with capture.fifo.open('wb',buffering=0) as stream:
                    for row in rows:stream.write(row)
            except Exception as error:errors.append(error)
        task=threading.Thread(target=writer);task.start()
        task.join(timeout=10)
        self.assertFalse(task.is_alive(),'producer blocked behind failed observer')
        self.assertFalse(errors)

    def test_required_record_after_more_than_32m_metadata_is_not_a_tail_substitute(self):
        with tempfile.TemporaryDirectory() as temp:
            capture=P.Capture(Path(temp)/'trace.private')
            noise=b'1 openat(AT_FDCWD, "/unrelated/'+b'n'*2000+b'", O_RDONLY) = 4\n1 close(4) = 0\n'
            required=b'2 openat(AT_FDCWD, "/workspace/credentials.txt", O_RDONLY) = 7\n'
            def rows():
                yield required
                for _ in range(17000):yield noise
                yield required
            self.produce(capture,rows())
            self.assertTrue(capture.sync())
            capture.finish()
            self.assertEqual(capture.path.read_bytes(),required+required)
            self.assertGreater(capture.summary()['input_bytes'],P.LIMIT)
            self.assertEqual(capture.summary()['retained_limit'],32*1024*1024)
            self.assertTrue(capture.summary()['complete'])

    def test_partial_input_cannot_prove_live_zero(self):
        with tempfile.TemporaryDirectory() as temp:
            capture=P.Capture(Path(temp)/'trace.private')
            self.produce(capture,[b'1 write(9, "incomplete'])
            self.assertFalse(capture.sync())
            with self.assertRaisesRegex(P.Invalid,'private_trace_capture_incomplete'):capture.finish()

    def test_live_zero_gate_drains_a_queued_forbidden_dispatch_before_reading(self):
        def wire(pid,method,args):
            frame=json.dumps({'method':method,'params':{'name':'read_text_file','arguments':args}})+'\n'
            return f'{pid} write(9, {json.dumps(frame)}, {len(frame)}) = {len(frame)}\n'.encode()
        with tempfile.TemporaryDirectory() as temp:
            capture=P.Capture(Path(temp)/'trace.private')
            writer=os.open(capture.fifo,os.O_WRONLY|os.O_NONBLOCK)
            try:
                discovery=b''.join(f'{pid} execve("/owned/agentfw", ["agentfw", "mcp"], 0x0) = 0\n'.encode()
                    +wire(pid,'tools/list',{}) for pid in (101,102))
                os.write(writer,discovery)
                self.assertTrue(capture.sync())
                args={'path':'/workspace/credentials.txt'}
                digest=M.BASE.hashlib.sha256(json.dumps(args,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                with capture.lock:
                    # The worker cannot drain while this reentrant lock is
                    # held. A gate which merely reads the old file sees zero.
                    os.write(writer,wire(101,'tools/call',args))
                    with self.assertRaisesRegex(ValueError,'^prepared_dispatch_before_approval$'):
                        M.no_original_dispatch(capture.path,Path('/owned/agentfw'),'read_text_file',digest,capture)
            finally:
                os.close(writer)
                capture.finish()

    def test_overflow_is_sticky_and_producer_can_finish(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(P,'LIMIT',512):
            capture=P.Capture(Path(temp)/'trace.private')
            self.produce(capture,[b'1 write(9, "x", 1) = 1\n']*100)
            with self.assertRaisesRegex(P.Invalid,'^private_trace_limit$'):capture.sync()
            with self.assertRaisesRegex(P.Invalid,'^private_trace_limit$'):capture.finish()
            self.assertLessEqual(capture.path.stat().st_size,512)

    def test_existing_output_is_preserved_on_constructor_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'trace.private';path.write_bytes(b'keep')
            with self.assertRaises(FileExistsError):P.Capture(path)
            self.assertEqual(path.read_bytes(),b'keep')
            self.assertFalse(path.with_suffix('.fifo').exists())


if __name__=='__main__':unittest.main()
