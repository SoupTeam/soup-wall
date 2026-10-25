# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
import unittest

spec = importlib.util.spec_from_file_location('small_cuda', Path(__file__).parents[1]/'evaluate-horizon-small-cuda.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


@unittest.skipUnless(sys.platform == 'linux', 'actual POSIX worker ownership')
class WorkerDeadline(unittest.TestCase):
    def test_timeout_kills_and_reaps_actual_worker_and_reader(self):
        with tempfile.TemporaryDirectory() as temp:
            worker = m.OwnedWorker([sys.executable,'-c',
                'import os,json,time;print(json.dumps({"worker_pid":os.getpid()}),flush=True);time.sleep(60)'],
                Path(temp)/'stderr')
            pid = worker.receive(5)['worker_pid']
            self.assertEqual(pid, worker.p.pid)
            with self.assertRaises(TimeoutError):
                worker.receive(.05)
            started = time.monotonic()
            worker.close()
            self.assertLess(time.monotonic()-started, 3)
            self.assertIsNotNone(worker.p.returncode)
            self.assertFalse(worker.reader.is_alive())


class OriginalEnvelope(unittest.TestCase):
    def test_multichannel_unicode_and_crlf_are_preserved_in_full(self):
        channels = ['Я😀\r\n---\nend', '', 'Я😀\r\n---\nend']
        text, spans = m.h.envelope(channels)
        self.assertEqual(len(spans), 3)
        for value, span in zip(channels, spans):
            self.assertEqual(text[span['start_char']:span['end_char']], value)
            self.assertEqual(span['source_start_byte'], 0)
            self.assertEqual(span['source_end_byte'], len(value.encode()))
        separate = m.views(channels)
        self.assertEqual(separate[0], ('ordered_envelope',text,spans))
        self.assertEqual([v[1] for v in separate[1:]],channels)
        self.assertEqual([v[2][0]['channel'] for v in separate[1:]], [0,1,2])


if __name__ == '__main__':
    unittest.main()
