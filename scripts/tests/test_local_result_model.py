# SPDX-License-Identifier: Apache-2.0
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('local_model', Path(__file__).resolve().parents[1] / 'evaluate-local-result-model.py')
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


class LocalModelControls(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows Job ownership test')
    def test_windows_job_reaps_descendant(self):
        import ctypes
        from ctypes import wintypes as w
        owned = model.OwnedProcess(['--test-worker', 'descendant'])
        handle = None
        k = ctypes.WinDLL('kernel32', use_last_error=True)
        k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        k.OpenProcess.restype = w.HANDLE
        k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        k.CloseHandle.argtypes = [w.HANDLE]
        try:
            owned.p.stdin.write(b'go\n')
            owned.p.stdin.flush()
            pid = json.loads(owned.p.stdout.readline(4096))['pid']
            handle = k.OpenProcess(0x100000, False, pid)
            self.assertTrue(handle)
            owned.close()
            self.assertEqual(k.WaitForSingleObject(handle, 2000), 0)
        finally:
            if owned.p.poll() is None:
                owned.close()
            owned.p.stdout.close()
            owned.p.stderr.close()
            if handle:
                k.CloseHandle(handle)

    def test_full_token_coverage_including_final_payload(self):
        for size in (0, 1, 510, 511, 1024, 65536):
            ids = list(range(size))
            windows = model.windows_for(ids)
            self.assertEqual(set(ids), {v for _, part in windows for v in part})
            self.assertTrue(all(len(part) <= 510 for _, part in windows))
            if size:
                self.assertEqual(windows[-1][1][-1], size - 1)

    def test_uncertainty_is_not_a_negative_label(self):
        for scores in ([], [.5], [float('nan')], [True], [1.1]):
            self.assertEqual(model.decide(scores), 'unknown')
        self.assertEqual(model.decide([.01, .99]), 'instruction')
        self.assertEqual(model.decide([.01, .02]), 'data')

    def test_stream_failures_and_deadline_reap_owned_worker(self):
        for mode in ('timeout', 'oversize', 'malformed', 'stderr'):
            with self.subTest(mode=mode):
                run = model.run_worker(Path('.'), [{'text': 'untrusted'}], test_mode=mode,
                                       startup=.4, per_case=.4, total=1)
                self.assertTrue(run['owned_worker_reaped'])
                self.assertIsNotNone(run['failure'])
                self.assertEqual(run['observations'][0]['assessment'], 'unknown')
                self.assertLess(run['elapsed_ms'], 5000)

    def test_bounds_and_assets_are_not_inferred_from_metadata(self):
        with self.assertRaises(ValueError):
            model.run_worker(Path('.'), [{'text': 'x' * 65537}])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                model.verify_assets(Path(tmp))

    def test_corpus_keeps_bulk_limits_and_original_fixture(self):
        rows = model.corpus()
        self.assertEqual(len(rows), 20)
        self.assertEqual(rows[0]['text'], rows[1]['text'])
        for size in (200, 201, 256):
            row = next(r for r in rows if r['id'] == f'filesystem-bulk-{size}')
            self.assertEqual(row['text'].count('SOU-97'), size)
        metrics = model.metrics([{'id': 'a', 'pair': 'git', 'expected': 'instruction',
                                 'observation': {'assessment': 'unknown', 'reason': 'timeout'}}])
        self.assertEqual(metrics['git']['attack_unknown'], 1)
        self.assertEqual(metrics['git']['unsafe_false_benign'], 0)


if __name__ == '__main__':
    unittest.main()
