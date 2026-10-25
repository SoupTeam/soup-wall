# SPDX-License-Identifier: Apache-2.0
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('ledger_replay', Path(__file__).parents[1]/'replay-result-evidence.py')
r = importlib.util.module_from_spec(spec)
# Linux resource is required by this diagnostic supervisor, not production.
if os.name == 'posix':
    spec.loader.exec_module(r)


@unittest.skipUnless(os.name == 'posix' and Path('/usr/bin/time').exists(), 'Linux wait4 diagnostic')
class SupervisorTests(unittest.TestCase):
    def worker(self, body, timeout=10):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'worker'
            path.write_text('#!/usr/bin/python3\n'+body+'\n')
            path.chmod(0o700)
            return r.run(path, b'{}\n', timeout)

    def test_deadline_kills_and_reaps_owned_process_group(self):
        observation, value = self.worker('import time\ntime.sleep(60)', .1)
        self.assertEqual(observation['reason'], 'timeout')
        self.assertIsNone(value)
        self.assertIsNotNone(observation['returncode'])
        self.assertLess(observation['elapsed_ms'], 2000)

    def test_measures_actual_worker_memory_and_rejects_invalid_response(self):
        observation, value = self.worker('x=bytearray(32*1024*1024)\nprint("{}")')
        self.assertIsNone(observation['reason'])
        self.assertEqual(value, {})
        self.assertGreaterEqual(observation['actual_worker_peak_rss_bytes'], 32*1024*1024)
        observation, value = self.worker('print("not JSON")')
        self.assertEqual(observation['reason'], 'invalid_response')

    def test_address_space_failure_is_not_a_prediction(self):
        observation, value = self.worker('x=bytearray(600*1024*1024)\nprint("{}")')
        self.assertEqual(observation['reason'], 'worker_error')
        self.assertIsNone(value)


if __name__ == '__main__':
    unittest.main()
