# SPDX-License-Identifier: Apache-2.0
"""Finite denominator and artifact identity controls; native evidence is separate."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('bench', ROOT / 'scripts/benchmark-native-results.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


class BenchmarkControls(unittest.TestCase):
    def test_summary_preserves_failed_and_unattempted_trials(self):
        rows = [{'condition': 'debug-idle', 'variant': 'measured-candidate', 'status': 'passed',
                 'burst_ms': 4000, 'burst_result_timing': [{'tracking_us': 2000}]},
                {'condition': 'debug-idle', 'variant': 'measured-candidate', 'status': 'failed'}]
        summary = B.summarize(rows)
        result = next(r for r in summary if r['condition'] == 'debug-idle' and r['variant'] == 'measured-candidate')
        self.assertEqual((result['planned'], result['attempted'], result['passed'], result['failed'], result['incomplete']),
                         (3, 2, 1, 1, 1))
        self.assertEqual(result['successful_burst_median_ms'], 4000)
        empty = next(r for r in summary if r['condition'] == 'distribution-idle')
        self.assertIsNone(empty['successful_burst_median_ms'])
        self.assertEqual(empty['incomplete'], 3)

    def test_manifest_rejects_changed_binary_wrong_profile_and_missing_variant(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'owned'; binary.write_bytes(b'public build fixture')
            entry = {'binary': str(binary), 'binary_sha256': B.sha(binary), 'source': 'a' * 40,
                     'rustc': 'rustc owned fixture', 'profile': 'dev'}
            value = {variant: {'dev': dict(entry), 'release': dict(entry, profile='release')}
                     for variant in ('instrumented-baseline', 'measured-candidate')}
            B.check_manifest(value)
            for mutate in (lambda r: r.pop('instrumented-baseline'),
                           lambda r: r['measured-candidate']['dev'].update(profile='release'),
                           lambda r: r['measured-candidate']['dev'].update(binary_sha256='b' * 64)):
                broken = copy.deepcopy(value); mutate(broken)
                with self.assertRaises(ValueError): B.check_manifest(broken)
            binary.write_bytes(b'changed fixture')
            with self.assertRaises(ValueError): B.check_manifest(value)


if __name__ == '__main__':
    unittest.main()
