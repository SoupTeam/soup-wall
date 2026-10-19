#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the SOU-35 unittest suite and print an exact JSON ledger. Exit 1 on any failure.

  python eval/sou35/run_tests.py                     public mode: only named private-artifact skips are allowed
  python eval/sou35/run_tests.py --require-private   owner mode: any skip (including a missing private pool) fails
"""
import argparse
import json
import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PRIVATE_SKIP = 'PRIVATE ARTIFACT MISSING'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--require-private', action='store_true')
    args = ap.parse_args(argv)
    sys.path.insert(0, str(ROOT / 'tests'))
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern='test_*.py',
                                                top_level_dir=str(ROOT / 'tests'))
    result = unittest.TextTestRunner(verbosity=1, stream=sys.stderr).run(suite)
    reasons = [reason for _, reason in result.skipped]
    bad_skips = reasons if args.require_private else [r for r in reasons if not r.startswith(PRIVATE_SKIP)]
    ledger = {'mode': 'owner (private required)' if args.require_private else 'public',
              'ran': result.testsRun, 'failed': len(result.failures), 'errored': len(result.errors),
              'skipped': len(result.skipped), 'unexpected_successes': len(result.unexpectedSuccesses),
              'skip_reasons': dict(Counter(reasons))}
    ledger['passed'] = ledger['ran'] - ledger['failed'] - ledger['errored'] - ledger['skipped']
    ledger['result'] = 'PASS' if result.wasSuccessful() and not bad_skips else 'FAIL'
    print(json.dumps(ledger, indent=2))
    return 0 if ledger['result'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
