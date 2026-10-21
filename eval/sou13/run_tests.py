#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the SOU-13 suites (tests/ = CP1, tests_cp2/ = CP2) and print an exact ledger.

  python eval/sou13/run_tests.py                      public data-free mode (CI)
  python eval/sou13/run_tests.py --expect-skipped N   also fail if the skip count is not exactly N
  python eval/sou13/run_tests.py --require-private    private run: no private-artifact skip is allowed

Public mode skips only tests whose named private artifacts are absent (see _testsupport.py); every skip
reason is listed. --require-private sets SOU13_REQUIRE_PRIVATE=1, so a missing artifact becomes an error.
Exit status 1 on any failure, error, unexpected success or skip-count mismatch.
"""
import argparse
import json
import os
import sys
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SUITES = ('tests', 'tests_cp2')


def run_suite(name, verbosity):
    suite = unittest.defaultTestLoader.discover(str(ROOT / name), pattern='test_*.py', top_level_dir=str(ROOT / name))
    result = unittest.TextTestRunner(verbosity=verbosity, stream=sys.stderr).run(suite)
    return {'ran': result.testsRun,
            'passed': result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped)
            - len(result.expectedFailures) - len(result.unexpectedSuccesses),
            'failed': len(result.failures), 'errored': len(result.errors), 'skipped': len(result.skipped),
            'unexpected_successes': len(result.unexpectedSuccesses),
            'skip_reasons': dict(Counter(reason for _, reason in result.skipped).most_common())}


def main(argv=None):
    if sys.version_info >= (3, 14):
        print('SOU-13 frozen CP1 evaluation does not support Python 3.14+: '
              'stdlib shlex defers a collections import inside the guarded fixture. '
              'Use the reviewed Python 3.12 environment; do not bypass the import guard.', file=sys.stderr)
        return 2
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--require-private', action='store_true')
    ap.add_argument('--expect-skipped', type=int)
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args(argv)
    if args.require_private:
        os.environ['SOU13_REQUIRE_PRIVATE'] = '1'
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    sys.dont_write_bytecode = True
    ledger = {name: run_suite(name, 2 if args.verbose else 1) for name in SUITES}
    keys = ('ran', 'passed', 'failed', 'errored', 'skipped', 'unexpected_successes')
    total = {k: sum(s[k] for s in ledger.values()) for k in keys}
    problems = []
    if total['failed'] or total['errored'] or total['unexpected_successes']:
        problems.append('failures, errors or unexpected successes')
    if args.expect_skipped is not None and total['skipped'] != args.expect_skipped:
        problems.append(f'skipped {total["skipped"]}, expected exactly {args.expect_skipped}')
    print(json.dumps({'mode': 'private (strict)' if args.require_private else 'public data-free',
                      'result': 'FAIL' if problems else 'PASS', 'problems': problems, 'total': total,
                      'suites': ledger}, indent=2))
    return 1 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
