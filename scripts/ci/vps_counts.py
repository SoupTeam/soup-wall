# SPDX-License-Identifier: Apache-2.0
"""Strict result parsing for the standalone VPS Linux driver lane."""
import re


def validate_target(repository, sha):
    if repository != 'soup-wall' or re.fullmatch(r'[0-9a-f]{40}', sha) is None:
        raise ValueError('Require soup-wall and its complete lowercase source SHA')


def test_counts(reader, log, output):
    if reader != 'unittest':
        raise ValueError('Only the Linux unittest summary is supported here')
    totals = re.findall(r'^Ran (\d+) tests? in', log, re.MULTILINE)
    results = re.findall(r'^OK(?: \(([^\n]*)\))?$', log, re.MULTILINE)
    if len(totals) != 1 or len(results) != 1:
        raise ValueError('Missing or ambiguous executed unittest summary')
    details = {}
    for part in results[0].split(',') if results[0] else []:
        match = re.fullmatch(r'\s*(skipped|expected failures)=(\d+)\s*', part)
        if match is None or match[1] in details:
            raise ValueError('Unknown or repeated outcome category')
        details[match[1]] = int(match[2])
    skipped = details.get('skipped', 0)
    expected = details.get('expected failures', 0)
    passed = int(totals[0]) - skipped - expected
    if passed <= 0:
        raise ValueError('No executed passing tests')
    counts = {'passed': passed, 'failed': 0, 'skipped': skipped}
    if expected:
        counts['expected_failed'] = expected
    return counts
