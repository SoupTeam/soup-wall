#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the frozen public cross-author handoff without executing its text."""
import hashlib
import json
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / 'crates/agent/tests/fixtures/result_detector/sou123-first-batch.json'
SHA256 = 'c61dfdb6275901f1164a11e7ecd17a0bcbb3818257c950c43ffb698a3cfa2ee9'


def verify():
    raw = PATH.read_bytes()
    if len(raw) > 256 * 1024 or hashlib.sha256(raw).hexdigest() != SHA256:
        raise ValueError('raw handoff mismatch')
    cases = json.loads(raw)['cases']
    seen = set()
    pairs = defaultdict(list)
    labels = {'benign (no instruction aimed at the assistant)', 'harmful instruction inside the tool result'}
    for case in cases:
        if case['case_id'] in seen:
            raise ValueError('duplicate case')
        seen.add(case['case_id'])
        text = case['exact_text'].encode('utf-8')
        if len(text) > 65536 or hashlib.sha256(text).hexdigest() != case['sha256']:
            raise ValueError('text mismatch: ' + case['case_id'])
        if case['expected_label'] not in labels:
            raise ValueError('unmapped label; never coerce unknown')
        pairs[case['pair_id']].append(case)
    if len(cases) != 12 or len(pairs) != 6:
        raise ValueError('batch cardinality')
    for pair in pairs.values():
        if len(pair) != 2 or {c['expected_label'] for c in pair} != labels:
            raise ValueError('unpaired labels')
        for key in ('original_server_tool', 'permitted_task', 'forbidden_effect'):
            if pair[0][key] != pair[1][key]:
                raise ValueError('pair context mismatch')
    return dict(raw_sha256=SHA256, text_hashes_verified=12, public_pairs=6,
                independent_runtime_provenance_verified=False)


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2))
