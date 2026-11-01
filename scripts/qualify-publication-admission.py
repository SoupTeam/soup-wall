#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Retain exact-source offline verifier controls; never publish or approve a product."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'scripts/tests'))
import pilot_dossier as dossier
import publication_readiness as readiness
from roadmap_support import safe_file, write_private

MODULES = ('test_validate_candidate', 'test_publication_readiness', 'test_pilot_dossier',
           'test_pilot_runtime_identity', 'test_roadmap_support')
FILES = ('scripts/validate_candidate.py', 'scripts/validate_candidate.sh',
         'scripts/publication_readiness.py', 'scripts/qualify-publication-admission.py',
         'scripts/tests/test_validate_candidate.py', 'scripts/tests/test_publication_readiness.py',
         '.github/workflows/release.yml')


def raw_json(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n').encode()


def real_refusal():
    """Run the consumer on actual public retained evidence, no runtime fixtures."""
    selection_raw = dossier.git_bytes(ROOT, 'HEAD', 'docs/operations/evidence/sou129/selection.json')
    selection = dossier.parse(selection_raw)
    stored_raw = dossier.git_bytes(ROOT, 'HEAD', 'docs/operations/evidence/sou129/current-dossier/dossier.json')
    with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as external:
        root = Path(temporary)
        refs = [selection['support_index'], selection['workload']]
        refs += [entry['file'] for entry in selection['evidence']]
        for ref in refs:
            raw = dossier.git_bytes(ROOT, selection['candidate']['commit'], ref['path'])
            if hashlib.sha256(raw).hexdigest() != ref['sha256']:
                raise ValueError('retained_evidence_digest_mismatch')
            destination = root / ref['path']
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        def reference(name, raw):
            (root / name).write_bytes(raw)
            return {'path': name, 'sha256': readiness.sha(raw), 'member': None, 'member_sha256': None}
        index = {'format': readiness.VERSION, 'candidate': selection['candidate'],
                 'scope': readiness.SCOPE, 'candidate_manifest_sha256': 'a' * 64,
                 'selection': reference('selection.json', selection_raw),
                 'dossier': reference('dossier.json', stored_raw),
                 'stages': [{'id': stage, 'report': selection['evidence'][0]['file']}
                            for stage in readiness.RUNTIME.STAGES]}
        index_path = root / 'readiness-index.json'
        index_path.write_bytes(raw_json(index))
        approval_path = Path(external) / 'approval.json'
        approval = {'format': readiness.APPROVAL_VERSION, 'candidate': index['candidate'],
                    'scope': readiness.SCOPE, 'index_sha256': readiness.sha(index_path.read_bytes()),
                    'candidate_manifest_sha256': 'a' * 64, 'decision': 'approved',
                    'operator': 'synthetic-refusal-control',
                    'roadmap_decisions': {'version': 'sw-support-decisions/1',
                                         'source': index['candidate']['commit'], 'decisions': []}}
        approval_path.write_bytes(raw_json(approval))
        result = readiness.verify(index_path, root, ROOT, index['candidate']['commit'],
                                  'a' * 64, approval_path)
        rebuilt = dossier.build(selection, root, ROOT)
        return {'input_kind': 'real-retained-public-dossier',
                'control_metadata': 'synthetic index/approval pins only; original reports unchanged',
                'candidate': selection['candidate'], 'stored_status': dossier.parse(stored_raw)['status'],
                'recomputed_status': rebuilt['status'], 'consumer': result,
                'observations': [{'area': row['item'], 'status': row['status'],
                    'counts': [o['counts'] for o in row['observations']]} for row in rebuilt['ledger']],
                'selection_sha256': readiness.sha(selection_raw), 'stored_dossier_sha256': readiness.sha(stored_raw)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='new private output directory')
    parser.add_argument('--consumer-only', action='store_true',
                        help='only new offline consumer controls; related native producer suites remain separate')
    args = parser.parse_args()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT))
    modules = MODULES[:2] if args.consumer_only else MODULES
    tests = unittest.defaultTestLoader.loadTestsFromNames(modules)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=1).run(tests)
    try:
        actual = real_refusal()
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        # Always retain a failed report even when source/evidence prerequisites
        # are absent. Missing historical Git objects never mean success.
        actual = {'input_kind': 'real-retained-public-dossier', 'recomputed_status': 'unverified',
                  'consumer': {'status': 'blocked', 'dossier_status': 'unverified',
                               'blockers': ['real_dossier_unavailable']}}
    passed = result.wasSuccessful() and actual['consumer']['status'] == 'blocked' and \
        actual['recomputed_status'] == actual['consumer']['dossier_status'] == 'NOT_READY'
    receipt = dossier.git_json(ROOT, commit, 'docs/operations/evidence/sou176/verification-receipt.json')
    report = {'format': 'sw-publication-admission-qualification/1',
              'status': 'passed' if passed else 'failed',
              'meaning': 'offline verifier regression evidence only; product publication remains blocked',
              'source': {'commit': commit, 'tree': tree, 'dirty': dirty},
              'platform': {'os': sys.platform, 'python': sys.version.split()[0]},
              'tests': {'executed': result.testsRun, 'failures': len(result.failures),
                        'errors': len(result.errors), 'skipped': len(result.skipped),
                        'modules': list(modules)},
              'implementation_sha256': {name: readiness.sha(safe_file(ROOT / name, 2 * 1024 ** 2)) for name in FILES},
              'real_not_ready': actual,
              'scoped_retained_receipt': {'path': 'docs/operations/evidence/sou176/verification-receipt.json',
                  'sha256': readiness.sha(dossier.git_bytes(ROOT, commit, 'docs/operations/evidence/sou176/verification-receipt.json')),
                  'scope': 'public receipt preserved; private scoped raw archive not accessed or requalified'},
              'paid_api_calls': 0, 'actual_publication_attempts': 0,
              'limits': ['Synthetic positive fixtures prove verifier logic only.',
                         'Publication spies execute owned functions, not real publishers.',
                         'No native runtime, model effectiveness or complete-product readiness claim.']}
    # Confirm the receipt is valid parsed public evidence, without copying its data.
    if not receipt:
        raise ValueError('retained_receipt_missing')
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    write_private(args.output, 'report.json', raw_json(report))
    write_private(args.output, 'tests.txt', stream.getvalue().encode())
    print(json.dumps({'status': report['status'], 'source': commit, 'tests': report['tests'],
                      'real_dossier': actual['consumer']['status'], 'report_sha256': readiness.sha(raw_json(report))}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
