#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Offline, single-profile coverage inventory; never grants semantic acceptance."""
import argparse
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('receipt_report', Path(__file__).with_name('sou218-openrouter-report.py'))
report = importlib.util.module_from_spec(spec)
spec.loader.exec_module(report)
a = report.adapter


def combine(sessions, retained_jobs, corpus):
    expected = {}
    for path in sorted(corpus.glob('*.json')):
        b = a.strict_json(path.read_bytes())
        if b['case_id'] in expected:
            raise ValueError('duplicate_corpus_case')
        expected[b['case_id']] = a.digest(b['source'].encode())
    if len(expected) != 30 or len(set(expected.values())) != 30:
        raise ValueError('expected_frozen_30_distinct_sources')
    selections = [(Path(s), None) for s in sessions]
    selections += [(Path(j).parent, Path(j).stem) for j in retained_jobs]
    rows, profiles = {}, set()
    for directory, selected in selections:
        audited = report.audit_session(directory)
        selected_rows = [r for r in audited['rows'] if selected is None or r['job'] == selected]
        if selected is not None and len(selected_rows) != 1:
            raise ValueError('retained_job_missing')
        for row in selected_rows:
            case = row['case_id']
            if expected.get(case) != row['source_sha256']:
                raise ValueError('frozen_source_mismatch')
            if case in rows:
                raise ValueError('duplicate_case_no_cherry_picking')
            bundle = a.strict_json((directory / (row['job'] + '.json')).read_bytes())
            body = a.request_body(bundle)
            # Every provider/request parameter except the per-case source message
            # must match. This includes schema, prompt, reasoning and token budget.
            body['messages'] = [body['messages'][0]]
            profiles.add(a.digest(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()))
            row = dict(row, session=directory.name)
            rows[case] = row
    if len(profiles) != 1:
        raise ValueError('mixed_request_profiles')
    answered = [r for r in rows.values() if 'response_sha256' in r]
    valid = [r for r in answered if r.get('offline_validation', {}).get('state') == 'structurally_valid_untrusted']
    missing = sorted(set(expected) - {r['case_id'] for r in answered})
    return {'profile_sha256': next(iter(profiles)), 'expected': 30,
            'responses': len(answered), 'structurally_valid': len(valid),
            'missing_responses': missing, 'all_responses_present': not missing,
            'rows': [rows[c] for c in sorted(rows)],
            'semantic_acceptance': False, 'native_protection_checked': False,
            'note': 'Response coverage only. Invalid answers remain visible; no retries or semantic acceptance.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--session', action='append', type=Path, default=[])
    p.add_argument('--retained-job', action='append', type=Path, default=[])
    p.add_argument('--corpus', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    result = combine(args.session, args.retained_job, args.corpus)
    a.save(args.output, json.dumps(result, ensure_ascii=False, indent=2).encode())
    print('Offline coverage:', result['responses'], '/ 30; structural:', result['structurally_valid'])


if __name__ == '__main__':
    main()
