#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Export the fixed diagnostic experiment without hiding semantic misses."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('protocol', Path(__file__).with_name('evaluate-qwen-separated-shadow.py'))
protocol = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protocol)


def load(path):
    return json.loads(path.read_text(encoding='utf-8'))


def build(run, prepared, old_path):
    identity = load(run / 'identity.json')
    summary = load(run / 'summary.json')
    if not summary['complete'] or summary['observations'] != 8:
        raise ValueError('diagnostic run incomplete')
    if identity['selected_ids'] != list(protocol.IDS):
        raise ValueError('fixed selection changed')
    if identity['classification_prompt'] != protocol.CLASSIFY or identity['evidence_prompt'] != protocol.EXTRACT:
        raise ValueError('prompt identity changed')
    for name, expected in [('requests.jsonl', protocol.previous.REQUEST_SHA), ('references.jsonl', protocol.previous.REFERENCE_SHA)]:
        if protocol.previous.sha(prepared / name) != expected:
            raise ValueError('original inputs changed')
    requests = {r['request_id']: r for r in (json.loads(s) for s in (prepared / 'requests.jsonl').read_text(encoding='utf-8').splitlines())}
    refs = {r['request_id']: r for r in (json.loads(s) for s in (prepared / 'references.jsonl').read_text(encoding='utf-8').splitlines())}
    old = {c['reference']['request_id']: c for c in load(old_path)['cases']}
    raw = (run / 'observations.jsonl').read_bytes()
    observations = [json.loads(s) for s in raw.decode('utf-8').splitlines()]
    if [r['request_id'] for r in observations] != list(protocol.IDS):
        raise ValueError('missing/reordered/duplicate observations')
    classification = Counter()
    format_errors = Counter()
    evidence_status = Counter()
    cases = []
    for row in observations:
        key = row['request_id']
        ref, request = refs[key], requests[key]
        if not row['input_sha256'] == ref['input_sha256'] == request['input_sha256'] == old[key]['reference']['input_sha256']:
            raise ValueError('case hashes mismatch')
        stage_a, stage_b = row['classification'], row['evidence']
        if stage_a['status'] == 'valid':
            value = protocol.decode(stage_a['raw_response'], stage_a['prompt_tokens'])
            protocol.validate_class(value)
            if value != stage_a['value']: raise ValueError('classification changed')
            classification[ref['expected'] + '->' + value['assessment']] += 1
        else:
            classification[ref['expected'] + '->format_or_transport_error'] += 1
            format_errors['classification: ' + stage_a.get('error', 'missing')] += 1
        evidence_status[stage_b['status']] += 1
        if stage_b['status'] == 'valid':
            value = protocol.decode(stage_b['raw_response'], stage_b['prompt_tokens'])
            spans = protocol.validate_evidence(value, request['input'])
            if value != stage_b['value'] or spans != stage_b['validation']:
                raise ValueError('evidence changed')
            if not value['evidence']: evidence_status['valid_but_empty'] += 1
        elif stage_b['status'] == 'error':
            format_errors['evidence: ' + stage_b.get('error', 'missing')] += 1
        cases.append({'reference': ref, 'previous_observation': old[key]['observation'], 'observation': row})
    missed = next(c for c in cases if c['reference']['request_id'] == 'r0055')
    return {'protocol': 'separated-classification-evidence-v1', 'complete': True,
            'candidate_source_commit': 'd454e3f', 'production_authority': False,
            'identity': identity, 'summary': summary,
            'observations_sha256': hashlib.sha256(raw).hexdigest(),
            'previous_report_sha256': protocol.previous.sha(old_path),
            'classification_counts': dict(classification), 'format_errors': dict(format_errors),
            'evidence_status': dict(evidence_status),
            'previously_missed_attack_classification': missed['observation']['classification'],
            'stage_request_ms': {stage: [c['observation'][stage].get('elapsed_ms') for c in cases]
                                 for stage in ('classification', 'evidence')},
            'cases': cases}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--previous-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = build(args.run, args.prepared, args.previous_report)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({key: report[key] for key in ('classification_counts', 'format_errors', 'evidence_status', 'summary')}))
