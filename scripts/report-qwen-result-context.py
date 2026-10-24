#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify retained Qwen segments and export complete public development evidence."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def build(notes):
    prepared = notes / 'sou109-context-shadow-58'
    requests = [json.loads(s) for s in (prepared / 'requests.jsonl').read_text(encoding='utf-8').splitlines()]
    refs = [json.loads(s) for s in (prepared / 'references.jsonl').read_text(encoding='utf-8').splitlines()]
    folders = [notes / 'sou109-qwen-run-24ae770'] + [notes / f'sou109-qwen-run-e75c286-segment{i}' for i in range(1, 5)]
    identity = read(folders[0] / 'identity.json')
    for name, key in [('requests.jsonl', 'request_sha256'), ('references.jsonl', 'reference_sha256')]:
        if digest((prepared / name).read_bytes()) != identity[key]:
            raise ValueError('input identity mismatch')
    previous = b''
    segments = []
    for folder in folders:
        if read(folder / 'identity.json') != identity:
            raise ValueError('experiment identity changed')
        raw = (folder / 'observations.jsonl').read_bytes()
        if not raw.startswith(previous):
            raise ValueError('prior observations changed')
        if previous:
            resume = read(folder / 'resume.json')
            if resume['source_observations_sha256'] != digest(previous):
                raise ValueError('resume digest mismatch')
        summary = read(folder / 'summary.json')
        segments.append({'name': folder.name, 'observations_sha256': digest(raw),
                         'previous_count': len(previous.splitlines()), 'summary': summary,
                         'server_log_sha256': digest((folder / 'server.log').read_bytes())})
        previous = raw
    observations = [json.loads(s) for s in previous.decode().splitlines()]
    if len(observations) != 58 or len(requests) != 58 or len(refs) != 58:
        raise ValueError('incomplete batch')
    counts = Counter()
    errors = Counter()
    cases = []
    groups = {}
    for observation, request, reference in zip(observations, requests, refs):
        for key in ('request_id', 'input_sha256'):
            if observation[key] != request[key] or reference[key] != request[key]:
                raise ValueError('case identity mismatch')
        key = reference['expected'] + '->' + observation['assessment']
        counts[key] += 1
        group = reference['origin'].split('/')[0]
        groups.setdefault(group, Counter())[key] += 1
        if observation['status'] == 'error':
            errors[observation['error']] += 1
        cases.append({'reference': reference, 'observation': observation})
    if dict(counts) != segments[-1]['summary']['counts']:
        raise ValueError('summary mismatch')
    times = sorted(o['elapsed_ms'] for o in observations)
    aborted = []
    for name in ('sou109-qwen-run-8c29d0b', 'sou109-qwen-run-bfe4f40'):
        folder = notes / name
        aborted.append({'name': name, 'reason': 'manually stopped for memory pressure',
                        'summary': read(folder / 'summary.json'),
                        'identity': read(folder / 'identity.json'),
                        'observations': [json.loads(s) for s in (folder / 'observations.jsonl').read_text().splitlines()]})
    return {'decision': 'reject_this_candidate_protocol_for_production',
            'complete_observations': 58, 'production_authority': False,
            'dataset': 'public development, not held out', 'identity': identity,
            'counts': dict(counts), 'groups': groups, 'errors': dict(errors),
            'latency_ms_including_errors_timeouts': {
                'median': (times[28] + times[29]) / 2,
                'p95_nearest_rank': times[math.ceil(.95 * len(times)) - 1],
                'p99_nearest_rank': times[math.ceil(.99 * len(times)) - 1],
                'total': sum(times)},
            'segment_wall_seconds': sum(s['summary'].get('segment_elapsed_seconds', s['summary'].get('elapsed_seconds', 0)) for s in segments),
            'segments': segments, 'aborted_resource_attempts': aborted, 'cases': cases}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--notes', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = build(args.notes)
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({k: report[k] for k in ('counts', 'groups', 'errors', 'latency_ms_including_errors_timeouts', 'segment_wall_seconds')}))
