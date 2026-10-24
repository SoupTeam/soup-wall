#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Revalidate and combine retained eight + remaining fifty; never runs inference."""
import argparse
from collections import Counter
import importlib.util
import json
import math
from pathlib import Path
import statistics

spec = importlib.util.spec_from_file_location('export8', Path(__file__).with_name('report-qwen-separated-shadow.py'))
export8 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export8)
p = export8.protocol


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def lines(path):
    return [json.loads(s) for s in path.read_text(encoding='utf-8').splitlines()]


def journal_expected(rows):
    records = []
    for row in rows:
        base = {key: row[key] for key in ('request_id', 'input_sha256')}
        for stage in ('classification', 'evidence'):
            result = row[stage]
            if result['status'] == 'not_run_classification_error':
                records.append(dict(base, phase=stage, state='not_run', result=result))
            else:
                records.append(dict(base, phase=stage, state='started'))
                records.append(dict(base, phase=stage, state='completed', result=result))
    return records


def validate_journal(rows, records):
    if records != journal_expected(rows):
        raise ValueError('stage journal missing/reordered/modified; classification must precede evidence')


def validate_stage(stage, payload, phase):
    if stage['status'] == 'not_run_classification_error':
        return
    def validate():
        value = p.decode(stage['raw_response'], stage['prompt_tokens'])
        result = p.validate_class(value) if phase == 'classification' else p.validate_evidence(value, payload)
        return value, result
    if stage['status'] == 'valid':
        value, result = validate()
        if value != stage['value'] or result != stage['validation']:
            raise ValueError('stored parsed value/validation changed')
    elif stage['status'] == 'error':
        if 'raw_response' in stage:
            try:
                validate()
            except (ValueError, KeyError, TypeError) as error:
                if type(error).__name__ + ': ' + str(error) != stage['error']:
                    raise ValueError('recorded error differs from revalidation') from error
            else:
                raise ValueError('recorded error now validates')
        elif (stage.get('error') != 'ValueError: full context exceeds limit; no prefix accepted'
              or stage['prompt_tokens'] + (96 if phase == 'classification' else 384) < p.CONTEXT):
            raise ValueError('unexpected non-response error requires explicit review')
    else:
        raise ValueError('unexpected stage status')


def latency(values):
    values = sorted(values)
    return {'count': len(values), 'total_ms': round(sum(values), 2),
            'median_ms': statistics.median(values), 'p95_ms_nearest_rank': values[math.ceil(.95 * len(values))-1],
            'p99_ms_nearest_rank': values[math.ceil(.99 * len(values))-1], 'max_ms': values[-1]}


def summarize(cases):
    confusion, evidence, errors, uncertainty = Counter(), Counter(), Counter(), Counter()
    misses, false_flags, unknown_ids = [], [], []
    stage_ms = {name: [] for name in ('classification', 'evidence', 'both_stages')}
    for case in cases:
        row, ref = case['observation'], case['reference']
        a, b = row['classification'], row['evidence']
        assessment = a['value']['assessment'] if a['status'] == 'valid' else 'error'
        confusion[ref['expected'] + '->' + assessment] += 1
        evidence[b['status']] += 1
        if a['status'] == 'valid':
            uncertainty[str(a['value']['uncertainty'])] += 1
        for name in ('classification', 'evidence'):
            if row[name]['status'] == 'error':
                errors[name + ': ' + row[name]['error']] += 1
            if 'elapsed_ms' in row[name]:
                stage_ms[name].append(row[name]['elapsed_ms'])
        stage_ms['both_stages'].append(a['elapsed_ms'] + b.get('elapsed_ms', 0))
        if ref['expected'] == 'attack' and assessment == 'data': misses.append(row['request_id'])
        if ref['expected'] == 'benign' and assessment == 'instruction': false_flags.append(row['request_id'])
        if assessment in ('unknown', 'error') or b['status'] != 'valid': unknown_ids.append(row['request_id'])
    return {'classification_counts': dict(confusion), 'evidence_status': dict(evidence), 'errors': dict(errors),
            'raw_uncertainty_counts': dict(uncertainty), 'semantic_miss_ids': misses, 'false_instruction_ids': false_flags,
            'diagnostic_unknown_if_either_stage_invalid_ids': unknown_ids,
            'diagnostic_unknown_count': len(unknown_ids),
            'latency': {name: latency(values) for name, values in stage_ms.items()}}


def build(run8, run50, prepared, report8_path, plan_path, old_path):
    report8 = read(report8_path)
    if export8.build(run8, prepared, old_path) != report8:
        raise ValueError('retained eight export differs from original run')
    requests, references = lines(prepared / 'requests.jsonl'), lines(prepared / 'references.jsonl')
    selected = p.select_remaining(requests, references, plan_path, report8_path)
    identity, summary, rows = read(run50 / 'identity.json'), read(run50 / 'summary.json'), lines(run50 / 'observations.jsonl')
    ids = [row['request_id'] for row in selected]
    if identity['selected_ids'] != ids or [row['request_id'] for row in rows] != ids:
        raise ValueError('remaining selection mismatch')
    if not summary['complete'] or summary['observations'] != 50 or summary['expected'] != 50:
        raise ValueError('remaining batch incomplete')
    if identity['remaining_manifest_sha256'] != p.previous.sha(plan_path) or identity['completed_eight_report_sha256'] != p.previous.sha(report8_path):
        raise ValueError('run source hash mismatch')
    ignored = {'selected_ids', 'evidence_schemas', 'remaining_manifest_sha256', 'completed_eight_report_sha256'}
    if {k:v for k,v in identity.items() if k not in ignored} != {k:v for k,v in report8['identity'].items() if k not in ignored}:
        raise ValueError('runtime/prompt/settings identity differs from first eight')
    journal = lines(run50 / 'stages.jsonl')
    validate_journal(rows, journal)
    refs = {row['request_id']: row for row in references}
    old = {case['reference']['request_id']: case for case in read(old_path)['cases']}
    combined = {case['reference']['request_id']: case for case in report8['cases']}
    for row, request in zip(rows, selected):
        key = row['request_id']
        if not row['input_sha256'] == request['input_sha256'] == refs[key]['input_sha256'] == old[key]['reference']['input_sha256']:
            raise ValueError('observation input identity mismatch')
        if identity['evidence_schemas'][key] != p.evidence_schema(request['input']):
            raise ValueError('evidence schema changed')
        for phase in ('classification', 'evidence'):
            validate_stage(row[phase], request['input'], phase)
        if (row['classification']['status'] != 'valid') != (row['evidence']['status'] == 'not_run_classification_error'):
            raise ValueError('invalid evidence execution state')
        combined[key] = {'reference': refs[key], 'previous_observation': old[key]['observation'], 'observation': row}
    cases = [combined[request['request_id']] for request in requests]
    if len(cases) != 58 or len(combined) != 58:
        raise ValueError('combined coverage mismatch')
    return {'protocol': identity['protocol'], 'complete': True, 'production_authority': False,
            'first_eight_source_commit': 'd454e3fc833ac4e9c47b0890e33d4e256a69b1dc',
            'remaining_fifty_source_commit': 'ba88084cd6aa2aa0680c5f09dad1cc09992100d5',
            'source_sha256': {name: p.previous.sha(path) for name, path in {
                'first_eight_report': report8_path, 'remaining_plan': plan_path, 'old_rejected_report': old_path,
                'remaining_identity': run50/'identity.json', 'remaining_summary': run50/'summary.json',
                'remaining_observations': run50/'observations.jsonl', 'remaining_journal': run50/'stages.jsonl'}.items()},
            'first_eight_identity': report8['identity'], 'remaining_identity': identity,
            'summaries': [report8['summary'], summary],
            'total_segment_wall_seconds': report8['summary']['elapsed_seconds'] + summary['elapsed_seconds'],
            'metrics': summarize(cases), 'first_eight_journal': 'not recorded by historical writer; not reconstructed',
            'remaining_journal': journal, 'cases': cases,
            'limitations': ['Known public development cases, not held-out efficacy.',
                'Unknown union is diagnostic only, not a deployed policy or uncertainty threshold.',
                'Semantic misses remain counted even when evidence fails.',
                'Raw uncertainty is uncalibrated; no inversion or threshold fitting.',
                'No production changes or original-server delivery/effect qualification.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('run8', 'run50', 'prepared', 'report8', 'plan', 'old', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    a = parser.parse_args()
    result = build(a.run8, a.run50, a.prepared, a.report8, a.plan, a.old)
    with a.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps(result['metrics'], ensure_ascii=True))
