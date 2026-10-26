#!/usr/bin/env python3
"""Retain current-source SOU-123 outcomes and complete finding attribution.

Uses the existing corpus reporter unchanged. No model or enforcement changes.
Exit 1 means the development gate failed, not that the diagnostic was lost.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sou123', ROOT / 'eval/sou123/run_corpus.py')
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_results(manifest, results, payload_dir):
    expected = {c['case_id'] for c in manifest['cases']}
    ids = [r['case_id'] for r in results]
    if len(ids) != len(set(ids)) or set(ids) != expected:
        raise ValueError('missing, duplicate or unexpected adapter result IDs')
    for row in results:
        payload = (payload_dir / (row['case_id'] + '.txt')).read_bytes()
        for finding in row.get('findings', []):
            if 'label' not in finding or 'span' not in finding:
                raise ValueError('adapter lacks full finding attribution')
            span = finding['span']
            if span is None:
                continue  # Aggregate findings have no invented source range.
            start, end = span['start'], span['end']
            if not 0 <= start <= end <= len(payload):
                raise ValueError('finding span outside original payload')
            payload[:start].decode('utf-8')
            payload[start:end].decode('utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adapter', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    manifest_path = ROOT / 'eval/sou123/manifest.json'
    payload_dir = ROOT / 'eval/sou123/payloads'
    policy = ROOT / 'profiles/pilot/linux-readonly-v1/policy.yaml'
    manifest = corpus.load_manifest(manifest_path)
    errors = corpus.verify_payloads(manifest, payload_dir)
    if errors:
        raise ValueError(errors)
    args.output_dir.mkdir(parents=True, exist_ok=False)
    command = [str(args.adapter.resolve()), '--manifest', str(manifest_path),
               '--payload-dir', str(payload_dir), '--policy', str(policy)]
    identity = {
        'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
        'tracked_diff_sha256': hashlib.sha256(subprocess.check_output(['git', 'diff', 'HEAD'], cwd=ROOT)).hexdigest(),
        'manifest_sha256': digest(manifest_path), 'policy_sha256': digest(policy),
        'adapter_sha256': digest(args.adapter), 'script_sha256': digest(__file__),
        'adapter_source_sha256': digest(ROOT / 'crates/agentfw/examples/result_inspection_corpus.rs'),
        'payloads': {c['case_id']: digest(payload_dir / (c['case_id'] + '.txt')) for c in manifest['cases']},
        'boundary': 'production policy preview; no original-server execution or effect witness',
    }
    (args.output_dir / 'identity.json').write_text(json.dumps(identity, indent=2) + '\n', encoding='utf-8')
    run = subprocess.run(command, capture_output=True, timeout=corpus.TIMEOUT)
    (args.output_dir / 'adapter.stdout.json').write_bytes(run.stdout)
    (args.output_dir / 'adapter.stderr.txt').write_bytes(run.stderr)
    run.check_returncode()
    results = json.loads(run.stdout)['results']
    validate_results(manifest, results, payload_dir)
    report = corpus.build_report(manifest, results, identity)
    (args.output_dir / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    by_id = {r['case_id']: r for r in results}
    lines = ['# Current-source false refusals', '',
             'Public development evidence only; all technical cases remain in report.json.', '',
             '| Case | Policy rule | Complete findings (including independent controls) |',
             '| --- | --- | --- |']
    for row in report['cases']:
        if row['outcome'] != 'false_refusal':
            continue
        findings = by_id[row['case_id']]['findings']
        text = '; '.join(f"{f['detector']}: {f['label']} [{f['severity']}; span={f['span']}]" for f in findings)
        lines.append(f"| {row['case_id']} | {row['rule']} | {text.replace('|', '&#124;')} |")
    (args.output_dir / 'false-refusals.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(report['totals']))
    return 0 if report['acceptance'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
