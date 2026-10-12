# SPDX-License-Identifier: Apache-2.0
"""Train reviewed development data without test; a separate custodian evaluates once."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

from experiments.local_classifier.model import Config, LinearClassifier, input_identity
from experiments.local_classifier.pilot import (
    digest, environment, evaluate, load_baseline, read_json, reserve_reviewed_run,
    train_model, validate_dataset, write_json,
)

LAYOUTS = {
    'development': ('train', 'validation', 'calibration'),
    'holdout': ('holdout',),
}


def load_part(dataset: Path, approval: Path, kind: str):
    """Review files assert provenance, not authenticated reviewer approval."""
    review, review_hash = read_json(approval, 16384)
    required = {'format', 'approval_reference', 'source', 'license', 'dataset_sha256',
                'split_manifest_sha256', 'holdout_id'}
    if kind == 'holdout':
        required.add('development_approval_sha256')
    if set(review) != required or review['format'] != f'soup-wall/classifier-{kind}-approval/1':
        raise ValueError('explicit reviewed ' + kind + ' approval required')
    for key in ('approval_reference', 'source', 'license', 'holdout_id'):
        value = review[key]
        if not isinstance(value, str) or not value.strip() or len(value) > 2048:
            raise ValueError('bounded review, source, license and holdout identity required')
    for key in required:
        if key.endswith('_sha256') and (not isinstance(review[key], str)
                                       or not re.fullmatch('[0-9a-f]{64}', review[key])):
            raise ValueError('lowercase SHA-256 digest required: ' + key)
    record, dataset_hash = read_json(dataset, 16 * 1024 * 1024)
    if review['dataset_sha256'] != dataset_hash:
        raise ValueError('dataset differs from reviewed digest')
    splits = validate_dataset(record, split_names=LAYOUTS[kind],
                              format_name=f'soup-wall/classifier-{kind}-dataset/1')
    return splits, review, review_hash


def check_linkage(development, dev_review, dev_review_hash, heldout, test_review):
    if test_review['development_approval_sha256'] != dev_review_hash:
        raise ValueError('heldout approval does not bind reviewed development provenance')
    for key in ('split_manifest_sha256', 'holdout_id'):
        if dev_review[key] != test_review[key]:
            raise ValueError('development and holdout differ in ' + key)
    public = [row for split in development.values() for row in split]
    test = heldout['holdout']
    if {r['id'] for r in public} & {r['id'] for r in test}:
        raise ValueError('case identity shared across development and holdout')
    if {r['family'] for r in public} & {r['family'] for r in test}:
        raise ValueError('tool family shared across development and holdout')
    if {input_identity(r['input']) for r in public} & {input_identity(r['input']) for r in test}:
        raise ValueError('semantic duplicate shared across development and holdout')


def run_environment():
    result = environment()
    result['source_sha256']['custodian.py'] = digest(Path(__file__))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('train', 'evaluate'))
    parser.add_argument('--development-dataset', required=True, type=Path)
    parser.add_argument('--development-approval', required=True, type=Path)
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--model-dir', type=Path)
    parser.add_argument('--holdout-dataset', type=Path)
    parser.add_argument('--holdout-approval', type=Path)
    parser.add_argument('--baseline-path', type=Path)
    parser.add_argument('--additional-classifier', action='append', default=[], metavar='ID=DIRECTORY',
                        help='include a reviewed, hash-authorized classifier in the same single run')
    parser.add_argument('--run-authorization', type=Path)
    parser.add_argument('--run-ledger-dir', type=Path)
    parser.add_argument('--epochs', type=int, default=60)
    parser.add_argument('--dimensions', type=int, default=512)
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args(argv)
    development, dev_review, dev_review_hash = load_part(
        args.development_dataset, args.development_approval, 'development')
    if args.mode == 'train':
        if args.additional_classifier or any(value is not None for value in (args.holdout_dataset, args.holdout_approval,
                                              args.run_authorization, args.run_ledger_dir)):
            parser.error('training accepts no holdout inputs or run authorization')
        if args.output_dir is None:
            parser.error('training requires --output-dir')
        if args.output_dir.exists() and any(args.output_dir.iterdir()):
            raise ValueError('output directory must be new or empty; preserve evidence')
        config = Config(epochs=args.epochs, dimensions=args.dimensions, seed=args.seed)
        # Validation is retained only for provenance/partition checks. Only these
        # two explicitly reviewed splits enter fitting and threshold selection.
        model, report = train_model(development['train'], development['calibration'], config)
        report.update({'format': 'soup-wall/local-classifier-training/1',
                       'mode': 'approved_training', 'data_layout': 'custodian-heldout/1',
                       'approval': dev_review, 'development_approval_sha256': dev_review_hash,
                       'official_heldout_run': False, 'environment': run_environment(),
                       'api_requests': 0, 'api_cost_usd': 0, 'tool_executions': 0,
                       'recommendation': 'await_independent_custodian_comparison'})
        args.output_dir.mkdir(parents=True, exist_ok=True)
        write_json(args.output_dir / 'model.json', model.artifact())
        report['model_sha256'] = digest(args.output_dir / 'model.json')
        write_json(args.output_dir / 'training.json', report)
        print(json.dumps({'mode': 'approved_training', 'data_layout': 'custodian-heldout/1',
                          'model_sha256': report['model_sha256'],
                          'official_heldout_run': False, 'output': str(args.output_dir)}))
        return 0

    if any(value is None for value in (args.model_dir, args.holdout_dataset, args.holdout_approval,
                                      args.baseline_path, args.run_authorization, args.run_ledger_dir)):
        parser.error('evaluation requires frozen model/baseline, reviewed holdout and external ledger')
    heldout, test_review, _ = load_part(args.holdout_dataset, args.holdout_approval, 'holdout')
    check_linkage(development, dev_review, dev_review_hash, heldout, test_review)
    training, _ = read_json(args.model_dir / 'training.json', 65536)
    if (training.get('mode') != 'approved_training'
            or training.get('data_layout') != 'custodian-heldout/1'
            or training.get('approval') != dev_review
            or training.get('development_approval_sha256') != dev_review_hash):
        raise ValueError('frozen model provenance differs from reviewed development data')
    artifact, model_hash = read_json(args.model_dir / 'model.json', 16 * 1024 * 1024)
    if training.get('model_sha256') != model_hash:
        raise ValueError('frozen model changed after calibration')
    model = LinearClassifier.restore(artifact)
    if not model.calibrated:
        raise ValueError('model must be calibrated before evaluation')
    authorization, _ = read_json(args.run_authorization, 16384)
    if authorization.get('holdout_id') != test_review['holdout_id']:
        raise ValueError('run authorization differs from reviewed holdout identity')
    baseline, baseline_hash = load_baseline(args.baseline_path)
    extra_paths = {}
    for participant in args.additional_classifier:
        identity, separator, directory = participant.partition('=')
        if (not separator or not directory or not re.fullmatch('[a-z][a-z0-9_-]{0,63}', identity)
                or identity in extra_paths or identity in ('candidate', 'baseline') or len(extra_paths) >= 8):
            raise ValueError('up to eight unique additional classifier IDs and directories required')
        extra_paths[identity] = Path(directory)
    extra = {identity: load_baseline(path) for identity, path in extra_paths.items()}
    extra_hashes = {identity: loaded[1] for identity, loaded in extra.items()}
    test_hash = test_review['dataset_sha256']
    local = args.model_dir / ('.holdout-' + test_hash + '.reserved')
    if local.exists() or (args.model_dir / 'evaluation.json').exists():
        raise FileExistsError('evaluation already reserved or retained in model artifacts')
    external, reservation = reserve_reviewed_run(args.run_authorization, args.run_ledger_dir,
                                               args.model_dir, test_hash, model_hash, baseline_hash,
                                               extra_hashes)
    with local.open('x', encoding='utf-8') as handle:
        handle.write(json.dumps({'dataset_sha256': test_hash, 'model_sha256': model_hash,
                                 'baseline_sha256': baseline_hash,
                                 'additional_classifiers': extra_hashes}) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    report = {'format': 'soup-wall/local-classifier-evaluation/1',
              'mode': 'approved_shadow_pilot', 'data_layout': 'custodian-heldout/1',
              'official_heldout_run': True, 'approval': test_review,
              'development_approval': dev_review, 'development_approval_sha256': dev_review_hash,
              'model_sha256': model_hash, 'baseline_sha256': baseline_hash,
              'reviewed_run': reservation, 'environment': run_environment(),
              'candidate': evaluate(heldout['holdout'], model.classify),
              'baseline': evaluate(heldout['holdout'], baseline),
              'additional_classifier_sha256': extra_hashes,
              'additional_classifiers': {identity: evaluate(heldout['holdout'], loaded[0])
                                         for identity, loaded in extra.items()},
              'api_requests': 0, 'api_cost_usd': 0, 'tool_executions': 0,
              'recommendation': 'manual_continue_revise_or_reject_review_required'}
    write_json(args.model_dir / 'evaluation.json', report)
    receipt = {'format': 'soup-wall/classifier-run-result/1',
               'reservation_sha256': digest(external),
               'evaluation_sha256': digest(args.model_dir / 'evaluation.json'),
               'completed_at': datetime.now(timezone.utc).isoformat(),
               'run_id': reservation['authorization']['run_id'],
               'holdout_id': reservation['authorization']['holdout_id']}
    with external.with_suffix('.result.json').open('x', encoding='utf-8') as handle:
        handle.write(json.dumps(receipt, indent=2, allow_nan=False) + '\n')
        handle.flush()
        os.fsync(handle.fileno())
    print('Custodian comparison retained; no runtime adoption or execution authority granted.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
