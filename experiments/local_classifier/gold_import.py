# SPDX-License-Identifier: Apache-2.0
"""Convert an externally reviewed, verified SOU-13 Gold development export."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

from experiments.local_classifier.model import ACTIONS
from experiments.local_classifier.pilot import read_json, validate_dataset

SPLITS = ('train', 'validation', 'calibration')


def bounded_member(root: Path, relative: str) -> bytes:
    if (not isinstance(relative, str) or not relative or '\\' in relative or ':' in relative
            or PurePosixPath(relative).is_absolute() or '..' in PurePosixPath(relative).parts
            or PurePosixPath(relative).as_posix() != relative):
        raise ValueError('canonical relative export member required')
    path = root / relative
    for ancestor in (path, *path.parents):
        if ancestor == root:
            break
        if ancestor.is_symlink() or getattr(ancestor.lstat(), 'st_file_attributes', 0) & 0x400:
            raise ValueError('export member contains a link or reparse point')
    if not path.resolve().is_relative_to(root):
        raise ValueError('export member leaves its directory')
    with path.open('rb') as handle:
        value = handle.read(16 * 1024 * 1024 + 1)
    if len(value) > 16 * 1024 * 1024:
        raise ValueError('export member exceeds byte limit')
    return value


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _constant(_):
    raise ValueError('non-finite JSON constant')


def decode(data: bytes):
    return json.loads(data.decode('utf-8'), object_pairs_hook=_object, parse_constant=_constant)


def canonical(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def prepare(root: Path, verification: Path, expected_digest: str, review_reference: str,
            holdout_id: str, expected_cases: int = 179):
    """A verification receipt asserts prior checking; it does not authenticate human approval."""
    root = root.resolve()
    if not re.fullmatch('[0-9a-f]{64}', expected_digest):
        raise ValueError('lowercase owner-published manifest SHA-256 required')
    for value in (review_reference, holdout_id):
        if not isinstance(value, str) or not value.strip() or len(value) > 2048:
            raise ValueError('actual bounded release review and custodian identity required')
    receipt, receipt_hash = read_json(verification, 65536)
    if (any(receipt.get(key) != 'PASS' for key in ('result', 'self_consistency', 'anchored_integrity'))
            or receipt.get('manifest_sha256') != expected_digest):
        raise ValueError('authenticated successful Gold verification receipt required')
    manifest_bytes = bounded_member(root, 'GOLD_EXPORT_MANIFEST.json')
    if hashlib.sha256(manifest_bytes).hexdigest() != expected_digest:
        raise ValueError('export manifest differs from owner-published digest')
    manifest = decode(manifest_bytes)
    if (manifest.get('export_kind') != 'sou13_gold_dev_export'
            or manifest.get('status') != 'AUTHORIZED_DEVELOPMENT_EXPORT'
            or manifest.get('format_version') != 1
            or set(manifest.get('splits', ())) != set(SPLITS)):
        raise ValueError('authorized development-only Gold export required')
    counts = manifest.get('counts')
    if (not isinstance(counts, dict) or set(counts) != set(SPLITS)
            or any(type(n) is not int or n <= 0 for n in counts.values())
            or not 1 <= expected_cases <= 10000 or sum(counts.values()) != expected_cases):
        raise ValueError('Gold release counts differ from reviewed development scope')
    listed = manifest.get('files_sha256')
    if not isinstance(listed, dict) or not 1 <= len(listed) <= 128:
        raise ValueError('bounded Gold file manifest required')
    members, total = {}, 0
    for relative, digest in listed.items():
        parts = PurePosixPath(relative).parts
        if any('test' in part.lower() or 'custodian' in part.lower() for part in parts):
            raise ValueError('test or custodian material is outside development import')
        data = bounded_member(root, relative)
        total += len(data)
        if total > 64 * 1024 * 1024:
            raise ValueError('Gold export exceeds total byte limit')
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError('export member differs from verified file manifest')
        members[relative] = data
    authorization = decode(members['authorization/EXPORT_AUTHORIZATION.json'])
    permitted = authorization.get('permitted_use', {})
    if (authorization.get('status') != 'approved'
            or permitted.get('training_use_authorized') is not True
            or set(permitted.get('splits', ())) != set(SPLITS)):
        raise ValueError('explicit reviewed development training-use permission required')
    for key in ('license_id', 'terms_reference'):
        if not isinstance(permitted.get(key), str) or not permitted[key].strip():
            raise ValueError('dataset-use terms and reference required')
    public_digest = manifest.get('source', {}).get('public_view_sha256')
    if not isinstance(public_digest, str) or not re.fullmatch('[0-9a-f]{64}', public_digest):
        raise ValueError('frozen public manifest identity required')
    rows = []
    for split in SPLITS:
        def records(relative):
            return [decode(line) for line in members[relative].splitlines() if line.strip()]
        labels = records(f'labels/{split}.jsonl')
        inputs = records(f'model_inputs/{split}.jsonl')
        by_id = {row['id']: row for row in inputs}
        if (len(labels) != counts[split] or len(inputs) != len(by_id)
                or {row['id'] for row in labels} != set(by_id)):
            raise ValueError('Gold input/label IDs or counts differ')
        for label in labels:
            case_id = label['id']
            source = by_id[case_id]
            if (not re.fullmatch('S13C2-[0-9A-F]{32}', case_id) or label.get('label_status') != 'confirmed'
                    or label['split'] != split or source['split'] != split):
                raise ValueError('confirmed CP2 development cases only; no CP1 or test')
            targets, mask = label['per_action_targets'], label['known_mask']
            if (set(targets) != set(ACTIONS) or set(mask) != set(ACTIONS)
                    or any(type(mask[a]) is not int or mask[a] != int(targets[a] is not None) for a in ACTIONS)):
                raise ValueError('tri-state targets and exact known masks required')
            if (source['hashes'] != label['hashes']
                    or canonical(source['input']) != source['hashes']['input_sha256']):
                raise ValueError('original model input differs from reviewed input digest')
            rows.append({'id': case_id, 'family': label['leakage_group_id'], 'split': split,
                         'input': source['input'], 'labels': {**targets, 'unknown': label['unknown']}})
    dataset = {'format': 'soup-wall/classifier-development-dataset/1',
               'cases': sorted(rows, key=lambda row: (SPLITS.index(row['split']), row['id']))}
    validate_dataset(dataset, split_names=SPLITS, format_name=dataset['format'])
    data = (json.dumps(dataset, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + '\n').encode()
    if len(data) > 16 * 1024 * 1024:
        raise ValueError('converted dataset exceeds the training loader byte limit')
    approval = {'format': 'soup-wall/classifier-development-approval/1',
                'approval_reference': review_reference,
                'source': 'SOU-13 authorized Gold dev export; manifest SHA256 ' + expected_digest,
                'license': permitted['license_id'] + '; ' + permitted['terms_reference'],
                'dataset_sha256': hashlib.sha256(data).hexdigest(),
                'split_manifest_sha256': public_digest, 'holdout_id': holdout_id}
    provenance = {'format': 'soup-wall/gold-development-import/1',
                  'gold_export_manifest_sha256': expected_digest, 'verification_receipt_sha256': receipt_hash,
                  'dataset_sha256': approval['dataset_sha256'], 'counts': counts,
                  'source_file_sha256': listed, 'approval_reference': review_reference,
                  'importer_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  'training_started': False, 'test_opened': False}
    return data, approval, provenance


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gold-export', required=True, type=Path)
    parser.add_argument('--verification-report', required=True, type=Path)
    parser.add_argument('--expect-manifest-sha256', required=True)
    parser.add_argument('--review-reference', required=True)
    parser.add_argument('--holdout-id', required=True)
    parser.add_argument('--expected-cases', type=int, default=179)
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args(argv)
    if args.output_dir.exists():
        raise FileExistsError('preserve previous import; output directory must be new')
    if args.output_dir.resolve().is_relative_to(args.gold_export.resolve()):
        raise ValueError('import must not modify the original export directory')
    data, approval, provenance = prepare(args.gold_export, args.verification_report,
                                         args.expect_manifest_sha256, args.review_reference,
                                         args.holdout_id, args.expected_cases)
    args.output_dir.mkdir(parents=True)
    (args.output_dir / 'development.json').write_bytes(data)
    for name, value in (('development-review.json', approval), ('conversion.json', provenance)):
        (args.output_dir / name).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n',
                                          encoding='utf-8')
    print(json.dumps({'result': 'PASS', 'counts': provenance['counts'],
                      'dataset_sha256': approval['dataset_sha256'], 'training_started': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
