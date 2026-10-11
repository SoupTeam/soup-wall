#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate an ordered chain of SOU-13 gold-label addenda against a development label export (read-only).

  python scripts_cp2/validate_gold_addendum.py --exports DIR --split-manifest-sha256 HEX \
      --addendum addendum-v1.json [--addendum addendum-v2.json ...]

DIR is a CP2 export directory: labels/ and non_pilot/labels/ ({train,validation,calibration}.jsonl) and
EXPORT_MANIFEST.json, against which every label file is checked. The base (export manifest digest, its
cp2_version, the SOU-10 contract digest) is computed from these files, not taken from the addendum.
The report contains counts and errors only; no label values are printed. Nothing is written.
Exit status 1 on any error.
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13.cases import CONTRACT  # noqa: E402
from sou13.hashing import file_sha  # noqa: E402
from sou13gold.addendum import DEV_SPLITS, chain_errors  # noqa: E402


def read_rows(exports, manifest):
    """Pilot and non-pilot development label rows, each file checked against EXPORT_MANIFEST.json."""
    rows, errors = [], []
    for prefix in ('', 'non_pilot/'):
        for split in DEV_SPLITS:
            rel = f'{prefix}labels/{split}.jsonl'
            p = Path(exports) / rel
            if manifest['files_sha256'].get(rel) != file_sha(p):
                errors.append(f'{rel}: digest differs from EXPORT_MANIFEST.json')
            rows += [json.loads(x) for x in p.read_text(encoding='utf-8').splitlines() if x.strip()]
    return rows, errors


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--exports', type=Path, required=True)
    ap.add_argument('--split-manifest-sha256', required=True,
                    help='logical digest of the frozen full split manifest, as published by the owner')
    ap.add_argument('--addendum', type=Path, action='append', required=True, help='repeat in chain order')
    args = ap.parse_args(argv)
    if (args.exports / 'labels' / 'test.jsonl').exists():
        raise SystemExit('refusing: a test label file is present in the export directory')
    manifest_path = args.exports / 'EXPORT_MANIFEST.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    rows, errors = read_rows(args.exports, manifest)
    addenda = [json.loads(p.read_text(encoding='utf-8')) for p in args.addendum]
    base = {'dataset_version': manifest['cp2_version'], 'export_manifest_sha256': file_sha(manifest_path),
            'split_manifest_sha256': args.split_manifest_sha256, 'contract_sha256': CONTRACT['sha256']}
    errors += chain_errors(addenda, rows, base)
    transitions = Counter(f'{e["from_status"]}->{e["to_status"]}' for a in addenda for e in a.get('entries', []))
    print(json.dumps({'result': 'FAIL' if errors else 'PASS', 'addenda': len(addenda),
                      'statuses': [a.get('status') for a in addenda], 'development_rows': len(rows),
                      'transitions': dict(sorted(transitions.items())), 'errors': errors}, indent=2))
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
