#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate an ordered chain of SOU-13 gold-label addenda against a development label export (read-only).

  python scripts_cp2/validate_gold_addendum.py --exports DIR --split-manifest-sha256 HEX \
      --addendum addendum-v1.json [--addendum addendum-v2.json ...]
  python scripts_cp2/validate_gold_addendum.py --strict --exports DIR --anchor F --allowed-signers F \
      --trusted-key-fpr SHA256:... --signer ID --addendum addendum-v1.json [...]

DIR is a CP2 export directory: labels/ and non_pilot/labels/ ({train,validation,calibration}.jsonl) and
EXPORT_MANIFEST.json, against which every label file is checked. Any test or custodian file anywhere below DIR
(for example labels/test.jsonl or non_pilot/labels/test.jsonl) refuses the whole directory. The base (export
manifest digest, its cp2_version, the SOU-10 contract digest) is computed from these files, not taken from the
addendum. The split-manifest digest comes from --split-manifest-sha256 and/or the owner-signed freeze anchor
(full_manifest_sha256); when both are given they must agree.

Default mode validates approved and draft addenda as before (sou13gold.addendum.chain_errors).
--strict applies the export-grade rules (sou13gold.addendum.strict_errors: every addendum approved, approval
integrity, independent reviewer separate from the dataset owner, gold eligibility) to addenda of the
schema, requires the anchor, and lists the release questions (open questions of gold rows, and
Q-CP2-DECL-EVIDENCE for false gold labels) for which an export authorization must cite recorded decisions
(traceability only; whether a decision resolves its question is a human release check).
--reviewer-submission FILE (repeatable) also proves that every individually confirmed entry's reviewer_labels
are exactly the labels of the reviewer's own submission files. With the anchor, every batch attestation
(PROPOSED, pending maintainer review) must list the anchored development package among its reviewed artifacts.
The report contains counts and errors only; no label values are printed. Nothing is written.
Exit status 1 on any error.
"""
import argparse
import sys
from collections import Counter
from pathlib import Path

sys.dont_write_bytecode = True  # never leave generated files in the checkout
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13.cases import CONTRACT  # noqa: E402
from sou13.hashing import file_sha  # noqa: E402
from sou13gold.addendum import (apply_addenda, batch_artifact_errors, chain_errors, release_questions,  # noqa: E402
                                strict_errors)
from sou13gold.cli import add_anchor_args, emit, load_json, split_manifest_digest, verified_anchor  # noqa: E402
from sou13gold.draft import submission_binding_errors  # noqa: E402
from sou13gold.files import read_export  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--exports', type=Path, required=True)
    ap.add_argument('--split-manifest-sha256',
                    help='logical digest of the frozen full split manifest, as published by the owner')
    ap.add_argument('--addendum', type=Path, action='append', required=True, help='repeat in chain order')
    ap.add_argument('--strict', action='store_true', help='export-grade rules; requires the owner trust anchor')
    ap.add_argument('--reviewer-submission', type=Path, action='append', default=[],
                    help='reviewer submission files: every confirmation must carry exactly the submitted labels')
    add_anchor_args(ap)
    args = ap.parse_args(argv)
    manifest, rows, _, errors = read_export(args.exports)
    if manifest is None or any('test or custodian material' in e for e in errors):
        emit({'result': 'FAIL', 'mode': 'strict' if args.strict else 'legacy', 'errors': errors})
        return 1
    anchor, anchor_errors = verified_anchor(args, untrusted_roots=[args.exports, ROOT])
    errors += anchor_errors
    if args.strict and anchor is None and not anchor_errors:
        errors.append('--strict requires the owner trust anchor (--anchor, --allowed-signers, --trusted-key-fpr, '
                      '--signer)')
    split_digest, digest_errors = split_manifest_digest(args, anchor)
    errors += [] if anchor_errors else digest_errors
    addenda = [load_json(p) for p in args.addendum]
    if not errors:
        base = {'dataset_version': manifest.get('cp2_version'),
                'export_manifest_sha256': file_sha(args.exports / 'EXPORT_MANIFEST.json'),
                'split_manifest_sha256': split_digest, 'contract_sha256': CONTRACT['sha256']}
        errors += (strict_errors if args.strict else chain_errors)(addenda, rows, base)
        if anchor is not None and any(a.get('batch_attestations') for a in addenda):
            package = (anchor.get('package_manifest_sha256') or {}).get('dev_review_package')
            errors += (batch_artifact_errors(addenda, package) if package else
                       ['anchor: records no dev_review_package digest to bind the batch attestation to'])
        if args.reviewer_submission:
            errors += submission_binding_errors(addenda, [load_json(p) for p in args.reviewer_submission], rows)
    questions = {}
    if args.strict and not errors:
        questions = {q: len(ids) for q, ids in release_questions(apply_addenda(rows, addenda, base), rows).items()}
    transitions = Counter(f'{e["from_status"]}->{e["to_status"]}' for a in addenda for e in a.get('entries', []))
    emit({'result': 'FAIL' if errors else 'PASS', 'mode': 'strict' if args.strict else 'legacy',
          'anchored': anchor is not None, 'addenda': len(addenda), 'statuses': [a.get('status') for a in addenda],
          'development_rows': len(rows),
          'transitions': dict(sorted(transitions.items())),
          'release_questions_to_cite_in_authorization': questions, 'errors': errors})
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
