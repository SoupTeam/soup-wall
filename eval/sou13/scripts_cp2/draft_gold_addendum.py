#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Draft the next SOU-13 gold addendum from recorded decisions (deterministic; owner workstation only).

  python scripts_cp2/draft_gold_addendum.py --exports DIR \
      (--split-manifest-sha256 HEX | --anchor F --allowed-signers F --trusted-key-fpr SHA256:... --signer ID) \
      [--previous addendum-v1.json ...] [--submission REVIEWER.json] --decisions OWNER.json --out addendum-vN.json

DIR is the CP2 export directory (labels/, non_pilot/labels/, EXPORT_MANIFEST.json). --submission is the
independent reviewer's own label vectors (schema/gold_reviewer_submission.schema.json), needed only for
individually confirmed cases; a recorded batch attestation goes into the owner decisions; --decisions is the
owner's record of verbatim approvals and per-case transitions (schema/gold_owner_decisions.schema.json). The
addendum uses schema/gold_addendum.schema.json. See sou13gold/draft.py for the binding rules.

The output keeps the owner's declared status: `approved` only if the extended chain passes every export-grade
rule; a `draft` lists what still blocks approval. The output must lie outside every Git work tree and is never
overwritten. Only counts, digests and error messages are printed; no label values.
Exit status 1 on any error.
"""
import argparse
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # never leave generated files in the checkout
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13.cases import CONTRACT  # noqa: E402
from sou13.hashing import file_sha  # noqa: E402
from sou13gold.addendum import AddendumError  # noqa: E402
from sou13gold.cli import add_anchor_args, emit, load_json, split_manifest_digest, verified_anchor  # noqa: E402
from sou13gold.draft import draft_addendum  # noqa: E402
from sou13gold.files import GoldFileError, dumps, read_export, write_new  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--exports', type=Path, required=True)
    ap.add_argument('--split-manifest-sha256')
    ap.add_argument('--previous', type=Path, action='append', default=[], help='issued addenda, in chain order')
    ap.add_argument('--submission', type=Path,
                    help='independent reviewer submission; required only for individually confirmed cases')
    ap.add_argument('--decisions', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    add_anchor_args(ap)
    args = ap.parse_args(argv)
    manifest, rows, _, errors = read_export(args.exports)
    anchor, anchor_errors = verified_anchor(args, untrusted_roots=[args.exports, ROOT])
    errors += anchor_errors
    split_digest, digest_errors = split_manifest_digest(args, anchor)
    errors += [] if anchor_errors else digest_errors
    if errors:
        emit({'result': 'FAIL', 'errors': errors})
        return 1
    base = {'dataset_version': manifest.get('cp2_version'),
            'export_manifest_sha256': file_sha(args.exports / 'EXPORT_MANIFEST.json'),
            'split_manifest_sha256': split_digest, 'contract_sha256': CONTRACT['sha256']}
    try:
        addendum, report = draft_addendum(rows, base, [load_json(p) for p in args.previous],
                                          load_json(args.submission) if args.submission else None,
                                          load_json(args.decisions))
        write_new(args.out, dumps(addendum))
    except (AddendumError, GoldFileError) as exc:
        emit({'result': 'FAIL', 'errors': getattr(exc, 'errors', [str(exc)])})
        return 1
    emit({'result': 'WRITTEN', 'out': args.out.name, 'anchored': anchor is not None, **report})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
