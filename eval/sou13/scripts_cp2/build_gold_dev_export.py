#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Plan or build the authorised SOU-13 gold development export (train/validation/calibration only).

  python scripts_cp2/build_gold_dev_export.py --dev-package DIR --anchor F --allowed-signers F \
      --trusted-key-fpr SHA256:... --signer ID --addendum addendum-v1.json [...] \
      --reviewer-submission REVIEWER.json [...] --plan
  python scripts_cp2/build_gold_dev_export.py ... --addendum addendum-v1.json [...] \
      --authorization EXPORT_AUTHORIZATION.json --out EXPORT_DIR

DIR is the CP2 development review package (dev_review_package/), authenticated through the owner-signed freeze
anchor. --plan validates the chain at export grade, proves every confirmation against the reviewer's own
submission files, and prints the base, the addendum chain head, the gold-set digest, the per-split counts and the
release questions for which the export authorization must cite recorded decisions (no label values; nothing
written). Citations are checked for presence only; their content is a human release check.
Building additionally requires an approved authorization (schema/gold_export_authorization.schema.json) and
writes EXPORT_DIR plus EXPORT_DIR.digest.json (the statement the owner signs) outside every Git work tree.
The sealed test split is never read. See sou13gold/export.py.
Exit status 1 on any error.
"""
import argparse
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # never leave generated files in the checkout
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13gold.cli import add_anchor_args, anchor_config, emit, load_json  # noqa: E402
from sou13gold.export import ExportError, build, load_sources, plan  # noqa: E402
from sou13gold.files import GoldFileError  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--dev-package', type=Path, required=True)
    ap.add_argument('--addendum', type=Path, action='append', required=True, help='repeat in chain order')
    ap.add_argument('--reviewer-submission', type=Path, action='append', default=[],
                    help='the independent reviewer\'s own submission files (repeatable); required when any case '
                         'is confirmed individually')
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--authorization', type=Path)
    ap.add_argument('--out', type=Path)
    add_anchor_args(ap, required=True)
    args = ap.parse_args(argv)
    if args.authorization and not args.out:
        ap.error('--authorization needs --out')
    try:
        src = load_sources(args.dev_package, anchor_config(args), untrusted_roots=[ROOT])
        submissions = [load_json(x) for x in args.reviewer_submission]
        if args.plan:
            p = plan(src, [load_json(x) for x in args.addendum], submissions)
            emit({'result': 'PLAN', 'base': p['base'], 'addendum_chain': p['addendum_chain'],
                  'gold_set': {'sha256': p['gold_set_sha256'], 'counts': p['counts']},
                  'confirmation_channels': p['confirmation_channels'],
                  'release_questions': p['release_questions']})
            return 0
        emit(build(src, args.addendum, submissions, args.authorization, args.out, repo_root=ROOT.parents[1]))
        return 0
    except (ExportError, GoldFileError) as exc:
        emit({'result': 'FAIL', 'errors': getattr(exc, 'errors', [str(exc)])})
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
