#!/usr/bin/env python3
"""Write the UNSIGNED freeze-anchor document for the owner to sign (does not freeze, sign or approve anything).

Usage: make_freeze_anchor.py --out FILE_OUTSIDE_REPO --approved-by @owner --approved-at ISO8601 --decision-ref REF
                             [--custodian-commitment HEX]
The owner then signs it on their own device:
    ssh-keygen -Y sign -f <owner_private_key> -n sou13-cp2-freeze FILE      (-> FILE.sig)
Run it only after the manifest has been frozen by the owner's explicit decision (docs/CP2_TRUST_ANCHOR.md)."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13cp2 import ROOT  # noqa: E402
from sou13cp2.anchor import _inside, anchor_document  # noqa: E402
from sou13cp2.pipeline import FULL_MANIFEST_FILE, PUBLIC_VIEW_FILE, current_artefact_digests  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True)
    ap.add_argument('--approved-by', required=True)
    ap.add_argument('--approved-at', required=True)
    ap.add_argument('--decision-ref', required=True)
    ap.add_argument('--custodian-commitment')
    args = ap.parse_args()
    if _inside(args.out, ROOT):
        sys.exit('the anchor must be written outside the repository')
    doc = anchor_document(
        full_manifest=json.loads((ROOT / FULL_MANIFEST_FILE).read_text(encoding='utf-8')),
        public_view=json.loads((ROOT / PUBLIC_VIEW_FILE).read_text(encoding='utf-8')),
        artefact_digests=current_artefact_digests(ROOT), approved_by=args.approved_by, approved_at=args.approved_at,
        decision_ref=args.decision_ref, custodian_commitment=args.custodian_commitment,
        package_manifest_sha256=(json.loads((ROOT / 'handoff/PACKAGE_DIGESTS.json').read_text(encoding='utf-8'))
                                 ['package_manifest_sha256'] if (ROOT / 'handoff/PACKAGE_DIGESTS.json').is_file() else None))
    Path(args.out).write_text(json.dumps(doc, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({'written': args.out, 'sign_with': f'ssh-keygen -Y sign -f <owner_key> -n sou13-cp2-freeze {args.out}'}))


if __name__ == '__main__':
    main()
