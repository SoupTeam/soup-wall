#!/usr/bin/env python3
"""Validate CP2 artefacts (taxonomy, manifest, records, leakage, exports, JSON Schema, CP1 validator, trust anchor).

Usage: validate_cp2.py [--root DIR] [--skip-cp1]
                       [--anchor FILE [--anchor-sig FILE] --allowed-signers FILE --trusted-key-fpr SHA256:... --signer ID]
Trust-anchor options may also come from SOU13_CP2_ANCHOR / _ANCHOR_SIG / _ALLOWED_SIGNERS / _TRUSTED_KEY_FPR / _SIGNER.
allowed_signers must lie outside the repository; the fingerprint must be obtained from an owner-controlled channel
(docs/CP2_TRUST_ANCHOR.md). A FROZEN manifest fails without a verified anchor. Every verification attempt with a configured anchor
(successful or failed) is appended to anchor_attempts.jsonl next to the anchor or to --attempt-log (outside the
repository). Exit code 1 on failure."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13cp2 import ROOT  # noqa: E402
from sou13cp2.anchor import config_from_env  # noqa: E402
from sou13cp2.pipeline import validate  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default=str(ROOT))
    ap.add_argument('--skip-cp1', action='store_true')
    for opt in ('anchor', 'anchor-sig', 'allowed-signers', 'trusted-key-fpr', 'signer', 'attempt-log'):
        ap.add_argument('--' + opt)
    args = ap.parse_args()
    cfg = config_from_env(anchor=args.anchor, signature=args.anchor_sig, allowed_signers=args.allowed_signers,
                          trusted_key_fpr=args.trusted_key_fpr, signer=args.signer, attempt_log=args.attempt_log)
    report = validate(Path(args.root), run_cp1=not args.skip_cp1, anchor_cfg=cfg)
    print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    sys.exit(0 if report['result'] == 'PASS' else 1)


if __name__ == '__main__':
    main()
