# SPDX-License-Identifier: Apache-2.0
"""Command-line plumbing shared by the gold-addendum tools: owner trust-anchor options and the binding of the
split-manifest digest to the owner-signed freeze anchor (sou13cp2.anchor)."""
import json
from pathlib import Path

ANCHOR_OPTIONS = ('anchor', 'anchor-sig', 'allowed-signers', 'trusted-key-fpr', 'signer')


def add_anchor_args(ap, required=False):
    g = ap.add_argument_group('owner trust anchor (sou13-cp2-freeze; trust files outside every repository)')
    for opt in ANCHOR_OPTIONS:
        g.add_argument('--' + opt, required=required and opt != 'anchor-sig')


def anchor_config(args):
    cfg = {'anchor': args.anchor, 'signature': args.anchor_sig or (args.anchor + '.sig' if args.anchor else None),
           'allowed_signers': args.allowed_signers, 'trusted_key_fpr': args.trusted_key_fpr, 'signer': args.signer}
    return cfg if any(cfg.values()) else None


def verified_anchor(args, untrusted_roots):
    """(anchor or None, errors). None without errors when no anchor option was given."""
    cfg = anchor_config(args)
    if cfg is None:
        return None, []
    from sou13cp2.anchor import verify_anchor
    anchor, errors = verify_anchor(cfg, untrusted_roots=[Path(r) for r in untrusted_roots])
    return anchor, [f'anchor: {e}' for e in errors]


def split_manifest_digest(args, anchor):
    """The split-manifest digest an addendum base must carry: from the verified anchor, the command line, or
    both (then they must agree)."""
    given = getattr(args, 'split_manifest_sha256', None)
    signed = (anchor or {}).get('full_manifest_sha256')
    if anchor is not None and not signed:
        return None, ['anchor: no full_manifest_sha256']
    if given and signed and given != signed:
        return None, ['--split-manifest-sha256 differs from the full_manifest_sha256 in the owner-signed anchor']
    if not (given or signed):
        return None, ['a split-manifest digest is required (--split-manifest-sha256 or the owner trust anchor)']
    return signed or given, []


def load_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def emit(report):
    print(json.dumps(report, indent=2, ensure_ascii=False))
