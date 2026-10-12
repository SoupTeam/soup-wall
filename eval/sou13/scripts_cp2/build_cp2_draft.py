#!/usr/bin/env python3
"""Build CP2 Phase 1 DRAFT artefacts (taxonomy, split manifest, label-separated exports, coverage).

Usage: build_cp2_draft.py            write artefacts in place (CP1 files are never written)
       build_cp2_draft.py --check    rebuild into a temp dir; exit 1 if any stored artefact differs
       build_cp2_draft.py --out DIR  write into DIR instead"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13cp2 import ROOT  # noqa: E402
from sou13cp2.pipeline import build, rebuild_differences  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--out')
    args = ap.parse_args()
    if args.check:
        diff = rebuild_differences(ROOT)
        print(json.dumps({'deterministic_rebuild_matches': not diff, 'differences': diff}, indent=2))
        sys.exit(1 if diff else 0)
    print(json.dumps(build(ROOT, out_root=args.out), indent=2))


if __name__ == '__main__':
    main()
