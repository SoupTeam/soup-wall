#!/usr/bin/env python3
"""Build the dev review package and the RESTRICTED test custodian package locally (nothing is sent).
Usage: build_handoff.py [--out DIR]   (default: <repo>/handoff)"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13cp2 import ROOT  # noqa: E402
from sou13cp2.handoff import build_packages  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=str(ROOT / 'handoff'))
    print(json.dumps(build_packages(Path(ap.parse_args().out)), indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
