#!/usr/bin/env python3
"""Build Checkpoint 1 artefacts deterministically. Usage: build_dev16.py [--out DIR]
No network, no real tool execution; fixtures run in the in-memory sandbox only."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13.build import ROOT, write_all  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=str(ROOT), help='output root (default: sou13_v03/)')
    freeze = write_all(Path(ap.parse_args().out))
    print(json.dumps({'counts': freeze['counts'], 'files': sorted(freeze['files_sha256'])}, ensure_ascii=False))


if __name__ == '__main__':
    main()
