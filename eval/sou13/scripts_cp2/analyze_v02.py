#!/usr/bin/env python3
"""Read-only leakage analysis of the v0.2 pilot data directory (source material, not gold).
Usage: python -I analyze_v02.py <sou13_pilot/data> [--out FILE]"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13cp2.v02_analysis import analyse  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('data_dir')
    ap.add_argument('--out')
    args = ap.parse_args()
    report = analyse(args.data_dir)
    text = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + '\n'
    if args.out:
        Path(args.out).write_bytes(text.encode('utf-8'))
    print(text, end='')


if __name__ == '__main__':
    main()
