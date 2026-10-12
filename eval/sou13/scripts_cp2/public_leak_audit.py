#!/usr/bin/env python3
"""Adversarial public-leak audit (owner/custodian only: scoring needs the restricted materials).
Usage: public_leak_audit.py [--out FILE]. Exit code 1 if any leak or reconstruction is found."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13cp2.public_audit import run  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out')
    report = run()
    text = json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + '\n'
    if ap.parse_args().out:
        Path(ap.parse_args().out).write_text(text, encoding='utf-8')
    print(text, end='')
    sys.exit(0 if report['passed'] else 1)


if __name__ == '__main__':
    main()
