#!/usr/bin/env python3
"""Validate Checkpoint 1 artefacts. Usage: validate.py [--root DIR]. Exit code 1 on failure."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13.build import ROOT  # noqa: E402
from sou13.validate import validate  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', default=str(ROOT))
    report = validate(Path(ap.parse_args().root))
    print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    sys.exit(0 if report['result'] == 'PASS' else 1)


if __name__ == '__main__':
    main()
