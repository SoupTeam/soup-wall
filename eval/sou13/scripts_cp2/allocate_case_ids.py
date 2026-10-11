#!/usr/bin/env python3
"""Explicitly allocate random 128-bit case ids for CP2 cases that have none (existing ids are never changed).
Public ids go to cp2/ids/case_ids.PUBLIC.json, test ids to the restricted cp2_sealed/ids/case_ids.TEST.json.
Usage: allocate_case_ids.py"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13cp2 import ROOT  # noqa: E402
from sou13cp2.case_ids import allocate, key  # noqa: E402
from sou13cp2.catalog import get_catalog  # noqa: E402


def main():
    needed = [key(fid, i) for fid, entry in get_catalog().items() for i in range(entry['n_new'])]
    print(json.dumps({'needed': len(needed), 'added': allocate(needed, ROOT)}))


if __name__ == '__main__':
    main()
