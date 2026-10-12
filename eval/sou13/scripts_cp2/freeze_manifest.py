#!/usr/bin/env python3
"""Freeze the authoritative CP2 split manifest. DRY-RUN BY DEFAULT: nothing is written without --execute.

Usage:
  freeze_manifest.py --approved-by @login --approved-at 2026-10-11T12:00:00+05:00 --decision-ref <link>
                     [--log FILE_OUTSIDE_REPO]                                   # dry-run: prints the plan
  freeze_manifest.py ... --execute --backup-dir DIR_OUTSIDE_REPO                 # writes the FROZEN manifest
Exit codes: 0 = plan OK (dry-run) or frozen; 2 = refused, nothing written; 1 = write failed, original restored.
Run --execute ONLY on the owner's explicit authorization. Freezing does not sign: the owner signs the external
trust anchor afterwards (docs/CP2_TRUST_ANCHOR.md); until then validate_cp2 reports the FROZEN manifest as
unauthenticated."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sou13cp2 import ROOT  # noqa: E402
from sou13cp2.freeze_cli import run  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--approved-by', required=True)
    ap.add_argument('--approved-at', required=True)
    ap.add_argument('--decision-ref', required=True)
    ap.add_argument('--execute', action='store_true', help='actually write the FROZEN manifest')
    ap.add_argument('--backup-dir', help='required with --execute; outside the repository')
    ap.add_argument('--log', help='audit log for dry-runs (outside the repository)')
    ap.add_argument('--root', default=str(ROOT), help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    code, report = run(approved_by=a.approved_by, approved_at=a.approved_at, decision_ref=a.decision_ref,
                       execute=a.execute, backup_dir=a.backup_dir, log_path=a.log, root=Path(a.root))
    print(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == '__main__':
    sys.exit(main())
