#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reproduce SOU-145 attempt 1 with the existing dossier; no runtime or new gate."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

import pilot_dossier as dossier
from roadmap_support import Invalid, load_json, require, safe_file, write_private

ROOT = Path(__file__).resolve().parents[1]
SELECTION = ROOT / "docs/operations/evidence/sou145/attempt-1-selection.json"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True,
                        help="Original bounded artifact ZIP from run 40208279919")
    parser.add_argument("--output", type=Path, required=True,
                        help="New private directory; parent must already exist")
    args = parser.parse_args(argv)
    try:
        selection, _ = load_json(SELECTION, 128 * 1024)
        dossier.validate_manifest(selection)
        archive = safe_file(args.archive, dossier.MAX_ARCHIVE)
        reference = selection["evidence"][0]["file"]
        require(dossier.sha(archive) == reference["sha256"], "original_archive_hash_mismatch")
        for parent in (args.output.absolute().parent, *args.output.absolute().parent.parents):
            require(parent.is_dir() and not parent.is_symlink()
                    and not (getattr(parent.lstat(), "st_file_attributes", 0) & 0x400),
                    "private_output_parent_required")
        args.output.mkdir(mode=0o700, exist_ok=False)
        write_private(args.output, reference["path"], archive)
        for ref in (selection["support_index"], selection["workload"]):
            raw = subprocess.check_output(
                ["git", "-C", str(ROOT), "show", selection["candidate"]["commit"] + ":" + ref["path"]],
                timeout=30, stderr=subprocess.DEVNULL, env={**os.environ, "GIT_NO_LAZY_FETCH": "1"})
            require(len(raw) <= dossier.MAX_REPORT and dossier.sha(raw) == ref["sha256"],
                    "candidate_input_hash_mismatch")
            target = args.output / ref["path"]
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_private(target.parent, target.name, raw)
        return dossier.main([
            "--selection", str(SELECTION), "--root", str(args.output),
            "--repo", str(ROOT), "--candidate", selection["candidate"]["commit"],
            "--output", str(args.output / "dossier"),
        ])
    except (Invalid, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        # Never print raw exception text that could contain private paths.
        print("sou145-evidence: " + (str(error) if isinstance(error, Invalid) else type(error).__name__), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
