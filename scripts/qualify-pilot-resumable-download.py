#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native Ubuntu 24.04 evidence for the exact public bubblewrap transfer pin."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import runpy
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
import pilot_preparation_lock as coordination


def run(report: Path):
    if (platform.system() != "Linux" or platform.machine() != "x86_64"
            or "microsoft" in platform.release().lower()):
        raise SystemExit("native_ubuntu_2404_x86_64_required")
    system = platform.freedesktop_os_release()
    if system.get("ID") != "ubuntu" or system.get("VERSION_ID") != "24.04":
        raise SystemExit("native_ubuntu_2404_x86_64_required")
    preparation = runpy.run_path(str(ROOT / "scripts/prepare-native-pilot-prerequisites.py"))
    version, _, _, sha256, _ = preparation["SOURCES"]["bwrap"]
    expected = preparation["BWRAP_ARCHIVE_BYTES"]
    with tempfile.TemporaryDirectory(prefix="sou173-transfer-", dir=os.environ.get("RUNNER_TEMP")) as temporary:
        root = Path(temporary) / "output"
        root.mkdir(mode=0o700)
        archive = Path(temporary) / "bwrap.tar.xz"
        started = time.monotonic()
        with coordination.hold(root) as claim:
            _, fresh = preparation["download"]("bwrap", archive, output=root, claim=claim)
        downloaded_seconds = round(time.monotonic() - started, 3)
        source = Path(temporary) / "extracted"
        source.mkdir(mode=0o700)
        preparation["extract"](preparation["bounded_archive"](archive, "bwrap"), source, "bwrap")
        if not (source / "meson.build").is_file():
            raise SystemExit("pinned_archive_extraction_missing")
        archive.unlink()
        started = time.monotonic()
        with coordination.hold(root) as claim:
            _, offline = preparation["download"]("bwrap", archive, output=root,
                                                 claim=claim, offline=True)
        offline_seconds = round(time.monotonic() - started, 3)
        preparation["bounded_archive"](archive, "bwrap")
        result = {"format": "sw-pilot-resumable-download-evidence/1", "status": "passed",
                  "platform": "ubuntu-24.04-x86_64", "version": version,
                  "sha256": sha256, "archive_bytes": expected,
                  "download_seconds": downloaded_seconds, "offline_reuse_seconds": offline_seconds,
                  "fresh": fresh, "offline": offline, "extracted": True,
                  "active_protection": False}
    if not report.is_absolute() or not report.parent.is_dir():
        raise SystemExit("absolute_existing_report_parent_required")
    report.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--report", type=Path, required=True)
    options = parser.parse_args()
    if not options.run:
        parser.error("--run is required for the explicit public transfer")
    try:
        run(options.report)
    except Exception as error:
        reason = getattr(error, "reason", None)
        if not isinstance(reason, str) or not re.fullmatch(r"[a-z0-9_]{1,100}", reason):
            reason = type(error).__name__ + "_failed"
        progress = getattr(error, "progress", None)
        evidence = {"format": "sw-pilot-resumable-download-evidence/1", "status": "failed",
                    "reason": reason, "progress": progress if isinstance(progress, dict) else {},
                    "active_protection": False}
        if options.report.is_absolute() and options.report.parent.is_dir():
            options.report.write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(evidence, sort_keys=True))
        raise SystemExit(2) from None
