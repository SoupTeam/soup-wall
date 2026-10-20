#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent APFS file observer role for SOU-94 acceptance testing.

Executes as a separate process to witness file modifications, atime advances,
and file publication without witness-side byte reads interfering with evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

sys.dont_write_bytecode = True



def calibrate(probe: Path) -> dict:
    probe.parent.mkdir(parents=True, exist_ok=True)
    probe.write_bytes(b"CALIBRATION-PROBE-BYTES-1024" * 32)
    st_init = probe.stat()
    calibrated_atime = st_init.st_mtime - 1000
    os.utime(probe, (calibrated_atime, st_init.st_mtime))
    st_base = probe.stat()
    init_atime_ns = st_base.st_atime_ns

    # Step 1: Prove metadata-only open does not advance atime
    for _ in range(3):
        fd = os.open(probe, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        st = os.fstat(fd)
        _ = st.st_size
        os.close(fd)
    st_meta = probe.stat()
    meta_unchanged = st_meta.st_atime_ns == init_atime_ns

    # Step 2: Prove reading bytes advances atime
    fd = os.open(probe, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    _ = os.read(fd, 64)
    os.close(fd)
    st_read = probe.stat()
    read_updated = st_read.st_atime_ns > init_atime_ns

    probe.unlink(missing_ok=True)
    return {
        "init_atime_ns": init_atime_ns,
        "meta_unchanged": meta_unchanged,
        "read_updated": read_updated,
        "calibrated": meta_unchanged and read_updated,
    }


def observe_before(target: Path, output_file: Path | None) -> dict:
    data = {
        "path": str(target),
        "exists": False,
        "is_symlink": False,
        "is_fifo": False,
        "st_ino": None,
        "st_dev": None,
        "st_size": None,
        "st_atime_ns": None,
        "st_mtime_ns": None,
        "st_ctime_ns": None,
        "st_nlink": None,
        "witness_time_ns": time.time_ns(),
        "stat_error": None,
    }
    try:
        lst = target.lstat()
        data["exists"] = True
        data["is_symlink"] = stat.S_ISLNK(lst.st_mode)
        data["is_fifo"] = stat.S_ISFIFO(lst.st_mode)
        data["st_ino"] = lst.st_ino
        data["st_dev"] = lst.st_dev
        data["st_size"] = lst.st_size
        data["st_atime_ns"] = lst.st_atime_ns
        data["st_mtime_ns"] = lst.st_mtime_ns
        data["st_ctime_ns"] = lst.st_ctime_ns
        data["st_nlink"] = lst.st_nlink

        # Only calibrate atime for regular files (never special files like FIFO or symlinks)
        if not data["is_symlink"] and not data["is_fifo"] and stat.S_ISREG(lst.st_mode):
            st_init = target.stat()
            calibrated_atime = st_init.st_mtime - 1000
            os.utime(target, (calibrated_atime, st_init.st_mtime))
            st = target.stat()
            data["st_ino"] = st.st_ino
            data["st_dev"] = st.st_dev
            data["st_size"] = st.st_size
            data["st_atime_ns"] = st.st_atime_ns
            data["st_mtime_ns"] = st.st_mtime_ns
            data["st_ctime_ns"] = st.st_ctime_ns
            data["st_nlink"] = st.st_nlink
    except FileNotFoundError:
        data["exists"] = False
    except OSError as e:
        data["stat_error"] = str(e)

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return data


def observe_after(target: Path, before: dict, output_file: Path | None, hash_content: bool = False) -> dict:
    after_data = {
        "path": str(target),
        "exists": False,
        "is_symlink": False,
        "is_fifo": False,
        "st_ino": None,
        "st_dev": None,
        "st_size": None,
        "st_atime_ns": None,
        "st_mtime_ns": None,
        "st_ctime_ns": None,
        "st_nlink": None,
        "atime_advanced": False,
        "size_changed": False,
        "content_sha256": None,
        "witness_time_ns": time.time_ns(),
        "stat_error": None,
    }
    try:
        lst = target.lstat()
        after_data["exists"] = True
        after_data["is_symlink"] = stat.S_ISLNK(lst.st_mode)
        after_data["is_fifo"] = stat.S_ISFIFO(lst.st_mode)
        after_data["st_ino"] = lst.st_ino
        after_data["st_dev"] = lst.st_dev
        after_data["st_size"] = lst.st_size
        after_data["st_atime_ns"] = lst.st_atime_ns
        after_data["st_mtime_ns"] = lst.st_mtime_ns
        after_data["st_ctime_ns"] = lst.st_ctime_ns
        after_data["st_nlink"] = lst.st_nlink

        if before.get("st_atime_ns") is not None:
            after_data["atime_advanced"] = lst.st_atime_ns > before["st_atime_ns"]
        if before.get("st_size") is not None:
            after_data["size_changed"] = lst.st_size != before["st_size"]

        # Only hash content if explicitly requested (e.g. created files).
        # Refusal observations MUST NEVER read bytes, avoiding observer-induced atime advance or canary leakage.
        if hash_content and stat.S_ISREG(lst.st_mode):
            after_data["content_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    except FileNotFoundError:
        after_data["exists"] = False
    except OSError as e:
        after_data["stat_error"] = str(e)

    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(json.dumps(after_data, indent=2), encoding="utf-8")
    return after_data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    cal_p = sub.add_parser("calibrate")
    cal_p.add_argument("--probe", required=True, type=Path)

    bef_p = sub.add_parser("before")
    bef_p.add_argument("--target", required=True, type=Path)
    bef_p.add_argument("--output", required=False, type=Path)

    aft_p = sub.add_parser("after")
    aft_p.add_argument("--target", required=True, type=Path)
    aft_p.add_argument("--before", required=True, type=Path)
    aft_p.add_argument("--output", required=False, type=Path)
    aft_p.add_argument("--hash-content", action="store_true", default=False)

    args = parser.parse_args()

    if args.cmd == "calibrate":
        res = calibrate(args.probe)
        print(json.dumps(res))
    elif args.cmd == "before":
        res = observe_before(args.target, args.output)
        print(json.dumps(res))
    elif args.cmd == "after":
        before_data = json.loads(args.before.read_text(encoding="utf-8"))
        res = observe_after(args.target, before_data, args.output, hash_content=args.hash_content)
        print(json.dumps(res))


if __name__ == "__main__":
    main()
