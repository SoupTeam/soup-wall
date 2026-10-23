#!/usr/bin/env python3
"""Qualify cleanup against two genuine native prerequisite preparation generations."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("qualified_cleanup", ROOT / "scripts/pilot-cleanup.py")
CLEAN = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CLEAN)


def qualify(args, report):
    CLEAN.require(not CLEAN.NATIVE.platform_missing(), "native_ubuntu_24_04_required")
    CLEAN.require(args.output.is_absolute() and args.output.parent.resolve(strict=True) == args.output.parent
                  and not args.output.is_relative_to(ROOT), "external_canonical_output_required")
    args.output.mkdir(mode=0o700)
    args.output_created = True
    prefix = args.output / "native"
    sentinel = args.output / "operator.txt"
    sentinel.write_text("Preserve unrelated operator data.\n")
    options = argparse.Namespace(prepare=True, rebuild=False, allow_download=False, output=prefix,
        expected_commit=args.expected_commit, git_archive=args.git_archive, bwrap_archive=args.bwrap_archive,
        pkg_config_libdir=args.pkg_config_libdir, pkg_config_sysroot=args.pkg_config_sysroot,
        meson_pythonpath=args.meson_pythonpath)
    first = CLEAN.NATIVE.prepare(options)
    old = Path(first["receipt"]).parent.name
    retained = CLEAN.inspect(prefix, old)
    CLEAN.require(retained["classification"] == "current" and retained["confirmation"] is None,
                  "current_generation_not_retained")
    report["cases"].append("current_retained")
    options.rebuild = True
    second = CLEAN.NATIVE.prepare(options)
    options.rebuild = False
    reused = CLEAN.NATIVE.prepare(options)
    CLEAN.require(reused["status"] == "reused" and reused["receipt"] == second["receipt"],
                  "accepted_generation_not_reused")
    report["cases"].append("prepare_and_reuse")
    marker_before = CLEAN.sha(prefix / "current.json")
    active = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"],
                              cwd=prefix / "generations" / old, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        CLEAN.require(CLEAN.inspect(prefix, old)["classification"] == "active-or-uncertain",
                      "active_generation_not_refused")
        report["cases"].append("active_refused")
    finally:
        active.terminate()
        active.wait(timeout=5)
    plan = CLEAN.inspect(prefix, old)
    CLEAN.require(plan["classification"] == "inactive", "generation_use_could_not_be_proven_inactive")
    CLEAN.NATIVE.write_json(args.output / "dry-run.json", plan)
    CLEAN.require((prefix / "generations" / old).exists(), "dry_run_removed_generation")
    report["cases"].append("dry_run_preserved_generation")
    removed = CLEAN.apply(prefix, old, plan["confirmation"])
    CLEAN.require(removed["status"] == "removed" and not (prefix / "generations" / old).exists(),
                  "inactive_generation_not_removed")
    CLEAN.require(CLEAN.sha(prefix / "current.json") == marker_before, "current_marker_changed")
    after = CLEAN.NATIVE.prepare(options)
    CLEAN.require(after["status"] == "reused" and after["receipt"] == second["receipt"],
                  "current_generation_not_reusable_after_cleanup")
    CLEAN.require(sentinel.read_text() == "Preserve unrelated operator data.\n", "unrelated_file_changed")
    report["cases"].extend(["inactive_removed", "current_reused_after_cleanup", "unrelated_preserved"])
    report.update(status="passed", removed_receipt_sha256=plan["receipt"]["sha256"],
                  retained_receipt_sha256=CLEAN.sha(Path(second["receipt"])),
                  current_marker_sha256=marker_before)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--git-archive", type=Path, required=True)
    parser.add_argument("--bwrap-archive", type=Path, required=True)
    parser.add_argument("--pkg-config-libdir", type=Path)
    parser.add_argument("--pkg-config-sysroot", type=Path)
    parser.add_argument("--meson-pythonpath", type=Path)
    args = parser.parse_args()
    args.output_created = False
    report = {"format": "sw-pilot-cleanup-qualification/1", "status": "plan", "cases": [],
              "source_commit": args.expected_commit, "native_acceptance": False}
    started = time.monotonic()
    if args.run:
        try:
            qualify(args, report)
            report["native_acceptance"] = True
        except Exception as error:
            value = str(error)
            report.update(status="failed", reason=value if re.fullmatch(r"[a-z][a-z0-9_]{0,100}", value)
                          else "cleanup_qualification_failed")
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if args.output_created:
            CLEAN.NATIVE.write_json(args.output / "report.json", report)
    print(json.dumps(report, sort_keys=True))
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
