#!/usr/bin/env python3
"""Run the prepared Linux pilot walkthrough with a local scripted provider."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
FIXTURES = {
    "filesystem-workspace/notes.txt": b"Owned prepared-selection useful notes.\n/workspace\n/workspace/credentials.txt\n/workspace/followup.txt\n",
    "filesystem-workspace/followup.txt": b"Owned prepared continuation.\n",
    "filesystem-workspace/credentials.txt": b"Owned synthetic sensitive path control.\n",
    "git-workspace/tracked.txt": b"Owned prepared Git change.\n",
}


def fixture_paths(generation):
    paths = {generation / name: raw for name, raw in FIXTURES.items()}
    for path in paths:
        if path.parent.resolve(strict=True) != path.parent:
            raise ValueError("demo_workspace_link_refused")
        if path.exists() or path.is_symlink():
            raise ValueError("demo_fixture_name_occupied")
    return paths


def cleanup_fixtures(paths):
    retained = []
    for path, expected in paths.items():
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_size == len(expected) and path.read_bytes() == expected):
            path.unlink()
        else:
            retained.append(path.name)
    return retained


def reason(error):
    value = str(error)
    return value if re.fullmatch(r"[a-z][a-z0-9_]{0,100}", value) else "demo_failed"


def run(args, report):
    spec = importlib.util.spec_from_file_location("pilot_demo_driver", ROOT / "scripts/qualify-prepared-pilot-run.py")
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    driver.RUN.PREP.supported_platform()
    if args.selection is None or args.output is None or args.expected_commit is None:
        raise ValueError("demo_selection_output_and_commit_required")
    if not args.output.is_absolute() or args.output.resolve().is_relative_to(ROOT):
        raise ValueError("demo_output_must_be_external_absolute_path")
    if args.output.parent.resolve(strict=True) != args.output.parent:
        raise ValueError("demo_output_parent_must_be_canonical")
    if not args.strace.is_absolute() or not args.strace.is_file() or not os.access(args.strace, os.X_OK):
        raise ValueError("demo_strace_executable_required")
    check = argparse.Namespace(selection=args.selection, expected_commit=args.expected_commit,
                               ask_wait_seconds=0, timeout_seconds=60, port=0)
    selection, _, profiles = driver.RUN.selected(check)
    if "prepared_workspaces" in selection:
        raise ValueError("generated_demo_requires_demo_selection_use_pilot_run_for_existing_project")
    generation = args.selection.parent
    fixtures = fixture_paths(generation)
    if any(args.output.is_relative_to(generation / name)
           for name in ("filesystem-workspace", "git-workspace")):
        raise ValueError("demo_output_inside_workspace")
    args.output.mkdir(mode=0o700)
    report.update(source=selection["source"], selection_sha256=hashlib.sha256(args.selection.read_bytes()).hexdigest(),
                  strace_sha256=hashlib.sha256(args.strace.read_bytes()).hexdigest(),
                  executed=True, status="running", cases=[])
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="soup-wall-demo-") as temporary:
            driver.qualify(args, Path(temporary), report)
    except Exception as error:
        report.update(status="failed", reason=reason(error))
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        retained = cleanup_fixtures(fixtures)
        report["fixture_cleanup"] = {"retained_changed_files": retained, "complete": not retained}
        if retained:
            report.update(status="failed", reason="demo_cleanup_preserved_changed_files")
        with (args.output / "report.json").open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(report, sort_keys=True, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--strace", type=Path, default=Path("/usr/bin/strace"))
    parser.add_argument("--validation-timeout-seconds", type=int, default=120)
    args = parser.parse_args()
    report = {"format": "sw-pilot-demo/1", "status": "plan", "executed": False,
              "provider": "owned-scripted-loopback", "live_model_effectiveness": "not_tested",
              "required_platform": "native Ubuntu 24.04 x86_64, non-root",
              "steps": ["verify prepared selection", "useful filesystem and Git calls", "refused mutation",
                        "explicit scripted Ask control", "cancel, timeout and daemon-loss recovery", "owned cleanup"]}
    try:
        if args.run:
            run(args, report)
    except Exception as error:
        report.update(status="failed", reason=reason(error))
    print(json.dumps(report, sort_keys=True))
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
