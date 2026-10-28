#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the existing pilot producers on one frozen selection; retain every outcome.

This is an inventory coordinator, never an alternative readiness evaluator.
Runtime verdicts and the final decision belong to their original producers and
pilot_dossier. No policy, label, timeout or broker lease is modified here.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
STAGES = ("installed", "matched", "ask", "prepared", "docs-code", "unicode-spaces", "local-history")
PRODUCERS = ("qualify-installed-pilot.py", "pilot_measurement.py", "qualify-pilot-ask.py",
             "qualify-prepared-pilot-run.py", "qualify-existing-pilot.py", "pilot_project_fixtures.py",
             "pilot_dossier.py", "qualify-sou145-readiness.py")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("coordinator_report_bound")
    path.write_bytes(raw)
    path.chmod(0o600)


def load_producer():
    spec = importlib.util.spec_from_file_location("sou145_installed", ROOT / "scripts/qualify-installed-pilot.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def live_processes():
    """Only usable inside the owned PID namespace selected by the operator."""
    rows = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if fields[0] != "Z":
                rows[int(entry.name)] = fields[19]
        except FileNotFoundError:
            continue
    return rows


def commands(selection, commit, strace, offline, output, paths):
    base = [sys.executable, "-B"]
    common = ["--selection", str(selection), "--expected-commit", commit]
    records = []
    for stage in STAGES:
        destination = output / stage
        if stage in ("installed", "matched"):
            words = ["qualify-installed-pilot.py", "--run", *common,
                     "--offline-inputs", str(offline)]
            if stage == "matched":
                words.append("--matched-development")
            report = "report.json"
        elif stage == "ask":
            words = ["qualify-pilot-ask.py", "--complete-inventory", "--require-five-second-pending",
                     "--offline-inputs", str(offline), "--strace", str(strace)]
            for role in ("agentfw", "git_launcher", "claude", "node", "npm", "bwrap", "git"):
                words += ["--" + role.replace("_", "-"), str(paths[role])]
            report = "qualification.json"
        elif stage == "prepared":
            words = ["qualify-prepared-pilot-run.py", *common, "--strace", str(strace)]
            report = "report.json"
        else:
            words = ["qualify-existing-pilot.py", *common, "--strace", str(strace),
                     "--project-fixture", stage, "--offline-inputs", str(offline)]
            report = "report.json"
        records.append((stage, [*base, str(ROOT / "scripts" / words[0]), *words[1:],
                                "--output", str(destination)], destination / report))
    return records


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--selection", type=Path, required=True)
    p.add_argument("--expected-commit", required=True)
    p.add_argument("--strace", type=Path, required=True)
    p.add_argument("--offline-inputs", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--owned-pid-namespace", action="store_true", required=True,
                   help="Require an externally isolated PID namespace, read-only source and scratch-only writes")
    a = p.parse_args(argv)
    a.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {"format": "sw-pilot-readiness-execution/1", "status": "incomplete",
              "decision": "NOT_READY", "evaluator": "pilot_dossier", "paid_api_calls": 0,
              "stages": [{"id": name, "status": "incomplete", "reason": "not_executed"} for name in STAGES]}
    destination = a.output / "execution.json"
    write(destination, report)
    try:
        if platform.system() != "Linux" or os.geteuid() == 0 or not (os.statvfs(ROOT).f_flag & os.ST_RDONLY):
            raise ValueError("nonroot_readonly_linux_required")
        # The namespace must not be the host's namespace. The outer custodian
        # records its own inode; the child cannot turn a report into this proof.
        expected_ns = os.environ.get("SOU145_HOST_PID_NS")
        if not expected_ns or os.readlink("/proc/self/ns/pid") == expected_ns:
            raise ValueError("owned_pid_namespace_required")
        api = load_producer()
        if a.selection.stat().st_size > 65536:
            raise ValueError("selection_byte_limit")
        selection = api.strict_json(a.selection.read_bytes())
        source, paths = api.validate_selection(selection, a.expected_commit)
        report.update(source_before=source, selection_sha256=sha(a.selection),
                      selected_sha256={name: sha(path) for name, path in paths.items()},
                      producer_sha256={name: sha(ROOT / "scripts" / name) for name in PRODUCERS},
                      environment={"platform": "wsl2" if "microsoft" in platform.release().lower() else "linux",
                                   "architecture": platform.machine(), "host": "Claude Code 2.1.251",
                                   "provider": "owned-scripted-loopback", "transport": "stdio",
                                   "distribution": platform.freedesktop_os_release().get("PRETTY_NAME"),
                                   "kernel_release": platform.release()},
                      inventories={"installed": 12, "matched_pairs": 20, "matched_arms": 40,
                                   "ask": 15, "prepared": 12, "ordinary_projects": 3,
                                   "ordinary_project_cases_each": 9},
                      pid_namespace=os.readlink("/proc/self/ns/pid"))
        baseline = live_processes()
        write(a.output / "frozen-plan.json", report)
        for index, (stage, command, original) in enumerate(commands(
                a.selection, a.expected_commit, a.strace, a.offline_inputs, a.output, paths)):
            row = report["stages"][index]
            row.update(status="running", reason=None)
            write(destination, report)
            started = time.monotonic()
            log = a.output / (stage + ".private.log")
            # Existing producers retain their own unchanged runtime deadlines.
            with log.open("xb") as stream:
                log.chmod(0o600)
                result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
            row.update(status="executed", exit_code=result.returncode,
                       elapsed_seconds=round(time.monotonic() - started, 3), log_sha256=sha(log))
            if original.is_file() and original.stat().st_size <= 2 * 1024 * 1024:
                row.update(report=original.relative_to(a.output).as_posix(), report_sha256=sha(original))
            else:
                row.update(status="incomplete", reason="original_report_missing_or_oversized")
            after = live_processes()
            remaining = [{"pid": pid, "start": start} for pid, start in after.items()
                         if baseline.get(pid) != start]
            row["independent_namespace_cleanup"] = {"all_stopped": not remaining, "remaining": remaining}
            write(destination, report)
            if remaining:
                raise ValueError("owned_cleanup_unconfirmed_stop_inventory")
            if api.source() != source or sha(a.selection) != report["selection_sha256"] or any(
                    sha(path) != report["selected_sha256"][name] for name, path in paths.items()):
                raise ValueError("source_or_selected_input_changed")
        report.update(status="executed", source_after=api.source(),
                      meaning="All original outcomes retained; run pilot_dossier for readiness, never infer GO from execution")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["reason"] = str(error) if type(error) is ValueError and str(error).replace("_", "").isalnum() else type(error).__name__
    write(destination, report)
    print(json.dumps({"status": report["status"], "decision": report["decision"]}))
    return 0 if report["status"] == "executed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
