#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Predeclared independent fresh runs; never rerun-until-green.

Build binaries and install the pinned driver first (see sso-acceptance.sh).
Only sanitized JSON reports are retained. Every run uses the genuine driver.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sso_diagnostics", Path(__file__).with_name("sso_diagnostics.py"))
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)


def classify(returncode, report):
    if (returncode == 0 and report.get("passed") is True and report.get("cleanup_passed") is True
            and report.get("outcome") == "completed"):
        return "completed"
    if report.get("outcome") == "failed":
        return "failed"
    return "incomplete"


def run(args):
    args.out.mkdir(parents=True, exist_ok=False)
    summary = {"schema_version": 1, "protocol": args.protocol, "backend": args.backend,
               "planned_runs": args.runs, "runs": [], "passed": False,
               "scope": "Independent disposable Keycloak/browser runs; no universal flake claim"}
    destination = args.out / "batch.json"

    def publish():
        summary["counts"] = {name: sum(item["outcome"] == name for item in summary["runs"])
                             for name in ("completed", "failed", "incomplete", "skipped")}
        pending = destination.with_suffix(".pending")
        pending.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        pending.replace(destination)

    for index in range(1, args.runs + 1):
        summary["runs"].append({"run": index, "outcome": "skipped"})
    publish()
    old_handlers = {}
    def cancel(_number, _frame):
        raise D.RunCancelled("batch cancelled")
    if os.name == "posix":
        for number in (signal.SIGINT, signal.SIGTERM):
            old_handlers[number] = signal.signal(number, cancel)
    try:
        for entry in summary["runs"]:
            entry["outcome"] = "incomplete"
            publish()
            path = args.out / f"run-{entry['run']}.json"
            entry["report"] = path.name
            command = [sys.executable, str(ROOT / "scripts" / (
                "keycloak-oidc-acceptance.py" if args.protocol == "oidc" else "keycloak-saml-linux.py")),
                "--backend", args.backend, "--gateway", str(args.gateway),
                "--bootstrap-helper", str(args.bootstrap_helper), "--artifact-label", args.artifact_label,
                "--out", str(path)]
            if args.protocol == "oidc":
                command.append("--docker")
            started = time.monotonic()
            child = None
            try:
                child = subprocess.Popen(command, cwd=ROOT)
                returncode = child.wait(timeout=960)
                report = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
                entry.update(outcome=classify(returncode, report), exit_code=returncode,
                             report=path.name, cleanup_passed=report.get("cleanup_passed") is True)
            except (D.RunCancelled, KeyboardInterrupt):
                entry["reason"] = "cancelled"
                return 1
            except subprocess.TimeoutExpired:
                entry["reason"] = "outer_budget_exhausted"
                return 1
            except (OSError, ValueError):
                entry["reason"] = "driver_or_report_unavailable"
                return 1
            finally:
                if child is not None and child.poll() is None:
                    # Let the driver's signal handler unwind owned containers and processes.
                    for number in old_handlers:
                        signal.signal(number, signal.SIG_IGN)
                    child.terminate()
                    try:
                        child.wait(timeout=60)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=10)
                        entry["cleanup_passed"] = False
                        entry["reason"] = "forced_stop_cleanup_unverified"
                if path.exists() and entry.get("reason") != "forced_stop_cleanup_unverified":
                    try:
                        entry["cleanup_passed"] = json.loads(path.read_text(encoding="utf-8")).get("cleanup_passed") is True
                    except (OSError, ValueError):
                        entry["cleanup_passed"] = False
                entry["duration_ms"] = round((time.monotonic() - started) * 1000)
                publish()
        summary["passed"] = all(item["outcome"] == "completed" for item in summary["runs"])
        publish()
        return 0 if summary["passed"] else 1
    finally:
        for number, handler in old_handlers.items():
            signal.signal(number, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", choices=("oidc", "saml"), required=True)
    parser.add_argument("--backend", choices=("sqlite", "postgres"), required=True)
    parser.add_argument("--runs", choices=(1, 2), type=int, default=1)
    parser.add_argument("--out", type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--gateway", type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--bootstrap-helper", type=lambda value: Path(value).resolve(), required=True)
    parser.add_argument("--artifact-label", required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
