#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the existing disposable setup, status/MCP and paired latency probes together.

Requires a clean exact candidate and a separately built Agent. This runs only
the accepted local fixture path, not final generic SOU-15 or host acceptance.
No models, GitHub settings, real host profiles or service registrations are used.
Use --include-generic to add the accepted SOU-17 classifier/policy boundary probe.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import html
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
BASE_STAGES = ("setup", "status", "latency")
SCRIPTS = {
    "setup": "clean-setup-acceptance.py",
    "status": "verify-sou18-status.py",
    "latency": "measure-sou17-latency.py",
    "generic": "verify-sou17-generic-boundary.py",
}
REPORTS = {"setup": "setup.json", "status": "status/results.json", "latency": "latency/results.json",
           "generic": "generic/results.json"}
SCHEMAS = {"setup": 1, "status": "sou18-status-witnesses/1", "latency": "sou17-paired-latency/0.1",
           "generic": "sou17-generic-boundary/1"}


def load(repo, name):
    spec = importlib.util.spec_from_file_location("sou18_suite_" + name, repo / "scripts" / SCRIPTS[name])
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def compact(snapshot):
    return {key: snapshot[key] for key in ("commit", "dirty", "inputs_digest")}


def execute(command, repo, env, timeout):
    """Bound one owned process tree; never retain ambient subprocess diagnostics."""
    started = time.monotonic()
    result = {"exit_code": None, "timed_out": False}
    try:
        with subprocess.Popen(command, cwd=repo, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              start_new_session=os.name != "nt",
                              creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)) as child:
            try:
                result["exit_code"] = child.wait(timeout=timeout)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                result["timed_out"] = True
                try:
                    if os.name == "nt":
                        # /T is restricted to this owned child's descendants, never an image-name kill.
                        system_root = next(value for key, value in env.items() if key.upper() == "SYSTEMROOT")
                        subprocess.run([str(Path(system_root) / "System32/taskkill.exe"),
                                        "/PID", str(child.pid), "/T", "/F"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=True)
                    else:
                        os.killpg(child.pid, signal.SIGKILL)
                except (OSError, subprocess.SubprocessError, StopIteration):
                    result["error"] = "tree_cleanup_unconfirmed"
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=10)
    except (OSError, subprocess.SubprocessError, StopIteration):
        result["error"] = "process_failed"
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return result


def evaluate(name, data, process, before, binary_hash, pairs, helpers):
    """Neither a zero exit nor a summary label alone can produce a suite pass."""
    try:
        if process.get("timed_out") or process.get("error"):
            return "incomplete", "process_incomplete"
        schema = data.get("schema_version")
        if type(schema) is not type(SCHEMAS[name]) or schema != SCHEMAS[name]:
            return "incomplete", "unsupported_report_schema"
        reported = data.get("summary", {}).get("status") if name == "latency" else data.get("status")
        if reported == "fail":
            return "fail", "probe_reported_failure"
        if reported != "pass" or type(process.get("exit_code")) is not int or process["exit_code"] != 0:
            return "incomplete", "probe_did_not_complete_successfully"
        observed_binary = data.get("agentfw", {}).get("sha256") if name == "latency" else data.get("binary_sha256")
        if name == "generic":
            observed_binary = data.get("binary_sha256_before")
        if observed_binary != binary_hash:
            return "incomplete", "binary_identity_mismatch"
        if name == "setup":
            if data["source"]["commit"] != before["commit"] or data["source"]["dirty"] is not False:
                return "incomplete", "candidate_identity_mismatch"
            checks = data["checks"]
            expected = {"install_preserves_settings_and_hides_token", "shadow", "enforcing", "unavailable",
                        "recovery", "remove_owned_install_and_profile"}
            if (len(checks) != len(expected) or {c["name"] for c in checks} != expected
                    or any(c["status"] != "pass" for c in checks)
                    or any(type(c.get("preflight_exit")) is not int
                           or c["preflight_exit"] != {"shadow": 4, "enforcing": 0, "unavailable": 2, "recovery": 0}[c["name"]]
                           for c in checks if c["name"] in {"shadow", "enforcing", "unavailable", "recovery"})):
                return "incomplete", "setup_witnesses_incomplete"
        elif name == "generic":
            # The accepted SOU-17 helper names the same complete hash map differently.
            generic_source = dict(before)
            generic_source["inputs_sha256"] = generic_source.pop("tracked_inputs_sha256")
            if data["source"] != generic_source or data["source_after"] != generic_source:
                return "incomplete", "candidate_identity_mismatch"
            if data["binary_sha256_after"] != binary_hash or data["expected_binary_sha256"] != binary_hash:
                return "incomplete", "binary_identity_mismatch"
            if data["expected_commit"] != before["commit"] or data.get("stable") is not True or data.get("error") is not None:
                return "incomplete", "generic_identity_or_completion_missing"
            if (data["script_sha256_before"] != data["script_sha256_after"]
                    or data["helper_sha256_before"] != data["helper_sha256_after"]):
                return "incomplete", "generic_verifier_changed"
            observed = data["observed"]
            if (data["expectations"] != helpers["generic"].cases()
                    or observed["classifier_sha256"] != observed["classifier_sha256_after"]
                    or observed["native_audit_errors"] or observed["final_ledger_errors"]):
                return "incomplete", "generic_witnesses_incomplete"
            status, _ = helpers["generic"].grade_report(
                observed["rows"], True, observed["classifier_sha256"], observed["receiver_bodies"],
                observed["native_decisions"], observed["classifications"], observed["gateway_exit_code"],
                transcript=observed["transcript"], error=observed["error"])
            if status != "pass":
                return ("fail" if status == "fail" else "incomplete"), "generic_witnesses_" + status
        else:
            if data["source_before"] != before or data["source_after"] != before:
                return "incomplete", "candidate_identity_mismatch"
            if name == "status":
                for row in data["rows"]:
                    helpers["status"].grade(row)
                if data.get("initial_path_verified") is not True or not helpers["status"].verified(data):
                    return "incomplete", "status_witnesses_incomplete"
            else:
                if (type(data["pairs"]) is not int or data["pairs"] != pairs
                        or type(data["excluded_warmup_pairs"]) is not int or data["excluded_warmup_pairs"] != 1):
                    return "incomplete", "latency_sample_count_mismatch"
                for row in data["rows"]:
                    helpers["latency"].grade(row, row["path"] == "protected", data["classifier"]["sha256"])
                reconciled = all(data["post_stop_reconciliation"].get(path) is True for path in ("direct", "protected"))
                summary = helpers["latency"].summarize(data["rows"], pairs, True, reconciled and "error" not in data)
                if summary != data["summary"] or summary["status"] != "pass":
                    return "incomplete", "latency_witnesses_incomplete"
        return "pass", "complete"
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return "incomplete", "invalid_report"


def outcome(stages, stable, required=BASE_STAGES):
    if any(row["status"] == "fail" for row in stages):
        return "fail"
    if stable and len(stages) == len(required) and {r["name"] for r in stages} == set(required) \
            and all(row["status"] == "pass" for row in stages):
        return "pass"
    return "incomplete"


def md(value):
    return html.escape(str(value), quote=True).replace("|", "&#124;").replace("`", "&#96;").replace("\n", " ").replace("\r", " ")


def markdown(report):
    rows = ["# SOU-18 local acceptance run", "", f"Probe suite: **{md(report['status'])}**.", "",
            "This is the selected local fixture path. Final generic integration, actual host and CodeQL merge protection are not verified.",
            "", f"Candidate: `{md(report['expected_commit'])}`.", f"Observed at: {md(report['observed_at'])}.",
            f"Agent SHA-256: `{md(report.get('binary_sha256', 'not recorded'))}`.",
            "Binary build provenance: supplied by the caller; retain the matching build record.", "",
            "| Stage | Status | Reason | Evidence |", "| --- | --- | --- | --- |"]
    for stage in report["stages"]:
        link = f"[JSON]({REPORTS[stage['name']]})" if stage.get("report_sha256") else "not recorded"
        rows.append(f"| {md(stage['name'])} | {md(stage['status'])} | {md(stage['reason'])} | {link} |")
    rows += ["", "Source/binary stable: " + md(report.get("source_binary_stable", False)) + ".",
             "Owned wrapper profiles removed: " + md(report.get("owned_profiles_removed", False)) + "."]
    if "error" in report:
        rows += ["", "Run error: " + md(report["error"]) + "."]
    if report.get("paired_overhead_ms"):
        stats = report["paired_overhead_ms"]
        rows += ["", f"Paired MCP added duration: p50 {stats['p50']:.3f} ms; p95 {stats['p95']:.3f} ms.",
                 "Includes per-call Python classifier startup. No numeric performance threshold has been accepted."]
    rows += ["", "Build/download time is outside this runner. Setup CLI timings are not MCP overhead.",
             "The optional generic stage uses synthetic classifier replies to test production policy routing, not classifier quality or resource confinement.",
             "Windows paired latency and the optional generic probe are unsupported; requested unsupported stages are skips, making the suite incomplete.",
             "Original child reports remain beside this summary, including failed or incomplete reports.", ""]
    return "\n".join(rows)


def run(args):
    repo, binary, out = args.repo.resolve(), args.agentfw.resolve(), args.output.resolve()
    required = BASE_STAGES + (("generic",) if getattr(args, "include_generic", False) else ())
    if out.is_relative_to(repo):
        raise ValueError("output_must_be_outside_candidate")
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": "sou18-local-suite/1", "status": "incomplete",
              "expected_commit": args.expected_commit, "observed_at": datetime.now(timezone.utc).isoformat(),
              "scope": "selected-local-fixture-path", "generic_candidate_acceptance": "pending_sou15",
              "required_stages": list(required),
              "actual_host": "not_run", "merge_protection_verified": False, "acceptance_passed": False,
              "build_provenance": "supplied_binary; retain the caller's matching build record",
              "environment": {"os": platform.system(), "architecture": platform.machine(),
                              "python": platform.python_version(), "cpu_count": os.cpu_count()},
              "stages": [{"name": name, "status": "not_run", "reason": "not_started"} for name in required]}
    profiles = []
    helpers, before, binary_hash, runner_hash = {}, None, None, None
    try:
        helpers = {name: load(repo, name) for name in required}
        before = helpers["latency"].snapshot(repo)
        report["source_before"] = compact(before)
        if before["dirty"] or before["commit"] != args.expected_commit:
            raise ValueError("clean_exact_candidate_required")
        binary_hash = report["binary_sha256"] = helpers["setup"].sha(binary)
        runner_hash = report["runner_sha256"] = helpers["setup"].sha(Path(__file__))
        report["probe_sha256"] = {name: helpers["setup"].sha(repo / "scripts" / SCRIPTS[name]) for name in required}
        common = ["--repo", str(repo), "--agentfw", str(binary), "--expected-commit", args.expected_commit]
        arguments = {
            "setup": ["--run", "--agentfw", str(binary), "--output", str(out / REPORTS["setup"])],
            "status": ["--run", *common, "--output", str(out / "status")],
            "latency": [*common, "--pairs", str(args.pairs), "--output", str(out / "latency")],
            "generic": [*common, "--expected-binary-sha256", binary_hash, "--output", str(out / "generic")],
        }
        for stage in report["stages"]:
            name = stage["name"]
            if helpers["latency"].snapshot(repo) != before or helpers["setup"].sha(binary) != binary_hash:
                raise ValueError("candidate_or_binary_changed")
            if name in {"latency", "generic"} and sys.platform not in ("linux", "darwin"):
                stage.update(status="skip", reason=("paired_latency" if name == "latency" else name)
                             + "_requires_native_linux_or_macos")
                continue
            print(f"Running {name}...", flush=True)
            with tempfile.TemporaryDirectory(prefix="sou18-suite-") as temporary:
                profile = Path(temporary).resolve()
                profiles.append(profile)
                env = helpers["setup"].private_environment(profile)
                process = execute([sys.executable, "-I", str(repo / "scripts" / SCRIPTS[name]), *arguments[name]],
                                  repo, env, {"setup": 120, "status": 180, "latency": 240, "generic": 120}[name])
            stage["process"] = process
            path = out / REPORTS[name]
            try:
                raw = path.read_bytes()
                stage["report_sha256"] = helpers["latency"].sha(raw)
                data = helpers["latency"].strict_json(raw)
                stage["status"], stage["reason"] = evaluate(name, data, process, before, binary_hash, args.pairs, helpers)
                if name == "latency" and stage["status"] == "pass":
                    report["paired_overhead_ms"] = data["summary"]["paired_overhead_ms"]
            except (OSError, ValueError, TypeError):
                stage.update(status="incomplete", reason="missing_or_invalid_report")
            if process["timed_out"]:
                stage.update(status="incomplete", reason="process_timed_out; cleanup_not_certified")
                break
    except (OSError, ValueError, subprocess.SubprocessError, ImportError, AttributeError, KeyboardInterrupt) as error:
        safe_labels = {"clean_exact_candidate_required", "candidate_or_binary_changed"}
        report["error"] = str(error) if type(error) is ValueError and str(error) in safe_labels else type(error).__name__
    finally:
        report["owned_profiles_removed"] = all(not path.exists() for path in profiles)
        report["source_binary_stable"] = False
        if before is not None and binary_hash is not None:
            try:
                after = helpers["latency"].snapshot(repo)
                report["source_after"] = compact(after)
                report["source_binary_stable"] = (before == after and helpers["setup"].sha(binary) == binary_hash
                    and helpers["setup"].sha(Path(__file__)) == runner_hash)
            except (OSError, subprocess.SubprocessError):
                pass
        stable = report["source_binary_stable"] and report["owned_profiles_removed"] and "error" not in report
        report["status"] = outcome(report["stages"], stable, required)
        (out / "results.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        (out / "report.md").write_text(markdown(report), encoding="utf-8")
    print(f"Local probe suite: {report['status']}. Final generic acceptance remains pending. Evidence: {out}")
    return {"pass": 0, "fail": 1, "incomplete": 2}[report["status"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--agentfw", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pairs", type=int, default=30)
    parser.add_argument("--include-generic", action="store_true",
                        help="also run the accepted synthetic classifier/policy boundary matrix")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "not_run", "processes_started": 0, "generic_candidate_acceptance": "pending_sou15"}))
        return 0
    if not all((args.repo, args.agentfw, args.expected_commit, args.output)) or not 30 <= args.pairs <= 60:
        parser.error("--run requires --repo, --agentfw, --expected-commit, a fresh --output directory and 30..60 pairs")
    try:
        return run(args)
    except (OSError, ValueError) as error:
        reason = str(error) if type(error) is ValueError else type(error).__name__
        print(f"Suite could not start: {reason}. No acceptance claimed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
