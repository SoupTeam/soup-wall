#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in SOU-127 installed two-server stability exercise; never an all-PR job.

Only --run executes. Smoke is a development slice, never hour-long evidence.
Raw syscall traces and credentials remain in a private stage. Public evidence
contains owned synthetic transcripts, numeric observations and dispatch hashes.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from types import SimpleNamespace
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import pilot_stability as S


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load("stability_installed", "qualify-installed-pilot.py")
TRACE = load("stability_syscalls", "qualify-pilot-launcher.py")
CRASH = load("stability_crash", "verify-sou86-crash-supervision.py")
PROVENANCE = load("stability_provenance", "verify-sou72-provenance-budget.py")
require = S.require


class Observer:
    def __init__(self, output, python):
        self.path = output / "process-samples.ndjson"
        self.stream = self.path.open("xb")
        self.errors, self.latest = [], None
        self.samples, self.total, self.max_gap, self.previous = 0, 0, 0, None
        self.peaks = {key: 0 for key in ("processes", "fds", "threads", "rss_bytes")}
        command = ["sudo", "-n", "--", str(python), "-I", str(ROOT / "scripts/pilot_stability.py"),
                   "--observe", "--root", str(os.getpid()), "--start", str(S.identity(os.getpid()))]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL)
        def drain():
            try:
                for raw in iter(self.process.stdout.readline, b""):
                    self.total += len(raw)
                    require(self.total <= S.BOUNDS["observer_bytes"] and len(raw) <= 65536, "observer_stream_bound")
                    self.stream.write(raw)
                    row = json.loads(raw)
                    require("error" not in row, "independent_observer_failed")
                    self.samples += 1
                    if self.previous is not None:
                        self.max_gap = max(self.max_gap, row["monotonic"] - self.previous)
                    self.previous, self.latest = row["monotonic"], row
                    for key in self.peaks:
                        self.peaks[key] = max(self.peaks[key], row["totals"][key])
            except Exception as error:
                self.errors.append(type(error).__name__)
                self.process.stdin.close()
        self.thread = threading.Thread(target=drain, daemon=True)
        self.thread.start()

    def check(self):
        require(not self.errors and self.process.poll() is None, "resource_observer_lost")
        require(self.latest is not None and time.monotonic() - self.latest["monotonic"] <= 5, "resource_observer_stale")

    def idle(self):
        self.check()
        return self.latest["totals"].copy()

    def finish(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()
        self.process.wait(timeout=5)
        self.thread.join(timeout=5)
        self.stream.close()
        return {"samples": self.samples, "max_gap_seconds": self.max_gap,
                "peaks": self.peaks, "errors": self.errors,
                "stopped": self.process.returncode == 0 and not self.thread.is_alive(),
                "file": self.path.name, "sha256": P.sha(self.path),
                "scope": "read-only privileged procfs observer of pinned owned descendants"}


def calibrate_observer(observer, python):
    code = ("import os,sys,threading\n"
            "fds=[os.open('/dev/null',os.O_RDONLY) for _ in range(32)]\n"
            "event=threading.Event()\n"
            "threads=[threading.Thread(target=event.wait) for _ in range(4)]\n"
            "for t in threads:t.start()\n"
            "print('READY',flush=True)\n"
            "sys.stdin.readline()\n"
            "event.set()\n"
            "for t in threads:t.join()\n")
    process = subprocess.Popen([str(python), "-I", "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        require(process.stdout.readline() == b"READY\n", "observer_calibration_child_failed")
        deadline, row = time.monotonic() + 5, None
        while time.monotonic() < deadline:
            row = next((r for r in (observer.latest or {}).get("processes", []) if r["pid"] == process.pid), None)
            if row and row["fds"] >= 35 and row["threads"] == 5 and row["rss_bytes"] > 0:
                break
            time.sleep(0.05)
        require(row and row["fds"] >= 35 and row["threads"] == 5 and row["rss_bytes"] > 0, "observer_not_calibrated")
        return {"passed": True, "controlled_open_fds": 32, "controlled_threads": 4, "observed": row}
    finally:
        process.stdin.close()
        process.wait(timeout=5)


class Pilot(P.Pilot):
    def __init__(self, *args, strace, **kwargs):
        super().__init__(*args, **kwargs)
        self.strace = strace
        self.trace_witnesses = []
        self.host_counter = 0
        self.label_lock = threading.Lock()

    def prepare(self, fault=None):
        result = super().prepare(fault)
        # The original unrelated sentinel's 30-minute sleep was a qualification
        # duration, not a product timeout. Replace only this owned test guard.
        P.BASE.DEMO.stop(self.unrelated)
        self.unrelated.wait(timeout=5)
        self.unrelated = subprocess.Popen([str(self.paths["python"]), "-I", "-c", "import time; time.sleep(4500)"],
                                          env=self.env, cwd=self.private, start_new_session=True)
        self.unrelated_start = P.BASE.ProcessWitness.identity(self.unrelated.pid)
        return result

    def host(self, label, batches, **kwargs):
        # Labels are unique even when the accepted recovery helper reuses one.
        with self.label_lock:
            self.host_counter += 1
            label = f"{self.host_counter:03d}-" + label
        trace = self.private / (label + ".trace")
        limit = ("import os,resource,sys;resource.setrlimit(resource.RLIMIT_FSIZE,"
                 f"({S.BOUNDS['trace_bytes']},{S.BOUNDS['trace_bytes']}));os.execv(sys.argv[1],sys.argv[1:])")
        prefix = [str(self.paths["python"]), "-I", "-c", limit, str(self.strace),
                  "-f", "-qq", "-s", "1048576", "-e", "trace=execve,write,writev,connect,sendto,sendmsg",
                  "-o", str(trace)]
        evidence, results = super().host(label, batches, command_prefix=prefix, **kwargs)
        require(trace.stat().st_size < S.BOUNDS["trace_bytes"], "syscall_trace_incomplete")
        raw = trace.read_text()
        witness = TRACE.collector_dispatches(raw, self.binary, strict=False)
        # Every dispatched tool must be one of the explicitly supported reads.
        require(all(call["tool"] in ("read_text_file", "git_show", "git_status", "git_diff")
                    for call in witness["calls"]), "forbidden_original_dispatch")
        # The declared errors here are pre-dispatch Ask/profile/outage cases.
        # Assert exact successful dispatches and zero dispatch of those errors;
        # an error frame by itself would not establish non-execution.
        proposals = [row for batch in batches for row in batch]
        expected = Counter((tool, S.digest({"repo_path": "/workspace", **arguments} if kind == "git" else arguments))
                           for index, (kind, tool, arguments) in enumerate(proposals)
                           if not results[f"toolu_pilot_{index}"]["is_error"])
        require(Counter((row["tool"], row["args_sha256"]) for row in witness["calls"]) == expected,
                "independent_dispatch_arguments_changed")
        import re
        endpoints = re.findall(r'(?:inet_addr\("|inet_pton\(AF_INET6, ")([^"\n]+)', raw)
        require(endpoints, "network_observer_not_calibrated")
        require(all(ip in ("127.0.0.1", "::1") for ip in endpoints), "non_loopback_egress_attempt")
        # No unknown address family or datagram send can be treated as absent.
        network = [line for line in TRACE.normalized_syscalls(raw)[0]
                   if re.search(r"\b(connect|sendto|sendmsg)\(", line)]
        require(all("AF_INET" not in line or "127.0.0.1" in line or '"::1"' in line for line in network),
                "unclassified_network_address")
        record = {"label": label, "trace_sha256": P.sha(trace), "trace_bytes": trace.stat().st_size,
                  "dispatch": witness, "observed_loopback_endpoints": len(endpoints),
                  "non_loopback_egress_attempts": 0}
        self.trace_witnesses.append(record)
        evidence["independent_dispatch_witness"] = record
        return evidence, results

    def retain(self):
        # Same accepted redaction, with a frozen long-run file denominator.
        rows = []
        paths = sorted(self.private.glob("*.log")) + sorted(self.private.glob("host-*/*.log"))
        audit = self.home / ".agentfw/audit.jsonl"
        if audit.exists():
            paths.append(audit)
        require(len(paths) <= 128, "long_run_evidence_file_bound")
        for index, path in enumerate(paths):
            with path.open("rb") as stream:
                raw = stream.read(P.LIMITS["host_bytes"] + 1)
            require(len(raw) <= P.LIMITS["host_bytes"], "long_run_log_incomplete")
            target = self.output / f"owned-{index:03d}-{path.name}"
            P.owned_bytes(target, self.redact(raw))
            rows.append({"file": target.name, "sha256": P.sha(target), "complete": True})
        for index, client in enumerate(self.clients):
            rows.append(self.retain_json(f"client-{index:02d}-wire.json", client.transcript()))
        return rows

    def server_recovery(self):
        host = str(uuid.uuid4())
        with self.client("git", host, "server-surviving-git") as sibling:
            with self.client("filesystem", host, "server-interrupted-filesystem") as client:
                reply, _ = client.exchange(P.frame(10, "filesystem", "read_text_file", {"path": "/workspace/guide.txt"}))
                require(P.BASE.result_text(reply) == P.BASE.TEXT, "server_precrash_read_failed")
                profile = json.loads((self.installs["filesystem"] / "profile.json").read_text())
                runtime = Path(profile["runtimePath"])
                client.process_witness.sample()
                targets = []
                for (pid, start) in list(client.process_witness.observed):
                    try:
                        observed, expected = Path(f"/proc/{pid}/exe").stat(), runtime.stat()
                        if (observed.st_dev, observed.st_ino) == (expected.st_dev, expected.st_ino):
                            targets.append((pid, start))
                    except (FileNotFoundError, PermissionError):
                        continue  # Only the exact independently observable Node is eligible.
                require(len(targets) == 1, "owned_original_server_target_ambiguous")
                pid, start = targets[0]
                started = time.monotonic()
                injected = CRASH.signal_owned(pid, start, runtime)
                client.process.wait(timeout=10)
                client.expected_exit = client.process.returncode
                require(client.expected_exit != 0, "server_death_not_observed")
                cleanup = client.process_witness.finish()
                require(cleanup["all_stopped"] and time.monotonic() - started <= 15, "server_cleanup_unbounded")
            response, _ = sibling.exchange(P.frame(10, "git", "git_show", {"revision": "HEAD"}))
            require(P.GIT.text(response) == self.controls[("git", "git_show", "default")], "server_death_killed_sibling")
            with self.client("filesystem", host, "server-interrupted-filesystem") as replacement:
                response, _ = replacement.exchange(P.frame(10, "filesystem", "read_text_file", {"path": "/workspace/guide.txt"}))
                require(P.BASE.result_text(response) == P.BASE.TEXT, "server_fresh_authority_recovery_failed")
        return {"passed": True, "target": injected, "cleanup": cleanup, "sibling_useful": True,
                "fresh_authority": True, **self.preserve()}


def workflows(pilot, label, count):
    batches = []
    for index in range(count):
        second = bool(index % 2)
        batches.append([("filesystem", "read_text_file", {"path": "/workspace/notes.txt" if second else "/workspace/guide.txt"}),
                        ("git", "git_diff", {"target": "HEAD", "context_lines": 3}) if second else
                        ("git", "git_show", {"revision": "HEAD"})])
    evidence, results = pilot.host(label, batches)
    for index in range(count):
        second = bool(index % 2)
        expected = [pilot.controls[("filesystem", "read_text_file", "default" if second else "guide")],
                    pilot.controls[("git", "git_diff" if second else "git_show", "default")]]
        for offset, kind in enumerate(("filesystem", "git")):
            actual = results[f"toolu_pilot_{2 * index + offset}"]
            require(not actual["is_error"] and P.host_text(actual, kind) == expected[offset], "benign_workflow_interrupted")
    calls = evidence["independent_dispatch_witness"]["dispatch"]["calls"]
    require(len(calls) == count * 2, "useful_dispatch_count_changed")
    return {"completed_workflows": count, "host": evidence}


def run(args):
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), "new_external_output_required")
    output.mkdir(mode=0o700, parents=True)
    workload = S.plan(args.mode)
    report = {"format": S.FORMAT, "status": "incomplete", "skipped": 0,
              "workload": workload, "workload_sha256": S.digest(workload),
              "iterations": [], "faults": {}, "native_samples": []}
    P.private_json(output / "frozen-plan.json", workload)
    P.private_json(output / "report.json", report)
    pilot = observer = private = None
    started = None
    try:
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "linux_x86_64_required")
        require(args.selection.stat().st_size <= 65536, "selection_bound")
        selection = P.strict_json(args.selection.read_bytes())
        before, paths = P.validate_selection(selection, args.expected_commit)
        report["source_before"] = before
        report["selected_sha256"] = {role: P.sha(path) for role, path in paths.items()}
        report["strace_sha256"] = P.sha(args.strace)
        private = tempfile.TemporaryDirectory(prefix="pilot-stability-")
        pilot = Pilot(Path(private.name), output, paths, report, selection["expected_refusal"], strace=args.strace.resolve(strict=True))
        report["installed"] = pilot.prepare()
        version = subprocess.check_output([str(paths["claude"]), "--version"], env=pilot.env, timeout=15, text=True).strip()
        host_package = json.loads((ROOT / "profiles/mcp/filesystem-readonly-v1/claude-host/package.json").read_text())
        require(version == host_package["dependencies"]["@anthropic-ai/claude-code"] + " (Claude Code)", "selected_host_version_changed")
        observer = Observer(output, paths["python"])
        report["observer_calibration"] = calibrate_observer(observer, paths["python"])
        report["sandbox"] = {"passed": True, "evidence": pilot.sandbox()}
        report["calibration"] = {"passed": True, "evidence": pilot.calibrate()}
        report["protection_before"] = {"passed": True, "refusal": pilot.refusal(), "independent": pilot.independent()}
        P.private_json(output / "report.json", report)
        # Calibration itself includes actual original reads, controlled write,
        # FIFO readers, repository opens, injection withholding and receiver hit.
        native = S.native_sample(pilot.http("/native/v1/instance"))
        require(native["active_collectors"] == 0, "calibration_capacity_not_released")
        started = time.monotonic()
        native_stopped, expected_outage = threading.Event(), threading.Event()
        native_errors = []
        def sample_native():
            unavailable_since = None
            while not native_stopped.is_set():
                try:
                    sample = S.native_sample(pilot.http("/native/v1/instance"))
                    report["native_samples"].append({"seconds": round(time.monotonic() - started, 3), **sample})
                    unavailable_since = None
                    require(len(report["native_samples"]) <= 800, "native_sample_bound")
                except Exception as error:
                    # Only an explicitly declared daemon outage permits an
                    # unavailable observation. It is retained, not made zero.
                    if expected_outage.is_set() and not isinstance(error, ValueError):
                        unavailable_since = unavailable_since or time.monotonic()
                        if time.monotonic() - unavailable_since > S.BOUNDS["recovery_seconds"]:
                            native_errors.append("declared_outage_exceeded_bound")
                            break
                        report["native_samples"].append({"seconds": round(time.monotonic() - started, 3), "unavailable": True})
                    else:
                        native_errors.append(type(error).__name__)
                        break
                native_stopped.wait(5)
        native_thread = threading.Thread(target=sample_native, daemon=True)
        native_thread.start()
        def tick():
            observer.check()
            require(not native_errors and native_thread.is_alive(), "native_observer_lost")
        for index in range(workload["rounds"]):
            target = started + index * workload["interval_seconds"]
            while time.monotonic() < target:
                tick()
                time.sleep(min(0.5, max(0, target - time.monotonic())))
            iteration = {"index": index, "status": "incomplete", "completed_workflows": 0,
                         "false_interruptions": 0, "started_seconds": round(time.monotonic() - started, 3)}
            report["iterations"].append(iteration)
            P.private_json(output / f"iteration-{index:02d}.json", iteration)
            P.private_json(output / "report.json", report)
            iteration_started = time.monotonic()
            try:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(workflows, pilot, f"round-{index}-{host}", workload["workflows_per_host"])
                               for host in range(2)]
                    while not all(future.done() for future in futures):
                        tick()
                        time.sleep(0.5)
                    iteration["hosts"] = [future.result() for future in futures]
                iteration["completed_workflows"] = sum(row["completed_workflows"] for row in iteration["hosts"])
                pilot.preserve()
                iteration["elapsed_seconds"] = round(time.monotonic() - iteration_started, 3)
                iteration["status"] = "pass"
                # Observe an idle sample after all host descendants exited.
                time.sleep(1.2)
                iteration["idle"] = observer.idle()
                fault = workload["faults"].get(str(index))
                if fault:
                    actions = {"parallel-cancellation": pilot.parallel, "collector-death": pilot.collector_recovery,
                               "server-death": pilot.server_recovery, "daemon-outage": pilot.daemon_recovery}
                    if fault == "provenance-pressure":
                        pressure_output = output / "provenance-pressure"
                        code = PROVENANCE.run(SimpleNamespace(agentfw=paths["agentfw"], output=pressure_output,
                                                              expected_commit=args.expected_commit))
                        pressure = P.strict_json((pressure_output / "report.json").read_bytes())
                        require(code == 0, "provenance_pressure_failed")
                        PROVENANCE.grade(pressure)
                        evidence = {"passed": True, "report_sha256": P.sha(pressure_output / "report.json"),
                                    "checks": len(pressure["checks"]), "scope": workload["pressure_scope"]}
                    else:
                        if fault == "daemon-outage":
                            expected_outage.set()
                        try:
                            evidence = {"passed": True, "evidence": actions[fault]()}
                        finally:
                            expected_outage.clear()
                    report["faults"][fault] = evidence
                tick()
            except Exception:
                iteration["status"] = "fail"
                iteration["false_interruptions"] = 1
                raise
            finally:
                P.private_json(output / f"iteration-{index:02d}.json", iteration)
                P.private_json(output / "report.json", report)
                print(json.dumps({"event": "stability_iteration", "index": index, "status": iteration["status"],
                                  "completed_workflows": iteration["completed_workflows"],
                                  "elapsed_seconds": round(time.monotonic() - started, 3)}), flush=True)
        deadline = started + workload["duration_seconds"]
        while time.monotonic() < deadline:
            tick()
            time.sleep(0.5)
        report["final_follow_up"] = {"passed": True, "evidence": workflows(pilot, "final-follow-up", 1)}
        report["protection_after"] = {"passed": True, "refusal": pilot.refusal(), "independent": pilot.independent()}
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["source_after"] = P.source()
        report["selected_unchanged"] = all(P.sha(path) == report["selected_sha256"][role] for role, path in paths.items())
        native_stopped.set()
        native_thread.join(timeout=6)
        require(not native_errors and not native_thread.is_alive(), "native_observer_incomplete")
        report["cleanup"] = {"passed": True, "evidence": pilot.cleanup()}
        pilot = None
        report["observer"] = observer.finish()
        observer = None
        if args.mode == "soak":
            report["summary"] = S.grade(report)
            report["status"] = "pass"
        else:
            report["status"] = "smoke-pass"
    except Exception as error:
        report["status"] = "fail"
        report["error"] = {"type": type(error).__name__, "code": str(error) if isinstance(error, ValueError) else "execution_failed"}
        diagnostic = traceback.format_exc().encode()
        safe_diagnostic = pilot.redact(diagnostic) if pilot else diagnostic
        P.owned_bytes(output / "failure.txt", safe_diagnostic[:65536])
        print(json.dumps({"event": "stability_failure", "diagnostic": safe_diagnostic[:65536].decode(errors="replace")}), flush=True)
    finally:
        if "native_stopped" in locals():
            native_stopped.set()
            native_thread.join(timeout=6)
        if pilot:
            try:
                report["cleanup"] = {"passed": True, "evidence": pilot.cleanup()}
            except Exception:
                report["cleanup"] = {"passed": False}
        if observer:
            report["observer"] = observer.finish()
        if private:
            private.cleanup()
        P.private_json(output / "report.json", report)
    print(json.dumps({"event": "stability_result", "status": report["status"], "error": report.get("error"),
                      "iterations": len(report["iterations"]), "report_sha256": P.sha(output / "report.json")}), flush=True)
    return 0 if report["status"] in ("pass", "smoke-pass") else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--mode", choices=("smoke", "soak"), default="soak")
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--strace", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False, "workload": S.plan(args.mode)}))
        return 0
    require(all((args.selection, args.strace, args.expected_commit, args.output)), "execution_inputs_required")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
