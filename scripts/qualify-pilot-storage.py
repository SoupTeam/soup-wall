#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded native Linux storage-failure qualification using disposable owned data.

Run on an exact clean candidate with the normal installed-pilot selection. The
original profile installers run once. No live provider, mounts, host disk filling,
operator data, production fault switches or acceptance-threshold changes are used.
Loader faults model errno at exact owned paths; they do not measure a real disk's
capacity, quota configuration or power-loss durability. Raw evidence stays private.
"""
from __future__ import annotations

import argparse
import copy
import errno
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from pilot_qualification import Failure, LIMITS, canonical, digest, require, sha


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PILOT = load("storage_installed_pilot", "qualify-installed-pilot.py")
PREP = load("storage_preparation", "prepare-installed-pilot.py")
ERRORS = ("ENOSPC", "EDQUOT", "EROFS", "EACCES")
CASES = ("exact-installed-inputs", "sandbox-positive", "witness-calibration",
         *("publication-" + name.lower() for name in ERRORS),
         "publication-rename", "publication-directory-sync", "interrupted-publication",
         "publication-cleanup-failure", "publication-directory-permission",
         *("startup-" + name.lower() for name in ERRORS),
         "startup-config-unreadable",
         *("audit-" + name.lower() for name in ERRORS),
         "daemon-fresh-conversation", "final-cleanup")
STATES = ("passed", "failed", "incomplete", "unsupported")
FORMAT = "sw-pilot-storage-qualification/1"


def new_report():
    return {"format": FORMAT, "status": "incomplete", "required": len(CASES),
            "scope": "native-linux-owned-path-syscall-fault-injection",
            "native_acceptance": False, "live_provider": False,
            "physical_disk_quota_and_power_loss": "not_measured",
            "cases": [{"id": name, "status": "incomplete", "reason": "not_executed",
                       "elapsed_ms": None, "evidence": {}} for name in CASES]}


def finish(report):
    require(report["required"] == len(CASES)
            and [row["id"] for row in report["cases"]] == list(CASES), "storage_denominator_changed")
    for row in report["cases"]:
        require(row["status"] in STATES, "invalid_storage_outcome")
        duration = row["elapsed_ms"]
        require(duration is None or (type(duration) in (float, int)
                and math.isfinite(duration) and duration >= 0), "invalid_storage_duration")
        require(row["status"] != "passed" or (row["reason"] is None and duration is not None
                and type(row["evidence"]) is dict and bool(row["evidence"])), "storage_pass_without_evidence")
    report["counts"] = {state: sum(row["status"] == state for row in report["cases"]) for state in STATES}
    counts = report["counts"]
    if counts["passed"] == len(CASES):
        env = report.get("environment", {})
        before = report.get("source_before", {})
        require(env.get("os") == "Linux" and env.get("machine") == "x86_64"
                and env.get("non_root") is True and env.get("ubuntu") == "24.04"
                and isinstance(env.get("kernel"), str) and env["kernel"]
                and "microsoft" not in env["kernel"].lower(), "storage_native_platform_evidence_missing")
        require(before == report.get("source_after") and before.get("dirty") is False
                and re.fullmatch(r"[0-9a-f]{40}", before.get("commit", ""))
                and re.fullmatch(r"[0-9a-f]{40}", before.get("tree", ""))
                and re.fullmatch(r"[0-9a-f]{64}", before.get("files_sha256", "")),
                "storage_exact_source_evidence_missing")
        require(set(report.get("selected_sha256", {})) == set(PILOT.ROLES)
                and all(re.fullmatch(r"[0-9a-f]{64}", value)
                        for value in report["selected_sha256"].values())
                and all(re.fullmatch(r"[0-9a-f]{64}", report.get(key, ""))
                        for key in ("selection_sha256", "strace_sha256", "driver_sha256", "fixture_sha256")),
                "storage_selected_identity_evidence_missing")
    report["status"] = ("passed" if counts["passed"] == len(CASES) else "failed" if counts["failed"]
                        else "unsupported" if counts["unsupported"] else "incomplete")
    report["native_acceptance"] = report["status"] == "passed"
    report["remaining_blockers"] = [{k: row[k] for k in ("id", "status", "reason")}
                                    for row in report["cases"] if row["status"] != "passed"]
    require(len(canonical(report)) <= LIMITS["report_bytes"], "storage_report_bound")
    return report


def measure(report, name, action, seconds=180):
    row = next(row for row in report["cases"] if row["id"] == name)
    require(row["reason"] == "not_executed", "storage_case_already_executed")
    started = time.monotonic()
    try:
        row["evidence"] = action()
        require(type(row["evidence"]) is dict and row["evidence"], "storage_empty_evidence")
        require(time.monotonic() - started <= seconds, "storage_case_deadline")
        row.update(status="passed", reason=None)
        return True
    except Failure as error:
        row.update(status="failed", reason=error.code)
    except Exception as error:
        row.update(status="failed", reason="runtime_" + type(error).__name__.lower())
    finally:
        row["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    return False


class Fault:
    """Private, initially disarmed and independently witnessed exact-path fault."""
    def __init__(self, root, library, target, label, code, operations, output=None):
        self.root = root.resolve(strict=True)
        self.output, self.label = output, label
        self.arm = self.root / (label + ".armed")
        self.events = self.root / (label + ".events")
        require(not target.is_symlink() and target.parent.resolve(strict=True).is_relative_to(self.root),
                "fault_target_outside_owned_root")
        require(not self.arm.exists() and not self.events.exists(), "fault_fixture_already_exists")
        PILOT.owned_bytes(self.events, b"")
        self.code = code
        self.env = {"LD_PRELOAD": str(library), "SW_STORAGE_ROOT": str(self.root),
                    "SW_STORAGE_TARGET": str(target), "SW_STORAGE_ARM": str(self.arm),
                    "SW_STORAGE_EVENT": str(self.events), "SW_STORAGE_ERRNO": str(code),
                    "SW_STORAGE_CLEANUP_ERRNO": str(errno.EACCES), "SW_STORAGE_OPS": operations}

    def enable(self):
        PILOT.owned_bytes(self.arm, b"armed\n")

    def disable(self):
        self.arm.unlink(missing_ok=True)

    def evidence(self, operations=None):
        require(self.events.stat().st_size <= 65536, "fault_event_bound")
        rows = [PILOT.strict_json(raw) for raw in self.events.read_bytes().splitlines()]
        require(rows and all(set(row) == {"op", "errno"}
                and row["errno"] == (errno.EACCES if row["op"] == "unlink" else self.code)
                for row in rows), "storage_fault_not_observed")
        if operations:
            require(set(operations).issubset({row["op"] for row in rows}), "storage_fault_operation_missing")
        result = {"errno": errno.errorcode[self.code], "operations": sorted({row["op"] for row in rows}),
                  "injections": len(rows), "events_sha256": sha(self.events), "exact_owned_path": True}
        if self.output is not None:
            retained = self.output / (self.label + "-fault-events.jsonl")
            if not retained.exists():
                PILOT.owned_bytes(retained, self.events.read_bytes())
            require(sha(retained) == result["events_sha256"], "retained_fault_witness_changed")
            result["events_file"] = retained.name
        return result


class StoragePilot(PILOT.Pilot):
    """Keep loader settings exclusively on the test daemon's Popen call."""
    daemon_fault = None
    retained_limit = 128

    def start_daemon(self):
        if self.daemon_fault is None:
            return super().start_daemon()
        log = (self.private / ("daemon-" + str(len(self.logs)) + ".log")).open("wb")
        self.logs.append(log)
        self.daemon = subprocess.Popen([str(self.binary), "serve"],
            env=dict(self.env, **self.daemon_fault.env), cwd=self.workspace,
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        self.daemon_witness = PILOT.BASE.ProcessWitness(self.daemon.pid)
        require(PILOT.BASE.DEMO.wait_healthy(self.port, self.daemon), "installed_daemon_unavailable")
        self.native_token = (self.home / ".agentfw/native-token").read_text().strip()
        self.secrets.extend((self.native_token, (self.home / ".agentfw/token").read_text().strip()))
        return self.http("/native/v1/instance")["instance_id"]

    def stop_daemon(self):
        if self.daemon is not None:
            PILOT.BASE.DEMO.stop(self.daemon)
            self.daemon.wait(timeout=10)
            require(self.daemon_witness.finish()["all_stopped"], "storage_daemon_tree_remains")

    def recovered(self, label, old_instance, old_host, old_proof):
        self.stop_daemon()
        self.daemon_fault = None
        new_instance = self.start_daemon()
        require(new_instance != old_instance, "storage_instance_resurrected")
        stale = self.stale_authority_refusal(old_host, old_proof)
        host, results = self.host(label + "-fresh", [[
            ("filesystem", "read_text_file", {"path": "/workspace/guide.txt"}),
            ("git", "git_show", {"revision": "HEAD"})]])
        require(host["host_session"] != old_host
                and PILOT.host_text(results["toolu_pilot_0"], "filesystem") == PILOT.BASE.TEXT
                and PILOT.host_text(results["toolu_pilot_1"], "git") == self.controls[("git", "git_show", "default")],
                "storage_fresh_conversation_not_useful")
        return {"old_instance_id": old_instance, "new_instance_id": new_instance,
                "stale_authority": stale, "fresh_host": host, "old_context_resumed": False, **self.preserve()}

    def explicit_audit_refusal(self):
        host = str(uuid.uuid4())
        proof = self.mint(host, "filesystem", "storage-audit-control")
        body = {"contract_version": "sw-native/1", "registry_sha256": self.registry_sha256,
                "session_id": "storage-" + uuid.uuid4().hex, "event": "session_start",
                "host_session": host, "server_id": "filesystem", "child_authority": proof}
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}/native/v1", canonical(body),
            headers={"Authorization": "Bearer " + self.native_token, "Content-Type": "application/json"})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5):
                raise Failure("storage_audit_failure_accepted")
        except urllib.error.HTTPError as error:
            with error:
                raw = error.read(16385)
            # /native/v1 preserves the existing 409 contract for inspection
            # failures. The explicit error_code distinguishes I/O from policy.
            require(error.code == 409 and len(raw) <= 16384, "storage_audit_wrong_http_failure")
            value = PILOT.strict_json(raw)
            require(value.get("release") is False and value.get("error_code") == "native_audit_unavailable",
                    "storage_explicit_audit_refusal_missing")
            return {"status": 409, "error_code": value["error_code"], "release": False,
                    "response_sha256": digest(value)}

    def startup_failure(self, library, name, real_config=False):
        label = "startup-config-unreadable" if real_config else "startup-" + name.lower()
        host = str(uuid.uuid4())
        old_instance = self.http("/native/v1/instance")["instance_id"]
        proof = self.mint(host, "filesystem", label)
        fault = Fault(self.private, library, self.home / ".agentfw/audit.jsonl", label, getattr(errno, name), "open", self.output)
        self.stop_daemon()
        probe = PILOT.SHARED.FifoProbe(self.workspace / "outage.fifo")
        config = self.home / ".agentfw/config.yaml"
        config_mode = config.stat().st_mode & 0o777
        config_digest = sha(config)
        self.daemon_fault = None if real_config else fault
        if real_config:
            config.chmod(0)
        else:
            fault.enable()
        try:
            try:
                self.start_daemon()
                raise Failure("storage_faulty_start_became_ready")
            except Failure as error:
                require(error.code == "installed_daemon_unavailable", "storage_faulty_start_became_ready")
            self.daemon.wait(timeout=15)
            require(self.daemon.returncode != 0, "storage_faulty_start_succeeded")
            if real_config:
                require(b"Permission denied" in Path(self.logs[-1].name).read_bytes(),
                        "unreadable_config_error_not_observed")
                observation = {"errno": "EACCES", "operation": "read-existing-config",
                               "real_owned_config_mode": "0000", "fallback_config_used": False}
            else:
                observation = fault.evidence(["open"])
            require(self.daemon_witness.finish()["all_stopped"], "storage_failed_start_tree_remains")
        finally:
            fault.disable()
            if real_config:
                config.chmod(config_mode)
                require(sha(config) == config_digest, "storage_config_changed_during_restore")
            record = probe.finish()
            self.stop_daemon()
            self.daemon_fault = None
        require(not record["reader_seen"] and record["bytes_written"] == 0, "storage_startup_fifo_effect")
        return {"fault": observation, "host_started": False, "outcome": "startup-technical-unavailability",
                "fifo": record, "recovery": self.recovered(label, old_instance, host, proof)}

    def audit_failure(self, library, name):
        label = "audit-" + name.lower()
        fault = Fault(self.private, library, self.home / ".agentfw/audit.jsonl", label, getattr(errno, name), "write", self.output)
        self.stop_daemon()
        self.daemon_fault = fault
        old_instance = self.start_daemon()
        host = str(uuid.uuid4())
        proofs = {kind: self.mint(host, kind, label + "-" + kind) for kind in PILOT.TOOLS}
        probe = PILOT.SHARED.FifoProbe(self.workspace / "outage.fifo")
        observed = {}
        def interrupt(index, results):
            if index == 1:
                require(PILOT.host_text(results["toolu_pilot_0"], "filesystem") == PILOT.BASE.TEXT,
                        "storage_precontrol_not_useful")
                fault.enable()
                observed["native_failure"] = self.explicit_audit_refusal()
        try:
            evidence, results = self.host(label, [
                [("filesystem", "read_text_file", {"path": "/workspace/guide.txt"})],
                [("filesystem", "read_text_file", {"path": "/workspace/outage.fifo"})]],
                before_batch=interrupt, host=host, proofs=proofs)
            blocked = results["toolu_pilot_1"]
            require(blocked["is_error"] is True and PILOT.BASE.FIFO_TEXT not in json.dumps(blocked),
                    "storage_audit_result_released")
            fault.disable()
            observation = fault.evidence(["write"])
        finally:
            fault.disable()
            record = probe.finish()
            self.stop_daemon()
            self.daemon_fault = None
        require(not record["reader_seen"] and record["bytes_written"] == 0, "storage_audit_fifo_effect")
        return {"fault": observation, "host": evidence, "fifo": record, **observed,
                "outcome": "technical-unavailability-not-policy-deny",
                "recovery": self.recovered(label, old_instance, host, proofs["filesystem"])}


def compile_fixture(private):
    compiler = shutil.which("cc")
    require(compiler is not None, "native_c_compiler_required")
    source = ROOT / "scripts/fixtures/pilot_storage_fault.c"
    library = private / "storage-fault.so"
    result = subprocess.run([compiler, "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
        "-o", str(library), str(source), "-ldl"], stdin=subprocess.DEVNULL,
        capture_output=True, timeout=30, env={"PATH": os.defpath, "LANG": "C.UTF-8"})
    require(result.returncode == 0 and library.is_file(), "storage_fixture_compile_failed")
    return library


def publication_child(directory, mode):
    """Isolated test helper; normal preparation entry points never inspect this."""
    PREP.uuid.uuid4 = lambda: type("OwnedId", (), {"hex": "1" * 32})()
    record = {"format": "storage-owned-publication/1", "generation": "new"}
    if mode == "interrupt":
        original = PREP.os.replace
        def paused(old, new):
            PILOT.owned_bytes(directory / "ready", b"before-publication\n")
            while not (directory / "continue").exists():
                time.sleep(.02)
            original(old, new)
        PREP.os.replace = paused
    try:
        PREP.publish_marker(directory, record)
        return 0
    except OSError as error:
        print(json.dumps({"errno": error.errno, "failure": "storage_error"}))
    except ValueError as error:
        # Never export arbitrary paths/messages. Recognize only actual known diagnostics.
        text = str(error)
        marker = ("completion_marker_published_durability_uncertain" if text.startswith(
            "completion_marker_published_durability_uncertain") else "unpublished_file_cleanup_failed"
            if text.startswith("unpublished_file_cleanup_failed") else "other_publication_failure")
        print(json.dumps({"failure": marker}))
    return 1


def publication_case(private, output, library, strace, name, mode="write"):
    directory = private / name
    directory.mkdir(mode=0o700)
    target = directory / (".current-" + "1" * 32)
    marker = directory / "current.json"
    PREP.write_json(marker, {"format": "storage-owned-publication/1", "generation": "old"})
    original = sha(marker)
    sentinel = directory / "foreign.txt"
    PILOT.owned_bytes(sentinel, b"owned unrelated operator data\n")
    survivor = sha(sentinel)
    code = getattr(errno, name.split("-")[-1].upper(), errno.EACCES)
    fault = Fault(private, library, directory if mode == "directory-sync" else target, name, code,
                  "fsync" if mode == "directory-sync" else "write,unlink" if mode == "cleanup" else mode, output)
    fault.enable()
    trace = output / (name + ".trace")
    child_env = {"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
    # Pass loader settings through strace -E so the observer itself is never preloaded.
    command = [str(strace), "-f", "-qq", "-s", "0", "-e", "trace=openat,write,writev,fsync,fdatasync,rename,unlink,unlinkat",
               "-o", str(trace)]
    if mode not in ("interrupt", "directory-permission"):
        for key, value in fault.env.items():
            command += ["-E", key + "=" + value]
    command += [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--publication-child", str(directory), mode]
    process = None
    directory_mode = directory.stat().st_mode & 0o777
    try:
        if mode == "directory-permission":
            directory.chmod(0o500)
        process = subprocess.Popen(command, cwd=ROOT, env=child_env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        if mode == "interrupt":
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and process.poll() is None and not (directory / "ready").exists():
                time.sleep(.02)
            require((directory / "ready").is_file(), "publication_interrupt_not_reached")
            os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=20)
        require(len(stdout) + len(stderr) <= 65536 and process.returncode != 0, "faulty_publication_succeeded")
        trace.chmod(0o600)
        require(trace.stat().st_size <= LIMITS["host_bytes"] and trace.stat().st_size > 0, "publication_trace_bound")
        if mode == "interrupt":
            require(target.is_file(), "publication_interruption_no_pending_marker")
            observed = {"signal": "SIGKILL", "reached": "after-file-sync-before-rename"}
        elif mode == "directory-permission":
            result = PILOT.strict_json(stdout)
            require(result.get("errno") == errno.EACCES and not target.exists(),
                    "publication_directory_permission_not_refused")
            observed = {"errno": "EACCES", "operation": "create-pending-marker",
                        "real_owned_directory_mode": "0500"}
            directory.chmod(directory_mode)
        else:
            observed = fault.evidence(["fsync" if mode == "directory-sync" else "write" if mode == "cleanup" else mode])
            result = PILOT.strict_json(stdout)
            if mode == "directory-sync":
                require(result.get("failure") == "completion_marker_published_durability_uncertain"
                        and PILOT.strict_json(marker.read_bytes())["generation"] == "new",
                        "publication_durability_uncertainty_hidden")
            elif mode == "cleanup":
                require(result.get("failure") == "unpublished_file_cleanup_failed" and target.is_file(),
                        "publication_cleanup_failure_hidden")
                fault.evidence(["write", "unlink"])
            else:
                require(result.get("errno") == code and not target.exists(), "publication_failure_or_cleanup_wrong")
        require(mode == "directory-sync" or sha(marker) == original, "previous_marker_changed_before_publication")
        require(sha(sentinel) == survivor, "publication_foreign_file_changed")
        fault.disable()
        target.unlink(missing_ok=True)
        # Repair retries the real publication function with the fault removed.
        PREP.publish_marker(directory, {"format": "storage-owned-publication/1", "generation": "recovered"})
        require(PILOT.strict_json(marker.read_bytes())["generation"] == "recovered"
                and sha(sentinel) == survivor and not list(directory.glob(".current-*")), "publication_retry_failed")
        return {"fault": observed, "previous_marker_preserved": mode != "directory-sync",
                "new_marker_visible_with_uncertain_durability": mode == "directory-sync",
                "retry_published": True, "foreign_file_preserved": True,
                "trace_sha256": sha(trace), "cleanup_retry_required": mode in ("cleanup", "interrupt")}
    finally:
        directory.chmod(directory_mode)
        fault.disable()
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)


def run(args):
    require(args.output.is_absolute() and not args.output.exists()
            and not args.output.resolve().is_relative_to(ROOT), "new_external_storage_output_required")
    args.output.mkdir(mode=0o700, parents=True)
    report = new_report()
    report["environment"] = {"os": platform.system(), "machine": platform.machine(), "kernel": platform.release()}
    report["driver_sha256"] = sha(__file__)
    private = pilot = library = None
    paths = {}
    def prepare():
        nonlocal private, pilot, library, paths
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "native_linux_x86_64_required")
        require(os.geteuid() != 0, "non_root_storage_operator_required")
        PREP.supported_platform()
        require(re.search(r'^ID=\"?ubuntu\"?$', Path("/etc/os-release").read_text(), re.MULTILINE),
                "native_ubuntu_storage_required")
        report["environment"].update(non_root=True, ubuntu="24.04")
        require(args.selection.is_absolute() and args.selection.stat().st_size <= 65536,
                "bounded_absolute_storage_selection_required")
        require(re.fullmatch(r"[0-9a-f]{40}", args.expected_commit), "full_storage_commit_required")
        selection = PILOT.strict_json(args.selection.read_bytes())
        before, paths = PILOT.validate_selection(selection, args.expected_commit)
        require(args.strace.is_absolute() and args.strace.is_file() and os.access(args.strace, os.X_OK),
                "native_strace_required")
        report.update(source_before=before, selection_sha256=sha(args.selection), strace_sha256=sha(args.strace),
                      selected_sha256={role: sha(path) for role, path in paths.items()})
        private = tempfile.TemporaryDirectory(prefix="pilot-storage-")
        library = compile_fixture(Path(private.name))
        report["fixture_sha256"] = sha(library)
        # The original Pilot has its own benign denominator; this separate report
        # never overwrites or shrinks the installed-pilot acceptance contract.
        pilot = StoragePilot(Path(private.name), args.output, paths, copy.deepcopy(report), selection["expected_refusal"])
        version = subprocess.check_output([str(paths["claude"]), "--version"], env=pilot.env,
            cwd=pilot.private, timeout=15, text=True).strip()
        package = json.loads((ROOT / "profiles/mcp/filesystem-readonly-v1/claude-host/package.json").read_bytes())
        require(version == package["dependencies"]["@anthropic-ai/claude-code"] + " (Claude Code)",
                "selected_host_version_changed")
        report["claude_version"] = version
        return pilot.prepare()
    try:
        ready = measure(report, "exact-installed-inputs", prepare, LIMITS["setup_seconds"])
        if report["cases"][0]["reason"] == "native_linux_x86_64_required":
            report["cases"][0]["status"] = "unsupported"
        calibrated = ready and measure(report, "sandbox-positive", pilot.sandbox)
        calibrated = calibrated and measure(report, "witness-calibration", pilot.calibrate)
        if calibrated:
            for name in ERRORS:
                label = "publication-" + name.lower()
                measure(report, label, lambda label=label: publication_case(Path(private.name), args.output,
                        library, args.strace, label))
            for label, mode in (("publication-rename", "rename"), ("publication-directory-sync", "directory-sync"),
                                ("interrupted-publication", "interrupt"), ("publication-cleanup-failure", "cleanup"),
                                ("publication-directory-permission", "directory-permission")):
                measure(report, label, lambda label=label, mode=mode: publication_case(Path(private.name), args.output,
                        library, args.strace, label, mode))
            for name in ERRORS:
                if not measure(report, "startup-" + name.lower(), lambda name=name: pilot.startup_failure(library, name)):
                    break
            if all(row["status"] == "passed" for row in report["cases"]
                   if row["id"].startswith("startup-") and row["id"] != "startup-config-unreadable"):
                measure(report, "startup-config-unreadable", lambda: pilot.startup_failure(library, "EACCES", real_config=True))
            # A failed startup leaves later runtime cases explicitly unexecuted.
            startup_ready = all(row["status"] == "passed" for row in report["cases"] if row["id"].startswith("startup-"))
            if startup_ready:
                for name in ERRORS:
                    if not measure(report, "audit-" + name.lower(), lambda name=name: pilot.audit_failure(library, name)):
                        break
                audit_ready = all(row["status"] == "passed" for row in report["cases"] if row["id"].startswith("audit-"))
                if audit_ready:
                    measure(report, "daemon-fresh-conversation", pilot.daemon_recovery)
    finally:
        def cleanup():
            evidence = {}
            try:
                if pilot is not None:
                    pilot.daemon_fault = None
                    evidence = pilot.cleanup()
            finally:
                try:
                    if private is not None:
                        private.cleanup()
                        require(not Path(private.name).exists(), "storage_private_state_remains")
                finally:
                    report["source_after"] = PILOT.source()
            require(report.get("source_before") == report["source_after"], "storage_source_changed")
            require(all(sha(path) == report["selected_sha256"][key] for key, path in paths.items()), "storage_selected_input_changed")
            require(sha(args.selection) == report["selection_sha256"] and sha(args.strace) == report["strace_sha256"],
                    "storage_observer_or_selection_changed")
            require(pilot is not None, "storage_runtime_not_started")
            return {**evidence, "private_state_removed": True, "exact_source_and_selection_unchanged": True}
        if private is not None:
            measure(report, "final-cleanup", cleanup)
        finish(report)
        PILOT.owned_bytes(args.output / "report.json", canonical(report) + b"\n")
    print(json.dumps({key: report[key] for key in ("format", "status", "required", "counts", "native_acceptance")}))
    return 0 if report["status"] == "passed" else 1


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--publication-child":
        return publication_child(Path(sys.argv[2]), sys.argv[3])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--strace", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"format": FORMAT, "status": "plan", "executed": False, "cases": CASES,
                          "required": len(CASES), "live_provider": False}))
        return 0
    if not all((args.selection, args.expected_commit, args.strace, args.output)):
        parser.error("--run requires --selection, --expected-commit, --strace and --output")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
