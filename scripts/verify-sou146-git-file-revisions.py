#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in exact-source Linux acceptance of literal local Git reference reads."""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
import importlib.util

SPEC = importlib.util.spec_from_file_location("sou146_original", ROOT / "scripts/verify-sou68-real-mcp.py")
GIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GIT)
BASE, INSTALL = GIT.BASE, GIT.INSTALL
APPROVAL = GIT.load("sou146_approval", "verify-sou105-selected-approval.py")
LEASE = GIT.load("sou146_git_lease", "native_git_liveness_control.py")
require, sha, write = BASE.require, BASE.sha, BASE.write
CLASSIFIER = ROOT / "rule_baseline/git_readonly_file_revisions_v1/rule_baseline.py"
PATHS = ("notes.txt", "docs/機能 notes.txt", "docs/café.txt", ".hidden.txt")
REFS = tuple("HEAD:" + path for path in PATHS)
INVALID = ("HEAD:", "HEAD:/etc/passwd", "HEAD:../outside", "HEAD:./notes.txt", "HEAD:a//b",
           "HEAD:a/../b", "HEAD:a\\b", "HEAD:a:b", "HEAD:.git/config", "HEAD:dir/.GIT/HEAD",
           "HEAD:.gitattributes", "HEAD:-x", "HEAD:dir/-x", "HEAD:a\0b", "HEAD:a\nb",
           "HEAD:a\u202eb", "HEAD~1:notes.txt", "HEAD@{0}:notes.txt", ":notes.txt", ":/message",
           "refs/heads/main:notes.txt", "refs/heads/main", "HEAD:a*", "HEAD:a?", "HEAD:a[b",
           "--help:notes.txt", "HEAD:" + "x" * 256, "HEAD:" + "/".join(["x"] * 17))


def prepare_repo(workspace, git, env):
    workspace.mkdir(mode=0o700)
    def command(*args, data=None):
        return subprocess.check_output([str(git), "-c", "user.name=SOU146 Synthetic",
            "-c", "user.email=sou146@example.invalid", *args], cwd=workspace, env=env,
            input=data, stderr=subprocess.PIPE, timeout=20).decode("utf-8").strip()
    command("init", "--initial-branch=main", "--template=")
    for path in PATHS:
        target = workspace / path
        target.parent.mkdir(exist_ok=True)
        target.write_text("Synthetic per-file first version.\n")
    command("add", ".")
    command("commit", "-m", "Synthetic per-file baseline")
    first = command("rev-parse", "HEAD")
    for path in PATHS:
        (workspace / path).write_text("Synthetic per-file second version.\n")
    command("add", ".")
    command("commit", "-m", "Synthetic per-file second version")
    second = command("rev-parse", "HEAD")
    (workspace / "notes.txt").write_text("Synthetic staged version.\n")
    command("add", "notes.txt")
    (workspace / "notes.txt").write_text("Synthetic working version.\n")
    poison = command("hash-object", "-w", "--stdin", data=GIT.INJECTION.encode())
    return first, second, poison


def reads(first):
    result = [("git_show", {"revision": revision + ":" + path}, revision + ":" + path)
              for revision in ("HEAD", first) for path in PATHS]
    result += [("git_status", {}, "working-tree"), ("git_log", {"max_count": 2}, "local-history"),
               ("git_show", {"revision": "HEAD"}, "HEAD"), ("git_diff", {"target": first}, first)]
    return result


def writable_mapping(path):
    source = path.open("r+b", buffering=0)
    try:
        return source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_WRITE)
    except Exception:
        source.close()
        raise


def close_mapping(value):
    if value is not None:
        value[1].close()
        value[0].close()


def mapped_source_controls(stack, second, report):
    ref = stack.workspace / ".git/refs/heads/main"
    before = ref.read_bytes()
    snapshot = BASE.snapshot(stack.workspace)
    report["mapped_source_controls"] = []
    opened = writable_mapping(ref)
    try:
        profile = json.loads(stack.profile.read_text())
        result = subprocess.run([str(stack.binary), "mcp", "--native-admission", "--id", "sou146-preexisting-map", "--",
            profile["runtimePath"], "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"],
            env=dict(stack.env, AGENTFW_MCP_SERVER_PROFILE=str(stack.profile)), cwd=stack.workspace,
            input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "owned-map-before-capture", "version": "1"}}}).encode() + b"\n",
            capture_output=True, timeout=20)
        (stack.root / "preexisting-mapping.log").write_bytes(result.stderr)
        require(result.returncode != 0 and b'"event":"mcp_real_server_start"' not in result.stderr and
            b"Git file-revision source has a writer or cannot be protected" in result.stderr,
            "preexisting writable mapping was not refused before original startup")
        report["mapped_source_controls"].append({"case": "before-capture", "server_started": False, "passed": True})
    finally:
        close_mapping(opened)
    for restore_before_call in (False, True):
        label = "mapped-restored" if restore_before_call else "mapped-changed"
        with (stack.root / (label + ".log")).open("wb") as log:
            client = collector(stack, log)
            witness = GIT.RepositoryWitness(stack.workspace)
            opened = None
            try:
                client.initialize()
                GIT.text(client.exchange(GIT.call(10, "git_show", {"revision": REFS[0]}))[0])
                opened = writable_mapping(ref)
                opened[1][:] = (second + "\n").encode()
                opened[1].flush()
                require(ref.read_bytes() != before, "owned mmap write did not change source bytes")
                if restore_before_call:
                    opened[1][:] = before
                    opened[1].flush()
                    require(ref.read_bytes() == before, "owned mmap restore did not calibrate")
                witness.drain()
                reply, _ = client.exchange(GIT.call(11, "git_show", {"revision": REFS[0]}))
                require(reply.get("error", {}).get("code") == -32602 and witness.drain() == 0,
                    "mapped source change reached original dispatch")
                opened[1][:] = before
                opened[1].flush()
                close_mapping(opened)
                opened = None
                witness.drain()
                restored, _ = client.exchange(GIT.call(12))
                require(restored.get("error", {}).get("code") == -32602 and witness.drain() == 0,
                    "closing/restoring mapped source revived the view")
                report["mapped_source_controls"].append({"case": label, "write_fd_held_during_call": True,
                    "restored_before_first_call": restore_before_call, "execution_dispatched": False,
                    "restoration_still_refused": True, "passed": True})
            finally:
                close_mapping(opened)
                client.close()
                witness.close()
                if ref.read_bytes() != before:
                    ref.write_bytes(before)
        require(client.process.returncode == 0 and client.process_witness.final["all_stopped"], "mapped collector cleanup unverified")
        with (stack.root / (label + "-fresh.log")).open("wb") as log:
            client = collector(stack, log)
            try:
                client.initialize()
                GIT.text(client.exchange(GIT.call(10, "git_show", {"revision": REFS[0]}))[0])
            finally:
                client.close()
        require(client.process.returncode == 0 and client.process_witness.final["all_stopped"], "fresh mapped-source collector failed")
    require(BASE.snapshot(stack.workspace) == snapshot, "mapped-source controls changed owned repository state")


def collector(stack, log, *, legacy=False, bound=None, lease_seconds=LEASE.HEALTHY_LEASE_SECONDS):
    python = stack.install / "package/python/bin/python3.11"
    env = dict(stack.env, AGENTFW_MCP_SERVER_PROFILE=str(stack.profile), AGENTFW_CLASSIFIER="rule-baseline",
        AGENTFW_RULE_BASELINE=str(ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py" if legacy else CLASSIFIER),
        AGENTFW_CLASSIFIER_PYTHON=sys.executable)
    if bound is None:
        bound = "execution-" + os.urandom(8).hex()
    extra = []
    if bound is not None:
        args = SimpleNamespace(agentfw=stack.binary, output=stack.root)
        native_token = (Path(stack.env["HOME"]) / ".agentfw/native-token").read_text().strip()
        request = urllib.request.Request(f"http://127.0.0.1:{stack.port}/native/v1/instance",
            headers={"Authorization": "Bearer " + native_token})
        with urllib.request.urlopen(request, timeout=5) as reply:
            instance = json.load(reply)["instance_id"]
        tools = [t["name"] for t in json.loads((stack.install / "registry.json").read_text())["tools"] if t.get("mcp_result_profile")]
        token = APPROVAL.command(args, env, "child-authority", "mint", "--session", "host-" + bound,
            "--server", "sou146-git", "--agent-id", "agent-" + bound, "--instance-id", instance,
            "--ttl-seconds", "120", "--tools", ",".join(tools))
        env.update(AGENTFW_NATIVE_LIVENESS="true", AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS=str(lease_seconds),
            AGENTFW_MCP_SESSION="collector-" + bound)
        extra = ["--host-session", "host-" + bound, "--child-authority", token, "--native-approval-wait-seconds", "25"]
    client = GIT.Client([str(stack.binary), "mcp", "--native-admission", "--id", "sou146-git", *extra, "--",
        str(python), "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"],
        env, stack.workspace, log, "protected file-revision original Git")
    client.liveness_session_id = "collector-" + bound
    return client


def execution_config(config, profile):
    return dict(config, native={**config["native"], "git_execution": {
        "profile_path": str(profile), "profile_sha256": sha(profile), "server_id": "sou146-git"}})


def healthy_lease(stack, client, report, label):
    epoch = LEASE.enrolled_epoch(LEASE.audit_rows(stack.audit), client.liveness_session_id, LEASE.HEALTHY_LEASE_SECONDS)
    row = {"case": label, "session_id": client.liveness_session_id,
        "requested_seconds": LEASE.HEALTHY_LEASE_SECONDS, "granted_seconds": LEASE.HEALTHY_LEASE_SECONDS,
        "epoch_sha256": hashlib.sha256(epoch.encode()).hexdigest()}
    report.setdefault("healthy_leases", []).append(row)
    return row


def pinned_execution_profile(installed, workspace):
    """Qualification-only copy; installer defaults and metadata stay intact."""
    profile = json.loads(installed.read_text())
    observed = workspace.stat()
    profile["workspaceIdentity"] = {"device": observed.st_dev, "inode": observed.st_ino, "uid": observed.st_uid}
    return profile


def execution_reservations(stack):
    return BASE.events(stack.audit, "native_git_execution_reserved")


def execution_start(stack):
    witness = stack.daemon_witnesses[-1][2]
    witness.sample()
    return {"reservations": len(execution_reservations(stack)),
            "workers": {key for key, row in list(witness.observed.items()) if row.get("original_git_server")}}


def require_execution(stack, before, tool):
    rows = execution_reservations(stack)[before["reservations"]:]
    witness = stack.daemon_witnesses[-1][2]
    witness.sample()
    workers = [row for key, row in list(witness.observed.items())
               if row.get("original_git_server") and key not in before["workers"]]
    require(len(rows) == 1 and rows[0]["tool"] == tool
            and rows[0]["profile_sha256"] == sha(stack.profile) and workers and not witness.incomplete,
            "exact configured execution and owned original worker witness required")
    return {"route": "daemon_owned_original_pipe", "profile": json.loads(stack.profile.read_text())["format"],
            "profile_sha256": sha(stack.profile), "reservation_count": 1, "owned_original_workers": workers,
            "completion_proof": "private completed/released frame checked against direct original bytes"}


def denial_batches(first, poison):
    """Fixed coverage, independent sessions; never retry an expired authority."""
    denials = [(tool, {key: ref}, "syntax") for ref in INVALID
               for tool, key in (("git_show", "revision"), ("git_diff", "target"))]
    denials += [("git_show", {"revision": ref}, "target") for ref in
        ("HEAD:missing.txt", first + ":missing.txt", poison + ":notes.txt", "0" * 40 + ":notes.txt", "HEAD:docs")]
    denials += [("git_checkout", {"branch_name": "main"}, "mutation"),
               ("git_create_branch", {"branch_name": "forbidden"}, "mutation"),
               ("git_add", {"files": ["notes.txt"]}, "mutation")]
    cases = [(identifier, *case) for identifier, case in enumerate(denials, 100)]
    require(len(cases) == 64, "fixed refusal coverage changed")
    return [cases[start:start + 16] for start in range(0, len(cases), 16)]


def batch_worker_cleanup(stack, previous):
    observer = stack.daemon_witnesses[-1][2]
    observer.sample()
    rows = [row for key, row in list(observer.observed.items()) if key not in previous and not row["parent_process"]]
    deadline = time.monotonic() + 5
    while True:
        alive = [row for row in rows if observer.identity(row["pid"]) == row["start_time_ticks"]]
        if not alive or time.monotonic() >= deadline:
            break
        time.sleep(0.02)
    return {"observed": rows, "all_stopped": not alive and not observer.incomplete,
            "remaining": alive, "observation_complete": not observer.incomplete}


def refusal_batches(stack, first, report, expected_text):
    report["refusal_batches"] = []
    sessions = {row["session_id"] for row in report.get("healthy_leases", [])}
    epochs = {row["epoch_sha256"] for row in report.get("healthy_leases", [])}
    for number, cases in enumerate(denial_batches(first, stack.poison), 1):
        label = f"refusal-batch-{number:02d}"
        folder = stack.root / label
        folder.mkdir(mode=0o700)
        path = folder / "collector.log"
        row = {"case": label, "planned_ids": [case[0] for case in cases], "completed_pairs": [],
               "refusals": [], "passed": False, "profile_sha256": sha(stack.profile),
               "child_authority_requested_seconds": 120, "scope": "one independent authenticated collector; same-client continuation after each refusal"}
        report["refusal_batches"].append(row)
        before = BASE.snapshot(stack.workspace)
        started = time.monotonic()
        observer = stack.daemon_witnesses[-1][2]
        observer.sample()
        previous = {key for key, _ in list(observer.observed.items())}
        with path.open("wb") as log:
            client = collector(stack, log)
            processes, witness, failure = None, None, None
            try:
                processes = DaemonProcessWitness(client.process.pid)
                witness = GIT.RepositoryWitness(stack.workspace)
                client.initialize()
                row["lease"] = healthy_lease(stack, client, report, label)
                require(row["lease"]["session_id"] not in sessions and row["lease"]["epoch_sha256"] not in epochs,
                        "independent refusal batch reused a session or epoch")
                sessions.add(row["lease"]["session_id"])
                epochs.add(row["lease"]["epoch_sha256"])
                for identifier, tool, args, category in cases:
                    witness.drain()
                    response, _ = client.exchange(GIT.call(identifier, tool, args))
                    require(BASE.refused(response), "unsupported original call was not refused")
                    require(witness.drain() == 0, "refused call opened repository")
                    require(not any(r.get("host_call_id") == identifier and r.get("state") == "inflight"
                                    for r in BASE.events(path)), "refused call dispatched")
                    if category == "target":
                        require(response.get("error", {}).get("code") == -32602 and
                                "Git" in response["error"]["message"], "unattributable target refusal")
                    refusal = {"id": identifier, "category": category, "session": label,
                        "response": response, "repository_opens": 0, "execution_dispatched": False}
                    row["refusals"].append(refusal)
                    report["refusals"].append(refusal)
                    followup, _ = client.exchange(GIT.call(identifier + 1000, "git_show", {"revision": REFS[0]}))
                    require(GIT.text(followup) == expected_text, "same-client useful continuation changed")
                    row["completed_pairs"].append({"refusal_id": identifier, "continuation_id": identifier + 1000})
            except Exception as error:
                failure = error
            finally:
                try:
                    LEASE.safe_close(client)
                except Exception as error:
                    row["collector_close_error"] = type(error).__name__
                    if failure is None:
                        failure = error
                finally:
                    if witness is not None:
                        witness.close()
                    row["protected_client"] = client.transcript()
                    row["collector_cleanup"] = processes.finish() if processes is not None else {
                        "all_stopped": False, "observation_complete": False,
                        "observed": [], "remaining": None, "reason": "collector observer unavailable"}
                    row["repository_observer_ready"] = witness is not None
                    row["worker_cleanup"] = batch_worker_cleanup(stack, previous)
                    row["diagnostics"] = GIT.protected_diagnostics(row, folder)
                    row["elapsed_seconds"] = round(time.monotonic() - started, 3)
                    row["repository_unchanged"] = BASE.snapshot(stack.workspace) == before
            if failure is not None:
                raise failure
            cleanup = row["collector_cleanup"]
            workers = row["worker_cleanup"]
            require(client.process.returncode == 0 and not client.forced_cleanup
                    and cleanup["all_stopped"] and cleanup["observation_complete"]
                    and any(item.get("original_git_server") and not item["parent_process"] for item in cleanup["observed"])
                    and workers["all_stopped"] and workers["observation_complete"]
                    and any(item.get("original_git_server") for item in workers["observed"])
                    and row["repository_unchanged"],
                    "refusal batch original-process cleanup unverified")
            row["passed"] = True


def exact_reads(stack, first, report):
    originals = {}
    python = stack.install / "package/python/bin/python3.11"
    env = dict(stack.env, GIT_PYTHON_GIT_EXECUTABLE=str(stack.git), GIT_OPTIONAL_LOCKS="0")
    with (stack.root / "original.log").open("wb") as log:
        client = GIT.Client([str(python), "-I", "-B", "-m", "mcp_server_git", "--repository", str(stack.workspace)],
                            env, stack.workspace, log, "direct original Git")
        try:
            client.initialize()
            for identifier, (tool, args, ref) in enumerate(reads(first), 10):
                response, raw = client.exchange(GIT.call(identifier, tool, args, stack.workspace))
                GIT.text(response)
                originals[identifier] = raw
            poison, _ = client.exchange(GIT.call(80, "git_show", {"revision": stack.poison}, stack.workspace))
            require(GIT.INJECTION in GIT.text(poison), "direct original result-injection witness did not calibrate")
        finally:
            client.close()
            report["direct_client"] = client.transcript()
    report["original_read_sha256"] = {str(identifier): hashlib.sha256(raw).hexdigest() for identifier, raw in originals.items()}
    before = BASE.snapshot(stack.workspace)
    witness = GIT.RepositoryWitness(stack.workspace)
    path = stack.root / "collector.log"
    with path.open("wb") as log:
        client = collector(stack, log)
        try:
            client.initialize()
            report["reads"], report["refusals"] = [], []
            healthy_lease(stack, client, report, "file-exact-reads")
            for identifier, (tool, args, ref) in enumerate(reads(first), 10):
                witness.drain()
                reserved = execution_start(stack)
                response, raw = client.exchange(GIT.call(identifier, tool, args))
                execution = require_execution(stack, reserved, tool) if tool in ("git_show", "git_diff") else None
                if BASE.refused(response) and tool in ("git_show", "git_diff") and ":" not in ref:
                    # Preserve the benign expectation as FAILED; never relabel
                    # a legacy refusal or a worker failure as successful equality.
                    report.setdefault("failed_benign_controls", []).append({"id": identifier, "tool": tool,
                        "reference": ref, "expected": "original_bytes_released", "observed": "withheld",
                        "passed": False, "related_issue": "SOU-109", "response": response,
                        "original_sha256": hashlib.sha256(originals[identifier]).hexdigest()})
                    continue
                GIT.text(response)
                require(raw == originals[identifier], "original response bytes changed: " + tool + " " + ref)
                require(execution is not None or any(row.get("host_call_id") == identifier
                    and row.get("state") == "inflight" for row in BASE.events(path)), "original dispatch witness absent")
                report["reads"].append({"id": identifier, "tool": tool, "reference": ref,
                    "response_sha256": hashlib.sha256(raw).hexdigest(), "original_bytes_equal": True,
                    "execution": execution})
            witness.drain()
            reserved = execution_start(stack)
            poison, _ = client.exchange(GIT.call(80, "git_show", {"revision": stack.poison}))
            require_execution(stack, reserved, "git_show")
            require(BASE.refused(poison) and GIT.INJECTION not in json.dumps(poison),
                    "unsafe executed original output escaped result inspection")
            GIT.text(client.exchange(GIT.call(81, "git_show", {"revision": REFS[0]}))[0])
            report["result_injection_withheld"] = True
            require(BASE.snapshot(stack.workspace) == before, "protected reads/refusals changed repository")
            report["positive_repository_unchanged"] = True
        finally:
            client.close()
            witness.close()
            report["protected_client"] = client.transcript()
    require(client.process.returncode == 0 and not client.forced_cleanup and
            client.process_witness.final.get("all_stopped") is True, "protected process cleanup unverified")
    report["protected_client_scope"] = "twelve positive original frames and result-injection control only; refusal batches are separate processes"
    refusal_batches(stack, first, report, GIT.text(json.loads(originals[10])))
    require(BASE.snapshot(stack.workspace) == before, "refusal batches changed repository")
    report["repository_unchanged"] = True


def legacy_refusal(stack, report):
    python = stack.install / "package/python/bin/python3.11"
    with (stack.root / "legacy-original.log").open("wb") as original_log:
        original = GIT.Client([str(python), "-I", "-B", "-m", "mcp_server_git", "--repository", str(stack.workspace)],
            dict(stack.env, GIT_PYTHON_GIT_EXECUTABLE=str(stack.git)), stack.workspace, original_log, "direct BASE control")
        try:
            original.initialize()
            _, expected = original.exchange(GIT.call(200, repo=stack.workspace))
        finally:
            original.close()
            report["legacy_original_client"] = original.transcript()
    path = stack.root / "legacy-collector.log"
    with path.open("wb") as log:
        client = collector(stack, log, legacy=True)
        try:
            client.initialize()
            report["legacy_refusals"] = []
            healthy_lease(stack, client, report, "BASE-ID200")
            for identifier, ref in enumerate(REFS, 10):
                for tool, key, offset in (("git_show", "revision", 0), ("git_diff", "target", 100)):
                    response, _ = client.exchange(GIT.call(identifier + offset, tool, {key: ref}))
                    require(BASE.refused(response), "default v1 unexpectedly admits named references")
                    report["legacy_refusals"].append({"id": identifier + offset, "response": response})
            reserved = execution_start(stack)
            baseline, raw = client.exchange(GIT.call(200))
            execution = require_execution(stack, reserved, "git_show")
            if BASE.refused(baseline):
                report.setdefault("failed_benign_controls", []).append({"id": 200, "tool": "git_show",
                    "reference": "HEAD", "profile": INSTALL.FORMAT, "expected": "original_bytes_released",
                    "observed": "withheld", "passed": False, "related_issue": "SOU-109", "response": baseline})
            else:
                GIT.text(baseline)
                require(raw == expected, "BASE control ID200 original response bytes changed")
                report["baseline_read"] = {"id": 200, "original_bytes_equal": True,
                    "response_sha256": hashlib.sha256(raw).hexdigest(), "execution": execution}
            GIT.text(client.exchange(GIT.call(201, "git_status", {}))[0])
        finally:
            client.close()
            report["legacy_client"] = client.transcript()
    require(client.process.returncode == 0 and client.process_witness.final["all_stopped"], "legacy cleanup unverified")


def helper_control(stack, report):
    marker = stack.root / "helper-effect"
    helper = stack.root / "synthetic-fsmonitor"
    helper.write_text("#!/bin/sh\nprintf calibrated > '" + str(marker) + "'\nprintf 'token\\000'\n")
    helper.chmod(0o700)
    config = stack.workspace / ".git/config"
    original = config.read_bytes()
    try:
        config.write_bytes(original + ("\n[core]\nfsmonitor = " + str(helper) + "\n").encode())
        python = stack.install / "package/python/bin/python3.11"
        with (stack.root / "helper-direct.log").open("wb") as log:
            client = GIT.Client([str(python), "-I", "-B", "-m", "mcp_server_git", "--repository", str(stack.workspace)],
                dict(stack.env, GIT_PYTHON_GIT_EXECUTABLE=str(stack.git)), stack.workspace, log, "direct helper calibration")
            try:
                client.initialize()
                GIT.text(client.exchange(GIT.call(10, "git_status", {}, stack.workspace))[0])
                require(marker.read_text() == "calibrated", "helper effect witness did not calibrate")
            finally:
                client.close()
        marker.unlink()
        profile = json.loads(stack.profile.read_text())
        frame = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "owned-helper-control", "version": "1"}}}
        result = subprocess.run([str(stack.binary), "mcp", "--native-admission", "--id", "sou146-helper", "--",
            profile["runtimePath"], "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"],
            env=dict(stack.env, AGENTFW_MCP_SERVER_PROFILE=str(stack.profile)), cwd=stack.workspace,
            input=json.dumps(frame).encode() + b"\n", capture_output=True, timeout=20)
        (stack.root / "helper-protected.log").write_bytes(result.stderr)
        require(result.returncode != 0 and b'"event":"mcp_real_server_start"' not in result.stderr and
                not marker.exists(), "protected helper configuration reached original server")
        report["helper_control"] = {"direct_effects": 1, "protected_effects": 0, "server_started": False}
    finally:
        config.write_bytes(original)


class DaemonProcessWitness(BASE.ProcessWitness):
    """Bounded procfs observation includes children of every Tokio worker TID."""
    incomplete = False

    def sample(self):
        pending, visited, task_count = [self.parent], set(), 0
        while pending:
            if len(visited) >= 512:
                self.incomplete = True
                return
            pid = pending.pop()
            if pid in visited:
                continue
            visited.add(pid)
            identity = self.identity(pid)
            if identity is None:
                continue
            key = (pid, identity)
            row = self.observed.setdefault(key, {"pid": pid, "start_time_ticks": identity,
                                                 "parent_process": pid == self.parent})
            try:
                argv = Path(f"/proc/{pid}/cmdline").read_bytes()[:4096].split(b"\0")
                if argv[0] == b"/mcp-server/python/bin/python3.11" and b"mcp_server_git" in argv:
                    row["original_git_server"] = True
            except OSError:
                pass
            try:
                tasks = list(Path(f"/proc/{pid}/task").iterdir())
                task_count += len(tasks)
                if task_count > 4096:
                    self.incomplete = True
                    return
                for task in tasks:
                    try:
                        data = (task / "children").read_text()
                        if len(data) > 4096:
                            self.incomplete = True
                            return
                        pending.extend(int(value) for value in data.split())
                    except FileNotFoundError:
                        pass
            except (FileNotFoundError, ProcessLookupError):
                pass
            except (OSError, ValueError):
                self.incomplete = True

    def finish(self):
        result = super().finish()
        result["observation_complete"] = not self.incomplete
        result["all_stopped"] = result["all_stopped"] and not self.incomplete
        return result


def start_daemon(stack, config, label):
    write(Path(stack.env["HOME"]) / ".agentfw/config.yaml", config)
    with (stack.root / (label + "-daemon.log")).open("wb") as log:
        stack.daemon = subprocess.Popen([str(stack.binary), "serve"], env=stack.env, stdout=log, stderr=log)
    stack.daemon_witnesses.append((label, stack.daemon, DaemonProcessWitness(stack.daemon.pid)))
    require(BASE.DEMO.wait_healthy(config["port"], stack.daemon), "owned enforcing daemon failed to start: " + label)
    return stack.daemon


def policy_controls(stack, config, second, report):
    args = SimpleNamespace(agentfw=stack.binary, output=stack.root)
    python = stack.install / "package/python/bin/python3.11"
    with (stack.root / "approval-original.log").open("wb") as log:
        original = GIT.Client([str(python), "-I", "-B", "-m", "mcp_server_git", "--repository", str(stack.workspace)],
            dict(stack.env, GIT_PYTHON_GIT_EXECUTABLE=str(stack.git)), stack.workspace, log, "direct approval calibration")
        try:
            original.initialize()
            _, expected = original.exchange(GIT.call(50, "git_show", {"revision": REFS[0]}, stack.workspace))
        finally:
            original.close()
    BASE.DEMO.stop(stack.daemon)
    policy = stack.root / "ask-policy.yaml"
    policy.write_text("agent_policies:\n  - name: sou146-owned-read\n    when: { action_class: read_only }\n    action: ask\ndefault: allow\n")
    selected = dict(config, policy=str(policy), native={**config["native"], "approval": {"ttl_seconds": 30},
        "liveness": {"default_lease_seconds": LEASE.HEALTHY_LEASE_SECONDS, "max_lease_seconds": 60, "maintenance_interval_ms": 100}})
    start_daemon(stack, selected, "ask")
    report["approval_controls"] = []
    ref = stack.workspace / ".git/refs/heads/main"
    old = ref.read_bytes()
    for case in ("approve", "cancel", "substitution", "mapped-substitution", "mapped-restore"):
        path = stack.root / (case + "-collector.log")
        with path.open("wb") as log:
            client = collector(stack, log, bound=case)
            witness = GIT.RepositoryWitness(stack.workspace)
            opened = None
            try:
                client.initialize()
                healthy_lease(stack, client, report, "Ask-" + case)
                witness.drain()
                frame = GIT.call(50, "git_show", {"revision": REFS[0]})
                reserved = execution_start(stack)
                client.send(frame)
                # Retain the shared first-pending bound, including cold input
                # preparation; no separate preparation allowance.
                waiting = APPROVAL.pending(args, stack.env, timeout=5)
                require(len(execution_reservations(stack)) == reserved["reservations"], "pending Ask reached daemon execution")
                inspected = APPROVAL.inspected_output(APPROVAL.command(args, stack.env, "native-approval", "inspect", waiting["pending_id"]),
                    waiting["pending_id"], waiting["binding_sha256"])
                require(inspected["args"] == frame["params"]["arguments"] and
                    inspected["selected_invocation"]["host_call_id"] == 50 and
                    inspected["selected_invocation"]["request_sha256"] == hashlib.sha256(client.sent[-1]).hexdigest(),
                    "approval did not bind exact original request")
                require(witness.drain() == 0, "Ask executed before explicit approval")
                if case == "substitution":
                    ref.write_text(second + "\n")
                    witness.drain()
                elif case.startswith("mapped-"):
                    opened = writable_mapping(ref)
                    opened[1][:] = (second + "\n").encode()
                    opened[1].flush()
                    require(ref.read_bytes() != old, "pending-Ask mapped write did not calibrate")
                    if case == "mapped-restore":
                        opened[1][:] = old
                        opened[1].flush()
                        require(ref.read_bytes() == old, "pending-Ask mapped restore did not calibrate")
                    witness.drain()
                if case == "cancel":
                    client.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 50}})
                    response, _ = client.receive()
                    require(response.get("id") == 50 and BASE.refused(response) and witness.drain() == 0, "cancelled per-file Ask dispatched or lost correlation")
                    APPROVAL.pending(args, stack.env, empty=True, timeout=8)
                    APPROVAL.command(args, stack.env, "native-approval", "approve", waiting["pending_id"], "--binding", waiting["binding_sha256"], success=False)
                    report["approval_controls"].append({"case": case, "preapproval_effects": 0, "passed": True, "first_pending_budget_ms": 5000, "execution_dispatched": False})
                else:
                    APPROVAL.command(args, stack.env, "native-approval", "approve", waiting["pending_id"], "--binding", waiting["binding_sha256"])
                    response, raw = client.receive()
                    require(response["id"] == 50, "approval response correlation changed")
                    if case == "approve":
                        require_execution(stack, reserved, "git_show")
                        require(raw == expected, "approved original bytes/execution changed")
                        client.send(GIT.call(51, "git_show", {"revision": REFS[0]}))
                        again = APPROVAL.pending(args, stack.env, timeout=5)
                        require(again["pending_id"] != waiting["pending_id"] and witness.drain() == 0, "approval was reused")
                        APPROVAL.command(args, stack.env, "native-approval", "reject", again["pending_id"])
                        require(BASE.refused(client.receive()[0]), "second Ask was not independently refused")
                    else:
                        require(response.get("error", {}).get("code") == -32602 and witness.drain() == 0
                                and len(execution_reservations(stack)) == reserved["reservations"],
                                "approved substituted reference dispatched")
                    APPROVAL.pending(args, stack.env, empty=True, timeout=8)
                    APPROVAL.command(args, stack.env, "native-approval", "approve", waiting["pending_id"],
                        "--binding", waiting["binding_sha256"], success=False)
                    report["approval_controls"].append({"case": case, "preapproval_effects": 0, "passed": True,
                        "first_pending_budget_ms": 5000,
                        "binding_sha256": waiting["binding_sha256"], "execution_dispatched": case == "approve"})
            finally:
                close_mapping(opened)
                client.close()
                witness.close()
                if ref.read_bytes() != old:
                    ref.write_bytes(old)
        require(client.process.returncode == 0 and client.process_witness.final["all_stopped"], "approval cleanup unverified")
    BASE.DEMO.stop(stack.daemon)
    start_daemon(stack, config, "uncertainty")
    # A mismatched old classifier remains uncertain even though the new profile accepts the syntax.
    with (stack.root / "uncertainty-collector.log").open("wb") as log:
        client = collector(stack, log, legacy=True)
        witness = GIT.RepositoryWitness(stack.workspace)
        try:
            client.initialize()
            witness.drain()
            response, _ = client.exchange(GIT.call(50, "git_show", {"revision": REFS[0]}))
            require(BASE.refused(response) and witness.drain() == 0, "classifier uncertainty floor bypassed")
            GIT.text(client.exchange(GIT.call(51, "git_status", {}))[0])
            report["classifier_uncertainty_refused"] = True
        finally:
            client.close()
            witness.close()
    BASE.DEMO.stop(stack.daemon)
    policy.write_text("agent_policies:\n  - name: sou146-owned-deny\n    when: { action_class: read_only }\n    action: deny\ndefault: allow\n")
    start_daemon(stack, dict(config, policy=str(policy)), "deny")
    with (stack.root / "deny-collector.log").open("wb") as log:
        client = collector(stack, log)
        witness = GIT.RepositoryWitness(stack.workspace)
        try:
            client.initialize()
            witness.drain()
            response, _ = client.exchange(GIT.call(50, "git_show", {"revision": REFS[0]}))
            require(BASE.refused(response) and witness.drain() == 0, "policy Deny floor bypassed")
            report["policy_deny_refused"] = True
        finally:
            client.close()
            witness.close()


def source_mutations(stack, first, second, report):
    ref = stack.workspace / ".git/refs/heads/main"
    original = ref.read_bytes()
    report["source_mutations"] = []
    for name in ("rewrite", "replace", "symlink"):
        path = stack.root / ("mutation-" + name + ".log")
        before = BASE.snapshot(stack.workspace)
        with path.open("wb") as log:
            client = collector(stack, log)
            witness = GIT.RepositoryWitness(stack.workspace)
            try:
                client.initialize()
                GIT.text(client.exchange(GIT.call(10, "git_show", {"revision": REFS[0]}))[0])
                if name == "rewrite":
                    ref.write_text(second + "\n")
                elif name == "replace":
                    temporary = ref.with_name("replacement")
                    temporary.write_text(second + "\n")
                    temporary.replace(ref)
                else:
                    ref.unlink()
                    ref.symlink_to(stack.workspace / ".git/HEAD")
                witness.drain()
                response, _ = client.exchange(GIT.call(11, "git_show", {"revision": REFS[0]}))
                require(response.get("error", {}).get("code") == -32602, "source mutation was not refused")
                require(witness.drain() == 0, "withdrawn source was dispatched")
                if ref.is_symlink():
                    ref.unlink()
                ref.write_bytes(original)
                witness.drain()
                restored, _ = client.exchange(GIT.call(12))
                require(restored.get("error", {}).get("code") == -32602 and witness.drain() == 0,
                        "restoration revived withdrawn source")
                report["source_mutations"].append({"case": name, "refused": True,
                    "restoration_still_refused": True, "repository_opens": 0})
            finally:
                client.close()
                witness.close()
                if ref.is_symlink():
                    ref.unlink()
                ref.write_bytes(original)
        # Replacement intentionally changes inode; independently compare data and modes.
        after = BASE.snapshot(stack.workspace)
        for records in (before, after):
            for row in records.values():
                row.pop("inode", None)
        require(before == after, "mutation harness did not restore owned fixture")
        with (stack.root / ("fresh-" + name + ".log")).open("wb") as log:
            client = collector(stack, log)
            try:
                client.initialize()
                GIT.text(client.exchange(GIT.call(10, "git_show", {"revision": REFS[0]}))[0])
            finally:
                client.close()
        require(client.process.returncode == 0 and not client.forced_cleanup, "fresh collector failed")


def inflight_substitution(stack, second, report, *, mapped=False, restore=False):
    """Change only an owned ref after native dispatch while the real server is stopped."""
    label = "inflight-mapped-restored" if restore else "inflight-mapped" if mapped else "inflight-substitution"
    path = stack.root / (label + ".log")
    ref = stack.workspace / ".git/refs/heads/main"
    original = ref.read_bytes()
    before = BASE.snapshot(stack.workspace)
    target = None
    opened = None
    with path.open("wb") as log:
        client = collector(stack, log)
        try:
            client.initialize()
            client.process_witness.sample()
            candidates = []
            for pid, start in client.process_witness.observed:
                try:
                    argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
                    if BASE.ProcessWitness.identity(pid) == start and argv[0] == b"/mcp-server/python/bin/python3.11" and b"mcp_server_git" in argv:
                        candidates.append((pid, start))
                except OSError:
                    pass
            require(len(candidates) == 1, "one owned original server required for inflight control")
            target = candidates[0]
            os.kill(target[0], signal.SIGSTOP)
            client.send(GIT.call(50, "git_show", {"revision": REFS[0]}))
            BASE.wait_event(path, lambda rows: any(r.get("host_call_id") == 50 and r.get("state") == "inflight" for r in rows),
                "owned original request was not dispatched before substitution")
            if mapped:
                opened = writable_mapping(ref)
                opened[1][:] = (second + "\n").encode()
                opened[1].flush()
                require(ref.read_bytes() != original, "inflight mapped write did not calibrate")
                if restore:
                    opened[1][:] = original
                    opened[1].flush()
                    require(ref.read_bytes() == original, "inflight mapped restore did not calibrate")
            else:
                ref.write_text(second + "\n")
            os.kill(target[0], signal.SIGCONT)
            target = None
            response, _ = client.receive()
            require(response["id"] == 50 and response.get("error", {}).get("code") == -32602,
                    "changed source released an inflight result")
            ref.write_bytes(original)
            restored, _ = client.exchange(GIT.call(51))
            require(restored.get("error", {}).get("code") == -32602, "inflight withdrawal was revived")
            row = {"route": "collector_held_selected_view_without_daemon_execution",
                "execution_dispatched_before_mutation": True,
                "result_released": False, "restoration_still_refused": True, "passed": True}
            if mapped:
                row.update(mapped=True, restored_before_result=restore)
                report.setdefault("mapped_inflight_substitutions", []).append(row)
            else:
                report["inflight_substitution"] = row
        finally:
            if target is not None and BASE.ProcessWitness.identity(target[0]) == target[1]:
                os.kill(target[0], signal.SIGCONT)
            close_mapping(opened)
            client.close()
            ref.write_bytes(original)
    require(before == BASE.snapshot(stack.workspace), "inflight fixture state was not restored")
    require(client.process.returncode == 0 and client.process_witness.final["all_stopped"], "inflight cleanup unverified")



def pause_daemon_worker(stack, before):
    """Stop only a new owned original server; a sampled PID alone is no barrier."""
    require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
            "pidfd stop barrier prerequisite unavailable")
    witness = stack.daemon_witnesses[-1][2]
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        witness.sample()
        require(not witness.incomplete, "daemon ownership observation incomplete")
        for key, row in list(witness.observed.items()):
            pid, start = key
            if key in before["workers"] or not row.get("original_git_server"):
                continue
            if BASE.ProcessWitness.identity(pid) != start:
                continue
            confirmed = False
            suspended = False
            pin = None
            try:
                pin = os.pidfd_open(pid, 0)
                os.set_inheritable(pin, False)
                if BASE.ProcessWitness.identity(pid) != start:
                    continue
                signal.pidfd_send_signal(pin, signal.SIGSTOP)
                suspended = True
                stopped_until = min(deadline, time.monotonic() + 0.2)
                while time.monotonic() < stopped_until:
                    raw = Path(f"/proc/{pid}/stat").read_text()
                    state = raw[raw.rfind(")") + 2:].split()[0]
                    if BASE.ProcessWitness.identity(pid) != start:
                        break
                    if state in ("T", "t"):
                        confirmed = True
                        return {"pid": pid, "start_time_ticks": start, "stopped_state": state,
                                "daemon_descendant": True, "original_git_server": True, "pidfd": pin}
                    time.sleep(0.001)
            except (OSError, ProcessLookupError):
                pass
            finally:
                if not confirmed and pin is not None:
                    try:
                        if suspended:
                            signal.pidfd_send_signal(pin, signal.SIGCONT)
                    except ProcessLookupError:
                        pass
                    finally:
                        os.close(pin)
        time.sleep(0.001)
    raise RuntimeError("new owned daemon original worker stop barrier not witnessed")


def daemon_source_substitution(stack, second, report, *, mapped=False, restore=False):
    label = "daemon-" + ("mapped-restored" if restore else "mapped" if mapped else "ref-substitution")
    reference = stack.workspace / ".git/refs/heads/main"
    original, before = reference.read_bytes(), BASE.snapshot(stack.workspace)
    target, opened = None, None
    with (stack.root / (label + ".log")).open("wb") as log:
        client = collector(stack, log)
        try:
            client.initialize()
            cursor = execution_start(stack)
            client.send(GIT.call(50, "git_show", {"revision": REFS[0]}))
            target = pause_daemon_worker(stack, cursor)
            rows = execution_reservations(stack)[cursor["reservations"]:]
            require(len(rows) == 1 and rows[0]["profile_sha256"] == sha(stack.profile),
                    "paused worker not bound to exact selected daemon invocation")
            if mapped:
                opened = writable_mapping(reference)
                opened[1][:] = (second + "\n").encode()
                opened[1].flush()
                require(reference.read_bytes() != original, "daemon mapped write did not calibrate")
                if restore:
                    opened[1][:] = original
                    opened[1].flush()
                    require(reference.read_bytes() == original, "daemon mapped restore did not calibrate")
            else:
                reference.write_text(second + "\n")
            barrier = {key: value for key, value in target.items() if key != "pidfd"}
            signal.pidfd_send_signal(target["pidfd"], signal.SIGCONT)
            os.close(target["pidfd"])
            target = None
            response, _ = client.receive()
            require(response.get("id") == 50 and response.get("error", {}).get("code") == -32602,
                    "daemon source withdrawal lacked correlated refusal")
        finally:
            if target is not None:
                try:
                    signal.pidfd_send_signal(target["pidfd"], signal.SIGCONT)
                except ProcessLookupError:
                    pass
                finally:
                    os.close(target["pidfd"])
            close_mapping(opened)
            reference.write_bytes(original)
            client.close()
    require(client.process_witness.final["all_stopped"], "withdrawn daemon collector cleanup unverified")
    # An incomplete worker may retire the old session. Never relabel that as
    # same-session continuation or suppress transport/cleanup uncertainty.
    with (stack.root / (label + "-fresh.log")).open("wb") as log:
        fresh = collector(stack, log)
        try:
            fresh.initialize()
            GIT.text(fresh.exchange(GIT.call(51, "git_show", {"revision": REFS[0]}))[0])
        finally:
            fresh.close()
    require(fresh.process.returncode == 0 and fresh.process_witness.final["all_stopped"], "fresh source session failed")
    require(BASE.snapshot(stack.workspace) == before, "daemon source fixture changed")
    report.setdefault("daemon_source_withdrawal", []).append({"case": label,
        "barrier": barrier, "boundary": "actual worker prepared and paused; original tools/call write not claimed",
        "mapped": mapped, "restored_before_resume": restore, "correlated_refusal": True,
        "old_session_exit_code": client.process.returncode, "fresh_session_valid": True, "passed": True})


def run(args):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 enforcing isolation required")
    before = BASE.source()
    require(before["commit"] == args.expected_commit and not before["dirty"], "clean exact candidate required")
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), "new evidence directory outside source required")
    output.mkdir(mode=0o700, parents=True)
    report = {"format": "sou146-git-file-revisions-acceptance/1", "status": "incomplete", "skipped": 0,
        "source_before": before, "driver_sha256": sha(__file__), "binary_sha256": sha(args.agentfw),
        "classifier_sha256": sha(CLASSIFIER)}
    daemon, stack = None, None
    try:
        with tempfile.TemporaryDirectory(prefix="sou146-owned-") as temporary:
            private = Path(temporary)
            home = private / "home"
            home.mkdir(mode=0o700)
            env = BASE.environment(home)
            env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
            workspace, install = private / "workspace", private / "installed"
            first, second, poison = prepare_repo(workspace, args.git, env)
            INSTALL.install(install, workspace, args.git, args.git_sha256, args.bwrap, args.git_launcher, file_revisions=True)
            report["installation"] = json.loads((install / "installation.json").read_text())
            execution_profile = private / "execution-profile.json"
            selected = pinned_execution_profile(install / "profile.json", workspace)
            write(execution_profile, selected)
            write(output / "execution-profile.json", selected)
            report["execution_profile"] = {"sha256": sha(execution_profile), "profile": selected,
                "installed_profile_sha256": sha(install / "profile.json"), "qualification_copy": True}
            subprocess.run([str(args.agentfw), "install"], env=env, capture_output=True, check=True, timeout=30)
            port = BASE.DEMO.free_port()
            config = {"port": port, "enforce": True, "max_record_bytes": 1048576,
                "policy": str(install / "policy.yaml"), "audit": str(output / "native-audit.jsonl"),
                "native": {"registry_path": str(install / "registry.json"),
                "registry_sha256": sha(install / "registry.json"), "liveness": {
                    "default_lease_seconds": LEASE.HEALTHY_LEASE_SECONDS, "max_lease_seconds": 60, "maintenance_interval_ms": 100}}}
            write(home / ".agentfw/config.yaml", config)
            stack = SimpleNamespace(root=output, binary=args.agentfw, git=args.git, workspace=workspace,
                install=install, profile=execution_profile, env=env, daemon=None, port=port,
                poison=poison, daemon_witnesses=[], audit=output / "native-audit.jsonl")
            positive = subprocess.run([str(args.sandbox_test_binary), "selected_git_sandbox_isolates_real_python_and_git", "--ignored", "--nocapture"],
                env=dict(env, SOU68_SANDBOX_TEST_PROFILE=str(stack.profile), SOU86_TEST_AGENTFW=str(args.agentfw.resolve())),
                capture_output=True, timeout=90)
            (output / "sandbox-positive.log").write_bytes(positive.stdout + positive.stderr)
            require(positive.returncode == 0 and b"SOU68_SANDBOX_POSITIVE" in positive.stdout and b"1 passed; 0 failed" in positive.stdout,
                    "file-revision OS isolation failed: " + positive.stderr[-2000:].decode("utf-8", "replace"))
            report["sandbox_positive"] = True
            verified = subprocess.run([str(args.sandbox_test_binary), "verified_git_preparation_isolates_real_python_and_git", "--ignored", "--nocapture"],
                env=dict(env, SOU68_SANDBOX_TEST_PROFILE=str(stack.profile), SOU86_TEST_AGENTFW=str(args.agentfw.resolve())),
                capture_output=True, timeout=90)
            (output / "verified-preparation-positive.log").write_bytes(verified.stdout + verified.stderr)
            require(verified.returncode == 0 and b"SOU146_VERIFIED_PREPARATION_POSITIVE" in verified.stdout
                    and b"1 passed; 0 failed" in verified.stdout,
                    "verified preparation confinement failed: " + verified.stderr[-2000:].decode("utf-8", "replace"))
            report["confinement_probes"] = {"collector_preparation": "pass", "verified_worker_preparation": "pass",
                "probe": "independently calibrated syscall script in actual preparation branches; original MCP bytes tested separately"}
            for test, marker, label in (
                ("actual_owned_original_git_commit_and_blob_keep_exact_kind_boundary",
                 "SOU146_REAL_WORKER_KIND_BOUNDARY format=" + INSTALL.FILE_READS_FORMAT, "worker-kind-boundary"),
                ("file_worker_withholds_after_original_tools_call_write_and_source_restore",
                 "SOU146_REAL_WORKER_AFTER_WRITE_WITHHELD restored=true completion=false fresh_original_bytes=true", "worker-after-write")):
                process = subprocess.Popen([str(args.sandbox_test_binary), "mcp::verified_git::linux::tests::" + test,
                    "--exact", "--ignored", "--nocapture", "--test-threads=1"],
                    env=dict(env, SOU68_SANDBOX_TEST_PROFILE=str(stack.profile), SOU156_VERIFIED_GIT_TEST_PROFILE=str(stack.profile),
                             SOU86_TEST_AGENTFW=str(args.agentfw.resolve())), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                witness = DaemonProcessWitness(process.pid)
                out, err = b"", b""
                try:
                    out, err = process.communicate(timeout=90)
                except subprocess.TimeoutExpired:
                    process.kill()
                    out, err = process.communicate(timeout=5)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                    cleanup = witness.finish()
                    report.setdefault("worker_libtest_cleanup", {})[label] = cleanup
                (output / (label + ".log")).write_bytes(out + err)
                require(process.returncode == 0 and marker.encode() in out
                        and b"1 passed; 0 failed" in out and cleanup["all_stopped"]
                        and any(row.get("original_git_server") and not row["parent_process"] for row in cleanup["observed"]),
                        "actual original worker qualification failed: " + label)
            report["worker_after_original_write"] = {"passed": True, "source_restored": True,
                "completion_created": False, "barrier": "private cfg(test) immediately after actual original tools/call write+flush",
                "production_hook": False, "fresh_original_bytes_equal": True,
                "cleanup": report["worker_libtest_cleanup"]["worker-after-write"]}
            report["file_source_kind_boundary"] = {"passed": True, "profile": INSTALL.FILE_READS_FORMAT,
                "probe": "actual pinned original commit and commit-looking blob; exact new FileRevisions Snapshot source"}
            legacy = private / "legacy"
            legacy.mkdir(mode=0o700)
            legacy_profile = json.loads(stack.profile.read_text())
            legacy_profile["format"] = INSTALL.FORMAT
            write(legacy / "profile.json", legacy_profile)
            write(output / "baseline-execution-profile.json", legacy_profile)
            report["baseline_execution_profile"] = {"sha256": sha(legacy / "profile.json"), "profile": legacy_profile,
                "qualification_copy": True, "purpose": "explicit BASE ID200 control"}
            write(legacy / "registry.json", INSTALL.registry(json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text())))
            legacy_config = execution_config(dict(config, native={**config["native"],
                "registry_path": str(legacy / "registry.json"), "registry_sha256": sha(legacy / "registry.json")}), legacy / "profile.json")
            stack.profile = legacy / "profile.json"
            daemon = start_daemon(stack, legacy_config, "legacy")
            legacy_refusal(stack, report)
            BASE.DEMO.stop(daemon)
            stack.profile = execution_profile
            daemon = start_daemon(stack, config, "startup-guards")
            helper_control(stack, report)
            GIT.startup_refusals(stack, report)
            inflight_substitution(stack, first, report)
            inflight_substitution(stack, first, report, mapped=True)
            inflight_substitution(stack, first, report, mapped=True, restore=True)
            report["startup_guard_route"] = "collector preparation without daemon execution opt-in"
            BASE.DEMO.stop(daemon)
            config = execution_config(config, stack.profile)
            daemon = start_daemon(stack, config, "file-revisions-execution")
            exact_reads(stack, first, report)
            LEASE.qualify_short_lease(make_client=lambda log, seconds: collector(stack, log, lease_seconds=seconds),
                make_call=lambda identifier: GIT.call(identifier, "git_show", {"revision": REFS[0]}),
                audit=stack.audit, log_path=output / "short-lease-expiry.log", witness_factory=DaemonProcessWitness,
                expected_sha256=report["original_read_sha256"]["10"], expected_profile=INSTALL.FILE_READS_FORMAT, report=report)
            source_mutations(stack, first, first, report)
            mapped_source_controls(stack, first, report)
            daemon_source_substitution(stack, first, report)
            daemon_source_substitution(stack, first, report, mapped=True)
            daemon_source_substitution(stack, first, report, mapped=True, restore=True)
            policy_controls(stack, config, first, report)
            require(INSTALL.tree_sha(install / "package") == report["installation"]["profile"]["packageTreeSha256"],
                    "original package bytes changed")
            BASE.DEMO.stop(stack.daemon)
        report["source_after"] = BASE.source()
        require(report["source_after"] == before, "candidate source changed")
        report["per_file_qualification"] = "pass"
        report["status"] = "fail" if report.get("failed_benign_controls") else "pass"
        if report.get("failed_benign_controls"):
            report["error"] = "SOU-109: existing benign whole-commit/diff result controls remain withheld; expectations unchanged"
    except Exception as error:
        report["status"], report["error"] = "fail", type(error).__name__ + ": " + str(error)
    finally:
        if daemon is not None:
            BASE.DEMO.stop(daemon)
        if stack is not None and stack.daemon is not None:
            BASE.DEMO.stop(stack.daemon)
            report["daemon_cleanup"] = []
            for label, process, witness in stack.daemon_witnesses:
                BASE.DEMO.stop(process)
                observed = witness.finish()
                report["daemon_cleanup"].append({"label": label, "exit_code": process.returncode, "process": observed})
                if not observed["all_stopped"]:
                    report["status"], report["error"] = "fail", "owned daemon process cleanup unverified"
        if "source_after" not in report:
            try:
                report["source_after"] = BASE.source()
            except Exception as error:
                report["source_after_error"] = type(error).__name__
                report["status"] = "fail"
        if "source_after" in report:
            report["source_after_matches_before"] = report["source_after"] == before
            if not report["source_after_matches_before"]:
                report["final_source_error"], report["status"] = "candidate source changed", "fail"
        report["protected_diagnostics"] = GIT.protected_diagnostics(dict(report, refusals=[]), output)
        report["protected_diagnostics"]["scope"] = "positive reads/output control only; see independently scoped refusal_batches diagnostics"
        write(output / "report.json", report)
    print(json.dumps({"status": report["status"], "error": report.get("error"), "report": str(output / "report.json"),
        "per_file_qualification": report.get("per_file_qualification"), "failed_benign_controls": report.get("failed_benign_controls", []),
        "reads": len(report.get("reads", [])), "refusals": len(report.get("refusals", [])),
        "legacy_refusals": len(report.get("legacy_refusals", [])), "helper_control": report.get("helper_control"),
        "approval_controls": report.get("approval_controls", []),
        "inflight_substitution": report.get("inflight_substitution"),
        "mapped_source_controls": report.get("mapped_source_controls", []),
        "mapped_inflight_substitutions": report.get("mapped_inflight_substitutions", []),
        "packed_reads": len(report.get("packed", {}).get("reads", [])),
        "forged_packed_peel_refused": report.get("packed", {}).get("forged_peel_refused_before_start"),
        "source_mutations": report.get("source_mutations", []), "protected_diagnostics": report["protected_diagnostics"]}))
    return 0 if report["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    for name in ("agentfw", "git", "bwrap", "git-launcher", "sandbox-test-binary", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False}))
        return 0
    try:
        return run(args)
    except Exception as error:
        print(json.dumps({"status": "fail", "error": str(error), "skipped": 0}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
