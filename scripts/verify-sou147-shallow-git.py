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
import shlex
import subprocess
import sys
import tempfile
import urllib.request
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
import importlib.util

SPEC = importlib.util.spec_from_file_location("sou147_original", ROOT / "scripts/verify-sou68-real-mcp.py")
GIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GIT)
BASE, INSTALL = GIT.BASE, GIT.INSTALL
APPROVAL = GIT.load("sou147_approval", "verify-sou105-selected-approval.py")
require, sha, write = BASE.require, BASE.sha, BASE.write
CLASSIFIER = ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py"
REFS = ("HEAD",)
INVALID = ("HEAD:notes.txt", "HEAD~1", "HEAD@{0}", "refs/heads/main", "main", "--help", "-c core.pager=helper", "HEAD..HEAD", "", "0" * 41)


def prepare_repo(workspace, git, env):
    source = workspace.parent / "ordinary-source"
    source.mkdir(mode=0o700)
    def command(*args, cwd=source, data=None):
        return subprocess.check_output([str(git), "-c", "user.name=SOU147 Synthetic", "-c", "user.email=sou147@example.invalid", *args],
            cwd=cwd, env=env, input=data, stderr=subprocess.PIPE, timeout=20).decode().strip()
    command("init", "--initial-branch=main", "--template=")
    (source / "notes.txt").write_text("Synthetic first local version.\n")
    command("add", "notes.txt"); command("commit", "-m", "Synthetic first local version")
    first = command("rev-parse", "HEAD")
    (source / "notes.txt").write_text("Synthetic second local version.\n")
    command("add", "notes.txt"); command("commit", "-m", "Synthetic second local version")
    second = command("rev-parse", "HEAD")
    # Preparation uses only this owned file:// fixture. Runtime never fetches.
    command("clone", "--depth", "1", "--no-local", "--template=", "--upload-pack=" + shlex.quote(str(git)) + " upload-pack", source.as_uri(), str(workspace), cwd=workspace.parent)
    # Retain accepted strict core-only semantics; general remote clone config is
    # deliberately outside SOU-147. Normalize only this generated owned fixture.
    (workspace / ".git/config").write_text("[core]\nrepositoryformatversion = 0\nbare = false\nfilemode = true\nlogallrefupdates = true\n")
    import shutil
    shutil.rmtree(workspace / ".git/refs/remotes", ignore_errors=True)
    packed = workspace / ".git/packed-refs"
    if packed.exists():
        packed.write_text("".join(line for line in packed.read_text().splitlines(keepends=True) if " refs/remotes/" not in line))
    require((workspace / ".git/shallow").read_text() == second + "\n", "owned shallow boundary did not calibrate")
    absent = subprocess.run([str(git), "cat-file", "-e", first], cwd=workspace, env=env, capture_output=True, timeout=10)
    require(absent.returncode != 0, "owned shallow fixture unexpectedly contains absent parent")
    for root in (source, workspace):
        (root / "notes.txt").write_text("Synthetic staged local version.\n")
        command("add", "notes.txt", cwd=root)
        (root / "notes.txt").write_text("Synthetic working local version.\n")
    poison = command("hash-object", "-w", "--stdin", cwd=workspace, data=GIT.INJECTION.encode())
    command("hash-object", "-w", "--stdin", cwd=source, data=GIT.INJECTION.encode())
    return first, second, poison


def reads(head):
    return [("git_status", {}, "status"), ("git_log", {"max_count": 2}, "local-history"),
            ("git_show", {"revision": "HEAD"}, "HEAD"), ("git_diff", {"target": "HEAD"}, "HEAD"),
            ("git_diff_staged", {}, "index"), ("git_diff_unstaged", {}, "working-tree"),
            ("git_show", {"revision": head}, head), ("git_diff", {"target": head}, head)]


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


def mapped_source_controls(stack, second, report, source_path=None):
    ref = source_path or stack.workspace / ".git/shallow"
    before = ref.read_bytes()
    snapshot = BASE.snapshot(stack.workspace)
    report["mapped_source_controls"] = []
    opened = writable_mapping(ref)
    try:
        profile = json.loads(stack.profile.read_text())
        result = subprocess.run([str(stack.binary), "mcp", "--native-admission", "--id", "sou147-preexisting-map", "--",
            profile["runtimePath"], "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"],
            env=dict(stack.env, AGENTFW_MCP_SERVER_PROFILE=str(stack.profile)), cwd=stack.workspace,
            input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "owned-map-before-capture", "version": "1"}}}).encode() + b"\n",
            capture_output=True, timeout=20)
        (stack.root / "preexisting-mapping.log").write_bytes(result.stderr)
        require(result.returncode != 0 and b'"event":"mcp_real_server_start"' not in result.stderr and
            b"Git shallow source has a writer or cannot be protected" in result.stderr,
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
                GIT.text(client.exchange(GIT.call(10, "git_status", {}))[0])
                opened = writable_mapping(ref)
                opened[1][:] = ((second + "\n").encode() if source_path is None else bytes([before[0] ^ 1]) + before[1:])
                opened[1].flush()
                require(ref.read_bytes() != before, "owned mmap write did not change source bytes")
                if restore_before_call:
                    opened[1][:] = before
                    opened[1].flush()
                    require(ref.read_bytes() == before, "owned mmap restore did not calibrate")
                witness.drain()
                reply, _ = client.exchange(GIT.call(11, "git_status", {}))
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
                GIT.text(client.exchange(GIT.call(10, "git_status", {}))[0])
            finally:
                client.close()
        require(client.process.returncode == 0 and client.process_witness.final["all_stopped"], "fresh mapped-source collector failed")
    require(BASE.snapshot(stack.workspace) == snapshot, "mapped-source controls changed owned repository state")


def collector(stack, log, *, legacy=False, bound=None):
    python = stack.install / "package/python/bin/python3.11"
    env = dict(stack.env, AGENTFW_MCP_SERVER_PROFILE=str(stack.profile), AGENTFW_CLASSIFIER="rule-baseline",
        AGENTFW_RULE_BASELINE=str(ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py" if legacy else CLASSIFIER),
        AGENTFW_CLASSIFIER_PYTHON=sys.executable)
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
            "--server", "sou147-git", "--agent-id", "agent-" + bound, "--instance-id", instance,
            "--ttl-seconds", "120", "--tools", ",".join(tools))
        env.update(AGENTFW_NATIVE_LIVENESS="true", AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS="2",
            AGENTFW_MCP_SESSION="collector-" + bound)
        extra = ["--host-session", "host-" + bound, "--child-authority", token, "--native-approval-wait-seconds", "25"]
    return GIT.Client([str(stack.binary), "mcp", "--native-admission", "--id", "sou147-git", *extra, "--",
        str(python), "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"],
        env, stack.workspace, log, "protected shallow original Git")


def exact_reads(stack, head, report):
    originals = {}
    original_errors = {}
    python = stack.install / "package/python/bin/python3.11"
    env = dict(stack.env, GIT_PYTHON_GIT_EXECUTABLE=str(stack.git), GIT_OPTIONAL_LOCKS="0")
    with (stack.root / "original.log").open("wb") as log:
        client = GIT.Client([str(python), "-I", "-B", "-m", "mcp_server_git", "--repository", str(stack.workspace)],
                            env, stack.workspace, log, "direct original Git")
        try:
            client.initialize()
            for identifier, (tool, args, ref) in enumerate(reads(head), 10):
                response, raw = client.exchange(GIT.call(identifier, tool, args, stack.workspace))
                if BASE.refused(response):
                    require(tool == "git_show" and (stack.workspace / ".git/shallow").exists()
                        and "fatal: bad object" in json.dumps(response) and stack.missing_ancestor in json.dumps(response),
                        "unexpected original failure outside calibrated absent-parent show")
                    original_errors[identifier] = response
                else:
                    GIT.text(response)
                originals[identifier] = raw
            poison, _ = client.exchange(GIT.call(80, "git_show", {"revision": stack.poison}, stack.workspace))
            require(GIT.INJECTION in GIT.text(poison), "direct original result-injection witness did not calibrate")
        finally:
            client.close()
            report["direct_client"] = client.transcript()
    before = BASE.snapshot(stack.workspace)
    witness = GIT.RepositoryWitness(stack.workspace)
    path = stack.root / "collector.log"
    with path.open("wb") as log:
        client = collector(stack, log)
        try:
            client.initialize()
            report["reads"], report["refusals"] = [], []
            for identifier, (tool, args, ref) in enumerate(reads(head), 10):
                witness.drain()
                response, raw = client.exchange(GIT.call(identifier, tool, args))
                if identifier in original_errors:
                    require(response.get("id") == identifier and response.get("result", {}).get("isError") is True
                        and "fatal: bad object" in json.dumps(response) and stack.missing_ancestor in json.dumps(response)
                        and "Soup Wall withheld" not in json.dumps(response), "original absent-parent error was not preserved")
                    report.setdefault("original_error_cases", []).append({"id": identifier, "tool": tool,
                        "reference": ref, "original_error": original_errors[identifier], "protected_error": response,
                        "original_sha256": hashlib.sha256(originals[identifier]).hexdigest(),
                        "protected_sha256": hashlib.sha256(raw).hexdigest(), "original_error_preserved": True,
                        "error_bytes_equal": raw == originals[identifier]})
                    GIT.text(client.exchange(GIT.call(identifier + 2000, "git_status", {}))[0])
                    continue
                GIT.text(response)
                require(raw == originals[identifier], "original response bytes changed: " + tool + " " + ref)
                require(any(row.get("host_call_id") == identifier and row.get("state") == "inflight" for row in BASE.events(path)), "original dispatch witness absent")
                report["reads"].append({"id": identifier, "tool": tool, "reference": ref,
                    "response_sha256": hashlib.sha256(raw).hexdigest(), "original_bytes_equal": True})
            witness.drain()
            poison, _ = client.exchange(GIT.call(80, "git_show", {"revision": stack.poison}))
            require(BASE.refused(poison) and GIT.INJECTION not in json.dumps(poison) and any(row.get("host_call_id") == 80 and row.get("state") == "inflight" for row in BASE.events(path)),
                    "unsafe executed original output escaped result inspection")
            GIT.text(client.exchange(GIT.call(81, "git_status", {}))[0])
            report["result_injection_withheld"] = True
            denials = [(tool, {key: ref}, "syntax") for ref in INVALID
                       for tool, key in (("git_show", "revision"), ("git_diff", "target"))]
            denials += [("git_checkout", {"branch_name": "main"}, "mutation"),
                       ("git_create_branch", {"branch_name": "forbidden"}, "mutation"),
                       ("git_add", {"files": ["notes.txt"]}, "mutation")]
            for identifier, (tool, args, category) in enumerate(denials, 100):
                witness.drain()
                response, _ = client.exchange(GIT.call(identifier, tool, args))
                require(BASE.refused(response), "unsupported original call was not refused")
                require(witness.drain() == 0, "refused call opened repository")
                require(not any(r.get("host_call_id") == identifier and r.get("state") == "inflight"
                                for r in BASE.events(path)), "refused call dispatched")
                report["refusals"].append({"id": identifier, "category": category,
                    "response": response, "repository_opens": 0, "execution_dispatched": False})
                followup, _ = client.exchange(GIT.call(identifier + 1000, "git_status", {}))
                GIT.text(followup)
            require(BASE.snapshot(stack.workspace) == before, "protected reads/refusals changed repository")
            report["repository_unchanged"] = True
        finally:
            client.close()
            witness.close()
            report["protected_client"] = client.transcript()
    require(client.process.returncode == 0 and not client.forced_cleanup and
            client.process_witness.final.get("all_stopped") is True, "protected process cleanup unverified")


def legacy_refusal(stack, report):
    profile = json.loads(stack.profile.read_text())
    original = dict(profile, format=INSTALL.FORMAT)
    path = stack.root / "legacy-profile.json"
    write(path, original)
    frame = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "owned-default-refusal", "version": "1"}}}
    result = subprocess.run([str(stack.binary), "mcp", "--native-admission", "--id", "sou147-default", "--",
        profile["runtimePath"], "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"],
        env=dict(stack.env, AGENTFW_MCP_SERVER_PROFILE=str(path)), cwd=stack.workspace,
        input=json.dumps(frame).encode()+b"\n", capture_output=True, timeout=20)
    (stack.root / "legacy-collector.log").write_bytes(result.stderr)
    require(result.returncode != 0 and b'"event":"mcp_real_server_start"' not in result.stderr
        and b"shallow" in result.stderr.lower(), "default profile unexpectedly started on shallow repository")
    report["default_shallow_refused_before_start"] = True


def ordinary_controls(stack, head, report, workspace=None, label="ordinary"):
    old_workspace = stack.workspace
    old_profile = stack.profile.read_bytes()
    ordinary = workspace or old_workspace.parent / "ordinary-source"
    old_root = stack.root
    stack.root = old_root / label
    stack.root.mkdir(mode=0o700)
    try:
        profile = json.loads(old_profile)
        profile["workspace"] = str(ordinary)
        write(stack.profile, profile)
        stack.workspace = ordinary
        exact_reads(stack, head, report.setdefault(label, {}))
    finally:
        stack.profile.write_bytes(old_profile)
        stack.workspace = old_workspace
        stack.root = old_root


def local_parent_controls(stack, report):
    source = stack.workspace.parent / "ordinary-source"
    deeper = stack.workspace.parent / "local-parent-shallow"
    def command(*args, cwd=source):
        return subprocess.check_output([str(stack.git), "-c", "user.name=SOU147 Synthetic", "-c", "user.email=sou147@example.invalid", *args],
            cwd=cwd, env=stack.env, stderr=subprocess.PIPE, timeout=20).decode().strip()
    # The original depth-one failure remains a calibrated error case. This
    # independent control adds a local parent so original git_show can succeed.
    (source / "notes.txt").write_text("Synthetic third local version.\n")
    command("add", "notes.txt"); command("commit", "-m", "Synthetic third local version")
    head = command("rev-parse", "HEAD")
    command("clone", "--depth", "2", "--no-local", "--template=", "--upload-pack=" + shlex.quote(str(stack.git)) + " -c pack.window=0 upload-pack", source.as_uri(), str(deeper), cwd=source.parent)
    import shutil
    (deeper / ".git/config").write_text("[core]\nrepositoryformatversion = 0\nbare = false\nfilemode = true\nlogallrefupdates = true\n")
    shutil.rmtree(deeper / ".git/refs/remotes", ignore_errors=True)
    packed = deeper / ".git/packed-refs"
    if packed.exists(): packed.write_text("".join(line for line in packed.read_text().splitlines(keepends=True) if " refs/remotes/" not in line))
    require((deeper / ".git/shallow").is_file(), "local-parent fixture lost shallow metadata")
    (deeper / "notes.txt").write_text("Synthetic staged local version.\n"); command("add", "notes.txt", cwd=deeper)
    (deeper / "notes.txt").write_text("Synthetic working local version.\n")
    subprocess.run([str(stack.git), "hash-object", "-w", "--stdin"], cwd=deeper, env=stack.env, input=GIT.INJECTION.encode(), capture_output=True, check=True, timeout=10)
    ordinary_controls(stack, head, report, workspace=deeper, label="local-parent-shallow")


def absent_ancestry(stack, first, report):
    python = stack.install / "package/python/bin/python3.11"
    results = []
    for protected in (False, True):
        label = "protected" if protected else "original"
        with (stack.root / ("absent-" + label + ".log")).open("wb") as log:
            client = collector(stack, log) if protected else GIT.Client([str(python), "-I", "-B", "-m", "mcp_server_git", "--repository", str(stack.workspace)],
                dict(stack.env, GIT_PYTHON_GIT_EXECUTABLE=str(stack.git)), stack.workspace, log, "direct absent-parent calibration")
            try:
                client.initialize()
                rows = []
                for identifier, tool, key in ((500, "git_show", "revision"), (501, "git_diff", "target")):
                    reply, _ = client.exchange(GIT.call(identifier, tool, {key: first}, "/workspace" if protected else stack.workspace))
                    require(reply.get("id") == identifier and (BASE.refused(reply) or (not protected and first in json.dumps(reply))), "absent local ancestor did not return correlated original error/refusal")
                    rows.append({"tool": tool, "response": reply})
                GIT.text(client.exchange(GIT.call(502, "git_status", {}, "/workspace" if protected else stack.workspace))[0])
                results.append({"kind": label, "errors": rows, "safe_continuation": True})
            finally:
                client.close()
        require(client.process.returncode == 0 and client.process_witness.final["all_stopped"], "absent-parent process cleanup unverified")
    report["absent_ancestry"] = results


def boundary_refusals(stack, report):
    boundary = stack.workspace / ".git/shallow"
    old = boundary.read_bytes()
    mode = boundary.stat().st_mode & 0o777
    profile = json.loads(stack.profile.read_text())
    report["boundary_refusals"] = []
    cases = {"empty": b"", "missing-newline": old.rstrip(b"\n"), "duplicate": old+old,
        "crlf": old.rstrip(b"\n")+b"\r\n", "oversized": b"a" * (64*41+1), "unknown-commit": b"0"*40+b"\n",
        "blob-target": stack.poison.encode()+b"\n", "uppercase": old.upper()}
    for name in (*cases, "symlink", "shared-writable"):
        try:
            if name == "symlink":
                outside = stack.workspace.parent / "outside-boundary"
                outside.write_bytes(old)
                boundary.unlink(); boundary.symlink_to(outside)
            elif name == "shared-writable":
                boundary.chmod(0o666)
            else:
                boundary.write_bytes(cases[name])
            frame = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "owned-boundary-negative", "version": "1"}}}
            result = subprocess.run([str(stack.binary), "mcp", "--native-admission", "--id", "sou147-boundary", "--", profile["runtimePath"], "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"],
                env=dict(stack.env, AGENTFW_MCP_SERVER_PROFILE=str(stack.profile)), cwd=stack.workspace, input=json.dumps(frame).encode()+b"\n", capture_output=True, timeout=20)
            (stack.root / ("boundary-"+name+".log")).write_bytes(result.stderr)
            require(result.returncode != 0 and b'"event":"mcp_real_server_start"' not in result.stderr, "unsafe shallow boundary started original server: "+name)
            report["boundary_refusals"].append({"case": name, "server_started": False, "passed": True})
        finally:
            if boundary.is_symlink(): boundary.unlink()
            boundary.write_bytes(old); boundary.chmod(mode)


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
        result = subprocess.run([str(stack.binary), "mcp", "--native-admission", "--id", "sou147-helper", "--",
            profile["runtimePath"], "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"],
            env=dict(stack.env, AGENTFW_MCP_SERVER_PROFILE=str(stack.profile)), cwd=stack.workspace,
            input=json.dumps(frame).encode() + b"\n", capture_output=True, timeout=20)
        (stack.root / "helper-protected.log").write_bytes(result.stderr)
        require(result.returncode != 0 and b'"event":"mcp_real_server_start"' not in result.stderr and
                not marker.exists(), "protected helper configuration reached original server")
        report["helper_control"] = {"direct_effects": 1, "protected_effects": 0, "server_started": False}
    finally:
        config.write_bytes(original)


def start_daemon(stack, config, label):
    write(Path(stack.env["HOME"]) / ".agentfw/config.yaml", config)
    with (stack.root / (label + "-daemon.log")).open("wb") as log:
        stack.daemon = subprocess.Popen([str(stack.binary), "serve"], env=stack.env, stdout=log, stderr=log)
    stack.daemon_witnesses.append((label, stack.daemon, BASE.ProcessWitness(stack.daemon.pid)))
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
            _, expected = original.exchange(GIT.call(50, "git_status", {}, stack.workspace))
        finally:
            original.close()
    BASE.DEMO.stop(stack.daemon)
    policy = stack.root / "ask-policy.yaml"
    policy.write_text("agent_policies:\n  - name: sou147-owned-read\n    when: { action_class: read_only }\n    action: ask\ndefault: allow\n")
    selected = dict(config, policy=str(policy), native={**config["native"], "approval": {"ttl_seconds": 30},
        "liveness": {"default_lease_seconds": 2, "max_lease_seconds": 60, "maintenance_interval_ms": 100}})
    start_daemon(stack, selected, "ask")
    report["approval_controls"] = []
    ref = stack.workspace / ".git/shallow"
    old = ref.read_bytes()
    for case in ("approve", "cancel", "substitution", "mapped-substitution", "mapped-restore"):
        path = stack.root / (case + "-collector.log")
        with path.open("wb") as log:
            client = collector(stack, log, bound=case)
            witness = GIT.RepositoryWitness(stack.workspace)
            opened = None
            try:
                client.initialize()
                witness.drain()
                frame = GIT.call(50, "git_status", {})
                client.send(frame)
                # Retain the shared first-pending bound, including cold input
                # preparation; no separate preparation allowance.
                waiting = APPROVAL.pending(args, stack.env, timeout=5)
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
                        require(raw == expected and any(row.get("host_call_id") == 50 and row.get("state") == "inflight" for row in BASE.events(path)), "approved original bytes/execution changed")
                        approved_opens = witness.drain()
                        require(approved_opens > 0, "approved status execution did not calibrate the independent observer")
                        client.send(GIT.call(51, "git_status", {}))
                        again = APPROVAL.pending(args, stack.env, timeout=5)
                        require(again["pending_id"] != waiting["pending_id"], "single-use approval ID was reused")
                        require(witness.drain() == 0 and not any(row.get("host_call_id") == 51 and row.get("state") == "inflight" for row in BASE.events(path)),
                                "second unapproved status request executed")
                        APPROVAL.command(args, stack.env, "native-approval", "reject", again["pending_id"])
                        require(BASE.refused(client.receive()[0]), "second Ask was not independently refused")
                    else:
                        require(response.get("error", {}).get("code") == -32602 and witness.drain() == 0,
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
    policy.write_text("agent_policies:\n  - name: sou147-owned-deny\n    when: { action_class: read_only }\n    action: deny\ndefault: allow\n")
    start_daemon(stack, dict(config, policy=str(policy)), "deny")
    with (stack.root / "deny-collector.log").open("wb") as log:
        client = collector(stack, log)
        witness = GIT.RepositoryWitness(stack.workspace)
        try:
            client.initialize()
            witness.drain()
            response, _ = client.exchange(GIT.call(50, "git_status", {}))
            require(BASE.refused(response) and witness.drain() == 0, "policy Deny floor bypassed")
            report["policy_deny_refused"] = True
        finally:
            client.close()
            witness.close()


def source_mutations(stack, first, second, report):
    ref = stack.workspace / ".git/shallow"
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
                GIT.text(client.exchange(GIT.call(10, "git_status", {}))[0])
                if name == "rewrite":
                    ref.write_text(second + "\n")
                elif name == "replace":
                    temporary = ref.with_name("replacement")
                    temporary.write_text(second + "\n")
                    temporary.replace(ref)
                else:
                    ref.unlink()
                    ref.symlink_to(stack.workspace.parent / "outside-boundary")
                witness.drain()
                response, _ = client.exchange(GIT.call(11, "git_status", {}))
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
                GIT.text(client.exchange(GIT.call(10, "git_status", {}))[0])
            finally:
                client.close()
        require(client.process.returncode == 0 and not client.forced_cleanup, "fresh collector failed")


def inflight_substitution(stack, second, report, *, mapped=False, restore=False):
    """Change only an owned ref after native dispatch while the real server is stopped."""
    label = "inflight-mapped-restored" if restore else "inflight-mapped" if mapped else "inflight-substitution"
    path = stack.root / (label + ".log")
    ref = stack.workspace / ".git/shallow"
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
            client.send(GIT.call(50, "git_status", {}))
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
            row = {"execution_dispatched_before_mutation": True,
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



def run(args):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 enforcing isolation required")
    before = BASE.source()
    require(before["commit"] == args.expected_commit and not before["dirty"], "clean exact candidate required")
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), "new evidence directory outside source required")
    output.mkdir(mode=0o700, parents=True)
    report = {"format": "sou147-git-shallow-acceptance/1", "status": "incomplete", "skipped": 0,
        "source_before": before, "driver_sha256": sha(__file__), "binary_sha256": sha(args.agentfw),
        "classifier_sha256": sha(CLASSIFIER)}
    daemon, stack = None, None
    try:
        with tempfile.TemporaryDirectory(prefix="sou147-owned-") as temporary:
            private = Path(temporary)
            home = private / "home"
            home.mkdir(mode=0o700)
            env = BASE.environment(home)
            env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
            workspace, install = private / "workspace", private / "installed"
            first, second, poison = prepare_repo(workspace, args.git, env)
            INSTALL.install(install, workspace, args.git, args.git_sha256, args.bwrap, args.git_launcher, shallow_repository=True)
            report["installation"] = json.loads((install / "installation.json").read_text())
            subprocess.run([str(args.agentfw), "install"], env=env, capture_output=True, check=True, timeout=30)
            port = BASE.DEMO.free_port()
            config = {"port": port, "enforce": True, "max_record_bytes": 1048576,
                "policy": str(install / "policy.yaml"), "native": {"registry_path": str(install / "registry.json"),
                "registry_sha256": sha(install / "registry.json")}}
            write(home / ".agentfw/config.yaml", config)
            stack = SimpleNamespace(root=output, binary=args.agentfw, git=args.git, workspace=workspace,
                install=install, profile=install / "profile.json", env=env, daemon=None, port=port,
                poison=poison, missing_ancestor=first, daemon_witnesses=[])
            positive = subprocess.run([str(args.sandbox_test_binary), "selected_git_sandbox_isolates_real_python_and_git", "--ignored", "--nocapture"],
                env=dict(env, SOU68_SANDBOX_TEST_PROFILE=str(stack.profile), SOU86_TEST_AGENTFW=str(args.agentfw.resolve())),
                capture_output=True, timeout=90)
            (output / "sandbox-positive.log").write_bytes(positive.stdout + positive.stderr)
            require(positive.returncode == 0 and b"SOU68_SANDBOX_POSITIVE" in positive.stdout and b"1 passed; 0 failed" in positive.stdout,
                    "shallow OS isolation failed: " + positive.stderr[-2000:].decode("utf-8", "replace"))
            report["sandbox_positive"] = True
            daemon = start_daemon(stack, config, "shallow")
            legacy_refusal(stack, report)
            ordinary_controls(stack, second, report)
            local_parent_controls(stack, report)
            boundary_refusals(stack, report)
            helper_control(stack, report)
            GIT.startup_refusals(stack, report)
            exact_reads(stack, second, report)
            absent_ancestry(stack, first, report)
            source_mutations(stack, first, first, report)
            mapped_source_controls(stack, first, report)
            original_root = stack.root
            stack.root = original_root / "mapped-pack"
            stack.root.mkdir(mode=0o700)
            packed = next((workspace / ".git/objects/pack").glob("*.pack"))
            original_pack_mode = packed.stat().st_mode & 0o777
            pack_controls = report.setdefault("mapped_pack_controls", {})
            pack_controls["original_mode"] = original_pack_mode
            try:
                # Git publishes pack files 0444. Calibrate owner-only writable
                # mappings in this generated fixture before taking any proof.
                packed.chmod(original_pack_mode | 0o200)
                mapped_source_controls(stack, first, pack_controls, source_path=packed)
            finally:
                packed.chmod(original_pack_mode)
                pack_controls["mode_restored"] = (packed.stat().st_mode & 0o777) == original_pack_mode
                stack.root = original_root
            inflight_substitution(stack, first, report)
            inflight_substitution(stack, first, report, mapped=True)
            inflight_substitution(stack, first, report, mapped=True, restore=True)
            policy_controls(stack, config, first, report)
            require(INSTALL.tree_sha(install / "package") == report["installation"]["profile"]["packageTreeSha256"],
                    "original package bytes changed")
            BASE.DEMO.stop(stack.daemon)
        report["source_after"] = BASE.source()
        require(report["source_after"] == before, "candidate source changed")
        report["status"] = "pass"
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
        report["protected_diagnostics"] = GIT.protected_diagnostics(report, output)
        write(output / "report.json", report)
    print(json.dumps({"status": report["status"], "error": report.get("error"), "report": str(output / "report.json"),
        "default_shallow_refused_before_start": report.get("default_shallow_refused_before_start"), "boundary_refusals": report.get("boundary_refusals", []),
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
