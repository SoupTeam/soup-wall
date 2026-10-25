#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Targeted opt-in Linux acceptance; no detector override or CI integration."""
from __future__ import annotations

import argparse
import json
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
import importlib.util

SPEC = importlib.util.spec_from_file_location("sou150_original_helpers", ROOT / "scripts/verify-sou107-real-git.py")
CLONE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLONE)
V1, BASE = CLONE.V1, CLONE.BASE
INSTALL = CLONE.load("sou150_installer", "install-sou150-git-profile.py")
require, sha, write = BASE.require, BASE.sha, BASE.write
READS = (
    ("git_show", {"revision": "HEAD"}, "tracked-link"),
    ("git_status", {}, "notes.txt"),
    ("git_log", {"max_count": 3}, "SOU150 tracked link objects"),
    ("git_diff", {"target": "HEAD", "context_lines": 3}, "synthetic changed text"),
    ("git_diff_unstaged", {"context_lines": 3}, "synthetic changed text"),
    ("git_diff_staged", {"context_lines": 3}, "synthetic staged text"),
)
CASES = ("changed-relative", "absolute", "outside-relative", "index", "metadata", "concurrent-writer")


def git(stack, *args):
    return subprocess.check_output([str(stack.git), "-c", "user.name=SOU150 Synthetic",
        "-c", "user.email=sou150@example.invalid", *args], cwd=stack.workspace,
        env=stack.env, stderr=subprocess.PIPE, timeout=20)


def fixture(root, git_binary, env):
    CLONE.fixture(root, git_binary, env)
    stack = SimpleNamespace(workspace=root, git=git_binary, env=env)
    # Leave regular staged/unstaged deltas while committing the actual link objects.
    git(stack, "reset", "HEAD", "notes.txt")
    (root / "tracked-link").symlink_to("notes.txt")
    (root / "nested/relative-link").symlink_to("../notes.txt")
    git(stack, "add", "tracked-link", "nested/relative-link")
    git(stack, "commit", "-m", "SOU150 tracked link objects")
    (root / "notes.txt").write_text("synthetic staged text\n")
    git(stack, "add", "notes.txt")
    (root / "notes.txt").write_text("synthetic changed text\n")
    require(git(stack, "show", "HEAD:tracked-link") == b"notes.txt", "Git link-object calibration failed")


def collector(stack, log, protected):
    python = str(stack.install / "package/python/bin/python3.11")
    if protected:
        command = [str(stack.binary), "mcp", "--native-admission", "--id", "sou150-git", "--",
            python, "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"]
        env = dict(stack.env, **stack.selection["environment"])
    else:
        command = [python, "-I", "-B", "-m", "mcp_server_git", "--repository", str(stack.workspace)]
        env = dict(stack.env, GIT_PYTHON_GIT_EXECUTABLE=str(stack.git))
    return V1.Client(command, env, stack.workspace, log, "SOU150 protected" if protected else "SOU150 unwrapped")


def byte_reads(stack, report):
    """Compare complete original JSON-RPC frames, including unchanged results/errors."""
    report["repository_states"] = {"before_unwrapped": BASE.snapshot(stack.workspace)}
    originals = {}
    with (stack.root / "unwrapped.log").open("wb") as log:
        client = collector(stack, log, False)
        try:
            client.initialize()
            for n, (tool, args, fragment) in enumerate(READS, 10):
                result, raw = client.exchange(V1.call(n, tool, args, stack.workspace))
                require(fragment in V1.text(result), "unwrapped calibration failed: " + tool)
                originals[tool] = raw
        finally:
            client.close()
            report["unwrapped_client"] = client.transcript()
    require(client.process_witness.final["all_stopped"], "unwrapped descendants remain")
    # The reference server runs outside the read-only boundary. Retain its
    # effects separately and take the protected baseline before protected launch.
    before = BASE.snapshot(stack.workspace)
    report["repository_states"]["after_unwrapped"] = before
    unwrapped_before = report["repository_states"]["before_unwrapped"]
    report["unwrapped_repository_changes"] = {
        path: {"before": unwrapped_before.get(path), "after": before.get(path)}
        for path in sorted(unwrapped_before.keys() | before.keys())
        if unwrapped_before.get(path) != before.get(path)}
    report["reads"], report["read_admission_failures"] = [], []
    with (stack.root / "collector.log").open("wb") as log:
        client = collector(stack, log, True)
        try:
            client.initialize()
            for n, (tool, args, _) in enumerate(READS, 10):
                reply, raw = client.exchange(V1.call(n, tool, args))
                if BASE.refused(reply):
                    report["read_admission_failures"].append({"tool": tool, "response": reply})
                    continue
                require(raw == originals[tool], "original payload bytes changed: " + tool)
                report["reads"].append({"tool": tool, "byte_identical": True, "sha256": hashlib.sha256(raw).hexdigest()})
        finally:
            client.close()
            report["protected_client"] = client.transcript()
    require(client.process_witness.final["all_stopped"], "protected descendants remain")
    after = BASE.snapshot(stack.workspace)
    report["repository_states"]["after_protected"] = after
    require(after == before, "protected original reads changed repository")
    report["repository_unchanged"] = True
    report["transport_events"] = BASE.events(stack.root / "collector.log")


def late_changes(stack, report):
    """An already initialized real server must revalidate each actual Git use."""
    root, report["late_changes"] = stack.workspace, []
    outside = root.parent / "owned-late-marker"
    outside.write_bytes(b"SOU150 external bytes must remain undisclosed")
    unrelated = root.parent / "unrelated-state"
    unrelated.write_bytes(b"unrelated owned state")
    link, config, index = root / "tracked-link", root / ".git/config", root / ".git/index"
    original_config, original_index = config.read_bytes(), index.read_bytes()
    with (stack.root / "late.log").open("wb") as log:
        client = collector(stack, log, True)
        try:
            client.initialize()
            baseline, _ = client.exchange(V1.call(30, "git_log", {"max_count": 3}))
            require("SOU150 tracked link objects" in V1.text(baseline), "late-change initial read failed")
            for n, case in enumerate(CASES, 40):
                stop, thread, failures, writes = threading.Event(), None, [], []
                saved_config = root / "owned-config-save"
                try:
                    if case in ("changed-relative", "absolute", "outside-relative"):
                        link.unlink()
                        link.symlink_to({"changed-relative": "nested/example.txt", "absolute": str(outside),
                                         "outside-relative": "../owned-late-marker"}[case])
                    elif case == "index":
                        oid = git(stack, "rev-parse", "HEAD:owned.bin").strip()
                        git(stack, "update-index", "--cacheinfo", "120000," + oid.decode() + ",tracked-link")
                    elif case == "metadata":
                        config.rename(saved_config)
                        config.symlink_to("../owned-config-save")
                    else:
                        def writer():
                            try:
                                for attempt in range(10000):
                                    if stop.is_set():
                                        break
                                    temporary = root / "owned-atomic-next"
                                    temporary.symlink_to("notes.txt" if attempt % 2 == 0 else "../owned-late-marker")
                                    os.replace(temporary, link)
                                    writes.append(attempt)
                                    stop.wait(0.001)
                            except Exception as error:
                                failures.append(str(error))
                        thread = threading.Thread(target=writer, daemon=True)
                        thread.start()
                    mutated = None if thread else BASE.snapshot(root)
                    reply, _ = client.exchange(V1.call(n, "git_status", {}))
                    require(outside.read_text() not in json.dumps(reply), "external bytes disclosed")
                    if not thread:
                        require(BASE.refused(reply), "unsupported late state accepted: " + case)
                        require(BASE.snapshot(root) == mutated, "guard rewrote unsupported repository")
                    elif not BASE.refused(reply):
                        V1.text(reply)  # Only an original valid status is acceptable while racing.
                    report["late_changes"].append({"case": case, "response": reply, "writer_replacements": len(writes), "passed": True})
                finally:
                    stop.set()
                    if thread:
                        thread.join(timeout=3)
                        require(not thread.is_alive() and not failures and writes, "owned writer did not run/stop cleanly")
                    (root / "owned-atomic-next").unlink(missing_ok=True)
                    link.unlink(missing_ok=True)
                    link.symlink_to("notes.txt")
                    if config.is_symlink():
                        config.unlink()
                        saved_config.rename(config)
                    require(config.read_bytes() == original_config, "unrelated config changed")
                    index.write_bytes(original_index)
                reply, _ = client.exchange(V1.call(n + 100, "git_log", {"max_count": 3}))
                require("SOU150 tracked link objects" in V1.text(reply), "refusal broke useful continuation")
            require(unrelated.read_bytes() == b"unrelated owned state", "unrelated state changed")
        finally:
            client.close()
            report["late_client"] = client.transcript()
    require(client.process_witness.final["all_stopped"], "late-change descendants remain")
    report["late_transport_events"] = BASE.events(stack.root / "late.log")
    require(all(any(row.get("host_call_id") == n and row.get("execution_dispatched") is True
                    for row in report["late_transport_events"]) for n in range(40, 40 + len(CASES))),
            "late-state controls did not reach the actual original server")


DEFAULT_LINK_REFUSAL = b"Git repository links and special files are unsupported"


def require_default_link_refusal(result):
    require(result.returncode != 0 and DEFAULT_LINK_REFUSAL in result.stderr
            and b'"event":"mcp_real_server_start"' not in result.stderr,
            "default link refusal lacks its specific repository diagnostic")


def default_refusal(stack, report):
    """Calibrate v1 with its own valid fixture/registry, then change only links."""
    private = stack.workspace.parent / "default-control"
    private.mkdir(mode=0o700)
    home, workspace = private / "home", private / "workspace"
    home.mkdir(mode=0o700)
    env = BASE.environment(home)
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    V1.prepare_repo(workspace, stack.git, env)
    profile = json.loads((stack.install / "profile.json").read_text())
    profile.update(format=V1.INSTALL.FORMAT, workspace=str(workspace))
    profile_path, registry_path = private / "profile.json", private / "registry.json"
    write(profile_path, profile)
    manifest = json.loads((V1.INSTALL.ASSETS / "upstream-tools-list.json").read_text())
    write(registry_path, V1.INSTALL.registry(manifest))
    port = BASE.DEMO.free_port()
    policy = V1.INSTALL.ASSETS / "policy.yaml"
    subprocess.run([str(stack.binary), "install"], env=env, stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
    write(home / ".agentfw/config.yaml", {"port": port, "enforce": True, "max_record_bytes": 1048576,
        "policy": str(policy), "native": {"registry_path": str(registry_path), "registry_sha256": sha(registry_path)}})
    env.update(AGENTFW_MCP_SERVER_PROFILE=str(profile_path), AGENTFW_WORKSPACE=str(workspace),
               AGENTFW_CLASSIFIER="rule-baseline", AGENTFW_CLASSIFIER_PYTHON=sys.executable,
               AGENTFW_RULE_BASELINE=str(ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py"))
    python = str(stack.install / "package/python/bin/python3.11")
    command = [str(stack.binary), "mcp", "--native-admission", "--id", "sou150-default", "--",
               python, "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"]
    state = {"profile_sha256": sha(profile_path), "registry_sha256": sha(registry_path),
             "policy_sha256": sha(policy), "profile": profile["format"]}
    report["default_control"] = state
    daemon = None
    with (stack.root / "default-daemon.log").open("wb") as daemon_log:
        try:
            daemon = subprocess.Popen([str(stack.binary), "serve"], env=env, stdout=daemon_log, stderr=daemon_log)
            require(BASE.DEMO.wait_healthy(port, daemon), "default control daemon unavailable")
            def useful(label):
                before = BASE.snapshot(workspace)
                with (stack.root / (label + ".log")).open("wb") as log:
                    client = V1.Client(command, env, workspace, log, "default v1 positive control")
                    try:
                        client.initialize()
                        result, raw = client.exchange(V1.call(10, "git_log", {"max_count": 1}))
                        require("SOU-68 synthetic initial commit" in V1.text(result), "default link-free useful read failed")
                    finally:
                        client.close()
                        state[label] = client.transcript()
                require(client.process_witness.final["all_stopped"], "default control descendants remain")
                require(BASE.snapshot(workspace) == before, "default control read changed repository")
                return raw
            original = useful("default-link-free")
            index = workspace / ".git/index"
            original_index = index.read_bytes()
            link = workspace / "tracked-link"
            link.symlink_to("notes.txt")
            control = SimpleNamespace(workspace=workspace, git=stack.git, env=env)
            git(control, "add", "tracked-link")
            require(b"120000" in git(control, "ls-files", "--stage", "tracked-link"), "negative link is not tracked")
            before = BASE.snapshot(workspace)
            request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "sou150-default-negative", "version": "1"}}}).encode() + b"\n"
            result = subprocess.run(command, env=env, cwd=workspace, input=request, capture_output=True, timeout=20)
            (stack.root / "default-refusal.log").write_bytes(result.stderr)
            state.update(exit_code=result.returncode, diagnostic=result.stderr.decode("utf-8", "replace"))
            require_default_link_refusal(result)
            require(BASE.snapshot(workspace) == before, "default refusal changed owned tracked-link fixture")
            link.unlink()
            index.write_bytes(original_index)
            require(useful("default-restored") == original, "default continuation payload changed")
            report["default_refused_before_startup"] = True
        finally:
            if daemon is not None:
                BASE.DEMO.stop(daemon)
                state["daemon_stopped"] = daemon.poll() is not None
                require(state["daemon_stopped"], "default control daemon remains")


def emit_owned_evidence(output):
    """Expose only bounded files created by this synthetic acceptance run."""
    for name in ("report.json", "os-marker.log"):
        path = output / name
        if not path.is_file():
            continue
        with path.open("rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            print("SOU150_EVIDENCE_LIMITED " + name + "; full file remains in the artifact")
            continue
        print("SOU150_EVIDENCE_BEGIN " + name + " sha256=" + hashlib.sha256(data).hexdigest())
        print(data.decode("utf-8", "strict"), end="" if data.endswith(b"\n") else "\n")
        print("SOU150_EVIDENCE_END " + name)


def run(args):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 required")
    before = BASE.source()
    require(before["commit"] == args.expected_commit and not before["dirty"], "clean exact source required")
    output = args.output.absolute()
    require(not output.exists() and not output.is_symlink() and not output.resolve().is_relative_to(ROOT), "fresh evidence outside source required")
    require(sha(args.git) == args.git_sha256, "Git hash mismatch")
    output.mkdir(mode=0o700, parents=True)
    report = {"format": "sou150-tracked-symlinks-acceptance/1", "status": "incomplete", "source_before": before,
              "runtime_sha256": {name: sha(getattr(args, name)) for name in ("agentfw", "git", "bwrap", "git_launcher", "sandbox_test_binary")},
              "driver_sha256": sha(__file__), "skipped": 0}
    daemon = None
    try:
        with tempfile.TemporaryDirectory(prefix="sou150-owned-") as temporary:
            private = Path(temporary)
            home = private / "home"
            home.mkdir(mode=0o700)
            env = BASE.environment(home)
            env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
            workspace, install = private / "workspace", private / "installed"
            fixture(workspace, args.git, env)
            INSTALL.install(install, workspace, args.git, args.git_sha256, args.bwrap, args.git_launcher)
            report["installation"] = json.loads((install / "installation.json").read_text())
            positive = subprocess.run([str(args.sandbox_test_binary),
                "selected_tracked_symlinks_late_and_racing_outside_reads_are_os_contained", "--ignored", "--nocapture"],
                env=dict(env, SOU150_TEST_PROFILE=str(install / "profile.json"), SOU86_TEST_AGENTFW=str(args.agentfw.resolve())),
                capture_output=True, timeout=150)
            (output / "os-marker.log").write_bytes(positive.stdout + positive.stderr)
            require(positive.returncode == 0 and b"SOU150_LATE_RACE_OS_MARKER_PASSED" in positive.stdout
                    and b"1 passed; 0 failed" in positive.stdout, "independent late/racing OS marker proof failed")
            report["sandbox_positive"] = True
            default_refusal(SimpleNamespace(root=output, binary=args.agentfw, git=args.git,
                                           workspace=workspace, install=install), report)
            subprocess.run([str(args.agentfw), "install"], env=env, stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
            port = BASE.DEMO.free_port()
            config, selection = INSTALL.prepare(install, output / "selection", port)
            report["pilot_selection"] = selection
            write(home / ".agentfw/config.yaml", config)
            with (output / "daemon.log").open("wb") as log:
                daemon = subprocess.Popen([str(args.agentfw), "serve"], env=env, stdout=log, stderr=log)
                require(BASE.DEMO.wait_healthy(port, daemon), "owned enforcing daemon failed")
                stack = SimpleNamespace(root=output, binary=args.agentfw, git=args.git, workspace=workspace,
                                        install=install, env=env, selection=selection)
                byte_reads(stack, report)
                late_changes(stack, report)
            require(INSTALL.SHARED.V1.tree_sha(install / "package") == report["installation"]["profile"]["packageTreeSha256"], "original package changed")
            require(sha(config["policy"]) == selection["policy_sha256"], "policy changed")
            require(not report["read_admission_failures"], "required original reads refused; shared detector failures retained without override")
        report["status"] = "pass"
    except Exception as error:
        report["status"], report["error"] = "fail", type(error).__name__ + ": " + str(error)
    finally:
        if daemon is not None:
            BASE.DEMO.stop(daemon)
            report["daemon_stopped"] = daemon.poll() is not None
            if not report["daemon_stopped"]:
                report["status"], report["cleanup_error"] = "fail", "owned daemon remains"
        try:
            report["source_after"] = BASE.source()
            report["source_unchanged"] = report["source_after"] == before
            if not report["source_unchanged"]:
                report["status"], report["source_error"] = "fail", "source changed during qualification"
        except Exception as error:
            report["status"], report["source_error"] = "fail", type(error).__name__
        report["protected_diagnostics"] = V1.protected_diagnostics(report, output)
        write(output / "report.json", report)
        emit_owned_evidence(output)
    print(json.dumps({"status": report["status"], "error": report.get("error"), "report": str(output / "report.json")}))
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
        print(json.dumps({"status": "plan", "executed": False, "format": INSTALL.FORMAT}))
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
