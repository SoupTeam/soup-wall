#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused, private, exact-source raw MCP boundary qualification on Linux."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FS = load("sou182_fs", "verify-sou62-real-mcp.py")
GIT = load("sou182_git", "verify-sou68-real-mcp.py")
FS_INSTALL = load("sou182_fs_install", "install-sou62-filesystem-profile.py")
GIT_INSTALL = GIT.INSTALL
require = FS.require


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def wire_cases(tool, arguments):
    """Only synthetic paths and names; no raw frame is written to evidence."""
    call = {"jsonrpc": "2.0", "id": "raw", "method": "tools/call",
            "params": {"name": tool, "arguments": arguments}}
    base = json.dumps(call, separators=(",", ":")).encode()
    path = b"/workspace/notes.txt" if tool == "read_text_file" else b"HEAD"
    require(path in base, "positive control path absent from raw template")
    name = tool.encode()
    duplicate_name = base.replace(b'"name":"' + name + b'",',
                                  b'"name":"' + name + b'","name":"write_file",', 1)
    argument_key = b'"path"' if tool == "read_text_file" else b'"revision"'
    duplicate_arg = base.replace(argument_key + b":", argument_key + b':"shadow",' + argument_key + b":", 1)
    nested = base.replace(b'"arguments":{', b'"arguments":{"extra":{"key":1,"key":2},', 1)
    nan = base.replace(b'"arguments":{', b'"arguments":{"weight":NaN,', 1)
    surrogate = base.replace(path, b"\\ud800", 1)
    duplicate_id = base.replace(b'"id":"raw",', b'"id":"raw","id":"other",', 1)
    invalid_id = base.replace(b'"id":"raw",', b'"id":true,', 1)
    null_id = base.replace(b'"id":"raw",', b'"id":null,', 1)
    fractional_id = base.replace(b'"id":"raw",', b'"id":1.5,', 1)
    unsafe_integer = base.replace(b'"id":"raw",', b'"id":9007199254740992,', 1)
    depth = base.replace(b'"arguments":{', b'"arguments":{"extra":' + b"[" * 22 + b"0" + b"]" * 22 + b",", 1)
    invalid_utf8 = base.replace(path, b"\xff", 1)
    oversized = base + b" " * 262_145
    return (
        ("duplicate-name", duplicate_name + b"\n", "protocol_json_invalid"),
        ("duplicate-arguments", duplicate_arg + b"\n", "protocol_json_invalid"),
        ("nested-duplicate", nested + b"\n", "protocol_json_invalid"),
        ("nan", nan + b"\n", "protocol_json_invalid"),
        ("lone-surrogate", surrogate + b"\n", "protocol_json_invalid"),
        ("invalid-utf8", invalid_utf8 + b"\n", "protocol_json_invalid"),
        ("incomplete-json", base[:-1] + b"\n", "protocol_json_invalid"),
        ("trailing-json", base + b"{}\n", "protocol_json_invalid"),
        ("unterminated-frame", base[:-1], "unterminated_frame"),
        ("over-depth", depth + b"\n", "depth_limit"),
        ("oversized-frame", oversized + b"\n", "frame_limit"),
        ("duplicate-id", duplicate_id + b"\n", "protocol_json_invalid"),
        ("invalid-id", invalid_id + b"\n", "invalid_id"),
        ("null-id", null_id + b"\n", "invalid_id"),
        ("fractional-id", fractional_id + b"\n", "invalid_id"),
        ("unsafe-integer-id", unsafe_integer + b"\n", "unsafe_integer_id"),
    )


def failure_code(log, expected):
    require(log.stat().st_size <= 262_144, "collector diagnostic exceeded private bound")
    raw = log.read_bytes()
    # The production error channel may include other bounded diagnostics. Never
    # copy untrusted text into the public report; map only reviewed literals.
    markers = {
        "protocol_json_invalid": b"unsupported or malformed MCP JSON",
        "unterminated_frame": b"unterminated MCP frame",
        "depth_limit": b"selected MCP JSON exceeds limits",
        "frame_limit": b"MCP frame exceeds admission limit",
        "invalid_id": b"unsupported MCP request id",
        "unsafe_integer_id": b"MCP ID is not a safe JSON integer",
    }
    require(markers[expected] in raw, "unexpected production refusal category")
    require(b"/workspace/notes.txt" not in raw, "raw path leaked into collector diagnostics")
    return expected


def classification_count(log):
    require(log.stat().st_size <= 262_144, "collector diagnostic exceeded private bound")
    count = 0
    for line in log.read_bytes().splitlines():
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        count += isinstance(value, dict) and value.get("event") == "mcp_classification"
    return count


def exact_read(client, kind):
    if kind == "filesystem":
        response, _ = client.exchange(FS.call(90, {"path": "/workspace/notes.txt"}))
        require(FS.result_text(response) == FS.TEXT, "selected filesystem read failed")
    else:
        response, _ = client.exchange(GIT.call(90))
        require("SOU-68 synthetic initial commit" in GIT.text(response), "selected Git read failed")


def initialize_selected(client, kind):
    manifest = client.initialize()
    if kind == "filesystem":
        expected = json.loads((FS_INSTALL.ASSETS / "upstream-tools-list.json").read_text())
        require(manifest["result"] == expected["result"], "original filesystem discovery changed")


def qualify_case(kind, command, env, workspace, root, label, raw, expected):
    log = root / f"{kind}-{label}.log"
    before = FS.snapshot(workspace)
    witness = GIT.RepositoryWitness(workspace)
    client_type = FS.Client if kind == "filesystem" else GIT.Client
    with log.open("wb") as stream:
        client = client_type(command, env, workspace, stream, f"sou182-{kind}-{label}")
        try:
            initialize_selected(client, kind)
            witness.drain()
            exact_read(client, kind)
            positive_opens = witness.drain()
            require(positive_opens > 0, "kernel open witness did not observe allowed read")
            # Write the exact bytes, including malformed UTF-8. The existing
            # Client.send JSON encoder is intentionally bypassed here.
            try:
                client.process.stdin.write(raw)
                client.process.stdin.flush()
            except BrokenPipeError:
                require(expected == "frame_limit", "raw frame was not delivered")
            if label == "unterminated-frame":
                client.process.stdin.close()
            try:
                reply = client.lines.get(timeout=12)
            except queue.Empty as error:
                raise ValueError("invalid frame did not reach a bounded terminal state") from error
            require(reply is None, "invalid raw frame was correlated or delivered")
            require(witness.drain() == 0, "rejected raw frame opened the workspace")
        finally:
            client.close()
            witness.close()
    require(client.process.returncode != 0 and not client.forced_cleanup,
            "invalid frame did not terminate the documented fatal relay")
    require(client.process_witness.final["all_stopped"] and client.process_witness.final["descendant_count"] > 0,
            "selected original server did not start or owned descendant survived")
    require(FS.snapshot(workspace) == before, "rejected frame changed workspace")
    require(classification_count(log) == 1,
            "rejected raw frame gained a classifier decision or positive control was absent")
    return {"case": label, "raw_sha256": digest(raw), "raw_bytes": len(raw),
            "failure_code": failure_code(log, expected), "response_delivered": False,
            "positive_read_kernel_opens": positive_opens, "kernel_workspace_opens": 0,
            "classifier_events_after_positive_read": 0,
            "workspace_unchanged": True,
            "collector_exit_code": client.process.returncode,
            "selected_server_processes_stopped": client.process_witness.final["all_stopped"],
            "selected_server_descendants_observed": client.process_witness.final["descendant_count"],
            "collector_log_sha256": FS.sha(log)}


def qualify_recoverable(kind, command, env, workspace, root):
    """A valid correlated unsupported method refuses and keeps the session useful."""
    log = root / f"{kind}-recoverable.log"
    witness = GIT.RepositoryWitness(workspace)
    client_type = FS.Client if kind == "filesystem" else GIT.Client
    before = FS.snapshot(workspace)
    with log.open("wb") as stream:
        client = client_type(command, env, workspace, stream, f"sou182-{kind}-recoverable")
        try:
            initialize_selected(client, kind)
            witness.drain()
            raw = b'{"jsonrpc":"2.0","id":"unsupported","method":"tools/call","params":{"name":"send_http","arguments":{}}}\n'
            client.process.stdin.write(raw)
            client.process.stdin.flush()
            response, _ = client.receive(timeout=12)
            require(response.get("id") == "unsupported" and response.get("error", {}).get("code") == -32601,
                    "supported recoverable refusal lost exact ID or error code")
            require(witness.drain() == 0, "recoverable refusal opened workspace")
            exact_read(client, kind)
            followup_opens = witness.drain()
            require(followup_opens > 0, "useful read did not continue after recoverable refusal")
        finally:
            client.close()
            witness.close()
    require(client.process.returncode == 0 and not client.forced_cleanup
            and client.process_witness.final["all_stopped"], "recoverable relay cleanup failed")
    require(FS.snapshot(workspace) == before, "recoverable control changed workspace")
    require(classification_count(log) == 1, "unsupported tool gained classifier decision")
    return {"case": "unsupported-tool-recoverable", "raw_sha256": digest(raw), "raw_bytes": len(raw),
            "correlated_id": "unsupported", "error_code": -32601, "kernel_workspace_opens_before_followup": 0,
            "classifier_events_on_unsupported_tool": 0, "useful_followup": True,
            "useful_followup_kernel_opens": followup_opens, "workspace_unchanged": True,
            "collector_log_sha256": FS.sha(log), "selected_server_processes_stopped": True}


def qualify_profile(kind, args, root, report):
    report["profiles"][kind] = {"status": "incomplete", "cases": []}
    with tempfile.TemporaryDirectory(prefix=f"sou182-{kind}-") as temporary:
        private = Path(temporary)
        workspace = private / "workspace"
        home = private / "home"
        home.mkdir(mode=0o700)
        env = FS.environment(home)
        install = private / "installed"
        if kind == "filesystem":
            workspace.mkdir(mode=0o700)
            (workspace / "notes.txt").write_text(FS.TEXT, encoding="utf-8")
            FS_INSTALL.install(install, workspace, args.node, args.bwrap, args.npm)
            entry = install / "package/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"
            command = [str(args.agentfw), "mcp", "--native-admission", "--id", "sou62-filesystem",
                       "--", str(args.node), str(entry), "/workspace"]
            classifier = ROOT / "rule_baseline/rule_baseline.py"
            tool, arguments = "read_text_file", {"path": "/workspace/notes.txt"}
        else:
            env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
            GIT.prepare_repo(workspace, args.git, env)
            GIT_INSTALL.install(install, workspace, args.git, FS.sha(args.git), args.bwrap, args.git_launcher)
            python = install / "package/python/bin/python3.11"
            env.update(GIT_PYTHON_GIT_EXECUTABLE=str(args.git), GIT_OPTIONAL_LOCKS="0")
            command = [str(args.agentfw), "mcp", "--native-admission", "--id", "sou68-git",
                       "--", str(python), "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"]
            classifier = ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py"
            tool, arguments = "git_show", {"repo_path": "/workspace", "revision": "HEAD"}
        subprocess.run([str(args.agentfw), "install"], env=env, stdin=subprocess.DEVNULL,
                       capture_output=True, check=True, timeout=30)
        port = FS.DEMO.free_port()
        config = {"port": port, "enforce": True, "max_record_bytes": 1048576,
                  "policy": str(install / "policy.yaml"),
                  "native": {"registry_path": str(install / "registry.json"),
                             "registry_sha256": FS.sha(install / "registry.json")}}
        FS.write(home / ".agentfw/config.yaml", config)
        env.update(AGENTFW_MCP_SERVER_PROFILE=str(install / "profile.json"),
                   AGENTFW_CLASSIFIER="rule-baseline", AGENTFW_RULE_BASELINE=str(classifier),
                   AGENTFW_CLASSIFIER_PYTHON=sys.executable)
        installed = json.loads((install / "installation.json").read_text())
        report["profiles"][kind].update(
            installation_sha256=FS.sha(install / "installation.json"),
            profile_sha256=FS.sha(install / "profile.json"),
            registry_sha256=FS.sha(install / "registry.json"),
            package_tree_sha256=installed["profile"]["packageTreeSha256"])
        with (root / f"{kind}-daemon.log").open("wb") as log:
            daemon = subprocess.Popen([str(args.agentfw), "serve"], env=env, stdout=log, stderr=log)
            try:
                require(FS.DEMO.wait_healthy(port, daemon), "owned enforcing daemon did not start")
                for label, raw, expected in wire_cases(tool, arguments):
                    row = {"case": label, "raw_sha256": digest(raw), "raw_bytes": len(raw),
                           "status": "incomplete"}
                    report["profiles"][kind]["cases"].append(row)
                    try:
                        row.update(qualify_case(kind, command, env, workspace, root, label, raw, expected))
                        row["status"] = "pass"
                    except Exception as error:
                        row["status"] = "fail"
                        row["failure_type"] = type(error).__name__
                        raise
                report["profiles"][kind]["recoverable"] = qualify_recoverable(
                    kind, command, env, workspace, root)
            finally:
                FS.DEMO.stop(daemon)
        require(daemon.poll() is not None, "owned daemon survived cleanup")
        require(FS_INSTALL.tree_sha(install / "package") == installed["profile"]["packageTreeSha256"]
                and FS.sha(install / "profile.json") == report["profiles"][kind]["profile_sha256"]
                and FS.sha(install / "registry.json") == report["profiles"][kind]["registry_sha256"],
                "installed selected profile drifted during raw qualification")
    report["profiles"][kind]["owned_profile_removed"] = not private.exists()
    require(report["profiles"][kind]["owned_profile_removed"], "owned profile cleanup incomplete")
    report["profiles"][kind]["status"] = "pass"


def run(args):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "native Linux x86_64 required")
    before = FS.source()
    require(not before["dirty"] and before["commit"] == args.expected_commit, "clean exact source required")
    paths = [args.agentfw, args.node, args.bwrap, args.git, args.git_launcher, args.npm]
    require(all(path.is_file() for path in paths), "exact installed runtime inputs missing")
    root = args.output.resolve()
    require(not root.exists() and not root.is_relative_to(ROOT), "new private evidence directory outside checkout required")
    root.mkdir(mode=0o700, parents=True)
    report = {"format": "sou182-raw-mcp-acceptance/1", "status": "incomplete", "source_before": before,
              "driver_sha256": FS.sha(Path(__file__)), "binary_sha256": FS.sha(args.agentfw),
              "runtime_sha256": {path.name: FS.sha(path) for path in paths[1:]},
              "profiles": {}, "failed": 0, "skipped": 0, "paid_model_calls": 0}
    try:
        for kind in ("filesystem", "git"):
            qualify_profile(kind, args, root, report)
        report["source_after"] = FS.source()
        require(report["source_after"] == before and FS.sha(args.agentfw) == report["binary_sha256"]
                and all(FS.sha(path) == report["runtime_sha256"][path.name] for path in paths[1:]),
                "source or runtime input changed during qualification")
        report["status"] = "pass"
    except Exception as error:
        report["status"], report["failed"] = "fail", 1
        report["failure_type"] = type(error).__name__
        report["failure_reason"] = str(error)[:512]
    finally:
        FS.write(root / "report.json", report)
    print(json.dumps({"status": report["status"], "failed": report["failed"], "skipped": 0,
                      "report": str(root / "report.json"), "failure_type": report.get("failure_type"),
                      "failure_reason": report.get("failure_reason")}))
    return 0 if report["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    for name in ("agentfw", "node", "bwrap", "git", "git-launcher", "npm", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False,
                          "profiles": ["filesystem", "git"], "cases_per_profile": 16}))
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
