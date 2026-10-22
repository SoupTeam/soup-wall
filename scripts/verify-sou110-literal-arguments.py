#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Required SOU-110 literal argument acceptance on pinned original Linux FS MCP.

Owned synthetic data only. Accepted profiles/classifier/policy, no stub server,
model/provider, classifier edits, detector changes or permissive fallback.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load("sou110_fs", ROOT / "scripts/verify-sou62-real-mcp.py")
ASK = load("sou110_witness", ROOT / "scripts/verify-sou105-selected-approval.py")
CLASSIFIER = load("sou110_classifier", ROOT / "rule_baseline/rule_baseline.py")
require, write, sha = BASE.require, BASE.write, BASE.sha
FORMAT = "sw-mcp/literal-arguments-acceptance/1"
TEXT = "SOU110 useful owned inventory: 7 red widgets.\n"
POSITIVES = (
    ("script-rm", "read_text_file", {"path": "/workspace/bin/rm.sh"}, TEXT, "/workspace/bin/rm.sh"),
    ("script-send", "read_text_file", {"path": "/workspace/bin/send_report.py"}, TEXT, "/workspace/bin/send_report.py"),
    ("script-chmod", "read_text_file", {"path": "/workspace/bin/chmod.sh"}, TEXT, "/workspace/bin/chmod.sh"),
    ("multiple-script-paths", "read_multiple_files", {"paths": ["/workspace/bin/rm.sh", "/workspace/bin/chmod.sh"]}, TEXT, "/workspace/bin/rm.sh"),
    ("literal-destructive-search", "search_files", {"path": "/workspace", "pattern": "rm -rf"}, "/workspace/rm -rf", "/workspace"),
    ("literal-privilege-search", "search_files", {"path": "/workspace", "pattern": "chmod 777"}, "/workspace/chmod 777", "/workspace"),
)
NEGATIVES = (
    ("mixed-command", "read_text_file", {"path": "/workspace/bin/rm.sh", "command": "rm -rf /workspace"}),
    ("mixed-split-argv", "read_text_file", {"path": "/workspace/bin/rm.sh", "argv": ["rm", "-rf", "/workspace"]}),
    ("forged-read-only", "read_text_file", {"path": "/workspace/bin/rm.sh", "read_only": True}),
    ("forged-roles", "read_text_file", {"path": "/workspace/bin/rm.sh", "argument_roles": {"command": "literal"}}),
    ("outside-workspace", "read_text_file", {"path": "/etc/passwd"}),
    ("traversal", "read_text_file", {"path": "/workspace/../outside"}),
    ("invalid-type", "read_text_file", {"path": ["/workspace/bin/rm.sh"]}),
    ("actual-shell", "Bash", {"command": "rm -rf /workspace"}),
    ("split-shell", "Bash", {"argv": ["rm", "-rf", "/workspace"]}),
    ("actual-write", "write_file", {"path": "/workspace/forbidden", "content": "must not exist"}),
    ("actual-chmod", "chmod", {"path": "/workspace/bin/rm.sh", "mode": "777"}),
    ("actual-send", "send_http", {"url": "http://127.0.0.1:1/owned", "body": "must not leave"}),
)
SOURCE_FILES = (
    "crates/agent/src/action.rs", "crates/agent/src/engine.rs", "crates/agent/src/lib.rs",
    "crates/agentfw/src/native.rs", "crates/agentfw/src/native/invocation.rs",
    "crates/agentfw/src/native/approval.rs", "crates/agentfw/src/mcp/server_profile.rs",
    "crates/agentfw/src/mcp/admission/real_server.rs", "rule_baseline/rule_baseline.py",
    "profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json",
    "profiles/mcp/filesystem-readonly-v1/policy.yaml", "scripts/verify-sou110-literal-arguments.py",
)


def validate_result(response, identifier, fragment):
    require(type(response.get("id")) is int and response["id"] == identifier, "typed call correlation changed")
    text = BASE.result_text(response)
    require(fragment in text, "useful original result missing")
    return text


def native_calls(path):
    raw = path.read_bytes()
    require(len(raw) <= 8 * 1024 * 1024, "native audit exceeded bound")
    return [row for line in raw.splitlines() if (row := json.loads(line)).get("event") == "native_call"]


def grade(report):
    require(report["source_before"] == report["source_after"] and not report["source_before"]["dirty"], "source changed or dirty")
    require(report["source_files_before"] == report["source_files_after"], "implementation/config/classifier bytes changed")
    require(report["skipped"] == 0, "required case skipped")
    rows = report["cases"]
    require([r["case"] for r in rows] == [p[0] for p in POSITIVES] + [n[0] for n in NEGATIVES], "labels or denominator changed")
    for row, positive in zip(rows, POSITIVES):
        require(row["passed"] and row["classifier"]["actions"] == ["read"] and row["classifier"]["unknown"] is False,
                "positive classification unsupported")
        validate_result(row["response"], row["id"], positive[3])
        require(row["target_reads_after"] > row["target_reads_before"], "independent useful execution absent")
        require(row["dispatch_events"] and all(e["execution_dispatched"] is True for e in row["dispatch_events"]), "collector dispatch absent")
        receipts = row["native_invocation"]
        require(len(receipts) == 1 and receipts[0]["tool"] == positive[1] and receipts[0]["verdict"] == "allow"
                and receipts[0]["released"] is True and receipts[0]["registry_sha256"] == report["registry_sha256"], "native policy admission absent")
    for row in rows[len(POSITIVES):]:
        require(row["passed"] and BASE.refused(row["response"]) and not row["dispatch_events"], "unsafe call dispatched")
        require(row["target_reads_after"] == row["target_reads_before"], "refused target executed")
    require(report["workspace_before"] == report["workspace_after"] and report["receiver_bodies"] == [], "forbidden mutation/egress")
    require(report["receiver_calibration"]["passed"] is True, "receiver uncalibrated")
    require(report["policy_controls"] and all(r["passed"] and r["verdict"] == "deny" for r in report["policy_controls"]), "real command policy weakened")
    require(report["classifier_limit"]["preserved"] is True and BASE.refused(report["classifier_limit"]["response"]), "classifier uncertainty bypassed")
    cleanup = report["client"]
    require(cleanup["exit_code"] == 0 and cleanup["forced_cleanup"] is False and cleanup["process_cleanup"]["all_stopped"]
            and cleanup["process_cleanup"]["descendant_count"] > 0, "original processes not reaped")
    require(report["daemon_cleanup"]["all_stopped"] and report["daemon_exit_code"] in (0, -15), "daemon not reaped")
    require(report["cleanup_audit"]["cleanup_verified"] is True, "collector cleanup not verified")


def run(args, report):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "native Linux x86-64 required; no fallback/skip")
    report["source_before"] = BASE.source()
    require(report["source_before"]["commit"] == args.expected_commit and not report["source_before"]["dirty"], "clean exact source required")
    report["source_files_before"] = {name: sha(ROOT / name) for name in SOURCE_FILES}
    report["runtime"] = {name: sha(getattr(args, name)) for name in ("agentfw", "node", "npm", "bwrap", "strace")}
    report["python"] = {"version": platform.python_version(), "sha256": sha(Path(sys.executable).resolve())}
    output = args.output
    workspace, home, installed = output / "workspace", output / "home", output / "installed"
    workspace.mkdir(mode=0o700); (workspace / "bin").mkdir(mode=0o700); home.mkdir(mode=0o700)
    for name in ("bin/rm.sh", "bin/send_report.py", "bin/chmod.sh", "notes.txt", "rm -rf", "chmod 777"):
        (workspace / name).write_text(TEXT)
    BASE.INSTALL.install(installed, workspace, args.node, args.bwrap, args.npm)
    profile = json.loads((installed / "profile.json").read_text())
    registry = json.loads((installed / "registry.json").read_text())
    report["installation"] = json.loads((installed / "installation.json").read_text())
    report["profile_sha256"] = sha(installed / "profile.json")
    report["registry_sha256"] = sha(installed / "registry.json")
    report["policy_sha256"] = sha(installed / "policy.yaml")
    env = BASE.environment(home)
    subprocess.run([str(args.agentfw), "install"], env=env, stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
    port = BASE.DEMO.free_port()
    config = {"port": port, "enforce": True, "policy": str(installed / "policy.yaml"), "audit": str(output / "native-audit.jsonl"), "native": {
        "registry_path": str(installed / "registry.json"), "registry_sha256": report["registry_sha256"]}}
    write(home / ".agentfw/config.yaml", config)
    report["config_sha256"] = sha(home / ".agentfw/config.yaml")
    report["workspace_before"] = BASE.snapshot(workspace)
    # Private sibling path deliberately outside exported artifacts. strace can
    # contain authority-bearing process arguments; export filtered witnesses only.
    private = output.parent / ("." + output.name + "-private-syscalls")
    private.mkdir(mode=0o700)
    trace = private / "original.syscalls"
    receiver = BASE.DEMO.Receiver()
    daemon, client, daemon_witness = None, None, None
    try:
        with (output / "daemon.log").open("wb") as log:
            daemon = subprocess.Popen([str(args.agentfw), "serve"], env=env, stdout=log, stderr=log)
        daemon_witness = BASE.ProcessWitness(daemon.pid)
        require(BASE.DEMO.wait_healthy(port, daemon), "owned enforcing daemon failed startup")
        controls = {}
        BASE.policy_controls(SimpleNamespace(workspace=workspace, receiver=receiver, env=env, binary=args.agentfw,
                                             install=installed, home=home, port=port), controls)
        report["receiver_calibration"] = controls["receiver_calibration"]
        report["policy_controls"] = controls["shipped_policy_controls"]
        env.update(AGENTFW_MCP_SERVER_PROFILE=str(installed / "profile.json"), AGENTFW_CLASSIFIER="rule-baseline",
                   AGENTFW_RULE_BASELINE=str(ROOT / "rule_baseline/rule_baseline.py"), AGENTFW_CLASSIFIER_PYTHON=sys.executable)
        command = [str(args.strace), "-f", "-qq", "-s", "4096", "-e", "trace=openat,execve", "-o", str(trace), "--",
                   str(args.agentfw), "mcp", "--native-admission", "--id", "sou110-filesystem", "--",
                   profile["runtimePath"], str(Path(profile["packageRoot"]) / "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"), "/workspace"]
        stderr = output / "collector.log"
        with stderr.open("wb") as log:
            client = BASE.Client(command, env, workspace, log, "sou110-original-filesystem")
        listing = client.initialize()
        manifest = json.loads((BASE.INSTALL.ASSETS / "upstream-tools-list.json").read_text())["result"]
        require(listing.get("result") == manifest, "original discovery changed")
        report["discovery_sha256"] = BASE.hashlib.sha256(BASE.INSTALL.canonical(listing["result"])).hexdigest()
        definitions = {d["name"]: d for d in manifest["tools"]}

        def reads(target, label, phase):
            return ASK.trace_effects(trace, "filesystem", target=target, evidence=output / f"{label}-{phase}.witness.json")

        for index, (label, tool, arguments, fragment, target) in enumerate(POSITIVES, 100):
            definition = definitions[tool]
            prediction = CLASSIFIER.classify({"tool_name": tool, "raw_arguments": arguments, "tool_description": definition["description"],
                                               "tool_schema": definition["inputSchema"], "pinned_schema": definition["inputSchema"]})
            row = {"case": label, "id": index, "tool": tool, "arguments": arguments, "classifier": prediction,
                   "schema_sha256": next(t["schema_sha256"] for t in registry["tools"] if t["name"] == tool),
                   "target_reads_before": reads(target, label, "before"), "passed": False}
            report["cases"].append(row)
            audit_before = len(native_calls(output / "native-audit.jsonl"))
            row["response"], raw = client.exchange(BASE.call(index, arguments, tool))
            row["native_invocation"] = native_calls(output / "native-audit.jsonl")[audit_before:]
            row["response_sha256"] = BASE.hashlib.sha256(raw).hexdigest()
            row["target_reads_after"] = reads(target, label, "after")
            row["dispatch_events"] = [e for e in BASE.events(stderr) if e.get("host_call_id") == index and e.get("state") == "inflight"]
            validate_result(row["response"], index, fragment)
            require(prediction["actions"] == ["read"] and prediction["unknown"] is False, "accepted classifier blocks supported positive; retain minimal blocker")
            require(row["target_reads_after"] > row["target_reads_before"], "useful read/search lacks independent syscall")
            row["passed"] = True

        for index, (label, tool, arguments) in enumerate(NEGATIVES, 200):
            row = {"case": label, "id": index, "tool": tool, "arguments": arguments, "target_reads_before": reads("/workspace/bin/rm.sh", label, "before"), "passed": False}
            report["cases"].append(row)
            row["response"], _ = client.exchange(BASE.call(index, arguments, tool))
            row["target_reads_after"] = reads("/workspace/bin/rm.sh", label, "after")
            row["dispatch_events"] = [e for e in BASE.events(stderr) if e.get("host_call_id") == index and e.get("state") == "inflight"]
            require(BASE.refused(row["response"]) and not row["dispatch_events"] and row["target_reads_after"] == row["target_reads_before"], "unsafe/mixed/forged dispatch")
            response, _ = client.exchange(BASE.call(index + 1000, {"path": "/workspace/notes.txt"}))
            validate_result(response, index + 1000, TEXT)
            row["useful_followup"] = response
            row["passed"] = True
        response, _ = client.exchange(BASE.call(300, {"path": "/workspace"}, "directory_tree"))
        report["classifier_limit"] = {"response": response, "preserved": BASE.refused(response) and "classifier_ask" in json.dumps(response)}
        require(report["classifier_limit"]["preserved"], "unrelated unknown classifier outcome weakened")
        report["workspace_after"] = BASE.snapshot(workspace)
        report["receiver_bodies"] = receiver.bodies.copy()
        report["trace_sha256"] = sha(trace)
    finally:
        try:
            if client is not None:
                client.close()
                report["client"] = client.transcript()
                endings = []
                for line in (output / "collector.log").read_bytes().splitlines():
                    try:
                        value = json.loads(line)
                        if value.get("event") == "mcp_real_server_end": endings.append(value)
                    except ValueError:
                        pass
                report["cleanup_audit"] = endings[-1] if len(endings) == 1 else {}
        finally:
            try:
                if daemon is not None:
                    BASE.DEMO.stop(daemon)
                    daemon.wait(timeout=8)
                    report["daemon_exit_code"] = daemon.returncode
                    report["daemon_cleanup"] = daemon_witness.finish()
            finally:
                receiver.close()
    report["source_after"] = BASE.source()
    report["source_files_after"] = {name: sha(ROOT / name) for name in SOURCE_FILES}
    grade(report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    for name in ("agentfw", "node", "npm", "bwrap", "strace", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    args.output = args.output.resolve()
    require(not args.output.exists() and not args.output.is_relative_to(ROOT), "new output outside checkout required")
    args.output.mkdir(mode=0o700, parents=True)
    report = {"format": FORMAT, "status": "failed", "cases": [], "skipped": 0}
    try:
        for name in ("agentfw", "node", "npm", "bwrap", "strace"):
            setattr(args, name, getattr(args, name).resolve(strict=True))
        run(args, report)
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)[:2000]
    finally:
        if "source_before" in report:
            report["source_after"] = BASE.source()
            report["source_files_after"] = {name: sha(ROOT / name) for name in SOURCE_FILES}
        write(args.output / "report.json", report)
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]), "error": report.get("error")}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
