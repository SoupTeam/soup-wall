#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare disposable daemon status with real MCP witnesses on an exact candidate.

Reuses the accepted demo fixture, production collector and real rule baseline.
No live provider, real host settings or GitHub settings are used or changed.
This bounded probe does not accept the pending generic SOU-15 integration.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
CASE_IDS = {"enforcing-read", "enforcing-delete", "enforcing-ask", "enforcing-result",
            "daemon-unavailable", "recovered-read", "shadow-read"}


class ProbeFailure(RuntimeError):
    pass


def load(repo, filename, name):
    spec = importlib.util.spec_from_file_location(name, repo / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def require(condition, reason):
    if not condition:
        raise ProbeFailure(reason)


def call_frame(name, tool, arguments, progress):
    return json.dumps({"jsonrpc": "2.0", "id": name, "method": "tools/call", "params": {
        "name": tool, "arguments": arguments,
        "_meta": {"claudecode/toolUseId": "toolu_sou18_" + name, "progressToken": progress}}}, separators=(",", ":"))


def verified(report):
    rows = report["rows"]
    return ("error" not in report and len(rows) == len(CASE_IDS) and {row["call_id"] for row in rows} == CASE_IDS
            and all(row["status"] == "pass" for row in rows) and report.get("final_ledger_matches") is True
            and report.get("inventory_preserved") is True and report.get("receiver_final_count") == 0
            and report.get("source_binary_stable") is True and report.get("owned_profile_removed") is True)


@contextmanager
def private_environment(values):
    original = dict(os.environ)
    os.environ.clear()
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)


def grade(row):
    """Status success alone cannot stand in for executor and client observations."""
    try:
        expected = row["expected"]
        require(expected in {"allow", "deny", "ask", "result_withheld", "unavailable", "shadow"}, "unknown_expectation")
        required_exit = {"unavailable": 2, "shadow": 4}.get(expected, 0)
        require(type(row["preflight_exit"]) is int and row["preflight_exit"] == required_exit, "preflight_mismatch")
        require(row["actual"] == expected, "outcome_mismatch")
        request = json.loads(row["submitted_frame"])
        require(request.get("id") == row["call_id"] and type(request.get("id")) is str, "request_identity_mismatch")
        require(request.get("method") == "tools/call" and request.get("jsonrpc") == "2.0", "request_shape_mismatch")
        executes = expected in {"allow", "result_withheld"}
        require(row["executor_raw"] == (row["submitted_frame"] + "\n" if executes else ""), "executor_witness_mismatch")
        require(type(row["receiver_count"]) is int and row["receiver_count"] == 0, "unexpected_delivery")
        if expected in {"unavailable", "shadow"}:
            require(row["released_raw"] == "" and row["server_result_raw"] == "", "unexpected_result")
            require(type(row["collector_exit"]) is int and row["collector_exit"] != 0, "collector_did_not_refuse")
        else:
            reply = json.loads(row["released_raw"])
            require(reply.get("id") == row["call_id"] and reply.get("jsonrpc") == "2.0", "result_identity_mismatch")
            if expected == "allow":
                require(row["server_result_raw"] == row["released_raw"], "result_bytes_changed")
                require(reply.get("result") == {"content": [{"type": "text", "text": "Inventory: 7 red widgets."}]},
                        "useful_result_missing")
            elif expected == "result_withheld":
                require(json.loads(row["server_result_raw"]).get("id") == row["call_id"], "server_result_identity_mismatch")
                require("MARKER-PRIVATE-FIXTURE" in row["server_result_raw"], "fixture_result_missing")
                require("MARKER-PRIVATE-FIXTURE" not in row["released_raw"], "protected_result_released")
                require("Soup Wall withheld MCP result" in row["released_raw"], "result_refusal_missing")
            else:
                require(row["server_result_raw"] == "", "refused_call_produced_result")
                reasons = {"deny": ("policy_denied", "demo-destructive-deny"),
                           "ask": ("policy_unconfirmed_ask", "demo-pii-confirmation")}[expected]
                require(any(f"Soup Wall withheld MCP invocation ({reason})" in row["released_raw"] for reason in reasons),
                        "policy_refusal_missing")
            require(row["classifier_matches_revision"] is True, "classifier_identity_missing")
        row["status"] = "pass"
    except (KeyError, TypeError, ValueError, AttributeError, ProbeFailure):
        row["status"] = "fail"
    return row


def run(args):
    repo, binary = args.repo.resolve(), args.agentfw.resolve()
    setup = load(repo, "clean-setup-acceptance.py", "sou18_setup")
    latency = load(repo, "measure-sou17-latency.py", "sou18_evidence")
    before = latency.snapshot(repo)
    require(not before["dirty"] and before["commit"] == args.expected_commit, "clean_exact_candidate_required")
    binary_hash = setup.sha(binary)
    out = args.output.resolve()
    require(not out.is_relative_to(repo), "evidence_must_be_outside_candidate")
    out.mkdir(parents=True, exist_ok=False)
    demo = load(repo, "mcp-admission-demo.py", "sou18_demo")
    demo.REAL_BASELINE, demo.CLASSIFIER = True, "rule-baseline/python"
    classifier_hash = setup.sha(repo / "rule_baseline/rule_baseline.py")
    report = {"schema_version": "sou18-status-witnesses/1", "status": "incomplete",
              "observed_at": datetime.now(timezone.utc).isoformat(), "source_before": before,
              "probe_sha256": setup.sha(Path(__file__)), "binary_sha256": binary_hash,
              "build_provenance": "Caller must retain the matching build record; binary identity alone is not a build attestation.",
              "environment": {"os": platform.system(), "architecture": platform.machine(),
                              "kernel": platform.release(), "python": platform.python_version(), "cpu_count": os.cpu_count()},
              "classifier": {"source": "rule-baseline/python", "sha256": classifier_hash},
              "initial_path_verified": False, "generic_candidate_acceptance": "pending_sou15",
              "actual_host": "not_run; scripted stdio client only", "rows": [],
              "limitations": ["Selected trusted local fixture and existing registry-only path; not arbitrary server containment.",
                              "Direct server launches, other host paths and independently launched OS commands are unprotected.",
                              "Constrained resource execution remains a SOU-15 acceptance dependency; this probe does not test generic classifier reply routing.",
                              "One sample per status case is not warm MCP overhead; use the paired SOU-17 measurement separately."]}
    credentials = []
    started = time.perf_counter()
    try:
        with tempfile.TemporaryDirectory(prefix="sou18-status-", dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            root = Path(temporary)
            with ExitStack() as cleanup, private_environment(setup.private_environment(root)):
                with demo.agent_stack(binary, root / "fixture") as stack:
                    report["install_and_daemon_ready_ms"] = (time.perf_counter() - started) * 1000
                    credentials = [(stack.workspace / ".agentfw" / name).read_bytes().strip()
                                   for name in ("token", "native-token")]
                    config_path = stack.workspace / ".agentfw/config.yaml"
                    config = json.loads(config_path.read_text(encoding="utf-8"))
                    report["runtime"] = {"policy_sha256": setup.sha(stack.workspace / "policy.yaml"),
                        "profile_sha256": setup.sha(stack.workspace / "registry.json"),
                        "config_enforcing_sha256": setup.sha(config_path),
                        "fixture_sha256": setup.sha(demo.FIXTURE),
                        "schema_sha256": demo.sha(demo.canonical(stack.tools)),
                        "transport": "stdio", "client": "scripted MCP frames"}
                    inventory = (stack.notes / "inventory.txt").read_bytes()
                    def probe(expected_exit):
                        return setup.check_probe(binary, stack.workspace, stack.env, expected_exit)

                    def connect(label, initialize=True):
                        log = (stack.workspace / (label + ".log")).open("wb")
                        cleanup.callback(log.close)
                        harness = demo.Harness(stack.collector, stack.env, log)
                        def close_harness():
                            setup.stop(harness.process)
                            for pipe in (harness.process.stdin, harness.process.stdout):
                                if pipe is not None:
                                    pipe.close()
                        cleanup.callback(close_harness)
                        if initialize:
                            reply = harness.send('{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sou18-status","version":"1"}}}')
                            require(reply is not None and json.loads(reply).get("id") == "init", "initialization_failed")
                            harness.send('{"jsonrpc":"2.0","method":"notifications/initialized"}', reply=False)
                            listed = harness.send('{"jsonrpc":"2.0","id":"list","method":"tools/list"}')
                            require(listed is not None and json.loads(listed).get("result", {}).get("tools") == stack.tools,
                                    "manifest_mismatch")
                        return harness, log

                    def observe(harness, log, name, tool, arguments, expected, preflight_exit):
                        ledger_before = latency.read(stack.ledger)
                        server_before = latency.read(stack.responses)
                        before_delivery = len(stack.receiver.bodies)
                        call_started = time.perf_counter()
                        frame = call_frame(name, tool, arguments, len(report["rows"]) + 1)
                        reply = harness.send(frame)
                        elapsed = (time.perf_counter() - call_started) * 1000
                        code = None
                        if expected in {"unavailable", "shadow"}:
                            code = harness.close()
                            actual = expected if reply is None and code not in (0, None) else "unexpected_response"
                        else:
                            response = json.loads(reply) if reply else {}
                            result = response.get("result", {})
                            text = response.get("error", {}).get("message") or (result.get("content") or [{}])[0].get("text", "")
                            actual = demo.outcome_of(text, bool(response.get("error")) or result.get("isError")) if reply else "missing_response"
                        evidence = [item for item in demo.classification_evidence(Path(log.name)) if item.get("host_call_id") == name]
                        row = {"call_id": name, "expected": expected, "actual": actual, "preflight_exit": preflight_exit,
                            "submitted_frame": frame, "executor_raw": latency.read(stack.ledger)[len(ledger_before):].decode(),
                            "server_result_raw": latency.read(stack.responses)[len(server_before):].decode(),
                            "released_raw": (reply or b"").decode(), "receiver_count": len(stack.receiver.bodies) - before_delivery,
                            "collector_exit": code, "request_ms": elapsed,
                            "classifier_matches_revision": len(evidence) == 1 and evidence[0].get("source") == "rule-baseline/python"
                                and evidence[0].get("classifier_sha256") == classifier_hash}
                        report["rows"].append(grade(row))

                    harness, log = connect("enforcing")
                    report["install_and_mcp_connect_ms"] = (time.perf_counter() - started) * 1000
                    healthy = probe(0)
                    for name, tool, arguments, expected in (
                        ("enforcing-read", "read_document", {"name": "inventory"}, "allow"),
                        ("enforcing-delete", "delete_note", {"name": "inventory"}, "deny"),
                        ("enforcing-ask", "send_http", {"url": stack.receiver.url, "body": "Contact alice@example.com"}, "ask"),
                        ("enforcing-result", "read_document", {"name": "injected"}, "result_withheld")):
                        observe(harness, log, name, tool, arguments, expected, healthy)
                    setup.stop(stack.daemon)
                    observe(harness, log, "daemon-unavailable", "read_document", {"name": "inventory"}, "unavailable", probe(2))

                    recovered = setup.start(binary, stack.workspace, stack.env, config["port"], True)
                    cleanup.callback(setup.stop, recovered)
                    recovered_probe = probe(0)
                    fresh, fresh_log = connect("recovered")
                    observe(fresh, fresh_log, "recovered-read", "read_document", {"name": "inventory"}, "allow", recovered_probe)
                    require(fresh.close() == 0, "recovered_collector_exit")
                    setup.stop(recovered)

                    config["enforce"] = False
                    # Production validation disallows native admission in shadow mode.
                    # Use a valid shadow daemon and prove that the native collector refuses it.
                    config.pop("native", None)
                    report["shadow_native_admission"] = "disabled; native configuration requires enforcement"
                    config_path.write_text(json.dumps(config), encoding="utf-8")
                    report["runtime"]["config_shadow_sha256"] = setup.sha(config_path)
                    shadow = setup.start(binary, stack.workspace, stack.env, config["port"], False)
                    cleanup.callback(setup.stop, shadow)
                    shadow_probe = probe(4)
                    blocked, blocked_log = connect("shadow", initialize=False)
                    observe(blocked, blocked_log, "shadow-read", "read_document", {"name": "inventory"}, "shadow", shadow_probe)
                    setup.stop(shadow)
                    report["inventory_preserved"] = (stack.notes / "inventory.txt").read_bytes() == inventory
                    final_ledger = latency.read(stack.ledger).decode()
                    report["final_executor_raw"] = final_ledger
                    report["final_ledger_matches"] = final_ledger == "".join(
                        row["submitted_frame"] + "\n" for row in report["rows"] if row["expected"] in {"allow", "result_withheld"})
                    report["receiver_final_count"] = len(stack.receiver.bodies)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = {"type": type(error).__name__,
                           "reason": str(error) if isinstance(error, (ProbeFailure, setup.CheckFailed)) else "probe_failed; no acceptance claimed"}
    report["owned_profile_removed"] = not root.exists() if "root" in locals() else False
    try:
        report["source_after"] = latency.snapshot(repo)
        report["source_binary_stable"] = before == report["source_after"] and setup.sha(binary) == binary_hash
    except (OSError, ValueError, subprocess.SubprocessError):
        report["source_binary_stable"] = False
    report["initial_path_verified"] = verified(report)
    report["status"] = "pass" if report["initial_path_verified"] else "incomplete"
    if any(row["status"] == "fail" for row in report["rows"]):
        report["status"] = "fail"
    serialized = json.dumps(report, indent=2, allow_nan=False) + "\n"
    require(not any(token and token in serialized.encode() for token in credentials), "credential_retention_refused")
    (out / "results.json").write_text(serialized, encoding="utf-8")
    print(f"Initial status/MCP path: {report['status']}. Generic acceptance: pending SOU-15. Evidence: {out}")
    return {"pass": 0, "fail": 1, "incomplete": 2}[report["status"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--agentfw", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "not_run", "processes_started": 0, "generic_candidate_acceptance": "pending_sou15"}))
        return 0
    if not all((args.repo, args.agentfw, args.expected_commit, args.output)):
        parser.error("--run requires --repo, --agentfw, --expected-commit and a fresh --output directory")
    try:
        return run(args)
    except (OSError, ValueError, ProbeFailure, subprocess.SubprocessError) as error:
        print(f"Probe could not complete ({type(error).__name__}); no acceptance claimed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
