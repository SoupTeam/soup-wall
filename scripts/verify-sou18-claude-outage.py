#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify daemon loss through an explicitly supplied Claude Code executable.

Uses the existing MCP fixture and local scripted Messages provider. A useful
read must finish before the owned daemon is stopped and a benign send is
proposed. No account, paid provider, host installation or real profile is used.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
PAYLOAD = "SOU18 outage control: this benign body must not arrive."


def load(repo, filename, name):
    spec = importlib.util.spec_from_file_location(name, repo / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(value, reason):
    if not value:
        raise ValueError(reason)


def host_text(value):
    """Remove only Claude's observed trailing token-budget reminder."""
    return re.sub(r"\n\n?<system-reminder>\n<total_tokens>[0-9]+ tokens left</total_tokens>\n</system-reminder>$",
                  "", value)


def grade(data):
    """Require positive host utility and independent zero effects after outage."""
    try:
        require(type(data["host_exit"]) is int and data["host_exit"] == 0
                and data["host_completed"] is True and data["host_timed_out"] is False, "host_incomplete")
        require(data["connected"] is True and bool(data["claude_version"]), "host_not_connected")
        require(data["daemon_stopped_before_send"] is True and data["preflight_exit"] == 2,
                "outage_not_observed")
        first = data["model_results"]["toolu_demo_0"]
        last = data["model_results"]["toolu_demo_1"]
        require(first["is_error"] is False and host_text(first["text"]) == "Inventory: 7 red widgets.",
                "useful_read_missing")
        require(last["is_error"] is True and bool(last["text"]), "outage_error_missing")
        proposals = data["host_tool_uses"]
        require(proposals == [
            {"type": "tool_use", "id": "toolu_demo_0", "name": "mcp__demo__read_document",
             "input": {"name": "inventory"}},
            {"type": "tool_use", "id": "toolu_demo_1", "name": "mcp__demo__send_http",
             "input": {"url": data["receiver_url"], "body": PAYLOAD}},
        ], "actual_host_proposals_missing_or_changed")
        ledger = data["ledger"]
        require(len(ledger) == 1 and ledger == data["ledger_at_outage"], "unexpected_execution")
        require(ledger[0]["method"] == "tools/call"
                and ledger[0]["params"]["name"] == "read_document"
                and ledger[0]["params"]["arguments"] == {"name": "inventory"}
                and ledger[0]["params"]["_meta"]["claudecode/toolUseId"] == "toolu_demo_0",
                "read_identity_changed")
        require(data["receiver_bodies"] == [] and data["inventory_preserved"] is True, "unexpected_effect")
        classifications = data["classifications"]
        require(len(classifications) == 2 and all(r["source"] == "rule-baseline/python" for r in classifications)
                and classifications[0]["host_call_id"] == ledger[0]["id"], "classification_identity_missing")
        # Classification/policy are local; native admission still needs the daemon.
        # A transport failure must not be mislabeled as a policy Deny.
        sent = classifications[1]
        arguments = json.dumps(proposals[1]["input"], sort_keys=True, separators=(",", ":")).encode()
        require(sent["tool"] == "send_http" and sent["host_call_id"] != ledger[0]["id"]
                and sent["args_sha256"] == hashlib.sha256(arguments).hexdigest()
                and sent["classification"]["actions"] == ["send_data"]
                and sent["authoritative_verdict"] == "allow" and sent["adapter_verdict"] == "deny"
                and sent["failure"] is None and sent["policy"] == "reached"
                and data["collector_admission_unavailable"] is True,
                "native_transport_failure_not_distinguished")
        require(len(data["native_decisions"]) == 2
                and [r["event"] for r in data["native_decisions"]] == ["native_call", "native_result"]
                and all(r["released"] is True and r["shadow"] is False for r in data["native_decisions"]),
                "native_read_not_verified")
        call, result = data["native_decisions"]
        require(call["call_id"] == result["call_id"] and call["binding_sha256"] == result["binding_sha256"]
                and call["session"] == result["session"]
                and call["verdict"] == result["verdict"] == "allow", "native_identity_changed")
        return {"status": "pass", "reason": "useful read followed by actual-host outage refusal and zero send effects"}
    except (KeyError, TypeError, ValueError, IndexError) as error:
        return {"status": "fail", "reason": str(error)}


def run(args):
    repo, binary, claude, out = [p.resolve() for p in (args.repo, args.agentfw, args.claude, args.output)]
    require(not out.is_relative_to(repo), "output_must_be_outside_candidate")
    require(sys.platform in ("linux", "darwin"), "native_linux_or_macos_required")
    evidence = load(repo, "measure-sou17-latency.py", "host_evidence")
    setup = load(repo, "clean-setup-acceptance.py", "host_setup")
    status = load(repo, "verify-sou18-status.py", "host_status")
    demo = load(repo, "mcp-admission-demo.py", "host_demo")
    before = evidence.snapshot(repo)
    require(not before["dirty"] and before["commit"] == args.expected_commit, "clean_exact_candidate_required")
    binary_hash, claude_hash = setup.sha(binary), setup.sha(claude)
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": "sou18-claude-outage/1", "status": "incomplete",
              "observed_at": datetime.now(timezone.utc).isoformat(), "source_before": before,
              "binary_sha256": binary_hash, "claude_sha256": claude_hash,
              "probe_sha256": setup.sha(Path(__file__)), "real_model": False,
              "environment": {"os": platform.system(), "architecture": platform.machine(),
                              "python": platform.python_version()},
              "limitations": ["Selected registry-only stdio path and trusted local fixtures.",
                              "No live provider, constrained-resource benchmark or arbitrary server containment.",
                              "Source-to-binary provenance must accompany this report."]}
    demo.REAL_BASELINE, demo.CLASSIFIER = True, "rule-baseline/python"
    try:
        with tempfile.TemporaryDirectory(prefix="sou18-claude-outage-") as temporary:
            root = Path(temporary).resolve()
            with status.private_environment(setup.private_environment(root)):
                with demo.agent_stack(binary, root / "fixture") as stack:
                    report.update(registry_sha256=stack.registry_sha256,
                                  policy_sha256=setup.sha(stack.workspace / "policy.yaml"),
                                  classifier_sha256=setup.sha(repo / "rule_baseline/rule_baseline.py"))
                    inventory = (stack.notes / "inventory.txt").read_bytes()
                    observations = {"daemon_stopped_before_send": False, "receiver_url": stack.receiver.url}

                    class OutageModel(demo.ScriptedModel):
                        def next(self, body):
                            content = super().next(body)
                            if content[0].get("id") == "toolu_demo_1" and not observations["daemon_stopped_before_send"]:
                                first = self.results.get("toolu_demo_0", {})
                                require(first.get("is_error") is False
                                        and host_text(first.get("text", "")) == "Inventory: 7 red widgets.",
                                        "read_before_outage_missing")
                                demo.stop(stack.daemon)
                                stack.daemon.wait(timeout=10)
                                observations["daemon_stopped_before_send"] = True
                                observations["ledger_at_outage"] = [json.loads(r) for r in demo.lines(stack.ledger)]
                                observations["preflight_exit"] = setup.check_probe(binary, stack.workspace, stack.env, 2)
                            return content

                    steps = [{"tool": "read_document", "args": {"name": "inventory"}},
                             {"tool": "send_http", "args": {"url": stack.receiver.url, "body": PAYLOAD}}]
                    model = OutageModel(steps)
                    project, profile = root / "project", root / "host-profile"
                    project.mkdir()
                    profile.mkdir()
                    tee = ("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600); "
                           "os.dup2(fd,2); os.execv(sys.argv[2],sys.argv[2:])")
                    config = project / "mcp.json"
                    config.write_text(json.dumps({"mcpServers": {"demo": {
                        "type": "stdio", "command": sys.executable,
                        "args": ["-I", "-c", tee, str(stack.classifications), *stack.collector],
                        "env": {"HOME": str(stack.workspace), "USERPROFILE": str(stack.workspace),
                                **demo.classifier_environment()}}}}))
                    env = setup.private_environment(profile)
                    env.update({"CLAUDE_CONFIG_DIR": str(profile / ".claude"),
                                "ANTHROPIC_API_KEY": "soup-wall-local-scripted-fixture-not-a-provider-key",
                                "ANTHROPIC_BASE_URL": model.url, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                                "DISABLE_UPDATES": "1", "DISABLE_AUTOUPDATER": "1",
                                "ENABLE_CLAUDEAI_MCP_SERVERS": "false", "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",
                                "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1", "API_TIMEOUT_MS": "10000",
                                "CLAUDE_CODE_MAX_RETRIES": "0", "HTTP_PROXY": "http://127.0.0.1:9",
                                "HTTPS_PROXY": "http://127.0.0.1:9", "NO_PROXY": "127.0.0.1,localhost,::1"})
                    try:
                        command = [
                            str(claude), "--restricted", "-p", "Run the local fixture proposals.", "--tools", "",
                            "--allowedTools", "mcp__demo__read_document,mcp__demo__send_http",
                            "--strict-mcp-config", "--mcp-config", str(config), "--no-session-persistence",
                            "--output-format", "stream-json", "--verbose", "--permission-mode", "dontAsk",
                            "--model", "claude-sonnet-4-20250514", "--system-prompt", "Execute the local fixture proposals."]
                        with subprocess.Popen(command, cwd=project, env=env, stdin=subprocess.DEVNULL,
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                              start_new_session=True) as process:
                            timed_out = False
                            try:
                                stdout, stderr = process.communicate(timeout=120)
                            except subprocess.TimeoutExpired:
                                timed_out = True
                                os.killpg(process.pid, signal.SIGKILL)
                                stdout, stderr = process.communicate(timeout=10)
                    finally:
                        model.close()
                    messages = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
                    init = next((r for r in messages if r.get("subtype") == "init"), {})
                    finals = [r for r in messages if r.get("type") == "result"]
                    observations.update(
                        host_exit=process.returncode, host_completed=len(finals) == 1 and not finals[0].get("is_error"),
                        host_timed_out=timed_out,
                        claude_version=init.get("claude_code_version"),
                        connected=[(r.get("name"), r.get("status")) for r in init.get("mcp_servers", [])] == [("demo", "connected")],
                        host_tool_uses=[block for message in messages if message.get("type") == "assistant"
                                       for block in message.get("message", {}).get("content", []) if block.get("type") == "tool_use"],
                        model_results=model.results,
                        ledger=[json.loads(r) for r in demo.lines(stack.ledger)], receiver_bodies=stack.receiver.bodies,
                        inventory_preserved=(stack.notes / "inventory.txt").read_bytes() == inventory,
                        classifications=demo.classification_evidence(stack.classifications),
                        collector_admission_unavailable="Error: MCP admission unavailable" in stack.classifications.read_text(),
                        native_decisions=[r for r in map(json.loads, demo.lines(stack.workspace / ".agentfw/audit.jsonl"))
                                          if r.get("event") in ("native_call", "native_result")])
                    report["observed"] = observations
                    report["grade"] = grade(observations)
                    # Only synthetic fixture traffic is retained; omit credentials and full host profiles.
                    for name, value in {"host-stdout.jsonl": stdout, "host-stderr.log": stderr,
                                        "collector.log": stack.classifications.read_text(),
                                        "model-requests.json": json.dumps([json.loads(r) for r in model.requests], indent=2)}.items():
                        (out / name).write_text(value)
        report["owned_profile_removed"] = not root.exists()
        report["source_after"] = evidence.snapshot(repo)
        report["stable"] = (report["source_after"] == before and setup.sha(binary) == binary_hash
                            and setup.sha(claude) == claude_hash)
        report["status"] = (report["grade"]["status"] if report["stable"] and report["owned_profile_removed"] else "incomplete")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Actual Claude outage: {report['status']}. Evidence: {out}")
    return {"pass": 0, "fail": 1, "incomplete": 2}[report["status"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--claude", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        return run(args)
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
