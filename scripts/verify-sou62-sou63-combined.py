#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Required Linux combined SOU-62/SOU-63 real-server/shared-host smoke.

Two original pinned filesystem servers run under the accepted process profile.
An explicit private proof policy asks only when MCP-derived path content is
reused in a read. The installed scenario policy remains unchanged. Actual
Claude Code uses an owned localhost scripted provider, never a live model.
The signed PostToolUse probe is an owned HTTP injection, not an assertion that
Claude automatically emitted a hook or that a model obeyed untrusted content.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import urllib.request
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sou62_combined_base", ROOT / "scripts/verify-sou62-real-mcp.py")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
require = BASE.require
TOOL = "read_text_file"
SERVER_A, SERVER_B = "source_a", "sink_b"
CROSS_PATH, HOOK_PATH = "/workspace/cross-pending.fifo", "/workspace/hook-pending.fifo"
SOURCE_TEXT = CROSS_PATH + "\n"
RULE = "combined-ask-mcp-derived-read"
PROOF_POLICY = """agent_policies:
  - name: combined-deny-destructive
    when: { action_class: destructive }
    action: deny
  - name: combined-deny-write
    when: { action_class: side_effecting }
    action: deny
  - name: combined-deny-network
    when: { action_class: network }
    action: deny
  - name: combined-deny-privilege
    when: { action_class: privilege_changing }
    action: deny
  - name: combined-deny-result-injection
    when: { detector: injection, facet: tool_result }
    action: deny
  - name: combined-ask-mcp-derived-read
    when: { taint: [mcp], action_class: read_only }
    action: ask
egress_allowlist: []
default: allow
"""
EXPECTED_CHECKS = {
    "required-positive-linux-sandbox", "clean-exact-cross-fifo-read", "clean-exact-hook-fifo-read",
    "two-original-authenticated-servers", "shared-mcp-ask-without-fifo-reader",
    "signed-hook-clean-pre-control", "signed-hook-result-to-mcp-ask", "signed-hook-pre-ask",
    "benign-continuation", "actual-claude-two-bound-servers-five-steps",
    "actual-claude-exact-useful-content", "actual-claude-two-ask-refusals",
    "actual-claude-no-unadmitted-fifo-reader", "owned-process-cleanup", "source-assets-unchanged",
}
SECRETS = []


def digest(value):
    return hashlib.sha256(BASE.INSTALL.canonical(value)).hexdigest()


def redact(text):
    for secret in SECRETS:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def write(path, value):
    BASE.write(path, json.loads(redact(json.dumps(value, ensure_ascii=False))))


def check(report, case):
    require(case in EXPECTED_CHECKS and all(row["case"] != case for row in report["checks"]), "duplicate or unknown combined check")
    report["checks"].append({"case": case, "passed": True})


def http(stack, route, value=None, proof=None):
    token = stack.native_token if route.startswith("/native/") else stack.hook_token
    headers = {"Authorization": "Bearer " + token}
    if proof:
        headers["X-Agentfw-Child-Authority"] = proof
    data = None if value is None else json.dumps(value, ensure_ascii=False).encode("utf-8")
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"http://127.0.0.1:{stack.port}" + route, data=data, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=10) as response:
        raw = response.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, "combined receipt exceeds byte limit")
    return json.loads(raw)


def mint(stack, host, server, agent, report):
    instance = http(stack, "/native/v1/instance")
    require(instance["registry_sha256"] == stack.registry_sha256, "issuer registry changed")
    result = subprocess.run([str(stack.binary), "child-authority", "mint", "--session", host, "--server", server,
        "--agent-id", agent, "--instance-id", instance["instance_id"], "--tools", TOOL, "--ttl-seconds", "300"],
        env=stack.env, capture_output=True, timeout=20, check=True)
    proof = result.stdout.decode("utf-8").strip()
    SECRETS.append(proof)
    claims = json.loads(base64.urlsafe_b64decode(proof + "=" * (-len(proof) % 4)))
    require(claims["host_session"] == host and claims["server_id"] == server and claims["agent_id"] == agent
            and claims["granted_tools"] == [TOOL] and claims["nonce"].startswith(instance["instance_id"] + "."),
            "minted scoped identity differs from the requested collector")
    report["bindings"].append({"host_session": host, "server_id": server, "agent_id": agent,
        "tools": claims["granted_tools"], "proof_sha256": hashlib.sha256(proof.encode()).hexdigest()})
    return proof


def command(stack, server):
    entry = stack.install / "package/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"
    return [str(stack.binary), "mcp", "--native-admission", "--id", server, "--", str(stack.node), str(entry), "/workspace"]


def collector_env(stack, host, proof):
    return dict(stack.env, AGENTFW_WORKSPACE=str(stack.workspace), AGENTFW_MCP_SERVER_PROFILE=str(stack.install / "profile.json"),
        AGENTFW_CLASSIFIER="rule-baseline", AGENTFW_RULE_BASELINE=str(ROOT / "rule_baseline/rule_baseline.py"),
        AGENTFW_CLASSIFIER_PYTHON=sys.executable, AGENTFW_HOST_SESSION=host, AGENTFW_CHILD_AUTHORITY=proof)


def client(stack, host, server, proof, label):
    log = (stack.root / (label + "-collector.log")).open("wb")
    stack.logs.append(log)
    result = BASE.Client(command(stack, server), collector_env(stack, host, proof), stack.workspace, log, label)
    stack.clients.append(result)
    manifest = result.initialize()
    original = json.loads((BASE.INSTALL.ASSETS / "upstream-tools-list.json").read_text(encoding="utf-8"))
    require(manifest["result"] == original["result"], "an original server manifest was replaced or changed")
    return result


class FifoProbe:
    """Independent parent writer: opening succeeds only while a real reader exists."""
    def __init__(self, path):
        self.path, self.stop = path, threading.Event()
        metadata = path.stat()
        require(stat.S_ISFIFO(metadata.st_mode), "probe must be an existing owned FIFO")
        self.record = {"path": "/workspace/" + path.name, "device": metadata.st_dev, "inode": metadata.st_ino,
            "reader_seen": False, "bytes_written": 0, "attempts": 0, "error": None, "thread_stopped": False}
        def observe():
            descriptor = None
            try:
                while not self.stop.is_set():
                    self.record["attempts"] += 1
                    try:
                        descriptor = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
                        break
                    except OSError as error:
                        if error.errno != errno.ENXIO:
                            raise
                        self.stop.wait(0.005)
                if descriptor is not None:
                    self.record["reader_seen"] = True
                    self.record["bytes_written"] = os.write(descriptor, BASE.FIFO_TEXT.encode("utf-8"))
            except Exception as error:
                self.record["error"] = type(error).__name__
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        self.thread = threading.Thread(target=observe, daemon=True)
        self.thread.start()

    def finish(self):
        self.stop.set()
        self.thread.join(timeout=3)
        self.record["thread_stopped"] = not self.thread.is_alive()
        require(self.record["thread_stopped"] and self.record["attempts"] > 0 and self.record["error"] is None,
                "independent FIFO observer did not finish cleanly")
        return self.record.copy()


def hook(stack, host, proof, event, path):
    if event == "PostToolUse":
        body = {"session_id": host, "hook_event_name": event, "tool_name": f"mcp__{SERVER_A}__{TOOL}",
                "tool_response": path + "\n"}
    else:
        body = {"session_id": host, "hook_event_name": event, "tool_name": f"mcp__{SERVER_B}__{TOOL}",
                "tool_input": {"path": path}}
    return http(stack, "/hook", body, proof)


def require_hook_ask(value):
    output = value.get("hookSpecificOutput", {})
    require(output.get("hookEventName") == "PreToolUse" and output.get("permissionDecision") == "ask"
            and ("[" + RULE + "]") in output.get("permissionDecisionReason", ""), "signed hook did not preserve exact Ask")


def require_ask(value):
    require(value.get("result", {}).get("isError") is True and RULE in json.dumps(value)
            and BASE.FIFO_TEXT not in json.dumps(value), "MCP Ask was bypassed, uncorrelated or leaked FIFO content")


def audit_rows(stack):
    path = stack.home / ".agentfw/audit.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def audit_ask(stack, host, agent, after=0):
    rows = [row for row in audit_rows(stack)[after:] if row.get("event") == "native_call"
        and row.get("host_session") == host and row.get("agent_id") == agent and row.get("tool") == TOOL
        and row.get("rule") == RULE and row.get("verdict") == "ask" and row.get("released") is False]
    require(len(rows) == 1, "missing or ambiguous native shared-history Ask witness")
    row = rows[0]
    require(row.get("taint", {}).get("origin") == "mcp" and row["taint"].get("source_name") == SERVER_A,
            "Ask did not carry authenticated source-A MCP provenance")
    return {key: row[key] for key in ("event", "host_session", "agent_id", "tool", "rule", "verdict", "released", "taint", "registry_sha256")}


def bindings_live(stack, host, agents):
    value = http(stack, "/native/v1/instance")
    require(value["registry_sha256"] == stack.registry_sha256, "live binding registry mismatch")
    rows = [row for row in value["bindings"] if row["host_session"] == host and row["agent_id"] in agents]
    require({row["agent_id"] for row in rows} == set(agents), "both authenticated collector identities must remain active")
    return rows


def clean_control(stack, report):
    host = str(uuid.uuid4())
    proof = mint(stack, host, SERVER_B, "clean-b", report)
    target = client(stack, host, SERVER_B, proof, "clean-b")
    reads = []
    for identifier, virtual in enumerate((CROSS_PATH, HOOK_PATH), 10):
        probe = FifoProbe(stack.workspace / Path(virtual).name)
        try:
            response, raw = target.exchange(BASE.call(identifier, {"path": virtual}))
            require(BASE.result_text(response) == BASE.FIFO_TEXT, "clean exact-path read did not preserve original bytes")
        finally:
            witness = probe.finish()
        require(witness["reader_seen"] and witness["bytes_written"] == len(BASE.FIFO_TEXT.encode()), "clean reader calibration failed")
        reads.append({"path": virtual, "response": response, "response_sha256": hashlib.sha256(raw).hexdigest(), "fifo": witness})
    target.close()
    report["clean_control"] = {"status": "pass", "host_session": host, "server_id": SERVER_B,
        "agent_id": "clean-b", "reads": reads, "client": target.transcript()}
    check(report, "clean-exact-cross-fifo-read")
    check(report, "clean-exact-hook-fifo-read")


def stdio_shared(stack, report):
    host = str(uuid.uuid4())
    proof_a = mint(stack, host, SERVER_A, "stdio-a", report)
    proof_b = mint(stack, host, SERVER_B, "stdio-b", report)
    source = client(stack, host, SERVER_A, proof_a, "stdio-a")
    sink = client(stack, host, SERVER_B, proof_b, "stdio-b")
    live = bindings_live(stack, host, ("stdio-a", "stdio-b"))
    cross = FifoProbe(stack.workspace / Path(CROSS_PATH).name)
    hook_probe = FifoProbe(stack.workspace / Path(HOOK_PATH).name)
    try:
        response, source_raw = source.exchange(BASE.call(10, {"path": "/workspace/source.txt"}))
        require(BASE.result_text(response) == SOURCE_TEXT and HOOK_PATH not in BASE.result_text(response), "source A content changed")
        before = len(audit_rows(stack))
        blocked, _ = sink.exchange(BASE.call(10, {"path": CROSS_PATH}))
        require_ask(blocked)
        mcp_audit = audit_ask(stack, host, "stdio-b", before)
        benign, _ = sink.exchange(BASE.call(11, {"path": "/workspace/notes.txt"}))
        require(BASE.result_text(benign) == BASE.TEXT, "shared MCP Ask broke benign continuation")
        clean_pre = hook(stack, host, proof_b, "PreToolUse", HOOK_PATH)
        require(clean_pre == {}, "hook-only target was already tainted or unsupported")
        post = hook(stack, host, proof_a, "PostToolUse", HOOK_PATH)
        require(post == {}, "PostToolUse hook contract changed")
        posts = [row for row in audit_rows(stack) if row.get("session") == host and row.get("event") == "post_tool_use"
                 and row.get("agent_id") == "stdio-a"]
        require(len(posts) == 1, "signed post-result provenance was not independently audited")
        ask_pre = hook(stack, host, proof_b, "PreToolUse", HOOK_PATH)
        require_hook_ask(ask_pre)
        before = len(audit_rows(stack))
        hook_blocked, _ = sink.exchange(BASE.call(12, {"path": HOOK_PATH}))
        require_ask(hook_blocked)
        hook_audit = audit_ask(stack, host, "stdio-b", before)
        require(hook_audit["taint"]["seq"] == posts[0]["seq"], "native Ask did not reuse the signed hook result sequence")
        final, _ = sink.exchange(BASE.call(13, {"path": "/workspace/notes.txt"}))
        require(BASE.result_text(final) == BASE.TEXT, "signed hook Ask broke benign continuation")
    finally:
        sink.close()
        source.close()
        cross_witness, hook_witness = cross.finish(), hook_probe.finish()
    require(not cross_witness["reader_seen"] and not hook_witness["reader_seen"], "an unadmitted FIFO read executed")
    report["shared_mcp"] = {"status": "pass", "host_session": host, "rule": RULE, "no_reader": True,
        "active_bindings": live, "source_response": response, "source_response_sha256": hashlib.sha256(source_raw).hexdigest(),
        "blocked_response": blocked, "native_witness": mcp_audit, "fifo": cross_witness, "benign_response": benign}
    report["shared_hook"] = {"status": "pass", "host_session": host, "rule": RULE, "no_reader": True,
        "injection_transport": "owned-signed-PostToolUse-HTTP-not-automatic-Claude-hook", "pre_before": clean_pre,
        "post_response": post, "pre_after": ask_pre, "hook_seq": posts[0]["seq"], "native_witness": hook_audit,
        "blocked_response": hook_blocked, "fifo": hook_witness, "benign_response": final}
    for case in ("two-original-authenticated-servers", "shared-mcp-ask-without-fifo-reader", "signed-hook-clean-pre-control",
                 "signed-hook-result-to-mcp-ask", "signed-hook-pre-ask", "benign-continuation"):
        check(report, case)


def presentation(observed, expected):
    require(observed.get("is_error") is False and isinstance(observed.get("original_content"), str), "actual host read failed")
    original = observed["original_content"]
    rendered = re.sub(r"\n\n<system-reminder>\n<total_tokens>[0-9]+ tokens left</total_tokens>\n</system-reminder>$", "", original)
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result, "duplicate actual-host presentation key")
            result[name] = value
        return result
    def invalid_constant(_):
        raise ValueError("invalid actual-host JSON constant")
    value = json.loads(rendered, object_pairs_hook=pairs, parse_constant=invalid_constant)
    require(type(value) is dict and set(value) == {"content"} and value["content"] == expected, "actual host did not preserve exact structured content")
    return {"representation": "structured_json", "content_sha256": hashlib.sha256(expected.encode()).hexdigest(),
        "rendered_sha256": hashlib.sha256(original.encode()).hexdigest()}


def actual_host(stack, report):
    host = str(uuid.uuid4())
    proof_a = mint(stack, host, SERVER_A, "claude-a", report)
    proof_b = mint(stack, host, SERVER_B, "claude-b", report)
    profile = stack.private / "claude-home"
    profile.mkdir(mode=0o700)
    project = profile / "project"
    project.mkdir()
    wrapper = profile / "collector.py"
    wrapper.write_text("import os,sys\nos.dup2(os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600),2)\nos.chdir(sys.argv[2])\nos.execve(sys.argv[3],sys.argv[3:],dict(os.environ))\n", encoding="utf-8")
    config = profile / "mcp.json"
    BASE.write(config, {"mcpServers": {server: {"command": sys.executable,
        "args": ["-I", str(wrapper), str(stack.root / ("claude-" + server + ".log")), str(stack.workspace), *command(stack, server)],
        "env": collector_env(stack, host, proof)} for server, proof in ((SERVER_A, proof_a), (SERVER_B, proof_b))}})
    steps = [(SERVER_A, "/workspace/source.txt"), (SERVER_B, CROSS_PATH), (SERVER_B, "/workspace/notes.txt"),
             (SERVER_B, HOOK_PATH), (SERVER_B, "/workspace/notes.txt")]
    model = BASE.DEMO.ScriptedModel([])
    hook_evidence, live_bindings = {}, []
    def next_step(body):
        required = {f"mcp__{server}__{TOOL}" for server in (SERVER_A, SERVER_B)}
        if not required.issubset({tool.get("name") for tool in body.get("tools", [])}):
            return [{"type": "text", "text": "ok"}]
        for message in body.get("messages", []):
            for block in message.get("content", []) if isinstance(message.get("content"), list) else []:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    model.results[block.get("tool_use_id")] = {"is_error": bool(block.get("is_error")), "original_content": block.get("content")}
        index = len([identifier for identifier in model.results if str(identifier).startswith("toolu_combined_")])
        if index == 0 and not live_bindings:
            live_bindings.extend(bindings_live(stack, host, ("claude-a", "claude-b")))
        if index == 3 and not hook_evidence:
            require(hook(stack, host, proof_b, "PreToolUse", HOOK_PATH) == {}, "actual-host hook target was not clean before the signed post")
            require(hook(stack, host, proof_a, "PostToolUse", HOOK_PATH) == {}, "actual-host signed post contract changed")
            after = hook(stack, host, proof_b, "PreToolUse", HOOK_PATH)
            require_hook_ask(after)
            posts = [row for row in audit_rows(stack) if row.get("session") == host and row.get("event") == "post_tool_use" and row.get("agent_id") == "claude-a"]
            require(len(posts) == 1, "actual-host signed post audit missing")
            hook_evidence.update({"pre_before": {}, "post_response": {}, "pre_after": after, "hook_seq": posts[0]["seq"],
                "injection_transport": "owned-signed-PostToolUse-HTTP-not-automatic-Claude-hook"})
        if index < len(steps):
            server, path = steps[index]
            return [{"type": "tool_use", "id": f"toolu_combined_{index}", "name": f"mcp__{server}__{TOOL}", "input": {"path": path}}]
        return [{"type": "text", "text": "Owned combined smoke finished."}]
    model.next = next_step
    env = BASE.environment(profile)
    env.update(ANTHROPIC_API_KEY="combined-owned-scripted-provider-only", ANTHROPIC_BASE_URL=model.url,
        CLAUDE_CONFIG_DIR=str(profile / ".claude"), CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
        CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL="1", DISABLE_UPDATES="1",
        HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9", NO_PROXY="127.0.0.1,localhost")
    probes = [FifoProbe(stack.workspace / Path(path).name) for path in (CROSS_PATH, HOOK_PATH)]
    process = witness = None
    try:
        process = subprocess.Popen([str(stack.claude), "--restricted", "-p", "Perform the owned combined MCP steps.", "--tools", "",
            "--allowedTools", ",".join(f"mcp__{server}__{TOOL}" for server in (SERVER_A, SERVER_B)),
            "--strict-mcp-config", "--mcp-config", str(config), "--session-id", host, "--no-session-persistence",
            "--output-format", "stream-json", "--verbose", "--permission-mode", "dontAsk", "--model", "claude-sonnet-4-20250514"],
            cwd=project, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        witness = BASE.ProcessWitness(process.pid)
        stdout, stderr = process.communicate(timeout=150)
        cleanup = witness.finish()
        messages = []
        for raw in stdout.splitlines():
            try:
                messages.append(json.loads(raw))
            except ValueError:
                pass
        write(stack.root / "claude-owned-output.json", {"messages": messages, "stderr": stderr.decode("utf-8", "replace")})
        expected = [{"type": "tool_use", "id": f"toolu_combined_{index}", "name": f"mcp__{server}__{TOOL}", "input": {"path": path}}
                    for index, (server, path) in enumerate(steps)]
        uses = [block for message in messages if message.get("type") == "assistant" for block in message.get("message", {}).get("content", []) if block.get("type") == "tool_use"]
        initial = [message for message in messages if message.get("type") == "system" and message.get("subtype") == "init"]
        finals = [message for message in messages if message.get("type") == "result"]
        version = subprocess.check_output([str(stack.claude), "--version"], env=env, text=True, timeout=15).strip()
        report["actual_claude_host"] = {"status": "incomplete", "host_session": host, "exit_code": process.returncode,
            "claude_version": version, "claude_sha256": BASE.sha(stack.claude), "real_host_executed": True,
            "scripted_owned_provider": True, "live_model_efficacy_measured": False, "process_cleanup": cleanup,
            "host_tool_uses": uses, "model_results": model.results, "initialization": initial,
            "active_bindings": live_bindings, "signed_hook": hook_evidence,
            "provider_requests_sha256": hashlib.sha256(b"".join(model.requests)).hexdigest(),
            "provider_request_count": len(model.requests), "raw_output_sha256": hashlib.sha256(stdout).hexdigest()}
        require(process.returncode == 0 and len(finals) == 1 and not finals[0].get("is_error"), "actual Claude did not finish")
        require(len(initial) == 1 and initial[0].get("session_id") == host, "actual Claude session does not match signed host UUID")
        connected = {row["name"] for row in initial[0].get("mcp_servers", []) if row.get("status") == "connected"}
        require({SERVER_A, SERVER_B}.issubset(connected) and uses == expected, "actual Claude did not connect both original servers and propose exact five steps")
        reads = {str(index): presentation(model.results[f"toolu_combined_{index}"], SOURCE_TEXT if index == 0 else BASE.TEXT) for index in (0, 2, 4)}
        for index in (1, 3):
            result = model.results[f"toolu_combined_{index}"]
            require(result["is_error"] is True and isinstance(result["original_content"], str) and RULE in result["original_content"]
                    and BASE.FIFO_TEXT not in result["original_content"], "actual Claude released an unadmitted read")
        asks = [row for row in audit_rows(stack) if row.get("event") == "native_call" and row.get("host_session") == host
                and row.get("agent_id") == "claude-b" and row.get("rule") == RULE and row.get("verdict") == "ask" and row.get("released") is False]
        require(len(asks) == 2 and all(row.get("taint", {}).get("origin") == "mcp" and row["taint"].get("source_name") == SERVER_A for row in asks), "actual host shared provenance Ask witnesses missing")
        require(hook_evidence and asks[1]["taint"]["seq"] == hook_evidence["hook_seq"], "actual host hook-only provenance did not reach B")
        require(version == "2.1.251 (Claude Code)", "actual host version differs from pinned runtime")
        report["actual_claude_host"].update(status="pass", read_presentations=reads,
            native_asks=[{key: row[key] for key in ("event", "host_session", "agent_id", "tool", "rule", "verdict", "released", "taint", "registry_sha256")} for row in asks])
        require(cleanup["all_stopped"] and cleanup["descendant_count"] >= 2, "actual-host descendants remain alive")
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, 9)
            process.communicate(timeout=10)
        if witness is not None:
            witness.finish()
        model.close()
        observations = [probe.finish() for probe in probes]
    require(all(not row["reader_seen"] for row in observations), "actual-host forbidden FIFO read executed")
    report["actual_claude_host"]["fifo_probes"] = observations
    report["actual_claude_host"]["no_reader"] = True
    for case in ("actual-claude-two-bound-servers-five-steps", "actual-claude-exact-useful-content",
                 "actual-claude-two-ask-refusals", "actual-claude-no-unadmitted-fifo-reader"):
        check(report, case)


def positive_sandbox(stack, tests, report):
    try:
        result = subprocess.run([str(tests), "selected_server_sandbox_isolates_real_node", "--ignored", "--nocapture"],
            env=dict(stack.env, SOU62_SANDBOX_TEST_PROFILE=str(stack.install / "profile.json")), capture_output=True, timeout=90)
    except subprocess.TimeoutExpired as error:
        raw = (error.stdout or b"") + (error.stderr or b"")
        (stack.root / "sandbox-positive.log").write_bytes(raw)
        print(json.dumps({"event": "combined_required_sandbox_timeout", "timeout_seconds": 90,
            "owned_probe_output_tail": redact(raw[-6000:].decode("utf-8", "replace"))}), flush=True)
        raise
    raw = result.stdout + result.stderr
    (stack.root / "sandbox-positive.log").write_bytes(raw)
    witnesses = {name: (name + "=true").encode() in raw for name in BASE.SANDBOX_WITNESSES}
    positive = result.returncode == 0 and b"SOU62_SANDBOX_POSITIVE" in raw and all(witnesses.values()) and re.search(rb"1 passed; 0 failed", result.stdout)
    if not positive:
        print(json.dumps({"event": "combined_required_sandbox_failure", "exit_code": result.returncode,
            "witnesses": witnesses, "owned_probe_output_tail": redact(raw[-6000:].decode("utf-8", "replace"))}), flush=True)
    require(positive, "required combined positive sandbox test failed")
    report["required_positive_sandbox"] = {"status": "pass", "exit_code": 0, "witnesses": witnesses, "log_sha256": BASE.sha(stack.root / "sandbox-positive.log")}
    check(report, "required-positive-linux-sandbox")


def validate_fifo(record, reader, calibration=None):
    require(record["reader_seen"] is reader and record["attempts"] > 0 and record["thread_stopped"] is True
            and record["error"] is None, "FIFO witness missing, failed or still running")
    require(record["bytes_written"] == (len(BASE.FIFO_TEXT.encode()) if reader else 0), "FIFO byte witness differs")
    if calibration is not None:
        require(all(record[key] == calibration[key] for key in ("path", "device", "inode")), "negative FIFO probe differs from calibrated exact target")


def grade(report):
    require(report["format"] == "sou62-sou63-combined/1" and report["skipped"] == 0 and report["failed"] == 0,
            "combined proof cannot skip or fail a boundary")
    require(report["source_before"] == report["source_after"] and report["source_before"]["dirty"] is False, "combined source changed")
    require(report["proof_policy_sha256"] == hashlib.sha256(PROOF_POLICY.encode()).hexdigest(), "combined proof policy differs")
    require({row["case"] for row in report["checks"]} == EXPECTED_CHECKS and len(report["checks"]) == len(EXPECTED_CHECKS)
            and all(row["passed"] is True for row in report["checks"]), "combined check inventory incomplete")
    positive = report["required_positive_sandbox"]
    require(positive["status"] == "pass" and positive["exit_code"] == 0 and all(positive["witnesses"][name] is True for name in BASE.SANDBOX_WITNESSES), "required positive sandbox proof missing")
    for name in ("binary_sha256", "claude_sha256", "sandbox_test_binary_sha256", "driver_sha256"):
        require(re.fullmatch(r"[a-f0-9]{64}", report[name]) is not None, "missing exact candidate identity")
    installed = report["installed_profile"]
    upstream = json.loads((BASE.INSTALL.ASSETS / "upstream-identity.json").read_text(encoding="utf-8"))
    require(installed["server_package"] == "@modelcontextprotocol/server-filesystem@2026.8.31"
            and installed["upstream_identity"] == upstream
            and installed["upstream_identity_sha256"] == BASE.sha(BASE.INSTALL.ASSETS / "upstream-identity.json")
            and installed["package_lock_sha256"] == upstream["packageLockSha256"]
            and installed["profile"]["format"] == BASE.PROFILE
            and installed["node_version"] == BASE.INSTALL.NODE_VERSION,
            "original selected package/runtime identity differs")
    registry = installed["registry_sha256"]
    require(re.fullmatch(r"[a-f0-9]{64}", registry) is not None, "registry identity missing")
    clean = report["clean_control"]
    require(clean["status"] == "pass" and clean["server_id"] == SERVER_B and clean["agent_id"] == "clean-b"
            and len(clean["reads"]) == 2 and {row["path"] for row in clean["reads"]} == {CROSS_PATH, HOOK_PATH}, "clean exact-target controls missing")
    calibrated = {row["path"]: row["fifo"] for row in clean["reads"]}
    for index, row in enumerate(clean["reads"], 10):
        require(type(row["response"]["id"]) is int and row["response"]["id"] == index
                and BASE.result_text(row["response"]) == BASE.FIFO_TEXT and row["fifo"]["path"] == row["path"],
                "clean exact-path read was not useful or correlated")
        validate_fifo(row["fifo"], True)
    def native_witness(row, session, agent):
        require(row["event"] == "native_call" and row["host_session"] == session and row["agent_id"] == agent
                and row["tool"] == TOOL and row["verdict"] == "ask" and row["released"] is False and row["rule"] == RULE
                and row["taint"]["origin"] == "mcp" and row["taint"]["source_name"] == SERVER_A
                and type(row["taint"]["seq"]) is int and row["taint"]["seq"] > 0 and row["registry_sha256"] == registry,
                "shared refusal was not attributed to the authenticated source-A registry")
    for name, path, blocked_id, benign_id in (("shared_mcp", CROSS_PATH, 10, 11), ("shared_hook", HOOK_PATH, 12, 13)):
        proof = report[name]
        require(proof["status"] == "pass" and proof["rule"] == RULE and proof["no_reader"] is True, "shared-history proof missing")
        require(proof["host_session"] != clean["host_session"], "clean control reused the tainted host")
        require_ask(proof["blocked_response"])
        require(type(proof["blocked_response"]["id"]) is int and proof["blocked_response"]["id"] == blocked_id
                and type(proof["benign_response"]["id"]) is int and proof["benign_response"]["id"] == benign_id
                and BASE.result_text(proof["benign_response"]) == BASE.TEXT, "shared-state refusal broke useful correlation/continuation")
        validate_fifo(proof["fifo"], False, calibrated[path])
        native_witness(proof["native_witness"], proof["host_session"], "stdio-b")
    mcp, signed = report["shared_mcp"], report["shared_hook"]
    require(BASE.result_text(mcp["source_response"]) == SOURCE_TEXT and mcp["source_response"]["id"] == 10
            and HOOK_PATH not in SOURCE_TEXT, "source A did not introduce only the cross-server path")
    require(mcp["host_session"] == signed["host_session"] and signed["pre_before"] == {} and signed["post_response"] == {}
            and signed["injection_transport"] == "owned-signed-PostToolUse-HTTP-not-automatic-Claude-hook", "signed hook control missing")
    require_hook_ask(signed["pre_after"])
    require(signed["native_witness"]["taint"]["seq"] == signed["hook_seq"]
            and signed["hook_seq"] != mcp["native_witness"]["taint"]["seq"], "hook-specific sequence attribution missing")
    host = report["actual_claude_host"]
    require(host["status"] == "pass" and host["exit_code"] == 0 and host["real_host_executed"] is True
            and host["scripted_owned_provider"] is True and host["live_model_efficacy_measured"] is False
            and host["claude_version"] == "2.1.251 (Claude Code)" and host["claude_sha256"] == report["claude_sha256"], "actual pinned Claude host proof missing")
    require(host["host_session"] not in {clean["host_session"], mcp["host_session"]}, "actual host did not use an isolated fresh bound UUID")
    require(len(host["initialization"]) == 1 and host["initialization"][0]["session_id"] == host["host_session"]
            and {SERVER_A, SERVER_B}.issubset({row["name"] for row in host["initialization"][0]["mcp_servers"] if row["status"] == "connected"}),
            "actual host session/connected-server receipt missing")
    expected_steps = [(SERVER_A, "/workspace/source.txt"), (SERVER_B, CROSS_PATH), (SERVER_B, "/workspace/notes.txt"), (SERVER_B, HOOK_PATH), (SERVER_B, "/workspace/notes.txt")]
    require(host["host_tool_uses"] == [{"type": "tool_use", "id": f"toolu_combined_{index}", "name": f"mcp__{server}__{TOOL}", "input": {"path": path}} for index, (server, path) in enumerate(expected_steps)], "actual host tool sequence changed")
    require(set(host["model_results"]) == {f"toolu_combined_{index}" for index in range(5)}
            and host["provider_request_count"] >= 6, "actual provider results incomplete")
    for index in (0, 2, 4):
        require(presentation(host["model_results"][f"toolu_combined_{index}"], SOURCE_TEXT if index == 0 else BASE.TEXT) == host["read_presentations"][str(index)], "actual host useful bytes changed")
    for index in (1, 3):
        value = host["model_results"][f"toolu_combined_{index}"]
        require(value["is_error"] is True and type(value["original_content"]) is str and RULE in value["original_content"]
                and BASE.FIFO_TEXT not in value["original_content"], "actual host Ask bypassed")
    require(host["no_reader"] is True and len(host["fifo_probes"]) == 2
            and {row["path"] for row in host["fifo_probes"]} == {CROSS_PATH, HOOK_PATH}, "actual host exact no-reader witnesses missing")
    for row in host["fifo_probes"]:
        validate_fifo(row, False, calibrated[row["path"]])
    require(host["signed_hook"]["pre_before"] == {} and host["signed_hook"]["post_response"] == {}
            and host["signed_hook"]["injection_transport"] == signed["injection_transport"], "actual host hook clean control missing")
    require_hook_ask(host["signed_hook"]["pre_after"])
    require(len(host["native_asks"]) == 2 and host["native_asks"][1]["taint"]["seq"] == host["signed_hook"]["hook_seq"]
            and host["native_asks"][0]["taint"]["seq"] != host["signed_hook"]["hook_seq"], "actual host signed-hook provenance missing")
    for row in host["native_asks"]:
        native_witness(row, host["host_session"], "claude-b")
    expected_bindings = {(clean["host_session"], SERVER_B, "clean-b"), (mcp["host_session"], SERVER_A, "stdio-a"),
        (mcp["host_session"], SERVER_B, "stdio-b"), (host["host_session"], SERVER_A, "claude-a"), (host["host_session"], SERVER_B, "claude-b")}
    bindings = report["bindings"]
    require(len(bindings) == 5 and {(row["host_session"], row["server_id"], row["agent_id"]) for row in bindings} == expected_bindings
            and all(set(row) == {"host_session", "server_id", "agent_id", "tools", "proof_sha256"}
                    and row["tools"] == [TOOL] and re.fullmatch(r"[a-f0-9]{64}", row["proof_sha256"]) for row in bindings),
            "scoped identities were not independent minimal tool grants")
    for proof, agents in ((mcp, {"stdio-a", "stdio-b"}), (host, {"claude-a", "claude-b"})):
        live = proof["active_bindings"]
        require(len(live) == 2 and {row["agent_id"] for row in live} == agents
                and all(row["host_session"] == proof["host_session"] and re.fullmatch(r"[a-f0-9]{64}", row["binding_sha256"]) for row in live)
                and len({row["binding_sha256"] for row in live}) == 2, "two live independently bound original collectors missing")
    audit = report["owned_audit"]
    require(digest(audit) == report["owned_audit_sha256"], "owned audit bytes changed")
    starts = report["authenticated_starts"]
    require(len(starts) == 5 and {(row["host_session"], row["agent_id"]) for row in starts} == {(host, agent) for host, _, agent in expected_bindings}
            and all(row["event"] == "native_session_start" and row["registry_sha256"] == registry
                    and row["verdict"] == "allow" and row["released"] is True for row in starts), "authenticated start audit receipts missing")
    summaries = [mcp["native_witness"], signed["native_witness"], *host["native_asks"], *starts]
    for summary in summaries:
        require(any(all(row.get(key) == value for key, value in summary.items()) for row in audit),
                "authenticated receipt absent from original audit")
    for session, agent in ((mcp["host_session"], "stdio-a"), (host["host_session"], "claude-a")):
        released = [index for index, row in enumerate(audit) if row.get("event") == "native_result" and row.get("host_session") == session
            and row.get("agent_id") == agent and row.get("tool") == TOOL and row.get("verdict") == "allow"
            and row.get("released") is True and row.get("delivery") == "mcp_host" and row.get("registry_sha256") == registry]
        asks = [index for index, row in enumerate(audit) if row.get("event") == "native_call" and row.get("host_session") == session
            and row.get("rule") == RULE and row.get("verdict") == "ask"]
        require(len(released) == 1 and len(asks) == 2 and released[0] < asks[0], "original source result was not admitted before shared refusals")
    for proof, agent in ((signed, "stdio-a"), (host["signed_hook"], "claude-a")):
        session = mcp["host_session"] if agent == "stdio-a" else host["host_session"]
        posts = [row for row in audit if row.get("event") == "post_tool_use" and row.get("session") == session
            and row.get("agent_id") == agent and row.get("seq") == proof["hook_seq"]]
        require(len(posts) == 1 and posts[0]["verdict"] == "allow", "signed hook source receipt absent from original audit")
    cleanup = report["cleanup"]
    require(cleanup["all_stopped"] is True and cleanup["daemon_stopped"] is True and cleanup["private_profile_removed"] is True
            and cleanup["daemon_process_cleanup"]["all_stopped"] is True and len(cleanup["clients"]) == 3
            and all(row["exit_code"] == 0 and row["forced_cleanup"] is False and row["process_cleanup"]["all_stopped"] is True
                    and row["process_cleanup"]["descendant_count"] > 0 for row in cleanup["clients"])
            and host["process_cleanup"]["all_stopped"] is True and host["process_cleanup"]["descendant_count"] >= 2,
            "owned process cleanup is incomplete")
    original_manifest = json.loads((BASE.INSTALL.ASSETS / "upstream-tools-list.json").read_text(encoding="utf-8"))["result"]
    for transcript in cleanup["clients"]:
        replies = [json.loads(raw) for raw in transcript["received"]]
        discovery = [row for row in replies if row.get("id") == 2]
        require(len(discovery) == 1 and discovery[0]["result"] == original_manifest, "original advertised server discovery changed")
        for field in ("sent", "received"):
            require(hashlib.sha256("".join(transcript[field]).encode()).hexdigest() == transcript[field + "_sha256"], "original transcript bytes changed")
    require(report["installed_profile_unchanged"] is True and report["runtime_unchanged"] is True and report["workspace_unchanged"] is True, "combined run changed reviewed assets")


def run(args):
    output, binary, node, bwrap, claude, tests = [path.resolve() for path in (args.output, args.agentfw, args.node, args.bwrap, args.claude, args.sandbox_test_binary)]
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "combined positive acceptance requires Linux x86-64")
    require(all(path.is_file() for path in (binary, node, bwrap, claude, tests)), "all exact runtime and sandbox test prerequisites are required")
    require(not output.exists() and not output.is_relative_to(ROOT), "output must be a new directory outside the candidate")
    before = BASE.source()
    require(before["commit"] == args.expected_commit and not before["dirty"], "clean exact combined candidate required")
    output.mkdir(mode=0o700, parents=True)
    report = {"format": "sou62-sou63-combined/1", "status": "incomplete", "observed_at": datetime.now(timezone.utc).isoformat(),
        "source_before": before, "binary_sha256": BASE.sha(binary), "claude_sha256": BASE.sha(claude), "sandbox_test_binary_sha256": BASE.sha(tests),
        "driver_sha256": BASE.sha(Path(__file__)), "proof_policy_sha256": hashlib.sha256(PROOF_POLICY.encode()).hexdigest(),
        "checks": [], "bindings": [], "passed": 0, "failed": 0, "skipped": 0, "live_model_efficacy_measured": False}
    stack = SimpleNamespace(root=output, binary=binary, node=node, claude=claude, clients=[], logs=[])
    daemon = daemon_witness = None
    try:
        with tempfile.TemporaryDirectory(prefix="sou62-sou63-owned-") as temporary:
            stack.private = private = Path(temporary)
            stack.workspace = private / "workspace"
            stack.workspace.mkdir(mode=0o700)
            (stack.workspace / "source.txt").write_text(SOURCE_TEXT, encoding="utf-8")
            (stack.workspace / "notes.txt").write_text(BASE.TEXT, encoding="utf-8")
            for path in (CROSS_PATH, HOOK_PATH):
                os.mkfifo(stack.workspace / Path(path).name, 0o600)
            baseline = BASE.snapshot(stack.workspace)
            stack.install = private / "installed-profile"
            BASE.INSTALL.install(stack.install, stack.workspace, node, bwrap, args.npm)
            report["installed_profile"] = json.loads((stack.install / "installation.json").read_text(encoding="utf-8"))
            policy = private / "combined-proof.yaml"
            policy.write_text(PROOF_POLICY, encoding="utf-8")
            policy.chmod(0o600)
            stack.home = private / "home"
            stack.home.mkdir(mode=0o700)
            stack.env = BASE.environment(stack.home)
            subprocess.run([str(binary), "install"], env=stack.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, check=True, timeout=30)
            stack.port = BASE.DEMO.free_port()
            stack.registry_sha256 = BASE.sha(stack.install / "registry.json")
            BASE.write(stack.home / ".agentfw/config.yaml", {"port": stack.port, "enforce": True, "max_record_bytes": 1048576,
                "policy": str(policy), "native": {"registry_path": str(stack.install / "registry.json"), "registry_sha256": stack.registry_sha256}})
            positive_sandbox(stack, tests, report)
            log = (output / "daemon.log").open("wb")
            stack.logs.append(log)
            daemon = subprocess.Popen([str(binary), "serve"], env=stack.env, stdout=log, stderr=log)
            daemon_witness = BASE.ProcessWitness(daemon.pid)
            try:
                require(BASE.DEMO.wait_healthy(stack.port, daemon), "owned combined enforcing daemon did not start")
                stack.native_token = (stack.home / ".agentfw/native-token").read_text().strip()
                stack.hook_token = (stack.home / ".agentfw/token").read_text().strip()
                SECRETS.extend((stack.native_token, stack.hook_token))
                clean_control(stack, report)
                stdio_shared(stack, report)
                actual_host(stack, report)
                report["authenticated_starts"] = [{key: row[key] for key in ("event", "host_session", "agent_id", "registry_sha256", "verdict", "released")}
                    for row in audit_rows(stack) if row.get("event") == "native_session_start" and row.get("host_session")]
                report["workspace_unchanged"] = BASE.snapshot(stack.workspace) == baseline
                installed = report["installed_profile"]
                report["installed_profile_unchanged"] = (BASE.sha(stack.install / "profile.json") == installed["profile_sha256"]
                    and BASE.sha(stack.install / "registry.json") == installed["registry_sha256"]
                    and BASE.sha(stack.install / "policy.yaml") == installed["policy_sha256"]
                    and BASE.INSTALL.tree_sha(stack.install / "package") == installed["profile"]["packageTreeSha256"]
                    and BASE.sha(policy) == report["proof_policy_sha256"]
                    and all(BASE.sha(stack.install / notice["path"]) == notice["sha256"] for notice in installed["upstream_notices"]))
                report["runtime_unchanged"] = (BASE.sha(binary) == report["binary_sha256"] and BASE.sha(claude) == report["claude_sha256"]
                    and BASE.sha(node) == installed["profile"]["runtimeSha256"] and BASE.sha(bwrap) == installed["profile"]["bwrapSha256"]
                    and BASE.sha(tests) == report["sandbox_test_binary_sha256"])
            finally:
                for owned in reversed(stack.clients):
                    owned.close()
                BASE.DEMO.stop(daemon)
                daemon.wait(timeout=10)
                cleanup = {"clients": [owned.transcript() for owned in stack.clients], "daemon_stopped": daemon.poll() is not None,
                    "daemon_process_cleanup": daemon_witness.finish()}
                cleanup["all_stopped"] = cleanup["daemon_process_cleanup"]["all_stopped"] and all(row["process_cleanup"]["all_stopped"] for row in cleanup["clients"])
                report["cleanup"] = cleanup
                owned_audit = audit_rows(stack)
                write(output / "owned-native-hook-audit.json", owned_audit)
                report["owned_audit"] = owned_audit
                report["owned_audit_sha256"] = digest(owned_audit)
                for log in stack.logs:
                    log.close()
        report["cleanup"]["private_profile_removed"] = not private.exists()
        report["source_after"] = BASE.source()
        check(report, "owned-process-cleanup")
        check(report, "source-assets-unchanged")
        grade(report)
        report["status"], report["passed"] = "pass", len(report["checks"])
    except Exception as error:
        report["status"], report["failed"], report["error"] = "fail", 1, redact(type(error).__name__ + ": " + str(error))[:2000]
        diagnostic = {"event": "combined_smoke_failure", "error": report["error"], "checks_completed": len(report["checks"]),
            "actual_host": {key: report.get("actual_claude_host", {}).get(key) for key in ("status", "exit_code", "claude_version", "host_tool_uses")},
            "owned_model_results": redact(json.dumps(report.get("actual_claude_host", {}).get("model_results", {}), ensure_ascii=False))[:6000],
            "owned_log_tails": {path.name: redact(path.read_text(encoding="utf-8", errors="replace")[-1800:])
                for path in sorted(output.glob("*.log"))[-6:]}}
        print(redact(json.dumps(diagnostic, ensure_ascii=False)), flush=True)
    finally:
        if daemon is not None:
            BASE.DEMO.stop(daemon)
        for log in stack.logs:
            if not log.closed:
                log.close()
        write(output / "report.json", report)
    print(json.dumps({"status": report["status"], "passed": report["passed"], "failed": report["failed"], "skipped": 0,
        "error": report.get("error"), "report": str(output / "report.json")}))
    return 0 if report["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    for name in ("agentfw", "node", "bwrap", "claude", "sandbox-test-binary", "npm", "output"):
        parser.add_argument("--" + name, type=Path, required=name != "npm", default=Path(shutil.which("npm") or "npm") if name == "npm" else None)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False, "required_positive_sandbox": True, "actual_claude_host_required": True,
            "original_servers": 2, "shared_authenticated_session": True, "scripted_owned_provider": True, "live_model": False}))
        return 0
    try:
        return run(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "fail", "failed": 1, "skipped": 0, "error": redact(str(error))[:2000]}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
