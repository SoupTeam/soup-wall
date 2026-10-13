#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-30: one-command disposable Console + real agentfw serve rollout witness.

No external IdP/provider/model and no real permissions are modified.
Runs a fully isolated SQLite Console and agentfw home on random loopback ports.
The actual /hook permissionDecision and in-process /health active revision
are captured before/after activation and a NEW monotonic signed rollback.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
OUTCOME = ROOT / "target" / "sou30-managed-rollout-evidence.json"


def port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def request(method: str, url: str, payload=None, headers=None, timeout=3):
    data = None if payload is None else json.dumps(payload).encode()
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as res:
        body = res.read(120_000)
        return res.status, json.loads(body) if body else None


def wait_for(label, predicate, timeout=45):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            candidate = predicate()
            if candidate is not None:
                return candidate
        except (ConnectionError, OSError, urllib.error.HTTPError, ValueError) as exc:
            last = str(exc)
        time.sleep(0.3)
    raise AssertionError(f"{label} timed out; last error={last}")


def proc(stack, cmd, cwd, env, log_path):
    logfile = stack.enter_context(open(log_path, "wb"))
    process = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=logfile, stderr=subprocess.STDOUT)
    stack.callback(lambda p=process: (p.terminate(), p.wait(timeout=8)) if p.poll() is None else None)
    return process


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-build", action="store_true", help="Reuse target/debug binaries")
    parser.add_argument("--output", type=Path, default=OUTCOME)
    args = parser.parse_args()

    if not args.no_build:
        subprocess.run(["cargo", "build", "--locked", "-p", "llm-firewall", "-p", "agentfw"],
                       cwd=ROOT, check=True)
    console_binary = ROOT / "target" / "debug" / ("llm-firewall.exe" if os.name == "nt" else "llm-firewall")
    agent_binary = ROOT / "target" / "debug" / ("agentfw.exe" if os.name == "nt" else "agentfw")
    assert console_binary.is_file() and agent_binary.is_file(), "missing built test binaries"

    with tempfile.TemporaryDirectory(prefix="sou30-") as folder, ExitStack() as stack:
        temp = Path(folder)
        console_dir = temp / "console"
        home = temp / "home"
        (home / ".agentfw").mkdir(parents=True)
        console_dir.mkdir()
        cp, ap = port(), port()
        (console_dir / "firewall.yaml").write_text(
            f'bind: "127.0.0.1:{cp}"\n'
            f'tenant_store:\n  enabled: true\n  backend: sqlite\n'
            f'  database_path: "{temp / "managed.sqlite"}"\n'
        )
        (home / ".agentfw" / "config.yaml").write_text(
            f"bind: 127.0.0.1\nport: {ap}\nenforce: true\n"
        )

        admin = secrets.token_urlsafe(32)
        seed = secrets.token_hex(32)
        common_env = os.environ.copy()
        common_env.pop("SOUP_MANAGED_AGENT_CONSOLE", None)
        common_env.update({
            "LLM_FW_ADMIN_TOKEN": admin,
            "SOUP_AGENT_POLICY_SEED_HEX": seed,
            "SOUP_AGENT_POLICY_KEY_ID": "demo-issuer-1",
            "OPENAI_API_KEY": "",
            "LLM_FW_OPENAI_API_KEY": "",
        })
        cons = proc(stack, [str(console_binary)], console_dir, common_env, temp / "console.log")
        console = f"http://127.0.0.1:{cp}"
        agent = f"http://127.0.0.1:{ap}"
        def console_ready():
            if cons.poll() is not None:
                raise RuntimeError(f"Console exited {cons.returncode}")
            return True if request("GET", console + "/healthz")[0] == 200 else None
        wait_for("Console readiness", console_ready)
        admin_headers = {"x-llm-firewall-admin-token": "Bearer " + admin}
        _, tenant = request("POST", console + "/admin/v1/tenants",
                            {"name": "sou30-disposable"}, admin_headers)
        tenant_id = tenant["id"]
        base = f"{console}/admin/v1/tenants/{tenant_id}/agents/agent-demo"
        _, enrollment = request("POST", console + f"/admin/v1/tenants/{tenant_id}/agents",
                                {"agent_id": "agent-demo"}, admin_headers)
        _, issuer = request("GET", console + "/admin/v1/managed-issuer", headers=admin_headers)
        assert len(issuer["public_key_hex"]) == 64
        agent_token = enrollment["token"]
        try:
            request("POST", console + f"/admin/v1/tenants/{tenant_id}/agents",
                    {"agent_id": "second"}, {"Authorization": "Bearer " + agent_token})
            raise AssertionError("Agent credential unexpectedly gained admin privileges")
        except urllib.error.HTTPError as ex:
            assert ex.code == 401, ex.code

        for revision, value in [("v-deny", "deny"), ("v-allow", "allow")]:
            request("POST", base + "/revisions",
                    {"revision": revision, "policy_yaml": f"default: {value}\n"}, admin_headers)
            request("POST", base + f"/revisions/{revision}/approve", {}, admin_headers)
        _, first = request("POST", base + "/revisions/v-deny/deploy",
                           {"rollback": False}, admin_headers)
        assert first["deployment_sequence"] == 1

        agent_env = os.environ.copy()
        for name in ("SOUP_AGENT_POLICY_SEED_HEX", "LLM_FW_ADMIN_TOKEN"):
            agent_env.pop(name, None)
        agent_env.update({
            "HOME": str(home),
            "SOUP_MANAGED_AGENT_CONSOLE": console + "/",
            "SOUP_MANAGED_AGENT_TOKEN": agent_token,
            "SOUP_MANAGED_AGENT_TENANT": tenant_id,
            "SOUP_MANAGED_AGENT_ID": "agent-demo",
            "SOUP_MANAGED_AGENT_KEY_ID": "demo-issuer-1",
            "SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX": issuer["public_key_hex"],
        })
        local = proc(stack, [str(agent_binary), "serve"], temp, agent_env, temp / "agent.log")
        def active(expected):
            def check():
                if local.poll() is not None:
                    raise RuntimeError(f"Agent exited {local.returncode}")
                _, health = request("GET", agent + "/health")
                item = health.get("managed_policy")
                return item if item and item["deployment_sequence"] == expected else None
            return wait_for(f"Agent applied sequence {expected}", check)
        hook_token = wait_for("hook token created",
            lambda: (home / ".agentfw" / "token").read_text().strip()
            if (home / ".agentfw" / "token").exists() else None)
        def verdict(number):
            _, data = request("POST", agent + "/hook", {
                "session_id": f"sou30-evidence-{number}",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo hello"},
            }, {"Authorization": "Bearer " + hook_token})
            return data.get("hookSpecificOutput", {}).get("permissionDecision", "unknown")
        def applied(seq):
            def check():
                _, items = request("GET", base + "/deployments", headers=admin_headers)
                return (items[0] if items and items[0]["deployment_sequence"] == seq
                        and items[0]["status"] == "applied" else None)
            return wait_for(f"Console applied ack {seq}", check)

        first_runtime = active(1)
        first_ack = applied(1)
        first_verdict = verdict(1)
        assert first_verdict == "deny", f"expected deny, got {first_verdict}"
        _, second = request("POST", base + "/revisions/v-allow/deploy",
                            {"rollback": False}, admin_headers)
        assert second["deployment_sequence"] == 2
        second_runtime = active(2)
        second_ack = applied(2)
        second_verdict = verdict(2)
        assert second_verdict == "defer", f"expected defer, got {second_verdict}"
        _, third = request("POST", base + "/revisions/v-deny/deploy",
                           {"rollback": True}, admin_headers)
        assert third["deployment_sequence"] == 3
        third_runtime = active(3)
        third_ack = applied(3)
        third_verdict = verdict(3)
        assert third_verdict == "deny", f"expected deny rollback, got {third_verdict}"
        assert first_runtime["policy_sha256"] == third_runtime["policy_sha256"]
        assert first_runtime["revision"] == third_runtime["revision"]
        assert second_runtime["policy_sha256"] != first_runtime["policy_sha256"]
        assert all(x["policy_sha256"] for x in [first_ack, second_ack, third_ack])

        _, other = request("POST", console + "/admin/v1/tenants",
                            {"name": "sou30-unrelated"}, admin_headers)
        try:
            request("POST", f'{console}/admin/v1/tenants/{other["id"]}/agents/agent-demo/revoke',
                    {}, admin_headers)
            raise AssertionError("cross-tenant revoke unexpectedly succeeded")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404, exc.code

        report = {
            "scope": "disposable-real-agentfw-and-sqlite-console",
            "no_external_provider": True,
            "checks": {
                "agent_admin_isolation": True,
                "cross_tenant_revocation_refused": True,
                "authenticated_runtime_applied": True,
                "rollback_sequence_increased": True,
                "policy_payload_restored": True,
            },
            "deployments": [
                {"sequence": 1, "revision": first_runtime["revision"],
                 "sha256": first_runtime["policy_sha256"], "decision": first_verdict,
                 "ack": first_ack["status"]},
                {"sequence": 2, "revision": second_runtime["revision"],
                 "sha256": second_runtime["policy_sha256"], "decision": second_verdict,
                 "ack": second_ack["status"]},
                {"sequence": 3, "revision": third_runtime["revision"],
                 "sha256": third_runtime["policy_sha256"], "decision": third_verdict,
                 "ack": third_ack["status"]},
            ],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(f"SOU-30 DEMO PASS: deny -> defer -> deny; applied acks=3; evidence={args.output}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"SOU-30 DEMO FAIL: {error}", file=sys.stderr)
        raise
