#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-46: zero-downtime policy signing key rotation and revocation witness.

Verifies:
1. Agent starts with key1 pinned in trusted-issuers.json.
2. Console deploys revision 1 (v-deny) signed by key1 -> applied, hook returns deny.
3. Hot rotation: trusted-issuers.json is updated on disk to include key2 WITHOUT restarting Agent (PID is verified identical).
4. Console deploys revision 2 (v-allow) signed by key2 -> applied, hook returns defer.
5. Hot revocation: trusted-issuers.json is updated on disk marking key1 as revoked WITHOUT restarting Agent (PID verified identical).
6. Console deploys revision 3 (v-deny) signed by revoked key1 -> Agent rejects candidate (fail-closed), Console receives rejected ack.
7. Active policy on running Agent strictly remains revision 2 (v-allow), hook remains defer, fail-closed invariant preserved.
8. Writes sanitized witness evidence to target/sou46-key-rotation-evidence.json.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
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
OUTCOME = ROOT / "target" / "sou46-key-rotation-evidence.json"


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
        subprocess.run(
            ["cargo", "build", "--locked", "-p", "llm-firewall", "-p", "agentfw"],
            cwd=ROOT,
            check=True,
        )
    console_binary = ROOT / "target" / "debug" / ("llm-firewall.exe" if os.name == "nt" else "llm-firewall")
    agent_binary = ROOT / "target" / "debug" / ("agentfw.exe" if os.name == "nt" else "agentfw")
    assert console_binary.is_file() and agent_binary.is_file(), "missing built test binaries"

    with tempfile.TemporaryDirectory(prefix="sou46-") as folder, ExitStack() as stack:
        temp = Path(folder)
        console_dir = temp / "console"
        home = temp / "home"
        agentfw_home = home / ".agentfw"
        agentfw_home.mkdir(parents=True)
        console_dir.mkdir()
        cp, ap = port(), port()

        (console_dir / "firewall.yaml").write_text(
            f'bind: "127.0.0.1:{cp}"\n'
            f'tenant_store:\n  enabled: true\n  backend: sqlite\n'
            f'  database_path: "{temp / "managed.sqlite"}"\n'
        )
        (agentfw_home / "config.yaml").write_text(
            f"bind: 127.0.0.1\nport: {ap}\nenforce: true\n"
        )

        admin = secrets.token_urlsafe(32)
        seed1 = secrets.token_hex(32)
        seed2 = secrets.token_hex(32)

        common_env = os.environ.copy()
        common_env.pop("SOUP_MANAGED_AGENT_CONSOLE", None)
        common_env.update({
            "LLM_FW_ADMIN_TOKEN": admin,
            "SOUP_AGENT_POLICY_KEY_ID": "demo-issuer-1",
            "SOUP_AGENT_POLICY_SEED_HEX": seed1,
            # Configure second issuer seed in Console environment
            "SOUP_AGENT_POLICY_SEED_HEX_DEMO_ISSUER_2": seed2,
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
        _, tenant = request(
            "POST",
            console + "/admin/v1/tenants",
            {"name": "sou46-rotation"},
            admin_headers,
        )
        tenant_id = tenant["id"]
        base = f"{console}/admin/v1/tenants/{tenant_id}/agents/agent-demo"
        _, enrollment = request(
            "POST",
            console + f"/admin/v1/tenants/{tenant_id}/agents",
            {"agent_id": "agent-demo"},
            admin_headers,
        )
        agent_token = enrollment["token"]

        # Retrieve public keys for both configured issuers
        _, issuer1 = request("GET", console + "/admin/v1/managed-issuer", headers=admin_headers)
        assert issuer1["key_id"] == "demo-issuer-1"
        assert len(issuer1["public_key_hex"]) == 64

        _, issuer2 = request(
            "GET",
            console + "/admin/v1/managed-issuer?key_id=demo-issuer-2",
            headers=admin_headers,
        )
        assert issuer2["key_id"] == "demo-issuer-2"
        assert len(issuer2["public_key_hex"]) == 64
        assert issuer1["public_key_hex"] != issuer2["public_key_hex"]

        # Write initial keyring file with demo-issuer-1 ONLY
        keyring_file = agentfw_home / "trusted-issuers.json"
        initial_keyring = [
            {
                "key_id": "demo-issuer-1",
                "public_key_hex": issuer1["public_key_hex"],
                "revoked": False,
            }
        ]
        keyring_file.write_text(json.dumps(initial_keyring, indent=2))

        # Register revisions
        request(
            "POST",
            base + "/revisions",
            {"revision": "v-deny", "policy_yaml": "default: deny\n"},
            admin_headers,
        )
        request("POST", base + "/revisions/v-deny/approve", {}, admin_headers)

        request(
            "POST",
            base + "/revisions",
            {"revision": "v-allow", "policy_yaml": "default: allow\n"},
            admin_headers,
        )
        request("POST", base + "/revisions/v-allow/approve", {}, admin_headers)

        # Deploy sequence 1 signed with key1 (default)
        _, first = request(
            "POST",
            base + "/revisions/v-deny/deploy",
            {"rollback": False, "issuer_key_id": "demo-issuer-1"},
            admin_headers,
        )
        assert first["deployment_sequence"] == 1

        agent_env = os.environ.copy()
        for name in (
            "SOUP_AGENT_POLICY_SEED_HEX",
            "SOUP_AGENT_POLICY_SEED_HEX_DEMO_ISSUER_2",
            "LLM_FW_ADMIN_TOKEN",
            "SOUP_MANAGED_AGENT_KEY_ID",
            "SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX",
        ):
            agent_env.pop(name, None)

        agent_env.update({
            "HOME": str(home),
            "SOUP_MANAGED_AGENT_CONSOLE": console + "/",
            "SOUP_MANAGED_AGENT_TOKEN": agent_token,
            "SOUP_MANAGED_AGENT_TENANT": tenant_id,
            "SOUP_MANAGED_AGENT_ID": "agent-demo",
            "SOUP_MANAGED_AGENT_KEYRING_PATH": str(keyring_file),
        })

        agent_proc = proc(stack, [str(agent_binary), "serve"], temp, agent_env, temp / "agent.log")
        agent_pid = agent_proc.pid

        def active(expected):
            def check():
                if agent_proc.poll() is not None:
                    raise RuntimeError(f"Agent exited {agent_proc.returncode}")
                _, health = request("GET", agent + "/health")
                item = health.get("managed_policy")
                return item if item and item["deployment_sequence"] == expected else None
            return wait_for(f"Agent applied sequence {expected}", check)

        hook_token = wait_for(
            "hook token created",
            lambda: (agentfw_home / "token").read_text().strip()
            if (agentfw_home / "token").exists()
            else None,
        )

        def verdict(number):
            _, data = request(
                "POST",
                agent + "/hook",
                {
                    "session_id": f"sou46-evidence-{number}",
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "echo hello"},
                },
                {"Authorization": "Bearer " + hook_token},
            )
            if data == {}:
                return "defer"
            return data["hookSpecificOutput"]["permissionDecision"]

        def applied(seq):
            def check():
                _, items = request("GET", base + "/deployments", headers=admin_headers)
                return (
                    items[0]
                    if items
                    and items[0]["deployment_sequence"] == seq
                    and items[0]["status"] == "applied"
                    else None
                )
            return wait_for(f"Console applied ack {seq}", check)

        def rejected(seq):
            def check():
                _, items = request("GET", base + "/deployments", headers=admin_headers)
                return (
                    items[0]
                    if items
                    and items[0]["deployment_sequence"] == seq
                    and items[0]["status"] == "rejected"
                    else None
                )
            return wait_for(f"Console rejected ack {seq}", check)

        # STEP 1: Verify sequence 1 applied with key1
        first_runtime = active(1)
        first_ack = applied(1)
        first_verdict = verdict(1)
        assert first_verdict == "deny", f"expected deny, got {first_verdict}"
        assert first_runtime["revision"] == "v-deny"

        # STEP 2: Hot rotation - add demo-issuer-2 to keyring on disk WITHOUT restarting Agent
        rotated_keyring = [
            {
                "key_id": "demo-issuer-1",
                "public_key_hex": issuer1["public_key_hex"],
                "revoked": False,
            },
            {
                "key_id": "demo-issuer-2",
                "public_key_hex": issuer2["public_key_hex"],
                "revoked": False,
            },
        ]
        keyring_file.write_text(json.dumps(rotated_keyring, indent=2))

        # Ensure Agent process is still running with identical PID (zero downtime)
        assert agent_proc.poll() is None, "Agent process unexpectedly stopped"
        assert agent_proc.pid == agent_pid, "Agent process was restarted"

        # Deploy sequence 2 signed by demo-issuer-2
        _, second = request(
            "POST",
            base + "/revisions/v-allow/deploy",
            {"rollback": False, "issuer_key_id": "demo-issuer-2"},
            admin_headers,
        )
        assert second["deployment_sequence"] == 2

        second_runtime = active(2)
        second_ack = applied(2)
        second_verdict = verdict(2)
        assert second_verdict == "defer", f"expected defer, got {second_verdict}"
        assert second_runtime["revision"] == "v-allow"

        # Verify Agent PID has NOT changed
        assert agent_proc.poll() is None, "Agent process unexpectedly stopped"
        assert agent_proc.pid == agent_pid, "Agent process was restarted during rotation"

        # STEP 3: Hot revocation - mark demo-issuer-1 as revoked in keyring on disk WITHOUT restarting Agent
        revoked_keyring = [
            {
                "key_id": "demo-issuer-1",
                "public_key_hex": issuer1["public_key_hex"],
                "revoked": True,
            },
            {
                "key_id": "demo-issuer-2",
                "public_key_hex": issuer2["public_key_hex"],
                "revoked": False,
            },
        ]
        keyring_file.write_text(json.dumps(revoked_keyring, indent=2))

        # Deploy sequence 3 signed by the newly revoked demo-issuer-1
        _, third = request(
            "POST",
            base + "/revisions/v-deny/deploy",
            {"rollback": False, "issuer_key_id": "demo-issuer-1"},
            admin_headers,
        )
        assert third["deployment_sequence"] == 3

        # Agent should reject candidate bundle fail-closed and report rejected to Console
        third_ack = rejected(3)
        assert third_ack["status"] == "rejected"

        # Running Agent must KEEP sequence 2 active (fail-closed invariant)
        _, health = request("GET", agent + "/health")
        current_managed = health["managed_policy"]
        assert current_managed["deployment_sequence"] == 2, (
            f"active policy was unexpectedly altered: {current_managed}"
        )
        assert current_managed["revision"] == "v-allow"

        # Hook decision must remain defer (since sequence 2 is v-allow)
        post_rejection_verdict = verdict(3)
        assert post_rejection_verdict == "defer", (
            f"hook decision was altered after rejection: {post_rejection_verdict}"
        )

        # Verify Agent PID has NOT changed throughout
        assert agent_proc.poll() is None, "Agent process unexpectedly stopped"
        assert agent_proc.pid == agent_pid, "Agent process was restarted during revocation"

        report = {
            "scope": "sou46-zero-downtime-key-rotation-and-revocation",
            "agent_pid_invariant": agent_pid,
            "no_agent_restart": True,
            "source_commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
            ).strip(),
            "source_hashes": {
                str(path.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in sorted([
                    ROOT / "crates/agentfw/src/managed_policy.rs",
                    ROOT / "crates/agentfw/src/managed_sync.rs",
                    ROOT / "crates/proxy/src/tenant_store/managed_policy.rs",
                    ROOT / "crates/proxy/src/managed_agent_api.rs",
                    ROOT / "docs/operations/MANAGED_AGENT_POLICY.md",
                    Path(__file__).resolve(),
                ])
            },
            "binary_hashes": {
                "console": hashlib.sha256(console_binary.read_bytes()).hexdigest(),
                "agent": hashlib.sha256(agent_binary.read_bytes()).hexdigest(),
            },
            "checks": {
                "key1_initial_deployment_applied": True,
                "key2_hot_rotation_applied_without_restart": True,
                "key1_hot_revocation_fail_closed": True,
                "active_policy_preserved_on_revoked_key_rejection": True,
                "hook_decision_preserved_on_rejection": True,
            },
            "issuers": {
                "issuer_1": {"key_id": issuer1["key_id"], "public_key_hex": issuer1["public_key_hex"]},
                "issuer_2": {"key_id": issuer2["key_id"], "public_key_hex": issuer2["public_key_hex"]},
            },
            "deployments": [
                {
                    "sequence": 1,
                    "signed_by": "demo-issuer-1",
                    "revision": first_runtime["revision"],
                    "sha256": first_runtime["policy_sha256"],
                    "decision": first_verdict,
                    "ack": first_ack["status"],
                },
                {
                    "sequence": 2,
                    "signed_by": "demo-issuer-2",
                    "revision": second_runtime["revision"],
                    "sha256": second_runtime["policy_sha256"],
                    "decision": second_verdict,
                    "ack": second_ack["status"],
                },
                {
                    "sequence": 3,
                    "signed_by": "demo-issuer-1 (revoked)",
                    "expected_ack": "rejected",
                    "actual_ack": third_ack["status"],
                    "active_policy_maintained_sequence": current_managed["deployment_sequence"],
                    "decision_maintained": post_rejection_verdict,
                },
            ],
        }
    # ExitStack stopped child processes and cleaned up temporary folder
    report["checks"]["owned_fixture_cleanup_completed"] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"SOU-46 DEMO PASS: key1 (deny) -> rotated key2 (defer) -> revoked key1 rejected (defer retained); no Agent restart (PID={agent_pid}); evidence={args.output}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"SOU-46 DEMO FAIL: {error}", file=sys.stderr)
        raise
