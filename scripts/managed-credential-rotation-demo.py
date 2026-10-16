#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-55: disposable, real-process managed Agent credential rotation acceptance.

Supports an owned SQLite Console or an isolated TLS PostgreSQL fixture.
Never prints credentials, raw HTTP bodies, or private database contents.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from urllib import error, request

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "target" / "sou55-managed-credential-rotation.json"


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def call(method, url, body=None, headers=None, timeout=5):
    payload = None if body is None else json.dumps(body).encode("utf-8")
    req = request.Request(url, data=payload, method=method,
                          headers={"Content-Type": "application/json", **(headers or {})})
    with request.urlopen(req, timeout=timeout) as response:
        data = response.read(120001)
        assert len(data) <= 120000, "oversized response"
        return response.status, json.loads(data) if data else None


def expect(status, method, url, body=None, headers=None):
    try:
        actual, data = call(method, url, body, headers)
    except error.HTTPError as exc:
        actual, data = exc.code, None
    assert actual == status, f"{method} returned HTTP {actual}, expected {status}"
    return data


def await_result(label, predicate, timeout=45):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        try:
            result = predicate()
            if result is not None:
                return result
        except (OSError, error.HTTPError, ValueError):
            pass
        time.sleep(.25)
    raise AssertionError(f"timeout: {label}")


def run_process(stack, cmd, cwd, env, logfile):
    handle = stack.enter_context(open(logfile, "wb"))
    process = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=handle, stderr=subprocess.STDOUT)
    stack.callback(lambda p=process: stop(p))
    return process


def stop(process):
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=10)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def token():
    return "sw_agent_" + secrets.token_urlsafe(32)


def replace_secret(path, value):
    pending = path.with_suffix(".pending")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(value.encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
    finally:
        if pending.exists():
            pending.unlink()


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("--backend", choices=("sqlite", "postgres"), required=True)
    cli.add_argument("--no-build", action="store_true")
    cli.add_argument("--output", type=Path, default=OUTPUT)
    args = cli.parse_args()
    assert os.name == "posix", "private credential-file mode requires Unix"
    if not args.no_build:
        subprocess.run(["cargo", "build", "--locked", "-p", "llm-firewall", "-p", "agentfw"],
                       cwd=ROOT, check=True)
    proxy_binary = ROOT / "target/debug/llm-firewall"
    agent_binary = ROOT / "target/debug/agentfw"
    assert proxy_binary.is_file() and agent_binary.is_file(), "missing built binaries"
    checks = {}

    def check(label, ok):
        checks[label] = bool(ok)
        assert ok, f"check failed: {label}"

    with tempfile.TemporaryDirectory(prefix="sou55-") as dirname, ExitStack() as stack:
        temp = Path(dirname)
        console_dir, home = temp / "console", temp / "home"
        console_dir.mkdir()
        (home / ".agentfw").mkdir(parents=True)
        cp, ap = port(), port()
        console, agent = f"http://127.0.0.1:{cp}", f"http://127.0.0.1:{ap}"
        (home / ".agentfw/config.yaml").write_text(
            f"bind: 127.0.0.1\nport: {ap}\nenforce: true\n", encoding="utf-8")
        admin, seed = secrets.token_urlsafe(32), secrets.token_hex(32)
        env = os.environ.copy()
        for name in ("SOUP_MANAGED_AGENT_CONSOLE", "SOUP_MANAGED_AGENT_TOKEN",
                     "SOUP_MANAGED_AGENT_TOKEN_FILE"):
            env.pop(name, None)
        env.update({"LLM_FW_ADMIN_TOKEN": admin, "SOUP_AGENT_POLICY_SEED_HEX": seed,
                    "SOUP_AGENT_POLICY_KEY_ID": "owned-issuer",
                    "OPENAI_API_KEY": "", "LLM_FW_OPENAI_API_KEY": ""})
        if args.backend == "sqlite":
            backend_config = (f"tenant_store:\n  enabled: true\n  backend: sqlite\n"
                              f'  database_path: "{temp / "managed.sqlite"}"\n')
        else:
            spec = importlib.util.spec_from_file_location(
                "oidc_fixture", ROOT / "scripts/keycloak-oidc-acceptance.py")
            helpers = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(helpers)
            ca, (cert, key), _ = helpers.vendor.certificate_files(temp)
            env["LLM_FW_POSTGRES_CA_CERT_FILE"] = str(ca)
            db = helpers.FixtureDatabase(temp, env, stack, postgres=True, cert=cert, key=key)
            backend_config = "tenant_store:\n  enabled: true\n" + db.configuration()
        (console_dir / "firewall.yaml").write_text(
            f'bind: "127.0.0.1:{cp}"\n' + backend_config, encoding="utf-8")
        if args.backend == "postgres":
            migrated = subprocess.run([str(proxy_binary), "migrate"], cwd=console_dir,
                                      env=env, capture_output=True, timeout=90)
            check("postgres-migration", migrated.returncode == 0)
        console_proc = run_process(stack, [str(proxy_binary)], console_dir,
                                   env, temp / "console.log")
        def console_ready():
            if console_proc.poll() is not None:
                raise AssertionError("Console failed to start")
            return True if call("GET", console + "/healthz")[0] == 200 else None
        await_result("Console readiness", console_ready)
        admin_headers = {"x-llm-firewall-admin-token": "Bearer " + admin}
        tenant = expect(201, "POST", console + "/admin/v1/tenants",
                        {"name": "sou55-controlled"}, admin_headers)
        tid = tenant["id"]
        base = f"{console}/admin/v1/tenants/{tid}/agents/agent-demo"
        enrollment = expect(201, "POST", console + f"/admin/v1/tenants/{tid}/agents",
                            {"agent_id": "agent-demo"}, admin_headers)
        old = enrollment["token"]
        initial_headers = {"Authorization": "Bearer " + old}
        issuer = expect(200, "GET", console + "/admin/v1/managed-issuer",
                        headers=admin_headers)
        for revision, policy in (("deny", "deny"), ("defer", "allow")):
            expect(201, "POST", base + "/revisions",
                   {"revision": revision, "policy_yaml": f"default: {policy}\n"}, admin_headers)
            expect(204, "POST", base + f"/revisions/{revision}/approve", {}, admin_headers)
        first = expect(201, "POST", base + "/revisions/deny/deploy",
                       {"rollback": False}, admin_headers)
        check("initial-sequence", first["deployment_sequence"] == 1)
        credential = temp / "credential"
        replace_secret(credential, old)
        agent_env = env.copy()
        for name in ("LLM_FW_ADMIN_TOKEN", "SOUP_AGENT_POLICY_SEED_HEX", "SOUP_MANAGED_AGENT_TOKEN"):
            agent_env.pop(name, None)
        agent_env.update({
            "HOME": str(home),
            "SOUP_MANAGED_AGENT_CONSOLE": console + "/",
            "SOUP_MANAGED_AGENT_TOKEN_FILE": str(credential),
            "SOUP_MANAGED_AGENT_TENANT": tid,
            "SOUP_MANAGED_AGENT_ID": "agent-demo",
            "SOUP_MANAGED_AGENT_KEY_ID": "owned-issuer",
            "SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX": issuer["public_key_hex"],
        })
        agent_proc = run_process(stack, [str(agent_binary), "serve"], temp,
                                 agent_env, temp / "agent.log")
        daemon_pid = agent_proc.pid
        def active(seq):
            def read():
                if agent_proc.poll() is not None:
                    raise AssertionError("Agent exited unexpectedly")
                data = call("GET", agent + "/health")[1]
                policy = data.get("managed_policy") or {}
                return data if policy.get("deployment_sequence") == seq else None
            return await_result(f"Agent active deployment {seq}", read)
        def applied(seq):
            def read():
                entries = call("GET", base + "/deployments", headers=admin_headers)[1]
                return entries[0] if (entries and entries[0]["deployment_sequence"] == seq
                                      and entries[0]["status"] == "applied") else None
            return await_result(f"Console applied {seq}", read)
        def auth_gap(seq):
            def read():
                data = call("GET", agent + "/health")[1]
                return data if (data.get("managed_transport") or {}).get("state") == "auth_unavailable"                     and (data.get("managed_policy") or {}).get("deployment_sequence") == seq else None
            return await_result("Agent authentication gap", read, timeout=15)
        hook_token = await_result(
            "Agent local hook bearer", lambda: (home / ".agentfw/token").read_text().strip()
            if (home / ".agentfw/token").exists() else None)
        def verdict(label):
            _, response = call("POST", agent + "/hook", {
                "session_id": "sou55-" + label,
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo harmless"},
            }, {"Authorization": "Bearer " + hook_token})
            return "defer" if response == {} else response["hookSpecificOutput"]["permissionDecision"]
        active(1)
        applied(1)
        check("initial-runtime-decision-deny", verdict("initial") == "deny")
        check("initial-same-daemon", agent_proc.pid == daemon_pid)

        next_token = token()
        op_id = secrets.token_hex(16)
        rotation = {"expected_generation": 1, "operation_id": op_id,
                    "replacement_token": next_token}
        endpoint = base + "/credential-rotations"
        expect(401, "POST", endpoint, rotation, initial_headers)
        check("agent-token-is-not-admin", True)
        other = expect(201, "POST", console + "/admin/v1/tenants",
                       {"name": "sou55-other"}, admin_headers)
        expect(409, "POST", f'{console}/admin/v1/tenants/{other["id"]}/agents/agent-demo/credential-rotations',
               rotation, admin_headers)
        check("cross-tenant-refusal", True)
        issued = expect(200, "POST", endpoint, rotation, admin_headers)
        check("atomic-first-rotation", issued["generation"] == 2 and not issued["already_applied"])
        retry = expect(200, "POST", endpoint, rotation, admin_headers)
        check("lost-response-retry-does-not-re-rotate",
              retry["generation"] == 2 and retry["already_applied"])
        expect(409, "POST", endpoint, dict(rotation, replacement_token=token()), admin_headers)
        expect(409, "POST", endpoint,
               {"expected_generation": 1, "operation_id": secrets.token_hex(16),
                "replacement_token": token()}, admin_headers)
        check("stale-or-mutated-operation-refused", True)

        ack = {"deployment_sequence": 1, "revision": "deny",
               "policy_sha256": first["policy_sha256"], "status": "applied"}
        expect(401, "GET", console + "/agent/v1/whoami", headers=initial_headers)
        expect(401, "GET", console + "/agent/v1/policy", headers=initial_headers)
        expect(401, "POST", console + "/agent/v1/policy/ack", ack, initial_headers)
        check("retired-token-fetch-and-ack-rejected", True)
        auth_gap(1)
        check("last-policy-preserved-with-retired-credential", True)
        credential.unlink()
        auth_gap(1)
        replace_secret(credential, "invalid-token")
        auth_gap(1)
        check("deleted-or-invalid-token-file-does-not-fallback", True)
        credential.unlink()
        replace_secret(credential, next_token)
        new_headers = {"Authorization": "Bearer " + next_token}
        expect(200, "GET", console + "/agent/v1/whoami", headers=new_headers)
        second = expect(201, "POST", base + "/revisions/defer/deploy",
                        {"rollback": False}, admin_headers)
        check("post-rotation-deployment-sequence", second["deployment_sequence"] == 2)
        active(2)
        applied(2)
        check("post-rotation-runtime-decision-defer", verdict("after-rotation") == "defer")
        rollback = expect(201, "POST", base + "/revisions/deny/deploy",
                          {"rollback": True}, admin_headers)
        check("monotonic-rollback", rollback["deployment_sequence"] == 3)
        active(3)
        applied(3)
        check("post-rotation-monotonic-rollback-deny", verdict("rollback") == "deny")
        check("live-reload-no-daemon-restart", agent_proc.pid == daemon_pid)

        # Separate Agent to prove competing generation-1 operations serialize.
        concurrent = expect(201, "POST", console + f"/admin/v1/tenants/{tid}/agents",
                            {"agent_id": "concurrent"}, admin_headers)
        cbase = f"{console}/admin/v1/tenants/{tid}/agents/concurrent/credential-rotations"
        competing = [{"expected_generation": 1, "operation_id": secrets.token_hex(16),
                      "replacement_token": token()} for _ in range(2)]
        def attempt(payload):
            try:
                return call("POST", cbase, payload, admin_headers)[0]
            except error.HTTPError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, competing))
        check("competing-rotations-exactly-one-wins", sorted(results) == [200, 409])
        # Disabled tenants must not be reactivated through a rotation request.
        disabled_base = f'{console}/admin/v1/tenants/{other["id"]}/agents'
        expect(201, "POST", disabled_base,
               {"agent_id": "disabled-agent"}, admin_headers)
        expect(204, "PATCH", f'{console}/admin/v1/tenants/{other["id"]}',
               {"active": False}, admin_headers)
        expect(409, "POST", disabled_base + "/disabled-agent/credential-rotations",
               {"expected_generation": 1, "operation_id": secrets.token_hex(16),
                "replacement_token": token()}, admin_headers)
        check("disabled-tenant-cannot-rotate", True)
        expect(204, "POST", base + "/revoke", {}, admin_headers)
        expect(409, "POST", endpoint,
               {"expected_generation": 2, "operation_id": secrets.token_hex(16),
                "replacement_token": token()}, admin_headers)
        expect(401, "GET", console + "/agent/v1/policy", headers=new_headers)
        check("revoked-enrollment-cannot-rotate-or-authenticate", True)
        auth_gap(3)
        check("active-policy-preserved-after-revocation", verdict("revoked") == "deny")
        stop(agent_proc)
        # A restart with the last accepted signed bundle still restores policy.
        restarted = run_process(stack, [str(agent_binary), "serve"], temp,
                                agent_env, temp / "agent-restart.log")
        def restored():
            if restarted.poll() is not None:
                raise AssertionError("restarted Agent exited")
            health = call("GET", agent + "/health")[1]
            return health if (health.get("managed_policy") or {}).get("deployment_sequence") == 3 else None
        await_result("restored signed policy", restored)
        check("restart-preserves-accepted-policy", True)

        report = {
            "scope": "disposable-local-console-real-running-agent",
            "backend": args.backend,
            "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"],
                                                     cwd=ROOT, text=True).strip(),
            "console_sha256": digest(proxy_binary),
            "agent_sha256": digest(agent_binary),
            "console_config_sha256": digest(console_dir / "firewall.yaml"),
            "agent_config_sha256": digest(home / ".agentfw/config.yaml"),
            "checks": checks,
            "daemon_pid_preserved_during_rotation": True,
            "acknowledged_sequences": [1, 2, 3],
            "no_credentials_in_report": True,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"SOU-55 PASS: {args.backend}; {len(checks)} checks; evidence={args.output}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Never expose raw credentials, auth headers or bodies in failure output.
        print(f"SOU-55 acceptance failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1)
