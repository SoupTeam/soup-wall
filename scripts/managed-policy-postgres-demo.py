#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable TLS PostgreSQL + real Console/unchanged Agent rollout witness.

Uses only an owned disposable database. No external provider calls or grants.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
from concurrent.futures import ThreadPoolExecutor
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
OUTCOME = ROOT / "target" / "sou42-managed-postgres-evidence.json"


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


def load_helpers():
    spec = importlib.util.spec_from_file_location("oidc_fixture", ROOT / "scripts/keycloak-oidc-acceptance.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-build", action="store_true", help="Reuse target/debug binaries")
    parser.add_argument("--output", type=Path, default=OUTCOME)
    parser.add_argument("--previous-gateway", type=Path, required=True,
                        help="Unmodified base revision Console binary for populated v25 upgrade")
    args = parser.parse_args()
    args.previous_gateway = args.previous_gateway.resolve()
    helpers = load_helpers()
    checks = {}
    def check(name, condition):
        checks[name] = bool(condition)
        print(f"{'PASS' if condition else 'FAIL'}: {name}", flush=True)
        if not condition:
            raise AssertionError(name)
    def expect_status(status, method, url, payload=None, headers=None):
        try:
            actual, result = request(method, url, payload, headers)
        except urllib.error.HTTPError as error:
            actual, result = error.code, None
        assert actual == status, f"expected HTTP {status}, got {actual}"
        return result

    if not args.no_build:
        subprocess.run(["cargo", "build", "--locked", "-p", "llm-firewall", "-p", "agentfw"],
                       cwd=ROOT, check=True)
    console_binary = ROOT / "target" / "debug" / ("llm-firewall.exe" if os.name == "nt" else "llm-firewall")
    agent_binary = ROOT / "target" / "debug" / ("agentfw.exe" if os.name == "nt" else "agentfw")
    assert console_binary.is_file() and agent_binary.is_file(), "missing built test binaries"

    with tempfile.TemporaryDirectory(prefix="sou42-") as folder, ExitStack() as stack:
        temp = Path(folder)
        console_dir = temp / "console"
        home = temp / "home"
        (home / ".agentfw").mkdir(parents=True)
        console_dir.mkdir()
        cp, ap = port(), port()
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
        ca, (cert, key), _ = helpers.vendor.certificate_files(temp)
        common_env["LLM_FW_POSTGRES_CA_CERT_FILE"] = str(ca)
        database = helpers.FixtureDatabase(temp, common_env, stack, postgres=True, cert=cert, key=key)
        config = (f'bind: "127.0.0.1:{cp}"\ntenant_store:\n  enabled: true\n'
                  + database.configuration())
        (console_dir / "firewall.yaml").write_text(config, encoding="utf-8")
        def migrate(binary):
            result = subprocess.run([str(binary), "migrate"], cwd=console_dir,
                env=common_env, capture_output=True, timeout=90)
            assert result.returncode == 0, "explicit migration failed (private logs suppressed)"
        console = f"http://127.0.0.1:{cp}"
        agent = f"http://127.0.0.1:{ap}"
        admin_headers = {"x-llm-firewall-admin-token": "Bearer " + admin}
        def start_console(binary):
            child = proc(stack, [str(binary)], console_dir, common_env, temp / (binary.name + ".log"))
            def ready():
                if child.poll() is not None:
                    raise RuntimeError("Console exited; private logs suppressed")
                return True if request("GET", console + "/healthz")[0] == 200 else None
            wait_for("Console readiness", ready)
            return child
        migrate(args.previous_gateway)
        check("previous-schema-is-25", database.sql("SELECT max(version) FROM llm_firewall_schema_migrations") == "25")
        old = start_console(args.previous_gateway)
        _, tenant = request("POST", console + "/admin/v1/tenants",
                            {"name": "sou42-existing-tenant"}, admin_headers)
        old.terminate()
        old.wait(timeout=8)
        preserved = database.identity_snapshot()
        migrate(console_binary)
        check("populated-v25-to-v27-preserves-existing-identities", preserved == database.identity_snapshot())
        check("schema-upgraded-to-28", int(database.sql("SELECT max(version) FROM llm_firewall_schema_migrations")) >= 28)
        cons = start_console(console_binary)
        tenant_id = tenant["id"]
        base = f"{console}/admin/v1/tenants/{tenant_id}/agents/agent-demo"
        _, enrollment = request("POST", console + f"/admin/v1/tenants/{tenant_id}/agents",
                                {"agent_id": "agent-demo"}, admin_headers)
        _, issuer = request("GET", console + "/admin/v1/managed-issuer", headers=admin_headers)
        assert len(issuer["public_key_hex"]) == 64
        agent_token = enrollment["token"]
        agent_headers = {"Authorization": "Bearer " + agent_token}
        inventory = request("GET", console + f"/admin/v1/tenants/{tenant_id}/agents", headers=admin_headers)[1]
        check("inventory-never-reveals-token-or-hash", "token" not in json.dumps(inventory))
        check("credential-hash-only", database.sql("SELECT bool_and(octet_length(token_hash)=32) FROM managed_agent_enrollments") == "t")
        stored_hash = database.sql("SELECT encode(token_hash, 'hex') FROM managed_agent_enrollments")
        check("credential-hash-matches-domain-separated-token", stored_hash == hashlib.sha256(
            b"soup-wall-managed-agent-credential-v1\0" + agent_token.encode()).hexdigest())
        check("database-connections-use-tls", int(database.sql("SELECT count(*) FROM pg_stat_ssl WHERE ssl")) > 0)
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
        # Exercise concurrency and adversarial API cases on a separate audience,
        # keeping the real runtime's three deployment sequences unambiguous.
        _, test_agent = request("POST", console + f"/admin/v1/tenants/{tenant_id}/agents",
                                {"agent_id": "concurrent"}, admin_headers)
        test_base = f"{console}/admin/v1/tenants/{tenant_id}/agents/concurrent"
        test_headers = {"Authorization": "Bearer " + test_agent["token"]}
        request("POST", test_base + "/revisions", {"revision": "test", "policy_yaml": "default: deny\n"}, admin_headers)
        expect_status(400, "POST", test_base + "/revisions/test/deploy", {}, admin_headers)
        request("POST", test_base + "/revisions/test/approve", {}, admin_headers)
        expect_status(400, "POST", test_base + "/revisions", {"revision": "test", "policy_yaml": "default: allow\n"}, admin_headers)
        def deploy(_):
            return request("POST", test_base + "/revisions/test/deploy", {}, admin_headers, timeout=15)[1]["deployment_sequence"]
        with ThreadPoolExecutor(max_workers=8) as pool:
            sequences = sorted(pool.map(deploy, range(8)))
        check("concurrent-deployments-have-unique-monotonic-sequences", sequences == list(range(1, 9)))
        check("unapproved-and-immutable-revision-writes-refused", True)
        bundle = request("GET", console + "/agent/v1/policy", headers=test_headers)[1]
        check("delivery-retry-identical", bundle == request("GET", console + "/agent/v1/policy", headers=test_headers)[1])
        ack = {key: bundle[key] for key in ("deployment_sequence", "revision", "policy_sha256")}
        ack["status"] = "rejected"
        expect_status(409, "POST", console + "/agent/v1/policy/ack", dict(ack, deployment_sequence=7), test_headers)
        expect_status(409, "POST", console + "/agent/v1/policy/ack", dict(ack, policy_sha256="0"*64), test_headers)
        expect_status(409, "POST", console + "/agent/v1/policy/ack", ack, agent_headers)
        expect_status(204, "POST", console + "/agent/v1/policy/ack", ack, test_headers)
        expect_status(204, "POST", console + "/agent/v1/policy/ack", ack, test_headers)
        expect_status(409, "POST", console + "/agent/v1/policy/ack", dict(ack, status="applied"), test_headers)
        expect_status(204, "GET", console + "/agent/v1/policy", headers=test_headers)
        check("rejected-terminal-idempotent-and-conflicting-stale-wrong-audience-acks-refused", True)
        _, foreign = request("POST", console + "/admin/v1/tenants", {"name": "other-audience"}, admin_headers)
        _, foreign_agent = request("POST", console + f'/admin/v1/tenants/{foreign["id"]}/agents', {"agent_id": "concurrent"}, admin_headers)
        foreign_headers = {"Authorization": "Bearer " + foreign_agent["token"]}
        expect_status(204, "GET", console + "/agent/v1/policy", headers=foreign_headers)
        expect_status(409, "POST", console + "/agent/v1/policy/ack", ack, foreign_headers)
        check("same-agent-id-different-tenant-isolated", True)

        request("POST", test_base + "/revoke", {}, admin_headers)
        expect_status(401, "GET", console + "/agent/v1/policy", headers=test_headers)
        expect_status(401, "POST", console + "/agent/v1/policy/ack", ack, test_headers)
        expect_status(400, "POST", test_base + "/revisions/test/deploy", {}, admin_headers)
        expect_status(400, "POST", test_base + "/revisions", {"revision": "after-revoke", "policy_yaml": "default: allow\n"}, admin_headers)
        check("revocation-refuses-delivery-ack-and-new-deployments", True)

        _, first = request("POST", base + "/revisions/v-deny/deploy",
                           {"rollback": False}, admin_headers)
        assert first["deployment_sequence"] == 1

        agent_env = os.environ.copy()
        for name in ("SOUP_AGENT_POLICY_SEED_HEX", "LLM_FW_ADMIN_TOKEN"):
            agent_env.pop(name, None)
        agent_env.update({
            "HOME": str(home),
            "USERPROFILE": str(home),
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
                "session_id": f"sou42-evidence-{number}",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo hello"},
            }, {"Authorization": "Bearer " + hook_token})
            # Agent hook intentionally returns {} for an Allow/defer verdict:
            # a no-objection decision must not grant provider permissions.
            if data == {}:
                return "defer"
            return data["hookSpecificOutput"]["permissionDecision"]
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
        for runtime, acknowledgement in zip([first_runtime, second_runtime, third_runtime], [first_ack, second_ack, third_ack]):
            for field in ("deployment_sequence", "revision", "policy_sha256"):
                check(f"runtime-ack-{runtime['deployment_sequence']}-{field}-matches", runtime[field] == acknowledgement[field])
        final_ack = {key: third_ack[key] for key in ("deployment_sequence", "revision", "policy_sha256")}
        final_ack["status"] = "applied"
        expect_status(204, "POST", console + "/agent/v1/policy/ack", final_ack, agent_headers)
        check("applied-ack-retry-preserves-timestamp", third_ack == applied(3))
        expect_status(409, "POST", console + "/agent/v1/policy/ack", dict(final_ack, status="rejected"), agent_headers)
        expect_status(409, "POST", console + "/agent/v1/policy/ack", dict(final_ack, deployment_sequence=1), agent_headers)
        check("applied-conflict-and-superseded-ack-refused", True)
        def managed_snapshot():
            return {table: database.sql(f"SELECT COALESCE(json_agg(row_to_json(t) ORDER BY row_to_json(t)::text)::text, '[]') FROM {table} t")
                    for table in ("managed_agent_enrollments", "managed_agent_revisions", "managed_agent_deployments")}
        cons.terminate()
        cons.wait(timeout=8)
        saved = managed_snapshot()
        database.restart()
        migrate(console_binary)
        check("populated-remigration-and-db-restart-preserve-managed-records", saved == managed_snapshot())
        cons = start_console(console_binary)
        expect_status(200, "GET", console + "/agent/v1/whoami", headers=agent_headers)
        check("console-restart-preserves-credential-and-ack", applied(3) == third_ack)
        check("runtime-retains-policy-through-console-and-db-restart", verdict(10) == "deny")

        _, other = request("POST", console + "/admin/v1/tenants",
                            {"name": "sou30-unrelated"}, admin_headers)
        try:
            request("POST", f'{console}/admin/v1/tenants/{other["id"]}/agents/agent-demo/revoke',
                    {}, admin_headers)
            raise AssertionError("cross-tenant revoke unexpectedly succeeded")
        except urllib.error.HTTPError as exc:
            assert exc.code == 404, exc.code

        # Revoke enrollment and verify the Agent's old credential cannot be
        # used again, while an already accepted live policy stays active.
        status, _ = request("POST", base + "/revoke", {}, admin_headers)
        assert status == 204
        try:
            request("GET", console + "/agent/v1/whoami",
                    headers={"Authorization": "Bearer " + agent_token})
            raise AssertionError("revoked Agent credential was still accepted")
        except urllib.error.HTTPError as exc:
            assert exc.code == 401, exc.code
        assert request("GET", agent + "/health")[1]["managed_policy"]["deployment_sequence"] == 3

        # A disconnected Console is not permission to erase or silently relax
        # the current policy. The Agent reports offline separately from active.
        cons.terminate()
        cons.wait(timeout=8)
        offline = wait_for("Agent offline state while retaining last policy", lambda: (
            (lambda h: h if h.get("managed_transport", {}).get("state") == "offline"
             and h["managed_policy"]["deployment_sequence"] == 3 else None)(
                request("GET", agent + "/health")[1])
        ), timeout=15)
        assert offline["managed_policy"]["revision"] == "v-deny"
        assert verdict(4) == "deny"

        report = {
            "scope": "disposable-real-agentfw-and-postgres-console",
            "postgres_image": helpers.POSTGRES_IMAGE,
            "postgres_version": database.sql("SHOW server_version"),
            "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "source_hashes": {str(path.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted([*ROOT.glob("crates/proxy/src/tenant_store/managed*.rs"),
                    ROOT / "crates/proxy/src/tenant_store/postgres.rs", ROOT / "crates/proxy/src/managed_agent_api.rs",
                    Path(__file__).resolve(), ROOT / "scripts/keycloak-oidc-acceptance.py", ROOT / "scripts/keycloak-saml-acceptance.py"])},
            "binary_hashes": {label: hashlib.sha256(path.read_bytes()).hexdigest()
                for label, path in (("console", console_binary), ("agent", agent_binary), ("previous_console", args.previous_gateway))},
            "configuration": {"console_and_agent": "existing loopback HTTP transport", "database": "TLS verified against disposable CA",
                "console_config_sha256": hashlib.sha256(config.encode()).hexdigest(), "issuer": "ephemeral Ed25519 seed, never persisted"},
            "no_external_provider": True,
            "checks": {
                **checks,
                "agent_admin_isolation": True,
                "cross_tenant_revocation_refused": True,
                "authenticated_runtime_applied": True,
                "rollback_sequence_increased": True,
                "policy_payload_restored": True,
                "credential_revocation_enforced": True,
                "offline_last_accepted_policy_retained": True,
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
    # ExitStack has stopped child processes and removed the owned database.
    report["checks"]["owned-fixture-cleanup-completed"] = True
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"SOU-42 DEMO PASS: deny -> defer -> deny; applied acks=3; evidence={args.output}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"SOU-42 DEMO FAIL: {type(error).__name__}; private fixture logs suppressed", file=sys.stderr)
        sys.exit(1)
