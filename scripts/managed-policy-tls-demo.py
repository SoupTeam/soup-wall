#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-43: owned-bridge HTTPS Console + real Agent rollout witness.

No external IdP/provider/model and no real permissions are modified.
Runs a fully isolated SQLite Console and agentfw home on random loopback ports.
The actual /hook permissionDecision and in-process /health active revision
are captured before/after activation and a NEW monotonic signed rollback.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import hashlib
import http.server
import ssl
import threading
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
OUTCOME = ROOT / "target" / "sou43-managed-policy-tls-evidence.json"
EDGE_IMAGE = "python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258"


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



def command(*parts, capture=False, timeout=40):
    result = subprocess.run([str(x) for x in parts], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command {parts[0]} failed with exit {result.returncode}: "
                           + result.stderr.decode(errors="replace")[-1500:])
    return result.stdout.decode().strip() if capture else None


def ca_material(tls, name):
    key, cert = tls / f"{name}.ca.key", tls / f"{name}.ca.pem"
    command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", cert, "-subj", f"/CN={name}", "-days", "30",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    return cert, key


def signed_certificate(tls, name, ca, ca_key, address, expired=False):
    key, csr, pem = (tls / f"{name}.{suffix}" for suffix in ("key", "csr", "pem"))
    command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", csr, "-subj", f"/CN={name}")
    extensions = tls / f"{name}.ext"
    extensions.write_text(f"subjectAltName=IP:{address}\n"
                          "basicConstraints=critical,CA:FALSE\n"
                          "keyUsage=critical,digitalSignature,keyEncipherment\n"
                          "extendedKeyUsage=serverAuth\n")
    if not expired:
        command("openssl", "x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key,
                "-set_serial", str(secrets.randbits(112)), "-days", "7", "-sha256",
                "-extfile", extensions, "-out", pem)
    else:
        index, serial, config = (tls / name for name in ("index.txt", "serial", "ca.conf"))
        index.write_text("")
        serial.write_text("01\n")
        config.write_text(
            f"[ca]\ndefault_ca=issuer\n[issuer]\ndatabase={index}\n"
            f"serial={serial}\nnew_certs_dir={tls}\ncertificate={ca}\n"
            f"private_key={ca_key}\ndefault_md=sha256\npolicy=names\n"
            "[names]\ncommonName=supplied\n[leaf]\n" + extensions.read_text())
        command("openssl", "ca", "-batch", "-config", config, "-in", csr,
                "-out", pem, "-notext", "-extensions", "leaf",
                "-startdate", "200101000000Z", "-enddate", "200201000000Z")
    return pem, key


def set_edge_mode(tls, mode, certificate="valid"):
    target = tls / "mode.json"
    staging = tls / "mode.next"
    config = json.loads(target.read_text())
    config.update(mode=mode, certificate=certificate)
    staging.write_text(json.dumps(config))
    os.replace(staging, target)


class Capture(http.server.BaseHTTPRequestHandler):
    captured = []

    def do_GET(self):
        self.captured.append((self.path, self.headers.get("Authorization")))
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_):
        pass


def https_edge(stack, root, upstream_port):
    """Docker-private nonloopback edge, with host Console on its bridge gateway.

    Containers cannot access other host sockets except the one disposable
    Console bound for this test. The TLS edge is unprivileged in capability
    terms, has no external provider credentials, and is deleted on exit.
    """
    network = "sou43-" + secrets.token_hex(5)
    command("docker", "network", "create", "--driver", "bridge", network)
    stack.callback(lambda: subprocess.run(["docker", "network", "rm", network],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                          timeout=20, check=False))
    net = json.loads(command("docker", "network", "inspect", network, capture=True))[0]
    gateway = net["IPAM"]["Config"][0]["Gateway"]
    tls = root / "tls"
    tls.mkdir()
    capture = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Capture)
    stack.callback(lambda: capture.server_close())
    stack.callback(lambda: capture.shutdown())
    thread = threading.Thread(target=capture.serve_forever, daemon=True)
    thread.start()
    Capture.captured = []
    (tls / "mode.json").write_text(json.dumps({
        "mode": "redirect", "certificate": "valid",
        "upstream_host": gateway, "upstream_port": upstream_port,
        "redirect": f"http://{gateway}:{capture.server_address[1]}/captured"
    }))
    container = network + "-edge"
    command("docker", "run", "-d", "--name", container, "--network", network,
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--mount", f"type=bind,source={tls.resolve()},target=/tls,readonly",
            "--mount", f"type=bind,source={(ROOT / 'scripts/fixtures/managed_policy_tls_edge.py').resolve()},target=/edge.py,readonly",
            EDGE_IMAGE, "python", "-u", "/edge.py", capture=True, timeout=120)
    stack.callback(lambda: subprocess.run(["docker", "rm", "-f", container],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                          timeout=20, check=False))
    info = json.loads(command("docker", "inspect", container, capture=True))[0]
    address = info["NetworkSettings"]["Networks"][network]["IPAddress"]
    assert address and not address.startswith("127."), address
    ca, ca_key = ca_material(tls, "owned")
    rogue_ca, rogue_key = ca_material(tls, "rogue")
    signed_certificate(tls, "valid", ca, ca_key, address)
    signed_certificate(tls, "wronghost", ca, ca_key, "192.0.2.211")
    signed_certificate(tls, "untrusted", rogue_ca, rogue_key, address)
    signed_certificate(tls, "expired", ca, ca_key, address, expired=True)
    ca_fp = hashlib.sha256(ca.read_bytes()).hexdigest()
    origin = f"https://{address}:8443"
    context = ssl.create_default_context(cafile=str(ca))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=context))
    try:
        wait_for("remote HTTPS edge readiness",
                 lambda: True if opener.open(origin + "/healthz", timeout=3).status == 200 else None,
                 timeout=35)
    except Exception:
        # The edge logs only verb/path, never Bearer headers or private material.
        print("TLS EDGE DIAGNOSTIC:", command("docker", "logs", container, capture=True)[-3500:],
              flush=True)
        print("TLS EDGE STATE:",
              command("docker", "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", container, capture=True),
              flush=True)
        raise
    return origin, ca, tls, opener, ca_fp, address


def verify_bad_certificate(origin, opener):
    try:
        with opener.open(origin + "/healthz", timeout=4):
            pass
    except urllib.error.URLError as error:
        assert isinstance(error.reason, ssl.SSLCertVerificationError), error
        return True
    raise AssertionError("invalid TLS certificate unexpectedly validated")



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
            f'bind: "0.0.0.0:{cp}"\n'
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
        origin, private_ca, tls, opener, ca_fingerprint, edge_ip = https_edge(stack, temp, cp)
        _, first = request("POST", base + "/revisions/v-deny/deploy",
                           {"rollback": False}, admin_headers)
        assert first["deployment_sequence"] == 1

        agent_env = os.environ.copy()
        for name in ("SOUP_AGENT_POLICY_SEED_HEX", "LLM_FW_ADMIN_TOKEN"):
            agent_env.pop(name, None)
        agent_env.update({
            "HOME": str(home),
            "SOUP_MANAGED_AGENT_CONSOLE": origin + "/",
            "SOUP_MANAGED_AGENT_TLS_CA_FILE": str(private_ca),
            "SOUP_MANAGED_AGENT_TOKEN": agent_token,
            "SOUP_MANAGED_AGENT_TENANT": tenant_id,
            "SOUP_MANAGED_AGENT_ID": "agent-demo",
            "SOUP_MANAGED_AGENT_KEY_ID": "demo-issuer-1",
            "SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX": issuer["public_key_hex"],
            # An inherited HTTPS proxy would be unreachable. Real HTTPS
            # rollout proves ManagedSync's explicit no_proxy() ignores it.
            "HTTPS_PROXY": "http://127.0.0.1:1",
            "HTTP_PROXY": "http://127.0.0.1:1",
            "ALL_PROXY": "http://127.0.0.1:1",
            "NO_PROXY": "",
            "no_proxy": "",
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

        # The first candidate exists, but a cross-origin redirect must not
        # forward the Bearer credential or falsely acknowledge application.
        def not_applied_initial():
            _, health = request("GET", agent + "/health")
            state = health.get("managed_transport", {}).get("state")
            return state if state == "rejected" else None
        wait_for("HTTPS redirect refused", not_applied_initial, timeout=15)
        assert not Capture.captured, "Agent Bearer leaked to redirect destination"
        assert request("GET", agent + "/health")[1].get("managed_policy") is None
        assert not any(row["status"] == "applied" for row in
                       request("GET", base + "/deployments", headers=admin_headers)[1])

        # Keep seq1 pending while the real Agent observes three distinct
        # certificate failures. Each MUST leave its live policy unchanged.
        bad_certificates = {}
        for cert in ("wronghost", "untrusted", "expired"):
            set_edge_mode(tls, "proxy", cert)
            assert verify_bad_certificate(origin, opener)
            time.sleep(3.0)  # > one Agent 2-second poll interval
            _, health = request("GET", agent + "/health")
            assert health.get("managed_policy") is None, (cert, health)
            deployments = request("GET", base + "/deployments",
                                  headers=admin_headers)[1]
            assert not any(row["status"] == "applied" for row in deployments), cert
            bad_certificates[cert] = "certificate_refused_no_activation"
        set_edge_mode(tls, "proxy", "valid")
        assert opener.open(origin + "/healthz", timeout=3).status == 200

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
        # Verify the same revoked enrollment token fails over the *verified
        # remote HTTPS transport*, not only through the local Console endpoint.
        revoked_request = urllib.request.Request(
            origin + "/agent/v1/whoami",
            headers={"Authorization": "Bearer " + agent_token},
            method="GET",
        )
        try:
            opener.open(revoked_request, timeout=3)
            raise AssertionError("revoked token unexpectedly authenticated over HTTPS")
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
            "scope": "controlled-owned-bridge-nonloopback-HTTPS-real-agentfw-sqlite-console",
            "source_sha": command("git", "rev-parse", "HEAD", capture=True),
            "source_and_runtime_sha256": {
                "agentfw_binary": hashlib.sha256(agent_binary.read_bytes()).hexdigest(),
                "sqlite_console_binary": hashlib.sha256(console_binary.read_bytes()).hexdigest(),
                "https_test_edge_source": hashlib.sha256(
                    (ROOT / "scripts/fixtures/managed_policy_tls_edge.py").read_bytes()
                ).hexdigest(),
                "test_driver_source": hashlib.sha256(
                    (ROOT / "scripts/managed-policy-tls-demo.py").read_bytes()
                ).hexdigest(),
                "served_certificate_der": hashlib.sha256(
                    ssl.PEM_cert_to_DER_cert((tls / "valid.pem").read_text())
                ).hexdigest(),
            },
            "network_scope": {
                "kind": "disposable-private-docker-bridge",
                "transport": "verified HTTPS to nonloopback container IP",
                "tls_termination_to_console": "owned bridge-local HTTP, not production E2E TLS",
                "edge_image": EDGE_IMAGE,
                "inherited_proxies_disabled": True,
                "cross_origin_redirects_disabled": True,
                "poisoned_inherited_proxy_ignored": True,
            },
            "remote_https_origin": origin,
            "remote_address": edge_ip,
            "operator_ca_pem_sha256": ca_fingerprint,
            "certificate_failures": bad_certificates,
            "no_external_provider": True,
            "checks": {
                "agent_admin_isolation": True,
                "cross_tenant_revocation_refused": True,
                "authenticated_runtime_applied": True,
                "rollback_sequence_increased": True,
                "policy_payload_restored": True,
                "credential_revocation_enforced": True,
                "verified_https_revoked_enrollment_refused": True,
                "offline_last_accepted_policy_retained": True,
                "remote_nonloopback_tls_verified": True,
                "redirect_credential_exfiltration_refused": not Capture.captured,
                "wrong_hostname_certificate_refused": True,
                "untrusted_ca_certificate_refused": True,
                "expired_certificate_refused": True,
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
        print(f"SOU-43 TLS DEMO PASS: HTTPS nonloopback deny -> defer -> deny; acks=3; evidence={args.output}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"SOU-43 TLS DEMO FAIL: {error}", file=sys.stderr)
        raise
