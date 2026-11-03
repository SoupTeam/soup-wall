#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in Agent heartbeat against a real Console and real Agents.

One disposable private Linux deployment per run: a Console on loopback with
SQLite or a disposable TLS PostgreSQL cluster (local binaries, owned CA), two
unchanged `agentfw serve` processes (one with SOUP_MANAGED_AGENT_HEARTBEAT=1,
one without) applying a real signed deny policy, an independent runtime
witness (the Agent's own /health and /hook decision), protocol probes with
the Agent's own credential, and Chromium reading the status as a Viewer.
Credentials stay in memory and the private temporary directory; retained
reports and screenshots never contain one.

    python3 scripts/console-agent-heartbeat-acceptance.py --backend sqlite|postgres --output DIR [--no-build]
"""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sw-console-agent-heartbeat-acceptance/1"
CONTRACT = "sw-agent-heartbeat/1"


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = module("heartbeat_managed_helpers", "managed-policy-demo.py")
PG = module("heartbeat_postgres_helpers", "console-enrollment-acceptance.py")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", choices=["sqlite", "postgres"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pg-bin", help="directory with initdb, pg_ctl and createdb")
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()
    from playwright.sync_api import expect, sync_playwright
    args.output = args.output.resolve()
    assert not args.output.is_relative_to(ROOT), "--output must be outside the checkout"
    args.output.mkdir(parents=True, exist_ok=True)
    if not args.no_build:
        subprocess.run(["cargo", "build", "--locked", "-p", "llm-firewall", "-p", "agentfw"], cwd=ROOT, check=True)
    console_binary, agent_binary = ROOT / "target/debug/llm-firewall", ROOT / "target/debug/agentfw"
    checks, snapshots, private = {}, {}, []
    report = {"format": FORMAT, "backend": args.backend, "status": "failed", "checks": checks, "snapshots": snapshots,
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
              "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "scope": "one disposable private Linux deployment; synthetic tenants and Agent IDs; an authenticated "
                       "self-report, not runtime attestation, production, multi-host or a health check"}

    def check(name, condition):
        checks[name] = bool(condition)
        if not condition:
            raise AssertionError(name)
        print("PASS:", name, flush=True)

    try:
        with tempfile.TemporaryDirectory(prefix="console-heartbeat-") as folder, ExitStack() as stack:
            temp = Path(folder).resolve()
            os.chmod(temp, 0o700)
            private.append(str(temp))
            console_dir = temp / "console"
            console_dir.mkdir()
            cp = D.port()
            console = f"http://127.0.0.1:{cp}"
            owner, seed = secrets.token_urlsafe(32), secrets.token_hex(32)
            private += [owner, seed]
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("SOUP_MANAGED_AGENT_", "SOUP_AGENT_POLICY_", "LLM_FW_", "OPENAI_", "PG"))}
            env.update(LLM_FW_ADMIN_TOKEN=owner, SOUP_AGENT_POLICY_KEY_ID="heartbeat-issuer", SOUP_AGENT_POLICY_SEED_HEX=seed)
            if args.backend == "postgres":
                url, ca, password, binaries = PG.postgres(stack, temp, PG.pg_bin(args.pg_bin))
                private += [password, url]
                env.update(LLM_FW_POSTGRES_URL=url, LLM_FW_POSTGRES_CA_CERT_FILE=str(ca))
                store = "  backend: postgres\n  postgres_command_timeout_ms: 30000\n  postgres_pool_wait_timeout_ms: 10000\n"
                report["postgres"] = {"server": subprocess.run([str(binaries / "postgres"), "--version"], capture_output=True, text=True).stdout.strip(),
                                      "tls": "sslmode=require with an owned CA", "listen": "127.0.0.1"}
            else:
                store = '  backend: sqlite\n  database_path: "heartbeat.sqlite"\n'
            (console_dir / "firewall.yaml").write_text(f'bind: "127.0.0.1:{cp}"\ntenant_store:\n  enabled: true\n' + store, encoding="utf-8")
            if args.backend == "postgres":
                migrate = subprocess.run([str(console_binary), "migrate"], cwd=console_dir, env=env, capture_output=True, timeout=120)
                check("postgres-migration-creates-observation-schema", migrate.returncode == 0)
            starts = [0]

            def start_console():
                starts[0] += 1
                process = D.proc(stack, [str(console_binary)], console_dir, env, temp / f"console-{starts[0]}.log")
                D.wait_for("Console", lambda: D.request("GET", console + "/healthz")[0] == 200, timeout=90)
                return process

            console_process = start_console()
            admin = {"x-llm-firewall-admin-token": "Bearer " + owner}

            def req(method, path, payload=None, auth=admin):
                return D.request(method, console + path, payload, auth, timeout=15)[1]

            def code(method, path, payload=None, auth=None):
                try:
                    status, body = D.request(method, console + path, payload, auth, timeout=15)
                    return status, body
                except urllib.error.HTTPError as error:
                    try:
                        return error.code, json.loads(error.read() or b"null")
                    except ValueError:
                        return error.code, None

            alpha = req("POST", "/admin/v1/tenants", {"name": "Heartbeat Alpha"})["id"]
            beta = req("POST", "/admin/v1/tenants", {"name": "Heartbeat Beta"})["id"]
            base = f"/admin/v1/tenants/{alpha}"
            viewer = req("POST", "/admin/v1/admins", {"name": "Heartbeat viewer", "role": "viewer"})["token"]
            private.append(viewer)
            view = {"x-llm-firewall-admin-token": "Bearer " + viewer}
            creds = {a: req("POST", base + "/agents", {"agent_id": a})["token"] for a in ("edge-hb", "edge-legacy")}
            creds["beta"] = req("POST", f"/admin/v1/tenants/{beta}/agents", {"agent_id": "edge-hb"})["token"]
            private += list(creds.values())
            issuer = req("GET", "/admin/v1/managed-issuer")
            for agent in ("edge-hb", "edge-legacy"):
                req("POST", f"{base}/agents/{agent}/revisions", {"revision": "r-deny", "policy_yaml": "default: deny\n"})
                req("POST", f"{base}/agents/{agent}/revisions/r-deny/approve", {})
                req("POST", f"{base}/agents/{agent}/revisions/r-deny/deploy", {})

            def status_of(agent, tenant=alpha):
                return req("GET", f"/admin/v1/tenants/{tenant}/agent-fleet/{agent}/heartbeat", auth=view)

            def wait_status(agent, wanted, timeout=60, extra=lambda s: True):
                return D.wait_for(f"{agent} heartbeat {wanted}",
                                  lambda: (lambda s: s if s["status"] == wanted and extra(s) else None)(status_of(agent)), timeout=timeout)

            agents = {}

            def start_agent(name, heartbeat, label):
                home = temp / f"home-{name}"
                (home / ".agentfw").mkdir(parents=True, exist_ok=True, mode=0o700)
                port = agents.get(name, {}).get("port") or D.port()
                (home / ".agentfw/config.yaml").write_text(f"port: {port}\nenforce: true\n", encoding="utf-8")
                token_file = home / ".agentfw/enrollment-token"
                if not token_file.exists():
                    token_file.write_text(creds[name], encoding="utf-8")
                    os.chmod(token_file, 0o600)
                agent_env = {k: v for k, v in env.items() if not k.startswith(("SOUP_", "LLM_FW_"))}
                agent_env.update(HOME=str(home), USERPROFILE=str(home), SOUP_MANAGED_AGENT_CONSOLE=console + "/",
                                 SOUP_MANAGED_AGENT_TOKEN_FILE=str(token_file), SOUP_MANAGED_AGENT_TENANT=alpha,
                                 SOUP_MANAGED_AGENT_ID=name, SOUP_MANAGED_AGENT_KEY_ID="heartbeat-issuer",
                                 SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX=issuer["public_key_hex"])
                if heartbeat:
                    agent_env.update(SOUP_MANAGED_AGENT_HEARTBEAT="1", SOUP_MANAGED_AGENT_HEARTBEAT_INTERVAL_SECONDS="5")
                process = D.proc(stack, [str(agent_binary), "serve"], temp, agent_env, temp / f"agent-{name}-{label}.log")
                agents[name] = {"port": port, "home": home, "process": process, "token_file": token_file, "env": agent_env}
                return process

            def witness(name):
                """Independent runtime witness: the Agent's own /health and a /hook decision."""
                a = agents[name]
                health = D.wait_for(f"{name} health", lambda: D.request("GET", f"http://127.0.0.1:{a['port']}/health")[1].get("managed_policy"), timeout=90)
                hook = (a["home"] / ".agentfw" / "token").read_text().strip()
                private.append(hook)
                _, data = D.request("POST", f"http://127.0.0.1:{a['port']}/hook", {
                    "session_id": "heartbeat-witness", "hook_event_name": "PreToolUse", "tool_name": "Bash",
                    "tool_input": {"command": "echo hello"}}, {"Authorization": "Bearer " + hook}, timeout=15)
                decision = "defer" if data == {} else data["hookSpecificOutput"]["permissionDecision"]
                return {"deployment_sequence": health["deployment_sequence"], "policy_sha256": health["policy_sha256"],
                        "revision": health.get("revision"), "hook_decision": decision}

            # Unsupported combination refuses: heartbeat without a managed Console.
            bad_env = {k: v for k, v in env.items() if not k.startswith(("SOUP_", "LLM_FW_"))}
            bad_home = temp / "home-refused"
            (bad_home / ".agentfw").mkdir(parents=True)
            (bad_home / ".agentfw/config.yaml").write_text(f"port: {D.port()}\nenforce: true\n", encoding="utf-8")
            bad_env.update(HOME=str(bad_home), USERPROFILE=str(bad_home), SOUP_MANAGED_AGENT_HEARTBEAT="1")
            refused = subprocess.run([str(agent_binary), "serve"], cwd=temp, env=bad_env, capture_output=True, timeout=60)
            check("heartbeat-without-managed-console-refuses-startup", refused.returncode != 0
                  and b"requires the managed Console configuration" in refused.stdout + refused.stderr)
            bad_env.update(SOUP_MANAGED_AGENT_HEARTBEAT="yes")
            refused = subprocess.run([str(agent_binary), "serve"], cwd=temp, env=bad_env, capture_output=True, timeout=60)
            check("heartbeat-opt-in-value-is-strict", refused.returncode != 0 and b"must be 0 or 1" in refused.stdout + refused.stderr)

            start_agent("edge-hb", True, "first")
            start_agent("edge-legacy", False, "first")
            fresh = wait_status("edge-hb", "fresh", extra=lambda s: (s["reported"] or {}).get("observed_policy") is not None)
            runtime = witness("edge-hb")
            reported = fresh["reported"]["observed_policy"]
            check("fresh-self-report-matches-independent-runtime-witness",
                  reported["deployment_sequence"] == runtime["deployment_sequence"] and reported["policy_sha256"] == runtime["policy_sha256"]
                  and runtime["hook_decision"] == "deny")
            server = req("GET", base + "/agent-fleet/edge-hb", auth=view)["agent"]
            check("server-delivery-record-stays-separate", server["current_liveness"] == "unknown"
                  and server["last_reported_applied"]["policy_sha256"] == reported["policy_sha256"])
            legacy_runtime = witness("edge-legacy")
            legacy = status_of("edge-legacy")
            check("unopted-agent-stays-unsupported", legacy["status"] == "unsupported" and legacy["reported"] is None
                  and legacy_runtime["hook_decision"] == "deny")
            snapshots["fresh"] = {k: fresh[k] for k in ("status", "age_seconds", "expires_after_seconds", "current_credential_generation")}
            snapshots["witness"] = runtime
            seq_before = fresh["reported"]["sequence"]
            check("sequence-advances", wait_status("edge-hb", "fresh", extra=lambda s: s["reported"]["sequence"] > seq_before)["reported"]["sequence"] > seq_before)

            # Protocol probes with the Agent's own credential.
            token = creds["edge-hb"]
            bearer = {"Authorization": "Bearer " + token}
            reg = lambda instance, generation=1, who=("edge-hb", alpha), auth=bearer: code("POST", "/agent/v1/heartbeat/registrations",
                {"contract_version": CONTRACT, "tenant_id": who[1], "agent_id": who[0], "credential_generation": generation, "instance_id": instance}, auth)
            beat = lambda instance, rid, seq, generation=1, auth=bearer: code("POST", "/agent/v1/heartbeats",
                {"contract_version": CONTRACT, "tenant_id": alpha, "agent_id": "edge-hb", "credential_generation": generation, "instance_id": instance,
                 "registration_id": rid, "sequence": seq, "observed_policy": None}, auth)
            probe = secrets.token_hex(16)
            status, body = reg(probe)
            check("probe-registers", status == 201)
            rid = body["registration_id"]
            check("probe-first-heartbeat", beat(probe, rid, 1)[0] == 204)
            replay = beat(probe, rid, 1)
            out_of_order = beat(probe, rid, 0)
            check("replay-refused", replay == (409, {"error": "sequence_replay"}))
            check("non-positive-sequence-refused", out_of_order[0] == 400)
            time.sleep(5)
            check("probe-second-heartbeat", beat(probe, rid, 3)[0] == 204)
            check("out-of-order-refused", beat(probe, rid, 2) == (409, {"error": "sequence_replay"}))
            check("wrong-epoch-refused", reg(probe, generation=7) == (409, {"error": "epoch_mismatch"}))
            check("cross-tenant-refused", reg(probe, who=("edge-hb", alpha), auth={"Authorization": "Bearer " + creds["beta"]}) == (403, {"error": "wrong_agent"}))
            check("admin-token-refused", reg(probe, auth={"Authorization": "Bearer " + owner})[0] == 401)
            check("forged-registration-refused", beat(probe, "0" * 32, 9) == (409, {"error": "registration_superseded"}))
            check("unknown-field-refused", code("POST", "/agent/v1/heartbeats", {"contract_version": CONTRACT, "prompt": "x"}, bearer)[0] == 400)
            # The live Agent was superseded by the probe; it must re-register itself.
            check("live-agent-reregisters-after-supersession",
                  wait_status("edge-hb", "fresh", extra=lambda s: (s["reported"] or {}).get("observed_policy") is not None, timeout=60) is not None)
            check("probe-registration-now-superseded", beat(probe, rid, 10) == (409, {"error": "registration_superseded"}))
            beta_status = status_of("edge-hb", beta)
            check("other-tenant-same-id-isolated", beta_status["status"] == "unsupported" and beta_status["tenant_id"] == beta)

            # Offline: the Agent stops; freshness expires by server time only.
            agents["edge-hb"]["process"].terminate()
            agents["edge-hb"]["process"].wait(timeout=15)
            stale = wait_status("edge-hb", "stale", timeout=150)
            check("offline-becomes-stale", stale["age_seconds"] > stale["expires_after_seconds"])
            snapshots["stale"] = {k: stale[k] for k in ("status", "age_seconds", "expires_after_seconds")}
            # Restart: a new process instance registers anew.
            registered_before = stale["reported"]["registered_at_unix"]
            start_agent("edge-hb", True, "restart")
            restarted = wait_status("edge-hb", "fresh", extra=lambda s: s["reported"]["registered_at_unix"] >= registered_before
                                     and (s["reported"] or {}).get("observed_policy") is not None, timeout=90)
            check("restart-registers-new-instance", restarted["reported"]["sequence"] < 20)

            # Console outage: enforcement unchanged, then reconnect.
            console_process.terminate()
            console_process.wait(timeout=15)
            time.sleep(12)
            during = witness("edge-hb")
            check("console-outage-keeps-enforcement", during["hook_decision"] == "deny"
                  and during["policy_sha256"] == runtime["policy_sha256"])
            console_process = start_console()
            reconnected = wait_status("edge-hb", "fresh", extra=lambda s: (s["reported"] or {}).get("observed_policy") is not None, timeout=120)
            check("reconnect-after-console-restart", reconnected["status"] == "fresh")
            snapshots["after_console_restart"] = {"status": reconnected["status"], "store": args.backend}

            # Rotation: the new credential must register under the new generation.
            replacement = "sw_agent_" + secrets.token_urlsafe(32)[:43]
            private.append(replacement)
            rotated = req("POST", base + "/agents/edge-hb/credential-rotations",
                          {"expected_generation": 1, "operation_id": secrets.token_hex(16), "replacement_token": replacement})
            check("rotation-generation-2", rotated["generation"] == 2)
            check("old-credential-refused-at-once", beat(probe, rid, 11)[0] == 401)
            changed = status_of("edge-hb")
            check("rotation-shows-credential-changed-until-reregistration", changed["status"] in ("credential_changed", "fresh")
                  and (changed["status"] == "credential_changed" or changed["reported"]["credential_generation"] == 2))
            tmp = agents["edge-hb"]["token_file"].with_suffix(".next")
            tmp.write_text(replacement, encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, agents["edge-hb"]["token_file"])
            after_rotation = wait_status("edge-hb", "fresh", extra=lambda s: s["reported"]["credential_generation"] == 2, timeout=120)
            check("same-process-reregisters-with-new-generation", after_rotation["current_credential_generation"] == 2)

            with sync_playwright() as playwright, ExitStack() as browser_stack:
                browser = playwright.chromium.launch(headless=True)
                browser_stack.callback(browser.close)
                page = browser.new_page(viewport={"width": 1366, "height": 1000})
                writes = []
                page.on("request", lambda r: writes.append(r.method) if r.method != "GET" else None)
                page.goto(console + "/admin")
                page.locator("#admin-token").fill(viewer)
                page.locator("#unlock-form button").click()
                expect(page.locator("#console")).to_be_visible()
                page.locator("#tenant-list button").filter(has_text="Heartbeat Alpha").click()
                page.locator("#fleet-list").get_by_role("button", name="edge-hb", exact=True).click()
                expect(page.locator("#heartbeat-status")).to_contain_text("Authenticated self-report received", timeout=20000)
                text = page.locator("#heartbeat-panel").inner_text()
                check("browser-fresh-self-report-not-health", "Self-reported loaded policy: #1 · r-deny" in text
                      and "not runtime attestation" in text and "ealthy" not in text)
                page.locator("#heartbeat-panel").screenshot(path=str(args.output / f"{args.backend}-heartbeat-fresh.png"))
                page.locator("#fleet-list").get_by_role("button", name="edge-legacy", exact=True).click()
                expect(page.locator("#heartbeat-status")).to_contain_text("Not opted in", timeout=20000)
                check("browser-unopted-unknown", "unknown" in page.locator("#heartbeat-status").inner_text())
                # Revocation: refused and shown; enforcement unchanged.
                req("POST", base + "/agents/edge-hb/revoke", {})
                page.locator("#fleet-list").get_by_role("button", name="edge-hb", exact=True).click()
                expect(page.locator("#heartbeat-status")).to_contain_text("Credential revoked", timeout=20000)
                page.locator("#heartbeat-panel").screenshot(path=str(args.output / f"{args.backend}-heartbeat-revoked.png"))
                check("browser-read-only", writes == [] and page.evaluate("localStorage.length + sessionStorage.length") == 0)
            check("revoked-status", status_of("edge-hb")["status"] == "revoked")
            check("revoked-credential-refused", reg(probe, generation=2, auth={"Authorization": "Bearer " + replacement})[0] == 401)
            after = witness("edge-hb")
            check("revocation-keeps-last-verified-enforcement", after["hook_decision"] == "deny" and after["policy_sha256"] == runtime["policy_sha256"])
            for name, a in agents.items():
                log = (temp / f"agent-{name}-first.log").read_bytes() if (temp / f"agent-{name}-first.log").exists() else b""
                check(f"agent-log-free-of-credentials-{name}", all(v.encode() not in log for v in creds.values()))
            report["binaries"] = {p.name: sha(p.read_bytes()) for p in (console_binary, agent_binary)}
            report["config_sha256"] = {"console": sha((console_dir / "firewall.yaml").read_bytes())}
            report["status"] = "passed"
    finally:
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if any(value and value in text for value in private):
            text = json.dumps({"format": FORMAT, "status": "failed", "error": "report withheld: private value found"}, indent=2) + "\n"
        (args.output / f"{args.backend}-report.json").write_text(text, encoding="utf-8")
        for png in args.output.glob(f"{args.backend}-*.png"):
            data = png.read_bytes()
            assert all(value.encode() not in data for value in private if value)
    print(f"{args.backend}: {sum(checks.values())} checks passed" if report["status"] == "passed" else "FAILED")


if __name__ == "__main__":
    main()
