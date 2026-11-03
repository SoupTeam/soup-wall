#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fleet triage overview against a real Console and Agent.

One disposable private Linux deployment per run: a Console on loopback with
SQLite or a disposable TLS PostgreSQL cluster (local binaries, owned CA), the
unchanged `agentfw serve` applying a real signed bundle, and Chromium driving
the Console's triage, fleet, history and rollout panels as Viewer, Operator
and Owner. Agents, deployments, acknowledgements, groups and revocations are
created through the existing admin and Agent APIs. Two recorded states that
no API can produce on demand, an expired deployment record and a day-old
acknowledgement, are made by one direct edit each of this run's own
disposable store. Credentials stay in memory and the private temporary
directory; retained reports and screenshots never contain one.

    python3 scripts/console-fleet-triage-acceptance.py --backend sqlite|postgres --output DIR [--no-build]
"""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import tempfile
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sw-console-fleet-triage-acceptance/1"


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = module("triage_managed_helpers", "managed-policy-demo.py")
PG = module("triage_postgres_helpers", "console-enrollment-acceptance.py")
FLAGS = ["attention", "pending", "rejected", "mismatch", "revoked", "incomplete_history", "no_ack", "stale_ack", "no_history",
         "no_recorded_problem"]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", choices=["sqlite", "postgres"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pg-bin", help="directory with initdb, pg_ctl, createdb and psql")
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
              "scope": "one disposable private Linux deployment; synthetic tenants and Agent IDs; recorded Console "
                       "evidence only, not liveness, production, multi-host or runtime attestation"}

    def check(name, condition):
        checks[name] = bool(condition)
        if not condition:
            raise AssertionError(name)
        print("PASS:", name, flush=True)

    try:
        with tempfile.TemporaryDirectory(prefix="console-triage-") as folder, ExitStack() as stack:
            temp = Path(folder).resolve()
            os.chmod(temp, 0o700)
            private.append(str(temp))
            console_dir, home = temp / "console", temp / "home"
            console_dir.mkdir()
            (home / ".agentfw").mkdir(parents=True, mode=0o700)
            cp, ap = D.port(), D.port()
            console = f"http://127.0.0.1:{cp}"
            owner, seed, untrusted = secrets.token_urlsafe(32), secrets.token_hex(32), secrets.token_hex(32)
            private += [owner, seed, untrusted]
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("SOUP_MANAGED_AGENT_", "SOUP_AGENT_POLICY_", "LLM_FW_", "OPENAI_", "PG"))}
            env.update(LLM_FW_ADMIN_TOKEN=owner, SOUP_AGENT_POLICY_KEY_ID="triage-issuer", SOUP_AGENT_POLICY_SEED_HEX=seed,
                       SOUP_AGENT_POLICY_SEED_HEX_UNTRUSTED=untrusted)
            if args.backend == "postgres":
                url, ca, password, binaries = PG.postgres(stack, temp, PG.pg_bin(args.pg_bin))
                private += [password, url]
                env.update(LLM_FW_POSTGRES_URL=url, LLM_FW_POSTGRES_CA_CERT_FILE=str(ca))
                store = "  backend: postgres\n  postgres_command_timeout_ms: 30000\n  postgres_pool_wait_timeout_ms: 10000\n"
                report["postgres"] = {"server": subprocess.run([str(binaries / "postgres"), "--version"], capture_output=True, text=True).stdout.strip(),
                                      "tls": "sslmode=require with an owned CA", "listen": "127.0.0.1"}

                def edit(sql, *values):
                    # psql variables keep the values out of the command text.
                    words = [str(binaries / "psql"), url, "-v", "ON_ERROR_STOP=1", "-q"]
                    for i, v in enumerate(values, 1):
                        words += ["-v", f"p{i}={v}"]
                    subprocess.run(words, input=sql.encode(), check=True, capture_output=True, timeout=60,
                                   env=dict(os.environ, PGSSLROOTCERT=str(ca)))
            else:
                store = '  backend: sqlite\n  database_path: "triage.sqlite"\n'

                def edit(sql, *values):
                    with sqlite3.connect(console_dir / "triage.sqlite", timeout=30) as db:
                        db.execute(sql.replace(":'p1'", "?").replace(":'p2'", "?"), values)
            (console_dir / "firewall.yaml").write_text(f'bind: "127.0.0.1:{cp}"\ntenant_store:\n  enabled: true\n' + store, encoding="utf-8")
            if args.backend == "postgres":
                migrate = subprocess.run([str(console_binary), "migrate"], cwd=console_dir, env=env, capture_output=True, timeout=120)
                check("postgres-explicit-migration", migrate.returncode == 0)
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

            def code(method, path, auth=None, payload=None):
                try:
                    return D.request(method, console + path, payload, auth, timeout=15)[0]
                except urllib.error.HTTPError as error:
                    return error.code

            alpha = req("POST", "/admin/v1/tenants", {"name": "Triage Alpha"})["id"]
            beta = req("POST", "/admin/v1/tenants", {"name": "Triage Beta"})["id"]
            base = f"/admin/v1/tenants/{alpha}"
            tokens = {"owner": owner}
            for role in ("viewer", "operator"):
                tokens[role] = req("POST", "/admin/v1/admins", {"name": f"Triage {role}", "role": role})["token"]
            private += list(tokens.values())
            auth = {role: {"x-llm-firewall-admin-token": "Bearer " + t} for role, t in tokens.items()}
            names = ["edge-applied", "edge-rejected", "edge-pending", "edge-delivered", "edge-mismatch", "edge-revoked",
                     "edge-fresh", "edge-gap", "edge-old"]
            creds = {n: req("POST", base + "/agents", {"agent_id": n})["token"] for n in names}
            for n in range(30):
                req("POST", base + "/agents", {"agent_id": f"bulk-{n:02d}"})
            creds["beta"] = req("POST", f"/admin/v1/tenants/{beta}/agents", {"agent_id": "edge-applied"})["token"]
            private += list(creds.values())
            issuer = req("GET", "/admin/v1/managed-issuer")

            def revision(agent, name, yaml):
                req("POST", f"{base}/agents/{agent}/revisions", {"revision": name, "policy_yaml": yaml})
                req("POST", f"{base}/agents/{agent}/revisions/{name}/approve", {})

            def deploy(agent, name, payload=None):
                return req("POST", f"{base}/agents/{agent}/revisions/{name}/deploy", payload or {})

            def agent_call(agent, method, path, payload=None):
                return D.request(method, console + path, payload, {"Authorization": "Bearer " + creds[agent]}, timeout=15)

            def ack(agent, d, status):
                return agent_call(agent, "POST", "/agent/v1/policy/ack", {"deployment_sequence": d["deployment_sequence"],
                                  "revision": d["revision"], "policy_sha256": d["policy_sha256"], "status": status})

            def triage(query="problem=all&limit=100", role="viewer", tenant=alpha):
                return req("GET", f"/admin/v1/tenants/{tenant}/agent-triage?{query}", auth=auth[role])

            for agent in ("edge-applied", "edge-rejected", "edge-pending", "edge-delivered", "edge-mismatch", "edge-gap", "edge-old"):
                revision(agent, "r1", "default: deny\n")
            revision("edge-mismatch", "r2", "default: allow\n")
            # A real Agent applies its signed bundle.
            deploy("edge-applied", "r1")
            (home / ".agentfw/config.yaml").write_text(f"port: {ap}\nenforce: true\n", encoding="utf-8")
            agent_env = {k: v for k, v in env.items() if not k.startswith(("SOUP_", "LLM_FW_"))}
            agent_env.update(HOME=str(home), USERPROFILE=str(home), SOUP_MANAGED_AGENT_CONSOLE=console + "/",
                             SOUP_MANAGED_AGENT_TOKEN=creds["edge-applied"], SOUP_MANAGED_AGENT_TENANT=alpha,
                             SOUP_MANAGED_AGENT_ID="edge-applied", SOUP_MANAGED_AGENT_KEY_ID="triage-issuer",
                             SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX=issuer["public_key_hex"])
            process = D.proc(stack, [str(agent_binary), "serve"], temp, agent_env, temp / "agent.log")
            D.wait_for("real Agent applied", lambda: req("GET", base + "/agent-fleet/edge-applied")["agent"]["latest_issued"]["recorded_state"] == "applied" or None, timeout=90)
            process.terminate()
            process.wait(timeout=10)
            # The other outcomes through the existing Agent API with each Agent's own credential.
            check("agent-api-rejection", ack("edge-rejected", deploy("edge-rejected", "r1"), "rejected")[0] == 204)
            pending = deploy("edge-pending", "r1")
            deploy("edge-delivered", "r1")
            check("agent-api-fetch", agent_call("edge-delivered", "GET", "/agent/v1/policy")[0] == 200)
            ack("edge-mismatch", deploy("edge-mismatch", "r1"), "applied")
            deploy("edge-mismatch", "r2")
            for _ in range(2):
                deploy("edge-gap", "r1")
            ack("edge-gap", deploy("edge-gap", "r1"), "applied")
            ack("edge-old", deploy("edge-old", "r1"), "applied")
            req("POST", base + "/agents/edge-revoked/revoke", {})
            req("POST", base + "/groups", {"group_id": "fleet", "name": "Triage fleet"})
            for agent, pilot in (("edge-applied", True), ("edge-old", False)):
                req("POST", base + "/groups/fleet/members", {"agent_id": agent, "is_pilot": pilot})
            # Expired history and an old acknowledgement in this run's own store.
            edit("DELETE FROM managed_agent_deployments WHERE tenant_id=:'p1' AND agent_id='edge-gap' AND deployment_sequence=1", alpha)
            edit("UPDATE managed_agent_deployments SET applied_at_unix=applied_at_unix-172800 WHERE tenant_id=:'p1' AND agent_id='edge-old'", alpha)

            full = triage()
            problems = {a["agent_id"]: a["problems"] for a in full["agents"]}
            expected = {"edge-applied": [], "edge-rejected": ["rejected", "no_ack"], "edge-pending": ["pending", "no_ack"],
                        "edge-delivered": ["pending", "no_ack"], "edge-mismatch": ["pending", "mismatch"],
                        "edge-revoked": ["revoked", "no_history"], "edge-fresh": ["no_history"], "edge-gap": ["incomplete_history"],
                        "edge-old": ["stale_ack"]}
            check("projection-flags", all(problems[k] == v for k, v in expected.items())
                  and all(problems[f"bulk-{n:02d}"] == ["no_history"] for n in range(30)))
            counts = full["counts"]
            check("projection-counts", (counts["counted_agents"], counts["attention"], counts["no_recorded_problem"], counts["pending"],
                                        counts["no_history"], counts["complete"]) == (39, 38, 1, 3, 32, True))
            check("projection-unknown-liveness", all(a["current_liveness"] == "unknown" and a["runtime_coverage"] == "unknown" for a in full["agents"]))
            check("projection-group-links", next(a for a in full["agents"] if a["agent_id"] == "edge-old")["first_group_id"] == "fleet")
            snapshots["counts"] = counts
            for role in ("viewer", "operator", "owner"):
                check(f"read-{role}", code("GET", base + "/agent-triage", auth[role]) == 200)
            check("no-session-401", code("GET", base + "/agent-triage") == 401)
            check("agent-credential-401", code("GET", base + "/agent-triage", {"x-llm-firewall-admin-token": "Bearer " + creds["edge-old"]}) == 401)
            check("unknown-tenant-404", code("GET", "/admin/v1/tenants/unknown/agent-triage", auth["viewer"]) == 404)
            check("invalid-queries-400", {code("GET", base + "/agent-triage?" + q, auth["viewer"]) for q in
                                          ("limit=101", "problem=healthy", "sort=x", "ack_age_seconds=1", "after=..%2Fx", "extra=1")} == {400})
            check("post-not-a-mutation", code("POST", base + "/agent-triage", auth["owner"], {}) in (404, 405))
            other = triage(tenant=beta)
            check("tenant-isolation", other["counts"]["counted_agents"] == 1 and other["agents"][0]["tenant_id"] == beta
                  and other["agents"][0]["problems"] == ["no_history"])
            raw = json.dumps(full)
            check("projection-no-private-fields", all(w not in raw for w in ("token_hash", "policy_yaml", "bundle_json", "signature_hex", "default: deny"))
                  and all(v not in raw for v in private))
            before_state = json.dumps(req("GET", base + "/agents")) + json.dumps(req("GET", base + "/groups/fleet/members"))
            # A tenant above the count bound: counts and pages share the first
            # 10,000 Agents by ID; the one after it is neither counted nor listed.
            large = req("POST", "/admin/v1/tenants", {"name": "Triage Large"})["id"]
            for n in range(10_000):
                req("POST", f"/admin/v1/tenants/{large}/agents", {"agent_id": f"agent-{n:05d}"})
            creds["agent-10000"] = req("POST", f"/admin/v1/tenants/{large}/agents", {"agent_id": "agent-10000"})["token"]
            private.append(creds["agent-10000"])
            lbase = f"/admin/v1/tenants/{large}/agents/agent-10000"
            req("POST", lbase + "/revisions", {"revision": "r1", "policy_yaml": "default: deny\n"})
            req("POST", lbase + "/revisions/r1/approve", {})
            check("outside-agent-applied", ack("agent-10000", req("POST", lbase + "/revisions/r1/deploy", {}), "applied")[0] == 204)
            outside = []
            for query in ("problem=all&prefix=agent-10000", "problem=no_recorded_problem&sort=ack_oldest",
                          "problem=all&sort=ack_oldest&prefix=agent-1&limit=100"):
                body = triage(query, tenant=large)
                outside.append((body["counts"]["complete"], body["counts"]["counted_agents"], body["counts"]["matching"],
                                [a["agent_id"] for a in body["agents"] if a["agent_id"] == "agent-10000"]))
            check("bounded-universe-pages-match-counts", all(c is False and n == 10_000 and listed == [] for c, n, _, listed in outside)
                  and outside[0][2] == 0)
            snapshots["bounded_universe"] = [{"complete": c, "counted_agents": n, "matching": m} for c, n, m, _ in outside]

            with sync_playwright() as playwright, ExitStack() as browser_stack:
                browser = playwright.chromium.launch(headless=True)
                browser_stack.callback(browser.close)
                context = browser.new_context(viewport={"width": 1366, "height": 1000})
                page = context.new_page()
                writes = []
                page.on("request", lambda r: writes.append((r.method, r.url)) if r.method != "GET" else None)

                def login(role="viewer"):
                    page.goto(console + "/admin")
                    page.locator("#admin-token").fill(tokens[role])
                    page.locator("#unlock-form button").click()
                    expect(page.locator("#console")).to_be_visible()

                def tenant(name):
                    page.locator("#tenant-list button").filter(has_text=name).click()

                def status(text):
                    expect(page.locator("#triage-status")).to_contain_text(text, timeout=20000)

                def count(key):
                    return page.locator(f"#triage-summary [data-problem='{key}'] strong").inner_text()

                def listed():
                    return page.locator("#triage-list tbody tr td:first-child").all_inner_texts()

                def apply(problem=None, sort=None):
                    if problem:
                        page.locator("#triage-problem").select_option(problem)
                    if sort:
                        page.locator("#triage-sort").select_option(sort)
                    page.locator("#triage-filter button[type=submit]").click()

                login()
                tenant("Triage Alpha")
                status("Page 1")
                check("browser-counts-match-projection", [count(k) for k in FLAGS] == [str(counts[k]) for k in FLAGS])
                check("browser-denominator-and-no-health-claim", "Seen 25 of 38 matching" in page.locator("#triage-status").inner_text()
                      and "of 39" in page.locator("#triage-summary").inner_text()
                      and "not proof of health" in page.locator("#triage-summary").inner_text())
                page.locator("#triage-next").click()
                status("Page 2")
                check("browser-second-page", "Seen 38 of 38" in page.locator("#triage-status").inner_text()
                      and "edge-gap" in listed() and page.locator("#triage-next").is_disabled())
                page.locator("#triage-prefix").fill("edge-")
                apply("all")
                status("Seen 9 of 9")
                check("browser-prefix-all-outcomes", listed() == sorted(expected))
                page.locator("#triage-panel").screenshot(path=str(args.output / f"{args.backend}-triage-edge.png"))
                page.locator("#triage-prefix").fill("")
                apply("rejected")
                status("Seen 1 of 1")
                check("browser-filter-rejected", listed() == ["edge-rejected"])
                apply("no_recorded_problem")
                status("Seen 1 of 1")
                check("browser-no-recorded-problem-is-not-health", listed() == ["edge-applied"]
                      and "not proof of health" in page.locator("#triage-list").inner_text())
                apply("stale_ack")
                status("Seen 1 of 1")
                check("browser-old-acknowledgement-historical", listed() == ["edge-old"] and "historical" in page.locator("#triage-list").inner_text())
                apply("all", "ack_oldest")
                status("Page 1")
                first = listed()
                check("browser-ack-oldest-sort", first[0] == "bulk-00" and "edge-old" not in first[:20])
                # Deep links into the accepted history and rollout modules.
                apply("incomplete_history", "agent_id")
                status("Seen 1 of 1")
                page.get_by_role("button", name="Open recorded history for edge-gap").click()
                expect(page.locator("#history-status")).to_contain_text("History for edge-gap", timeout=20000)
                check("deep-link-history", "earlier sequences are absent" in page.locator("#history-summary").inner_text())
                apply("stale_ack")
                status("Seen 1 of 1")
                page.get_by_role("button", name="Open rollout group fleet for edge-old").click()
                page.wait_for_function("() => document.getElementById('rollout-group').value === 'fleet'")
                check("deep-link-rollout", True)
                # Concurrent acknowledgement: the next read reflects the server.
                apply("pending")
                status("Seen 3 of 3")
                check("concurrent-ack-recorded", ack("edge-pending", pending, "applied")[0] == 204)
                page.locator("#triage-refresh").click()
                status("Seen 2 of 2")
                check("concurrent-ack-reflected", "edge-pending" not in listed() and count("pending") == "2")
                # A delayed page after a tenant switch is discarded.
                apply("attention")
                status("Page 1")
                held = []
                later = lambda u: "/agent-triage?" in u and "after=" in u
                page.route(later, lambda route: held.append(route))
                page.locator("#triage-next").click()
                status("Loading the next page")
                tenant("Triage Beta")
                status("Seen 1 of 1")
                held[0].continue_()
                page.unroute(later)
                page.wait_for_timeout(500)
                check("stale-page-after-tenant-switch-discarded", listed() == ["edge-applied"] and "of 1" in page.locator("#triage-summary").inner_text())
                check("browser-no-writes-url-or-storage", writes == [] and page.url == console + "/admin"
                      and page.evaluate("localStorage.length + sessionStorage.length") == 0)
                check("triage-changed-nothing", json.dumps(req("GET", base + "/agents")) + json.dumps(req("GET", base + "/groups/fleet/members")) == before_state)
                # Restart: unavailable, then the same recorded counts.
                console_process.terminate()
                console_process.wait(timeout=15)
                page.locator("#triage-refresh").click()
                status("Unable to load")
                check("unavailable-console-clears", listed() == [] and page.locator("#triage-summary").inner_text() == "")
                console_process = start_console()
                for role in ("operator", "owner", "viewer"):
                    login(role)
                    tenant("Triage Alpha")
                    status("Page 1")
                    check(f"browser-{role}-after-restart", count("attention") == "37"
                          and page.locator("#triage-panel button.danger").count() == 0)
                page.set_viewport_size({"width": 390, "height": 900})
                check("narrow-no-horizontal-overflow", page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"))
                page.set_viewport_size({"width": 1366, "height": 1000})
                tenant("Triage Large")
                status("among the first 10000 Agents by ID")
                check("browser-bounded-universe-wording", "later Agents are neither counted nor listed" in page.locator("#triage-summary").inner_text()
                      and "Seen 25 of 10000 matching" in page.locator("#triage-status").inner_text())
                page.locator("#triage-prefix").fill("agent-10000")
                apply("all")
                status("Seen 0 of 0")
                check("browser-outside-agent-not-listed", listed() == [])
                page.locator("#triage-panel").screenshot(path=str(args.output / f"{args.backend}-triage-narrow.png"))
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
