#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Recorded Agent history and incident snapshot against a real Console and Agent.

One disposable private Linux deployment per run: a Console on loopback with
SQLite or a disposable TLS PostgreSQL cluster (local binaries, owned CA), the
unchanged `agentfw serve` applying and rejecting real signed bundles, and
Chromium driving the Console's fleet and history panels as a Viewer. Agent
records are created only through the existing admin and Agent APIs.
Credentials stay in this process's memory and the run's private temporary
directory; the retained report, snapshots and screenshots never contain one.

    python3 scripts/console-agent-history-acceptance.py --backend sqlite|postgres --output DIR [--no-build]
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
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sw-console-agent-history-acceptance/1"


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = module("history_managed_helpers", "managed-policy-demo.py")
PG = module("history_postgres_helpers", "console-enrollment-acceptance.py")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def kinds(page):
    return [t.split(" · ")[0] for t in page.locator("#history-timeline li").all_inner_texts()]


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
              "scope": "one disposable private Linux deployment; synthetic tenants and Agent IDs; recorded Console "
                       "evidence only, not production, multi-host or runtime attestation"}

    def check(name, condition):
        checks[name] = bool(condition)
        if not condition:
            raise AssertionError(name)
        print("PASS:", name, flush=True)

    try:
        with tempfile.TemporaryDirectory(prefix="console-history-") as folder, ExitStack() as stack:
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
            env.update(LLM_FW_ADMIN_TOKEN=owner, SOUP_AGENT_POLICY_KEY_ID="history-issuer", SOUP_AGENT_POLICY_SEED_HEX=seed,
                       SOUP_AGENT_POLICY_SEED_HEX_UNTRUSTED=untrusted)
            if args.backend == "postgres":
                url, ca, password, binaries = PG.postgres(stack, temp, PG.pg_bin(args.pg_bin))
                private += [password, url]
                env.update(LLM_FW_POSTGRES_URL=url, LLM_FW_POSTGRES_CA_CERT_FILE=str(ca))
                store = "  backend: postgres\n  postgres_command_timeout_ms: 30000\n  postgres_pool_wait_timeout_ms: 10000\n"
                version = subprocess.run([str(binaries / "postgres"), "--version"], capture_output=True, text=True).stdout.strip()
                report["postgres"] = {"server": version, "tls": "sslmode=require with an owned CA", "listen": "127.0.0.1"}
            else:
                store = '  backend: sqlite\n  database_path: "history.sqlite"\n'
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
                return D.request(method, console + path, payload, auth, timeout=10)[1]

            def code(method, path, auth=None, payload=None):
                try:
                    return D.request(method, console + path, payload, auth, timeout=10)[0]
                except urllib.error.HTTPError as error:
                    return error.code

            alpha = req("POST", "/admin/v1/tenants", {"name": "History Alpha"})["id"]
            beta = req("POST", "/admin/v1/tenants", {"name": "History Beta"})["id"]
            base = f"/admin/v1/tenants/{alpha}"
            viewer = req("POST", "/admin/v1/admins", {"name": "History viewer", "role": "viewer"})["token"]
            operator = req("POST", "/admin/v1/admins", {"name": "History operator", "role": "operator"})["token"]
            private += [viewer, operator]
            view = {"x-llm-firewall-admin-token": "Bearer " + viewer}
            creds = {}
            for agent in ("edge-history", "edge-many", "edge-revoked"):
                creds[agent] = req("POST", base + "/agents", {"agent_id": agent})["token"]
            creds["beta"] = req("POST", f"/admin/v1/tenants/{beta}/agents", {"agent_id": "edge-history"})["token"]
            private += list(creds.values())
            issuer = req("GET", "/admin/v1/managed-issuer")

            def revision(agent, name, yaml):
                req("POST", f"{base}/agents/{agent}/revisions", {"revision": name, "policy_yaml": yaml})
                req("POST", f"{base}/agents/{agent}/revisions/{name}/approve", {})

            def deploy(agent, name, payload=None):
                return req("POST", f"{base}/agents/{agent}/revisions/{name}/deploy", payload or {})

            def detail(agent, tenant=alpha):
                return req("GET", f"/admin/v1/tenants/{tenant}/agent-fleet/{agent}", auth=view)

            def wait_state(agent, sequence, state):
                return D.wait_for(f"{agent} #{sequence} {state}", lambda: (lambda d: d if d["agent"]["latest_issued"]["sequence"] == str(sequence)
                                  and d["agent"]["latest_issued"]["recorded_state"] == state else None)(detail(agent)), timeout=90)

            policies = {"r1": "default: deny\n", "r2": "default: allow\n"}
            for name, yaml in policies.items():
                revision("edge-history", name, yaml)
            (home / ".agentfw/config.yaml").write_text(f"port: {ap}\nenforce: true\n", encoding="utf-8")
            agent_env = {k: v for k, v in env.items() if not k.startswith(("SOUP_", "LLM_FW_"))}
            agent_env.update(HOME=str(home), USERPROFILE=str(home), SOUP_MANAGED_AGENT_CONSOLE=console + "/",
                             SOUP_MANAGED_AGENT_TOKEN=creds["edge-history"], SOUP_MANAGED_AGENT_TENANT=alpha,
                             SOUP_MANAGED_AGENT_ID="edge-history", SOUP_MANAGED_AGENT_KEY_ID="history-issuer",
                             SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX=issuer["public_key_hex"])
            # 1 applied by the real Agent.
            deploy("edge-history", "r1")
            agent = D.proc(stack, [str(agent_binary), "serve"], temp, agent_env, temp / "agent-1.log")
            wait_state("edge-history", 1, "applied")
            agent.terminate()
            agent.wait(timeout=10)
            # 2 issued and superseded; 3 signed by an untrusted key and rejected
            # by the real Agent; 4 a rollback the Agent applies.
            deploy("edge-history", "r2")
            deploy("edge-history", "r2", {"issuer_key_id": "untrusted"})
            agent = D.proc(stack, [str(agent_binary), "serve"], temp, agent_env, temp / "agent-2.log")
            wait_state("edge-history", 3, "rejected")
            deploy("edge-history", "r1", {"rollback": True})
            wait_state("edge-history", 4, "applied")
            agent.terminate()
            agent.wait(timeout=10)
            # 5 fetched with the Agent credential and never acknowledged.
            deploy("edge-history", "r2")
            fetched = D.request("GET", console + "/agent/v1/policy", None, {"Authorization": "Bearer " + creds["edge-history"]}, timeout=10)
            check("agent-fetch-recorded", fetched[0] == 200 and wait_state("edge-history", 5, "delivered"))
            # A credential rotation (no dated record exists for it).
            replacement = "sw_agent_" + secrets.token_urlsafe(32)[:43]
            private.append(replacement)
            rotated = req("POST", f"{base}/agents/edge-history/credential-rotations",
                          {"expected_generation": 1, "operation_id": secrets.token_hex(16), "replacement_token": replacement})
            check("rotation-through-existing-api", rotated["generation"] == 2)
            # Many records for paging, and a revoked Agent with a pending deployment.
            revision("edge-many", "r1", policies["r1"])
            for _ in range(56):
                deploy("edge-many", "r1")
            revision("edge-revoked", "r1", policies["r1"])
            deploy("edge-revoked", "r1")
            req("POST", f"{base}/agents/edge-revoked/revoke", {})
            history = detail("edge-history")
            check("store-mixed-history", [d["recorded_state"] for d in history["deployments"]] == ["delivered", "applied", "rejected", "issued", "applied"])
            snapshots["store_detail_edge_history"] = history
            # Existing read authorization: Viewer and Operator read; no session,
            # an Agent credential or another tenant's path cannot.
            fleet = base + "/agent-fleet/edge-history"
            check("viewer-and-operator-read", code("GET", fleet, view) == 200
                  and code("GET", fleet, {"x-llm-firewall-admin-token": "Bearer " + operator}) == 200)
            check("no-session-refused", code("GET", fleet) == 401)
            check("agent-credential-refused", code("GET", fleet, {"x-llm-firewall-admin-token": "Bearer " + replacement}) == 401)
            check("cross-tenant-agent-404", code("GET", f"/admin/v1/tenants/{beta}/agent-fleet/edge-many", view) == 404)
            check("same-id-other-tenant-isolated", detail("edge-history", beta)["agent"]["latest_issued"] is None)
            before_state = {a: detail(a) for a in ("edge-history", "edge-many", "edge-revoked")}
            before_generation = req("GET", base + "/agents")

            with sync_playwright() as playwright, ExitStack() as browser_stack:
                browser = playwright.chromium.launch(headless=True)
                browser_stack.callback(browser.close)
                context = browser.new_context(viewport={"width": 1366, "height": 1000}, accept_downloads=True)
                page = context.new_page()
                writes = []
                page.on("request", lambda r: writes.append((r.method, r.url)) if r.method != "GET" else None)

                def login():
                    page.goto(console + "/admin")
                    page.locator("#admin-token").fill(viewer)
                    page.locator("#unlock-form button").click()
                    expect(page.locator("#console")).to_be_visible()

                def tenant(name):
                    page.locator("#tenant-list button").filter(has_text=name).click()
                    expect(page.locator("#fleet-list")).to_contain_text("edge-history")

                def pick(agent):
                    page.locator("#fleet-list").get_by_role("button", name=agent, exact=True).click()

                def status(text):
                    expect(page.locator("#history-status")).to_contain_text(text, timeout=20000)

                def download():
                    with page.expect_download() as info:
                        page.locator("#history-download").click()
                    item = info.value
                    return item.suggested_filename, Path(item.path()).read_text(encoding="utf-8")

                login()
                tenant("History Alpha")
                pick("edge-history")
                status("No older pages")
                check("browser-mixed-timeline", kinds(page) == ["Enrolled", "Issued", "Applied", "Issued", "Superseded", "Issued",
                                                                "Rejected", "Issued", "Applied", "Issued", "Fetched", "Pending"])
                summary = page.locator("#history-summary").inner_text()
                check("browser-unresolved-and-unknown-protection", "2 unresolved outcome(s)" in summary
                      and "Current protection and liveness: unknown" in summary and "Loaded 5 of 5" in summary)
                check("browser-historical-applied-links", page.locator("#history-summary a").evaluate_all(
                    "a => a.map(x => x.getAttribute('href'))") == ["#history-dep-5", "#history-dep-4"])
                page.locator("#history-panel").screenshot(path=str(args.output / f"{args.backend}-timeline-mixed.png"))
                name, text = download()
                full = json.loads(text)
                check("export-complete-records-not-healthy", full["completeness"]["status"] == "complete_records" and not full["partial"]
                      and full["summary"]["current_protection"] == "unknown" and not name.endswith("-partial.json"))
                check("export-scope-and-source-ids", full["scope"] == {"tenant_id": alpha, "agent_id": "edge-history"}
                      and all(e["event_id"].startswith(f"{alpha}/edge-history/") for e in full["events"])
                      and len({e["event_id"] for e in full["events"]}) == len(full["events"]))
                dated = [e["at_unix"] for e in full["events"] if e["at_unix"] is not None]
                check("export-dated-events-chronological", dated == sorted(dated) and len(dated) == 8)
                check("export-names-unrecorded-rotation", "credential_rotations_not_recorded" in [r["code"] for r in full["completeness"]["reasons"]])
                exports = {"edge-history": text}
                # Pagination: 56 records, 50 per page.
                pick("edge-many")
                status("Older records may exist")
                check("browser-first-page-denominator", "Loaded 50 of 56 deployment records in 1 page(s)" in page.locator("#history-summary").inner_text())
                page.locator("#history-preview").click()
                expect(page.locator("#history-snapshot")).to_be_visible()
                partial = json.loads(page.locator("#history-snapshot").text_content())
                check("export-partial-denominators", partial["partial"] and partial["coverage"]["expected_deployments"] == 56
                      and partial["coverage"]["loaded_deployments"] == 50 and partial["coverage"]["missing_sequence_ranges"] == [[1, 6]])
                page.locator("#history-panel").screenshot(path=str(args.output / f"{args.backend}-partial-preview.png"))
                name, exports["edge-many-partial"] = download()
                check("partial-download-marked", name.endswith("-partial.json") and json.loads(exports["edge-many-partial"])["partial"])
                page.locator("#history-more").click()
                status("No older pages")
                check("browser-second-page-completes", "Loaded 56 of 56 deployment records in 2 page(s)" in page.locator("#history-summary").inner_text())
                pick("edge-revoked")
                status("No older pages")
                check("browser-revoked-pending-stays-unresolved", kinds(page) == ["Enrolled", "Issued", "Pending", "Revoked"])
                # A delayed reply after a tenant switch is discarded.
                held = []
                page.route("**/agent-fleet/edge-history?limit=50", lambda route: held.append(route))
                pick("edge-history")
                status("Loading")
                tenant("History Beta")
                held[0].continue_()
                page.unroute("**/agent-fleet/edge-history?limit=50")
                page.wait_for_timeout(500)
                check("browser-stale-tenant-reply-discarded", kinds(page) == [] and "Select an Agent" in page.locator("#history-status").inner_text())
                pick("edge-history")
                status("No older pages")
                check("browser-same-id-other-tenant", kinds(page) == ["Enrolled"])
                check("browser-no-writes-or-storage", writes == [] and page.evaluate("localStorage.length + sessionStorage.length") == 0)
                check("export-changed-nothing", {a: detail(a)["deployments"] for a in before_state} == {a: s["deployments"] for a, s in before_state.items()}
                      and req("GET", base + "/agents") == before_generation)
                # Restart and reconcile: the same records give the same events.
                console_process.terminate()
                console_process.wait(timeout=15)
                pick("edge-history")
                status("Unable to load")
                check("browser-unavailable-console-visible", kinds(page) == [] and page.locator("#history-download").is_disabled())
                console_process = start_console()
                login()
                tenant("History Alpha")
                pick("edge-history")
                status("No older pages")
                name, again = download()
                after = json.loads(again)
                strip = lambda s: [{k: v for k, v in e.items()} for e in s["events"]]
                check("restart-same-event-identities", strip(after) == strip(full) and after["coverage"]["loaded_deployments"] == 5)
                page.set_viewport_size({"width": 390, "height": 900})
                page.locator("#history-preview").click()
                check("narrow-no-horizontal-overflow", page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"))
                page.locator("#history-panel").screenshot(path=str(args.output / f"{args.backend}-narrow.png"))
                exports["edge-history-after-restart"] = again
            for label, text in exports.items():
                check("export-free-of-private-values-" + label, all(value not in text for value in private)
                      and all(word not in text for word in ("token_hash", "policy_yaml", "bundle_json", "signature_hex", "default: allow", "default: deny")))
                (args.output / f"{args.backend}-snapshot-{label}.json").write_text(text, encoding="utf-8")
            report["binaries"] = {p.name: sha(p.read_bytes()) for p in (console_binary, agent_binary)}
            report["config_sha256"] = {"console": sha((console_dir / "firewall.yaml").read_bytes())}
            report["status"] = "passed"
    finally:
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
        leaked = [i for i, value in enumerate(private) if value and value in text]
        if leaked:
            text = json.dumps({"format": FORMAT, "status": "failed", "error": "report withheld: private value found"}, indent=2) + "\n"
        (args.output / f"{args.backend}-report.json").write_text(text, encoding="utf-8")
        for png in args.output.glob("*.png"):
            data = png.read_bytes()
            assert all(value.encode() not in data for value in private if value)
    print(f"{args.backend}: {sum(checks.values())} checks passed" if report["status"] == "passed" else "FAILED")


if __name__ == "__main__":
    main()
