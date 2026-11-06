#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Agent policy rejection reasons against a real Console and Agent (SOU-241).

One disposable private Linux deployment per run: a Console on loopback with
SQLite or a disposable TLS PostgreSQL cluster (local binaries, owned CA), and
the unchanged `agentfw serve` verifying real signed bundles. The real Agent
rejects an untrusted issuer, an expired bundle (Agent clock moved forward with
an owned LD_PRELOAD shim) and an invalid policy (an approved invalid revision
inserted into the owned disposable store, because the Console refuses one at
authoring), and reports a transient native-boundary refusal as pending only.
A corrected signed redeploy is applied and witnessed through the Agent's own
/health and /hook. Chromium drives the history, fleet and policy panels as a
Viewer. Credentials stay in this process's memory and the run's private
temporary directory; the retained report, snapshots and screenshots never
contain one.

    python3 scripts/console-agent-rejection-acceptance.py --backend sqlite|postgres --output DIR [--no-build]
"""
import argparse
from contextlib import ExitStack
import fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sw-console-agent-rejection-acceptance/1"
SHIM = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <time.h>
static int (*real_clock_gettime)(clockid_t, struct timespec *);
int clock_gettime(clockid_t id, struct timespec *ts) {
    if (!real_clock_gettime) real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
    int rc = real_clock_gettime(id, ts);
    const char *offset = getenv("SW_ACCEPTANCE_CLOCK_OFFSET_SECONDS");
    if (rc == 0 && offset && (id == CLOCK_REALTIME || id == CLOCK_REALTIME_COARSE)) ts->tv_sec += atol(offset);
    return rc;
}
"""


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = module("rejection_managed_helpers", "managed-policy-demo.py")
PG = module("rejection_postgres_helpers", "console-enrollment-acceptance.py")
R = module("rejection_recovery", "console_recovery.py")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def older_console(stack, upstream, seen):
    """A loopback stand-in for a Console that predates reason codes: it
    refuses an acknowledgement carrying the new field with 422 (strict JSON,
    as the existing extractor does) and forwards everything else unchanged."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def relay(self, body=None):
            if body is not None and self.path == "/agent/v1/policy/ack" and "rejection" in json.loads(body):
                seen.append("refused-new-field")
                self.send_response(422)
                self.send_header("content-length", "0")
                self.end_headers()
                return
            if body is not None and self.path == "/agent/v1/policy/ack":
                seen.append("forwarded-legacy" if json.loads(body).get("status") == "rejected" else "forwarded-other")
            request = urllib.request.Request(upstream + self.path, data=body, method=self.command,
                                             headers={k: v for k, v in self.headers.items() if k.lower() in ("authorization", "content-type")})
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    status, data = response.status, response.read()
            except urllib.error.HTTPError as error:
                status, data = error.code, error.read()
            self.send_response(status)
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self.relay()

        def do_POST(self):
            self.relay(self.rfile.read(int(self.headers.get("content-length", "0"))))

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    stack.callback(server.shutdown)
    return f"http://127.0.0.1:{server.server_address[1]}"


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
              "fault_injection": {"expiry": "owned LD_PRELOAD shim adds +7200 s to the Agent's CLOCK_REALTIME only",
                                  "invalid_policy": "one approved invalid revision row inserted into the owned disposable store",
                                  "transient_activation": "a shared flock on the Agent's own managed-native-boundary.lock"},
              "scope": "one disposable private Linux deployment; synthetic tenants and Agent IDs; recorded Console "
                       "evidence and one local Agent, not production, multi-host or runtime attestation"}

    def check(name, condition):
        checks[name] = bool(condition)
        if not condition:
            raise AssertionError(name)
        print("PASS:", name, flush=True)

    try:
        with tempfile.TemporaryDirectory(prefix="console-rejection-") as folder, ExitStack() as stack:
            temp = Path(folder).resolve()
            os.chmod(temp, 0o700)
            private.append(str(temp))
            console_dir, home = temp / "console", temp / "home"
            console_dir.mkdir()
            (home / ".agentfw").mkdir(parents=True, mode=0o700)
            shim = temp / "clock-offset.so"
            (temp / "clock-offset.c").write_text(SHIM, encoding="utf-8")
            subprocess.run(["cc", "-shared", "-fPIC", "-O2", "-o", str(shim), str(temp / "clock-offset.c"), "-ldl"], check=True, timeout=120)
            cp, ap = D.port(), D.port()
            console, agent_url = f"http://127.0.0.1:{cp}", f"http://127.0.0.1:{ap}"
            owner, seed, untrusted = secrets.token_urlsafe(32), secrets.token_hex(32), secrets.token_hex(32)
            private += [owner, seed, untrusted]
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("SOUP_MANAGED_AGENT_", "SOUP_AGENT_POLICY_", "LLM_FW_", "OPENAI_", "PG", "LD_PRELOAD"))}
            env.update(LLM_FW_ADMIN_TOKEN=owner, SOUP_AGENT_POLICY_KEY_ID="rejection-issuer", SOUP_AGENT_POLICY_SEED_HEX=seed,
                       SOUP_AGENT_POLICY_SEED_HEX_UNTRUSTED=untrusted)
            if args.backend == "postgres":
                url, ca, password, binaries = PG.postgres(stack, temp, PG.pg_bin(args.pg_bin))
                private += [password, url]
                verified_url = url.replace("sslmode=require", f"sslmode=verify-full&sslrootcert={ca}")
                env.update(LLM_FW_POSTGRES_URL=url, LLM_FW_POSTGRES_CA_CERT_FILE=str(ca))
                store = "  backend: postgres\n  postgres_command_timeout_ms: 30000\n  postgres_pool_wait_timeout_ms: 10000\n"
                version = subprocess.run([str(binaries / "postgres"), "--version"], capture_output=True, text=True).stdout.strip()
                report["postgres"] = {"server": version, "tls": "sslmode=require with an owned CA", "listen": "127.0.0.1"}
            else:
                store = '  backend: sqlite\n  database_path: "rejection.sqlite"\n'
            (console_dir / "firewall.yaml").write_text(f'bind: "127.0.0.1:{cp}"\ntenant_store:\n  enabled: true\n' + store, encoding="utf-8")
            if args.backend == "postgres":
                migrate = subprocess.run([str(console_binary), "migrate"], cwd=console_dir, env=env, capture_output=True, timeout=120)
                check("postgres-explicit-migration-to-32", migrate.returncode == 0)

            def sql(statement):
                """Direct read/write of the owned disposable store (fault injection and independent reads)."""
                if args.backend == "postgres":
                    out = subprocess.run([str(binaries / "psql"), "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", statement],
                                         env=dict(R.postgres_environment(verified_url), PATH=os.environ["PATH"]),
                                         capture_output=True, text=True, timeout=60, check=True)
                    return [line.split("|") for line in out.stdout.splitlines() if line]
                with sqlite3.connect(console_dir / "rejection.sqlite") as db:
                    rows = db.execute(statement).fetchall()
                    db.commit()
                    return [["" if v is None else str(v) for v in row] for row in rows]

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

            alpha = req("POST", "/admin/v1/tenants", {"name": "Rejection Alpha"})["id"]
            beta = req("POST", "/admin/v1/tenants", {"name": "Rejection Beta"})["id"]
            base = f"/admin/v1/tenants/{alpha}"
            viewer = req("POST", "/admin/v1/admins", {"name": "Rejection viewer", "role": "viewer"})["token"]
            private.append(viewer)
            view = {"x-llm-firewall-admin-token": "Bearer " + viewer}
            creds = {a: req("POST", base + "/agents", {"agent_id": a})["token"] for a in ("edge-reject", "edge-revoked")}
            creds["beta"] = req("POST", f"/admin/v1/tenants/{beta}/agents", {"agent_id": "edge-reject"})["token"]
            private += list(creds.values())
            issuer = req("GET", "/admin/v1/managed-issuer")
            AG = "edge-reject"

            def revision(name, yaml, agent=AG):
                req("POST", f"{base}/agents/{agent}/revisions", {"revision": name, "policy_yaml": yaml})
                req("POST", f"{base}/agents/{agent}/revisions/{name}/approve", {})

            def deploy(name, payload=None, agent=AG):
                return req("POST", f"{base}/agents/{agent}/revisions/{name}/deploy", payload or {})

            def detail():
                return req("GET", f"{base}/agent-fleet/{AG}", auth=view)

            def record(sequence):
                return next(d for d in detail()["deployments"] if d["sequence"] == str(sequence))

            def wait_state(sequence, state):
                return D.wait_for(f"#{sequence} {state}", lambda: (lambda d: d if d["agent"]["latest_issued"]["sequence"] == str(sequence)
                                  and d["agent"]["latest_issued"]["recorded_state"] == state else None)(detail()), timeout=90)

            def stored(sequence):
                rows = sql(f"SELECT reason_version,reason_code,received_at_unix FROM managed_agent_rejections WHERE tenant_id='{alpha}' "
                           f"AND agent_id='{AG}' AND deployment_sequence={int(sequence)}")
                return rows

            def ack(body, token=None):
                try:
                    return D.request("POST", console + "/agent/v1/policy/ack", body, {"Authorization": "Bearer " + (token or creds[AG])}, timeout=10)[0]
                except urllib.error.HTTPError as error:
                    return error.code

            policies = {"r1": "default: deny\n", "r2": "default: allow\n"}
            for name, yaml in policies.items():
                revision(name, yaml)
            (home / ".agentfw/config.yaml").write_text(f"port: {ap}\nenforce: true\n", encoding="utf-8")
            agent_env = {k: v for k, v in env.items() if not k.startswith(("SOUP_", "LLM_FW_"))}
            agent_env.update(HOME=str(home), USERPROFILE=str(home), SOUP_MANAGED_AGENT_CONSOLE=console + "/",
                             SOUP_MANAGED_AGENT_TOKEN=creds[AG], SOUP_MANAGED_AGENT_TENANT=alpha,
                             SOUP_MANAGED_AGENT_ID=AG, SOUP_MANAGED_AGENT_KEY_ID="rejection-issuer",
                             SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX=issuer["public_key_hex"])
            runs = [0]

            def start_agent(extra=None):
                runs[0] += 1
                return D.proc(stack, [str(agent_binary), "serve"], temp, dict(agent_env, **(extra or {})), temp / f"agent-{runs[0]}.log")

            def stop(process):
                process.terminate()
                process.wait(timeout=15)

            def health():
                return D.request("GET", agent_url + "/health")[1].get("managed_policy") or {}

            def verdict():
                token = (home / ".agentfw" / "token").read_text().strip()
                data = D.request("POST", agent_url + "/hook", {"session_id": "sou241-witness", "hook_event_name": "PreToolUse",
                                 "tool_name": "Bash", "tool_input": {"command": "echo hello"}}, {"Authorization": "Bearer " + token})[1]
                return "defer" if data == {} else data["hookSpecificOutput"]["permissionDecision"]

            def active(sequence):
                return D.wait_for(f"Agent active #{sequence}", lambda: health() if health().get("deployment_sequence") == sequence else None, timeout=90)

            # 1. Baseline applied by the real Agent: r1 (deny).
            deploy("r1")
            agent = start_agent()
            wait_state(1, "applied")
            active(1)
            D.wait_for("hook token", lambda: (home / ".agentfw" / "token").exists())
            check("baseline-applied-and-enforced", verdict() == "deny")

            # 2. Trust: signed by a key the Agent does not trust.
            deploy("r2", {"issuer_key_id": "untrusted"})
            wait_state(2, "rejected")
            r = record(2)
            check("trust-issuer-key-unknown", r["rejection_code"] == "issuer_key_unknown" and r["rejection_reason_version"] == 1
                  and isinstance(r["rejected_at_unix"], int))
            check("trust-rejection-stored-directly", stored(2) == [["1", "issuer_key_unknown", str(r["rejected_at_unix"])]])
            check("trust-active-policy-unchanged", health().get("deployment_sequence") == 1 and verdict() == "deny")
            stop(agent)

            # 3. Expiry: the Agent clock is two hours ahead (bundle TTL is one hour).
            deploy("r2")
            agent = start_agent({"LD_PRELOAD": str(shim), "SW_ACCEPTANCE_CLOCK_OFFSET_SECONDS": "7200"})
            wait_state(3, "rejected")
            first = stored(3)
            time.sleep(7)  # later polls get no redelivery; the first receipt stands
            check("expiry-bundle-expired", record(3)["rejection_code"] == "bundle_expired" and first[0][1] == "bundle_expired")
            check("expiry-retry-keeps-first-receipt", stored(3) == first)
            stop(agent)

            # 4. Policy validation: an approved invalid revision in the owned store.
            bad = "default: escalate\n"
            sql(f"INSERT INTO managed_agent_revisions (tenant_id,agent_id,revision,policy_yaml,policy_sha256,approved_at_unix) "
                f"VALUES ('{alpha}','{AG}','r-invalid','{bad}','{sha(bad.encode())}',{int(time.time())})")
            deploy("r-invalid")
            agent = start_agent()
            wait_state(4, "rejected")
            check("policy-invalid", record(4)["rejection_code"] == "policy_invalid")
            active(1)
            check("policy-active-policy-unchanged", verdict() == "deny")

            # 5. Transient activation refusal: the native boundary is busy. The
            # candidate stays pending and retryable; nothing is reported rejected.
            lock = open(home / ".agentfw" / "managed-native-boundary.lock", "a+")
            fcntl.flock(lock, fcntl.LOCK_SH)
            deploy("r2")
            wait_state(5, "delivered")
            time.sleep(7)
            check("transient-stays-pending", record(5)["recorded_state"] == "delivered" and stored(5) == []
                  and "rejection_code" not in record(5) and health().get("deployment_sequence") == 1)
            snapshots["store_detail_while_pending"] = detail()
            # Corrected signed redeploy: the same candidate applies once the
            # boundary is free, witnessed by the Agent's own health and hook.
            fcntl.flock(lock, fcntl.LOCK_UN)
            lock.close()
            wait_state(5, "applied")
            active(5)
            check("corrected-redeploy-applied", verdict() == "defer" and record(5)["recorded_state"] == "applied")
            check("rejected-candidates-separate-from-active", detail()["agent"]["last_reported_applied"]["sequence"] == "5"
                  and [record(n)["recorded_state"] for n in (2, 3, 4)] == ["rejected"] * 3)
            stop(agent)

            # 6. Older Agent: a rejection without a reason; idempotent retry and conflicts.
            deploy("r1")
            fetched = D.request("GET", console + "/agent/v1/policy", None, {"Authorization": "Bearer " + creds[AG]}, timeout=10)[1]
            legacy = {k: fetched[k] for k in ("deployment_sequence", "revision", "policy_sha256")} | {"status": "rejected"}
            check("old-client-ack-accepted", ack(legacy) == 204 and stored(6)[0][:2] == ["", ""])
            check("old-client-retry-idempotent", ack(legacy) == 204)
            check("conflicting-reason-refused", ack(legacy | {"rejection": {"version": 1, "code": "policy_invalid"}}) == 409)
            check("applied-after-rejected-refused", ack(legacy | {"status": "applied"}) == 409)
            check("unknown-reason-refused", ack(legacy | {"rejection": {"version": 1, "code": "made_up"}}) == 400
                  and ack(legacy | {"rejection": {"version": 1, "code": "bundle_expired", "detail": "free text"}}) == 422)
            check("foreign-tenant-credential-no-effect", ack(legacy | {"rejection": {"version": 1, "code": "bundle_expired"}}, creds["beta"]) == 409)
            req("POST", f"{base}/agents/edge-revoked/revoke", {})
            check("revoked-credential-refused", ack(legacy, creds["edge-revoked"]) == 401 and ack(legacy, "sw_agent_" + "x" * 43) == 401)
            check("stored-rows-unchanged-by-refusals", stored(6)[0][:2] == ["", ""] and len(sql(
                f"SELECT 1 FROM managed_agent_rejections WHERE tenant_id='{alpha}'")) == 4
                and sql(f"SELECT count(*) FROM managed_agent_rejections WHERE tenant_id='{beta}'") == [["0"]])
            # Role checks: a Viewer reads but cannot deploy; an Agent credential cannot read.
            check("viewer-cannot-deploy", code("POST", f"{base}/agents/{AG}/revisions/r1/deploy", view, {}) == 403)
            check("agent-credential-cannot-read-history", code("GET", f"{base}/agent-fleet/{AG}", {"x-llm-firewall-admin-token": "Bearer " + creds[AG]}) == 401)
            # New Agent, older Console: the refused reason field falls back to
            # the legacy body, so the rejection is still recorded (no code).
            seen = []
            older = older_console(stack, console, seen)
            deploy("r2", {"issuer_key_id": "untrusted"})
            agent = start_agent({"SOUP_MANAGED_AGENT_CONSOLE": older + "/"})
            wait_state(7, "rejected")
            check("older-console-fallback-recorded", seen[:2] == ["refused-new-field", "forwarded-legacy"] and stored(7)[0][:2] == ["", ""])
            active(5)
            stop(agent)
            before = detail()
            snapshots["store_detail"] = before

            # 7. Restarts: Console and Agent keep the recorded reasons and the active policy.
            console_process.terminate()
            console_process.wait(timeout=15)
            console_process = start_console()
            agent = start_agent()
            active(5)
            time.sleep(5)
            after = detail()
            check("restart-keeps-reasons", [d for d in after["deployments"]] == [d for d in before["deployments"]])
            check("restart-agent-keeps-applied", verdict() == "defer")
            listed = req("GET", f"{base}/agents/{AG}/deployments", auth=view)
            check("policy-list-carries-reasons", {d["deployment_sequence"]: d.get("rejection_code") for d in listed if d["status"] == "rejected"}
                  == {2: "issuer_key_unknown", 3: "bundle_expired", 4: "policy_invalid", 6: None, 7: None})

            with sync_playwright() as playwright, ExitStack() as browser_stack:
                browser = playwright.chromium.launch(headless=True)
                browser_stack.callback(browser.close)
                context = browser.new_context(viewport={"width": 1366, "height": 1000}, accept_downloads=True)
                page = context.new_page()
                writes, errors = [], []
                page.on("request", lambda r: writes.append((r.method, r.url)) if r.method != "GET" else None)
                page.on("pageerror", lambda e: errors.append(str(e)))
                page.goto(console + "/admin")
                page.locator("#admin-token").fill(viewer)
                page.locator("#unlock-form button").click()
                expect(page.locator("#console")).to_be_visible()
                page.locator("#tenant-list button").filter(has_text="Rejection Alpha").click()
                expect(page.locator("#fleet-list")).to_contain_text(AG)
                page.locator("#fleet-list").get_by_role("button", name=AG, exact=True).click()
                expect(page.locator("#history-status")).to_contain_text("No older pages", timeout=20000)
                events = page.locator("#history-timeline li").all_inner_texts()
                rejected = {e.split(" · ")[2]: e for e in events if e.startswith("Rejected")}
                check("browser-history-reasons", "issuer key the Agent does not trust" in rejected["#2"]
                      and "Bundle had expired" in rejected["#3"] and "Policy failed the Agent's validation" in rejected["#4"]
                      and "did not report a reason" in rejected["#6"] and "did not report a reason" in rejected["#7"])
                check("browser-history-next-steps", all("Next step:" in rejected[k] and "kept its previous policy" in rejected[k] for k in rejected))
                check("browser-history-receipt-times", all("time not recorded" not in rejected[k].lower() for k in ("#2", "#3", "#4", "#6", "#7")))
                fleet = page.locator("#fleet-agent-detail").inner_text()
                check("browser-fleet-latest-rejected-reason", "Latest deployment was rejected: Rejected; this Agent did not report a reason" in fleet
                      and "Policy failed the Agent's validation · received" in fleet)
                page.locator("#history-panel").screenshot(path=str(args.output / f"{args.backend}-history-reasons.png"))
                page.locator("#fleet-agent-detail").screenshot(path=str(args.output / f"{args.backend}-fleet-reasons.png"))
                page.locator("#history-preview").click()
                expect(page.locator("#history-snapshot")).to_be_visible()
                snap_text = page.locator("#history-snapshot").text_content()
                snap = json.loads(snap_text)
                codes = {e["sequence"]: e.get("rejection_code") for e in snap["events"] if e["kind"] == "rejected"}
                check("snapshot-reason-codes", codes == {"2": "issuer_key_unknown", "3": "bundle_expired", "4": "policy_invalid", "6": None, "7": None}
                      and snap["summary"]["historical_last_reported_applied"]["sequence"] == "5")
                page.locator("#single-agent").select_option(AG)
                expect(page.locator("#single-deployments")).to_contain_text("Rejected candidate", timeout=20000)
                policy_text = page.locator("#single-deployments").text_content()
                blocks = {b.split(" · ")[0]: b for b in policy_text.split("\n\n")}
                check("browser-policy-panel-reasons", "issuer key the Agent does not trust" in blocks["Sequence 2"]
                      and "Bundle had expired" in blocks["Sequence 3"] and "Rejected candidate" not in blocks["Sequence 5"])
                page.locator("#single-deployments").screenshot(path=str(args.output / f"{args.backend}-policy-reasons.png"))
                page.set_viewport_size({"width": 390, "height": 900})
                check("narrow-no-horizontal-overflow", page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth"))
                page.locator("#history-panel").screenshot(path=str(args.output / f"{args.backend}-history-narrow.png"))
                check("browser-read-only-no-errors", writes == [] and errors == [] and page.evaluate("localStorage.length + sessionStorage.length") == 0)
            stop(agent)
            console_process.terminate()
            console_process.wait(timeout=15)

            # 8. Recovery inventory: the live store with rejection rows matches it.
            if args.backend == "postgres":
                folder_r = temp / "recovery"
                folder_r.mkdir(mode=0o700)
                state = R.PostgresBackend(verified_url, directory=folder_r, psql=str(binaries / "psql")).snapshot()
            else:
                database = console_dir / "rejection.sqlite"
                os.chmod(console_dir, 0o700)  # the recovery tool reads only owner-only private state
                os.chmod(database, 0o600)
                state = R.inspect_sqlite(database)
            rows = state["tables"]["managed_agent_rejections"]
            check("recovery-inventory-accepts-live-store", len(rows["rows"] if isinstance(rows, dict) else rows) == 5)
            report["recovery_schema_version"] = R.POSTGRES_SCHEMA_VERSION
            (args.output / f"{args.backend}-snapshot.json").write_text(snap_text, encoding="utf-8")
            for label, text in (("snapshot", snap_text), ("detail", json.dumps(snapshots))):
                check("free-of-private-values-" + label, all(value not in text for value in private)
                      and all(word not in text for word in ("token_hash", "policy_yaml", "bundle_json", "signature_hex", "default: allow", "default: deny", "escalate")))
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
