#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owner-confirmed stale-restore recovery with a real Console and Agent (SOU-242).

One disposable private Linux deployment per run: a Console on loopback with
SQLite or a disposable TLS PostgreSQL cluster (owned CA, non-superuser owner),
the unchanged `agentfw serve` with the opt-in heartbeat, and the supported
`scripts/console_recovery.py` backup and restore. The Console is backed up
while the Agent applies #1, the Agent then applies #2, and the Console is
restored to the backup. The original negative result is reproduced (a new
deployment at #2 is refused; the Agent keeps #2). Then the Agent's retained
signed bundle and its fresh authenticated heartbeat drive the refusals,
an interrupted confirmation and retry, concurrent confirmations and, through
the normal deployment path, a real applied acknowledgement above the fence.
The Agent's own /health and /hook are the protection witnesses throughout.
Credentials stay in memory and the private temporary directory; the retained
report and screenshots never contain one.

    python3 scripts/console-stale-restore-acceptance.py --backend sqlite|postgres --output DIR [--no-build]
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
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
FORMAT = "sw-console-stale-restore-acceptance/1"


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = module("stale_managed_helpers", "managed-policy-demo.py")
PG = module("stale_postgres_helpers", "console-enrollment-acceptance.py")
R = module("stale_console_recovery", "console_recovery.py")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", choices=["sqlite", "postgres"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pg-bin", help="directory with initdb, pg_ctl, createdb, psql, pg_dump and pg_restore")
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()
    from playwright.sync_api import expect, sync_playwright
    args.output = args.output.resolve()
    assert not args.output.is_relative_to(ROOT), "--output must be outside the checkout"
    args.output.mkdir(parents=True, exist_ok=True)
    if not args.no_build:
        subprocess.run(["cargo", "build", "--locked", "-p", "llm-firewall", "-p", "agentfw"], cwd=ROOT, check=True)
    console_binary, agent_binary = ROOT / "target/debug/llm-firewall", ROOT / "target/debug/agentfw"
    checks, observations, private, timings = {}, {}, [], {}
    report = {"format": FORMAT, "backend": args.backend, "status": "failed", "checks": checks, "observations": observations,
              "timings_seconds": timings,
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
              "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "scope": "one disposable private Linux deployment; synthetic tenants and Agent IDs; one local Agent with the "
                       "opt-in heartbeat; recorded Console evidence and the Agent's own witnesses, not production or multi-host"}

    def check(name, condition):
        checks[name] = bool(condition)
        if not condition:
            raise AssertionError(name)
        print("PASS:", name, flush=True)

    try:
        with tempfile.TemporaryDirectory(prefix="console-stale-restore-") as folder, ExitStack() as stack:
            temp = Path(folder).resolve()
            os.chmod(temp, 0o700)
            private.append(str(temp))
            console_dir, work = temp / "console", temp / "recovery"
            console_dir.mkdir(mode=0o700)
            work.mkdir(mode=0o700)
            cp = D.port()
            console = f"http://127.0.0.1:{cp}"
            owner, seed = secrets.token_urlsafe(32), secrets.token_hex(32)
            other_seed = secrets.token_hex(32)
            private += [owner, seed, other_seed]
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("SOUP_MANAGED_AGENT_", "SOUP_AGENT_POLICY_", "LLM_FW_", "OPENAI_", "PG"))}
            env.update(LLM_FW_ADMIN_TOKEN=owner, SOUP_AGENT_POLICY_KEY_ID="stale-issuer", SOUP_AGENT_POLICY_SEED_HEX=seed)
            identity_file = temp / "recovery.key"
            generated = subprocess.run(["age-keygen", "-o", str(identity_file)], check=True, capture_output=True, timeout=30)
            recipient = next(l.split(": ", 1)[1] for l in generated.stderr.decode().splitlines() if l.startswith("Public key:"))
            os.chmod(identity_file, 0o600)
            if args.backend == "postgres":
                url, ca, password, binaries = PG.postgres(stack, temp, PG.pg_bin(args.pg_bin))
                private += [password, url]
                pg_port = int(url.rsplit(":", 1)[1].split("/", 1)[0])
                owner_password = secrets.token_urlsafe(24)
                private.append(owner_password)

                def superuser_sql(sql, **variables):
                    words = [str(binaries / "psql"), "-h", "127.0.0.1", "-p", str(pg_port), "-U", "enrollment_owner",
                             "-d", "console", "-v", "ON_ERROR_STOP=1", "-q", "-At"]
                    for key, value in variables.items():
                        words += ["-v", f"{key}={value}"]
                    return subprocess.run(words, input=sql.encode(), check=True, capture_output=True, timeout=60,
                                          env=dict(os.environ, PGPASSWORD=password, PGSSLMODE="verify-full", PGSSLROOTCERT=str(ca))).stdout.decode()

                superuser_sql("CREATE ROLE stale_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'pw';", pw=owner_password)
                superuser_sql("GRANT pg_monitor TO stale_owner;")
                for name in ("stale_source", "stale_restored"):
                    superuser_sql(f"CREATE DATABASE {name} OWNER stale_owner;")
                with open(temp / "pgdata" / "pg_hba.conf", "a", encoding="utf-8") as hba:
                    hba.write("hostssl all stale_owner 127.0.0.1/32 scram-sha-256\n")
                subprocess.run([str(binaries / "pg_ctl"), "-D", str(temp / "pgdata"), "reload"], check=True, capture_output=True, timeout=60)
                database = lambda name, mode="require": (f"postgresql://stale_owner:{owner_password}@127.0.0.1:{pg_port}/{name}?sslmode={mode}"
                                                          + ("" if mode == "require" else f"&sslrootcert={ca}"))
                private += [database(n, m) for n in ("stale_source", "stale_restored") for m in ("require", "verify-full")]
                env.update(LLM_FW_POSTGRES_URL=database("stale_source"), LLM_FW_POSTGRES_CA_CERT_FILE=str(ca))
                store = "  backend: postgres\n  postgres_command_timeout_ms: 30000\n  postgres_pool_wait_timeout_ms: 10000\n"
                report["postgres"] = {"server": subprocess.run([str(binaries / "postgres"), "--version"], capture_output=True, text=True).stdout.strip(),
                                      "tls": "sslmode=require with an owned CA", "listen": "127.0.0.1", "owner": "non-superuser"}

                def migrate():
                    done = subprocess.run([str(console_binary), "migrate"], cwd=console_dir, env=env, capture_output=True, timeout=120)
                    return done.returncode == 0

                def owner_sql(name, sql):
                    words = [str(binaries / "psql"), "-h", "127.0.0.1", "-p", str(pg_port), "-U", "stale_owner", "-d", name,
                             "-v", "ON_ERROR_STOP=1", "-q", "-At"]
                    return subprocess.run(words, input=sql.encode(), check=True, capture_output=True, timeout=60,
                                          env=dict(os.environ, PGPASSWORD=owner_password, PGSSLMODE="verify-full",
                                                   PGSSLROOTCERT=str(ca))).stdout.decode().strip()
            else:
                store = '  backend: sqlite\n  database_path: "console.sqlite"\n'
            (console_dir / "firewall.yaml").write_text(f'bind: "127.0.0.1:{cp}"\ntenant_store:\n  enabled: true\n' + store, encoding="utf-8")
            if args.backend == "postgres":
                check("postgres-migration-to-33", migrate())
            starts = [0]

            def start_console(extra=None):
                starts[0] += 1
                process = D.proc(stack, [str(console_binary)], console_dir, dict(env, **(extra or {})), temp / f"console-{starts[0]}.log")
                D.wait_for("Console", lambda: D.request("GET", console + "/healthz")[0] == 200, timeout=90)
                return process

            def stop(process):
                process.terminate()
                process.wait(timeout=20)

            console_process = start_console()
            admin = {"x-llm-firewall-admin-token": "Bearer " + owner}

            def call(method, path, payload=None, auth=None):
                try:
                    return D.request(method, console + path, payload, auth, timeout=20)
                except urllib.error.HTTPError as error:
                    try:
                        return error.code, json.loads(error.read() or b"null")
                    except ValueError:
                        return error.code, None

            def req(method, path, payload=None, auth=admin):
                code, body = call(method, path, payload, auth)
                assert 200 <= code < 300, (method, path, code)
                return body

            alpha = req("POST", "/admin/v1/tenants", {"name": "Stale Alpha"})["id"]
            beta = req("POST", "/admin/v1/tenants", {"name": "Stale Beta"})["id"]
            base = f"/admin/v1/tenants/{alpha}"
            AG = "edge-stale"
            tokens = {role: req("POST", "/admin/v1/admins", {"name": f"Stale {role}", "role": role})["token"] for role in ("viewer", "operator")}
            private += list(tokens.values())
            view = {"x-llm-firewall-admin-token": "Bearer " + tokens["viewer"]}
            operator = {"x-llm-firewall-admin-token": "Bearer " + tokens["operator"]}
            creds = {a: req("POST", base + "/agents", {"agent_id": a})["token"] for a in (AG, "edge-revoked")}
            creds["beta"] = req("POST", f"/admin/v1/tenants/{beta}/agents", {"agent_id": AG})["token"]
            private += list(creds.values())
            issuer = req("GET", "/admin/v1/managed-issuer")
            for name, yaml in (("r-deny", "default: deny\n"), ("r-allow", "default: allow\n")):
                req("POST", f"{base}/agents/{AG}/revisions", {"revision": name, "policy_yaml": yaml})
                req("POST", f"{base}/agents/{AG}/revisions/{name}/approve", {})

            home = temp / "home"
            (home / ".agentfw").mkdir(parents=True, mode=0o700)
            ap = D.port()
            (home / ".agentfw/config.yaml").write_text(f"port: {ap}\nenforce: true\n", encoding="utf-8")
            token_file = home / ".agentfw/enrollment-token"
            token_file.write_text(creds[AG], encoding="utf-8")
            os.chmod(token_file, 0o600)
            agent_env = {k: v for k, v in env.items() if not k.startswith(("SOUP_", "LLM_FW_"))}
            agent_env.update(HOME=str(home), USERPROFILE=str(home), SOUP_MANAGED_AGENT_CONSOLE=console + "/",
                             SOUP_MANAGED_AGENT_TOKEN_FILE=str(token_file), SOUP_MANAGED_AGENT_TENANT=alpha,
                             SOUP_MANAGED_AGENT_ID=AG, SOUP_MANAGED_AGENT_KEY_ID="stale-issuer",
                             SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX=issuer["public_key_hex"],
                             SOUP_MANAGED_AGENT_HEARTBEAT="1", SOUP_MANAGED_AGENT_HEARTBEAT_INTERVAL_SECONDS="5")
            agent_runs = [0]

            def start_agent():
                agent_runs[0] += 1
                return D.proc(stack, [str(agent_binary), "serve"], temp, agent_env, temp / f"agent-{agent_runs[0]}.log")

            def witness():
                health = D.wait_for("Agent health", lambda: D.request("GET", f"http://127.0.0.1:{ap}/health")[1].get("managed_policy"), timeout=90)
                hook = (home / ".agentfw/token").read_text().strip()
                if hook not in private:
                    private.append(hook)
                _, data = D.request("POST", f"http://127.0.0.1:{ap}/hook", {"session_id": "stale-witness", "hook_event_name": "PreToolUse",
                                    "tool_name": "Bash", "tool_input": {"command": "echo hello"}}, {"Authorization": "Bearer " + hook}, timeout=15)
                return {"deployment_sequence": health["deployment_sequence"], "policy_sha256": health["policy_sha256"],
                        "hook_decision": "defer" if data == {} else data["hookSpecificOutput"]["permissionDecision"]}

            def deployments():
                return {d["deployment_sequence"]: d for d in req("GET", f"{base}/agents/{AG}/deployments", auth=view)}

            def wait_record(sequence, status, timeout=90):
                return D.wait_for(f"#{sequence} {status}", lambda: (lambda d: d if d.get("status") == status else None)(deployments().get(sequence, {})), timeout=timeout)

            def wait_active(sequence):
                return D.wait_for(f"Agent active #{sequence}", lambda: (lambda w: w if w["deployment_sequence"] == sequence else None)(witness()), timeout=90)

            def heartbeat_names(sequence):
                return D.wait_for(f"fresh heartbeat names #{sequence}", lambda: (lambda s: s if s["status"] == "fresh" and
                    ((s.get("reported") or {}).get("observed_policy") or {}).get("deployment_sequence") == sequence else None)(
                    req("GET", f"{base}/agent-fleet/{AG}/heartbeat", auth=view)), timeout=120)

            # 1. Applied #1, then an encrypted backup of the quiesced Console.
            req("POST", f"{base}/agents/{AG}/revisions/r-deny/deploy", {})
            agent = start_agent()
            wait_record(1, "applied")
            first = wait_active(1)
            check("baseline-applied-deny", first["hook_decision"] == "deny")
            old_evidence = json.loads((home / ".agentfw/managed-policy-active.json").read_text())
            stop(console_process)
            started = time.monotonic()
            archive = work / "behind.age"
            if args.backend == "sqlite":
                os.chmod(console_dir / "console.sqlite", 0o600)
                R.backup_sqlite(console_dir / "console.sqlite", archive, recipient, workdir=work)
            else:
                R.backup_postgres(database("stale_source", "verify-full"), archive, recipient, workdir=work, source_quiesced=True,
                                  psql=str(binaries / "psql"), pg_dump=str(binaries / "pg_dump"), pg_restore=str(binaries / "pg_restore"))
            timings["backup"] = round(time.monotonic() - started, 3)
            check("backup-archive-written", archive.is_file())

            # 2. The live Console moves on: the Agent applies #2 (allow).
            console_process = start_console()
            req("POST", f"{base}/agents/{AG}/revisions/r-allow/deploy", {})
            wait_record(2, "applied")
            live = wait_active(2)
            check("agent-applies-newer-deployment", live["hook_decision"] == "defer")
            evidence = json.loads((home / ".agentfw/managed-policy-active.json").read_text())
            check("retained-signed-bundle-is-active", evidence["deployment_sequence"] == 2 and evidence["policy_sha256"] == live["policy_sha256"])
            stop(console_process)

            # 3. Restore the older backup to a fresh target and start it.
            started = time.monotonic()
            if args.backend == "sqlite":
                restored = work / "restored.sqlite"
                receipt = R.restore_sqlite(archive, restored, identity_file, workdir=work)
                store = f'  backend: sqlite\n  database_path: "{restored}"\n'
                (console_dir / "firewall.yaml").write_text(f'bind: "127.0.0.1:{cp}"\ntenant_store:\n  enabled: true\n' + store, encoding="utf-8")
            else:
                receipt = R.restore_postgres(archive, database("stale_restored", "verify-full"), identity_file, workdir=work,
                                             psql=str(binaries / "psql"), pg_restore=str(binaries / "pg_restore"))
                env["LLM_FW_POSTGRES_URL"] = database("stale_restored")
                check("restored-migrate-recreates-observations", migrate())
            timings["restore"] = round(time.monotonic() - started, 3)
            check("restore-verified", receipt.get("status") == "passed" and receipt.get("tables_verified", 0) > 0)
            console_process = start_console()
            check("restored-console-is-behind", max(deployments()) == 1)

            # 4. Original negative: a new deployment at #2 is refused by the Agent.
            req("POST", f"{base}/agents/{AG}/revisions/r-deny/deploy", {})
            wait_record(2, "rejected")
            kept = witness()
            check("stale-console-cannot-rewind-agent", kept["deployment_sequence"] == 2 and kept["hook_decision"] == "defer")
            observations["original_negative"] = {"restored_sequence": 1, "agent_sequence": 2, "new_deployment": 2,
                                                 "status": "rejected", "hook_decision": kept["hook_decision"], "recovery_complete": False}
            heartbeat_names(2)

            recovery = f"{base}/agents/{AG}/stale-recovery"
            preview = lambda body, auth=admin: call("POST", recovery + "/preview", body, auth)
            confirm = lambda body, auth=admin: call("POST", recovery + "/confirm", body, auth)
            refusal = lambda result: (result[0], (result[1] or {}).get("refusal"))
            check("status-none-after-restore", req("GET", recovery, auth=view)["state"] == "none")

            # 5. Role, credential, audience, tamper, replay and issuer refusals.
            check("operator-cannot-preview", preview({"evidence": evidence}, operator)[0] == 403)
            check("viewer-cannot-preview", preview({"evidence": evidence}, view)[0] == 403)
            check("agent-credential-cannot-preview", call("POST", recovery + "/preview", {"evidence": evidence},
                                                          {"Authorization": "Bearer " + creds[AG]})[0] == 401)
            check("foreign-audience-refused", refusal(call("POST", f"/admin/v1/tenants/{beta}/agents/{AG}/stale-recovery/preview",
                                                           {"evidence": evidence}, admin)) == (409, "evidence_wrong_audience"))
            req("POST", f"{base}/agents/edge-revoked/revoke", {})
            check("revoked-enrollment-refused", refusal(call("POST", f"{base}/agents/edge-revoked/stale-recovery/preview",
                                                             {"evidence": evidence}, admin)) == (409, "revoked"))
            tampered = dict(evidence, policy_yaml="default: allow\n# tampered\n")
            check("tampered-policy-refused", refusal(preview({"evidence": tampered})) == (409, "evidence_digest_mismatch"))
            forged = dict(evidence, signature_hex="00" * 64)
            check("forged-signature-refused", refusal(preview({"evidence": forged})) == (409, "evidence_signature_invalid"))
            check("replayed-old-evidence-refused", refusal(preview({"evidence": old_evidence})) == (409, "evidence_not_ahead"))
            check("unknown-field-refused", preview({"evidence": dict(evidence, note="x")})[0] == 400)
            stop(console_process)
            console_process = start_console({"SOUP_AGENT_POLICY_SEED_HEX": other_seed})
            check("changed-issuer-key-refused", refusal(preview({"evidence": evidence})) == (409, "evidence_signature_invalid"))
            stop(console_process)
            console_process = start_console({"SOUP_AGENT_POLICY_KEY_ID": "other-issuer", "SOUP_AGENT_POLICY_SEED_HEX_OTHER_ISSUER": seed})
            check("changed-issuer-id-refused", refusal(preview({"evidence": evidence})) == (409, "issuer_changed"))
            stop(console_process)
            console_process = start_console()
            heartbeat_names(2)

            # 6. Preview; a concurrent policy mutation keeps it closed.
            code, first_preview = preview({"evidence": evidence})
            check("preview-valid", code == 200 and first_preview["restored_sequence"] == 1 and first_preview["latest_restored_sequence"] == 2
                  and first_preview["next_sequence"] == 3
                  and first_preview["evidence"]["deployment_sequence"] == 2 and first_preview["unrecoverable_interval"] is None)
            check("preview-writes-nothing", req("GET", recovery, auth=view)["state"] == "none")
            req("POST", f"{base}/agents/{AG}/revisions", {"revision": "r-concurrent", "policy_yaml": "default: deny\n"})
            body = lambda p: {"evidence": evidence, "state_binding": p["state_binding"], "confirmation": p["confirmation"]}
            check("concurrent-mutation-refused", refusal(confirm(body(first_preview))) == (409, "state_changed"))
            code, final_preview = preview({"evidence": evidence})
            check("preview-after-mutation", code == 200 and final_preview["state_binding"] != first_preview["state_binding"])
            check("operator-cannot-confirm", confirm(body(final_preview), operator)[0] == 403)
            check("wrong-phrase-refused", refusal(confirm(dict(body(final_preview), confirmation="recover"))) == (400, "confirmation_mismatch"))
            observations["preview"] = {k: final_preview[k] for k in ("restored_sequence", "latest_restored_sequence", "next_sequence", "unrecoverable_interval",
                                                                     "credential_generation", "observation_age_seconds")}

            # 7. Concurrent confirmations: exactly one fence.
            started = time.monotonic()
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: confirm(body(final_preview)), range(2)))
            timings["confirm"] = round(time.monotonic() - started, 3)
            codes = sorted(r[0] for r in results)
            check("concurrent-confirmations-one-fence", codes in ([200, 201], [201, 409]))
            fence = next(r[1] for r in results if r[0] == 201)["fence"]
            check("fence-at-agent-sequence", fence["fence_sequence"] == 2 and fence["restored_sequence"] == 1 and fence["state"] == "fenced")

            # 8. Interruption: the Console stops after confirmation; retry is idempotent.
            stop(console_process)
            console_process = start_console()
            check("fence-survives-restart", req("GET", recovery, auth=view)["state"] == "fenced")
            code, retried = confirm(body(final_preview))
            check("retry-is-idempotent", code == 200 and retried["replayed"] is True and retried["fence"]["fence_sequence"] == 2)
            check("agent-unchanged-while-fenced", witness() == kept)

            # 9. Normal deployment above the fence; completion only after the real applied ACK.
            started = time.monotonic()
            deployed = req("POST", f"{base}/agents/{AG}/revisions/r-deny/deploy", {})
            check("issued-above-fence", deployed["deployment_sequence"] == 3)
            # Each recovery-state read is followed by a record read. A state
            # of complete is a violation unless that later read shows the
            # authenticated applied acknowledgement already recorded.
            states, deadline, applied = [], time.monotonic() + 90, None
            while time.monotonic() < deadline:
                state_now = req("GET", recovery, auth=view)["state"]
                record = deployments().get(3, {})
                states.append((state_now, record.get("status")))
                if record.get("status") == "applied":
                    applied = record
                    break
                time.sleep(0.2)
            assert applied, "#3 applied timed out"
            final = wait_active(3)
            timings["fence_to_applied"] = round(time.monotonic() - started, 3)
            check("agent-applies-above-fence", final["hook_decision"] == "deny" and applied["status"] == "applied")
            check("not-complete-before-ack", all(state == "fenced" or status == "applied" for state, status in states))
            observations["fenced_reads_before_ack"] = sum(1 for state, _ in states if state == "fenced")
            status = req("GET", recovery, auth=view)
            check("recovery-complete-after-applied-ack", status["state"] == "complete"
                  and status["fences"][0]["completion"]["deployment_sequence"] == 3)
            lower = {"deployment_sequence": 2, "revision": "r-allow", "policy_sha256": evidence["policy_sha256"], "status": "applied"}
            check("equal-lower-ack-refused", call("POST", "/agent/v1/policy/ack", lower, {"Authorization": "Bearer " + creds[AG]})[0] == 409)
            check("foreign-credential-ack-refused", call("POST", "/agent/v1/policy/ack", dict(lower, deployment_sequence=3, revision="r-deny",
                  policy_sha256=deployed["policy_sha256"]), {"Authorization": "Bearer " + creds["beta"]})[0] == 409)
            check("completed-evidence-cannot-reopen", refusal(preview({"evidence": evidence})) == (409, "evidence_not_ahead"))
            observations["completion"] = {"fence": 2, "deployment": 3, "hook_decision": final["hook_decision"], "recovery_complete": True}

            # 10. Restarts keep completion and the Agent's active policy.
            stop(console_process)
            stop(agent)
            console_process = start_console()
            agent = start_agent()
            check("restart-keeps-completion", req("GET", recovery, auth=view)["state"] == "complete" and wait_active(3)["hook_decision"] == "deny")

            # 11. Browser: Viewer sees the completed state; Owner sees the controls.
            with sync_playwright() as playwright, ExitStack() as browsers:
                browser = playwright.chromium.launch(headless=True)
                browsers.callback(browser.close)
                for role, token in (("viewer", tokens["viewer"]), ("owner", owner)):
                    page = browser.new_context(viewport={"width": 1366, "height": 1000}).new_page()
                    writes, errors = [], []
                    page.on("request", lambda r: writes.append(r.method) if r.method != "GET" else None)
                    page.on("pageerror", lambda e: errors.append(str(e)))
                    page.goto(console + "/admin")
                    page.locator("#admin-token").fill(token)
                    page.locator("#unlock-form button").click()
                    expect(page.locator("#console")).to_be_visible()
                    page.locator("#tenant-list button").filter(has_text="Stale Alpha").click()
                    page.locator("#fleet-list").get_by_role("button", name=AG, exact=True).click()
                    expect(page.locator("#recovery-status")).to_contain_text("Recovery complete: #3", timeout=20000)
                    text = page.locator("#recovery-panel").inner_text()
                    check(f"browser-{role}-complete", "above fence #2" in text and "Restored sequence #1" in text)
                    check(f"browser-{role}-controls", page.locator("#recovery-preview").is_visible() == (role == "owner"))
                    check(f"browser-{role}-read-only", writes == [] and errors == [])
                    page.locator("#recovery-panel").screenshot(path=str(args.output / f"{args.backend}-recovery-{role}.png"))
            stop(agent)
            stop(console_process)

            # 12. The recovery inventory accepts the store with a fence row.
            if args.backend == "sqlite":
                state = R.inspect_sqlite(restored)
            else:
                state = R.PostgresBackend(database("stale_restored", "verify-full"), directory=work, psql=str(binaries / "psql")).snapshot()
            rows = state["tables"]["managed_agent_recovery_fences"]
            check("recovery-inventory-accepts-fence", len(rows["rows"] if isinstance(rows, dict) else rows) == 1)
            report["recovery_schema_version"] = R.POSTGRES_SCHEMA_VERSION
            text = json.dumps(observations)
            check("observations-free-of-private-values", all(v not in text for v in private))
            report["binaries"] = {p.name: sha(p.read_bytes()) for p in (console_binary, agent_binary)}
            report["status"] = "passed"
    finally:
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if any(v and v in text for v in private):
            text = json.dumps({"format": FORMAT, "status": "failed", "error": "report withheld: private value found"}, indent=2) + "\n"
        (args.output / f"{args.backend}-report.json").write_text(text, encoding="utf-8")
        for png in args.output.glob(f"{args.backend}-*.png"):
            data = png.read_bytes()
            assert all(v.encode() not in data for v in private if v)
    print(f"{args.backend}: {sum(checks.values())} checks passed" if report["status"] == "passed" else "FAILED")


if __name__ == "__main__":
    main()
