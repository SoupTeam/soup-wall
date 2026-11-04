#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Complete single-Agent policy lifecycle through the shipped Console browser.

Uses the accepted private disposable Console/Agent/PostgreSQL fixture helpers.
No production credentials or infrastructure. Both backends exercise exact YAML
readback, approval, applied ACKs, lost-response retry, a higher-sequence rollback,
role restrictions and Agent revocation. Output is sanitized and failures retained.
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
FORMAT = "sw-console-single-policy-acceptance/1"


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
              "scope": "one disposable private Linux deployment with one real Agent, a browser and Console; synthetic tenants; not production, multi-host or runtime attestation"}

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

            alpha = req("POST", "/admin/v1/tenants", {"name": "Single policy Alpha"})["id"]
            beta = req("POST", "/admin/v1/tenants", {"name": "Single policy Beta"})["id"]
            path = f"/admin/v1/tenants/{alpha}/agents/edge-single"
            enrollment = req("POST", f"/admin/v1/tenants/{alpha}/agents", {"agent_id": "edge-single"})
            req("POST", f"/admin/v1/tenants/{beta}/agents", {"agent_id": "edge-single"})
            token = enrollment["token"]
            private.append(token)
            viewer = req("POST", "/admin/v1/admins", {"name": "Single viewer", "role": "viewer"})["token"]
            operator = req("POST", "/admin/v1/admins", {"name": "Single operator", "role": "operator"})["token"]
            private += [viewer, operator]
            issuer = req("GET", "/admin/v1/managed-issuer")
            (home / ".agentfw/config.yaml").write_text(f"bind: 127.0.0.1\nport: {ap}\nenforce: true\n")
            agent_env = {k: v for k, v in env.items() if not k.startswith(("SOUP_", "LLM_FW_"))}
            agent_env.update(HOME=str(home), USERPROFILE=str(home), SOUP_MANAGED_AGENT_CONSOLE=console + "/",
                SOUP_MANAGED_AGENT_TOKEN=token, SOUP_MANAGED_AGENT_TENANT=alpha, SOUP_MANAGED_AGENT_ID="edge-single",
                SOUP_MANAGED_AGENT_KEY_ID="history-issuer", SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX=issuer["public_key_hex"])
            agent = D.proc(stack, [str(agent_binary), "serve"], temp, agent_env, temp / "agent.log")
            def applied(revision, sequence):
                value=D.request("GET",f"http://127.0.0.1:{ap}/health")[1].get("managed_policy")
                return value if value and value["revision"] == revision and value["deployment_sequence"] == sequence else None
            D.wait_for("Agent healthy", lambda: D.request("GET",f"http://127.0.0.1:{ap}/health")[0] == 200)
            hook_token=(home/".agentfw/token").read_text().strip()
            private.append(hook_token)
            def hook(label):
                value=D.request("POST",f"http://127.0.0.1:{ap}/hook",{"session_id":"sou227-"+label,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo sou227-controlled"}},{"Authorization":"Bearer "+hook_token})[1]
                return value.get("hookSpecificOutput",{}).get("permissionDecision","allow")
            with sync_playwright() as playwright, ExitStack() as browser_stack:
                browser=playwright.chromium.launch(headless=True)
                browser_stack.callback(browser.close)
                context=browser.new_context(viewport={"width":1366,"height":1200})
                page=context.new_page()
                page.on("dialog",lambda dialog:dialog.accept())
                errors=[]
                page.on("pageerror",lambda error:errors.append(str(error)))
                def login(target, credential):
                    target.goto(console+"/admin")
                    target.locator("#admin-token").fill(credential)
                    target.locator("#unlock-form button").click()
                    expect(target.locator("#console")).to_be_visible()
                    target.locator("#tenant-list button").filter(has_text="Single policy Alpha").click()
                    expect(target.locator("#single-agent option[value='edge-single']")).to_have_count(1)
                    target.locator("#single-agent").select_option("edge-single")
                    expect(target.locator("#single-policy-status")).to_contain_text("historical evidence")
                login(page,owner)
                def review(name):
                    page.locator("#single-revision").select_option(name)
                    expect(page.locator("#single-document")).to_contain_text("Server SHA-256")
                def create(name,yaml):
                    page.locator("#single-new-revision").fill(name)
                    page.locator("#single-yaml").fill(yaml)
                    page.locator("#single-create").click()
                    expect(page.locator(f"#single-revision option[value='{name}']")).to_have_count(1)
                    review(name)
                    check(name+"-exact-server-yaml",yaml in page.locator("#single-document").inner_text() and sha(yaml.encode()) in page.locator("#single-document").inner_text())
                    page.locator("#single-approve").click()
                    expect(page.locator(f"#single-revision option[value='{name}']")).to_have_text(name+" · approved")
                    review(name)
                create("r1","default: deny\n")
                page.locator("#single-deploy").click()
                expect(page.locator("#single-intent")).to_contain_text("sequence 1")
                D.wait_for("real baseline applied",lambda:applied("r1",1))
                check("real-agent-baseline-applied",True)
                check("real-baseline-hook-deny",hook("baseline")=="deny")
                create("r2","default: allow\n")
                captured=[]
                def lose_response(route):
                    response=route.fetch()
                    captured.append(response.json())
                    route.abort("failed")
                page.route("**/revisions/r2/deploy",lose_response)
                page.locator("#single-deploy").click()
                expect(page.locator("#single-policy-status")).to_contain_text("outcome unresolved")
                check("lost-response-reaches-persisted-issuance",len(captured)==1 and captured[0]["deployment_sequence"]==2)
                page.unroute("**/revisions/r2/deploy",lose_response)
                page.locator("#single-retry").click()
                expect(page.locator("#single-intent")).to_contain_text("sequence 2")
                D.wait_for("real candidate applied",lambda:applied("r2",2))
                check("real-candidate-hook-allow",hook("candidate")=="allow")
                recorded=req("GET",path+"/deployments")
                check("lost-response-retry-no-additional-sequence",len(recorded)==2 and recorded[0]["deployment_sequence"]==2)
                page.locator("#single-retry").click()
                expect(page.locator("#single-intent")).to_contain_text("sequence 2")
                check("explicit-retry-same-issuance",len(req("GET",path+"/deployments"))==2)
                review("r1")
                page.locator("#single-rollback").click()
                expect(page.locator("#single-intent")).to_contain_text("sequence 3")
                D.wait_for("real rollback baseline applied",lambda:applied("r1",3))
                check("real-rollback-hook-deny",hook("rollback")=="deny")
                page.locator("#single-refresh").click()
                expect(page.locator("#single-deployments")).to_contain_text("rollback · applied")
                final=req("GET",path+"/deployments")
                check("rollback-higher-sequence-exact-applied-ack",final[0]["deployment_sequence"]==3 and final[0]["revision"]=="r1" and final[0]["policy_sha256"]==sha(b"default: deny\n") and final[0]["status"]=="applied")
                snapshots["recorded_deployments"]=[{k:d[k] for k in ("deployment_sequence","revision","policy_sha256","action","status","applied_at_unix")} for d in final]
                check("independent-tenant-same-agent-id-empty",req("GET",f"/admin/v1/tenants/{beta}/agents/edge-single/revisions")==[])
                for role,credential in [("viewer",viewer),("operator",operator)]:
                    other=context.new_page()
                    login(other,credential)
                    check(role+"-browser-read-only",other.locator("#single-policy-panel .owner-action:visible").count()==0)
                    auth={"x-llm-firewall-admin-token":"Bearer "+credential}
                    check(role+"-server-mutation-refused",code("POST",path+"/revisions/r1/deploy",auth,{})==403)
                    other.close()
                check("no-browser-credential-storage",page.evaluate("localStorage.length+sessionStorage.length===0"))
                req("POST",path+"/revoke",{})
                page.locator("#single-refresh").click()
                expect(page.locator("#single-policy-status")).to_contain_text("Agent revoked")
                check("revocation-blocks-browser-mutation",page.locator("#single-deploy").is_disabled())
                check("revocation-blocks-server-mutation",code("POST",path+"/revisions/r1/deploy",admin,{})==400)
                check("no-script-errors",not errors)
                page.locator("#single-policy-panel").screenshot(path=str(args.output/f"{args.backend}-single-policy.png"))
            report["binaries"]={p.name:sha(p.read_bytes()) for p in (console_binary,agent_binary)}
            report["config_sha256"]={"console":sha((console_dir/"firewall.yaml").read_bytes())}
            inputs=[ROOT/"Cargo.lock",ROOT/"scripts/console-single-policy-acceptance.py"]+sorted((ROOT/"crates/proxy/src").rglob("*.rs"))+sorted((ROOT/"crates/proxy/src").glob("*.js"))+[ROOT/"crates/proxy/src/admin_dashboard.html"]
            report["source_sha256"]={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in inputs}
            report["status"]="passed"
    finally:
        text=json.dumps(report,indent=2,sort_keys=True)+"\n"
        if any(value and value in text for value in private):
            text=json.dumps({"format":FORMAT,"status":"failed","error":"report withheld: private value found"})+"\n"
        (args.output/f"{args.backend}-report.json").write_text(text)
    assert report["status"]=="passed"
    print(f"{args.backend}: {sum(checks.values())} checks passed")

if __name__=="__main__":
    main()
