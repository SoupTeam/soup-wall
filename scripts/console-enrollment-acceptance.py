#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Browser enrollment and credential lifecycle against a real Console and Agent.

One disposable private Linux deployment per run: a Console on loopback with
SQLite or a disposable TLS PostgreSQL cluster (local binaries, owned CA), an
owned private-CA HTTPS edge for the Agent and Chromium driving the Console's
enrollment panel. The Agent is the unchanged `agentfw serve` reading its
credential from SOUP_MANAGED_AGENT_TOKEN_FILE. Credentials exist only in this
process's memory and the run's private temporary directory; the retained
report and screenshots never contain one.

    python3 scripts/console-enrollment-acceptance.py --backend sqlite|postgres --output DIR [--no-build]
"""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sw-console-enrollment-acceptance/1"


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = module("enrollment_managed_helpers", "managed-policy-demo.py")
EDGE = module("enrollment_rollout_edge", "console-rollout-acceptance.py")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pg_bin(explicit):
    if explicit:
        return Path(explicit)
    found = sorted(Path("/usr/lib/postgresql").glob("*/bin/initdb"))
    assert found, "PostgreSQL server binaries are required for --backend postgres (or --pg-bin)"
    return found[-1].parent


def postgres(stack, temp, binaries):
    """A disposable TLS cluster owned by this run, on 127.0.0.1 only."""
    assert os.geteuid() != 0, "run the PostgreSQL backend as an ordinary user"
    data, tls = temp / "pgdata", temp / "pgtls"
    tls.mkdir(mode=0o700)
    run = lambda *words: subprocess.run(["openssl", *map(str, words)], check=True, capture_output=True, timeout=60)
    ca_key, ca, key, csr, cert, ext = (tls / n for n in ("ca.key", "ca.pem", "server.key", "server.csr", "server.pem", "server.ext"))
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key, "-out", ca, "-days", "2", "-subj", "/CN=Owned enrollment database CA")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr, "-subj", "/CN=127.0.0.1")
    ext.write_text("subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n")
    run("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial", "-out", cert, "-days", "2", "-extfile", ext)
    os.chmod(key, 0o600)
    password = secrets.token_urlsafe(24)
    # The generated password goes to initdb through its standard input only;
    # it is never written to a file.
    subprocess.run([str(binaries / "initdb"), "-D", str(data), "-U", "enrollment_owner", "--auth=scram-sha-256",
                    "--pwfile=/dev/stdin", "--no-instructions"], input=(password + "\n").encode(),
                   check=True, capture_output=True, timeout=120)
    port = D.port()
    (data / "postgresql.auto.conf").write_text(
        f"listen_addresses='127.0.0.1'\nport={port}\nunix_socket_directories='{data}'\nssl=on\n"
        f"ssl_cert_file='{cert}'\nssl_key_file='{key}'\n")
    (data / "pg_hba.conf").write_text("hostssl all enrollment_owner 127.0.0.1/32 scram-sha-256\n")
    subprocess.run([str(binaries / "pg_ctl"), "-D", str(data), "-l", str(temp / "postgres.log"), "-w", "start"],
                   check=True, capture_output=True, timeout=120)
    stack.callback(lambda: subprocess.run([str(binaries / "pg_ctl"), "-D", str(data), "-m", "fast", "-w", "stop"],
                                          capture_output=True, timeout=120))
    subprocess.run([str(binaries / "createdb"), "-h", "127.0.0.1", "-p", str(port), "-U", "enrollment_owner", "console"],
                   check=True, capture_output=True, timeout=60,
                   env=dict(os.environ, PGPASSWORD=password, PGSSLMODE="verify-full", PGSSLROOTCERT=str(ca)))
    url = f"postgresql://enrollment_owner:{password}@127.0.0.1:{port}/console?sslmode=require"
    return url, ca, password, binaries


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
              "scope": "one disposable private Linux deployment; synthetic tenants and Agent IDs; "
                       "not production, multi-host or runtime attestation"}

    def check(name, condition):
        checks[name] = bool(condition)
        if not condition:
            raise AssertionError(name)
        print("PASS:", name, flush=True)

    try:
        with tempfile.TemporaryDirectory(prefix="console-enrollment-") as folder, ExitStack() as stack:
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
            env.update(LLM_FW_ADMIN_TOKEN=owner, SOUP_AGENT_POLICY_KEY_ID="enrollment-issuer", SOUP_AGENT_POLICY_SEED_HEX=seed)
            store = '  backend: sqlite\n  database_path: "console.sqlite"\n'
            if args.backend == "postgres":
                url, db_ca, password, binaries = postgres(stack, temp, pg_bin(args.pg_bin))
                private += [password, url]
                env.update(LLM_FW_POSTGRES_URL=url, LLM_FW_POSTGRES_CA_CERT_FILE=str(db_ca))
                store = "  backend: postgres\n  postgres_command_timeout_ms: 30000\n  postgres_pool_wait_timeout_ms: 10000\n"
            config = console_dir / "firewall.yaml"
            config.write_text(f'bind: "127.0.0.1:{cp}"\ntenant_store:\n  enabled: true\n' + store, encoding="utf-8")
            if args.backend == "postgres":
                migrated = subprocess.run([str(console_binary), "migrate"], cwd=console_dir, env=env, capture_output=True, timeout=180)
                if migrated.returncode != 0:
                    print(migrated.stderr.decode("utf-8", "replace")[-600:].replace(password, "<private>"), flush=True)
                check("postgres-tls-migration", migrated.returncode == 0)

            def start_console(log):
                process = D.proc(stack, [str(console_binary)], console_dir, env, temp / log)
                D.wait_for("Console", lambda: D.request("GET", console + "/healthz")[0] == 200 or None, timeout=90)
                return process

            console_process = start_console("console.log")

            def api(method, path, payload=None, token=None, bearer=None):
                headers = {"Authorization": "Bearer " + bearer} if bearer else \
                    {"x-llm-firewall-admin-token": "Bearer " + (token or owner)}
                try:
                    return D.request(method, console + path, payload, headers, timeout=15)
                except urllib.error.HTTPError as error:
                    return error.code, None

            tenant_a = api("POST", "/admin/v1/tenants", {"name": "Enrollment Alpha"})[1]["id"]
            tenant_b = api("POST", "/admin/v1/tenants", {"name": "Enrollment Beta"})[1]["id"]
            base = f"/admin/v1/tenants/{tenant_a}/agents"
            viewer = api("POST", "/admin/v1/admins", {"name": "Enrollment viewer", "role": "viewer"})[1]["token"]
            operator = api("POST", "/admin/v1/admins", {"name": "Enrollment operator", "role": "operator"})[1]["token"]
            private += [viewer, operator]
            origin, ca, edge_counts, ca_fingerprint = EDGE.tls_edge(stack, temp, cp)
            issuer = api("GET", "/admin/v1/managed-issuer")[1]
            home = temp / "agent-home"
            (home / ".agentfw").mkdir(parents=True, mode=0o700)
            (home / ".agentfw").chmod(0o700)
            agent_port = D.port()
            (home / ".agentfw/config.yaml").write_text(f"bind: 127.0.0.1\nport: {agent_port}\nenforce: true\n")
            token_file = home / ".agentfw/enrollment-token"
            agent_env = {k: v for k, v in env.items() if not k.startswith(("SOUP_AGENT_POLICY_", "LLM_FW_"))}
            agent_env.update(HOME=str(home), SOUP_MANAGED_AGENT_CONSOLE=origin, SOUP_MANAGED_AGENT_TLS_CA_FILE=str(ca),
                             SOUP_MANAGED_AGENT_TOKEN_FILE=str(token_file), SOUP_MANAGED_AGENT_TENANT=tenant_a,
                             SOUP_MANAGED_AGENT_ID="edge-1", SOUP_MANAGED_AGENT_KEY_ID=issuer["key_id"],
                             SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX=issuer["public_key_hex"])
            agent_url = f"http://127.0.0.1:{agent_port}"

            def installer():
                """The exact install command the one-time view displays."""
                code = page.locator("#enroll-secret-steps li").first.locator("code")
                expect(code).to_contain_text("mktemp")
                return code.inner_text()

            def run_installer(command, token):
                return subprocess.run(["bash", "-c", command], input=token.encode(), capture_output=True, timeout=30,
                                      env={"PATH": "/usr/bin:/bin", "HOME": str(home),
                                           "SOUP_MANAGED_AGENT_TOKEN_FILE": str(token_file)})

            def install(token):
                result = run_installer(installer(), token)
                assert result.returncode == 0, "displayed installer failed: " + result.stderr.decode("utf-8", "replace")[-300:]
                assert token_file.read_text() == token and (token_file.stat().st_mode & 0o777) == 0o600

            def deploy(revision):
                path = base + "/edge-1/revisions"
                api("POST", path, {"revision": revision, "policy_yaml": f"default: allow\n# {revision}\n"})
                api("POST", f"{path}/{revision}/approve", {})
                return api("POST", f"{path}/{revision}/deploy", {})[1]

            def applied(revision, sequence):
                value = D.request("GET", agent_url + "/health")[1].get("managed_policy")
                return value if value and value["revision"] == revision and value["deployment_sequence"] == sequence else None

            def agent_auth(token):
                return {"whoami": api("GET", "/agent/v1/whoami", bearer=token)[0],
                        "policy": api("GET", "/agent/v1/policy", bearer=token)[0],
                        "ack": api("POST", "/agent/v1/policy/ack", {"deployment_sequence": 1, "revision": "r1",
                                   "policy_sha256": "0" * 64, "status": "applied"}, bearer=token)[0]}

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context(viewport={"width": 1440, "height": 1200})
                page = context.new_page()
                posts = []
                page.on("request", lambda r: posts.append(r.url.split("/admin/v1/tenants/")[-1])
                        if r.method == "POST" and "/admin/v1/tenants/" in r.url else None)

                def login(target, token):
                    target.goto(console + "/admin")
                    target.locator("#admin-token").fill(token)
                    target.locator("#unlock-form button").click()
                    expect(target.locator("#console")).to_be_visible()
                    target.locator("#tenant-list button").filter(has_text="Enrollment Alpha").click()
                    expect(target.locator("#enroll-status")).to_contain_text("Enrollment records read")

                def status(text, timeout=30_000):
                    expect(page.locator("#enroll-status")).to_contain_text(text, timeout=timeout)

                def secret():
                    value = page.locator("#enroll-secret-value").inner_text()
                    assert re.fullmatch(r"sw_agent_[A-Za-z0-9_-]{43}", value)
                    private.append(value)
                    return value

                def dismiss(label):
                    page.get_by_role("button", name="I stored it, clear it").click()
                    check(f"secret-cleared-after-{label}", not page.locator("#enroll-secret").is_visible()
                          and all(s not in page.content() for s in private if s.startswith("sw_agent_")))

                def confirm(text):
                    page.locator("#enroll-confirm-input").fill(text)
                    page.locator("#enroll-confirm-input").press("Enter")

                def shot(name):
                    page.locator("#enroll-panel").screenshot(path=str(args.output / f"{args.backend}-{name}.png"))

                login(page, owner)
                expect(page.locator("#enroll-list")).to_contain_text("No Agents are enrolled")
                shot("empty")
                # 1. Enroll through the keyboard; the credential appears once.
                page.locator("#enroll-agent-id").focus()
                page.keyboard.type("edge-1")
                page.keyboard.press("Enter")
                status("edge-1 enrolled")
                first = secret()
                expect(page.locator("#enroll-secret-steps")).to_contain_text(f"SOUP_MANAGED_AGENT_TENANT={tenant_a}")
                expect(page.locator("#enroll-secret-steps")).to_contain_text(issuer["public_key_hex"])
                check("credential-not-in-url-or-storage", first not in page.url
                      and page.evaluate("localStorage.length === 0 && sessionStorage.length === 0"))
                # The displayed installer refuses unsafe existing targets and
                # ignores a planted fixed-name staging link.
                command = installer()
                victim = temp / "owned-other-file"
                victim.write_text("owned other file\n")
                victim.chmod(0o644)
                token_file.symlink_to(victim)
                linked = run_installer(command, first)
                token_file.unlink()
                token_file.write_text("old public\n")
                token_file.chmod(0o644)
                public = run_installer(command, first)
                public_unchanged = token_file.read_text() == "old public\n"
                token_file.unlink()
                token_file.with_name(token_file.name + ".next").symlink_to(victim)
                check("displayed-installer-refuses-link-and-public-target",
                      linked.returncode != 0 and public.returncode != 0 and public_unchanged
                      and victim.read_text() == "owned other file\n" and (victim.stat().st_mode & 0o777) == 0o644)
                install(first)
                check("displayed-installer-private-and-ignores-planted-staging-link",
                      victim.read_text() == "owned other file\n" and (token_file.stat().st_mode & 0o777) == 0o600)
                token_file.with_name(token_file.name + ".next").unlink()
                dismiss("enrollment")
                expect(page.locator("#enroll-list")).to_contain_text("edge-1")
                shot("enrolled")
                check("enrolled-whoami", agent_auth(first)["whoami"] == 200)

                # 2. Legitimate fetch and applied acknowledgement over HTTPS.
                deploy("r1")
                agent = D.proc(stack, [str(agent_binary), "serve"], temp, agent_env, temp / "agent.log")
                D.wait_for("Agent health", lambda: D.request("GET", agent_url + "/health")[1])
                D.wait_for("r1 applied", lambda: applied("r1", 1), timeout=120)
                check("enrolled-agent-fetched-and-acknowledged", True)

                # 3. Rotation in the browser; the same Agent process reloads the file.
                page.get_by_role("button", name="Rotate credential for edge-1").click()
                confirm("edge-1")
                status("rotated to generation 2")
                second = secret()
                check("old-credential-refused-after-rotation", set(agent_auth(first).values()) == {401})
                install(second)
                dismiss("rotation")
                deploy("r2")
                D.wait_for("r2 applied with the rotated credential", lambda: applied("r2", 2), timeout=120)
                check("same-agent-process-uses-rotated-credential", agent.poll() is None)
                expect(page.locator("#enroll-list")).to_contain_text("2")

                # 4. Ambiguous rotation: committed, response lost; confirmed only by
                #    the identical request.
                def lose(route):
                    route.fetch()
                    route.abort("failed")

                page.route("**/agents/edge-1/credential-rotations", lose, times=1)
                before = len(posts)
                page.get_by_role("button", name="Rotate credential for edge-1").click()
                confirm("edge-1")
                status("Confirm with the same request")
                check("ambiguous-rotation-shows-no-credential", not page.locator("#enroll-secret").is_visible())
                page.get_by_role("button", name="Confirm with the same request").click()
                status("this exact request was already committed")
                third = secret()
                check("ambiguous-rotation-two-identical-posts-one-change",
                      len(posts) - before == 2 and api("GET", base)[1][0]["credential_generation"] == 3)
                check("second-credential-refused", set(agent_auth(second).values()) == {401})
                install(third)
                dismiss("confirmed-rotation")
                deploy("r3")
                D.wait_for("r3 applied", lambda: applied("r3", 3), timeout=120)
                shot("rotated")

                # 5. Delayed enrollment response after a tenant switch.
                held = []
                page.route("**/admin/v1/tenants/*/agents", lambda r: held.append(r) if r.request.method == "POST" else r.continue_())
                page.locator("#enroll-agent-id").fill("edge-race")
                page.locator("#enroll-form button").click()
                status("sending")
                page.locator("#tenant-list button").filter(has_text="Enrollment Beta").click()
                status("Enrollment records read")
                response = held[0].fetch()
                held[0].fulfill(response=response)
                page.unroute("**/admin/v1/tenants/*/agents")
                page.wait_for_timeout(500)
                check("late-enrollment-not-shown-in-other-tenant", not page.locator("#enroll-secret").is_visible()
                      and "edge-race" not in page.locator("#enroll-panel").inner_text())
                check("late-enrollment-committed-only-to-submitted-tenant",
                      any(a["agent_id"] == "edge-race" for a in api("GET", base)[1])
                      and api("GET", f"/admin/v1/tenants/{tenant_b}/agents")[1] == [])
                page.locator("#tenant-list button").filter(has_text="Enrollment Alpha").click()
                status("Enrollment records read")

                # 6. Role, cross-tenant and credential-type negatives.
                viewer_page = browser.new_context(viewport={"width": 1440, "height": 1000}).new_page()
                login(viewer_page, viewer)
                check("viewer-browser-has-no-enrollment-controls",
                      viewer_page.locator("#enroll-panel .owner-action:visible").count() == 0
                      and viewer_page.locator("#enroll-list button").count() == 0)
                viewer_page.locator("#enroll-panel").screenshot(path=str(args.output / f"{args.backend}-viewer.png"))
                viewer_page.context.close()
                rotation = {"expected_generation": 3, "operation_id": secrets.token_hex(16),
                            "replacement_token": "sw_agent_" + secrets.token_urlsafe(32)}
                refused = {}
                for role, token in (("viewer", viewer), ("operator", operator)):
                    refused[role + " enroll"] = api("POST", base, {"agent_id": "forbidden"}, token)[0]
                    refused[role + " rotate"] = api("POST", base + "/edge-1/credential-rotations", rotation, token)[0]
                    refused[role + " revoke"] = api("POST", base + "/edge-1/revoke", {}, token)[0]
                check("viewer-and-operator-lifecycle-refused-403", set(refused.values()) == {403})
                cross = {"rotate": api("POST", f"/admin/v1/tenants/{tenant_b}/agents/edge-1/credential-rotations", rotation)[0],
                         "revoke": api("POST", f"/admin/v1/tenants/{tenant_b}/agents/edge-1/revoke", {})[0]}
                check("cross-tenant-lifecycle-refused", cross["rotate"] == 409 and cross["revoke"] == 404)
                check("agent-credential-cannot-administer", api("POST", base, {"agent_id": "x"}, third)[0] == 401)
                check("negatives-changed-nothing", api("GET", base)[1][0]["credential_generation"] == 3
                      and agent_auth(third)["whoami"] == 200)
                snapshots["refused"] = {**refused, **{"cross-tenant " + k: v for k, v in cross.items()}}
                # An Owner session that loses authorization while the panel is
                # open: the next inventory read locks every change.
                second_owner = api("POST", "/admin/v1/admins", {"name": "Enrollment second owner", "role": "owner"})[1]
                private.append(second_owner["token"])
                lost_page = browser.new_context(viewport={"width": 1440, "height": 1000}).new_page()
                login(lost_page, second_owner["token"])
                enabled = "[...document.querySelectorAll('#enroll-panel .enroll-mutation')].filter(b => !b.disabled).length"
                was_enabled = lost_page.evaluate(enabled)
                api("POST", f"/admin/v1/admins/{second_owner['admin']['id']}/revoke", {})
                lost_posts = []
                lost_page.on("request", lambda r: lost_posts.append(r.url) if r.method == "POST" else None)
                lost_page.locator("#enroll-refresh").click()
                expect(lost_page.locator("#enroll-status")).to_contain_text("Reading enrollment records: the admin session expired")
                lost_page.locator("#enroll-agent-id").fill("edge-after-revocation")
                lost_page.locator("#enroll-agent-id").press("Enter")
                lost_page.wait_for_timeout(300)
                check("revoked-admin-session-locks-panel-on-read", was_enabled > 0 and lost_page.evaluate(enabled) == 0
                      and lost_posts == [])
                lost_page.context.close()

                # 7. Revocation; the Agent keeps its last verified policy.
                page.get_by_role("button", name="Revoke edge-1").click()
                confirm("edge-1")
                status("edge-1 revoked")
                check("revoked-credential-refused", set(agent_auth(third).values()) == {401})
                check("revoked-agent-keeps-last-policy", bool(applied("r3", 3)))
                shot("revoked")

                # 8. Unavailable API: reads fail, an enrollment outcome stays
                #    unknown until the server answers again.
                console_process.terminate()
                console_process.wait(timeout=15)
                page.locator("#enroll-refresh").click()
                status("Unable to load enrollment records")
                page.locator("#enroll-agent-id").fill("edge-offline")
                page.locator("#enroll-form button").click()
                status("could not be read")
                check("unavailable-api-keeps-changes-disabled",
                      page.evaluate("[...document.querySelectorAll('#enroll-panel .enroll-mutation')].every(b => b.disabled)"))
                shot("unavailable")
                console_process = start_console("console-restarted.log")
                page.get_by_role("button", name="Check again").click()
                status("is not recorded. You may enroll it again")
                check("restart-retains-lifecycle-state", sorted((a["agent_id"], a["credential_generation"], a["revoked_at_unix"] is not None)
                      for a in api("GET", base)[1]) == [("edge-1", 3, True), ("edge-race", 1, False)])
                page.set_viewport_size({"width": 390, "height": 1000})
                check("narrow-layout-no-horizontal-overflow",
                      page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1"))
                page.locator("#enroll-panel").screenshot(path=str(args.output / f"{args.backend}-narrow.png"))
                check("browser-no-storage", page.evaluate("localStorage.length === 0 && sessionStorage.length === 0"))
                context.close()
                browser.close()

            check("agent-used-https-edge", edge_counts["forwarded"] > 0)
            report["transport"] = {"agent_to_console": "HTTPS through an owned private-CA edge on 127.0.0.1",
                                   "ca_sha256_fingerprint": ca_fingerprint, "edge_forwarded_requests": edge_counts["forwarded"],
                                   "browser_to_console": "loopback HTTP",
                                   "console_to_database": "TLS (sslmode=require) verified against an owned CA by the Console rustls connector" if args.backend == "postgres" else "local SQLite file"}
            report["config_sha256"] = {"console": sha(config.read_bytes()), "agent": sha((home / ".agentfw/config.yaml").read_bytes())}
            report["binary_sha256"] = {p.name: sha(p.read_bytes()) for p in (console_binary, agent_binary)}
            if args.backend == "postgres":
                report["postgres_version"] = subprocess.check_output([str(binaries / "postgres"), "--version"], text=True).strip()
        report["cleanup"] = "temporary directory, Console, Agent, edge" + (" and PostgreSQL cluster" if args.backend == "postgres" else "") + " stopped and removed"
        raw = json.dumps(report)
        check("evidence-sanitized", all(s not in raw for s in private))
        report["status"] = "passed"
    except Exception as error:
        message = str(error)
        for value in private:
            message = message.replace(value, "<private>")
        report["error"] = re.sub(r"\s+", " ", message)[:400]
        raise
    finally:
        (args.output / f"{args.backend}-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "backend": args.backend, "checks": len(checks)}))


if __name__ == "__main__":
    main()
