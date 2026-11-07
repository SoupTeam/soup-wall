#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Browser enrollment and credential lifecycle against a real Console and Agent.

One disposable private Linux deployment per run: a Console on loopback with
SQLite or a disposable TLS PostgreSQL cluster (local binaries, owned CA), an
owned private-CA HTTPS edge for the Agent and Chromium driving the Console's
enrollment panel. The copied Agent binary is installed into a private home
and runs through the displayed managed-console and lifecycle commands. Credentials exist only in this
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
import shutil
import subprocess
import tempfile
import time
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sw-console-enrollment-acceptance/2"


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = module("enrollment_managed_helpers", "managed-policy-demo.py")
EDGE = module("enrollment_rollout_edge", "console-rollout-acceptance.py")
AUDIT = module("operator_audit_controls", "console_operator_audit_controls.py")
write_private = module("enrollment_private_files", "managed-credential-rotation-demo.py").replace_secret


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
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    args.output = args.output.resolve()
    assert not args.output.is_relative_to(ROOT), "--output must be outside the checkout"
    args.output.mkdir(parents=True, exist_ok=True)
    if not args.no_build:
        subprocess.run(["cargo", "build", "--locked", "-p", "llm-firewall", "-p", "agentfw"], cwd=ROOT, check=True)
    console_binary, agent_binary = ROOT / "target/debug/llm-firewall", ROOT / "target/debug/agentfw"
    checks, snapshots, private = {}, {}, []
    outputs = []
    source_inputs = {}
    fixtures = {"scripts/console-enrollment-acceptance.py", "scripts/console_operator_audit_controls.py",
                "scripts/console-rollout-acceptance.py", "scripts/managed-policy-demo.py",
                "scripts/managed-credential-rotation-demo.py",
                "scripts/tests/test_console_enrollment_browser.py", ".github/workflows/agent-fleet.yml",
                "Cargo.toml", "Cargo.lock", "rust-toolchain.toml"}
    for name in subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines():
        if name in fixtures or name.startswith(("crates/agentfw/src/", "crates/proxy/src/")):
            source_inputs[name] = sha((ROOT / name).read_bytes())
    loss_probe = {}
    report = {"format": FORMAT, "backend": args.backend, "status": "failed", "checks": checks, "snapshots": snapshots,
              "source_sha256": source_inputs, "tasks": ["SOU-233", "SOU-234"],
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
              "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "scope": "one disposable private Linux deployment; synthetic tenants and Agent IDs; "
                       "not production, multi-host or runtime attestation",
              "diagnostic_observer": {
                  "scope": "ephemeral runner observation; not public-source qualification",
                  "baseline_head": "ea670e69e192d342202f7992cc3fb54a67606666",
                  "modified_console_and_driver": True,
                  "binary_sha256": {p.name: sha(p.read_bytes()) for p in (console_binary, agent_binary)},
                  "driver_sha256": sha(Path(__file__).read_bytes()),
              }}

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
            owner, seed, alternate_seed = secrets.token_urlsafe(32), secrets.token_hex(32), secrets.token_hex(32)
            private += [owner, seed, alternate_seed]
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("SOUP_MANAGED_AGENT_", "SOUP_AGENT_POLICY_", "LLM_FW_", "OPENAI_", "PG"))}
            env.update(LLM_FW_ADMIN_TOKEN=owner, SOUP_AGENT_POLICY_KEY_ID="enrollment-issuer", SOUP_AGENT_POLICY_SEED_HEX=seed,
                       SOUP_AGENT_POLICY_SEED_HEX_UNTRUSTED_FIXTURE=alternate_seed)
            store = '  backend: sqlite\n  database_path: "console.sqlite"\n'
            url = db_ca = binaries = None
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

            def api(method, path, payload=None, token=None, bearer=None, idempotency=None):
                headers = {"Authorization": "Bearer " + bearer} if bearer else \
                    {"x-llm-firewall-admin-token": "Bearer " + (token or owner)}
                if idempotency:
                    headers["Idempotency-Key"] = idempotency
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
            trusted_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)).public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw).hex()
            check("issuer-confirmed-from-independent-fixture-seed",
                  issuer == {"key_id": "enrollment-issuer", "public_key_hex": trusted_key})
            home = temp / "agent-home"
            profile = home / ".agentfw"
            profile.mkdir(parents=True, mode=0o700)
            home.chmod(0o700)
            profile.chmod(0o700)
            agent_port = D.port()
            (profile / "config.yaml").write_text(f"bind: 127.0.0.1\nport: {agent_port}\nenforce: true\n")
            (profile / "config.yaml").chmod(0o600)
            token_file = profile / "enrollment-token"
            selector = profile / "managed-console.json"
            trust_file = profile / "trusted-issuers.json"
            ca_file = profile / "console-ca.pem"
            keyring = {"schema_version": 1, "issuers": [{"key_id": "enrollment-issuer",
                       "public_key_hex": trusted_key, "revoked": False}]}
            installed = temp / "bin"
            installed.mkdir(mode=0o700)
            binary = installed / "agentfw"
            shutil.copyfile(agent_binary, binary)
            binary.chmod(0o700)
            agent_env = {k: v for k, v in env.items() if not k.startswith(("SOUP_AGENT_POLICY_", "LLM_FW_"))}
            agent_env.update(HOME=str(home), PATH=str(installed) + ":/usr/bin:/bin")
            agent_url = f"http://127.0.0.1:{agent_port}"

            def shell(command, expected=True):
                assert all(value not in command for value in private if value != str(temp))
                result = subprocess.run(["bash", "-c", command], cwd=temp, env=agent_env,
                                        capture_output=True, timeout=60)
                outputs.append(result.stdout + result.stderr)
                assert (result.returncode == 0) == expected, "Installed command returned an unexpected exit status"
                return json.loads(result.stdout) if result.stdout.lstrip().startswith(b"{") else None

            def managed(words):
                return shell("agentfw managed-console " + words)

            check("installed-binary-and-working-directory-outside-checkout",
                  not binary.is_relative_to(ROOT) and not temp.is_relative_to(ROOT))
            shell(f"agentfw lifecycle install 233.0.0 '{binary}' --sha256 {sha(binary.read_bytes())}")
            stack.callback(lambda: subprocess.run([str(binary), "lifecycle", "stop"], cwd=temp, env=agent_env,
                                                  capture_output=True, timeout=45))

            def installer():
                """The exact install command the one-time view displays."""
                code = page.locator("#enroll-secret-steps li").first.locator("code")
                expect(code).to_contain_text("mktemp")
                return code.inner_text()

            def run_installer(command, token):
                assert token not in command
                result = subprocess.run(["bash", "-c", command], input=token.encode(), capture_output=True,
                                        cwd=temp, timeout=30, env=agent_env)
                outputs.append(result.stdout + result.stderr)
                return result

            def install(token):
                result = run_installer(installer(), token)
                assert result.returncode == 0, "displayed installer failed: " + result.stderr.decode("utf-8", "replace")[-300:]
                assert token_file.read_text() == token and (token_file.stat().st_mode & 0o777) == 0o600

            def deploy(revision, decision="allow", issuer_key=None):
                path = base + "/edge-1/revisions"
                assert api("POST", path, {"revision": revision,
                                          "policy_yaml": f"default: {decision}\n# {revision}\n"})[0] == 201
                assert api("POST", f"{path}/{revision}/approve", {})[0] == 204
                code, deployment = api("POST", f"{path}/{revision}/deploy",
                                       {"issuer_key_id": issuer_key} if issuer_key else {})
                assert code == 201
                return deployment

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
                browser_errors = []
                page.on("pageerror", lambda error: browser_errors.append(type(error).__name__))
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
                expect(page.locator("#enroll-connection-issuer")).to_contain_text(trusted_key)
                page.locator("#enroll-console-origin").fill(origin)
                page.locator("#enroll-private-ca").check()
                command_rows = page.locator("#enroll-connection-steps code")
                preview = command_rows.filter(has_text="managed-console preview").inner_text()
                apply = command_rows.filter(has_text="managed-console apply").inner_text()
                check("displayed-installed-command-binds-exact-audience-and-ca",
                      f"--tenant '{tenant_a}'" in preview and "--agent 'edge-1'" in preview
                      and origin in preview and "--ca-file" in preview and first not in (preview + apply))
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

                # 2. Run the exact preview/apply commands shown by Console.
                # A queued signed policy forces issuer validation during setup.
                first_deployment = deploy("r1", "deny")
                write_private(trust_file, json.dumps({**keyring, "issuers": [
                    {**keyring["issuers"][0], "public_key_hex": "01" * 32}]}))
                other_ca_key = temp / "wrong-ca.key"
                subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                "-keyout", str(other_ca_key), "-out", str(ca_file), "-days", "2",
                                "-subj", "/CN=Unrelated fixture CA"], check=True, capture_output=True, timeout=45)
                ca_file.chmod(0o600)
                shell(apply.replace("PREVIEW_DIGEST", shell(preview)["confirmation"]), expected=False)
                check("incorrect-ca-preserves-absent-selector", not selector.exists())
                write_private(ca_file, ca.read_text())
                shell(apply.replace("PREVIEW_DIGEST", shell(preview)["confirmation"]), expected=False)
                check("incorrect-issuer-preserves-absent-selector", not selector.exists())
                write_private(trust_file, json.dumps(keyring))
                pending = shell(apply.replace("PREVIEW_DIGEST", shell(preview)["confirmation"]))
                check("corrected-setup-configures-without-applying",
                      pending["status"] == "committed" and managed("inspect")["runtime_authenticated"] is False)
                probe = managed("verify")
                check("signed-bundle-probe-is-not-an-application",
                      probe["verification"]["state"] == "verified_candidate"
                      and probe["verification"]["applied"] is False and probe["recorded_application"] is None)
                page.locator("#enroll-connection-refresh").click()
                expect(page.locator("#enroll-connection-evidence")).to_contain_text("Bundle fetched, awaiting application")
                expect(page.locator("#enroll-connection-evidence")).to_contain_text("No authenticated application")
                shell("agentfw lifecycle start")
                D.wait_for("r1 applied", lambda: applied("r1", 1), timeout=120)
                def confirmed():
                    rows = api("GET", base + "/edge-1/deployments")[1]
                    return rows[0] if rows and rows[0]["status"] == "applied" else None
                ack = D.wait_for("first Console application acknowledgement", confirmed, timeout=120)
                inspect = managed("inspect")
                check("first-application-exact-identity-and-live-connection",
                      inspect["runtime_authenticated"] and inspect["running_matches_configured"]
                      and inspect["recorded_application"]["managed_sequence"] == 1
                      and ack["policy_sha256"] == first_deployment["policy_sha256"])
                hook_token = (profile / "token").read_text().strip()
                private.append(hook_token)

                def verdict(label):
                    _, response = D.request("POST", agent_url + "/hook",
                        {"session_id": "sou233-" + label, "hook_event_name": "PreToolUse", "tool_name": "Bash",
                         "tool_input": {"command": "echo harmless"}}, {"Authorization": "Bearer " + hook_token})
                    return "allow" if response == {} else response["hookSpecificOutput"]["permissionDecision"]

                check("first-signed-policy-changes-real-hook-decision", verdict("first") == "deny")
                page.locator("#enroll-connection-refresh").click()
                expect(page.locator("#enroll-connection-evidence")).to_contain_text("Last authenticated application acknowledgement: #1")
                page.locator("#enroll-connection-policy").click()
                expect(page.locator("#single-agent")).to_have_value("edge-1")
                first_pid = shell("agentfw lifecycle status")["process"]["pid"]
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
                check("same-agent-process-uses-rotated-credential",
                      shell("agentfw lifecycle status")["process"]["pid"] == first_pid
                      and verdict("rotated") == "allow")
                expect(page.locator("#enroll-list")).to_contain_text("2")

                # 4. Ambiguous rotation: committed, response lost; confirmed only by
                #    the identical request.
                review_probe_started = time.monotonic()
                loss_probe["review_server_log_start_bytes"] = (temp / "console.log").stat().st_size

                def review_offset_ms():
                    return min(120_000, max(0, round((time.monotonic() - review_probe_started) * 1000)))

                def review_server_snapshot(end):
                    try:
                        with (temp / "console.log").open("rb") as stream:
                            start = loss_probe["review_server_log_start_bytes"]
                            stream.seek(start)
                            raw = stream.read(max(0, min(32_769, end - start)))
                        events, parse_failed = [], end < start
                        for line in raw[:32_768].decode("ascii", errors="replace").splitlines():
                            if not line.startswith("REVIEW_ENROLLMENT"):
                                continue
                            match = re.fullmatch(
                                r"REVIEW_ENROLLMENT (arrival|completion) ([0-9]{1,2}) ([0-9]{1,9})(?: ([0-9]{3}))?", line)
                            if not match:
                                parse_failed = True
                                continue
                            event, sequence, offset, status = match.groups()
                            sequence, offset = int(sequence), int(offset)
                            status = int(status) if status else None
                            if (len(events) >= 128 or sequence >= 64 or offset > 2_400_000
                                    or (event == "completion" and (status is None or not 100 <= status <= 599))
                                    or (event == "arrival" and status is not None)):
                                parse_failed = True
                                continue
                            events.append({"event": event, "sequence": sequence,
                                           "server_offset_ms": offset, "status": status})
                        return {"events": events, "truncated": len(raw) > 32_768,
                                "read_failed": False, "parse_failed": parse_failed}
                    except OSError:
                        return {"events": [], "truncated": False, "read_failed": True, "parse_failed": False}

                def lose(route):
                    loss_probe["review_route_enter_ms"] = review_offset_ms()
                    loss_probe["started"] = True
                    try:
                        response = route.fetch()
                        loss_probe["downstream_status"] = response.status
                        loss_probe["review_post_fetched_ms"] = review_offset_ms()
                        assert response.status == 200, "Loss probe did not receive a committed rotation response"
                    except Exception as error:
                        loss_probe["fetch_error_type"] = type(error).__name__[:60]
                        raise
                    finally:
                        # Even a failed probe must release the paused browser request.
                        route.abort("failed")
                        loss_probe["abort_requested"] = True
                        loss_probe["review_abort_returned_ms"] = review_offset_ms()

                # Phase-scoped public metadata only. Never retain request URLs,
                # headers, response bodies or exception messages.
                reconciliation_probe = loss_probe.setdefault("reconciliation_get", {
                    "request_seen": False, "response_seen": False, "finished": False,
                    "network_failed": False, "metadata_callback_error": False,
                })

                def observe_reconciliation(event, value):
                    try:
                        request = value.request if event == "response" else value
                        if not (loss_probe.get("started") and request.method == "GET"
                                and request.url == console + base + "/enrollment?agent_id=edge-1"):
                            return
                        reconciliation_probe["review_" + event + "_ms"] = review_offset_ms()
                        if event == "request":
                            reconciliation_probe["request_seen"] = True
                        elif event == "response":
                            reconciliation_probe.update(response_seen=True, status=value.status)
                        elif event == "requestfinished":
                            reconciliation_probe["finished"] = True
                        else:
                            known = {"net::ERR_FAILED", "net::ERR_ABORTED", "net::ERR_CONNECTION_RESET",
                                     "net::ERR_CONNECTION_CLOSED", "net::ERR_TIMED_OUT"}
                            reconciliation_probe.update(network_failed=True,
                                network_failure=request.failure if request.failure in known else "other")
                    except Exception:
                        reconciliation_probe["metadata_callback_error"] = True

                rotation_observers = [
                    (event, lambda value, event=event: observe_reconciliation(event, value))
                    for event in ("request", "response", "requestfailed", "requestfinished")
                ]
                for event, observer in rotation_observers:
                    page.on(event, observer)

                def failed_rotation(request):
                    if request.method == "POST" and request.url.endswith("/credential-rotations"):
                        known = {"net::ERR_FAILED", "net::ERR_ABORTED", "net::ERR_CONNECTION_RESET", "net::ERR_CONNECTION_CLOSED"}
                        loss_probe["network_failure"] = request.failure if request.failure in known else "other"

                page.on("requestfailed", failed_rotation)

                page.route("**/agents/edge-1/credential-rotations", lose, times=1)
                before = len(posts)
                page.get_by_role("button", name="Rotate credential for edge-1").click()
                confirm("edge-1")
                review_assertion_passed = False
                try:
                    status("Confirm with the same request")
                    review_assertion_passed = True
                finally:
                    review_end = (temp / "console.log").stat().st_size
                    report["review_before_browser_cleanup"] = {
                        "offset_ms": review_offset_ms(),
                        "assertion_passed": review_assertion_passed,
                        "page_closed": page.is_closed(),
                        "server_log_end_bytes": review_end,
                        "reconciliation_get": dict(reconciliation_probe),
                        "server_observation": review_server_snapshot(review_end),
                    }
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
                for event, observer in rotation_observers:
                    page.remove_listener(event, observer)
                reconciliation_probe["observers_detached"] = True
                report["rotation_loss_probe"] = json.loads(json.dumps(loss_probe))
                loss_probe.clear()

                # Lose the real 201 one-time enrollment response. The exact
                # enrollment is reconciled and rotated, never automatically repeated.
                lost_enrollment = {}
                def lose_enrollment(route):
                    if route.request.method != "POST":
                        route.continue_()
                        return
                    try:
                        response = route.fetch()
                        lost_enrollment["status"] = response.status
                    finally:
                        route.abort("failed")

                page.route("**/admin/v1/tenants/*/agents", lose_enrollment)
                before = len(posts)
                page.locator("#enroll-agent-id").fill("edge-lost")
                page.locator("#enroll-form button").click()
                status("its one-time credential did not reach this browser")
                page.unroute("**/admin/v1/tenants/*/agents", lose_enrollment)
                check("lost-one-time-credential-reconciles-exactly-one-enrollment",
                      lost_enrollment.get("status") == 201 and len(posts) - before == 1
                      and not page.locator("#enroll-secret").is_visible()
                      and api("GET", base + "/enrollment?agent_id=edge-lost")[1]["credential_generation"] == 1)
                page.get_by_role("button", name="Rotate credential for edge-lost").click()
                confirm("edge-lost")
                status("Credential of edge-lost rotated to generation 2")
                recovered = secret()
                check("lost-enrollment-recovered-by-rotation-in-place",
                      api("GET", "/agent/v1/whoami", bearer=recovered)[1]["agent_id"] == "edge-lost")
                dismiss("lost-enrollment-recovery")
                before = len(posts)
                page.get_by_role("button", name="Revoke edge-lost").click()
                page.locator("#enroll-confirm").get_by_role("button", name="Cancel", exact=True).click()
                check("cancelled-revocation-never-sends-a-mutation",
                      len(posts) == before and api("GET", "/agent/v1/whoami", bearer=recovered)[0] == 200)
                page.get_by_role("button", name="Revoke edge-lost").click()
                confirm("edge-lost")
                status("edge-lost revoked")

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
                      and viewer_page.locator("#enroll-list .enroll-mutation").count() == 0)
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

                # Genuine Agent rejection of a correctly issued bundle from an
                # independently untrusted signer leaves the last applied policy visible.
                rejected = deploy("rejected-candidate", "deny", "untrusted-fixture")
                def rejected_record():
                    rows = api("GET", base + "/edge-1/deployments")[1]
                    return rows[0] if rows and rows[0]["status"] == "rejected" else None

                D.wait_for("Agent reported rejection of unknown issuer", rejected_record, timeout=120)
                page.get_by_role("button", name="Connection setup for edge-1").click()
                expect(page.locator("#enroll-connection-evidence")).to_contain_text("Candidate rejected")
                expect(page.locator("#enroll-connection-evidence")).to_contain_text("Last authenticated application acknowledgement: #3")
                check("real-rejected-candidate-preserves-previous-policy-and-history",
                      rejected["deployment_sequence"] == 4 and bool(applied("r3", 3))
                      and verdict("after-rejected") == "allow")

                # 7. Guarded disconnect retains the last signed policy and stops sync.
                shell("agentfw lifecycle stop")
                write_private(profile / "user-note.txt", "owned data survives disconnect")
                retained = {p.name: sha(p.read_bytes()) for p in profile.iterdir()
                            if p.is_file() and p.name != "managed-console.json"}
                disconnect = managed("disconnect-preview")["confirmation"]
                managed("disconnect --confirm " + disconnect)
                check("disconnect-preserves-local-policy-and-user-data",
                      all((profile / name).is_file() and sha((profile / name).read_bytes()) == digest
                          for name, digest in retained.items()))
                forwarded = edge_counts["forwarded"]
                shell("agentfw lifecycle start")
                after_disconnect = deploy("after-disconnect", "deny")
                time.sleep(5)
                check("disconnected-keeps-protection-and-new-deployment-pending",
                      edge_counts["forwarded"] == forwarded
                      and managed("inspect")["configured"]["enabled"] is False
                      and managed("inspect")["transport"]["state"] == "disconnected"
                      and verdict("disconnected") == "allow"
                      and api("GET", base + "/edge-1/deployments")[1][0]["status"] == "issued"
                      and after_disconnect["deployment_sequence"] == 5)
                page.get_by_role("button", name="Connection setup for edge-1").click()
                expect(page.locator("#enroll-connection-evidence")).to_contain_text("Latest deployment: #5")
                expect(page.locator("#enroll-connection-evidence")).to_contain_text("Last authenticated application acknowledgement: #3")

                # Revocation retains the last verified policy.
                page.get_by_role("button", name="Revoke edge-1").click()
                confirm("edge-1")
                status("edge-1 revoked")
                check("revoked-credential-refused", set(agent_auth(third).values()) == {401})
                check("revoked-agent-keeps-last-policy", bool(applied("r3", 3)))
                shot("revoked")

                # Operator audit is exercised on the same real Console and store.
                sql = AUDIT.database(args.backend, console_dir, url, db_ca, binaries, env)
                audit_proof = AUDIT.audit_controls(api, sql, args.backend, viewer, check, private)
                page.locator("#refresh-tenants").click()
                page.locator("#tenant-list button").filter(has_text="Audit Alpha").click()
                page.locator("#operator-audit-load").click()
                expect(page.locator("#operator-audit-rows")).to_contain_text("agent.rotate")
                with page.expect_download() as exported:
                    page.locator("#operator-audit-download").click()
                payload = json.loads(Path(exported.value.path()).read_text())
                check("browser-exports-only-selected-tenant-operator-events",
                      payload["tenant_id"] == audit_proof["tenant"] and payload["events"] == audit_proof["events"]
                      and not any(value in json.dumps(payload) for value in private))
                page.locator("#tenant-list button").filter(has_text="Enrollment Alpha").click()
                expect(page.locator("#operator-audit-download")).to_be_disabled()

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
                check("restart-retains-operator-audit",
                      api("GET", audit_proof["path"], token=viewer)[1]["events"] == audit_proof["events"])
                check("restart-retains-lifecycle-state", sorted((a["agent_id"], a["credential_generation"], a["revoked_at_unix"] is not None)
                      for a in api("GET", base)[1]) == [("edge-1", 3, True), ("edge-lost", 2, True), ("edge-race", 1, False)])
                page.set_viewport_size({"width": 390, "height": 1000})
                check("narrow-layout-no-horizontal-overflow",
                      page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1"))
                page.locator("#enroll-panel").screenshot(path=str(args.output / f"{args.backend}-narrow.png"))
                check("browser-no-storage", page.evaluate("localStorage.length === 0 && sessionStorage.length === 0"))
                check("enrollment-page-has-no-uncaught-errors", not browser_errors)
                context.close()
                browser.close()

            # Reconstruct the additive predecessor schema on this owned database.
            # Reopening/migrating must preserve old rows, without inventing audit history.
            preserved_paths = [base, base + "/edge-1/deployments",
                               f"/admin/v1/tenants/{audit_proof['tenant']}/policy-versions"]
            old_records = [api("GET", path)[1] for path in preserved_paths]
            assert all(old_records), "Upgrade fixture did not contain predecessor records"
            console_process.terminate()
            console_process.wait(timeout=15)
            sql("DROP TABLE operator_audit_events;" +
                (" DELETE FROM llm_firewall_schema_migrations WHERE version=31;" if args.backend == "postgres" else ""))
            if args.backend == "postgres":
                migration = subprocess.run([str(console_binary), "migrate"], cwd=console_dir, env=env,
                                           capture_output=True, timeout=180)
                check("postgres-schema-30-to-31-explicit-migration", migration.returncode == 0)
            console_process = start_console("console-upgraded.log")
            check("schema-upgrade-keeps-existing-inventory-and-starts-empty-audit",
                  old_records == [api("GET", path)[1] for path in preserved_paths]
                  and api("GET", audit_proof["path"], token=viewer)[1]["events"] == [])
            check("agent-used-https-edge", edge_counts["forwarded"] > 0)
            report["transport"] = {"agent_to_console": "HTTPS through an owned private-CA edge on 127.0.0.1",
                                   "ca_sha256_fingerprint": ca_fingerprint, "edge_forwarded_requests": edge_counts["forwarded"],
                                   "browser_to_console": "loopback HTTP",
                                   "console_to_database": "TLS (sslmode=require) verified against an owned CA by the Console rustls connector" if args.backend == "postgres" else "local SQLite file"}
            report["config_sha256"] = {"console": sha(config.read_bytes()), "agent": sha((home / ".agentfw/config.yaml").read_bytes())}
            report["binary_sha256"] = {p.name: sha(p.read_bytes()) for p in (console_binary, binary)}
            safe_outputs = b"\n".join(outputs + [
                (temp / name).read_bytes() for name in ("console.log", "console-restarted.log", "console-upgraded.log")
            ])
            check("private-material-absent-from-cli-and-console-logs",
                  not any(value.encode() in safe_outputs for value in private if len(value) >= 32 and value != str(temp)))
            if args.backend == "postgres":
                report["postgres_version"] = subprocess.check_output([str(binaries / "postgres"), "--version"], text=True).strip()
        report["cleanup"] = "temporary directory, Console, Agent, edge" + (" and PostgreSQL cluster" if args.backend == "postgres" else "") + " stopped and removed"
        raw = json.dumps(report)
        check("evidence-sanitized", all(s not in raw for s in private))
        report["status"] = "passed"
    except Exception as error:
        message = str(error)
        if loss_probe:
            if "reconciliation_get" in loss_probe:
                report["rotation_loss_probe"] = json.loads(json.dumps(loss_probe))
            # Finite phase/status codes only: never headers, URLs, tokens or bodies.
            message = "rotation_loss_probe=" + json.dumps(loss_probe, sort_keys=True) + "; " + message
        for value in private:
            message = message.replace(value, "<private>")
        message = re.sub(r"(?:sw_(?:agent|admin|live)_|llmfw_)[A-Za-z0-9_-]+", "<private>", message)
        report["error"] = re.sub(r"\s+", " ", message)[:400]
        raise SystemExit(report["error"]) from None
    finally:
        (args.output / f"{args.backend}-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"], "backend": args.backend, "checks": len(checks)}))


if __name__ == "__main__":
    main()
