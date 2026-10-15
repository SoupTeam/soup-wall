#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable Linux/Docker Keycloak OIDC and Console browser acceptance.

Uses the existing pinned vendor-runtime and owned-cleanup helpers. Never connects
to an operator's realm or database. Reports contain checks and hashes, not tokens.
"""
import argparse
import base64
from contextlib import ExitStack, closing
import datetime as dt
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import traceback
import urllib.parse
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("vendor_helpers", Path(__file__).with_name("keycloak-saml-acceptance.py"))
vendor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vendor)
KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak@sha256:ad1b0f0fa4bb5eff10f7a78eaafbb6d65b25431c1f824b0710836d74373a7dfb"
POSTGRES_IMAGE = "postgres@sha256:ec9f656f17c8b4dfebf49e58cf5c46d493d4846d4ea6d8b85d0637f68ee33bfc"


def owned_container(docker, arguments, resources, environment=None):
    created = subprocess.run([docker, "create", *arguments], check=True,
                             capture_output=True, text=True, timeout=30, env=environment)
    identifier = created.stdout.strip()
    if len(identifier) != 64 or any(c not in "0123456789abcdef" for c in identifier):
        raise RuntimeError("Docker did not return an owned container ID")
    resources.callback(lambda: subprocess.run([docker, "rm", "--force", "--volumes", identifier],
                       check=True, capture_output=True, timeout=30))
    return identifier


class FixtureDatabase:
    """Only the newly created file/container; no operator-supplied DSN or SQL CLI."""
    def __init__(self, directory, environment, resources, postgres=False, cert=None, key=None):
        self.path = directory / "gateway.sqlite"
        self.container = None
        self.environment = environment
        self.name = "soup_oidc_" + uuid.uuid4().hex
        if not postgres:
            return
        self.docker = shutil.which("docker")
        subprocess.run([self.docker, "pull", "--platform", "linux/amd64", POSTGRES_IMAGE],
                       check=True, capture_output=True, timeout=240)
        password = secrets.token_urlsafe(32)
        port = vendor.free_port()
        self.container = owned_container(self.docker, ["--platform", "linux/amd64",
            "--name", "soup-oidc-postgres-" + uuid.uuid4().hex,
            "--publish", f"127.0.0.1:{port}:5432", "--memory=512m",
            "--security-opt=no-new-privileges", "--cap-drop=ALL",
            "--cap-add=CHOWN", "--cap-add=DAC_OVERRIDE", "--cap-add=FOWNER",
            "--cap-add=SETGID", "--cap-add=SETUID",
            "--env", "POSTGRES_USER=oidc_fixture", "--env", "POSTGRES_DB=" + self.name,
            "--env", "POSTGRES_PASSWORD",
            "--mount", f"type=bind,src={cert},dst=/fixture-cert.pem,readonly",
            "--mount", f"type=bind,src={key},dst=/fixture-key.pem,readonly",
            POSTGRES_IMAGE, "bash", "-ec",
            # Private host files may belong to a different UID on native Linux.
            # Keep both read-only mounts private, then stage server-readable
            # copies inside this disposable container before dropping privileges.
            "cp /fixture-cert.pem /tmp/oidc-server.crt; cp /fixture-key.pem /tmp/oidc-server.key; "
            "chown postgres:postgres /tmp/oidc-server.crt /tmp/oidc-server.key; "
            "chmod 600 /tmp/oidc-server.crt /tmp/oidc-server.key; exec docker-entrypoint.sh postgres "
            "-c ssl=on -c ssl_cert_file=/tmp/oidc-server.crt -c ssl_key_file=/tmp/oidc-server.key"], resources,
            environment=dict(os.environ, POSTGRES_PASSWORD=password))
        subprocess.run([self.docker, "start", self.container], check=True, capture_output=True, timeout=30)
        environment.update(SOUP_OIDC_FIXTURE_DATABASE_URL=
            f"postgresql://oidc_fixture:{password}@127.0.0.1:{port}/{self.name}?sslmode=require",
            SOUP_OIDC_FIXTURE_DATABASE_NAME=self.name)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                if self.sql("SELECT 1") == "1":
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        return
            except (subprocess.SubprocessError, OSError):
                pass
            time.sleep(.25)
        raise RuntimeError("disposable PostgreSQL startup failed")

    def sql(self, query):
        if self.container:
            result = subprocess.run([self.docker, "exec", "--user", "postgres", "-i", self.container,
                "psql", "--no-psqlrc", "--quiet", "--tuples-only", "--no-align",
                "--set", "ON_ERROR_STOP=1", "--username", "oidc_fixture", "--dbname", self.name],
                input=query, capture_output=True, text=True, check=True, timeout=15)
            return result.stdout.strip()
        with closing(sqlite3.connect(self.path)) as connection:
            cursor = connection.execute(query)
            row = cursor.fetchone()
            connection.commit()
            return str(row[0]) if row else ""

    def bootstrap_target(self):
        return "postgres" if self.container else str(self.path)

    def configuration(self):
        if self.container:
            return "  backend: postgres\n  postgres_url_env: SOUP_OIDC_FIXTURE_DATABASE_URL\n"
        return '  backend: sqlite\n  database_path: "gateway.sqlite"\n'

    def identity_snapshot(self):
        # Compare all persisted identity/session values privately. No raw rows
        # or their hashes are exported as acceptance evidence.
        tables = ("organizations", "tenants", "workspaces", "workspace_principals",
                  "workspace_external_identities", "workspace_memberships",
                  "organization_oidc_connections", "oidc_authorization_states", "oidc_browser_sessions")
        return {table: self.sql(f"SELECT COALESCE(json_agg(row_to_json(t) ORDER BY row_to_json(t)::text)::text, '[]') FROM {table} t")
                for table in tables}

    def restart(self):
        if not self.container:
            raise RuntimeError("no owned database service")
        subprocess.run([self.docker, "restart", self.container], capture_output=True, check=True, timeout=45)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                if self.sql("SELECT 1") == "1":
                    return
            except subprocess.SubprocessError:
                pass
            time.sleep(.25)
        raise RuntimeError("owned database did not restart")


def imported_credential(password):
    """Import a salted Keycloak credential; keep generated cleartext in memory."""
    salt = secrets.token_bytes(16)
    iterations = 210_000
    derived = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, iterations, dklen=64)
    return {"type": "password", "temporary": False,
            "credentialData": json.dumps({"algorithm": "pbkdf2-sha512", "hashIterations": iterations}),
            "secretData": json.dumps({"value": base64.b64encode(derived).decode("ascii"),
                                       "salt": base64.b64encode(salt).decode("ascii")})}


def stop_child(child):
    if os.name == "nt":
        return vendor.stop_child(child)
    if child.poll() is None:
        if os.getpgid(child.pid) != child.pid:
            raise RuntimeError("owned child is not its own process group")
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=10)
    child.soup_tree_stopped = True


def start_child(command, directory, environment, log, resources):
    if os.name == "nt":
        return vendor.start_child(command, directory, environment, log, resources)
    child = subprocess.Popen(command, cwd=directory, env=environment, stdout=log, stderr=log,
                             start_new_session=True)
    child.soup_tree_stopped = False
    resources.callback(stop_child, child)
    return child


def run(args):
    report = {"schema_version": 1, "scope": "Disposable Keycloak OIDC and Console browser acceptance",
              "started_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "artifact_label": args.artifact_label, "backend": args.backend, "checks": [], "passed": False,
              "cleanup_passed": False, "platform": os.name,
              "runtimes": ({"keycloak_image": KEYCLOAK_IMAGE, "keycloak_version": "26.8.0",
                            "keycloak_license": "Apache-2.0", "platform": "linux/amd64"}
                           if args.docker else vendor.RUNTIMES),
              "limitations": ["Local synthetic realm; no customer deployment, MFA or external federation",
                              "Console logout revokes its local session; Keycloak SSO remains active",
                              ("Browser trusts the ephemeral CA in its isolated HOME/NSS database"
                               if args.docker else "Windows diagnostic browser uses an ephemeral SPKI pin"),
                              "Gateway and HTTP driver verify TLS with an explicit ephemeral CA",
                              "Session expiry is advanced only in this run's disposable database fixture"]}
    output = vendor.ReportOutput(args.out, [args.gateway, args.bootstrap_helper, args.keycloak_zip,
                                          args.jdk_zip, Path(__file__)], report)

    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        output.publish(report)
        print(json.dumps({"check": name, "passed": bool(condition)}), flush=True)
        if not condition:
            raise RuntimeError(name)

    try:
        if args.backend == "postgres" and not args.docker:
            raise RuntimeError("PostgreSQL acceptance requires the owned Linux Docker service")
        if args.docker:
            if os.name != "posix" or not shutil.which("docker") or not shutil.which("certutil"):
                raise RuntimeError("Linux Docker and NSS certutil are required")
        elif os.name != "nt" or not args.keycloak_zip or not args.jdk_zip:
            raise RuntimeError("use --docker on Linux or supply pinned archives for Windows diagnostics")
        import requests
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from playwright.sync_api import sync_playwright

        for name in ("gateway", "bootstrap_helper"):
            report[name + "_sha256"] = vendor.sha256(getattr(args, name))
        report["source_sha256"] = {str(path.relative_to(ROOT)).replace("\\", "/"): vendor.sha256(path)
                                  for path in [Path(__file__), ROOT / "scripts/keycloak-saml-acceptance.py",
                                               ROOT / "Cargo.lock", ROOT / "crates/proxy/examples/keycloak-oidc-bootstrap.rs",
                                               ROOT / "crates/proxy/src/oidc.rs",
                                               ROOT / "crates/proxy/src/oidc_auth.rs",
                                               ROOT / "crates/proxy/src/customer_dashboard.html",
                                               ROOT / "crates/proxy/src/tenant_store.rs",
                                               ROOT / "crates/proxy/src/tenant_store/postgres.rs",
                                               ROOT / "scripts/keycloak-oidc-acceptance.sh",
                                               ROOT / ".github/workflows/keycloak-oidc.yml"]}
        scratch = vendor.scratch_directory(ROOT)
        children = []
        with ExitStack() as resources:
            directory = Path(tempfile.mkdtemp(prefix="soup-wall-keycloak-session-", dir=scratch)).resolve()
            resources.callback(vendor.cleanup_new_directory, directory, scratch, children)
            if args.docker:
                docker = shutil.which("docker")
                subprocess.run([docker, "pull", "--platform", "linux/amd64", KEYCLOAK_IMAGE],
                               check=True, capture_output=True, timeout=240)
                check("pinned-container-image-pulled-by-digest", True)
            else:
                keycloak = vendor.unpack(args.keycloak_zip, directory / "keycloak", vendor.RUNTIMES["keycloak"])
                jdk = vendor.unpack(args.jdk_zip, directory / "jdk", vendor.RUNTIMES["jdk"])
                check("pinned-runtime-checksums", True)
            ca, (cert, key), _ = vendor.certificate_files(directory)
            gateway_port, vendor_port = vendor.free_port(), vendor.free_port()
            vendor_base = f"https://127.0.0.1:{vendor_port}"
            realm = "oidc-" + uuid.uuid4().hex
            issuer = vendor_base + "/realms/" + realm

            class Edge(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass

                def forward(self):
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 0 or length > 2 * 1024 * 1024:
                        self.send_error(413)
                        return
                    data = self.rfile.read(length) if length else None
                    headers = {key: value for key, value in self.headers.items()
                               if key.lower() not in {"connection", "transfer-encoding"}}
                    try:
                        response = vendor.forward_gateway(gateway_port, self.path, self.command, headers, data)
                        vendor.write_gateway_response(self, response)
                    except (RuntimeError, requests.RequestException):
                        self.send_error(502)

                do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = forward

            edge = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Edge)
            resources.callback(edge.server_close)
            tls = vendor.edge_tls_context()
            tls.load_cert_chain(cert, key)
            edge.socket = tls.wrap_socket(edge.socket, server_side=True)
            threading.Thread(target=edge.serve_forever, daemon=True).start()
            resources.callback(edge.shutdown)
            gateway_base = f"https://127.0.0.1:{edge.server_port}"
            callback = gateway_base + "/auth/oidc/callback"
            origins = {vendor_base, gateway_base}
            client_id = "soup-console"
            users = [{"id": str(uuid.uuid4()), "username": name, "password": secrets.token_urlsafe(24)}
                     for name in ("owner", "analyst", "unprovisioned")]
            client = {"clientId": client_id, "protocol": "openid-connect", "enabled": True,
                      "publicClient": True, "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
                      "implicitFlowEnabled": False, "redirectUris": [callback],
                      "attributes": {"pkce.code.challenge.method": "S256"}}
            realm_data = {"realm": realm, "enabled": True, "sslRequired": "all", "clients": [client],
                          "roles": {"realm": [{"name": "owner"}]},
                          "users": [{"id": user["id"], "username": user["username"], "enabled": True,
                                     "email": user["username"] + "@example.test", "emailVerified": True,
                                     "firstName": "Synthetic", "lastName": "Acceptance", "realmRoles": ["owner"],
                                     "credentials": [imported_credential(user["password"])]}
                                    for user in users]}
            import_dir = directory / "realm-import" if args.docker else keycloak / "data/import"
            import_dir.mkdir(parents=True)
            (import_dir / "realm.json").write_text(json.dumps(realm_data), encoding="utf-8")
            if args.docker:
                profile = directory / "profile"
                profile.mkdir()
                temporary = directory / "tmp"
                temporary.mkdir()
                environment = {"HOME": str(profile), "TMPDIR": str(temporary), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
            else:
                environment = vendor.child_environment(directory)
            vendor_log = resources.enter_context((directory / "vendor.log").open("wb"))
            if args.docker:
                created = subprocess.run([docker, "create", "--platform", "linux/amd64", "--network", "host",
                    "--name", "soup-oidc-" + uuid.uuid4().hex, "--user", "0:0", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--memory=1536m",
                    "--mount", f"type=bind,src={import_dir},dst=/opt/keycloak/data/import,readonly",
                    "--mount", f"type=bind,src={cert},dst=/fixture-cert.pem,readonly",
                    "--mount", f"type=bind,src={key},dst=/fixture-key.pem,readonly",
                    KEYCLOAK_IMAGE, "start-dev", "--import-realm", "--http-enabled=false",
                    "--http-host=127.0.0.1", f"--https-port={vendor_port}", f"--hostname={vendor_base}",
                    "--https-certificate-file=/fixture-cert.pem", "--https-certificate-key-file=/fixture-key.pem",
                    "--log-level=warn"], check=True, capture_output=True, text=True, timeout=30)
                container_id = created.stdout.strip()
                if len(container_id) != 64 or any(c not in "0123456789abcdef" for c in container_id):
                    raise RuntimeError("Docker did not return a created container ID")
                def remove_container():
                    subprocess.run([docker, "rm", "--force", container_id], check=True,
                                   capture_output=True, timeout=30)
                resources.callback(remove_container)
                child = start_child([docker, "start", "--attach", container_id], directory, environment, vendor_log, resources)
            else:
                vendor_environment = dict(environment, JAVA_HOME=str(jdk),
                    JAVA_OPTS_APPEND='-Duser.home="' + environment["USERPROFILE"] + '"',
                    PATH=str(jdk / "bin") + os.pathsep + environment.get("PATH", ""))
                child = start_child([environment["COMSPEC"], "/d", "/c", str(keycloak / "bin/kc.bat"),
                    "start-dev", "--import-realm", "--http-enabled=false", "--http-host=127.0.0.1",
                    f"--https-port={vendor_port}", f"--hostname={vendor_base}",
                    f"--https-certificate-file={cert}", f"--https-certificate-key-file={key}",
                    "--log-level=warn"], directory, vendor_environment, vendor_log, resources)
            children.append(child)
            session = resources.enter_context(requests.Session())
            session.trust_env = False
            session.verify = str(ca)

            def request(method, url, **kwargs):
                parsed = urllib.parse.urlsplit(url)
                if parsed.scheme + "://" + parsed.netloc not in origins:
                    raise RuntimeError("non-disposable destination refused")
                return session.request(method, url, timeout=10, allow_redirects=False, **kwargs)

            def ready(url, process, timeout):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline and process.poll() is None:
                    try:
                        if request("GET", url).status_code == 200:
                            return True
                    except requests.RequestException:
                        pass
                    time.sleep(.25)
                return False

            report["phase"] = "vendor-startup"
            check("real-keycloak-https-discovery", ready(issuer + "/.well-known/openid-configuration", child, 120))
            environment["LLM_FW_POSTGRES_CA_CERT_FILE"] = str(ca)
            report["phase"] = "database-startup"
            database = FixtureDatabase(directory, environment, resources,
                                       postgres=args.backend == "postgres", cert=cert, key=key)
            gateway_environment = dict(environment, SOUP_FIXTURE_ADMIN_TOKEN=secrets.token_urlsafe(32),
                LLM_FW_OIDC_STATE_KEY=secrets.token_urlsafe(32), LLM_FW_OIDC_CA_CERT_FILE=str(ca), RUST_LOG="error")
            (directory / "policy.yaml").write_text("policies: []\ndefault: allow\n", encoding="utf-8")
            (directory / "firewall.yaml").write_text(
                f'bind: "127.0.0.1:{gateway_port}"\ntenant_store:\n  enabled: true\n'
                + database.configuration() +
                '  admin_token_env: "SOUP_FIXTURE_ADMIN_TOKEN"\npolicy_file: "policy.yaml"\n'
                'fail_mode: fail_closed\n', encoding="utf-8")

            def migrate():
                return subprocess.run([str(args.gateway), "migrate"], env=gateway_environment, cwd=directory,
                                      capture_output=True, timeout=60).returncode == 0

            if database.container:
                report["runtimes"]["postgres_image"] = POSTGRES_IMAGE
                report["runtimes"]["postgres_version"] = database.sql("SHOW server_version")
                report["runtimes"]["postgres_license"] = "PostgreSQL License"
                check("fresh-postgres-has-no-public-tables", database.sql(
                    "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'") == "0")
                check("explicit-production-postgres-migrations", migrate())
            seed_command = [str(args.bootstrap_helper), database.bootstrap_target(), issuer, client_id,
                            callback, users[0]["id"], users[1]["id"]]
            seeded = subprocess.run(seed_command, env=environment, cwd=directory,
                                    capture_output=True, timeout=30, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            check("local-membership-bootstrap", seeded.returncode == 0)
            scope = json.loads(seeded.stdout)
            repeat = subprocess.run(seed_command, env=environment, cwd=directory, capture_output=True, timeout=30)
            check("bootstrap-refuses-populated-store", repeat.returncode != 0)
            if database.container:
                # A valid but unrelated certificate must not authenticate the
                # database. The probe does not change rows or run migrations.
                wrong_ca = dict(environment, LLM_FW_POSTGRES_CA_CERT_FILE=str(directory / "soup-wall-sp.pem"))
                rejected = subprocess.run([str(args.bootstrap_helper), "--probe-token", "postgres"],
                    input="synthetic-invalid", text=True, env=wrong_ca, cwd=directory,
                    capture_output=True, timeout=30)
                check("postgres-untrusted-certificate-refused", rejected.returncode != 0)
            report["configuration"] = {"bind": "loopback only", "store": "new disposable " + args.backend,
                "database_tls_verified": bool(database.container),
                "oidc_client": "public", "flow": "authorization_code", "pkce": "S256 required",
                "https": True, "gateway_certificate_verification": True,
                "os_trust_modified": False, "identity_source": "generated synthetic users",
                "firewall_yaml_sha256": vendor.sha256(directory / "firewall.yaml"),
                "realm_configuration_sha256": vendor.sha256(import_dir / "realm.json")}
            gateway_log = resources.enter_context((directory / "gateway.log").open("wb"))

            def start_gateway():
                process = start_child([str(args.gateway)], directory, gateway_environment, gateway_log, resources)
                children.append(process)
                check("gateway-ready", ready(gateway_base + "/readyz", process, 30))
                return process

            gateway = start_gateway()
            if database.container:
                check("gateway-postgres-connections-use-tls", database.sql(
                    "SELECT count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a USING(pid) "
                    "WHERE a.application_name = 'llm-firewall-control-plane' AND s.ssl") != "0")
            report["phase"] = "real-provider-negative-flow"
            start_url = gateway_base + "/auth/oidc/start?" + urllib.parse.urlencode({
                "organization_id": scope["organization_id"], "workspace_id": scope["workspace_id"]})
            started = request("GET", start_url)
            check("production-start-redirect", started.status_code == 303)
            authorization = started.headers["Location"]
            state_value = urllib.parse.parse_qs(urllib.parse.urlsplit(authorization).query)["state"][0]
            missing_browser = request("GET", callback, headers={"Cookie": ""},
                                      params={"state": state_value, "code": "unused-negative"})
            pending = int(database.sql("SELECT count(*) FROM oidc_authorization_states WHERE consumed_at_unix IS NULL"))
            check("callback-without-originating-browser-rejected-before-state-consumption",
                  missing_browser.status_code == 400 and pending == 1)
            invalid_state = "synthetic-invalid-state"
            binding = base64.urlsafe_b64encode(hashlib.sha256(invalid_state.encode()).digest()).decode().rstrip("=")
            check("invalid-state-refused-by-production-callback", request("GET", callback,
                  headers={"Cookie": "__Host-llm-fw-oidc-flow=" + binding},
                  params={"state": invalid_state, "code": "unused-negative"}).status_code == 400)
            form_response = request("GET", authorization)
            form = next(form for form in vendor.Forms(form_response.text).forms if form["id"] == "kc-form-login")
            signed_in = request("POST", urllib.parse.urljoin(form_response.url, form["action"]),
                                data=dict(form["fields"], username=users[0]["username"], password=users[0]["password"]))
            location = signed_in.headers.get("Location", "")
            check("separate-vendor-code-issued-for-pkce-negative", signed_in.status_code in (302, 303)
                  and location.startswith(callback + "?"))
            code = urllib.parse.parse_qs(urllib.parse.urlsplit(location).query)["code"][0]
            wrong_pkce = request("POST", issuer + "/protocol/openid-connect/token", data={
                "grant_type": "authorization_code", "client_id": client_id, "redirect_uri": callback,
                "code": code, "code_verifier": "x" * 64})
            pkce_error = wrong_pkce.json()
            check("real-keycloak-rejects-wrong-pkce-verifier", wrong_pkce.status_code == 400
                  and pkce_error.get("error") == "invalid_grant"
                  and "pkce" in pkce_error.get("error_description", "").lower())
            leaf = x509.load_pem_x509_certificate(cert.read_bytes())
            spki = base64.b64encode(hashlib.sha256(leaf.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()).decode()
            pw = resources.enter_context(sync_playwright())
            if args.docker:
                nss = Path(environment["HOME"]) / ".pki/nssdb"
                nss.mkdir(parents=True)
                subprocess.run([shutil.which("certutil"), "-N", "-d", "sql:" + str(nss), "--empty-password"],
                               check=True, capture_output=True, env=environment, timeout=15)
                subprocess.run([shutil.which("certutil"), "-A", "-d", "sql:" + str(nss), "-n", "Disposable OIDC CA",
                                "-t", "C,,", "-i", str(ca)], check=True, capture_output=True, env=environment, timeout=15)
                browser_args = []
            else:
                browser_args = ["--ignore-certificate-errors-spki-list=" + spki]
            browser = pw.chromium.launch(headless=True, args=browser_args, env=environment)
            resources.callback(browser.close)
            report["browser_version"] = browser.version

            def context():
                ctx = browser.new_context()
                resources.callback(ctx.close)
                def route_request(route):
                    parsed = urllib.parse.urlsplit(route.request.url)
                    if parsed.scheme + "://" + parsed.netloc in origins:
                        route.continue_()
                    else:
                        route.abort()
                ctx.route("**/*", route_request)
                return ctx

            def login(ctx, user, organization=None, workspace=None, success=True):
                page = ctx.new_page()
                report["phase"] = "console-entry-" + user["username"]
                output.publish(report)
                page.goto(gateway_base + "/customer")
                page.locator("#sign-in").wait_for(state="visible")
                page.locator("#login-organization").fill(organization or scope["organization_id"])
                page.locator("#login-workspace").fill(workspace or scope["workspace_id"])
                report["phase"] = "idp-redirect-" + user["username"]
                output.publish(report)
                page.locator("#sign-in-form button").click()
                page.locator("#username").fill(user["username"])
                page.locator("#password").fill(user["password"])
                callback_cookies[user["username"]] = "; ".join(
                    cookie["name"] + "=" + cookie["value"] for cookie in ctx.cookies()
                    if cookie["name"] == "__Host-llm-fw-oidc-flow")
                report["phase"] = "idp-password-callback-" + user["username"]
                output.publish(report)
                page.locator("#kc-login").click()
                try:
                    if success:
                        page.wait_for_url(gateway_base + "/customer")
                        page.locator("#identity").wait_for(state="visible")
                        page.wait_for_load_state("networkidle")
                    else:
                        page.wait_for_url(callback + "?**")
                except Exception:
                    report["browser_failure_path"] = urllib.parse.urlsplit(page.url).path
                    report["browser_failure_controls"] = {selector: page.locator(selector).count()
                        for selector in ("#username", "#input-error", "#kc-error-message", "#identity", "#sign-in")}
                    raise
                return page

            def browser_fetch(page, path, method="GET", headers=None, body=None):
                return page.evaluate("""async ({path, method, headers, body}) => {
                    const response = await fetch(path, {method, headers, body, credentials:'same-origin', cache:'no-store'});
                    const text = await response.text();
                    let data = null; try { data = JSON.parse(text); } catch (_) {}
                    return {status:response.status, data};
                }""", {"path": path, "method": method, "headers": headers or {}, "body": body})

            report["phase"] = "browser-login"
            owner = context()
            callbacks = []
            callback_cookies = {}
            owner.on("request", lambda req: callbacks.append(req.url) if req.url.startswith(callback + "?") else None)
            page = login(owner, users[0])
            check("console-login-through-real-keycloak", page.locator("#role").inner_text() == "owner")
            cookie = next(c for c in owner.cookies() if c["name"] == "__Host-llm-fw-session")
            check("secure-opaque-host-session-cookie", cookie["secure"] and cookie["httpOnly"]
                  and cookie["sameSite"] == "Lax" and cookie["path"] == "/" and "." not in cookie["value"])
            check("authorization-callback-replay-rejected", bool(callbacks)
                  and request("GET", callbacks[-1], headers={"Cookie": callback_cookies["owner"]}).status_code == 400)
            check("owner-can-read-owner-only-api", browser_fetch(page, "/customer/v1/billing/invoice-preview")["status"] == 200)
            check("refresh-needs-csrf", browser_fetch(page, "/auth/session/refresh", "POST")["status"] == 403)
            csrf = browser_fetch(page, "/customer/v1/csrf")["data"]["token"]
            old_cookie = cookie["value"]
            check("csrf-protected-session-rotation", browser_fetch(page, "/auth/session/refresh", "POST",
                  {"X-LLM-Firewall-CSRF-Token": csrf})["status"] == 204)
            check("rotated-cookie-invalidates-previous-session", request("GET", gateway_base + "/customer/v1/session",
                  headers={"Cookie": "__Host-llm-fw-session=" + old_cookie}).status_code == 401)
            stop_child(gateway)
            if database.container:
                before = database.identity_snapshot()
                check("migrations-on-populated-identity-store", migrate())
                check("populated-identity-and-session-state-preserved", database.identity_snapshot() == before)
                database.restart()
                check("postgres-restart-preserves-populated-state", database.identity_snapshot() == before)
            gateway = start_gateway()
            check("session-persists-across-gateway-restart", browser_fetch(page, "/customer/v1/session")["status"] == 200)
            active_cookie = next(c["value"] for c in owner.cookies() if c["name"] == "__Host-llm-fw-session")
            report["phase"] = "console-logout"
            page.locator("#logout").click()
            page.get_by_text("You have been logged out of this workspace.", exact=True).wait_for(state="visible")
            check("console-logout-clears-workspace-ui", not page.locator("#identity").is_visible()
                  and page.locator("#sign-in").is_visible() and page.locator("#identity").inner_html() == "")
            check("logout-revokes-server-session", request("GET", gateway_base + "/customer/v1/session",
                  headers={"Cookie": "__Host-llm-fw-session=" + active_cookie}).status_code == 401)
            check("logout-cookie-removed", not any(c["name"] == "__Host-llm-fw-session" for c in owner.cookies()))

            analyst = context()
            analyst_page = login(analyst, users[1])
            check("idp-owner-role-does-not-override-local-analyst", analyst_page.locator("#role").inner_text() == "analyst")
            check("analyst-denied-owner-only-api", browser_fetch(analyst_page, "/customer/v1/billing/invoice-preview")["status"] == 403)
            # New genuine owner login after logout; local membership changes use
            # the public CSRF-protected endpoint, not direct SQL modifications.
            manager = context()
            manager_page = login(manager, users[0])
            manager_csrf = browser_fetch(manager_page, "/customer/v1/csrf")["data"]["token"]
            mutation_headers = {"X-LLM-Firewall-CSRF-Token": manager_csrf, "Content-Type": "application/json"}

            def membership(active):
                return browser_fetch(manager_page, "/customer/v1/members", "PATCH", mutation_headers,
                    json.dumps({"principal_id": scope["analyst_principal_id"], "role": "analyst", "active": active}))

            check("owner-revokes-analyst-membership", membership(False)["status"] == 200)
            check("revoked-membership-invalidates-existing-session",
                  browser_fetch(analyst_page, "/customer/v1/session")["status"] == 401)
            stop_child(gateway)
            gateway = start_gateway()
            check("membership-revocation-survives-restart",
                  browser_fetch(analyst_page, "/customer/v1/session")["status"] == 401)
            check("logout-revocation-survives-restart", request("GET", gateway_base + "/customer/v1/session",
                  headers={"Cookie": "__Host-llm-fw-session=" + active_cookie}).status_code == 401)
            check("owner-session-survives-second-restart",
                  browser_fetch(manager_page, "/customer/v1/session")["status"] == 200)
            denied_member = context()
            denied_member_page = login(denied_member, users[1], success=False)
            check("revoked-member-cannot-create-new-session",
                  "oidc_login_failed" in denied_member_page.locator("body").inner_text())
            check("owner-restores-analyst-membership", membership(True)["status"] == 200)
            # Positive authentication and revocation are checked against the
            # production store API, without making any external model request.
            issued = browser_fetch(manager_page, "/customer/v1/service-accounts", "POST", mutation_headers,
                json.dumps({"name": "Disposable token", "expires_at_unix": int(time.time()) + 1800}))
            check("owner-issues-workspace-token", issued["status"] == 200)
            credential = issued["data"]

            def token_authenticates():
                result = subprocess.run([str(args.bootstrap_helper), "--probe-token", database.bootstrap_target()],
                    input=credential["token"], env=environment, cwd=directory,
                    text=True, capture_output=True, timeout=30)
                if result.returncode:
                    raise RuntimeError("production store token probe failed")
                return json.loads(result.stdout)["authenticated"]

            check("issued-token-authenticates-production-store", token_authenticates())
            revoked = browser_fetch(manager_page,
                "/customer/v1/service-accounts/" + credential["account"]["id"] + "/revoke", "POST", mutation_headers)
            check("owner-revokes-workspace-token", revoked["status"] == 200 and revoked["data"].get("revoked") is True)
            check("revoked-token-refused-production-store", not token_authenticates())
            stop_child(gateway)
            gateway = start_gateway()
            check("token-revocation-survives-restart", not token_authenticates())
            # Fresh positive session ensures the expiry test cannot pass merely
            # because the preceding membership test already denied this user.
            analyst = context()
            analyst_page = login(analyst, users[1])
            check("restored-member-can-login", browser_fetch(analyst_page, "/customer/v1/session")["status"] == 200)
            for name, user, org, workspace in [
                ("unprovisioned-idp-user-denied", users[2], scope["organization_id"], scope["workspace_id"]),
                ("cross-organization-membership-denied", users[0], scope["other_organization_id"], scope["other_workspace_id"])]:
                denied = context()
                denied_page = login(denied, user, org, workspace, success=False)
                check(name, "oidc_login_failed" in denied_page.locator("body").inner_text()
                      and not any(c["name"] == "__Host-llm-fw-session" for c in denied.cookies()))
            # Advance expiry only in the new fixture, never in an existing store.
            database.sql("UPDATE oidc_browser_sessions SET expires_at_unix = 1")
            check("expired-session-denied-server-side", browser_fetch(analyst_page, "/customer/v1/session")["status"] == 401)
            analyst_page.reload()
            analyst_page.locator("#sign-in").wait_for(state="visible")
            check("expired-session-returns-to-sign-in", not analyst_page.locator("#identity").is_visible())
        report["cleanup_passed"] = True
        report["passed"] = True
        report["phase"] = "complete"
        output.publish(report)
        print(json.dumps({"passed": True, "checks": len(report["checks"]), "cleanup_passed": True}), flush=True)
        return 0
    except Exception as error:
        report["error_type"] = type(error).__name__
        report["error_locations"] = [{"file": Path(frame.filename).name, "line": frame.lineno,
                                      "function": frame.name}
                                     for frame in traceback.extract_tb(error.__traceback__)]
        output.publish(report)
        print(json.dumps({"passed": False, "phase": report.get("phase"), "error_type": type(error).__name__}), flush=True)
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("gateway", "bootstrap-helper", "out"):
        parser.add_argument("--" + name, required=True, type=lambda value: Path(value).resolve())
    for name in ("keycloak-zip", "jdk-zip"):
        parser.add_argument("--" + name, type=lambda value: Path(value).resolve())
    parser.add_argument("--backend", choices=("sqlite", "postgres"), default="sqlite")
    parser.add_argument("--docker", action="store_true")
    parser.add_argument("--artifact-label", required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
