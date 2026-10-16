#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable Linux/Docker Keycloak SAML and Console browser acceptance.

Uses the existing pinned vendor-runtime and owned-cleanup helpers. Never connects
to an operator's realm or database. Reports contain checks and hashes, not tokens.
"""
import argparse
import base64
from contextlib import ExitStack
import datetime as dt
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
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


spec = importlib.util.spec_from_file_location("lifecycle_helpers", Path(__file__).with_name("keycloak-oidc-acceptance.py"))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
FixtureDatabase = shared.FixtureDatabase
start_child = shared.start_child
stop_child = shared.stop_child
imported_credential = shared.imported_credential
import xml.etree.ElementTree as ET

def tls_handshake(port, hostname, ca):
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=hostname):
            return True

def run(args):
    report = {"schema_version": 1, "scope": "Disposable Keycloak SAML and Console browser acceptance",
              "started_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "artifact_label": args.artifact_label, "backend": args.backend, "checks": [], "passed": False,
              "cleanup_passed": False, "platform": os.name,
              "runtimes": {"keycloak_image": KEYCLOAK_IMAGE, "keycloak_version": "26.8.0",
                            "keycloak_license": "Apache-2.0", "platform": "linux/amd64"},
              "limitations": ["Local synthetic realm; no customer deployment, MFA or external federation",
                              "Console logout revokes its local session; Keycloak SSO remains active",
                              "Browser trusts the ephemeral CA in its isolated HOME/NSS database",
                              "Gateway and HTTP driver verify TLS with an explicit ephemeral CA",
                              "Session expiry is advanced only in this run's disposable database fixture"]}
    output = vendor.ReportOutput(args.out, [args.gateway, args.bootstrap_helper, Path(__file__)], report)

    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        output.publish(report)
        print(json.dumps({"check": name, "passed": bool(condition)}), flush=True)
        if not condition:
            raise RuntimeError(name)

    try:
        if os.name != "posix" or not shutil.which("docker") or not shutil.which("certutil"):
            raise RuntimeError("Linux Docker and NSS certutil are required")
        import requests
        from playwright.sync_api import sync_playwright

        for name in ("gateway", "bootstrap_helper"):
            report[name + "_sha256"] = vendor.sha256(getattr(args, name))
        report["source_sha256"] = {str(path.relative_to(ROOT)).replace("\\", "/"): vendor.sha256(path)
                                  for path in [Path(__file__), ROOT / "scripts/keycloak-saml-acceptance.py",
                                               ROOT / "scripts/keycloak-oidc-acceptance.py",
                                               ROOT / "Cargo.lock", ROOT / "crates/proxy/examples/keycloak-saml-bootstrap.rs",
                                               ROOT / "crates/proxy/src/saml_auth.rs",
                                               ROOT / "crates/proxy/src/oidc_auth.rs",
                                               ROOT / "crates/proxy/src/customer_dashboard.html",
                                               ROOT / "crates/proxy/src/tenant_store.rs",
                                               ROOT / "crates/proxy/src/tenant_store/postgres.rs",
                                               ROOT / "scripts/keycloak-saml-linux.sh",
                                               ROOT / ".github/workflows/keycloak-saml.yml"]}
        scratch = vendor.scratch_directory(ROOT)
        children = []
        with ExitStack() as resources:
            directory = Path(tempfile.mkdtemp(prefix="soup-wall-keycloak-session-", dir=scratch)).resolve()
            resources.callback(vendor.cleanup_new_directory, directory, scratch, children)
            docker = shutil.which("docker")
            subprocess.run([docker, "pull", "--platform", "linux/amd64", KEYCLOAK_IMAGE],
                           check=True, capture_output=True, timeout=240)
            check("pinned-container-image-pulled-by-digest", True)
            ca, (cert, key), (sp_cert, sp_key) = vendor.certificate_files(directory)
            gateway_port, vendor_port, vendor_http_port = vendor.free_port(), vendor.free_port(), vendor.free_port()
            # Different sites exercise the real cross-site POST cookie boundary;
            # different ports alone would still be same-site and share cookies.
            vendor_base = f"https://localhost:{vendor_port}"
            realm = "saml-" + uuid.uuid4().hex
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
            callback = gateway_base + "/auth/saml/acs"
            origins = {vendor_base, gateway_base}
            client_id = "soup-console"
            users = [{"id": str(uuid.uuid4()), "username": name, "password": secrets.token_urlsafe(24)}
                     for name in ("owner", "analyst", "unprovisioned")]
            operator_password = secrets.token_urlsafe(32)
            client = {"clientId": client_id, "protocol": "saml", "enabled": True,
                      "redirectUris": [callback], "attributes": {
                          "saml.server.signature": "true", "saml.assertion.signature": "true",
                          "saml.client.signature": "true", "saml.signature.algorithm": "RSA_SHA256",
                          "saml.force.post.binding": "true", "saml.encrypt": "false",
                          "saml_name_id_format": "email", "saml_force_name_id_format": "true",
                          "saml_assertion_consumer_url_post": callback,
                          "saml.signing.certificate": "".join(sp_cert.read_text().splitlines()[1:-1])},
                      "protocolMappers": [{"name": "untrusted-role", "protocol": "saml",
                          "protocolMapper": "saml-role-list-mapper", "consentRequired": False,
                          "config": {"attribute.name": "Role", "single": "true"}}]}
            realm_data = {"realm": realm, "enabled": True, "sslRequired": "all", "clients": [client], "attributes": {"saml.signature.algorithm": "RSA_SHA256"},
                          "roles": {"realm": [{"name": "owner"}]},
                          "users": [{"id": user["id"], "username": user["username"], "enabled": True,
                                     "email": user["username"] + "@example.test", "emailVerified": True,
                                     "firstName": "Synthetic", "lastName": "Acceptance", "realmRoles": ["owner"],
                                     "credentials": [imported_credential(user["password"])]}
                                    for user in users]}
            realm_data["users"].append({"username": "fixture-operator", "enabled": True,
                "email": "operator@example.test", "emailVerified": True, "firstName": "Fixture", "lastName": "Operator",
                "clientRoles": {"realm-management": ["realm-admin"]},
                "credentials": [imported_credential(operator_password)]})
            import_dir = directory / "realm-import"
            import_dir.mkdir(parents=True)
            (import_dir / "realm.json").write_text(json.dumps(realm_data), encoding="utf-8")
            profile = directory / "profile"
            profile.mkdir()
            temporary = directory / "tmp"
            temporary.mkdir()
            environment = {"HOME": str(profile), "TMPDIR": str(temporary), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
            vendor_log = resources.enter_context((directory / "vendor.log").open("wb"))
            created = subprocess.run([docker, "create", "--platform", "linux/amd64", "--network", "host",
                "--name", "soup-saml-" + uuid.uuid4().hex, "--user", "0:0", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--memory=1536m",
                "--mount", f"type=bind,src={import_dir},dst=/opt/keycloak/data/import,readonly",
                "--mount", f"type=bind,src={cert},dst=/fixture-cert.pem,readonly",
                "--mount", f"type=bind,src={key},dst=/fixture-key.pem,readonly",
                KEYCLOAK_IMAGE, "start-dev", "--import-realm", "--http-enabled=false",
                "--http-host=127.0.0.1", f"--http-port={vendor_http_port}",
                f"--https-port={vendor_port}", f"--hostname={vendor_base}",
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
            check("real-keycloak-https-discovery", ready(issuer + "/protocol/saml/descriptor", child, 120))
            environment["LLM_FW_POSTGRES_CA_CERT_FILE"] = str(ca)
            report["phase"] = "database-startup"
            database = FixtureDatabase(directory, environment, resources,
                                       postgres=args.backend == "postgres", cert=cert, key=key)
            gateway_environment = dict(environment, SOUP_FIXTURE_ADMIN_TOKEN=secrets.token_urlsafe(32),
                LLM_FW_OIDC_STATE_KEY=secrets.token_urlsafe(32), LLM_FW_OIDC_CA_CERT_FILE=str(ca), LLM_FW_SAML_SP_ENTITY_ID=client_id, LLM_FW_SAML_ACS_URL=callback,
                LLM_FW_SAML_SP_PRIVATE_KEY_PEM=sp_key.read_text(),
                LLM_FW_SAML_SP_CERTIFICATE_PEM=sp_cert.read_text(), RUST_LOG="warn")
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
            seed_command = [str(args.bootstrap_helper), "--lifecycle", database.bootstrap_target(), issuer,
                            users[0]["username"] + "@example.test", users[1]["username"] + "@example.test"]
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
                "saml_client": "signed SP requests", "flow": "signed assertion", 
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
            check("owned-https-certificate-and-hostname-accepted", tls_handshake(edge.server_port, "localhost", ca))
            for name, hostname, trust in [("wrong-hostname", "wrong.example.test", ca),
                                           ("untrusted-ca", "localhost", sp_cert)]:
                try:
                    tls_handshake(edge.server_port, hostname, trust)
                except ssl.SSLCertVerificationError:
                    check("https-" + name + "-refused", True)
                else:
                    check("https-" + name + "-refused", False)
            if database.container:
                check("gateway-postgres-connections-use-tls", database.sql(
                    "SELECT count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a USING(pid) "
                    "WHERE a.application_name = 'llm-firewall-control-plane' AND s.ssl") != "0")
            connection_url = gateway_base + "/admin/v1/organizations/" + scope["organization_id"] + "/saml"
            admin_headers = {"x-llm-firewall-admin-token": "Bearer " + gateway_environment["SOUP_FIXTURE_ADMIN_TOKEN"]}

            def metadata_connection():
                response = request("GET", issuer + "/protocol/saml/descriptor")
                tree = ET.fromstring(response.content)
                if response.status_code != 200 or tree.find("ds:Signature", vendor.NS) is None:
                    raise RuntimeError("vendor did not return signed metadata")
                certificate = tree.find("md:IDPSSODescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate", vendor.NS).text
                certificate = "".join(certificate.split())
                pin = "-----BEGIN CERTIFICATE-----\n" + "\n".join(certificate[i:i+64] for i in range(0, len(certificate), 64)) + "\n-----END CERTIFICATE-----\n"
                report.setdefault("vendor_certificates", []).append({
                    "metadata_sha256": hashlib.sha256(response.content).hexdigest(),
                    "certificate_sha256": hashlib.sha256(base64.b64decode(certificate)).hexdigest()})
                return {"entity_id": issuer, "metadata_xml": response.text, "metadata_signing_cert_pem": pin, "active": True}

            connection = metadata_connection()
            check("operator-imports-genuine-signed-metadata-and-explicit-pin", request("PUT", connection_url,
                  json=connection, headers=admin_headers).status_code == 200)
            start_url = gateway_base + "/auth/saml/start?" + urllib.parse.urlencode({
                "organization_id": scope["organization_id"], "workspace_id": scope["workspace_id"]})
            pw = resources.enter_context(sync_playwright())
            nss = Path(environment["HOME"]) / ".pki/nssdb"
            nss.mkdir(parents=True)
            subprocess.run([shutil.which("certutil"), "-N", "-d", "sql:" + str(nss), "--empty-password"],
                           check=True, capture_output=True, env=environment, timeout=15)
            subprocess.run([shutil.which("certutil"), "-A", "-d", "sql:" + str(nss), "-n", "Disposable SAML CA",
                            "-t", "C,,", "-i", str(ca)], check=True, capture_output=True, env=environment, timeout=15)
            browser = pw.chromium.launch(headless=True, env=environment)
            resources.callback(browser.close)
            report["browser_version"] = browser.version
            report["crypto_provider"] = "saml-rs 0.5.3 crypto-aws-lc, non-FIPS; Keycloak RSA_SHA256"

            def context():
                ctx = browser.new_context()
                resources.callback(ctx.close)
                def bounded(route):
                    parsed = urllib.parse.urlsplit(route.request.url)
                    if parsed.scheme + "://" + parsed.netloc in origins:
                        route.continue_()
                    else:
                        route.abort()
                ctx.route("**/*", bounded)
                return ctx

            def login(ctx, user, organization=None, workspace=None, success=True, capture=None):
                page = ctx.new_page()
                page.set_default_timeout(45000)
                log_offset = (directory / "gateway.log").stat().st_size
                observation = {"subject": user["username"]}
                def observe(response):
                    if response.url == callback:
                        observation["acs_status"] = response.status
                        observation["browser_binding_sent"] = "__Host-llm-fw-saml-flow=" in response.request.all_headers().get("cookie", "")
                    elif response.request.is_navigation_request() and response.url.startswith(vendor_base + "/"):
                        observation["vendor_status"] = response.status
                page.on("response", observe)
                if capture is not None:
                    def hold(route):
                        capture["fields"] = dict(urllib.parse.parse_qsl(route.request.post_data))
                        capture["cookie"] = "; ".join(c["name"] + "=" + c["value"] for c in ctx.cookies()
                                                   if c["name"] == "__Host-llm-fw-saml-flow")
                        route.fulfill(status=200, content_type="text/plain", body="Synthetic callback held")
                    page.route(callback, hold)
                url = gateway_base + "/auth/saml/start?" + urllib.parse.urlencode({
                    "organization_id": organization or scope["organization_id"],
                    "workspace_id": workspace or scope["workspace_id"]})
                report["phase"] = "saml-browser-login-" + user["username"]
                output.publish(report)
                page.goto(url)
                page.locator("#username").fill(user["username"])
                page.locator("#password").fill(user["password"])
                page.locator("#kc-login").click()
                if capture is not None:
                    page.wait_for_url(callback)
                    page.get_by_text("Synthetic callback held", exact=True).wait_for()
                    if "SAMLResponse" not in capture.get("fields", {}):
                        raise RuntimeError("genuine vendor callback absent")
                elif success:
                    try:
                        page.wait_for_url(gateway_base + "/customer")
                        page.locator("#identity").wait_for(state="visible")
                        page.locator("#role").wait_for(state="visible")
                    except Exception:
                        # Keep bounded diagnostics, never cookies, assertions,
                        # raw error text or private runtime logs in evidence.
                        observation["at_acs"] = page.url == callback
                        observation["at_console"] = page.url == gateway_base + "/customer"
                        observation["at_vendor"] = page.url.startswith(vendor_base + "/")
                        visible = page.locator("body").inner_text(timeout=3000).lower()
                        observation["vendor_error_categories"] = [label for label in (
                            "invalid username or password", "invalid user", "account is disabled", "account is not fully set up",
                            "expired", "timed out", "cookie", "invalid requester", "invalid signature", "unexpected error",
                            "verify your email", "update password", "update account information") if label in visible]
                        log_text = (directory / "gateway.log").read_bytes()[log_offset:].decode(errors="replace").lower()
                        last = log_text.rsplit("saml response validation failed", 1)
                        observation["validation_error_categories"] = [word for word in
                            ("expired", "signature", "audience", "issuer", "destination", "recipient", "request", "replay", "notbefore", "not yet valid")
                            if len(last) == 2 and word in last[-1]]
                        observation["local_authorization_error"] = "failed to authorize saml identity" in log_text
                        report["failed_login"] = observation
                        raise
                else:
                    page.wait_for_url(callback)
                    page.get_by_text("SAML login could not be completed", exact=False).wait_for()
                return page

            def browser_fetch(page, path, method="GET", headers=None, body=None):
                return page.evaluate("""async ({path, method, headers, body}) => {
                    const response = await fetch(path, {method, headers, body, credentials:'same-origin', cache:'no-store'});
                    const text = await response.text();
                    let data = null; try { data = JSON.parse(text); } catch (_) {}
                    return {status:response.status, data};
                }""", {"path": path, "method": method, "headers": headers or {}, "body": body})

            def capture_assertion():
                captured = {}
                login(context(), users[0], capture=captured)
                return captured

            def submit(captured, fields=None, cookie=None):
                return request("POST", callback, data=fields or captured["fields"],
                               headers={"Cookie": captured["cookie"] if cookie is None else cookie})

            captured = capture_assertion()
            original = ET.fromstring(base64.b64decode(captured["fields"]["SAMLResponse"]))
            check("genuine-vendor-assertion-contains-untrusted-owner-role", any(
                value.text == "owner" for value in original.findall(".//saml:AttributeValue", vendor.NS)))
            count = database.sql("SELECT count(*) FROM oidc_browser_sessions")
            check("genuine-assertion-without-browser-binding-rejected", submit(captured, cookie="").status_code == 400)
            check("missing-binding-does-not-create-session", database.sql("SELECT count(*) FROM oidc_browser_sessions") == count)
            check("same-genuine-assertion-with-originating-browser-accepted", submit(captured).status_code == 303)
            check("callback-replay-rejected", submit(captured).status_code == 400)
            captured = capture_assertion()
            tampered = dict(captured["fields"])
            tampered["SAMLResponse"] = base64.b64encode(vendor.tamper_nameid(base64.b64decode(tampered["SAMLResponse"]),
                users[0]["username"] + "@example.test", users[1]["username"] + "@example.test")).decode()
            count = database.sql("SELECT count(*) FROM oidc_browser_sessions")
            check("altered-identity-to-another-provisioned-member-rejected", submit(captured, tampered).status_code == 400)
            check("altered-assertion-does-not-create-session", database.sql("SELECT count(*) FROM oidc_browser_sessions") == count)
            first, second = capture_assertion(), capture_assertion()
            mismatch = dict(first["fields"], RelayState=second["fields"]["RelayState"])
            check("genuine-assertion-wrong-request-correlation-rejected", submit(second, mismatch).status_code == 400)
            check("original-request-remains-usable", submit(first).status_code == 303)

            owner = context()
            page = login(owner, users[0])
            check("console-login-through-real-keycloak", page.locator("#role").inner_text() == "owner")
            cookie = next(c for c in owner.cookies() if c["name"] == "__Host-llm-fw-session")
            check("secure-opaque-host-session-cookie", cookie["secure"] and cookie["httpOnly"]
                  and cookie["sameSite"] == "Lax" and cookie["path"] == "/" and "." not in cookie["value"])
            check("owner-can-read-owner-only-api", browser_fetch(page, "/customer/v1/billing/invoice-preview")["status"] == 200)
            check("refresh-needs-csrf", browser_fetch(page, "/auth/session/refresh", "POST")["status"] == 403)
            csrf = browser_fetch(page, "/customer/v1/csrf")["data"]["token"]
            old_cookie = cookie["value"]
            check("csrf-protected-session-rotation", browser_fetch(page, "/auth/session/refresh", "POST",
                  {"X-LLM-Firewall-CSRF-Token": csrf})["status"] == 204)
            check("rotated-cookie-invalidates-previous-session", request("GET", gateway_base + "/customer/v1/session",
                  headers={"Cookie": "__Host-llm-fw-session=" + old_cookie}).status_code == 401)
            pending_restart = capture_assertion()
            stop_child(gateway)
            if database.container:
                before = database.identity_snapshot()
                check("migrations-on-populated-identity-store", migrate())
                check("populated-identity-and-session-state-preserved", database.identity_snapshot() == before)
                database.restart()
                check("postgres-restart-preserves-populated-state", database.identity_snapshot() == before)
            gateway = start_gateway()
            check("pending-saml-login-survives-gateway-and-database-restart", submit(pending_restart).status_code == 303)
            check("pending-saml-login-remains-single-use-after-restart", submit(pending_restart).status_code == 400)
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
                  "SAML login could not be completed" in denied_member_page.locator("body").inner_text())
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
                ("selected-workspace-without-membership-denied", users[0], scope["organization_id"], scope["other_workspace_id"])]:
                denied = context()
                denied_page = login(denied, user, org, workspace, success=False)
                check(name, "SAML login could not be completed" in denied_page.locator("body").inner_text()
                      and not any(c["name"] == "__Host-llm-fw-session" for c in denied.cookies()))
            # Only this disposable realm's administrator may rotate the vendor key.
            def operator_headers():
                auth = request("POST", issuer + "/protocol/openid-connect/token", data={
                    "client_id": "admin-cli", "grant_type": "password", "username": "fixture-operator",
                    "password": operator_password})
                check("owned-realm-operator-authenticated", auth.status_code == 200)
                return {"Authorization": "Bearer " + auth.json()["access_token"]}

            vendor_admin = operator_headers()
            realm_admin = vendor_base + "/admin/realms/" + realm
            realm_id = request("GET", realm_admin, headers=vendor_admin).json()["id"]
            components = request("GET", realm_admin + "/components", headers=vendor_admin,
                                 params={"type": "org.keycloak.keys.KeyProvider"}).json()
            old_assertion = capture_assertion()
            new_key = {"name": "disposable-rotation", "providerId": "rsa-generated",
                "providerType": "org.keycloak.keys.KeyProvider", "parentId": realm_id,
                "config": {"priority": ["200"], "enabled": ["true"], "active": ["true"],
                           "algorithm": ["RS256"], "keySize": ["2048"]}}
            check("keycloak-generates-new-signing-key", request("POST", realm_admin + "/components",
                  headers=vendor_admin, json=new_key).status_code in (200, 201))
            for component in components:
                if component.get("providerId") == "rsa-generated":
                    component["config"]["enabled"] = ["false"]
                    component["config"]["active"] = ["false"]
                    check("vendor-retires-previous-rsa-key", request("PUT", realm_admin + "/components/" + component["id"],
                          headers=vendor_admin, json=component).status_code == 204)
            rotated = metadata_connection()
            check("genuine-vendor-certificate-changed", rotated["metadata_signing_cert_pem"] != connection["metadata_signing_cert_pem"])
            fresh = capture_assertion()
            count = database.sql("SELECT count(*) FROM oidc_browser_sessions")
            check("incoming-new-key-not-automatically-trusted", submit(fresh).status_code == 400)
            check("untrusted-key-cannot-create-session", database.sql("SELECT count(*) FROM oidc_browser_sessions") == count)
            check("operator-replaces-metadata-and-pin", request("PUT", connection_url, headers=admin_headers,
                  json=rotated).status_code == 200)
            check("retired-key-valid-unconsumed-assertion-rejected", submit(old_assertion).status_code == 400)
            check("new-key-login-after-explicit-pin-update", login(context(), users[0]).locator("#role").inner_text() == "owner")
            # The retired realm key also signed the old admin access token.
            # Authenticate again; never silently accept an unauthorized API response.
            vendor_admin = operator_headers()
            # Vendor generates an otherwise valid short-lived assertion. Do not edit signed XML or the system clock.
            clients = request("GET", realm_admin + "/clients", headers=vendor_admin,
                              params={"clientId": client_id}).json()
            client_record = request("GET", realm_admin + "/clients/" + clients[0]["id"], headers=vendor_admin).json()
            client_record["attributes"]["saml.assertion.lifespan"] = "2"
            client_url = realm_admin + "/clients/" + client_record["id"]
            check("vendor-short-lived-assertion-configured", request("PUT", client_url,
                  headers=vendor_admin, json=client_record).status_code == 204)
            expired = capture_assertion()
            xml = ET.fromstring(base64.b64decode(expired["fields"]["SAMLResponse"]))
            conditions = xml.find("saml:Assertion/saml:Conditions", vendor.NS)
            expiry = dt.datetime.fromisoformat(conditions.attrib["NotOnOrAfter"].replace("Z", "+00:00"))
            remaining = (expiry - dt.datetime.now(dt.timezone.utc)).total_seconds()
            check("vendor-expiry-bounded-for-real-time-control", -5 < remaining < 10)
            time.sleep(max(0, remaining) + 1)
            count = database.sql("SELECT count(*) FROM oidc_browser_sessions")
            check("genuine-expired-assertion-refused", submit(expired).status_code == 400)
            check("expiry-refusal-does-not-create-session", database.sql("SELECT count(*) FROM oidc_browser_sessions") == count)
            # Keycloak updates may retain omitted attributes; explicitly reset
            # the lifetime instead of relying on deletion by omission.
            client_record["attributes"]["saml.assertion.lifespan"] = "300"
            check("vendor-normal-lifetime-restored", request("PUT", client_url, headers=vendor_admin,
                  json=client_record).status_code == 204)
            check("fresh-normal-lifetime-login-succeeds", login(context(), users[0]).locator("#role").inner_text() == "owner")
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
    parser.add_argument("--gateway", type=Path, required=True)
    parser.add_argument("--bootstrap-helper", type=Path, required=True)
    parser.add_argument("--backend", choices=["sqlite", "postgres"], default="sqlite")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--artifact-label", required=True)
    args = parser.parse_args()
    args.gateway = args.gateway.resolve(strict=True)
    args.bootstrap_helper = args.bootstrap_helper.resolve(strict=True)
    return run(args)

if __name__ == "__main__":
    raise SystemExit(main())
