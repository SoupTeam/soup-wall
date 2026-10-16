#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in, owned Console recovery with two real managed Agent processes.

No default/customer database or external provider is accessed. The report is a
bounded local recovery witness, not fleet/remote transport acceptance. Owned
private fixtures are removed after the run unless explicit debugging retention
is selected. Public evidence must be written outside that disposable directory.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
OBJECTIVE = {
    "recovery_time_objective_seconds": 120,
    "recovery_time_objective_start": "valid current archive restore begins after isolated negative controls",
    "recovery_time_objective_end": "both restored Agents acknowledge a higher signed sequence and live hooks match",
    "recovery_point": "complete quiesced snapshot; zero accepted Console writes after snapshot",
    "deployment_limits": "owned Unix, literal-loopback Console/Agents, one issuer, schema 27",
    "excluded": ["remote HTTPS", "fleet reconciliation", "new signing epoch", "exactly-once delivery"],
}


class AcceptanceError(RuntimeError):
    """Only fixed, public-safe descriptions cross this boundary."""


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def unchanged_private_file(path, expected_digest):
    """A missing/replaced/nonprivate file cannot establish retained trust."""
    try:
        metadata = Path(path).lstat()
        return (stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) == 0o600
                and sha256(path) == expected_digest)
    except OSError:
        return False


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def private_directory(path, *, create=False):
    path = Path(path).absolute()
    if create:
        if path.parent.resolve() != path.parent or not path.parent.is_dir():
            raise AcceptanceError("Private fixture parent must be an existing canonical directory.")
        path.mkdir(mode=0o700)
    try:
        metadata = path.lstat()
        good = (os.name == "posix" and stat.S_ISDIR(metadata.st_mode)
                and path.resolve() == path and metadata.st_uid == os.geteuid()
                and stat.S_IMODE(metadata.st_mode) == 0o700)
    except OSError:
        good = False
    if not good:
        raise AcceptanceError("Private fixture directory is unsafe.")
    return path


def private_write(path, data):
    path = Path(path)
    private_directory(path.parent)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def child_environment(extra=None):
    keep = {"PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "SYSTEMROOT",
            "WINDIR", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"}
    result = {key: value for key, value in os.environ.items() if key.upper() in keep}
    result.update(extra or {})
    return result


def checked(command, *, environment, cwd, timeout=120, log=None):
    result = subprocess.run([str(value) for value in command], cwd=cwd,
                            env=environment, capture_output=True, timeout=timeout)
    if log is not None:
        private_write(log, (result.stdout + result.stderr).decode("utf-8", errors="replace"))
    if result.returncode:
        raise AcceptanceError("A fixture command failed; private output was withheld.")
    return result.stdout.decode("utf-8")


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def request(method, url, payload=None, headers=None):
    """No proxy, redirects or external authority; all callers use owned URLs."""
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.port is None
            or parsed.username or parsed.password or parsed.fragment):
        raise AcceptanceError("Only the owned numeric-loopback HTTP fixture is supported.")
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=4) as response:
            raw = response.read(256 * 1024 + 1)
            if len(raw) > 256 * 1024:
                raise AcceptanceError("The local fixture response exceeded its bound.")
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        return error.code, None


def wait_for(label, predicate, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (ConnectionError, OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    raise AcceptanceError("A bounded local runtime observation timed out: " + label)


def stop_child(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def cleanup_owned_tree(directory, identity):
    """Remove only the fresh private directory created by this invocation."""
    directory = private_directory(directory)
    metadata = directory.lstat()
    if (metadata.st_dev, metadata.st_ino) != identity:
        raise AcceptanceError("Private fixture ownership changed; cleanup was refused.")
    shutil.rmtree(directory)
    if directory.exists() or directory.is_symlink():
        raise AcceptanceError("Owned private fixture cleanup did not complete.")


def source_metadata(args):
    """Bind uncommitted runtime inputs too; publish only code/file hashes."""
    paths = [
        "Cargo.toml", "Cargo.lock", "crates/proxy/Cargo.toml",
        "crates/proxy/src/main.rs", "crates/proxy/src/tenant_store.rs",
        "crates/proxy/src/managed_agent_api.rs", "crates/proxy/src/tenant_store/managed_policy.rs",
        "crates/proxy/src/tenant_store/managed_postgres.rs",
        "crates/proxy/src/tenant_store/postgres.rs",
        "crates/proxy/src/tenant_store/managed_async.rs",
        "crates/proxy/src/tenant_store/recovery_outbox_fixture.rs",
        "crates/proxy/examples/console-recovery-fixture.rs",
        "crates/agentfw/src/managed_policy.rs", "crates/agentfw/src/managed_sync.rs",
        "crates/agentfw/src/handlers.rs", "scripts/console-recovery-acceptance.py",
        "scripts/console_recovery.py", "scripts/console-recovery.py",
        "scripts/fixtures/console_recovery_inventory_v1.json",
        "scripts/alert_receiver.py", "scripts/keycloak-oidc-acceptance.py",
        "scripts/keycloak-saml-acceptance.py",
    ]
    # Include native submodules and include_str!/include_bytes! assets rather
    # than assuming the top-level Rust files establish the compiled boundary.
    for crate in ("core", "agent", "adapter", "agentfw", "proxy"):
        paths.append(f"crates/{crate}/Cargo.toml")
        paths.append(f"crates/{crate}/build.rs")
        paths.extend(str(path.relative_to(ROOT)) for path in (ROOT / "crates" / crate / "src").rglob("*")
                     if path.is_file())
    paths.extend(str(path.relative_to(ROOT)) for path in (ROOT / "vendor/kryptering/src").rglob("*")
                 if path.is_file())
    paths.append("vendor/kryptering/Cargo.toml")
    inputs = {path: sha256(ROOT / path) for path in sorted(set(paths)) if (ROOT / path).is_file()}
    if args.webhook_driver:
        inputs["selected_webhook_adapter"] = sha256(args.webhook_driver)
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"],
                                     cwd=ROOT)
    return {"commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                    text=True).strip(), "worktree_dirty": bool(status.strip()),
            "tracked_diff_sha256": hashlib.sha256(subprocess.check_output(
                ["git", "diff", "--binary", "HEAD"], cwd=ROOT)).hexdigest(),
            "runtime_input_sha256": inputs,
            "runtime_inputs_sha256": hashlib.sha256(canonical(inputs).encode()).hexdigest(),
            "schema_version": 27,
            "configuration": "owned loopback, webhook source dispatcher disabled"}


class Run:
    def __init__(self, args, directory):
        self.args, self.directory = args, directory
        self.checks, self.durations = [], {}
        self.children = []
        self.console = None
        self.console_counter = 0
        self.console_port = free_port()
        self.console_url = f"http://127.0.0.1:{self.console_port}"
        self.admin = secrets.token_urlsafe(32)
        self.issuer_seed = secrets.token_hex(32)
        self.admin_headers = {"x-llm-firewall-admin-token": "Bearer " + self.admin}
        self.environment = child_environment({"LLM_FW_ADMIN_TOKEN": self.admin,
            "SOUP_AGENT_POLICY_SEED_HEX": self.issuer_seed,
            "SOUP_AGENT_POLICY_KEY_ID": "sou49-owned-issuer"})
        self.workspace = private_directory(directory / "console", create=True)
        self.fixture = None
        self.databases = {}
        self.current_database = None
        self.postgres = None
        self.agents = []
        self.schema_version = 27

    def check(self, name, passed, **observations):
        self.checks.append({"name": name, "passed": bool(passed), **observations})
        print(f"{'PASS' if passed else 'FAIL'}: {name}", flush=True)
        if not passed:
            raise AcceptanceError("A recovery acceptance assertion failed: " + name)

    def timed(self, name, operation):
        start = time.monotonic()
        try:
            return operation()
        finally:
            self.durations[name] = round(time.monotonic() - start, 6)

    def process(self, command, cwd, environment, label):
        log = self.directory / (label + ".log")
        descriptor = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            process = subprocess.Popen([str(item) for item in command], cwd=cwd,
                env=environment, stdout=stream, stderr=subprocess.STDOUT)
        self.children.append(process)
        return process

    def configure(self, name):
        self.current_database = name
        database = self.databases[name]
        path = self.workspace / "firewall.yaml"
        if path.exists():
            path.unlink()
        backend = (f'  backend: sqlite\n  database_path: {json.dumps(str(database))}\n'
                   if self.args.backend == "sqlite" else
                   "  backend: postgres\n  postgres_url_env: SOU49_RUNTIME_DATABASE_URL\n")
        private_write(path, f'bind: "127.0.0.1:{self.console_port}"\n'
            + "tenant_store:\n  enabled: true\n" + backend)
        if self.args.backend == "postgres":
            self.environment["SOU49_RUNTIME_DATABASE_URL"] = database

    def initialize(self, resources):
        if self.args.backend == "sqlite":
            self.databases = {name: self.directory / (name + ".sqlite")
                              for name in ("source", "recovered", "stale")}
        else:
            helpers = load_module("sou49_owned_database", ROOT / "scripts/keycloak-oidc-acceptance.py")
            ca, (cert, key), _ = helpers.vendor.certificate_files(self.directory)
            self.postgres = helpers.FixtureDatabase(self.directory, self.environment,
                resources, postgres=True, cert=cert, key=key)
            from urllib.parse import quote, urlsplit, urlunsplit
            original = urlsplit(self.environment["SOUP_OIDC_FIXTURE_DATABASE_URL"])
            # Numeric-loopback development DB only. Neither the fixture role
            # nor these plaintext URLs are supported for remote production use.
            role = "sou49_owner_" + secrets.token_hex(8)
            password = secrets.token_urlsafe(32)
            self.postgres.sql(f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '{password}'; GRANT pg_monitor TO {role}")
            authority = f"{role}:{quote(password, safe='')}@{original.hostname}:{original.port}"
            for name in ("source", "recovered", "stale"):
                database_name = "sou49_" + name + "_" + secrets.token_hex(8)
                self.postgres.sql(f"CREATE DATABASE {database_name} OWNER {role}")
                self.databases[name] = urlunsplit(original._replace(netloc=authority, path="/" + database_name,
                                                                    query="sslmode=disable"))
            self.environment.pop("LLM_FW_POSTGRES_CA_CERT_FILE", None)
        self.configure("source")
        if self.args.backend == "postgres":
            checked([self.args.console_binary, "migrate"], environment=self.environment,
                    cwd=self.workspace, log=self.directory / "explicit-source-migration.log")
        self.fixture_call("seed", "source")
        manifest = self.directory / "fixture-manifest.json"
        metadata = manifest.lstat()
        self.check("fixture-manifest-owner-only", stat.S_IMODE(metadata.st_mode) == 0o600
                   and metadata.st_uid == os.geteuid() and not manifest.is_symlink())
        self.fixture = json.loads(manifest.read_text())
        self.check("source-webhook-dispatcher-disabled", "LLM_FW_WEBHOOK_SIGNING_KEY" not in self.environment)

    def fixture_environment(self, name):
        name_key = ("LLM_FW_CONSOLE_RECOVERY_FIXTURE_SQLITE_PATH" if self.args.backend == "sqlite"
                    else "LLM_FW_CONSOLE_RECOVERY_FIXTURE_DATABASE_URL")
        return child_environment({name_key: str(self.databases[name])})

    def fixture_call(self, phase, name):
        output = checked([self.args.fixture_helper, phase, self.directory],
            environment=self.fixture_environment(name), cwd=self.directory,
            log=self.directory / f"fixture-{phase}-{name}-{secrets.token_hex(3)}.log")
        result = json.loads(output)
        self.check(f"native-fixture-{phase}-{name}", result.get("status") == "passed")
        return result

    def start_console(self, name):
        if self.console is not None and self.console.poll() is None:
            raise AcceptanceError("Previous Console must be stopped before controlled startup.")
        self.configure(name)
        self.console_counter += 1
        self.console = self.process([self.args.console_binary], self.workspace,
            self.environment, f"console-{self.console_counter}-{name}")
        def ready():
            if self.console.poll() is not None:
                raise AcceptanceError("The Console exited during startup; private logs withheld.")
            return request("GET", self.console_url + "/healthz")[0] == 200
        wait_for("Console readiness", ready)

    def stop_console(self):
        if self.console is not None:
            stop_child(self.console)
            self.check("owned-console-process-stopped", self.console.poll() is not None)

    def api(self, method, path, payload=None, headers=None, status=200):
        actual, body = request(method, self.console_url + path, payload,
                               self.admin_headers if headers is None else headers)
        if actual != status:
            raise AcceptanceError("An owned Console API returned an unexpected HTTP status.")
        return body

    def enroll_agents(self):
        issuer = self.api("GET", "/admin/v1/managed-issuer")
        self.check("operator-pinned-issuer-shape", issuer["key_id"] == "sou49-owned-issuer"
                   and len(issuer["public_key_hex"]) == 64)
        self.initial_issuer = {key: issuer[key] for key in ("key_id", "public_key_hex")}
        for number, tenant in enumerate((self.fixture["tenant_id"], self.fixture["control_tenant_id"])):
            agent_id = "sou49-agent"
            base = f"/admin/v1/tenants/{tenant}/agents/{agent_id}"
            credentials = self.api("POST", f"/admin/v1/tenants/{tenant}/agents",
                                   {"agent_id": agent_id}, status=201)
            for revision, decision in (("deny", "deny"), ("allow", "allow")):
                self.api("POST", base + "/revisions", {"revision": revision,
                    "policy_yaml": f"default: {decision}\n"}, status=201)
                self.api("POST", base + f"/revisions/{revision}/approve", {}, status=204)
            home = private_directory(self.directory / f"agent-home-{number}", create=True)
            agent_home = private_directory(home / ".agentfw", create=True)
            agent_port = free_port()
            private_write(agent_home / "config.yaml", f"bind: 127.0.0.1\nport: {agent_port}\nenforce: true\n")
            keyring = agent_home / "trusted-issuers.json"
            private_write(keyring, canonical({"schema_version": 1, "issuers": [{
                "key_id": issuer["key_id"], "public_key_hex": issuer["public_key_hex"],
                "revoked": False}]}) + "\n")
            environment = child_environment({"HOME": str(home),
                "SOUP_MANAGED_AGENT_CONSOLE": self.console_url + "/",
                "SOUP_MANAGED_AGENT_TOKEN": credentials["token"],
                "SOUP_MANAGED_AGENT_TENANT": tenant,
                "SOUP_MANAGED_AGENT_ID": agent_id,
                "SOUP_MANAGED_AGENT_KEYRING_PATH": str(keyring),
                "SOUP_MANAGED_AGENT_KEY_ID": issuer["key_id"],
                "SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX": issuer["public_key_hex"]})
            item = {"tenant": tenant, "base": base, "token": credentials["token"],
                    "url": f"http://127.0.0.1:{agent_port}", "home": home,
                    "environment": environment, "number": number,
                    "keyring": keyring, "initial_keyring_sha256": sha256(keyring),
                    "initial_configuration_sha256": sha256(agent_home / "config.yaml")}
            self.deploy(item, "deny", 1)
            item["process"] = self.process([self.args.agent_binary, "serve"], self.directory,
                                            environment, f"agent-{number}-initial")
            self.agents.append(item)
        revoked = self.api("POST", f'/admin/v1/tenants/{self.fixture["tenant_id"]}/agents',
                           {"agent_id": "revoked-recovery-agent"}, status=201)
        self.revoked_agent_token = revoked["token"]
        self.api("POST", f'/admin/v1/tenants/{self.fixture["tenant_id"]}/agents/revoked-recovery-agent/revoke',
                 {}, status=204)
        for item in self.agents:
            item["hook_token"] = wait_for("Agent hook credential", lambda item=item:
                (item["home"] / ".agentfw/token").read_text().strip()
                if (item["home"] / ".agentfw/token").exists() else None)
            self.observe(item, 1, "deny")
        self.check("two-real-agent-processes-distinct-tenants", len(self.agents) == 2
            and len({item["process"].pid for item in self.agents}) == 2
            and len({item["tenant"] for item in self.agents}) == 2)

    def deploy(self, item, revision, sequence):
        data = self.api("POST", item["base"] + f"/revisions/{revision}/deploy", {"rollback": False}, status=201)
        self.check(f"signed-deployment-sequence-{sequence}-agent-{item['number']}",
                   data["deployment_sequence"] == sequence)
        return data

    def health(self, item):
        if item["process"].poll() is not None:
            raise AcceptanceError("An actual Agent exited; private logs withheld.")
        status, body = request("GET", item["url"] + "/health")
        if status != 200:
            raise AcceptanceError("Agent health unavailable.")
        return body

    def online(self, item, phase, sequence=3):
        health = wait_for("actual Agent transport reconnected", lambda:
            (lambda value: value if value.get("managed_transport", {}).get("state") == "online"
             and value.get("managed_policy", {}).get("deployment_sequence") == sequence
             else None)(self.health(item)))
        self.check(phase + "-transport-online-agent-" + str(item["number"]),
                   health["managed_transport"]["state"] == "online")
        return {"agent": item["number"], "state": health["managed_transport"]["state"],
                "deployment_sequence": health["managed_policy"]["deployment_sequence"]}

    def verify_operator_trust(self):
        """Check actual retained files, Agent pin selection and issuer API."""
        self.check("operator-signing-settings-bytes-and-environment-unchanged",
            unchanged_private_file(self.directory / "operator-settings.json", self.operator_settings_sha256)
            and self.environment.get("SOUP_AGENT_POLICY_SEED_HEX") == self.issuer_seed
            and self.environment.get("SOUP_AGENT_POLICY_KEY_ID") == self.initial_issuer["key_id"])
        issuer = self.api("GET", "/admin/v1/managed-issuer")
        self.check("recovered-console-issuer-key-id-and-public-key-unchanged",
                   {key: issuer.get(key) for key in ("key_id", "public_key_hex")} == self.initial_issuer)
        agents = []
        for item in self.agents:
            self.check("operator-pinned-trust-file-unchanged-agent-" + str(item["number"]),
                unchanged_private_file(item["keyring"], item["initial_keyring_sha256"])
                and item["environment"].get("SOUP_MANAGED_AGENT_KEYRING_PATH") == str(item["keyring"]))
            self.check("actual-agent-configuration-unchanged-agent-" + str(item["number"]),
                unchanged_private_file(item["home"] / ".agentfw/config.yaml",
                                       item["initial_configuration_sha256"]))
            agents.append({"agent": item["number"], "trust_mode": "explicit native keyring file",
                "pinned_trust_sha256": item["initial_keyring_sha256"],
                "configuration_sha256": item["initial_configuration_sha256"]})
        return {"operator_settings_sha256": self.operator_settings_sha256,
                "issuer_key_id": self.initial_issuer["key_id"],
                "issuer_public_key_sha256": hashlib.sha256(bytes.fromhex(
                    self.initial_issuer["public_key_hex"])).hexdigest(),
                "unchanged": True, "agents": agents}

    def hook(self, item):
        status, body = request("POST", item["url"] + "/hook", {
            "session_id": "sou49-" + secrets.token_hex(8), "hook_event_name": "PreToolUse",
            "tool_name": "Bash", "tool_input": {"command": "echo recovery-owned-fixture"}},
            {"Authorization": "Bearer " + item["hook_token"]})
        if status != 200:
            raise AcceptanceError("Owned Agent hook unavailable.")
        return "defer" if body == {} else body["hookSpecificOutput"]["permissionDecision"]

    def observe(self, item, sequence, decision):
        health = wait_for("actual Agent applied sequence", lambda:
            (lambda health: health if health.get("managed_policy", {}).get("deployment_sequence")
             == sequence else None)(self.health(item)))
        def acknowledged():
            rows = self.api("GET", item["base"] + "/deployments")
            return next((row for row in rows if row["deployment_sequence"] == sequence
                and row["status"] == "applied" and row["revision"] == health["managed_policy"]["revision"]
                and row["policy_sha256"] == health["managed_policy"]["policy_sha256"]), None)
        ack = wait_for("exact Console acknowledgement", acknowledged)
        self.check(f"live-hook-sequence-{sequence}-{decision}-agent-{item['number']}",
                   self.hook(item) == decision)
        return {"deployment_sequence": sequence, "revision": ack["revision"],
                "policy_sha256": ack["policy_sha256"], "status": ack["status"],
                "hook_decision": decision}

    def backup(self, label):
        self.check("source-stopped-before-backup-" + label,
                   self.console is not None and self.console.poll() is not None)
        archive = self.directory / (label + ".age")
        if self.args.backend == "sqlite":
            self.backup_module.backup_sqlite(self.databases["source"], archive, self.recipient,
                workdir=self.directory, age=self.args.age)
        else:
            self.backup_module.backup_postgres(self.databases["source"], archive, self.recipient,
                workdir=self.directory, age=self.args.age, source_quiesced=True,
                psql=self.args.psql, pg_dump=self.args.pg_dump)
        return archive

    def restore(self, archive, name):
        if self.args.backend == "sqlite":
            receipt = self.backup_module.restore_sqlite(archive, self.databases[name], self.identity,
                workdir=self.directory, age=self.args.age)
        else:
            receipt = self.backup_module.restore_postgres(archive, self.databases[name], self.identity,
                workdir=self.directory, age=self.args.age, psql=self.args.psql,
                pg_restore=self.args.pg_restore)
        self.check("private-row-and-sequence-verification-" + name,
                   receipt.get("status") == "passed" and receipt.get("phase") == "restore"
                   and receipt.get("tables_verified", 0) > 0)
        return receipt

    def snapshot(self, name):
        if self.args.backend == "sqlite":
            return self.backup_module.inspect_sqlite(self.databases[name])
        return self.backup_module.PostgresBackend(self.databases[name], directory=self.directory,
                                                  psql=self.args.psql).snapshot()

    def postgres_backend(self, name):
        return self.backup_module.PostgresBackend(self.databases[name], directory=self.directory,
                                                  psql=self.args.psql)

    def refused_restore(self, archive, url, *, identity=None):
        try:
            self.backup_module.restore_postgres(archive, url, identity or self.identity,
                workdir=self.directory, age=self.args.age, psql=self.args.psql,
                pg_restore=self.args.pg_restore)
        except self.backup_module.RecoveryError:
            return True
        return False

    def mutated_encrypted_archive(self, archive, variant):
        """Re-encrypt one deliberately incompatible, internally hashed archive.

        This is a negative fixture, never a repair/import path. The shared
        production decoder validates the original before these owned mutations.
        Its private plaintext scope is removed on every exit by the shared tool.
        """
        module = self.backup_module
        output = self.directory / ("negative-" + variant + ".age")
        with module.decrypted_archive(archive, self.identity, workdir=self.directory,
                                      age=self.args.age) as (manifest, state, dump, temporary):
            definition = json.loads(module.canonical(module.inventory()))
            if variant == "schema":
                manifest["schema_version"] += 1
            elif variant == "inventory":
                definition["unreviewed_recovery_inventory"] = True
            else:
                raise AcceptanceError("Unsupported owned negative archive variant.")
            members = {"inventory.json": module.canonical(definition),
                       "state.json": module.canonical(state), "database.dump": dump.read_bytes()}
            manifest["inventory_sha256"] = hashlib.sha256(members["inventory.json"]).hexdigest()
            manifest["files"] = {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                                 for name, data in members.items()}
            members["manifest.json"] = module.canonical(manifest)
            plain = temporary / "negative.tar"
            descriptor = os.open(plain, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream, tarfile.open(fileobj=stream,
                    mode="w", format=tarfile.USTAR_FORMAT) as container:
                for name, data in sorted(members.items()):
                    member = tarfile.TarInfo(name)
                    member.size, member.mode, member.uid, member.gid, member.mtime = len(data), 0o600, 0, 0, 0
                    container.addfile(member, io.BytesIO(data))
            module.encrypt_archive(plain, output, self.recipient, temporary, self.args.age)
        return output

    def postgres_negative_controls(self, archive, source_state):
        """Run actual native refusal paths against three owned databases."""
        from urllib.parse import urlsplit, urlunsplit
        source = self.postgres_backend("source")
        target = self.postgres_backend("recovered")
        source_identity, target_identity = source.identity(), target.identity()
        self.check("negative-target-is-physically-separate",
                   not self.backup_module.same_postgres_database(source_identity, target_identity))
        target.require_owned()
        target.require_empty()
        def unchanged(label):
            target.require_empty()
            self.check("negative-" + label + "-preserves-source-and-fresh-target",
                source.identity() == source_identity and target.identity() == target_identity
                and source_state == canonical(self.snapshot("source")))
        # The spelling differs, but libpq decodes the first username byte and
        # the same cluster/database OID must be observed before refusing it.
        parsed = urlsplit(self.databases["source"])
        username = parsed.username
        alias_authority = "%" + format(ord(username[0]), "02x") + parsed.netloc[1:]
        alias = urlunsplit(parsed._replace(netloc=alias_authority))
        alias_backend = self.backup_module.PostgresBackend(alias, directory=self.directory,
                                                          psql=self.args.psql)
        self.check("negative-alternate-url-resolves-to-source-identity",
                   alias != self.databases["source"] and alias_backend.identity() == source_identity)
        self.check("negative-source-alias-refused", self.refused_restore(archive, alias))
        unchanged("source-alias")
        populated = self.postgres_backend("stale")
        populated.require_owned()
        populated.require_empty()
        populated.sql("CREATE TABLE sou49_negative_sentinel (id INTEGER PRIMARY KEY, value TEXT NOT NULL); "
                      "INSERT INTO sou49_negative_sentinel VALUES (1,'owned populated target must remain unchanged');")
        def populated_witness():
            return canonical({"identity": populated.identity(), "catalog": populated.catalog(),
                "schema": populated.logical_schema(), "rows": json.loads(populated.sql(
                    "SELECT json_agg(row_to_json(t) ORDER BY id) FROM sou49_negative_sentinel t;"))})
        before_populated = populated_witness()
        self.check("negative-populated-target-refused", self.refused_restore(archive, self.databases["stale"]))
        self.check("negative-populated-target-rows-and-ddl-preserved", before_populated == populated_witness())
        populated.sql("DROP TABLE sou49_negative_sentinel;")
        populated.require_empty()
        unchanged("populated-target")
        corrupt = self.directory / "negative-corrupt.age"
        raw = bytearray(archive.read_bytes())
        raw[len(raw) // 2] ^= 1
        self.backup_module.write_private(corrupt, bytes(raw))
        self.check("negative-corrupt-ciphertext-refused", self.refused_restore(corrupt, self.databases["recovered"]))
        unchanged("corrupt-ciphertext")
        wrong_key = self.directory / "negative-wrong.agekey"
        checked([self.args.age_keygen, "-o", wrong_key], environment=child_environment(), cwd=self.directory)
        os.chmod(wrong_key, 0o600)
        self.check("negative-wrong-decryption-identity-refused",
                   self.refused_restore(archive, self.databases["recovered"], identity=wrong_key))
        unchanged("wrong-decryption-identity")
        for variant in ("schema", "inventory"):
            incompatible = self.mutated_encrypted_archive(archive, variant)
            self.check("negative-reauthenticated-" + variant + "-refused",
                       self.refused_restore(incompatible, self.databases["recovered"]))
            unchanged("reauthenticated-" + variant)

    def identities(self):
        for item in self.agents:
            body = self.api("GET", "/agent/v1/whoami", headers={"Authorization": "Bearer " + item["token"]})
            self.check("restored-managed-identity-" + str(item["number"]), body.get("tenant_id") == item["tenant"])
        self.api("GET", "/agent/v1/whoami", headers={"Authorization": "Bearer " + self.revoked_agent_token}, status=401)
        self.check("revoked-managed-credential-remains-revoked", True)
        # Invalid JSON reaches the authenticated API extractor but never a
        # provider request. Revoked credentials must stop at authentication.
        for name in ("active_account_token", "control_active_account_token"):
            status, _ = request("POST", self.console_url + "/v1/chat/completions", {},
                                {"x-llm-firewall-token": "Bearer " + self.fixture[name]})
            self.check("restored-retained-service-credential-" + name, status == 422)
        self.api("POST", "/v1/chat/completions", {},
            {"x-llm-firewall-token": "Bearer " + self.fixture["revoked_account_token"]}, status=401)
        self.check("revoked-service-credential-remains-revoked", True)

    def run(self, resources):
        self.backup_module = load_module("sou49_console_recovery", ROOT / "scripts/console_recovery.py")
        self.identity = self.directory / "recovery.agekey"
        output = checked([self.args.age_keygen, "-o", self.identity], environment=child_environment(),
                         cwd=self.directory)
        del output
        self.recipient = checked([self.args.age_keygen, "-y", self.identity],
            environment=child_environment(), cwd=self.directory).strip()
        os.chmod(self.identity, 0o600)
        self.initialize(resources)
        private_write(self.directory / "operator-settings.json", canonical({
            "schema_version": 1, "issuer_key_id": "sou49-owned-issuer",
            "issuer_seed_hex": self.issuer_seed, "console_admin_token": self.admin,
            "note": "Retained outside database archives; never derive signing trust from restored DB."}) + "\n")
        self.operator_settings_sha256 = sha256(self.directory / "operator-settings.json")
        self.start_console("source")
        self.enroll_agents()
        original_pids = [item["process"].pid for item in self.agents]
        self.stop_console()
        stale = self.timed("stale_backup_seconds", lambda: self.backup("stale-backup"))
        self.start_console("source")
        for item in self.agents:
            self.deploy(item, "allow", 2)
            self.observe(item, 2, "defer")
        self.stop_console()
        current = self.timed("current_backup_seconds", lambda: self.backup("current-backup"))
        source_state = canonical(self.snapshot("source"))
        if self.args.backend == "postgres":
            self.timed("actual_postgres_negative_controls_seconds",
                       lambda: self.postgres_negative_controls(current, source_state))
        recovery_start = time.monotonic()
        self.timed("current_restore_seconds", lambda: self.restore(current, "recovered"))
        self.fixture_call("probe", "recovered")
        self.start_console("recovered")
        self.identities()
        preserved = [self.observe(item, 2, "defer") for item in self.agents]
        self.check("live-agent-processes-preserved-during-console-recovery",
                   original_pids == [item["process"].pid for item in self.agents])
        advanced = []
        for item in self.agents:
            self.deploy(item, "deny", 3)
            advanced.append(self.observe(item, 3, "deny"))
        self.durations["current_recovery_to_signed_ack_seconds"] = round(time.monotonic() - recovery_start, 6)
        self.check("predeclared-recovery-objective-met",
            self.durations["current_recovery_to_signed_ack_seconds"] <= OBJECTIVE["recovery_time_objective_seconds"])
        self.stop_console()
        if self.postgres:
            self.timed("database_restart_seconds", self.postgres.restart)
        else:
            self.check("sqlite-reopen-is-database-restart-boundary", True)
        self.start_console("recovered")
        self.identities()
        for item in self.agents:
            self.observe(item, 3, "deny")
        self.check("database-and-console-restart-preserve-live-policy", True)
        restarted = self.agents[0]
        stop_child(restarted["process"])
        restarted["process"] = self.process([self.args.agent_binary, "serve"], self.directory,
            restarted["environment"], "agent-0-restored-cache")
        restarted["hook_token"] = wait_for("restarted hook credential", lambda:
            (restarted["home"] / ".agentfw/token").read_text().strip())
        self.observe(restarted, 3, "deny")
        self.check("agent-restart-restores-durable-signed-policy", True)
        self.stop_console()
        self.timed("stale_restore_seconds", lambda: self.restore(stale, "stale"))
        self.start_console("stale")
        stale_observations = []
        for item in self.agents:
            self.deploy(item, "allow", 2)
            def rejected(item=item):
                rows = self.api("GET", item["base"] + "/deployments")
                return next((row for row in rows if row["deployment_sequence"] == 2
                             and row["status"] == "rejected"), None)
            wait_for("stale recovery deployment rejection", rejected)
            health = wait_for("actual Agent stale transport state", lambda item=item:
                (lambda value: value if value.get("managed_transport", {}).get("state") == "stale"
                 else None)(self.health(item)))
            self.check("stale-backup-never-rewinds-agent-" + str(item["number"]),
                health["managed_policy"]["deployment_sequence"] == 3 and self.hook(item) == "deny")
            stale_observations.append({"agent": item["number"], "restored_sequence": 2,
                "agent_sequence": 3, "status": "rejected", "transport": "stale",
                "hook_decision": "deny", "recovery_complete": False})
        self.stop_console()
        self.start_console("recovered")
        transport_recovery = []
        for item in self.agents:
            self.observe(item, 3, "deny")
            transport_recovery.append(self.online(item, "after-stale-console-recovery"))
        webhook = {"status": "incomplete", "reason": "owned receiver adapter was not supplied",
                   "production_external_https_delivery_verified": False}
        if self.args.webhook_driver:
            self.stop_console()
            command = [sys.executable, self.args.webhook_driver, "--run", "--private-dir",
                       self.directory, "--fixture-helper", self.args.fixture_helper]
            if self.args.outbox_test_binary:
                command.extend(["--outbox-test-binary", self.args.outbox_test_binary])
            output = checked(command,
                environment=self.fixture_environment("recovered"), cwd=self.directory,
                log=self.directory / "restored-webhook-adapter.log")
            webhook = json.loads(output)
            self.check("restored-owned-receiver-adapter", webhook.get("status") == "passed")
            for item in self.agents:
                wait_for("Agent observed stopped Console during outbox exercise", lambda item=item:
                    self.health(item).get("managed_transport", {}).get("state") == "offline")
            self.start_console("recovered")
            for item in self.agents:
                transport_recovery.append(self.online(item, "after-webhook-console-restart"))
                self.observe(item, 3, "deny")
        self.check("original-source-never-restarted-for-recovered-delivery", self.current_database == "recovered")
        self.fixture_call("probe", "source")
        self.check("complete-original-source-rows-and-sequences-unchanged",
                   source_state == canonical(self.snapshot("source")))
        operator_trust = self.verify_operator_trust()
        return {"preserved_agent_runtime": preserved, "new_signed_deployments": advanced,
            "operator_trust_and_configuration": operator_trust,
            "post_restore_transport_recovery": transport_recovery,
            "stale_backup_negative": {"detected": True, "recovery_complete": False,
                "observations": stale_observations,
                "operator_guidance": "Stop recovered Console; recover a current Console snapshot. Do not reset Agent sequence or signing trust. Reconciliation or a new epoch requires a separate reviewed procedure."},
            "webhook_delivery": webhook,
            "status": "passed" if webhook.get("status") == "passed" else "incomplete"}


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--run", action="store_true", help="Explicitly create owned fixtures and processes")
    result.add_argument("--backend", choices=("sqlite", "postgres"), default="sqlite")
    result.add_argument("--private-dir", type=Path)
    result.add_argument("--retain-private-fixture", action="store_true",
        help="Explicit debugging exception: retain the private fixture and report incomplete cleanup")
    result.add_argument("--output", type=Path, default=ROOT / "target/sou49-recovery-result.json")
    result.add_argument("--console-binary", type=Path, default=ROOT / "target/debug/llm-firewall")
    result.add_argument("--agent-binary", type=Path, default=ROOT / "target/debug/agentfw")
    result.add_argument("--fixture-helper", type=Path, default=ROOT / "target/debug/examples/console-recovery-fixture")
    result.add_argument("--webhook-driver", type=Path)
    result.add_argument("--outbox-test-binary", type=Path)
    for name in ("age", "age-keygen", "psql", "pg-dump", "pg-restore"):
        result.add_argument("--" + name, default=name.replace("-", "_") if name.startswith("pg-") else name)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    print(canonical({"predeclared_objective": OBJECTIVE}), flush=True)
    if not args.run:
        print("No resources created. Build the three binaries, then pass --run explicitly.")
        return 0
    if os.name != "posix":
        raise AcceptanceError("This secret-bearing acceptance fixture requires Unix owner-only permissions.")
    for name in ("console_binary", "agent_binary", "fixture_helper"):
        item = getattr(args, name).resolve(strict=True)
        if not item.is_file():
            raise AcceptanceError("An explicitly selected fixture binary is missing.")
        setattr(args, name, item)
    if args.webhook_driver:
        args.webhook_driver = args.webhook_driver.resolve(strict=True)
    if args.outbox_test_binary:
        args.outbox_test_binary = args.outbox_test_binary.resolve(strict=True)
    previous_umask = os.umask(0o077)
    run, directory, directory_identity = None, None, None
    resources_closed = False
    report_descriptor = None
    started = time.monotonic()
    report = {"schema_version": 1, "task": "SOU-49", "backend": args.backend,
              "predeclared_objective": OBJECTIVE, "status": "failed", "failures": [],
              "cleanup": {"owned_processes_stopped": False,
                          "owned_container_removed": False if args.backend == "postgres" else None,
                          "private_tree_removed": False,
                          "private_fixture_retained": False, "complete": False}}
    try:
        args.output = args.output.absolute()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.parent.resolve() != args.output.parent:
            raise AcceptanceError("Report output must not be redirected through a filesystem alias.")
        # Reserve evidence before starting any process. A previous result must
        # never be overwritten or discovered only after costly runtime work.
        report_descriptor = os.open(args.output,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        if args.private_dir:
            selected_directory = args.private_dir.absolute()
        else:
            target = ROOT / "target"
            target.mkdir(exist_ok=True)
            selected_directory = target / ("sou49-recovery-" + secrets.token_hex(12))
        if args.output.is_relative_to(selected_directory):
            raise AcceptanceError("Public evidence must be outside the disposable private fixture.")
        directory = private_directory(selected_directory, create=True)
        metadata = directory.lstat()
        directory_identity = (metadata.st_dev, metadata.st_ino)
        run = Run(args, directory)
        report["binaries"] = {name: sha256(getattr(args, name))
                              for name in ("console_binary", "agent_binary", "fixture_helper")}
        if args.outbox_test_binary:
            report["binaries"]["outbox_test_binary"] = sha256(args.outbox_test_binary)
        report["source"] = source_metadata(args)
        runtime_error = None
        with ExitStack() as resources:
            try:
                report.update(run.run(resources))
                observed_source = source_metadata(args)
                report["source"]["observed_end_commit"] = observed_source.get("commit")
                report["source"]["observed_end_runtime_inputs_sha256"] = observed_source.get("runtime_inputs_sha256")
                run.check("runtime-source-inputs-and-commit-unchanged-through-run",
                    report["source"].get("commit") == observed_source.get("commit")
                    and report["source"].get("runtime_inputs_sha256") == observed_source.get("runtime_inputs_sha256"))
                observed_binaries = {name: sha256(getattr(args, name)) for name in report["binaries"]}
                run.check("all-selected-runtime-binaries-unchanged-through-run",
                          observed_binaries == report["binaries"])
            except BaseException as error:
                # Close every owned resource before propagating the original
                # failure. A failing child cleanup must not prevent its peers
                # or the database container from receiving cleanup attempts.
                runtime_error = error
            finally:
                child_cleanup_errors = False
                for process in reversed(run.children):
                    try:
                        stop_child(process)
                    except (OSError, subprocess.SubprocessError):
                        child_cleanup_errors = True
                report["cleanup"]["owned_processes_stopped"] = not child_cleanup_errors and all(
                    child.poll() is not None for child in run.children)
                configuration = run.workspace / "firewall.yaml"
                if configuration.is_file():
                    report["configuration_sha256"] = sha256(configuration)
                report["private_fixture_permissions_verified"] = all(
                    not item.is_symlink() and item.stat().st_uid == os.geteuid()
                    and stat.S_IMODE(item.stat().st_mode) == (0o700 if item.is_dir() else 0o600)
                    for item in run.directory.rglob("*"))
                if not report["private_fixture_permissions_verified"]:
                    runtime_error = AcceptanceError("Private fixture artifact permissions were not preserved.")
                if not report["cleanup"]["owned_processes_stopped"]:
                    runtime_error = AcceptanceError("Not all owned processes stopped cleanly.")
        resources_closed = True
        if args.backend == "postgres":
            report["cleanup"]["owned_container_removed"] = True
        if runtime_error is not None:
            raise runtime_error
    except Exception as error:
        report["status"] = "failed"
        report["failures"].append(str(error) if isinstance(error, AcceptanceError)
                                  else "A fixture operation failed; private diagnostic details withheld.")
    finally:
        if run:
            report["checks"] = run.checks
            report["durations_seconds"] = run.durations
        if directory is not None and directory_identity is not None:
            if args.retain_private_fixture:
                report["cleanup"]["private_fixture_retained"] = True
                if report["status"] == "passed":
                    report["status"] = "incomplete"
            else:
                try:
                    cleanup_owned_tree(directory, directory_identity)
                    report["cleanup"]["private_tree_removed"] = True
                except (AcceptanceError, OSError):
                    report["status"] = "failed"
                    report["failures"].append("Owned private fixture cleanup failed; inspect the selected private directory.")
        report["cleanup"]["complete"] = (report["cleanup"]["owned_processes_stopped"]
            and resources_closed and report["cleanup"]["private_tree_removed"]
            and (args.backend != "postgres" or report["cleanup"]["owned_container_removed"]))
        report["duration_seconds"] = round(time.monotonic() - started, 6)
        try:
            if report_descriptor is not None:
                # Only sanitized outcomes survive default private cleanup.
                with os.fdopen(report_descriptor, "w", encoding="utf-8") as stream:
                    json.dump(report, stream, sort_keys=True, indent=2)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
        finally:
            os.umask(previous_umask)
    print(canonical({"status": report["status"], "checks": len(report.get("checks", [])),
                     "failures": len(report["failures"]), "report": str(args.output)}), flush=True)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
