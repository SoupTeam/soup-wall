#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Genuine pinned scim2-client against an owned real Soup Wall HTTP listener."""
import argparse
from contextlib import ExitStack
import datetime as dt
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import traceback

ROOT = Path(__file__).resolve().parents[1]

def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def run(args):
    from httpx2 import Client
    from scim2_client.engines.httpx2 import SyncSCIMClient
    from scim2_models import SearchRequest
    import scim2_client
    report = {"backend": args.backend, "passed": False, "cleanup_passed": False, "checks": [],
              "started_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "fixture_binary_sha256": digest(args.fixture),
              "packages": {name: importlib.metadata.version(name) for name in
                           ("scim2-client", "scim2-models", "httpx2", "pydantic")},
              "source_sha256": {name: digest(ROOT / name) for name in
                    ("scripts/scim-directory-acceptance.py", "crates/proxy/src/scim.rs",
                     "crates/proxy/src/tenant_store.rs", "crates/proxy/src/tenant_store/postgres.rs",
                     "crates/proxy/src/lib.rs", "crates/proxy/examples/scim-directory-fixture.rs", "Cargo.lock",
                     "scripts/scim-directory-requirements.txt", ".github/workflows/scim-directory.yml",
                     "scripts/keycloak-oidc-acceptance.py", "scripts/keycloak-saml-acceptance.py")},
              "limitations": ["Synthetic directory only; no customer IdP certification",
                              "Owned loopback HTTP client/server; PostgreSQL uses verified fixture TLS",
                              "User DELETE retains the existing deactivation/tombstone contract",
                              "Equality values are case-sensitive without normalization on both stores"]}
    package_root = Path(scim2_client.__file__).parent
    report["client_source_sha256"] = hashlib.sha256("\n".join(str(p.relative_to(package_root)) + ":" + digest(p) for p in sorted(package_root.rglob("*.py"))).encode()).hexdigest()
    def publish():
        args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    def check(name, condition):
        report["checks"].append({"name": name, "passed": bool(condition)})
        publish()
        print(json.dumps(report["checks"][-1]), flush=True)
        if not condition:
            raise RuntimeError(name)
    child = None
    directory = None
    try:
        check("pinned-client", report["packages"]["scim2-client"] == "0.13.1")
        with ExitStack() as stack:
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="soup-scim-")))
            os.chmod(directory, 0o700)
            env = {key: value for key, value in os.environ.items()
                   if key.upper() in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "LANG")}
            env["RUST_LOG"] = "off"
            target = str(directory / "gateway.sqlite")
            if args.backend == "postgres":
                spec = importlib.util.spec_from_file_location("oidc_fixture", ROOT / "scripts/keycloak-oidc-acceptance.py")
                helpers = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(helpers)
                ca, (cert, key), _ = helpers.vendor.certificate_files(directory)
                env["LLM_FW_POSTGRES_CA_CERT_FILE"] = str(ca)
                database = helpers.FixtureDatabase(directory, env, stack, postgres=True, cert=cert, key=key)
                check("fresh-postgres-has-no-tables", database.sql("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'") == "0")
                target = database.bootstrap_target()
                report["postgres_image"] = helpers.POSTGRES_IMAGE
            log = stack.enter_context((directory / "fixture.log").open("wb"))
            child = subprocess.Popen([str(args.fixture), target], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=log, text=True, env=env, cwd=directory)
            def stop():
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=10)
                child.stdin.close()
                child.stdout.close()
            stack.callback(stop)
            lines = queue.Queue()
            def read_lines():
                for line in child.stdout:
                    lines.put(line)
                lines.put(None)
            reader = threading.Thread(target=read_lines, daemon=True)
            reader.start()
            startup = lines.get(timeout=45)
            if startup is None:
                raise RuntimeError("fixture exited before readiness")
            credentials = json.loads(startup)
            if args.backend == "postgres":
                check("explicit-migrations-and-verified-postgres-tls", database.sql("SELECT COUNT(*) FROM pg_stat_ssl WHERE ssl AND pid IN (SELECT pid FROM pg_stat_activity WHERE application_name = 'llm-firewall-control-plane')") != "0")
            check("owned-loopback-listener", credentials["base_url"].startswith("http://127.0.0.1:"))
            http = stack.enter_context(Client(base_url=credentials["base_url"],
                headers={"Authorization": "Bearer " + credentials["token"]}, timeout=10, trust_env=False, follow_redirects=False))
            other_http = stack.enter_context(Client(base_url=credentials["base_url"],
                headers={"Authorization": "Bearer " + credentials["other_token"]}, timeout=10, trust_env=False, follow_redirects=False))
            scim = SyncSCIMClient(http, raise_scim_errors=False)
            other = SyncSCIMClient(other_http, raise_scim_errors=False)
            scim.discover()
            other.discover()
            User = scim.get_resource_model("User")
            Group = scim.get_resource_model("Group")
            check("client-discovery", User is not None and Group is not None)
            def create_user(client, name):
                return client.create(User(user_name=name, external_id=name, display_name=name, active=True))
            alice = create_user(scim, "Alice")
            bob = create_user(scim, "Bob")
            foreign = create_user(other, "Alice")
            check("client-create-users", bool(alice.id and bob.id and foreign.id and foreign.id != alice.id))
            duplicate = create_user(scim, "Alice")
            check("duplicate-create-refused", int(duplicate.status) in (400, 409))
            def lookup(model, expression, count=100, start=1, client=scim):
                return client.query(model, query_parameters=SearchRequest(filter=expression, count=count, start_index=start))
            for field, value in (("id", alice.id), ("userName", "Alice"), ("externalId", "Alice")):
                found = lookup(User, field + " eq " + json.dumps(value))
                check("users-filter-" + field, found.total_results == 1 and found.resources[0].id == alice.id)
            check("case-sensitive-values", lookup(User, 'userName eq "alice"').total_results == 0)
            check("count-zero", lookup(User, 'userName eq "Alice"', count=0).total_results == 1)
            check("offset-after-match", lookup(User, 'userName eq "Alice"', start=2).resources == [])
            check("foreign-user-hidden", lookup(User, 'id eq ' + json.dumps(foreign.id)).total_results == 0)
            check("literal-sql-looking-value", lookup(User, 'userName eq "\' OR 1=1 --"').total_results == 0)
            for i, expression in enumerate(('userName co "A"', 'id eq "x" or id eq "y"', 'id eq 4', 'roles eq "Owner"')):
                error = lookup(User, expression)
                check(f"invalid-filter-{i}", int(error.status) == 400 and str(error.scim_type) == "invalidFilter")
            def patch(model, identifier, ops, client=scim):
                # The independent client serializes/dispatches the actual PATCH and validates its response.
                # Raw request input permits testing deliberately malformed/unsupported operations.
                return client.modify(model, identifier, {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": ops}, check_request_payload=False)
            updated = patch(User, alice.id, [{"op": "replace", "value": {"active": False, "displayName": "Changed"}}])
            check("pathless-user-deactivate", updated.active is False and updated.display_name == "Changed")
            updated = patch(User, alice.id, [{"op": "replace", "path": "active", "value": True}])
            check("user-reactivate", updated.active is True)
            error = patch(User, alice.id, [{"op": "replace", "path": "active", "value": False},
                                          {"op": "replace", "path": "roles", "value": ["Owner"]}])
            check("malformed-user-patch-atomic", int(error.status) == 400 and scim.query(User, alice.id).active is True)
            group = scim.create(Group(external_id="team", display_name="Team", members=[{"value": alice.id}]))
            check("client-create-group", bool(group.id))
            for field, value in (("id", group.id), ("displayName", "Team"), ("externalId", "team")):
                found = lookup(Group, field + " eq " + json.dumps(value))
                check("groups-filter-" + field, found.total_results == 1 and found.resources[0].id == group.id)
            def members(group):
                return sorted(m.value for m in (group.members or []))
            for attempt in range(2):
                updated = patch(Group, group.id, [{"op": "add", "path": "members", "value": [{"value": bob.id}]}])
                check(f"add-member-retry-{attempt}", members(updated) == sorted([alice.id, bob.id]))
            for attempt in range(2):
                updated = patch(Group, group.id, [{"op": "replace", "value": {"displayName": "Updated", "members": [{"value": bob.id}]}}])
                check(f"replace-retains-existing-member-{attempt}", members(updated) == [bob.id] and updated.display_name == "Updated")
            for attempt in range(2):
                updated = patch(Group, group.id, [{"op": "remove", "path": 'members[value eq ' + json.dumps(bob.id) + ']'}])
                check(f"filtered-remove-retry-{attempt}", members(updated) == [])
            before = scim.query(Group, group.id)
            error = patch(Group, group.id, [{"op": "replace", "path": "displayName", "value": "MustNotPersist"},
                                           {"op": "add", "path": "members", "value": [{"value": foreign.id}]}])
            after = scim.query(Group, group.id)
            check("foreign-member-patch-atomic", int(error.status) in (400, 404) and after.display_name == before.display_name and members(after) == members(before))
            error = patch(Group, group.id, [{"op": "replace", "path": "displayName", "value": "MustNotPersist"},
                                           {"op": "replace", "path": "admin", "value": True}])
            check("malformed-group-patch-atomic", int(error.status) == 400 and scim.query(Group, group.id).display_name == before.display_name)
            check("foreign-group-hidden", int(other.query(Group, group.id).status) == 404)
            scim.delete(Group, group.id)
            check("group-delete", int(scim.query(Group, group.id).status) == 404)
            scim.delete(User, alice.id)
            check("user-delete-deactivates", scim.query(User, alice.id).active is False)
            child.stdin.write("revoke\n"); child.stdin.flush()
            check("credential-revoked", lines.get(timeout=10).strip() == "revoked")
            check("revoked-client-refused", int(scim.query(User, bob.id).status) == 401)
            check("other-organization-unaffected", other.query(User, foreign.id).id == foreign.id)
            child.stdin.write("stop\n"); child.stdin.flush()
            child.wait(timeout=15)
            check("fixture-stopped", child.returncode == 0)
        report["cleanup_passed"] = not directory.exists() and child.poll() is not None
        check("owned-cleanup", report["cleanup_passed"])
        report["passed"] = True
    except Exception as error:
        # Never emit request/response exception strings: they may contain credentials or directory data.
        report["failure_type"] = type(error).__name__
        report["failure_frames"] = [{"file": Path(frame.filename).name, "line": frame.lineno, "function": frame.name} for frame in traceback.extract_tb(error.__traceback__)[-6:]]
        report["cleanup_passed"] = bool(directory and not directory.exists() and (child is None or child.poll() is not None))
    publish()
    return 0 if report["passed"] else 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=("sqlite", "postgres"), required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.fixture = args.fixture.resolve(strict=True)
    args.out = args.out.resolve()
    if args.out.exists():
        parser.error("use a new evidence output path to preserve earlier failures")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    raise SystemExit(run(args))
