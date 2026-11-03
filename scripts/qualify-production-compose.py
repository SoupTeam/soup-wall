#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Qualify the production Compose closure on a disposable owned local stack.

Uses the existing identity gate, staging acceptance and dependency-failure drill.
No provider requests, image pulls/builds, or publication occur. Requires Docker
and PowerShell 7. Only this invocation's random Compose project is removed.
"""

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
SOURCE = re.compile(r"[0-9a-f]{40}\Z")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_RESPONSE = 262144


class QualificationError(Exception):
    """Fixed diagnostic categories only; subprocess bodies are never emitted."""


def require(condition, category):
    if not condition:
        raise QualificationError(category)


def load_gate():
    spec = importlib.util.spec_from_file_location("production_compose", ROOT / "scripts/production-compose.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def clean_source(expected):
    try:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                                       stderr=subprocess.DEVNULL, timeout=10).strip()
        status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"],
                                         cwd=ROOT, text=True, stderr=subprocess.DEVNULL, timeout=10)
        tracked = subprocess.check_output(["git", "ls-files", "--error-unmatch",
                                          "scripts/qualify-production-compose.py"], cwd=ROOT,
                                         text=True, stderr=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.SubprocessError):
        raise QualificationError("source_identity_unavailable") from None
    require(head == expected and not status.strip() and bool(tracked.strip()), "source_not_exact_clean_commit")
    return head


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(path, *, method="GET", document=None, token=None):
    headers = {}
    if token is not None:
        headers["x-llm-firewall-admin-token"] = "Bearer " + token
    payload = None
    if document is not None:
        payload = json.dumps(document).encode()
        headers["Content-Type"] = "application/json"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    call = urllib.request.Request("http://127.0.0.1:8080" + path, payload, headers, method=method)
    try:
        response = opener.open(call, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, urllib.error.URLError):
        raise QualificationError("loopback_request_failed") from None
    with response:
        body = response.read(MAX_RESPONSE + 1)
        require(len(body) <= MAX_RESPONSE, "loopback_response_too_large")
        try:
            parsed = json.loads(body)
        except (ValueError, UnicodeError):
            parsed = None
        return response.status, parsed


def fixture_environment():
    values = {name: secrets.token_hex(24) for name in (
        "POSTGRES_PASSWORD", "REDIS_PASSWORD", "LLM_FW_ADMIN_TOKEN",
        "LLM_FW_OIDC_STATE_KEY", "LLM_FW_WEBHOOK_SIGNING_KEY")}
    values.update(POSTGRES_USER="owned_compose", POSTGRES_DB="owned_compose")
    values["LLM_FW_POSTGRES_URL"] = ("postgres://owned_compose:" + values["POSTGRES_PASSWORD"]
                                      + "@postgres:5432/owned_compose?sslmode=disable")
    values["LLM_FW_REDIS_URL"] = "redis://:" + values["REDIS_PASSWORD"] + "@redis:6379/0"
    return values


def safe_project_containers(docker, project):
    """Refuse cleanup if any returned container is outside the owned project."""
    require(re.fullmatch(r"soup-compose-qual-[0-9a-f]{16}", project) is not None, "unsafe_cleanup_project")
    ids = docker.run(["ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + project]).split()
    for identifier in ids:
        require(re.fullmatch(r"[0-9a-f]{12,64}", identifier) is not None, "invalid_owned_container_id")
        rows = docker.json(["container", "inspect", identifier])
        require(isinstance(rows, list) and len(rows) == 1, "owned_container_inspection_failed")
        labels = rows[0].get("Config", {}).get("Labels", {})
        require(labels.get("com.docker.compose.project") == project
                and labels.get("com.docker.compose.service") in {"postgres", "redis", "firewall"},
                "unexpected_cleanup_owner")
    return ids


def require_local_daemon(docker):
    def local(endpoint):
        return isinstance(endpoint, str) and endpoint.startswith(("unix:///", "npipe:////"))
    if docker.environment.get("DOCKER_HOST"):
        require(local(docker.environment["DOCKER_HOST"]), "qualification_requires_local_docker")
    contexts = docker.json(["context", "inspect"])
    require(isinstance(contexts, list) and len(contexts) == 1
            and local(contexts[0].get("Endpoints", {}).get("docker", {}).get("Host")),
            "qualification_requires_local_docker")


def cleanup_owned(docker, project, compose_args, frozen):
    # Cleanup uses the already verified in-memory configuration, even when a
    # source drift prevents the startup gate from accepting further commands.
    safe_project_containers(docker, project)
    docker.run([*compose_args, "down", "--volumes", "--remove-orphans", "--timeout", "10"], stdin=frozen)
    require(not safe_project_containers(docker, project), "owned_container_cleanup_incomplete")


def wait_healthy(gate, module):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            gate.verify_containers(gate.images)
            return
        except module.ClosureError as error:
            if str(error) != "service_not_healthy":
                raise
        time.sleep(2)
    raise QualificationError("restarted_stack_not_healthy")


def shell(gate, service, program):
    return gate.compose(["exec", "-T", service, "sh", "-c", program]).strip()


def postgres_program(sql):
    # SQL is an application-owned constant/hex witness, never a CLI argument.
    require("'" not in sql and "\n" not in sql, "unsafe_fixture_sql")
    return ('PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -w '
            '-U "$POSTGRES_USER" -d "$POSTGRES_DB" -qAt -v ON_ERROR_STOP=1 -c \'' + sql + "'")


def existing_drill(module, values, project, gateway, platform):
    environment = module.docker_environment()
    environment.update(values, COMPOSE_PROJECT_NAME=project, SOUP_WALL_IMAGE=gateway,
                       SOUP_WALL_PLATFORM=platform)
    pwsh = shutil.which("pwsh")
    require(pwsh is not None, "powershell7_unavailable")
    try:
        result = subprocess.run([pwsh, "-NoProfile", "-File", str(ROOT / "scripts/local-compose-drill.ps1"),
                                 "-ComposeFile", str(ROOT / "deploy/docker-compose.production.yaml"),
                                 "-BaseUrl", "http://127.0.0.1:8080"], cwd=ROOT, env=environment,
                                capture_output=True, text=True, timeout=420, check=False)
    except (OSError, subprocess.SubprocessError):
        raise QualificationError("existing_dependency_drill_unavailable") from None
    require(result.returncode == 0 and len(result.stdout) <= MAX_RESPONSE,
            "existing_dependency_drill_failed")
    try:
        document = json.loads(result.stdout)
        phases = [row.get("phase") for row in document["phases"]]
    except (ValueError, KeyError, TypeError):
        raise QualificationError("existing_dependency_drill_invalid_output") from None
    require(document.get("status") == "passed" and phases == [
        "BaselineAcceptance", "PostgresDown", "Baseline", "RedisDown", "Recovered"],
        "existing_dependency_drill_incomplete")
    return phases


def qualify(args, report):
    clean_source(args.expected_commit)
    module = load_gate()
    docker = module.Docker()
    require_local_daemon(docker)
    image = docker.json(["image", "inspect", args.gateway_image_id])
    require(len(image) == 1 and image[0].get("Id") == args.gateway_image_id,
            "gateway_image_identity_mismatch")
    label = image[0].get("Config", {}).get("Labels", {}).get("org.opencontainers.image.revision")
    require(label == args.gateway_source_commit, "gateway_source_label_mismatch")
    # Labels identify the supplied owned build; they do not attest compilation.
    report["gateway"] = {"image_id": args.gateway_image_id, "observed_source_label": label,
                         "build_attestation": "not_asserted"}
    report["source_commit"] = args.expected_commit
    checks = report["checks"]
    values = fixture_environment()
    with tempfile.TemporaryDirectory(prefix="soup-compose-owned-") as temporary:
        env_file = Path(temporary) / "fixture.env"
        descriptor = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write("".join(f"{key}={value}\n" for key, value in values.items()))
        project = "soup-compose-qual-" + secrets.token_hex(8)
        report["project"] = project
        gate = module.ProductionCompose(ROOT, project, env_file, args.gateway_image_id, docker)
        # Prove a real locally missing image is refused before any project starts.
        absent = "sha256:" + secrets.token_hex(32)
        missing_gate = module.ProductionCompose(ROOT, project, env_file, absent, docker)
        refused = False
        try:
            missing_gate.execute("start")
        except module.ClosureError as error:
            refused = str(error) == "docker_command_failed"
        require(refused and not safe_project_containers(docker, project), "missing_image_did_not_refuse")
        checks.append("missing-image-refused-before-container-creation")
        cleanup_needed = False
        cleanup_config = None
        try:
            with gate.freeze():
                require(not safe_project_containers(docker, project), "project_already_exists")
                cleanup_config = gate.frozen
                # A real owned container with valid Compose labels but the wrong
                # image must not be silently recreated by the startup wrapper.
                cleanup_needed = True
                wrong_id = docker.run(["create", "--pull", "never", "--name", project + "-wrong",
                                       "--label", "com.docker.compose.project=" + project,
                                       "--label", "com.docker.compose.service=postgres",
                                       "--label", "com.docker.compose.oneoff=False",
                                       "--label", "com.docker.compose.config-hash=owned-wrong-image-control",
                                       "--entrypoint", "/bin/true", args.gateway_image_id]).strip()
                refused = False
                try:
                    gate.verify_containers(gate.images, required=False)
                except module.ClosureError as error:
                    refused = str(error) == "container_identity_or_owner_mismatch"
                require(refused, "wrong_container_image_not_refused")
                require(safe_project_containers(docker, project) == [wrong_id[:12]]
                        or safe_project_containers(docker, project) == [wrong_id],
                        "unexpected_container_created_during_refusal")
                docker.run(["rm", wrong_id])
                checks.append("wrong-owned-container-image-refused-without-replacement")
            report["closure"] = gate.execute("check")
            gate.execute("preflight")
            gate.execute("migrate")
            gate.execute("start")
            checks.append("verified-images-preflight-migrate-and-healthy-start")
            status, _ = request("/admin/v1/tenants")
            require(status == 401, "admin_authentication_not_enforced")
            status, document = request("/admin/v1/tenants", method="POST",
                                       document={"name": "Owned Compose qualification"},
                                       token=values["LLM_FW_ADMIN_TOKEN"])
            require(status == 201 and isinstance(document, dict) and isinstance(document.get("id"), str),
                    "authenticated_postgres_control_plane_failed")
            tenant = document["id"]
            checks.append("admin-refusal-and-authenticated-postgres-mutation")
            marker = secrets.token_hex(16)
            with gate.freeze():
                wrong_password = ('if PGPASSWORD=owned-invalid-password psql -h 127.0.0.1 -w '
                                  '-U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT 1" '
                                  '> /dev/null 2>&1; then exit 19; fi; ')
                require(shell(gate, "postgres", wrong_password + postgres_program("SELECT 1")) == "1",
                        "postgres_password_control_failed")
                sql = ("CREATE TABLE compose_qualification_probe (value text NOT NULL); "
                       "INSERT INTO compose_qualification_probe VALUES (chr(120)); "
                       "SELECT value FROM compose_qualification_probe")
                require(shell(gate, "postgres", postgres_program(sql)) == "x", "postgres_witness_write_failed")
                redis_write = ('bad=$(REDISCLI_AUTH=owned-invalid-password redis-cli --no-auth-warning '
                               '--raw PING 2>/dev/null); [ "$bad" != PONG ] || exit 19; '
                               'export REDISCLI_AUTH="$REDIS_PASSWORD"; '
                               f'redis-cli --no-auth-warning --raw SET compose:qualification {marker} > /dev/null; '
                               'redis-cli --no-auth-warning --raw GET compose:qualification')
                require(shell(gate, "redis", redis_write) == marker, "redis_auth_or_write_failed")
                checks.append("postgres-and-redis-authenticated-data-witnesses")
                gate.compose(["restart", "postgres", "redis", "firewall"])
                wait_healthy(gate, module)
                require(shell(gate, "postgres", postgres_program("SELECT value FROM compose_qualification_probe"))
                        == "x", "postgres_data_lost_after_restart")
                require(shell(gate, "redis", 'REDISCLI_AUTH="$REDIS_PASSWORD" redis-cli --no-auth-warning '
                              '--raw GET compose:qualification') == marker, "redis_data_lost_after_restart")
            status, document = request("/admin/v1/tenants", token=values["LLM_FW_ADMIN_TOKEN"])
            require(status == 200 and isinstance(document, list)
                    and any(row.get("id") == tenant for row in document), "tenant_lost_after_restart")
            checks.append("three-container-restart-retains-postgres-redis-and-tenant-data")
            report["existing_drill_phases"] = existing_drill(module, values, project,
                                                            args.gateway_image_id, gate.platform)
            checks.append("existing-staging-and-postgres-redis-outage-recovery-drill")
            with gate.freeze():
                gate.verify_containers(gate.images)
            clean_source(args.expected_commit)
        finally:
            if cleanup_needed:
                try:
                    cleanup_owned(docker, project, gate._args(), cleanup_config)
                    report["owned_stack_cleanup"] = "passed"
                except (module.ClosureError, QualificationError) as error:
                    report["cleanup_reason"] = str(error)
                    raise QualificationError("owned_stack_cleanup_failed") from None
        # Never retain even generated fixture credentials in an observation.
        serialized = json.dumps(report)
        require(all(secret not in serialized for key, secret in values.items()
                    if key.endswith("PASSWORD") or key.startswith("LLM_FW_")), "unsafe_report_content")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True, help="create and remove an owned local stack")
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--gateway-source-commit", required=True)
    parser.add_argument("--gateway-image-id", required=True)
    parser.add_argument("--output", type=Path, required=True, help="new sanitized report path")
    args = parser.parse_args(argv)
    report = {"format": "sw-production-compose-qualification/1", "status": "failed", "checks": [],
              "checked_at": datetime.now(timezone.utc).isoformat(), "provider_requests": 0,
              "scope": "owned-local-docker-stack-not-release-or-native-platform-approval"}
    if (not SOURCE.fullmatch(args.expected_commit) or not SOURCE.fullmatch(args.gateway_source_commit)
            or not IMAGE.fullmatch(args.gateway_image_id)):
        parser.error("full source revisions and a sha256 image ID are required")
    # Reserve the output before any mutation. Existing attempts are preserved.
    try:
        with args.output.open("x", encoding="utf-8") as output:
            try:
                qualify(args, report)
                report["status"] = "passed"
            except QualificationError as error:
                report["reason"] = str(error)
            except Exception:
                report["reason"] = "qualification_failed"
            json.dump(report, output, indent=2)
            output.write("\n")
    except OSError:
        print("qualification output unavailable", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
