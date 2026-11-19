#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Qualify the production Compose closure on a disposable owned local stack.

Uses the existing identity gate, staging acceptance and dependency-failure drill.
No provider requests, image pulls/builds, or publication occur. Requires Docker
and PowerShell 7. Only this invocation's random Compose project is removed.
"""

import argparse
import base64
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


def public_failure(error):
    if isinstance(error, QualificationError):
        return str(error)
    if (error.__class__.__module__ == "production_compose"
            and error.__class__.__name__ == "ClosureError"):
        # The gate deliberately exposes only fixed public categories.
        return "closure_" + str(error)
    return "qualification_failed"


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
        "POSTGRES_PASSWORD", "REDIS_PASSWORD", "LLM_FW_ADMIN_TOKEN")}
    # Gateway encryption/signing contracts require unpadded base64url keys
    # decoding to exactly 32 bytes; ordinary random password text is invalid.
    for name in ("LLM_FW_OIDC_STATE_KEY", "LLM_FW_WEBHOOK_SIGNING_KEY"):
        values[name] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
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
        if not isinstance(endpoint, str):
            return False
        # Named pipes can also address a remote Windows host over UNC. Only
        # the explicit local-machine authority belongs to this owned drill.
        return (endpoint.startswith("unix:///")
                or re.fullmatch(r"npipe:////\./pipe/[A-Za-z0-9_.-]+", endpoint) is not None)
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


def shell(gate, service, program):
    return gate.compose(["exec", "-T", service, "sh", "-c", program]).strip()


def postgres_program(sql):
    # SQL is an application-owned constant/hex witness, never a CLI argument.
    require("'" not in sql and "\n" not in sql, "unsafe_fixture_sql")
    # The application uses the Compose network. Loopback can have a separate
    # initdb trust rule and would not test the application's password boundary.
    return ('PGPASSWORD="$POSTGRES_PASSWORD" psql -h postgres -w '
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


def exercise_operations(gate, module, report):
    """Exercise the operator commands against the same fresh owned stack."""
    docker = gate.docker

    class AuditedDocker:
        def __init__(self):
            self.interrupt = False
            self.audit_status = False

        def run(self, args, **kwargs):
            if self.audit_status:
                require(args[0] in {"version", "exec"}
                        or args[:2] in (["context", "inspect"], ["container", "inspect"],
                                        ["image", "inspect"], ["network", "ls"], ["network", "inspect"],
                                        ["volume", "ls"], ["volume", "inspect"])
                        or (args[0] == "compose" and (args[-3:] == ["config", "--format", "json"]
                                                      or args[-4:-1] == ["ps", "--all", "--quiet"])),
                        "status_attempted_docker_mutation")
            result = docker.run(args, **kwargs)
            if self.interrupt and args[:2] == ["container", "start"]:
                self.interrupt = False
                raise module.ClosureError("owned_restart_interruption")
            return result

        def json(self, args, **kwargs):
            return module.decode(self.run(args, **kwargs))

        def require_local(self):
            docker.require_local()

    def status():
        audited.audit_status = True
        try:
            return gate.execute("status")
        finally:
            audited.audit_status = False

    audited = AuditedDocker()
    gate.docker = audited
    witness = None
    try:
        first = status()
        require(all(row["state"] == "healthy" and row["probe"] in {"ready", "available"}
                    for row in first["services"].values()), "status_healthy_stack_not_verified")
        closure = first["closure"]
        report["operations_status"] = {"healthy": first["services"], "closure": closure}
        report["checks"].append("observed-healthy-stack-and-authenticated-readiness")

        policy = gate.policy_snapshot
        original = policy.read_bytes()
        try:
            policy.write_bytes(b"# owned checkpoint changed policy\n")
            try:
                status()
            except module.ClosureError as error:
                require(str(error) == "staged_policy_changed", "status_wrong_policy_failure")
            else:
                raise QualificationError("status_accepted_changed_policy")
        finally:
            policy.write_bytes(original)
        report["checks"].append("read-only-status-refuses-changed-policy")

        owner = gate.project + "-witness"
        witness = docker.run(["create", "--pull", "never", "--network", "none", "--tmpfs", "/data",
                              "--label", "com.docker.compose.project=" + owner, "--entrypoint", "sh",
                              gate.images["redis"]["reference"], "-c", "sleep 600"]).strip()
        require(module.CONTAINER_ID.fullmatch(witness) is not None, "invalid_unrelated_witness_id")
        docker.run(["container", "start", witness])
        before = docker.json(["container", "inspect", witness])[0]["State"]["StartedAt"]

        docker.run(["container", "stop", "--time", "10", closure["containers"]["redis"]])
        outage = status()
        require(outage["closure"] == closure and outage["services"]["redis"]["state"] == "stopped"
                and outage["services"]["firewall"]["probe"] == "not_ready", "status_dependency_outage_not_observed")
        report["operations_status"]["dependency_outage"] = outage["services"]
        report["checks"].append("read-only-status-distinguishes-stopped-redis-and-gateway-not-ready")

        stop = gate.execute("stop")
        require(stop["phase"] == "preview" and stop["closure"] == closure, "stop_preview_wrong_closure")
        result = gate.execute("stop", confirmation=stop["confirmation"])
        require(result["closure"] == closure and set(result["services"].values()) == {"stopped"},
                "stop_did_not_preserve_closure")
        report["operations_status"]["stopped"] = status()["services"]
        report["checks"].append("confirmed-stop-retains-exact-containers-network-and-volumes")

        restart = gate.execute("restart")
        audited.interrupt = True
        try:
            gate.execute("restart", confirmation=restart["confirmation"])
        except module.ClosureError as error:
            require(str(error) == "owned_restart_interruption" and gate.recovery_required,
                    "restart_recovery_not_recorded")
        else:
            raise QualificationError("restart_interruption_not_triggered")
        result = gate.execute("restart", confirmation=restart["confirmation"])
        require(result["closure"] == closure and set(result["services"].values()) == {"healthy"},
                "restarted_closure_changed_or_unhealthy")
        recovered = status()
        require(recovered["closure"] == closure and recovered["services"] == first["services"],
                "status_did_not_verify_recovery")
        report["operations_status"]["recovered"] = recovered["services"]
        row = docker.json(["container", "inspect", witness])[0]
        require(row["State"]["Running"] and row["State"]["StartedAt"] == before,
                "unrelated_project_was_interrupted")
        report["checks"].append("interrupted-restart-resumes-exact-closure-and-preserves-unrelated-project")
    finally:
        gate.docker = docker
        if witness and module.CONTAINER_ID.fullmatch(witness):
            row = docker.json(["container", "inspect", witness])[0]
            require(row["Id"] == witness and row["Config"]["Labels"]["com.docker.compose.project"] == owner,
                    "unrelated_witness_cleanup_owner_mismatch")
            docker.run(["container", "rm", "--force", witness])


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

        def status_refuses(category):
            try:
                gate.execute("status")
            except module.ClosureError as error:
                require(str(error) == category, "unexpected_status_refusal")
            else:
                raise QualificationError("status_accepted_unverified_closure")

        foreign = docker.run(["network", "create", "--label", "com.docker.compose.project=" + project + "-foreign",
                              project + "_default"]).strip()
        require(module.CONTAINER_ID.fullmatch(foreign) is not None, "invalid_foreign_network_id")
        try:
            status_refuses("project_network_identity_or_owner_mismatch")
            require(not safe_project_containers(docker, project), "foreign_network_refusal_created_container")
            checks.append("status-refuses-foreign-project-network-without-creating-resources")
        finally:
            docker.run(["network", "rm", foreign])

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
                observer = module.ProductionCompose(ROOT, project, env_file, args.gateway_image_id, docker)
                try:
                    observer.execute("status")
                except module.ClosureError as error:
                    require(str(error) == "container_identity_or_owner_mismatch", "wrong_container_refusal_category")
                else:
                    raise QualificationError("wrong_container_image_not_refused")
                require(safe_project_containers(docker, project) == [wrong_id[:12]]
                        or safe_project_containers(docker, project) == [wrong_id],
                        "unexpected_container_created_during_refusal")
                docker.run(["rm", wrong_id])
                checks.append("wrong-owned-container-image-refused-without-replacement")
            report["closure"] = gate.execute("check")
            for action in ("preflight", "migrate", "start"):
                report["stage"] = action
                gate.execute(action)
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
                wrong_password = ('if PGPASSWORD=owned-invalid-password psql -h postgres -w '
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
            exercise_operations(gate, module, report)
            with gate.freeze():
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
            except Exception as error:
                report["reason"] = public_failure(error)
            json.dump(report, output, indent=2)
            output.write("\n")
    except OSError:
        print("qualification output unavailable", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
