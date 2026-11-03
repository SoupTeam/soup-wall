#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the existing production Compose template from verified local images.

No command pulls or builds images. Expanded configuration and Docker inspection
responses remain in memory; diagnostics deliberately omit subprocess output.
"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
LOCK = "deploy/production-images.lock.json"
IMPLEMENTATION = "scripts/production-compose.py"
INPUTS = ("deploy/docker-compose.production.yaml", "deploy/production.firewall.yaml",
          "deploy/Dockerfile", "policies/default.yaml")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
PROJECT = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PLATFORMS = {"linux/amd64", "linux/arm64"}
MAX_BYTES = 2 * 1024 * 1024


class ClosureError(Exception):
    """Only fixed public categories, never external input or secret values."""


def fail(category):
    raise ClosureError(category)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def bounded_file(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        fail("unsafe_or_missing_input")
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        fail("input_too_large")
    # Git may check text out with CRLF. The lock binds canonical LF bytes.
    return data.replace(b"\r\n", b"\n")


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate_json_key")
        result[key] = value
    return result


def decode(data):
    try:
        return json.loads(data, object_pairs_hook=no_duplicates)
    except (ValueError, TypeError, UnicodeError):
        fail("invalid_json")


def docker_environment():
    # Preserve Docker's selected endpoint/credentials, not Compose overrides,
    # provider keys, deployment secrets, or inherited dotenv variables.
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "HOME", "USERPROFILE", "APPDATA",
               "LOCALAPPDATA", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL",
               "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY",
               "DOCKER_CERT_PATH", "SSH_AUTH_SOCK"}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


class Docker:
    def __init__(self):
        self.environment = docker_environment()

    def run(self, args, *, stdin=None, environment=None, timeout=180):
        env = dict(self.environment)
        env.update(environment or {})
        try:
            result = subprocess.run(["docker", *args], input=stdin, text=True,
                                    capture_output=True, env=env, timeout=timeout,
                                    check=False)
        except (OSError, subprocess.TimeoutExpired):
            fail("docker_unavailable_or_timed_out")
        # Never surface raw errors: Compose can quote secret-bearing commands.
        if result.returncode:
            fail("docker_command_failed")
        if len(result.stdout.encode("utf-8")) > MAX_BYTES:
            fail("docker_output_too_large")
        return result.stdout

    def json(self, args, **kwargs):
        return decode(self.run(args, **kwargs))


class ProductionCompose:
    def __init__(self, root, project, env_file, gateway_image, docker=None):
        if not PROJECT.fullmatch(project) or not DIGEST.fullmatch(gateway_image):
            fail("invalid_project_or_gateway_image_id")
        self.root = Path(root).resolve()
        self.project = project
        self.env_file = Path(env_file).resolve()
        if not self.env_file.is_file() or self.env_file.is_symlink():
            fail("missing_environment_file")
        self.gateway_image = gateway_image
        self.docker = docker or Docker()
        self.snapshot = {p: bounded_file(self.root / p) for p in (*INPUTS, LOCK, IMPLEMENTATION)}
        self.lock = decode(self.snapshot[LOCK])
        self._validate_lock()
        server = self.docker.json(["version", "--format", "{{json .Server}}"])
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(server.get("Arch"), server.get("Arch"))
        self.platform = server.get("Os", "") + "/" + str(arch)
        if self.platform not in PLATFORMS:
            fail("unsupported_daemon_platform")
        self.images = {name: {
            "reference": value["image"],
            "config_digest": value["platforms"][self.platform]["config_digest"],
            "manifest_digest": value["platforms"][self.platform]["manifest_digest"],
        } for name, value in self.lock["images"].items()}
        self.images["firewall"] = {"reference": gateway_image,
                                   "config_digest": gateway_image}
        self.configuration = None
        self.frozen = None
        self.policy_snapshot = None

    def _validate_lock(self):
        value = self.lock
        if (not isinstance(value, dict) or value.get("format") != "sw-production-images/1"
                or set(value.get("files", {})) != set(INPUTS)
                or set(value.get("images", {})) != {"postgres", "redis"}):
            fail("invalid_image_lock")
        for path in INPUTS:
            if sha256(self.snapshot[path]) != value["files"][path]:
                fail("source_input_digest_mismatch")
        for name, image in value["images"].items():
            prefix = "docker.io/library/" + name + ":"
            if (not isinstance(image, dict) or not isinstance(image.get("image"), str)
                    or not image["image"].startswith(prefix)
                    or "@" not in image["image"]
                    or not DIGEST.fullmatch(image["image"].split("@", 1)[1])
                    or set(image.get("platforms", {})) != PLATFORMS):
                fail("invalid_image_lock")
            for platform in PLATFORMS:
                row = image["platforms"][platform]
                if any(not DIGEST.fullmatch(row.get(k, ""))
                       for k in ("manifest_digest", "config_digest")):
                    fail("invalid_image_lock")

    def unchanged(self):
        if any(bounded_file(self.root / p) != data for p, data in self.snapshot.items()):
            fail("source_inputs_changed")
        if (self.policy_snapshot is not None
                and bounded_file(self.policy_snapshot) != self.snapshot["deploy/production.firewall.yaml"]):
            fail("staged_policy_changed")

    def verify_images(self):
        self.unchanged()
        for name, row in self.images.items():
            result = self.docker.json(["image", "inspect", row["reference"]])
            if not isinstance(result, list) or len(result) != 1:
                fail("image_inspection_incomplete")
            actual = result[0]
            platform = str(actual.get("Os")) + "/" + str(actual.get("Architecture"))
            if actual.get("Id") != row["config_digest"] or platform != self.platform:
                fail("local_image_identity_or_platform_mismatch")
        self.unchanged()

    def _args(self):
        return ["compose", "--project-name", self.project, "--project-directory",
                str(self.root / "deploy"), "--env-file", os.devnull, "-f", "-"]

    def compose(self, args):
        if self.frozen is None:
            fail("configuration_not_frozen")
        self.unchanged()
        output = self.docker.run([*self._args(), *args], stdin=self.frozen)
        self.unchanged()
        return output

    def _validate_model(self, model):
        if not isinstance(model, dict) or set(model.get("services", {})) != set(self.images):
            fail("unexpected_compose_services")
        for name, row in self.images.items():
            service = model["services"][name]
            if (service.get("image") != row["reference"]
                    or service.get("platform") != self.platform
                    or service.get("pull_policy") != "never" or "build" in service
                    or service.get("profiles") or service.get("container_name")):
                fail("compose_image_or_execution_override")
        firewall = model["services"]["firewall"]
        ports = firewall.get("ports", [])
        if (firewall.get("read_only") is not True or firewall.get("cap_drop") != ["ALL"]
                or "no-new-privileges:true" not in firewall.get("security_opt", [])
                or len(ports) != 1 or ports[0].get("host_ip") != "127.0.0.1"
                or str(ports[0].get("published")) != "8080" or ports[0].get("target") != 8080):
            fail("gateway_isolation_changed")
        for name in ("postgres", "redis"):
            if model["services"][name].get("ports"):
                fail("dependency_host_port_exposed")
        mounts = firewall.get("volumes", [])
        if (len(mounts) != 1 or mounts[0].get("type") != "bind"
                or mounts[0].get("target") != "/app/firewall.yaml"
                or mounts[0].get("read_only") is not True
                or Path(mounts[0].get("source", "")).resolve()
                != (self.root / "deploy/production.firewall.yaml").resolve()):
            fail("gateway_config_mount_changed")

    @contextmanager
    def freeze(self):
        self.verify_images()
        args = ["compose", "--project-name", self.project, "--project-directory",
                str(self.root / "deploy"), "--env-file", str(self.env_file),
                "-f", str(self.root / "deploy/docker-compose.production.yaml"),
                "config", "--format", "json"]
        model = self.docker.json(args, environment={"SOUP_WALL_IMAGE": self.gateway_image,
                                                  "SOUP_WALL_PLATFORM": self.platform})
        self._validate_model(model)
        self.unchanged()
        # Only the nonsecret policy is copied. Expanded credentials stay in the
        # in-memory model and are sent through stdin, never retained in a file.
        staging = self.root / "target/production-compose" / self.project
        for parent in (self.root / "target", staging.parent, staging):
            if parent.is_symlink() or not parent.resolve().is_relative_to(self.root):
                fail("unsafe_policy_staging_path")
        staging.mkdir(parents=True, exist_ok=True)
        policy = staging / (sha256(self.snapshot["deploy/production.firewall.yaml"]) + ".yaml")
        if not policy.exists():
            descriptor = os.open(policy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(self.snapshot["deploy/production.firewall.yaml"])
        self.policy_snapshot = policy
        self.unchanged()
        model["services"]["firewall"]["volumes"][0]["source"] = str(policy)
        self.configuration = model
        # A Compose config result has resolved dollar characters. Escape them
        # for the second parse; never interpolate secret values twice.
        self.frozen = json.dumps(model).replace("$", "$$")
        try:
            yield self
        finally:
            self.frozen = None
            self.configuration = None

    def verify_containers(self, names, *, required=True):
        for name in names:
            ids = self.compose(["ps", "--all", "--quiet", name]).split()
            if not ids and not required:
                continue
            if len(ids) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", ids[0]):
                fail("service_container_missing_or_ambiguous")
            actual = self.docker.json(["container", "inspect", ids[0]])
            if not isinstance(actual, list) or len(actual) != 1:
                fail("container_inspection_incomplete")
            row = actual[0]
            config = row.get("Config", {})
            labels = config.get("Labels", {})
            if (row.get("Image") != self.images[name]["config_digest"]
                    or config.get("Image") != self.images[name]["reference"]
                    or labels.get("com.docker.compose.project") != self.project
                    or labels.get("com.docker.compose.service") != name
                    or labels.get("com.docker.compose.oneoff", "false").lower() != "false"):
                fail("container_identity_or_owner_mismatch")
            if required and (not row.get("State", {}).get("Running")
                    or row.get("State", {}).get("Health", {}).get("Status") != "healthy"):
                fail("service_not_healthy")

    def dependencies(self):
        self.verify_images()
        self.verify_containers(self.images, required=False)
        self.compose(["up", "--detach", "--no-build", "--pull", "never", "--wait",
                      "--wait-timeout", "120", "postgres", "redis"])
        self.verify_containers(("postgres", "redis"))

    def execute(self, action):
        with self.freeze():
            self.verify_containers(self.images, required=False)
            if action in {"start", "migrate"}:
                self.dependencies()
            if action in {"preflight", "migrate"}:
                self.verify_images()
                self.compose(["run", "--rm", "--no-deps", "--pull", "never", "-T",
                              "firewall", action])
            elif action == "start":
                self.verify_images()
                self.verify_containers(("postgres", "redis"))
                self.compose(["up", "--detach", "--no-deps", "--no-build", "--pull",
                              "never", "--wait", "--wait-timeout", "120", "firewall"])
                self.verify_containers(self.images)
            elif action != "check":
                fail("unsupported_action")
            self.verify_images()
            return {"format": "sw-production-compose-observation/1", "status": "passed",
                    "action": action, "checked_at": datetime.now(timezone.utc).isoformat(),
                    "project": self.project, "platform": self.platform, "images": self.images,
                    "input_sha256": {p: sha256(data) for p, data in self.snapshot.items()},
                    "network_downloads": 0, "image_builds": 0,
                    "scope": "local-image-and-compose-closure-not-advisory-or-license-clearance"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "preflight", "migrate", "start"))
    parser.add_argument("--project", required=True)
    parser.add_argument("--env-file", required=True, type=Path)
    parser.add_argument("--gateway-image-id", required=True)
    parser.add_argument("--output", type=Path, help="new JSON observation file; no secrets")
    args = parser.parse_args(argv)
    try:
        observation = ProductionCompose(ROOT, args.project, args.env_file,
                                        args.gateway_image_id).execute(args.action)
        if args.output:
            # Exclusive creation preserves previous attempts, including failures.
            with args.output.open("x", encoding="utf-8") as handle:
                json.dump(observation, handle, indent=2)
                handle.write("\n")
        print(json.dumps(observation, sort_keys=True))
        return 0
    except (ClosureError, OSError, KeyError, TypeError, AttributeError, ValueError) as error:
        category = str(error) if isinstance(error, ClosureError) else "invalid_input_or_output"
        print(json.dumps({"format": "sw-production-compose-observation/1", "status": "refused",
                          "reason": category}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
