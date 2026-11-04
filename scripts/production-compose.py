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
import stat
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
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json"}
INDEX_TYPES = {"application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json"}


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


def public_policy_snapshot(path, data):
    """Make only verified, nonsecret policy bytes readable by the container UID.

    Existing owner-only snapshots are repaired through their verified descriptor.
    Symlinks, reparse points, hardlinks and special files are never chmod targets.
    """
    flags = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    created = False
    try:
        try:
            descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | flags, 0o644)
            created = True
        except FileExistsError:
            descriptor = os.open(path, os.O_RDONLY | flags)
    except OSError:
        fail("unsafe_policy_snapshot")
    with os.fdopen(descriptor, "r+b" if created else "rb") as handle:
        opened = os.fstat(handle.fileno())
        named = path.lstat()
        reparse = getattr(named, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or stat.S_ISLNK(named.st_mode) or reparse
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or (os.name == "posix" and opened.st_uid != os.geteuid())):
            fail("unsafe_policy_snapshot")
        if created:
            handle.write(data)
            handle.flush()
            handle.seek(0)
        if handle.read(MAX_BYTES + 1).replace(b"\r\n", b"\n") != data:
            fail("staged_policy_changed")
        # Policy is public source material, unlike the protected environment
        # file. UID65532 must be able to read a Linux host bind mount.
        if os.name == "posix":
            os.fchmod(handle.fileno(), 0o644)
        final = path.lstat()
        if (opened.st_dev, opened.st_ino) != (final.st_dev, final.st_ino):
            fail("unsafe_policy_snapshot")


def same_mount_source(actual, expected):
    if not isinstance(actual, str) or expected is None:
        return False
    expected = str(expected)
    if os.name == "nt":
        # Docker Desktop preserves the full Windows path with forward slashes.
        # Normalize separators and drive-letter case only, never a path suffix
        # or Linux filename case.
        actual, expected = actual.replace("\\", "/"), expected.replace("\\", "/")
        if not re.match(r"[A-Za-z]:/", actual) or not re.match(r"[A-Za-z]:/", expected):
            return False
        actual, expected = actual[0].lower() + actual[1:], expected[0].lower() + expected[1:]
    return actual == expected


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


def compose_dollars(value, *, escape):
    """Convert Compose's serialized dollar escapes and runtime values.

    `compose config` already escapes every value's literal dollar characters,
    including shell health checks and resolved environment/command values.
    Keys are not interpolated. Keep that representation out of comparisons
    against the actual container's unescaped configuration.
    """
    if isinstance(value, str):
        return value.replace("$", "$$") if escape else value.replace("$$", "$")
    if isinstance(value, list):
        return [compose_dollars(item, escape=escape) for item in value]
    if isinstance(value, dict):
        return {key: compose_dollars(item, escape=escape) for key, item in value.items()}
    return value


def docker_environment():
    # Preserve Docker's selected endpoint/credentials, not Compose overrides,
    # provider keys, deployment secrets, or inherited dotenv variables.
    allowed = {"PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR",
               "PROGRAMDATA", "ALLUSERSPROFILE", "HOME", "USERPROFILE", "APPDATA",
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
        self.image_defaults = {}
        self.container_identities = {}
        self.snapshot = {p: bounded_file(self.root / p) for p in (*INPUTS, LOCK, IMPLEMENTATION)}
        self.lock = decode(self.snapshot[LOCK])
        self._validate_lock()
        server = self.docker.json(["version", "--format", "{{json .Server}}"])
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(server.get("Arch"), server.get("Arch"))
        self.platform = server.get("Os", "") + "/" + str(arch)
        if self.platform not in PLATFORMS:
            fail("unsupported_daemon_platform")
        api = str(server.get("ApiVersion", server.get("APIVersion", "0")))
        self.platform_inspection = bool(re.fullmatch(r"[0-9]+\.[0-9]+", api)
                                        and tuple(map(int, api.split("."))) >= (1, 49))
        self.images = {name: {
            "reference": value["image"],
            "config_digest": value["platforms"][self.platform]["config_digest"],
            "manifest_digest": value["platforms"][self.platform]["manifest_digest"],
        } for name, value in self.lock["images"].items()}
        self.images["firewall"] = {"reference": gateway_image}
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
            root = result[0]
            actual = root
            if self.platform_inspection:
                selected = self.docker.json(["image", "inspect", "--platform", self.platform,
                                             row["reference"]])
                if not isinstance(selected, list) or len(selected) != 1:
                    fail("image_inspection_incomplete")
                actual = selected[0]
            platform = str(actual.get("Os")) + "/" + str(actual.get("Architecture"))
            if platform != self.platform:
                fail("local_image_identity_or_platform_mismatch")
            root_descriptor = root.get("Descriptor")
            descriptor = actual.get("Descriptor")
            if root_descriptor is not None or descriptor is not None:
                expected_root = (row["reference"].split("@", 1)[1]
                                 if name != "firewall" else self.gateway_image)
                if (not self.platform_inspection or not isinstance(root_descriptor, dict)
                        or root_descriptor.get("digest") != expected_root
                        or root.get("Id") != expected_root
                        or root_descriptor.get("mediaType") not in INDEX_TYPES | MANIFEST_TYPES
                        or not isinstance(descriptor, dict)
                        or descriptor.get("mediaType") not in MANIFEST_TYPES
                        or not DIGEST.fullmatch(descriptor.get("digest", ""))
                        or actual.get("Id") != descriptor["digest"]
                        or not self._descriptor_platform(descriptor)):
                    fail("local_manifest_identity_or_platform_mismatch")
                if name != "firewall" and descriptor["digest"] != row["manifest_digest"]:
                    fail("locked_platform_manifest_mismatch")
                # A verified immutable child manifest content-addresses the
                # lock's reviewed config blob. Modern containerd stores expose
                # index/manifest IDs here, not the legacy config ID.
                row["manifest_digest"] = descriptor["digest"]
                row["local_image_id"] = root["Id"]
                row["selected_local_id"] = actual["Id"]
                row["store_identity"] = "oci-manifest"
                self.container_identities[name] = (root["Id"], descriptor["digest"])
            else:
                expected_config = row.get("config_digest", self.gateway_image)
                if actual.get("Id") != expected_config or root.get("Id") != expected_config:
                    fail("local_image_identity_or_platform_mismatch")
                row["local_image_id"] = expected_config
                row["store_identity"] = "legacy-config"
                self.container_identities[name] = (expected_config, None)
            defaults = actual.get("Config", {})
            if not isinstance(defaults, dict):
                fail("image_configuration_missing")
            self.image_defaults[name] = defaults
        self.unchanged()

    def _descriptor_platform(self, descriptor):
        platform = descriptor.get("platform", {})
        return (isinstance(platform, dict)
                and str(platform.get("os")) + "/" + str(platform.get("architecture")) == self.platform)

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
                    or service.get("profiles") or service.get("container_name")
                    or service.get("privileged") or service.get("cap_add")):
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
        model = compose_dollars(model, escape=False)
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
        public_policy_snapshot(policy, self.snapshot["deploy/production.firewall.yaml"])
        self.policy_snapshot = policy
        self.unchanged()
        model["services"]["firewall"]["volumes"][0]["source"] = str(policy)
        self.configuration = model
        # Serialize runtime values once. Doubling the already escaped config
        # output again changes shell health checks (and passwords) at runtime.
        self.frozen = json.dumps(compose_dollars(model, escape=True))
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
            image_id, manifest_digest = self.container_identities[name]
            if (row.get("Image") != image_id
                    or config.get("Image") != self.images[name]["reference"]
                    or labels.get("com.docker.compose.project") != self.project
                    or labels.get("com.docker.compose.service") != name
                    or labels.get("com.docker.compose.oneoff", "false").lower() != "false"):
                fail("container_identity_or_owner_mismatch")
            if manifest_digest is not None:
                descriptor = row.get("ImageManifestDescriptor", {})
                if (not isinstance(descriptor, dict)
                        or descriptor.get("digest") != manifest_digest
                        or descriptor.get("mediaType") not in MANIFEST_TYPES
                        or not self._descriptor_platform(descriptor)):
                    fail("container_platform_manifest_mismatch")
            service = self.configuration["services"][name]
            defaults = self.image_defaults[name]
            expected_env = self._environment(defaults.get("Env", []))
            expected_env.update(service.get("environment", {}))
            # Compose emits explicit nulls for inherited process defaults.
            # A non-null entrypoint suppresses the image's default command.
            entrypoint = service.get("entrypoint")
            command = service.get("command")
            if command is None and entrypoint is None:
                command = defaults.get("Cmd")
            if entrypoint is None:
                entrypoint = defaults.get("Entrypoint")
            if (self._environment(config.get("Env", [])) != expected_env
                    or config.get("Cmd") != command
                    or config.get("Entrypoint") != entrypoint
                    or config.get("User", "") != service.get("user", defaults.get("User", ""))):
                fail("container_process_or_environment_mismatch")
            self._verify_container_isolation(name, row)
            if required and (not row.get("State", {}).get("Running")
                    or row.get("State", {}).get("Health", {}).get("Status") != "healthy"):
                fail("service_not_healthy")

    @staticmethod
    def _environment(entries):
        if not isinstance(entries, list) or any(not isinstance(e, str) or "=" not in e for e in entries):
            fail("invalid_container_environment")
        parsed = [e.split("=", 1) for e in entries]
        result = dict(parsed)
        if len(result) != len(parsed):
            fail("duplicate_container_environment")
        return result

    def _verify_container_isolation(self, name, container):
        host = container.get("HostConfig", {})
        mounts = container.get("Mounts", [])
        if host.get("Privileged") or host.get("CapAdd"):
            fail("container_runtime_isolation_mismatch")
        if name == "firewall":
            if (host.get("ReadonlyRootfs") is not True or set(host.get("CapDrop", [])) != {"ALL"}
                    or not {"no-new-privileges", "no-new-privileges:true"}.intersection(host.get("SecurityOpt", []))
                    or host.get("PortBindings") != {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}):
                fail("container_runtime_isolation_mismatch")
            policy_mounts = [m for m in mounts if m.get("Destination") == "/app/firewall.yaml"]
            if (len(policy_mounts) != 1 or policy_mounts[0].get("Type") != "bind"
                    or policy_mounts[0].get("RW") is not False
                    or not same_mount_source(policy_mounts[0].get("Source"), self.policy_snapshot)
                    or any(m.get("Destination") not in {"/app/firewall.yaml", "/tmp"} for m in mounts)):
                fail("container_policy_mount_mismatch")
        else:
            destination = "/var/lib/postgresql/data" if name == "postgres" else "/data"
            expected_name = self.configuration["volumes"][name + "-data"]["name"]
            if (host.get("PortBindings") or len(mounts) != 1
                    or mounts[0].get("Type") != "volume" or mounts[0].get("Name") != expected_name
                    or mounts[0].get("Destination") != destination or mounts[0].get("RW") is not True):
                fail("container_data_volume_or_port_mismatch")

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
    handle = None
    try:
        # Reserve the destination before any Docker operation. Existing evidence
        # or an unwritable destination cannot cause a late startup side effect.
        if args.output:
            handle = args.output.open("x", encoding="utf-8")
        observation = ProductionCompose(ROOT, args.project, args.env_file,
                                        args.gateway_image_id).execute(args.action)
        if handle:
            json.dump(observation, handle, indent=2)
            handle.write("\n")
        print(json.dumps(observation, sort_keys=True))
        return 0
    except (ClosureError, OSError, KeyError, TypeError, AttributeError, ValueError) as error:
        category = str(error) if isinstance(error, ClosureError) else "invalid_input_or_output"
        observation = {"format": "sw-production-compose-observation/1", "status": "refused",
                       "reason": category}
        if handle:
            handle.seek(0)
            handle.truncate()
            json.dump(observation, handle, indent=2)
            handle.write("\n")
        print(json.dumps(observation), file=sys.stderr)
        return 1
    finally:
        if handle:
            handle.close()


if __name__ == "__main__":
    raise SystemExit(main())
