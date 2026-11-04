# SPDX-License-Identifier: Apache-2.0
"""Image/config closure controls; mocks do not claim actual Docker acceptance."""

import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from types import SimpleNamespace
from contextlib import redirect_stderr
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("production_compose", SOURCE / "scripts/production-compose.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
GATEWAY = "sha256:" + "a" * 64
SECRET = "fixture-password-$should-not-interpolate"


class FakeDocker:
    def __init__(self, root):
        self.root = root
        self.lock = json.loads((root / MODULE.LOCK).read_text())
        self.calls = []
        self.containers = {}
        self.arch = "amd64"
        self.wrong_image = None
        self.after_render = None
        self.unhealthy = False
        self.model_override = None
        self.stdin_values = []
        self.current_model = None
        self.modern = False
        self.descriptor_override = None

    def model(self):
        services = {name: {"image": row["image"], "platform": "linux/" + self.arch,
                           "pull_policy": "never", "volumes": [{"type": "volume", "source": name + "-data",
                               "target": "/var/lib/postgresql/data" if name == "postgres" else "/data"}]}
                    for name, row in self.lock["images"].items()}
        services["firewall"] = {"image": GATEWAY, "platform": "linux/" + self.arch,
            "pull_policy": "never", "read_only": True, "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "ports": [{"host_ip": "127.0.0.1", "published": "8080", "target": 8080}],
            "environment": {"TEST_PASSWORD": SECRET},
            "volumes": [{"type": "bind", "read_only": True, "target": "/app/firewall.yaml",
                         "source": str(self.root / "deploy/production.firewall.yaml")}]}
        model = {"name": "owned-test", "services": services,
                 "volumes": {n + "-data": {"name": "owned-test_" + n + "-data"} for n in ("postgres", "redis")}}
        if self.model_override:
            self.model_override(model)
        for service in services.values():
            service.setdefault("command", None)
            service.setdefault("entrypoint", None)
        return model

    @staticmethod
    def defaults(name):
        return {"Cmd": None if name == "firewall" else [name],
                "Entrypoint": ["soup-wall-gateway"] if name == "firewall" else ["docker-entrypoint.sh"]}

    def image(self, name):
        if self.modern and name != "firewall":
            return self.lock["images"][name]["image"].split("@", 1)[1]
        return (GATEWAY if name == "firewall" else
                self.lock["images"][name]["platforms"]["linux/" + self.arch]["config_digest"])

    def manifest(self, name):
        return ("sha256:" + "e" * 64 if name == "firewall" else
                self.lock["images"][name]["platforms"]["linux/" + self.arch]["manifest_digest"])

    def descriptor(self, name):
        return {"digest": self.manifest(name), "mediaType": next(iter(MODULE.MANIFEST_TYPES)),
                "platform": {"os": "linux", "architecture": self.arch}}

    def add_container(self, name):
        service = (self.current_model or self.model())["services"][name]
        defaults = self.defaults(name)
        entrypoint = service.get("entrypoint")
        command = service.get("command")
        if command is None and entrypoint is None:
            command = defaults["Cmd"]
        if entrypoint is None:
            entrypoint = defaults["Entrypoint"]
        self.containers[name] = {
            "Id": ("b" if name == "postgres" else "c" if name == "redis" else "d") * 64,
            "Image": self.image(name),
            "Config": {"Image": GATEWAY if name == "firewall" else self.lock["images"][name]["image"],
                       "Env": [k + "=" + v for k, v in service.get("environment", {}).items()],
                       "Cmd": command, "Entrypoint": entrypoint, "User": "",
                       "Labels": {"com.docker.compose.project": "owned-test",
                                  "com.docker.compose.service": name,
                                  "com.docker.compose.oneoff": "False"}},
            "State": {"Running": True, "Health": {"Status": "unhealthy" if self.unhealthy else "healthy"}},
            "HostConfig": {"ReadonlyRootfs": name == "firewall", "CapDrop": ["ALL"] if name == "firewall" else [],
                           "SecurityOpt": ["no-new-privileges:true"] if name == "firewall" else [],
                           "PortBindings": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]} if name == "firewall" else {}},
            "Mounts": ([{"Type": "bind", "Destination": "/app/firewall.yaml", "RW": False,
                         "Source": service["volumes"][0]["source"].replace("\\", "/")}]
                       if name == "firewall" else [{"Type": "volume", "Name": "owned-test_" + name + "-data",
                           "Destination": "/var/lib/postgresql/data" if name == "postgres" else "/data", "RW": True}])}
        if self.modern:
            self.containers[name]["ImageManifestDescriptor"] = self.descriptor(name)

    def run(self, args, *, stdin=None, environment=None, timeout=180):
        self.calls.append(args)
        if stdin is not None:
            self.stdin_values.append(stdin)
            self.current_model = json.loads(stdin.replace("$$", "$"))
        if args[:2] == ["image", "inspect"]:
            name = next((n for n, row in self.lock["images"].items() if row["image"] == args[-1]), "firewall")
            actual = {"Id": self.wrong_image if name == "postgres" and self.wrong_image else self.image(name),
                      "Os": "linux", "Architecture": self.arch, "Config": self.defaults(name)}
            if self.modern:
                actual["Descriptor"] = {"digest": self.image(name), "mediaType": next(iter(MODULE.INDEX_TYPES))}
                if "--platform" in args:
                    actual["Id"] = self.manifest(name)
                    actual["Descriptor"] = self.descriptor(name)
                if self.descriptor_override:
                    self.descriptor_override(name, args, actual)
            return json.dumps([actual])
        if args[:2] == ["container", "inspect"]:
            return json.dumps([next(row for row in self.containers.values() if row["Id"] == args[2])])
        if args[0] == "version":
            return json.dumps({"Os": "linux", "Arch": self.arch, "ApiVersion": "1.56" if self.modern else "1.43"})
        if args[-3:] == ["config", "--format", "json"]:
            result = self.model()
            if self.after_render:
                self.after_render()
            # Real Compose config emits escaped values, not runtime strings.
            return json.dumps(result).replace("$", "$$")
        if "ps" in args:
            row = self.containers.get(args[-1])
            return row["Id"] + "\n" if row else ""
        if "up" in args:
            for name in ("postgres", "redis", "firewall"):
                if name in args:
                    self.add_container(name)
            return ""
        if "run" in args:
            return ""
        raise AssertionError(args)

    def json(self, args, **kwargs):
        return MODULE.decode(self.run(args, **kwargs))

    def mutations(self):
        return [args for args in self.calls if "up" in args or "run" in args]


class ProductionComposeControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="production-compose-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative in (*MODULE.INPUTS, MODULE.LOCK, MODULE.IMPLEMENTATION):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / relative, target)
        self.env_file = self.root / "fixture.env"
        self.env_file.write_text("TEST_PASSWORD=" + SECRET + "\n")
        self.docker = FakeDocker(self.root)

    def closure(self, **kwargs):
        return MODULE.ProductionCompose(self.root, "owned-test", self.env_file,
                                        GATEWAY, self.docker, **kwargs)

    def test_check_is_read_only_and_report_omits_secrets(self):
        report = self.closure().execute("check")
        self.assertEqual(report["status"], "passed")
        self.assertEqual(self.docker.mutations(), [])
        self.assertNotIn(SECRET, json.dumps(report))
        self.assertNotIn("fixture.env", json.dumps(report))

    def test_gateway_starts_only_after_verified_healthy_dependencies(self):
        self.closure().execute("start")
        calls = self.docker.mutations()
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][-2:], ["postgres", "redis"])
        self.assertEqual(calls[1][-1], "firewall")
        self.assertIn("--no-deps", calls[1])
        for call in calls:
            self.assertIn("--no-build", call)
            self.assertEqual(call[call.index("--pull") + 1], "never")

    def test_rendered_null_process_fields_inherit_verified_image_defaults(self):
        self.closure().execute("start")
        self.assertEqual(self.docker.containers["postgres"]["Config"]["Cmd"], ["postgres"])
        self.assertEqual(self.docker.containers["redis"]["Config"]["Entrypoint"], ["docker-entrypoint.sh"])

    def test_explicit_process_override_still_requires_exact_actual_values(self):
        def override(model):
            model["services"]["redis"].update(command=["owned-command"], entrypoint=["owned-entrypoint"])
        self.docker.model_override = override
        for field in ("Cmd", "Entrypoint"):
            with self.subTest(field=field):
                self.docker.containers.clear()
                self.docker.add_container("redis")
                self.docker.containers["redis"]["Config"][field] = ["unexpected-process"]
                with self.assertRaisesRegex(MODULE.ClosureError, "container_process_or_environment_mismatch"):
                    self.closure().execute("start")
                self.assertEqual(self.docker.mutations(), [])

    def test_matching_digest_reference_with_wrong_local_image_id_refuses(self):
        self.docker.wrong_image = "sha256:" + "f" * 64
        with self.assertRaisesRegex(MODULE.ClosureError, "local_image_identity"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_actual_daemon_platform_selects_arm64_closure(self):
        self.docker.arch = "arm64"
        with patch.dict(os.environ, {"PROCESSOR_ARCHITECTURE": "AMD64", "DOCKER_DEFAULT_PLATFORM": "linux/amd64"}):
            result = self.closure().execute("check")
        self.assertEqual(result["platform"], "linux/arm64")
        self.assertEqual(result["images"]["postgres"]["config_digest"], self.docker.image("postgres"))

    def test_unsupported_daemon_architecture_refuses(self):
        self.docker.arch = "riscv64"
        with self.assertRaisesRegex(MODULE.ClosureError, "unsupported_daemon_platform"):
            self.closure()

    def test_changed_source_config_refuses_before_docker(self):
        (self.root / "deploy/production.firewall.yaml").write_text("changed\n")
        with self.assertRaisesRegex(MODULE.ClosureError, "source_input_digest_mismatch"):
            self.closure()
        self.assertEqual(self.docker.calls, [])

    def test_source_drift_during_render_refuses_before_start(self):
        self.docker.after_render = lambda: (self.root / "deploy/Dockerfile").write_text("changed")
        with self.assertRaisesRegex(MODULE.ClosureError, "source_inputs_changed"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_missing_platform_lock_refuses(self):
        lock = json.loads((self.root / MODULE.LOCK).read_text())
        del lock["images"]["redis"]["platforms"]["linux/arm64"]
        (self.root / MODULE.LOCK).write_text(json.dumps(lock))
        with self.assertRaisesRegex(MODULE.ClosureError, "invalid_image_lock"):
            self.closure()

    def test_duplicate_lock_json_keys_refuse(self):
        (self.root / MODULE.LOCK).write_text('{"format":1,"format":2}')
        with self.assertRaisesRegex(MODULE.ClosureError, "duplicate_json_key"):
            self.closure()

    def test_secret_dollar_values_are_escaped_for_second_parse_only(self):
        closure = self.closure()
        with closure.freeze():
            self.assertIn("fixture-password-$$should-not-interpolate", closure.frozen)
            self.assertEqual(closure.configuration["services"]["firewall"]["environment"]["TEST_PASSWORD"], SECRET)
        self.assertIsNone(closure.frozen)

    def test_rendered_shell_healthcheck_and_literal_password_keep_runtime_values(self):
        password = "owned-$TOKEN-$$PAIR-${BRACED}"
        command = ["redis-server", "--requirepass", password]
        healthcheck = ["CMD-SHELL", 'redis-cli -a "$REDIS_PASSWORD" ping | grep PONG']
        def configure(model):
            model["services"]["redis"].update(command=command,
                environment={"REDIS_PASSWORD": password}, healthcheck={"test": healthcheck})
        self.docker.model_override = configure
        closure = self.closure()
        with closure.freeze():
            service = closure.configuration["services"]["redis"]
            self.assertEqual(service["command"], command)
            self.assertEqual(service["environment"]["REDIS_PASSWORD"], password)
            self.assertEqual(service["healthcheck"]["test"], healthcheck)
            serialized = json.loads(closure.frozen)["services"]["redis"]
            self.assertEqual(serialized["healthcheck"]["test"][1],
                             'redis-cli -a "$$REDIS_PASSWORD" ping | grep PONG')
            self.assertEqual(serialized["command"][-1], "owned-$$TOKEN-$$$$PAIR-$${BRACED}")

    def test_inherited_compose_overrides_and_provider_keys_are_not_forwarded(self):
        with patch.dict(os.environ, {"COMPOSE_FILE": "unrelated.yaml", "COMPOSE_PROFILES": "other",
                                     "OPENAI_API_KEY": SECRET, "LLM_FW_ADMIN_TOKEN": SECRET}):
            environment = MODULE.docker_environment()
        self.assertNotIn("COMPOSE_FILE", environment)
        self.assertNotIn("COMPOSE_PROFILES", environment)
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("LLM_FW_ADMIN_TOKEN", environment)

    def test_windows_native_command_resolution_prerequisites_are_retained(self):
        # Without PATHEXT, PowerShell can select Docker Desktop's extensionless
        # Unix launcher instead of docker.exe and never obtain an exit code.
        required = {"PATHEXT": ".COM;.EXE;.BAT;.CMD", "SYSTEMDRIVE": "C:",
                    "PROGRAMDATA": "C:/ProgramData", "ALLUSERSPROFILE": "C:/ProgramData"}
        with patch.dict(os.environ, required, clear=True):
            self.assertEqual(MODULE.docker_environment(), required)

    def test_gateway_requires_immutable_local_id(self):
        with self.assertRaisesRegex(MODULE.ClosureError, "invalid_project_or_gateway_image_id"):
            MODULE.ProductionCompose(self.root, "owned-test", self.env_file, "soup-wall:production", self.docker)

    def test_existing_wrong_image_container_refuses_before_mutation(self):
        self.docker.add_container("redis")
        self.docker.containers["redis"]["Image"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(MODULE.ClosureError, "container_identity_or_owner_mismatch"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_existing_wrong_owner_container_refuses_before_mutation(self):
        self.docker.add_container("postgres")
        self.docker.containers["postgres"]["Config"]["Labels"]["com.docker.compose.project"] = "somebody-else"
        with self.assertRaisesRegex(MODULE.ClosureError, "container_identity_or_owner_mismatch"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_existing_correct_image_wrong_environment_refuses(self):
        self.docker.add_container("postgres")
        self.docker.containers["postgres"]["Config"]["Env"] = ["UNREVIEWED_VALUE=" + SECRET]
        with self.assertRaisesRegex(MODULE.ClosureError, "container_process_or_environment_mismatch"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_existing_correct_image_wrong_volume_refuses(self):
        self.docker.add_container("redis")
        self.docker.containers["redis"]["Mounts"][0]["Name"] = "somebody-elses-data"
        with self.assertRaisesRegex(MODULE.ClosureError, "container_data_volume_or_port_mismatch"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_dependency_health_failure_never_starts_gateway(self):
        self.docker.unhealthy = True
        with self.assertRaisesRegex(MODULE.ClosureError, "service_not_healthy"):
            self.closure().execute("start")
        self.assertEqual(len(self.docker.mutations()), 1)
        self.assertNotIn("firewall", self.docker.mutations()[0])

    def test_pull_build_or_unexpected_service_override_refuses(self):
        for mutate in (lambda m: m["services"]["redis"].update(pull_policy="always"),
                       lambda m: m["services"]["firewall"].update(build="."),
                       lambda m: m["services"].update(extra={})):
            with self.subTest(mutate=mutate):
                self.docker.model_override = mutate
                with self.assertRaises(MODULE.ClosureError):
                    self.closure().execute("start")
                self.assertEqual(self.docker.mutations(), [])

    def test_policy_snapshot_survives_wrapper_and_tamper_refuses(self):
        closure = self.closure()
        closure.execute("check")
        self.assertTrue(closure.policy_snapshot.is_file())
        closure.policy_snapshot.write_text("tampered")
        with self.assertRaisesRegex(MODULE.ClosureError, "staged_policy_changed"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_migration_runs_after_dependencies_with_no_implicit_dependency_start(self):
        self.closure().execute("migrate")
        calls = self.docker.mutations()
        self.assertEqual(calls[0][-2:], ["postgres", "redis"])
        self.assertEqual(calls[1][-2:], ["firewall", "migrate"])
        self.assertIn("--no-deps", calls[1])
        self.assertEqual(calls[1][calls[1].index("--pull") + 1], "never")

    def test_command_failure_never_surfaces_secret_stdout_or_stderr(self):
        result = SimpleNamespace(returncode=1, stdout=SECRET, stderr=SECRET)
        with patch.object(MODULE.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(MODULE.ClosureError, "^docker_command_failed$") as caught:
                MODULE.Docker().run(["compose", "config"])
        self.assertNotIn(SECRET, str(caught.exception))

    def test_helper_source_drift_refuses_before_start(self):
        closure = self.closure()
        (self.root / MODULE.IMPLEMENTATION).write_text("modified helper")
        with self.assertRaisesRegex(MODULE.ClosureError, "source_inputs_changed"):
            closure.execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_existing_output_refuses_without_constructing_docker_gate(self):
        existing = self.root / "previous-result.json"
        existing.write_text("previous attempt")
        args = ["start", "--project", "owned-test", "--env-file", str(self.env_file),
                "--gateway-image-id", GATEWAY, "--output", str(existing)]
        with patch.object(MODULE, "ProductionCompose") as gate, redirect_stderr(io.StringIO()):
            self.assertEqual(MODULE.main(args), 1)
        gate.assert_not_called()
        self.assertEqual(existing.read_text(), "previous attempt")

    def test_modern_index_and_platform_manifest_are_both_bound(self):
        self.docker.modern = True
        report = self.closure().execute("start")
        self.assertEqual(report["images"]["postgres"]["store_identity"], "oci-manifest")
        self.assertEqual(report["images"]["postgres"]["local_image_id"], self.docker.image("postgres"))
        self.assertEqual(report["images"]["postgres"]["selected_local_id"], self.docker.manifest("postgres"))
        self.assertTrue(any("--platform" in call for call in self.docker.calls))

    def test_modern_wrong_platform_child_is_not_accepted_from_matching_index(self):
        self.docker.modern = True
        def mismatch(name, args, actual):
            if name == "postgres" and "--platform" in args:
                actual["Id"] = "sha256:" + "f" * 64
                actual["Descriptor"]["digest"] = actual["Id"]
        self.docker.descriptor_override = mismatch
        with self.assertRaisesRegex(MODULE.ClosureError, "locked_platform_manifest_mismatch"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_modern_platform_descriptor_cannot_disagree_with_selected_daemon(self):
        self.docker.modern = True
        def mismatch(name, args, actual):
            if name == "postgres" and "--platform" in args:
                actual["Descriptor"]["platform"]["architecture"] = "arm64"
        self.docker.descriptor_override = mismatch
        with self.assertRaisesRegex(MODULE.ClosureError, "local_manifest_identity"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_bare_index_id_without_manifest_descriptors_has_no_weak_fallback(self):
        self.docker.modern = True
        def omit(name, args, actual):
            actual.pop("Descriptor", None)
        self.docker.descriptor_override = omit
        with self.assertRaisesRegex(MODULE.ClosureError, "local_image_identity"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_container_matching_index_with_wrong_actual_child_is_refused(self):
        self.docker.modern = True
        self.docker.add_container("redis")
        self.docker.containers["redis"]["ImageManifestDescriptor"]["digest"] = "sha256:" + "f" * 64
        with self.assertRaisesRegex(MODULE.ClosureError, "container_platform_manifest_mismatch"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_container_index_store_requires_actual_manifest_descriptor(self):
        self.docker.modern = True
        self.docker.add_container("redis")
        del self.docker.containers["redis"]["ImageManifestDescriptor"]
        with self.assertRaisesRegex(MODULE.ClosureError, "container_platform_manifest_mismatch"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_legacy_config_store_with_modern_api_stays_strict_and_supported(self):
        original = self.docker.json
        def modern_api(args, **kwargs):
            return ({"Os": "linux", "Arch": "amd64", "ApiVersion": "1.56"}
                    if args[0] == "version" else original(args, **kwargs))
        with patch.object(self.docker, "json", side_effect=modern_api):
            report = self.closure().execute("start")
        self.assertEqual(report["images"]["postgres"]["store_identity"], "legacy-config")

    def test_modern_matching_child_does_not_approve_wrong_parent_index(self):
        self.docker.modern = True
        def wrong_parent(name, args, actual):
            if name == "postgres" and "--platform" not in args:
                actual["Id"] = "sha256:" + "f" * 64
                actual["Descriptor"]["digest"] = actual["Id"]
        self.docker.descriptor_override = wrong_parent
        with self.assertRaisesRegex(MODULE.ClosureError, "local_manifest_identity"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_wrong_policy_bind_source_refuses_before_start(self):
        self.docker.add_container("firewall")
        expected_name = MODULE.sha256((self.root / "deploy/production.firewall.yaml").read_bytes().replace(b"\r\n", b"\n")) + ".yaml"
        self.docker.containers["firewall"]["Mounts"][0]["Source"] = str(self.root / "other" / expected_name)
        with self.assertRaisesRegex(MODULE.ClosureError, "container_policy_mount_mismatch"):
            self.closure().execute("start")
        self.assertEqual(self.docker.mutations(), [])

    def test_added_capability_or_privileged_mode_refuses_even_with_all_dropped(self):
        for name in ("firewall", "postgres", "redis"):
            for field, value in (("CapAdd", ["SYS_ADMIN"]), ("Privileged", True)):
                with self.subTest(name=name, field=field):
                    self.docker.containers.clear()
                    self.docker.add_container(name)
                    self.docker.containers[name]["HostConfig"][field] = value
                    with self.assertRaisesRegex(MODULE.ClosureError, "container_runtime_isolation_mismatch"):
                        self.closure().execute("start")
                    self.assertEqual(self.docker.mutations(), [])

    def test_rendered_privileged_or_added_capability_refuses_before_start(self):
        for field, value in (("cap_add", ["SYS_ADMIN"]), ("privileged", True)):
            with self.subTest(field=field):
                self.docker.model_override = lambda m: m["services"]["firewall"].update({field: value})
                with self.assertRaisesRegex(MODULE.ClosureError, "compose_image_or_execution_override"):
                    self.closure().execute("start")
                self.assertEqual(self.docker.mutations(), [])

    @unittest.skipUnless(os.name == "posix", "POSIX mode semantics")
    def test_policy_is_container_readable_under_private_process_umask(self):
        previous = os.umask(0o077)
        try:
            closure = self.closure()
            closure.execute("check")
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(closure.policy_snapshot.stat().st_mode), 0o644)

    @unittest.skipUnless(os.name == "posix", "POSIX mode semantics")
    def test_existing_0600_policy_snapshot_is_repaired(self):
        closure = self.closure()
        closure.execute("check")
        closure.policy_snapshot.chmod(0o600)
        self.closure().execute("check")
        self.assertEqual(stat.S_IMODE(closure.policy_snapshot.stat().st_mode), 0o644)

    @unittest.skipUnless(os.name == "posix", "POSIX link and chmod semantics")
    def test_policy_symlink_never_changes_external_target_mode(self):
        target = self.root / "external-policy.yaml"
        target.write_bytes(b"same verified policy bytes")
        target.chmod(0o600)
        link = self.root / "snapshot.yaml"
        link.symlink_to(target)
        with self.assertRaises(MODULE.ClosureError):
            MODULE.public_policy_snapshot(link, b"same verified policy bytes")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX link and chmod semantics")
    def test_policy_hardlink_never_changes_shared_target_mode(self):
        target = self.root / "external-policy.yaml"
        target.write_bytes(b"same verified policy bytes")
        target.chmod(0o600)
        link = self.root / "snapshot.yaml"
        os.link(target, link)
        with self.assertRaisesRegex(MODULE.ClosureError, "unsafe_policy_snapshot"):
            MODULE.public_policy_snapshot(link, b"same verified policy bytes")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX FIFO semantics")
    def test_policy_fifo_refuses_without_blocking_or_chmod(self):
        fifo = self.root / "snapshot.yaml"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(MODULE.ClosureError, "unsafe_policy_snapshot"):
            MODULE.public_policy_snapshot(fifo, b"policy")
        self.assertEqual(stat.S_IMODE(fifo.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX chmod semantics")
    def test_unmatched_policy_bytes_are_never_made_public(self):
        path = self.root / "unmatched-snapshot.yaml"
        path.write_bytes(b"unmatched private bytes")
        path.chmod(0o600)
        with self.assertRaisesRegex(MODULE.ClosureError, "staged_policy_changed"):
            MODULE.public_policy_snapshot(path, b"expected public policy bytes")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
