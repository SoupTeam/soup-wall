# SPDX-License-Identifier: Apache-2.0
"""Image/config closure controls; mocks do not claim actual Docker acceptance."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from types import SimpleNamespace
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

    def model(self):
        services = {name: {"image": row["image"], "platform": "linux/" + self.arch,
                           "pull_policy": "never"} for name, row in self.lock["images"].items()}
        services["firewall"] = {"image": GATEWAY, "platform": "linux/" + self.arch,
            "pull_policy": "never", "read_only": True, "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "ports": [{"host_ip": "127.0.0.1", "published": "8080", "target": 8080}],
            "environment": {"TEST_PASSWORD": SECRET},
            "volumes": [{"type": "bind", "read_only": True, "target": "/app/firewall.yaml",
                         "source": str(self.root / "deploy/production.firewall.yaml")}]}
        model = {"name": "owned-test", "services": services}
        if self.model_override:
            self.model_override(model)
        return model

    def image(self, name):
        return (GATEWAY if name == "firewall" else
                self.lock["images"][name]["platforms"]["linux/" + self.arch]["config_digest"])

    def add_container(self, name):
        self.containers[name] = {
            "Id": ("b" if name == "postgres" else "c" if name == "redis" else "d") * 64,
            "Image": self.image(name),
            "Config": {"Image": GATEWAY if name == "firewall" else self.lock["images"][name]["image"],
                       "Labels": {"com.docker.compose.project": "owned-test",
                                  "com.docker.compose.service": name,
                                  "com.docker.compose.oneoff": "False"}},
            "State": {"Running": True, "Health": {"Status": "unhealthy" if self.unhealthy else "healthy"}}}

    def run(self, args, *, stdin=None, environment=None, timeout=180):
        self.calls.append(args)
        if stdin is not None:
            self.stdin_values.append(stdin)
        if args[:2] == ["image", "inspect"]:
            name = next((n for n, row in self.lock["images"].items() if row["image"] == args[2]), "firewall")
            return json.dumps([{"Id": self.wrong_image if name == "postgres" and self.wrong_image else self.image(name),
                                "Os": "linux", "Architecture": self.arch}])
        if args[:2] == ["container", "inspect"]:
            return json.dumps([next(row for row in self.containers.values() if row["Id"] == args[2])])
        if args[0] == "version":
            return json.dumps({"Os": "linux", "Arch": self.arch})
        if args[-3:] == ["config", "--format", "json"]:
            result = self.model()
            if self.after_render:
                self.after_render()
            return json.dumps(result)
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

    def test_inherited_compose_overrides_and_provider_keys_are_not_forwarded(self):
        with patch.dict(os.environ, {"COMPOSE_FILE": "unrelated.yaml", "COMPOSE_PROFILES": "other",
                                     "OPENAI_API_KEY": SECRET, "LLM_FW_ADMIN_TOKEN": SECRET}):
            environment = MODULE.docker_environment()
        self.assertNotIn("COMPOSE_FILE", environment)
        self.assertNotIn("COMPOSE_PROFILES", environment)
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("LLM_FW_ADMIN_TOKEN", environment)

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


if __name__ == "__main__":
    unittest.main()
