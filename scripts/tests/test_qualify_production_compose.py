# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "qualify_production_compose", Path(__file__).resolve().parents[1] / "qualify-production-compose.py")
qualify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualify)
PROJECT = "soup-compose-qual-1234567890abcdef"


class Docker:
    def __init__(self, endpoint="npipe:////./pipe/dockerDesktopLinuxEngine", owner=PROJECT):
        self.environment = {}
        self.endpoint = endpoint
        self.owner = owner
        self.commands = []
        self.removed = False

    def json(self, args):
        if args == ["context", "inspect"]:
            return [{"Endpoints": {"docker": {"Host": self.endpoint}}}]
        return [{"Config": {"Labels": {"com.docker.compose.project": self.owner,
                                       "com.docker.compose.service": "postgres"}}}]

    def run(self, args, *, stdin=None):
        self.commands.append((args, stdin))
        if args[0] == "ps":
            return "" if self.removed else "a" * 12
        self.removed = True
        return ""


class OwnedQualificationTests(unittest.TestCase):
    def test_remote_context_is_refused_before_container_commands(self):
        for endpoint in ("ssh://operator@remote", "tcp://example.test:2376", "tcp://127.0.0.1:2375"):
            docker = Docker(endpoint)
            with self.assertRaisesRegex(qualify.QualificationError, "qualification_requires_local_docker"):
                qualify.require_local_daemon(docker)
            self.assertEqual(docker.commands, [])

    def test_remote_docker_host_cannot_hide_behind_local_context(self):
        docker = Docker()
        docker.environment["DOCKER_HOST"] = "tcp://example.test:2376"
        with self.assertRaises(qualify.QualificationError):
            qualify.require_local_daemon(docker)

    def test_local_desktop_and_unix_socket_are_supported(self):
        qualify.require_local_daemon(Docker())
        qualify.require_local_daemon(Docker("unix:///var/run/docker.sock"))

    def test_cleanup_refuses_unrelated_container(self):
        docker = Docker(owner="another-project")
        with self.assertRaisesRegex(qualify.QualificationError, "unexpected_cleanup_owner"):
            qualify.cleanup_owned(docker, PROJECT, ["compose"], "frozen")
        self.assertFalse(docker.removed)

    def test_cleanup_refuses_non_generated_project(self):
        docker = Docker()
        with self.assertRaises(qualify.QualificationError):
            qualify.cleanup_owned(docker, "soup-wall-production", ["compose"], "frozen")
        self.assertEqual(docker.commands, [])

    def test_cleanup_uses_retained_configuration_and_only_owned_project(self):
        docker = Docker()
        arguments = ["compose", "--project-name", PROJECT, "-f", "-"]
        qualify.cleanup_owned(docker, PROJECT, arguments, "frozen")
        self.assertIn((arguments + ["down", "--volumes", "--remove-orphans", "--timeout", "10"], "frozen"), docker.commands)
        self.assertTrue(docker.removed)

    def test_fixture_urls_use_only_disposable_internal_services(self):
        values = qualify.fixture_environment()
        self.assertIn("@postgres:5432/owned_compose?sslmode=disable", values["LLM_FW_POSTGRES_URL"])
        self.assertTrue(values["LLM_FW_REDIS_URL"].endswith("@redis:6379/0"))
        self.assertNotEqual(values["POSTGRES_PASSWORD"], values["REDIS_PASSWORD"])


if __name__ == "__main__":
    unittest.main()
