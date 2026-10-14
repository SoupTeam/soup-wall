# SPDX-License-Identifier: Apache-2.0
"""Offline safety checks for the disposable OIDC driver."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from contextlib import ExitStack
import subprocess
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("oidc_driver", Path(__file__).resolve().parents[1] / "keycloak-oidc-acceptance.py")
DRIVER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DRIVER)


class ImportedCredentialTests(unittest.TestCase):
    def test_realm_import_contains_salted_verifier_instead_of_cleartext(self):
        secret = "generated-only-for-this-unit-test"
        first, second = DRIVER.imported_credential(secret), DRIVER.imported_credential(secret)
        self.assertNotIn(secret, json.dumps(first))
        self.assertNotIn("value", first)
        self.assertNotEqual(first["secretData"], second["secretData"])
        parameters = json.loads(first["credentialData"])
        material = json.loads(first["secretData"])
        self.assertEqual(parameters["algorithm"], "pbkdf2-sha512")
        self.assertEqual(parameters["hashIterations"], 210_000)
        salt = base64.b64decode(material["salt"])
        self.assertEqual(len(salt), 16)
        expected = hashlib.pbkdf2_hmac("sha512", secret.encode(), salt, 210_000, dklen=64)
        self.assertEqual(base64.b64decode(material["value"]), expected)


class OwnedDatabaseTests(unittest.TestCase):
    def test_sqlite_mode_uses_new_fixture_without_docker_or_environment_changes(self):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as resources:
            environment = {"HOME": directory}
            with patch.object(DRIVER.subprocess, "run", side_effect=AssertionError("unexpected process")):
                fixture = DRIVER.FixtureDatabase(Path(directory), environment, resources)
                fixture.sql("CREATE TABLE sessions (expires_at INTEGER)")
                fixture.sql("INSERT INTO sessions VALUES (100)")
                self.assertEqual(fixture.sql("SELECT expires_at FROM sessions"), "100")
                fixture.sql("UPDATE sessions SET expires_at = 1")
                self.assertEqual(fixture.sql("SELECT expires_at FROM sessions"), "1")
            self.assertEqual(environment, {"HOME": directory})
            self.assertEqual(Path(fixture.bootstrap_target()).parent, Path(directory))
            self.assertIn("backend: sqlite", fixture.configuration())

    def test_container_removed_with_its_volumes_even_when_later_work_fails(self):
        identifier = "a" * 64
        with patch.object(DRIVER.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, identifier)) as run:
            with self.assertRaisesRegex(RuntimeError, "fixture failed"):
                with ExitStack() as resources:
                    self.assertEqual(DRIVER.owned_container("docker", ["pinned-image"], resources), identifier)
                    raise RuntimeError("fixture failed")
            self.assertEqual(run.call_args_list[-1].args[0], ["docker", "rm", "--force", "--volumes", identifier])

    def test_unverified_container_identifier_never_becomes_cleanup_target(self):
        for value in ("existing-container", "a" * 63, "g" * 64, "a" * 64 + "\nother"):
            with self.subTest(value=value), patch.object(DRIVER.subprocess, "run",
                    return_value=subprocess.CompletedProcess([], 0, value)) as run:
                with ExitStack() as resources, self.assertRaises(RuntimeError):
                    DRIVER.owned_container("docker", ["pinned-image"], resources)
                self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
