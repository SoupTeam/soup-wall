# SPDX-License-Identifier: Apache-2.0
"""Offline safety checks for the disposable OIDC driver."""
import base64
import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import stat
from pathlib import Path
import unittest
from contextlib import ExitStack
import subprocess
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("oidc_driver", Path(__file__).resolve().parents[1] / "keycloak-oidc-acceptance.py")
DRIVER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DRIVER)


class SamlNavigationDiagnosticsTests(unittest.TestCase):
    def test_navigation_diagnostics_never_retain_untrusted_urls_or_failures(self):
        spec = importlib.util.spec_from_file_location(
            "saml_linux_driver", Path(__file__).resolve().parents[1] / "keycloak-saml-linux.py")
        driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(driver)
        gateway, vendor = "https://127.0.0.1:443", "https://localhost:8443"
        self.assertEqual(driver.navigation_location(
            gateway + "/auth/saml/acs?SAMLResponse=synthetic-secret", gateway, vendor), "gateway_acs")
        self.assertEqual(driver.navigation_location(
            gateway + "/private-secret?token=synthetic-secret", gateway, vendor), "gateway_other")
        self.assertEqual(driver.navigation_location(
            "https://unknown.test/private-secret", gateway, vendor), "other")
        self.assertEqual(driver.navigation_location("chrome-error://chromewebdata/", gateway, vendor),
                         "browser_error")
        self.assertEqual(driver.network_failure_category("net::ERR_CONNECTION_RESET"),
                         "net::ERR_CONNECTION_RESET")
        self.assertEqual(driver.network_failure_category("untrusted secret"), "other")
        transient = {"final_location": "browser_error", "network_failures": [
            {"category": "net::ERR_NETWORK_CHANGED"}]}
        self.assertTrue(driver.retryable_login_transport(transient))
        for extra in ({"acs_status": 400}, {"acs_status": 303}, {"local_authorization_error": True},
                      {"validation_error_categories": ["signature"]},
                      {"vendor_error_categories": ["invalid username or password"]},
                      {"final_location": "gateway_acs"},
                      {"network_failures": [{"category": "net::ERR_CONNECTION_REFUSED"}]}):
            self.assertFalse(driver.retryable_login_transport(dict(transient, **extra)))


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
    def test_postgres_password_uses_process_environment_without_file_or_argument(self):
        secret = "synthetic-generated-secret"
        with tempfile.TemporaryDirectory() as directory, ExitStack() as resources:
            root = Path(directory)
            with patch.object(DRIVER.secrets, "token_urlsafe", return_value=secret), \
                    patch.object(DRIVER.shutil, "which", return_value="docker"), \
                    patch.object(DRIVER.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "a" * 64)) as run, \
                    patch.object(DRIVER.FixtureDatabase, "sql", return_value="1"), \
                    patch.object(DRIVER.socket, "create_connection"):
                with resources:
                    DRIVER.FixtureDatabase(root, {}, resources, postgres=True,
                                           cert=root / "cert.pem", key=root / "key.pem")
                creation = next(call for call in run.call_args_list if call.args[0][1] == "create")
                self.assertEqual(creation.kwargs["env"]["POSTGRES_PASSWORD"], secret)
                for call in run.call_args_list:
                    self.assertNotIn(secret, " ".join(call.args[0]))
                self.assertEqual(list(root.iterdir()), [])

    @unittest.skipUnless(os.environ.get("SOUP_TEST_PRIVATE_POSTGRES_TLS") == "1",
                         "explicit opt-in requires the cached pinned PostgreSQL Docker image")
    def test_private_host_tls_material_is_readable_only_after_owned_container_staging(self):
        """Exercise actual Linux UID/mode semantics, including on Docker Desktop.

        Merely checking command strings misses the native bind-mount ownership
        boundary. An unrelated source UID makes the old direct certificate path
        unreadable to postgres; no host permission or production TLS change is
        needed. The real recovery run separately parses TLS and starts PostgreSQL.
        """
        docker = shutil.which("docker")
        self.assertIsNotNone(docker, "explicit fixture requires Docker")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            cert, key = root / "cert.pem", root / "key.pem"
            for path, value in ((cert, b"synthetic certificate"), (key, b"synthetic private key")):
                path.write_bytes(value)
                path.chmod(0o600)
            originals = {path: (path.read_bytes(), path.stat().st_mode, path.stat().st_uid)
                         for path in (cert, key)}
            with ExitStack() as resources, \
                    patch.object(DRIVER.shutil, "which", return_value=docker), \
                    patch.object(DRIVER.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "a" * 64)) as run, \
                    patch.object(DRIVER.FixtureDatabase, "sql", return_value="1"), \
                    patch.object(DRIVER.socket, "create_connection"):
                DRIVER.FixtureDatabase(root, {}, resources, postgres=True, cert=cert, key=key)
                creation = next(call.args[0] for call in run.call_args_list if call.args[0][1] == "create")
                script = creation[-1]
            staging, separator, postgres_args = script.partition("exec docker-entrypoint.sh postgres ")
            self.assertTrue(separator, "native PostgreSQL entrypoint must remain in use")
            settings = [value for value in shlex.split(postgres_args) if value.startswith("ssl_")]
            options = dict(value.split("=", 1) for value in settings)
            cert_path, key_path = options["ssl_cert_file"], options["ssl_key_file"]
            probe = ("set -e; "
                "cp /host-cert.pem /fixture-cert.pem; cp /host-key.pem /fixture-key.pem; "
                "chown 12345:12345 /fixture-cert.pem /fixture-key.pem; "
                "chmod 600 /fixture-cert.pem /fixture-key.pem; "
                "test \"$(id -u postgres)\" != 12345; "
                "if gosu postgres test -r /fixture-cert.pem; then exit 65; fi; "
                "if gosu postgres test -r /fixture-key.pem; then exit 66; fi; " + staging +
                "gosu postgres sh -ec 'test -r \"$1\"; test -r \"$2\"; "
                "test \"$(stat -c %a \"$1\")\" = 600; test \"$(stat -c %a \"$2\")\" = 600' "
                "sh " + shlex.quote(cert_path) + " " + shlex.quote(key_path))
            result = subprocess.run([docker, "run", "--rm", "--pull=never", "--network=none",
                "--security-opt=no-new-privileges", "--cap-drop=ALL", "--cap-add=CHOWN",
                "--cap-add=DAC_OVERRIDE", "--cap-add=FOWNER", "--cap-add=SETGID", "--cap-add=SETUID",
                "--mount", f"type=bind,src={cert},dst=/host-cert.pem,readonly",
                "--mount", f"type=bind,src={key},dst=/host-key.pem,readonly",
                DRIVER.POSTGRES_IMAGE, "bash", "-ec", probe], capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, "private TLS staging must work for the actual postgres UID")
            for path in (cert, key):
                self.assertEqual((path.read_bytes(), path.stat().st_mode, path.stat().st_uid), originals[path])
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

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
