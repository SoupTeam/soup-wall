# SPDX-License-Identifier: Apache-2.0
"""Offline safety checks for the disposable OIDC driver."""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

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


if __name__ == "__main__":
    unittest.main()
