#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Finite owned TLS transport controls for the installed SOU-195 qualifier."""
import importlib.util
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener, HTTPSHandler


SCRIPTS = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


QUAL = load("ca_qualification_test", "pilot_provider_ca_qualification.py")
DEMO = load("ca_demo_test", "mcp-admission-demo.py")


@unittest.skipUnless(os.name == "posix" and Path("/usr/bin/openssl").is_file(),
                     "native Linux OpenSSL fixture required")
class ProviderCaTransport(unittest.TestCase):
    def test_early_source_refusal_and_started_process_boundary(self):
        early = {"status": "failed", "executed": False, "reason": "provider_transport_invalid"}
        self.assertTrue(QUAL.unsafe_source_refused(1, early, 0, "", ("synthetic-secret",)))
        for outcome, delivered, stderr in (
            (dict(early, executed=True), 0, ""),
            (dict(early, host_started=True), 0, ""),
            (early, 1, ""),
            (early, 0, "synthetic-secret"),
        ):
            self.assertFalse(QUAL.unsafe_source_refused(1, outcome, delivered, stderr,
                                                        ("synthetic-secret",)))

    def test_owned_https_selection_and_negative_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_ca = QUAL.material(root, "old-ca")
            other_ca = QUAL.material(root, "other-ca")
            certificates = [QUAL.material(root, "good", issuer=old_ca),
                            QUAL.material(root, "other", issuer=other_ca),
                            QUAL.material(root, "wrong-host", issuer=old_ca,
                                          hostname="wrong.invalid")]
            models = [QUAL.HTTPSModel(DEMO.ScriptedModel, cert, key)
                      for key, cert in certificates]
            try:
                for model in models:
                    model.expected_credential = "synthetic-secret"
                context = ssl.create_default_context(cafile=str(old_ca[1]))
                opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))

                def request(model):
                    data = json.dumps({"model": "owned", "tools": []}).encode()
                    return opener.open(Request(model.model.url + "/v1/messages", data=data,
                                               headers={"x-api-key": "synthetic-secret",
                                                        "Content-Type": "application/json"}),
                                       timeout=5)

                with request(models[0]) as response:
                    self.assertEqual(response.status, 200)
                self.assertEqual(len(models[0].auth), 1)
                self.assertEqual(models[0].model.server.successful_handshakes, 1)
                for bad in models[1:]:
                    with self.assertRaises((ssl.SSLError, URLError)):
                        request(bad)
                    self.assertEqual(bad.auth, [])
                    self.assertEqual(bad.model.requests, [])
            finally:
                for model in models:
                    model.close()


if __name__ == "__main__":
    unittest.main()
