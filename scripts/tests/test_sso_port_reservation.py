# SPDX-License-Identifier: Apache-2.0
"""Real loopback ownership checks for disposable SSO fixture setup."""
from contextlib import ExitStack
import importlib.util
from pathlib import Path
import socket
import unittest

SPEC = importlib.util.spec_from_file_location("vendor_ports", Path(__file__).resolve().parents[1] / "keycloak-saml-acceptance.py")
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


class ReservedPorts(unittest.TestCase):
    def test_fixture_setup_cannot_reuse_the_gateway_port(self):
        with ExitStack() as resources:
            held = V.reserve_port(resources)
            host, port = held.getsockname()
            self.assertEqual(host, "127.0.0.1")
            with socket.socket() as competitor:
                competitor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                with self.assertRaises(OSError):
                    competitor.bind((host, port))
            # This models the independently bound TLS edge and PostgreSQL port.
            with socket.socket() as other:
                other.bind((host, 0))
                self.assertNotEqual(other.getsockname()[1], port)
            held.close()  # The one explicit handoff immediately before spawn.
            with socket.socket() as owned_backend:
                owned_backend.bind((host, port))
                owned_backend.listen(1)

    def test_fixture_failure_closes_the_reservation(self):
        with self.assertRaisesRegex(RuntimeError, "fixture failed"):
            with ExitStack() as resources:
                held = V.reserve_port(resources)
                address = held.getsockname()
                raise RuntimeError("fixture failed")
        self.assertEqual(held.fileno(), -1)
        with socket.socket() as probe:
            probe.bind(address)

    def test_normal_cleanup_and_repeated_close_do_not_leak(self):
        with ExitStack() as resources:
            held = V.reserve_port(resources)
            address = held.getsockname()
            held.close()
        self.assertEqual(held.fileno(), -1)
        with socket.socket() as probe:
            probe.bind(address)


if __name__ == "__main__":
    unittest.main()
