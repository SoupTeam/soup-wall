"""A fixture mode transition must not change an already authenticated exchange."""
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "fixtures"))
from managed_policy_tls_edge import Edge, Handler


class EdgeEpochTests(unittest.TestCase):
    def policy_on_preaccepted_connection(self, initial_tamper, current_tamper):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            old = {"mode": "proxy", "certificate": "valid",
                   "upstream_host": "127.0.0.1", "upstream_port": 1,
                   "tamper_policy": initial_tamper}
            path.write_text(json.dumps(old))
            server = Edge.__new__(Edge)
            server.configuration = path
            accepted = SimpleNamespace()
            context = Mock()
            context.wrap_socket.return_value = accepted
            with patch("managed_policy_tls_edge.ThreadingHTTPServer.get_request",
                       return_value=(object(), ("127.0.0.1", 1))), \
                 patch("managed_policy_tls_edge.ssl.SSLContext", return_value=context):
                request, _ = Edge.get_request(server)
            # The connection already exists when the driver arms/disarms its
            # payload control, before issuing the new deployment/request.
            path.write_text(json.dumps({**old, "tamper_policy": current_tamper}))
            handler = Handler.__new__(Handler)
            handler.server, handler.request = server, request
            handler.path, handler.command = "/agent/v1/policy", "GET"
            handler.headers, handler.rfile, handler.wfile = {}, io.BytesIO(), io.BytesIO()
            handler.send_response = Mock()
            handler.send_header = Mock()
            handler.end_headers = Mock()
            handler.send_error = Mock()
            original = {"policy_yaml": "default: allow", "deployment_sequence": 4,
                        "signature": "owned-synthetic-signature"}
            with patch("managed_policy_tls_edge.http.client.HTTPConnection") as upstream:
                response = upstream.return_value.getresponse.return_value
                response.read.return_value = json.dumps(original).encode()
                response.status = 200
                Handler._serve(handler)
            self.assertEqual(request.edge_configuration, old)
            handler.send_response.assert_called_once_with(200)
            handler.send_error.assert_not_called()
            actual = json.loads(handler.wfile.getvalue())
            self.assertEqual(actual["deployment_sequence"], original["deployment_sequence"])
            self.assertEqual(actual["signature"], original["signature"])
            return original, actual

    def test_payload_tamper_arms_after_connection_before_deployment(self):
        original, actual = self.policy_on_preaccepted_connection(False, True)
        self.assertEqual(actual["policy_yaml"], original["policy_yaml"]
                         + "\n# owned SOU-82 tamper control\n")

    def test_payload_tamper_disarms_without_reusing_a_stale_fault(self):
        original, actual = self.policy_on_preaccepted_connection(True, False)
        self.assertEqual(actual, original)

    def test_request_uses_mode_selected_with_its_certificate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            old = {"mode": "redirect", "certificate": "valid",
                   "redirect": "http://127.0.0.1:1/owned-control"}
            new = {"mode": "proxy", "certificate": "wronghost",
                   "upstream_host": "127.0.0.1", "upstream_port": 1}
            path.write_text(json.dumps(old))
            server = Edge.__new__(Edge)
            server.configuration = path
            accepted = SimpleNamespace()

            def finish_handshake(raw, server_side):
                # Deterministically rotate the fixture between certificate
                # selection and HTTP handling; no timing sleeps or TLS bypass
                # are introduced in the production Agent.
                path.write_text(json.dumps(new))
                return accepted

            context = Mock()
            context.wrap_socket.side_effect = finish_handshake
            with patch("managed_policy_tls_edge.ThreadingHTTPServer.get_request",
                       return_value=(object(), ("127.0.0.1", 1))), \
                 patch("managed_policy_tls_edge.ssl.SSLContext", return_value=context):
                request, _ = Edge.get_request(server)
            context.load_cert_chain.assert_called_once_with("/tls/valid.pem", "/tls/valid.key")
            handler = Handler.__new__(Handler)
            handler.server, handler.request = server, request
            handler.path, handler.command = "/agent/v1/policy", "GET"
            handler.headers, handler.rfile, handler.wfile = {}, io.BytesIO(), io.BytesIO()
            handler.send_response = Mock()
            handler.send_header = Mock()
            handler.end_headers = Mock()
            handler.send_error = Mock()
            with patch("managed_policy_tls_edge.http.client.HTTPConnection") as upstream:
                upstream.return_value.getresponse.return_value.read.return_value = b""
                upstream.return_value.getresponse.return_value.status = 200
                Handler._serve(handler)
            upstream.assert_not_called()
            handler.send_response.assert_called_once_with(302)
            handler.send_header.assert_any_call("Location", old["redirect"])
            handler.send_error.assert_not_called()

    def test_new_connection_observes_new_certificate_and_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mode.json"
            current = {"mode": "proxy", "certificate": "wronghost"}
            path.write_text(json.dumps(current))
            accepted = SimpleNamespace()
            context = Mock()
            context.wrap_socket.return_value = accepted
            with patch("managed_policy_tls_edge.ThreadingHTTPServer.get_request",
                       return_value=(object(), ("127.0.0.1", 1))), \
                 patch("managed_policy_tls_edge.ssl.SSLContext", return_value=context):
                server = Edge.__new__(Edge)
                server.configuration = path
                request, _ = Edge.get_request(server)
            context.load_cert_chain.assert_called_once_with("/tls/wronghost.pem", "/tls/wronghost.key")
            self.assertEqual(request.edge_configuration, current)


if __name__ == "__main__":
    unittest.main()
