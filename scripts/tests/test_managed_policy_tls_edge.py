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
