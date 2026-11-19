# SPDX-License-Identifier: Apache-2.0
"""The local protocol witness must not reflect upstream HTTP metadata."""
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "macos_file_acceptance_headers", Path(__file__).parents[1] / "macos-file-acceptance.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RelayHeaders(unittest.TestCase):
    def test_untrusted_headers_never_reach_client(self):
        for headers in (
            [("X-Witness", "value\r\nX-Injected: yes")],
            [("X-Witness\r\nX-Injected", "yes")],
            [("Content-Length", "999"), ("Transfer-Encoding", "chunked"),
             ("Content-Type", "text/html"), ("Set-Cookie", "untrusted=yes")],
        ):
            with self.subTest(headers=headers):
                body = b'{"release":false}'
                response = Mock(status=403)
                response.read.return_value = body
                response.getheaders.return_value = headers
                connection = Mock()
                connection.getresponse.return_value = response
                handler = MODULE.RelayHandler.__new__(MODULE.RelayHandler)
                handler.server = SimpleNamespace(relay=MODULE.RelayState(1))
                handler.headers = {"Content-Length": "2"}
                handler.path = "/native/v1"
                handler.rfile = io.BytesIO(b"{}")
                handler.wfile = io.BytesIO()
                handler.request_version = "HTTP/1.1"
                handler.requestline = "POST /native/v1 HTTP/1.1"
                handler.command = "POST"
                with patch.object(MODULE.http.client, "HTTPConnection", return_value=connection):
                    handler.do_POST()
                raw_headers, actual_body = handler.wfile.getvalue().split(b"\r\n\r\n", 1)
                self.assertTrue(raw_headers.startswith(b"HTTP/1.0 403 "))
                self.assertIn(b"Content-Type: application/json", raw_headers)
                self.assertIn(b"Content-Length: 17", raw_headers)
                for marker in (b"X-Witness", b"X-Injected", b"Transfer-Encoding", b"Set-Cookie", b"text/html", b"999"):
                    self.assertNotIn(marker, raw_headers)
                self.assertEqual(actual_body, body)


if __name__ == "__main__":
    unittest.main()
