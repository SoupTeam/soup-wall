#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable SOU-43 HTTPS edge: nonloopback, operator-generated certs, no provider.

Run inside a private Docker bridge. The edge terminates TLS, forwarding only
policy-related requests to the disposable SQLite Console over the same bridge.
This is a TEST EDGE, not a production TLS proxy or a certificate-rotation path.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import pathlib
import ssl
import time
from urllib.parse import urlsplit

MAX_BYTES = 128_000


class Edge(ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler, configuration):
        self.configuration = configuration
        super().__init__(addr, handler)

    def get_request(self):
        raw, remote = super().get_request()
        mode = json.loads(self.configuration.read_text())
        certificate = mode.get("certificate", "valid")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(f"/tls/{certificate}.pem", f"/tls/{certificate}.key")
        return ctx.wrap_socket(raw, server_side=True), remote


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):
        # Deliberately never log request headers or Agent Bearer tokens.
        print(f"edge: {self.command} {self.path} status_event", flush=True)

    def do_GET(self):
        self._serve()

    def do_POST(self):
        self._serve()

    def _serve(self):
        config = json.loads(self.server.configuration.read_text())
        if self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if config.get("mode") == "redirect" and self.path.startswith("/agent/v1/"):
            self.send_response(302)
            self.send_header("Location", config["redirect"])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if config.get("mode") != "proxy":
            self.send_error(503, "test edge unavailable")
            return
        if not (self.path == "/healthz" or self.path.startswith("/agent/v1/")):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > MAX_BYTES:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        upstream = http.client.HTTPConnection(config["upstream_host"], config["upstream_port"], timeout=3)
        headers = {}
        for key in ("Authorization", "Content-Type"):
            if key in self.headers:
                headers[key] = self.headers[key]
        try:
            upstream.request(self.command, self.path, body=body, headers=headers)
            response = upstream.getresponse()
            payload = response.read(MAX_BYTES + 1)
            if len(payload) > MAX_BYTES:
                self.send_error(502)
                return
            # Owned negative control: preserve the signed identity while
            # changing its payload in transit. The Agent must reject it.
            if (config.get("tamper_policy") is True and self.command == "GET"
                    and self.path == "/agent/v1/policy" and response.status == 200):
                candidate = json.loads(payload)
                candidate["policy_yaml"] += "\n# owned SOU-82 tamper control\n"
                payload = json.dumps(candidate).encode("utf-8")
            self.send_response(response.status)
            self.send_header("Content-Length", str(len(payload)))
            # The HTTPS test edge proxies only JSON Agent API responses.
            # Never echo arbitrary upstream header bytes into TLS responses.
            if payload and self.path.startswith("/agent/v1/"):
                self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload)
        except (OSError, http.client.HTTPException):
            self.send_error(502)
        finally:
            upstream.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--configuration", type=pathlib.Path, default=pathlib.Path("/tls/mode.json"))
    args = parser.parse_args()
    for _ in range(100):
        if (pathlib.Path("/tls/valid.pem").exists()
                and pathlib.Path("/tls/valid.key").exists()
                and args.configuration.exists()):
            break
        time.sleep(0.2)
    else:
        raise SystemExit("TLS fixtures unavailable")
    with Edge(("0.0.0.0", 8443), Handler, args.configuration) as server:
        server.serve_forever(poll_interval=0.2)


if __name__ == "__main__":
    main()
