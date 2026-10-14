#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Internal, synthetic provider witness for the opt-in Linux monitoring drill."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import threading

TEXT = "Useful monitored Gateway fixture response"


class Provider(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, receipt_file):
        super().__init__(address, Handler)
        self.receipt_file = receipt_file
        self.lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_json(self, status, data):
        raw = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/healthz":
            return self.send_json(200, {"status": "fixture"})
        return self.send_json(404, {})

    def do_POST(self):
        self.connection.settimeout(3)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if self.path != "/v1/chat/completions" or not 0 < size <= 65536:
                raise ValueError()
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise ValueError()
            body = json.loads(raw)
            if body.get("model") != "fixture-safe" or body.get("stream", False):
                raise ValueError()
            receipt = {"path": self.path, "body_sha256": hashlib.sha256(raw).hexdigest()}
            with self.server.lock:
                with self.server.receipt_file.open("a", encoding="utf-8") as output:
                    output.write(json.dumps(receipt) + "\n")
                    output.flush()
                    os.fsync(output.fileno())
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return self.send_json(400, {"status": "refused"})
        return self.send_json(200, {
            "id": "sou41-fixture-completion", "object": "chat.completion",
            "created": 1, "model": "fixture-safe",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": TEXT}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    with Provider(("0.0.0.0", args.port), args.receipts) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
