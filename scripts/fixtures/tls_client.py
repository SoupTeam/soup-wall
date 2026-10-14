# SPDX-License-Identifier: Apache-2.0
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys


def probe(ca, hostname="localhost", path="/healthz", method="GET", body=None,
          token_file=None, port=8443, verify_hostname=None):
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    row = {"hostname": hostname, "path": path, "method": method,
           "verified": False, "http_status": None}
    if verify_hostname is not None:
        result = subprocess.run(["openssl", "s_client", "-connect", f"127.0.0.1:{port}",
                                 "-servername", hostname, "-verify_hostname", verify_hostname,
                                 "-verify_return_error", "-CAfile", str(ca)],
                                input=b"", capture_output=True, timeout=10)
        row.update(verification_client="openssl", verify_hostname=verify_hostname,
                   verified=result.returncode == 0)
        failure = re.search(rb"verify error:num=(\d+):([^\r\n]+)", result.stderr)
        if failure:
            row.update(error="certificate_verification_failed", verify_code=int(failure[1]),
                       diagnostic=failure[2].decode("utf-8", errors="replace"))
        elif result.returncode:
            row["error"] = "TLS_handshake_failed"
        return row
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as connection:
                cert = connection.getpeercert()
                row.update(verified=True, fingerprint_sha256=hashlib.sha256(
                    connection.getpeercert(binary_form=True)).hexdigest(),
                    not_before=cert["notBefore"], not_after=cert["notAfter"],
                    tls_version=connection.version(), cipher=connection.cipher()[0])
                payload = b"" if body is None else body
                headers = [f"{method} {path} HTTP/1.1", f"Host: {hostname}",
                           "Connection: close", f"Content-Length: {len(payload)}"]
                if body is not None:
                    headers.append("Content-Type: application/json")
                if token_file:
                    token = Path(token_file).read_text().strip()
                    headers += [f"x-llm-firewall-token: Bearer {token}",
                                "Authorization: Bearer local-provider-fixture"]
                connection.sendall(("\r\n".join(headers) + "\r\n\r\n").encode() + payload)
                response = http.client.HTTPResponse(connection)
                response.begin()
                data = response.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    raise ValueError("response exceeds the client bound")
                row.update(http_status=response.status,
                           response_sha256=hashlib.sha256(data).hexdigest(),
                           response_bytes=len(data))
                if response.status == 200 and path == "/v1/chat/completions":
                    result = json.loads(data)
                    row["useful_response"] = result["choices"][0]["message"]["content"] == "hello"
    except ssl.SSLCertVerificationError as error:
        row.update(error="certificate_verification_failed", verify_code=error.verify_code,
                   diagnostic=error.verify_message)
    except (OSError, ValueError, http.client.HTTPException) as error:
        row.update(error=type(error).__name__)
    return row


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--hostname", default="localhost")
    parser.add_argument("--verify-hostname")
    parser.add_argument("--path", default="/healthz")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--body-file", type=Path)
    parser.add_argument("--token-file", type=Path)
    args = parser.parse_args()
    row = probe(args.ca, args.hostname, args.path, args.method,
                args.body_file.read_bytes() if args.body_file else None, args.token_file,
                verify_hostname=args.verify_hostname)
    print(json.dumps(row, sort_keys=True))
    return 0 if row["verified"] and row["http_status"] is not None else 1


if __name__ == "__main__":
    sys.exit(main())
