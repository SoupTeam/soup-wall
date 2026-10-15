#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real Linux MCP/native HTTPS GET acceptance using only owned local receivers.

Only --run starts processes. An already built exact clean candidate is required.
Exit 0 means complete passing evidence, 1 witnessed violation, 2 incomplete.
The native transport fixture forwards real authenticated daemon replies; it never
creates Allow. TLS retains normal CA/hostname/expiry checks with a disposable CA.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import http.client
import http.server
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/verify-sou54-create-file.py"
FIXTURE = ROOT / "scripts/fixtures/mcp_https_get_probe_server.py"
PROFILE = "sw-native/https-get/linux-pinned/1"
READ_TEXT = "SOU-56 useful continuation: 7 red widgets."
REPEATED = 70
SPEC = importlib.util.spec_from_file_location("sou56_process_helpers", HELPER)
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)
SPEC = importlib.util.spec_from_file_location("sou56_owned_receiver", FIXTURE)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
CASES = ("allow-json", "allow-text", "cookie-state", "native-deny", "native-ask", "classifier-deny", "classifier-ask",
         "url-substitution", "query-substitution", "host-substitution", "port-substitution", "http-scheme",
         "caller-headers", "caller-method", "caller-body", "url-credentials", "metadata-address", "private-address",
         "loopback-without-exception", "dns-address-substitution", "native-url-substitution", "native-authority-substitution",
         "redirect", "proxy-poisoning", "tls-hostname", "tls-untrusted", "tls-expired", "tls-invalid",
         "timeout", "oversize", "invalid-utf8", "invalid-json", "unsupported-compression", "unsupported-content",
         "unsupported-charset", "http-error", "result-withheld", "repeated-failures", "cross-session", "replayed-id",
         "queued-cancellation", "queued-overlap", "unsupported-chunked", "massive-header", "informational-response",
         "truncated-body", "duplicate-content-length")
PROTOCOL = {"replayed-id", "queued-cancellation", "queued-overlap"}
HELD = {"queued-cancellation", "queued-overlap"}
PROXIED = HELD | {"native-url-substitution", "native-authority-substitution", "cross-session"}
SUCCESS = {"allow-json", "allow-text", "cookie-state", "proxy-poisoning", "cross-session", "replayed-id"}
ZERO = {"native-deny", "native-ask", "classifier-deny", "classifier-ask", "url-substitution", "query-substitution",
        "host-substitution", "port-substitution", "http-scheme", "caller-headers", "caller-method", "caller-body",
        "url-credentials", "metadata-address", "private-address", "loopback-without-exception", "dns-address-substitution",
        "native-url-substitution", "native-authority-substitution"} | HELD
TLS_FAILURES = {"tls-hostname", "tls-untrusted", "tls-expired", "tls-invalid"}
ERRORS = {"redirect": {"unsupported_http_response"}, "timeout": {"request_timeout"}, "oversize": {"response_too_large"},
          "invalid-utf8": {"invalid_response_utf8"}, "invalid-json": {"invalid_response_json"},
          "unsupported-compression": {"unsupported_content_encoding"}, "unsupported-content": {"unsupported_content_type"},
          "unsupported-charset": {"unsupported_content_type"}, "http-error": {"unsupported_http_response"},
          "unsupported-chunked": {"unsupported_transfer_encoding"}, "massive-header": {"response_headers_too_large"},
          "informational-response": {"unsupported_http_response"}, "truncated-body": {"incomplete_response_body", "response_read_failed"},
          "duplicate-content-length": {"invalid_content_length"}, "repeated-failures": {"invalid_response_utf8"},
          "dns-address-substitution": {"dns_address_substitution"}, **{name: {"tls_verification_failed"} for name in TLS_FAILURES}}


class ExpectedStartupRefusal(Exception):
    """Control flow for one deliberately invalid operator installation."""


def certificates(root):
    """Create a real owned CA and valid, wrong-host and expired leaves, without dependencies."""
    root.mkdir(mode=0o700)
    def openssl(*args):
        return subprocess.run(["openssl", *args], cwd=root, check=True, stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=15)
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-subj", "/CN=SOU56-Disposable-CA", "-days", "2", "-keyout", "ca.key", "-out", "ca.pem",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash")
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-subj", "/CN=SOU56-Owned-Receiver", "-keyout", "server.key", "-out", "server.csr")
    (root / "index").write_text("")
    (root / "serial").write_text("01\n")
    for name, san in (("valid", "IP:127.0.0.1"), ("wrong-host", "DNS:wrong.invalid"), ("expired", "IP:127.0.0.1")):
        config = ("[ca]\ndefault_ca=owned\n[owned]\ndir=" + str(root) + "\ndatabase=$dir/index\n"
                  "new_certs_dir=$dir\ncertificate=$dir/ca.pem\nprivate_key=$dir/ca.key\nserial=$dir/serial\n"
                  "default_md=sha256\ndefault_days=2\npolicy=names\nunique_subject=no\nx509_extensions=server\n"
                  "[names]\ncommonName=supplied\n[server]\nbasicConstraints=critical,CA:FALSE\n"
                  "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\n"
                  "authorityKeyIdentifier=keyid,issuer\nsubjectAltName=" + san + "\n")
        config_path = root / (name + ".cnf")
        config_path.write_text(config)
        extra = ["-startdate", "20200101000000Z", "-enddate", "20200102000000Z"] if name == "expired" else []
        openssl("ca", "-batch", "-config", str(config_path), "-in", "server.csr", "-out", name + ".pem", "-notext", *extra)
    witness = {}
    for name in ("ca", "valid", "wrong-host", "expired"):
        path = root / (name + ".pem")
        witness[name] = {"sha256": H.sha(path.read_bytes()),
                         "certificate": path.read_text(),
                         "details": openssl("x509", "-in", str(path), "-noout", "-dates", "-subject", "-issuer").stdout.decode()}
    witness["openssl"] = openssl("version").stdout.decode().strip()
    return witness


def registry(workspace, url, port, ca_pem, binary_digest, classifier_digest, name):
    network = {"exact_url": url, "approved_addresses": ["127.0.0.1"],
               "private_endpoint": {"host": "127.0.0.1", "port": port, "address": "127.0.0.1"},
               "root_certificate_pem": ca_pem}
    if name == "loopback-without-exception":
        network["private_endpoint"] = None
    if name == "dns-address-substitution":
        url = url.replace("127.0.0.1", "localhost")
        network["exact_url"] = url
        network["private_endpoint"]["host"] = "localhost"
        network["approved_addresses"] = ["127.0.0.2"]
        network["private_endpoint"]["address"] = "127.0.0.2"
    if name == "tls-untrusted":
        network["root_certificate_pem"] = None
    declarations = []
    for tool in F.TOOLS:
        fetch = tool["name"] == "https_get"
        resource = {"profile": {"server_id": "sou56", "tool_name": tool["name"],
            "schema_sha256": H.sha(H.canonical(tool["inputSchema"])),
            "selectors": [{"pointer": "/url" if fetch else "/path", "kind": "url" if fetch else "path"}]},
            "workspace": str(workspace), "cwd": str(workspace),
            "executor_sha256": H.sha(PROFILE.encode()) if fetch else binary_digest,
            "classifier_sha256": classifier_digest,
            "allowed_resources": ([{"kind": "url", "canonical": url, "host": "localhost" if name == "dns-address-substitution" else "127.0.0.1", "port": port}]
                                  if fetch else [{"kind": "path", "canonical": str(workspace / "inventory.txt")}])}
        if fetch:
            resource["network"] = network
        declarations.append({"name": tool["name"], "schema_sha256": H.sha(H.canonical(tool["inputSchema"])),
            "action_class": "network" if fetch else "read_only", "result_provenance": "untrusted",
            "egress": [{"pointer": "/url", "kind": "url_host", "optional": False}] if fetch else [],
            "resource_policy": resource})
    return {"contract_version": "sw-native/1", "registry_id": "sou56-https-get-v1", "tools": declarations}


def policy_for(name):
    egress = "egress_allowlist: [127.0.0.1, localhost]\n"
    if name in {"native-deny", "native-ask"}:
        action = name.removeprefix("native-")
        return (egress + "agent_policies:\n  - name: sou56-explicit-" + action + "\n    when: { action_class: network }\n"
                "    action: " + action + "\ndefault: allow\n")
    if name == "result-withheld":
        return (egress + "agent_policies:\n  - name: sou56-withhold-result-injection\n"
                "    when: { detector: injection, facet: tool_result }\n    action: deny\ndefault: allow\n")
    return egress + "agent_policies: []\ndefault: allow\n"


def arguments_for(name, url, alternate_port):
    arguments = {"url": url}
    if name == "url-substitution":
        arguments["url"] = url.replace("/document", "/unapproved")
    elif name == "query-substitution":
        arguments["url"] = url.replace("item=7", "item=8")
    elif name == "host-substitution":
        arguments["url"] = url.replace("127.0.0.1", "localhost")
    elif name == "port-substitution":
        arguments["url"] = "https://127.0.0.1:" + str(alternate_port) + "/document?item=7"
    elif name == "http-scheme":
        arguments["url"] = url.replace("https:", "http:")
    elif name in {"caller-headers", "caller-method", "caller-body"}:
        arguments[name.removeprefix("caller-")] = {"X-SOU56": "MUST-NOT-SEND"} if name.endswith("headers") else "POST" if name.endswith("method") else "MUST-NOT-SEND"
    elif name == "url-credentials":
        arguments["url"] = url.replace("https://", "https://synthetic-user:must-not-send@")
    elif name == "metadata-address":
        arguments["url"] = "https://169.254.169.254/latest/meta-data/"
    elif name == "private-address":
        arguments["url"] = "https://10.0.0.1/private"
    return arguments


class NativeProxy:
    """Owned transport fault fixture forwarding real authenticated replies unchanged."""
    def __init__(self, upstream_port, name):
        self.rows, self.lock = [], threading.Lock()
        self.ready, self.release, self.session_ended, self.idle = (threading.Event() for _ in range(4))
        self.idle.set()
        self.active, self.first_session = 0, None
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                connection = None
                row = {"path": self.path, "authorization_header_retained": False}
                with owner.lock:
                    owner.active += 1
                    owner.idle.clear()
                try:
                    H.require(self.path in {"/native/v1", "/mcp"}, "unexpected native fixture path")
                    length = int(self.headers.get("Content-Length", "0"))
                    H.require(0 < length <= 1024 * 1024, "native fixture body bound")
                    raw = self.rfile.read(length)
                    original, forwarded = H.strict_json(raw), H.strict_json(raw)
                    fetch = original.get("event") == "call" and original.get("tool") == "https_get"
                    if fetch and name == "native-url-substitution":
                        forwarded["args"]["url"] += "&unauthorized=1"
                    if fetch and name == "native-authority-substitution":
                        forwarded["resource_admission"]["network"]["authority_sha256"] = "f" * 64
                    if fetch and name == "cross-session":
                        if owner.first_session is None:
                            owner.first_session = original["session_id"]
                        else:
                            forwarded["session_id"] = owner.first_session
                    sent = H.canonical(forwarded) if forwarded != original else raw
                    connection = http.client.HTTPConnection("127.0.0.1", upstream_port, timeout=8)
                    connection.request("POST", self.path, body=sent, headers={"Authorization": self.headers.get("Authorization", ""),
                                       "Content-Type": "application/json", "Content-Length": str(len(sent))})
                    reply = connection.getresponse()
                    reply_raw = reply.read(65537)
                    H.require(len(reply_raw) <= 65536, "native fixture reply bound")
                    row.update(original_raw=raw.decode(), forwarded_raw=sent.decode(), reply_raw=reply_raw.decode(),
                        original_sha256=H.sha(raw), forwarded_sha256=H.sha(sent), reply_sha256=H.sha(reply_raw),
                        upstream_status=reply.status, upstream_completed_at=time.monotonic())
                    value = H.strict_json(reply_raw)
                    if fetch and name in HELD:
                        H.require(reply.status == 200 and value.get("release") is True and value.get("verdict") == "allow",
                                  "genuine native Allow missing")
                        row["held"] = True
                        owner.ready.set()
                    if original.get("event") == "session_end" and reply.status == 200:
                        owner.session_ended.set()
                    with owner.lock:
                        owner.rows.append(row)
                    if row.get("held"):
                        H.require(owner.release.wait(timeout=12), "bounded native Allow hold expired")
                        row["released_at"] = time.monotonic()
                    self.send_response(reply.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(reply_raw)))
                    self.end_headers()
                    self.wfile.write(reply_raw)
                    self.wfile.flush()
                    row["downstream_delivered"] = True
                except (OSError, ValueError, KeyError, http.client.HTTPException) as error:
                    row["error"] = type(error).__name__ + ": " + str(error)
                    with owner.lock:
                        if not any(value is row for value in owner.rows):
                            owner.rows.append(row)
                finally:
                    if connection:
                        connection.close()
                    self.close_connection = True
                    with owner.lock:
                        owner.active -= 1
                        if owner.active == 0:
                            owner.idle.set()
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.closed_cleanly = self.idle.wait(timeout=8) and not self.thread.is_alive()


def grade(row):
    """Independent receiver, actual native gates and released bytes must all agree."""
    try:
        name = row["case"]
        H.require(name in CASES and row.get("error") is None, "unknown or incomplete observation")
        H.require(row["workspace_before"] == row["workspace_after"], "network executor changed owned workspace")
        receiver = H.json_lines(row["receiver_raw"].encode())
        secondary = H.json_lines(row["secondary_raw"].encode())
        poison = H.json_lines(row["proxy_receiver_raw"].encode())
        for ledger in (receiver, secondary, poison):
            H.require(sum(value.get("event") == "receiver_started" for value in ledger) == 1
                      and sum(value.get("event") == "receiver_closed" for value in ledger) == 1,
                      "independent receiver lifecycle witness missing")
        requests = [value for value in receiver if value.get("event") == "request"]
        connections = [value for value in receiver if value.get("event") == "connection"]
        expected = 0 if name in ZERO | TLS_FAILURES else REPEATED if name == "repeated-failures" else 2 if name == "cookie-state" else 1
        H.require(len(requests) == expected, "unexpected number of actual receiver requests")
        if name in ZERO:
            H.require(not connections, "preexecution refusal opened a receiver socket")
        if name in TLS_FAILURES:
            H.require(len(connections) == 1, "TLS rejection did not attempt exactly one owned transport")
        if name not in ZERO | TLS_FAILURES:
            H.require(len(connections) == expected, "executor retried or opened extra receiver sockets")
        H.require(not any(value.get("event") in {"request", "connection"} for value in secondary),
                  "unauthorized second origin received transport or request")
        H.require(not any(value.get("event") in {"request", "connection"} for value in poison),
                  "inherited proxy received transport or request")
        for request in requests:
            H.require(request.get("method") == "GET" and request.get("target") == "/document?item=7"
                      and request.get("host") == row["expected_host"], "receiver target/method/Host authority changed")
            headers = request["headers"]
            H.require(not any(key in headers for key in ("authorization", "proxy-authorization", "cookie", "content-length", "transfer-encoding")),
                      "implicit credentials/cookies/body reached receiver")
        if name in SUCCESS | {"result-withheld"}:
            responses = [value for value in receiver if value.get("event") == "response"]
            expected_body = F.INJECTION if name == "result-withheld" else F.DOCUMENT
            H.require(len(responses) == expected and all(value.get("status") == 200
                      and value.get("bytes") == len(expected_body.encode())
                      and value.get("sha256") == H.sha(expected_body.encode()) for value in responses),
                      "independent response-byte witness disagrees with useful/withheld result")
        if name == "loopback-without-exception":
            H.require(row.get("startup_refused") is True and type(row.get("daemon_exit_code")) is int
                      and row["daemon_exit_code"] != 0 and "forbidden_address" in row["daemon_raw"]
                      and row["sessions"] == [] and row["owned_fixture_removed"] is True,
                      "unsafe operator configuration was not explicitly refused at startup")
            return {"status": "pass", "reason": "invalid loopback authority refused at startup; independent receivers saw zero transport"}
        native = H.json_lines(row["native_audit_raw"].encode())
        starts = [value for value in native if value.get("event") == "native_session_start"]
        ends = [value for value in native if value.get("event") == "native_session_end"]
        sessions = row["sessions"]
        H.require(len(sessions) == (2 if name in PROTOCOL or name == "cross-session" else 1), "wrong MCP session count")
        H.require(len(starts) == len(ends) == len(sessions) and len({value["session"] for value in starts}) == len(sessions)
                  and {value["session"] for value in starts} == {value["session"] for value in ends},
                  "native session cleanup/isolation missing")
        for session in sessions:
            H.require(session["child_ledger_present"] is True and session["child_started_raw"] == "started\n"
                      and session["child_ledger_raw"] == "", "discovery child executed a call or ledger missing")
            child_input = H.json_lines(session["child_input_raw"].encode())
            H.require([value.get("method") for value in child_input] == ["initialize", "notifications/initialized", "tools/list"],
                      "unexpected discovery traffic")
            clients = H.json_lines(session["client_raw"].encode())
            H.require(H.json_lines(session["child_output_raw"].encode()) == clients[:2], "discovery response changed")
            closure = session["closure"]
            H.require(closure.get("stdout_eof") is True and closure.get("reader_joined") is True
                      and closure.get("forced_cleanup") is False, "collector closure incomplete")
            abnormal = name in PROTOCOL and session["label"] == "primary"
            if abnormal:
                reason = "replayed MCP request" if name == "replayed-id" else "concurrent MCP requests are not supported"
                H.require(closure.get("exit_code") != 0 and reason in session["collector_raw"], "unrelated failure is not protocol refusal")
                H.require(len(clients) == (3 if name == "replayed-id" else 2), "reply released after protocol refusal")
            else:
                H.require(closure.get("exit_code") == 0 and session["child_closed_raw"] == "closed\n", "MCP session did not close cleanly")
                follow = H.strict_json(session["useful"]["reply_raw"])
                H.require(follow == clients[-1] and follow.get("id") == session["useful"]["request"]["id"]
                          and follow.get("result", {}).get("isError") is not True
                          and follow.get("result", {}).get("content") == [{"type": "text", "text": READ_TEXT}],
                          "useful same-session continuation missing")
                useful_gates = [value for value in native if value.get("tool") == "read_document"
                                and value.get("event") in {"native_call", "native_result"}
                                and value.get("session") == session["native_session_id"]]
                H.require([value["event"] for value in useful_gates] == ["native_call", "native_result"]
                          and all(value.get("released") is True and value.get("shadow") is False
                                  and value.get("verdict") == "allow" for value in useful_gates),
                          "useful continuation bypassed enforcing native gates")
            attempts = session.get("attempts", [])
            H.require(len(clients) == 2 + len(attempts) + (0 if abnormal else 1), "missing/extra released responses")
            for index, attempt in enumerate(attempts):
                response = H.strict_json(attempt["reply_raw"])
                H.require(response == clients[index + 2] and response.get("id") == attempt["request"]["id"]
                          and response.get("jsonrpc") == "2.0", "original MCP response/ID bytes changed")
                result = response.get("result")
                H.require(isinstance(result, dict), "ordinary MCP result/refusal missing")
                if attempt["success"]:
                    H.require(result.get("isError") is not True, "useful allowed fetch interrupted")
                    H.require(len(result["content"]) == 2 and all(value.get("type") == "text" for value in result["content"]),
                              "metadata/raw fetched content boundary missing")
                    payload = H.strict_json(result["content"][0]["text"])
                    H.require(payload.get("success") is True and payload.get("status") == 200 and "text" not in payload and result["content"][1]["text"] == F.DOCUMENT
                              and payload.get("received_bytes") == len(F.DOCUMENT.encode())
                              and payload.get("request_issued") is True, "successful body/byte/effect receipt disagrees")
                    H.require(type(payload.get("received_http_bytes")) is int and type(payload.get("received_encrypted_bytes")) is int
                              and payload["received_bytes"] < payload["received_http_bytes"] <= 16384
                              and payload["received_http_bytes"] < payload["received_encrypted_bytes"] <= 65536,
                              "bounded actual plaintext/encrypted receive counters missing or inconsistent")
                else:
                    H.require(result.get("isError") is True, "failed/refused fetch returned success")
                    if name in ERRORS:
                        H.require(len(result.get("content", [])) == 1, "failed fetch exposed partially inspected body")
                        error = H.strict_json(result["content"][0]["text"])
                        H.require(error.get("success") is False and error.get("error") in ERRORS[name]
                                  and error.get("request_issued") is (name not in TLS_FAILURES | {"dns-address-substitution"}),
                                  "actual transport/content error or request-effect receipt missing")
                if name == "result-withheld":
                    H.require("Soup Wall withheld MCP result" in attempt["reply_raw"], "untrusted fetched result was not withheld")
                meta = attempt["request"]["params"]["_meta"]
                H.require(meta == {"claudecode/toolUseId": "toolu_" + attempt["request"]["id"], "progressToken": 0},
                          "host correlation metadata changed")
            predictions = H.classify_rows(session["collector_raw"].encode())
            H.require(all(value.get("classifier_sha256") == row["configuration"]["classifier_sha256"] for value in predictions),
                      "classifier identity changed")
            if not abnormal:
                H.require(predictions and predictions[-1].get("host_call_id") == session["useful"]["request"]["id"],
                          "useful classifier continuation witness missing")
            for prediction in predictions:
                attempt = next((a for a in attempts if a["request"]["id"] == prediction.get("host_call_id")), None)
                if attempt:
                    H.require(prediction.get("args_sha256") == H.sha(H.canonical(attempt["request"]["params"]["arguments"])),
                              "classification original arguments changed")
        executions = [value for session in sessions for value in H.classify_rows(session["collector_raw"].encode(), "mcp_https_get_execution")]
        execution_count = 0 if name in ZERO - {"dns-address-substitution"} else REPEATED if name == "repeated-failures" else 2 if name == "cookie-state" else 1
        H.require(len(executions) == execution_count, "actual broker execution boundary count missing or inconsistent")
        for execution in executions:
            attempt = next((value for session in sessions for value in session.get("attempts", [])
                            if value["request"]["id"] == execution.get("host_call_id")), None)
            H.require(attempt is not None, "execution lost original host-call identifier")
            if name == "result-withheld" or attempt["success"]:
                H.require(execution.get("result_kind") == "value" and execution.get("request_issued") is True
                          and execution.get("error") is None, "actual successful execution/effect witness missing")
            elif name in ERRORS:
                H.require(execution.get("result_kind") == "error" and execution.get("error") in ERRORS[name]
                          and execution.get("request_issued") is (name not in TLS_FAILURES | {"dns-address-substitution"}),
                          "actual failure execution/effect witness missing")
        fetch_calls = [value for value in native if value.get("event") == "native_call" and value.get("tool") == "https_get"]
        fetch_results = [value for value in native if value.get("event") == "native_result" and value.get("tool") == "https_get"]
        if name in SUCCESS | {"result-withheld"} | set(ERRORS):
            H.require(any(value.get("verdict") == "allow" and value.get("released") is True and value.get("shadow") is False
                          for value in fetch_calls), "real native execution Allow missing")
            H.require(fetch_results, "actual result/error never reached native inspection")
            for result in fetch_results:
                matches = [value for value in fetch_calls if value.get("call_id") == result.get("call_id")
                           and value.get("binding_sha256") == result.get("binding_sha256") and value.get("session") == result.get("session")]
                H.require(len(matches) == 1 and result.get("call_id") and result.get("binding_sha256"), "native result correlation lost")
            if name == "result-withheld":
                H.require(len(fetch_results) == 1 and fetch_results[0].get("released") is False, "withheld result release changed")
        if name in {"native-deny", "native-ask", "classifier-deny", "classifier-ask"}:
            H.require(not fetch_results and not any(value.get("released") is True for value in fetch_calls),
                      "Deny/unapproved Ask obtained execution/result release")
        if name in PROXIED:
            H.require(row["proxy_closed_cleanly"] is True and row["proxy_exchanges"], "authenticated native proxy incomplete")
            for exchange in row["proxy_exchanges"]:
                H.require(exchange.get("error") is None and exchange.get("authorization_header_retained") is False,
                          "proxy transport error or unsafe credential retention")
                for field in ("original", "forwarded", "reply"):
                    H.strict_json(exchange[field + "_raw"])
                    H.require(H.sha(exchange[field + "_raw"].encode()) == exchange[field + "_sha256"], "proxy raw digest mismatch")
            changed = [value for value in row["proxy_exchanges"] if value["original_raw"] != value["forwarded_raw"]]
            if name in {"native-url-substitution", "native-authority-substitution", "cross-session"}:
                H.require(len(changed) == 1 and H.strict_json(changed[0]["reply_raw"]).get("release") is False,
                          "real daemon accepted substituted/cross-session authority")
            if name in HELD:
                held = [value for value in row["proxy_exchanges"] if value.get("held")]
                H.require(len(held) == 1 and row["session_end_before_release"] is True
                          and held[0]["upstream_completed_at"] <= row["queued_at"] < row["release_at"]
                          and H.strict_json(held[0]["reply_raw"]).get("verdict") == "allow",
                          "cancellation/overlap did not race a genuine held Allow")
        H.require(row["owned_fixture_removed"] is True, "owned temporary fixture leaked")
        return {"status": "pass", "reason": "owned receiver, authenticated native gates, client bytes and continuation agree"}
    except (ValueError, KeyError, TypeError, IndexError) as error:
        return {"status": "fail", "reason": str(error)}


def run_case(repo, binary, name, binary_digest, certificate_dir, certificate_witness):
    started = time.monotonic()
    row = {"case": name, "sessions": []}
    daemon = proxy = None
    receivers, collectors, logs = [], [], []
    with tempfile.TemporaryDirectory(prefix="sou56-https-", dir=Path(tempfile.gettempdir()).resolve()) as temporary:
        root = Path(temporary).resolve()
        home, workspace = root / "home", root / "workspace"
        for path in (home, workspace):
            path.mkdir(mode=0o700)
        (workspace / "inventory.txt").write_text(READ_TEXT, encoding="utf-8")
        env = H.private_environment(home)
        row["workspace_before"] = H.tree_snapshot(workspace)
        def read(path):
            return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
        def receiver(label, mode="document", *, plain=False, redirect_to=None):
            ledger, ready, log_path = root / (label + ".jsonl"), root / (label + ".ready"), root / (label + ".log")
            log = log_path.open("wb")
            logs.append(log)
            cert = "wrong-host" if name == "tls-hostname" and label == "receiver" else "expired" if name == "tls-expired" and label == "receiver" else "valid"
            command = [sys.executable, "-I", "-u", str(FIXTURE), "--https", "--ledger", str(ledger), "--ready", str(ready),
                       "--cert", str(certificate_dir / (cert + ".pem")), "--key", str(certificate_dir / "server.key"), "--mode", mode]
            if plain:
                command.append("--plain-http")
            if redirect_to:
                command += ["--redirect-to", redirect_to]
            process = subprocess.Popen(command, env=env, cwd=root, stdout=log, stderr=log, start_new_session=True)
            item = {"label": label, "process": process, "ledger": ledger, "log": log_path}
            receivers.append(item)
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and process.poll() is None and not ready.is_file():
                time.sleep(.02)
            H.require(ready.is_file(), "owned receiver did not become ready")
            value = H.strict_json(ready.read_bytes())
            H.require(value.get("pid") == process.pid and type(value.get("port")) is int, "receiver readiness identity mismatch")
            item["ready"] = value
            return value["port"]
        try:
            secondary_port = receiver("secondary")
            poisoned_port = receiver("proxy_receiver", plain=True)
            mode = {"allow-text": "text", "redirect": "redirect", "oversize": "oversize", "invalid-utf8": "invalid-utf8",
                    "invalid-json": "invalid-json", "unsupported-compression": "compressed", "unsupported-content": "binary",
                    "unsupported-charset": "charset", "result-withheld": "injection", "timeout": "timeout",
                    "http-error": "status", "repeated-failures": "invalid-utf8", "unsupported-chunked": "chunked",
                    "massive-header": "massive-header", "informational-response": "informational", "truncated-body": "truncated",
                    "duplicate-content-length": "duplicate-length", "tls-invalid": "invalid-tls"}.get(name, "document")
            port = receiver("receiver", mode, plain=name == "tls-invalid", redirect_to="https://127.0.0.1:" + str(secondary_port) + "/must-not-follow")
            url = "https://127.0.0.1:" + str(port) + "/document?item=7"
            row["expected_host"] = "127.0.0.1:" + str(port)
            install = subprocess.run([str(binary), "install"], env=env, cwd=root, stdin=subprocess.DEVNULL,
                                     capture_output=True, timeout=20)
            H.require(install.returncode == 0, "isolated Agent install failed")
            classifier = repo / "rule_baseline/rule_baseline.py"
            if name.startswith("classifier-"):
                classifier = root / "synthetic-classifier.py"
                classifier.write_text(H.synthetic_classifier(name.removeprefix("classifier-")).replace("create_file", "https_get"))
            classifier_digest = H.sha(classifier.read_bytes())
            registry_path, policy_path = root / "registry.json", root / "policy.yaml"
            registry_bytes = H.canonical(registry(workspace, url, port, certificate_witness["ca"]["certificate"], binary_digest,
                                                classifier_digest, name))
            registry_path.write_bytes(registry_bytes)
            policy_path.write_text(policy_for(name))
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                daemon_port = probe.getsockname()[1]
            config = {"port": daemon_port, "enforce": True, "policy": str(policy_path),
                      "native": {"registry_path": str(registry_path), "registry_sha256": H.sha(registry_bytes)}}
            config_path = home / ".agentfw/config.yaml"
            config_path.write_bytes(H.canonical(config))
            row["configuration"] = {"registry": H.strict_json(registry_bytes), "registry_sha256": H.sha(registry_bytes),
                "policy": policy_path.read_text(), "policy_sha256": H.sha(policy_path.read_bytes()),
                "daemon_config_sha256": H.sha(config_path.read_bytes()), "classifier_sha256": classifier_digest,
                "synthetic_classifier": name.startswith("classifier-"), "tls_leaf": "wrong-host" if name == "tls-hostname" else "expired" if name == "tls-expired" else "valid"}
            daemon_stream = (root / "daemon.log").open("wb")
            logs.append(daemon_stream)
            daemon = subprocess.Popen([str(binary), "serve"], env=env, cwd=root, stdout=daemon_stream,
                                      stderr=daemon_stream, start_new_session=True)
            if name == "loopback-without-exception":
                daemon.wait(timeout=8)
                H.require(daemon.returncode != 0, "unsafe loopback operator installation was accepted")
                row.update(startup_refused=True, daemon_exit_code=daemon.returncode)
                raise ExpectedStartupRefusal()
            H.require(H.healthy(daemon_port, daemon), "isolated enforcing daemon did not become healthy")
            if name in PROXIED:
                proxy = NativeProxy(daemon_port, name)
                config["port"] = proxy.port
                config_path.write_bytes(H.canonical(config))
                row["configuration"]["collector_config_sha256"] = H.sha(config_path.read_bytes())
            collector_env = dict(env, AGENTFW_CLASSIFIER="rule-baseline", AGENTFW_RULE_BASELINE=str(classifier),
                                 AGENTFW_CLASSIFIER_PYTHON=sys.executable, AGENTFW_WORKSPACE=str(workspace))
            if name == "proxy-poisoning":
                poison = "http://127.0.0.1:" + str(poisoned_port)
                collector_env.update({key: poison for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")})
                collector_env.update(NO_PROXY="", no_proxy="")
                row["configuration"]["poisoned_proxy"] = poison
            def start(label):
                ledger, log_path = root / (label + "-child.jsonl"), root / (label + "-collector.log")
                log = log_path.open("wb")
                logs.append(log)
                command = [str(binary), "mcp", "--native-admission", "--id", "sou56", "--", sys.executable,
                           "-I", "-u", str(FIXTURE), "--ledger", str(ledger)]
                collector = H.Collector(command, collector_env, workspace, log)
                item = {"label": label, "collector": collector, "ledger": ledger, "log_path": log_path, "attempts": []}
                collectors.append(item)
                H.require(collector.send({"jsonrpc": "2.0", "id": "init", "method": "initialize", "params": {
                    "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "sou56-probe", "version": "1"}}}), "MCP initialize missing")
                collector.send({"jsonrpc": "2.0", "method": "notifications/initialized"}, reply=False)
                listing = collector.send({"jsonrpc": "2.0", "id": "list", "method": "tools/list"})
                H.require(listing and H.strict_json(listing).get("result", {}).get("tools") == F.TOOLS, "discovery manifest mismatch")
                return item
            def useful(item):
                request = H.frame("useful-" + item["label"], "read_document", {"path": str(workspace / "inventory.txt")})
                reply = item["collector"].send(request)
                H.require(reply is not None, "useful continuation missing")
                item["useful"] = {"request": request, "reply_raw": reply.decode()}
            def fetch(item, call_id, arguments, success):
                request = H.frame(call_id, "https_get", arguments)
                sent_at = time.monotonic()
                reply = item["collector"].send(request)
                H.require(reply is not None, "HTTPS fetch reply missing")
                item["attempts"].append({"request": request, "reply_raw": reply.decode(), "success": success,
                                         "latency_ms": round((time.monotonic() - sent_at) * 1000, 6)})
                return request
            primary = start("primary")
            arguments = arguments_for(name, url, secondary_port)
            if name == "dns-address-substitution":
                arguments["url"] = url.replace("127.0.0.1", "localhost")
            if name in HELD:
                original = H.frame("fetch-1", "https_get", arguments)
                primary["collector"].send(original, reply=False)
                H.require(proxy.ready.wait(timeout=10), "genuine native Allow hold missing")
                queued = (H.frame("overlap", "https_get", arguments) if name == "queued-overlap" else {
                    "jsonrpc": "2.0", "method": "notifications/cancelled", "params": {
                        "requestId": original["id"], "reason": "SOU56 owned cancellation before held real Allow"}})
                primary["collector"].send(queued, reply=False)
                row.update(queued_at=time.monotonic(), queued_frame=queued, original_frame=original)
                row["session_end_before_release"] = proxy.session_ended.wait(timeout=5)
                H.require(row["session_end_before_release"], "native session not ended before held receipt release")
                row["release_at"] = time.monotonic()
                proxy.release.set()
            else:
                for index in range(REPEATED if name == "repeated-failures" else 2 if name == "cookie-state" else 1):
                    original = fetch(primary, "fetch-" + str(index + 1), arguments, name in SUCCESS)
                if name == "replayed-id":
                    row["replayed_frame"] = original
                    primary["collector"].send(original, reply=False)
            if name in PROTOCOL:
                primary["closure"] = primary["collector"].close()
                primary["closed"] = True
                fresh = start("fresh-after-refusal")
                useful(fresh)
            elif name == "cross-session":
                useful(primary)
                primary["closure"] = primary["collector"].close()
                primary["closed"] = True
                second = start("second-session")
                fetch(second, "cross-session-fetch", arguments, False)
                useful(second)
            else:
                useful(primary)
        except ExpectedStartupRefusal:
            pass
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError, queue.Empty) as error:
            row["error"] = type(error).__name__ + ": " + str(error)
        finally:
            if proxy:
                proxy.release.set()
            for item in collectors:
                if not item.get("closed"):
                    item["closure"] = item["collector"].close()
            H.stop_owned(daemon)
            if proxy:
                proxy.close()
                row.update(proxy_exchanges=proxy.rows, proxy_closed_cleanly=proxy.closed_cleanly)
            for item in receivers:
                H.stop_owned(item["process"])
                row[item["label"] + "_raw"] = read(item["ledger"])
                row[item["label"] + "_stderr"] = read(item["log"])
                row[item["label"] + "_closure"] = {"exit_code": item["process"].returncode, "readiness": item.get("ready")}
            for log in logs:
                log.close()
            audit = read(home / ".agentfw/audit.jsonl")
            row["native_audit_raw"] = audit
            row["daemon_raw"] = read(root / "daemon.log")
            opened = [value for value in H.json_lines(audit.encode()) if value.get("event") == "native_session_start"] if audit else []
            for index, item in enumerate(collectors):
                ledger = item["ledger"]
                row["sessions"].append({key: value for key, value in item.items() if key in {"label", "closure", "attempts", "useful"}} | {
                    "native_session_id": opened[index].get("session") if index < len(opened) else None,
                    "child_ledger_present": ledger.is_file(), "child_ledger_raw": read(ledger),
                    "child_started_raw": read(ledger.with_suffix(".started")), "child_closed_raw": read(ledger.with_suffix(".closed")),
                    "child_input_raw": read(ledger.with_suffix(".input")), "child_output_raw": read(ledger.with_suffix(".responses")),
                    "collector_raw": read(item["log_path"]), "client_raw": b"".join(item["collector"].received).decode()})
            row["workspace_after"] = H.tree_snapshot(workspace)
            tokens = [path.read_bytes().strip() for path in (home / ".agentfw/token", home / ".agentfw/native-token") if path.is_file()]
            retained = json.dumps(row, ensure_ascii=False).encode()
            if any(token and token in retained for token in tokens):
                row = {"case": name, "error": "credential retention refused; unsafe observations discarded"}
    row["owned_fixture_removed"] = not root.exists()
    row["duration_seconds"] = round(time.monotonic() - started, 6)
    row["grade"] = grade(row)
    return row


def run(args):
    repo, binary, output = args.repo.resolve(), args.agentfw.resolve(), args.output.resolve()
    H.require(not output.exists(), "fresh output required")
    H.require(binary.is_file(), "built Agent binary missing")
    before = H.source_snapshot(repo)
    H.require(before == {"commit": args.expected_commit, "tracked_dirty": False}, "clean exact expected source required")
    digest = H.sha(binary.read_bytes())
    report = {"schema_version": "sou56-https-get-probe/1", "status": "incomplete", "acceptance_passed": False,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(), "source_before": before,
        "binary_sha256": digest, "driver_sha256": H.sha(Path(__file__).read_bytes()), "fixture_sha256": H.sha(FIXTURE.read_bytes()),
        "process_helper_sha256": H.sha(HELPER.read_bytes()), "environment": {"os": platform.system(),
            "architecture": platform.machine(), "python": platform.python_version()}, "cases": [],
        "limits": {"requests_per_call": 1, "connect_seconds": 3, "total_seconds": 5, "response_bytes": 4096,
                   "encrypted_receive_bytes": 65536, "http_plaintext_bytes": 16384,
                   "http_header_bytes": 8192,
                   "repeated_failures": REPEATED, "supported_status": 200, "methods": ["GET"]},
        "limitations": ["Owned local endpoints with an exact address/HTTPS identity exception; no external provider traffic.",
            "Scripted MCP client, not an interactive model-host acceptance claim.",
            "Socket/request ledgers are produced by receiver processes independent of the broker and MCP child.",
            "Proxy controls retain authenticated request/reply bodies but never Authorization headers and never fabricate Allow.",
            "Result withholding cannot undo an already issued GET; the receiver witness is retained.",
            "Unsupported overlap/cancellation/replay ends the original session; useful recovery then uses a fresh session.",
            "Binary digests identify artifacts; matching build logs establish build provenance."]}
    try:
        if platform.system() != "Linux":
            report["unsupported"] = "positive HTTPS GET execution acceptance requires Linux"
        else:
            with tempfile.TemporaryDirectory(prefix="sou56-ca-", dir=Path(tempfile.gettempdir()).resolve()) as temporary:
                certificate_dir = Path(temporary).resolve() / "certificates"
                witness = certificates(certificate_dir)
                report["certificates"] = witness
                for name in CASES:
                    row = run_case(repo, binary, name, digest, certificate_dir, witness)
                    report["cases"].append(row)
                    print(name + ": " + row["grade"]["status"] + " (" + row["grade"]["reason"] + ")", flush=True)
            report["certificate_fixture_removed"] = not Path(temporary).exists()
        report["source_after"] = H.source_snapshot(repo)
        report["source_binary_stable"] = before == report["source_after"] and H.sha(binary.read_bytes()) == digest
        if any(row["grade"]["status"] == "fail" for row in report["cases"]):
            report["status"] = "fail"
        elif ([row["case"] for row in report["cases"]] == list(CASES) and report["source_binary_stable"]
              and report.get("certificate_fixture_removed") is True and all(row["owned_fixture_removed"] for row in report["cases"])):
            report["status"] = "pass"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    report["summary"] = {"cases_run": len(report["cases"]), "cases_expected": len(CASES),
        "passed": sum(row["grade"]["status"] == "pass" for row in report["cases"]),
        "failed": sum(row["grade"]["status"] == "fail" for row in report["cases"]), "skips": int("unsupported" in report)}
    report["acceptance_passed"] = report["status"] == "pass"
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")
    print("SOU-56 owned HTTPS result: " + report["status"] + "; " + str(output))
    return {"pass": 0, "fail": 1, "incomplete": 2}[report["status"]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--agentfw", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "not_run", "processes_started": 0, "acceptance_passed": False,
                          "cases": list(CASES), "required_os": "Linux"}))
        return 0
    if not all((args.agentfw, args.expected_commit, args.output)):
        parser.error("--run requires --agentfw, --expected-commit and a fresh --output")
    try:
        return run(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("SOU-56 incomplete (" + type(error).__name__ + "): " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
