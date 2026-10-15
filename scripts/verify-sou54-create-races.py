#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual native HTTP/stdio failure, race and replay witnesses for SOU-54.

The fixture proxy forwards authenticated real daemon exchanges; it never
fabricates an Allow. It mutates only two explicitly marked request controls or
holds a genuine Allow while the scripted MCP client creates a bounded race.
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
SPEC = importlib.util.spec_from_file_location("sou54_create_helpers", ROOT / "scripts/verify-sou54-create-file.py")
LIMIT_WRAPPER = ROOT / "scripts/fixtures/limited_create_file_agent.py"
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)
CASES = ("destination-substitution", "content-substitution", "root-replacement-after-allow",
         "two-session-same-target", "queued-overlap", "queued-cancellation", "batch-refused", "replayed-id", "partial-write-os-limit")
PROTOCOL = {"queued-overlap", "queued-cancellation", "batch-refused", "replayed-id"}


def receive(collector):
    raw = collector.queue.get(timeout=15)
    if raw is not None:
        collector.received.append(raw)
    return raw


class NativeProxy:
    """Owned loopback transport fault fixture; no policy or admission implementation."""
    def __init__(self, upstream_port, case):
        self.upstream_port, self.case = upstream_port, case
        self.rows, self.lock = [], threading.Lock()
        self.active, self.idle = 0, threading.Event()
        self.idle.set()
        self.ready, self.release, self.session_ended = threading.Event(), threading.Event(), threading.Event()
        self.expected_holds = 2 if case == "two-session-same-target" else 1
        self.hold = case in {"root-replacement-after-allow", "two-session-same-target", "queued-overlap", "queued-cancellation"}
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *_):
                pass

            def do_POST(self):
                connection = None
                with owner.lock:
                    owner.active += 1
                    owner.idle.clear()
                row = {"path": self.path, "received_at": time.monotonic()}
                try:
                    H.require(self.path in {"/native/v1", "/mcp"}, "unexpected local proxy path")
                    length = int(self.headers.get("Content-Length", "0"))
                    H.require(0 < length <= 1024 * 1024, "invalid local proxy body bound")
                    original_raw = self.rfile.read(length)
                    H.require(len(original_raw) == length, "truncated local proxy request")
                    original = H.strict_json(original_raw)
                    forwarded = H.strict_json(original_raw)
                    create = self.path == "/native/v1" and original.get("event") == "call" and original.get("tool") == "create_file"
                    if create and owner.case == "destination-substitution":
                        forwarded["args"]["path"] = "substituted.txt"
                    elif create and owner.case == "content-substitution":
                        forwarded["args"]["content"] = "UNAUTHORIZED-SUBSTITUTED-CONTENT"
                    forwarded_raw = H.canonical(forwarded) if forwarded != original else original_raw
                    row.update(original=original, forwarded=forwarded, original_sha256=H.sha(original_raw), original_raw=original_raw.decode(),
                               forwarded_sha256=H.sha(forwarded_raw), forwarded_raw=forwarded_raw.decode(), authorization_header_retained=False)
                    connection = http.client.HTTPConnection("127.0.0.1", owner.upstream_port, timeout=5)
                    # The existing collector's credential passes unchanged, in memory only.
                    connection.request("POST", self.path, body=forwarded_raw, headers={
                        "Authorization": self.headers.get("Authorization", ""),
                        "Content-Type": "application/json", "Content-Length": str(len(forwarded_raw))})
                    response = connection.getresponse()
                    reply_raw = response.read(65537)
                    H.require(len(reply_raw) <= 65536, "local proxy reply over bound")
                    row.update(upstream_status=response.status, reply=H.strict_json(reply_raw), reply_raw=reply_raw.decode(),
                               reply_sha256=H.sha(reply_raw), upstream_completed_at=time.monotonic())
                    with owner.lock:
                        owner.rows.append(row)
                        held = sum(item.get("held") is True for item in owner.rows)
                        if create and owner.hold:
                            H.require(response.status == 200 and row["reply"].get("release") is True
                                      and row["reply"].get("verdict") == "allow", "genuine upstream Allow missing")
                            row["held"] = True
                            held += 1
                            if held == owner.expected_holds:
                                owner.ready.set()
                    if original.get("event") == "session_end" and response.status == 200:
                        owner.session_ended.set()
                    if row.get("held"):
                        H.require(owner.release.wait(timeout=10), "bounded native receipt hold expired")
                        row["released_at"] = time.monotonic()
                    self.send_response(response.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(reply_raw)))
                    self.end_headers()
                    self.wfile.write(reply_raw)
                    self.wfile.flush()
                    row["downstream_delivered"] = True
                except (OSError, ValueError, http.client.HTTPException) as error:
                    row["transport_error"] = type(error).__name__ + ": " + str(error)
                    with owner.lock:
                        if not any(item is row for item in owner.rows):
                            owner.rows.append(row)
                    self.close_connection = True
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
        self.closed_cleanly = self.idle.wait(timeout=6) and not self.thread.is_alive()


def handshake(collector):
    initial = {"jsonrpc": "2.0", "id": "init", "method": "initialize", "params": {
        "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "sou54-race-probe", "version": "1"}}}
    H.require(collector.send(initial), "missing real MCP initialization")
    collector.send({"jsonrpc": "2.0", "method": "notifications/initialized"}, reply=False)
    listed = collector.send({"jsonrpc": "2.0", "id": "list", "method": "tools/list"})
    H.require(listed and H.strict_json(listed).get("result", {}).get("tools") == H.load_tools(), "discovery mismatch")


def useful(collector, workspace, label):
    request = H.frame("useful-" + label, "read_document", {"path": str(workspace / "inventory.txt")})
    reply = collector.send(request)
    H.require(reply is not None, "missing useful continuation")
    return {"request": request, "reply_raw": reply.decode()}


def grade(row):
    try:
        name = row["case"]
        H.require(name in CASES and row.get("error") is None, "unknown or incomplete race observation")
        H.require(row["outside_before"] == row["outside_after"], "outside fixture changed")
        H.require(row["proxy_closed_cleanly"] is True, "local proxy still has unfinished transport handlers")
        exchanges = row["proxy_exchanges"]
        H.require(isinstance(exchanges, list) and exchanges, "real authenticated proxy transcript absent")
        H.require(all(item.get("authorization_header_retained") is False for item in exchanges), "unsafe proxy header retention")
        for item in exchanges:
            for field in ("original", "forwarded", "reply"):
                H.require(H.strict_json(item[field + "_raw"]) == item[field]
                          and H.sha(item[field + "_raw"].encode()) == item[field + "_sha256"],
                          "proxy raw byte/digest/decoded witness mismatch")
        create = [item for item in exchanges if item.get("original", {}).get("event") == "call"
                  and item["original"].get("tool") == "create_file"]
        sessions = row["sessions"]
        expected_sessions = 2 if name in PROTOCOL or name == "two-session-same-target" else 1
        H.require(len(sessions) == expected_sessions, "wrong number of actual MCP sessions")
        executions = []
        for index, session in enumerate(sessions):
            abnormal = name in PROTOCOL and index == 0
            H.require(session["child_ledger_present"] is True and session["child_started_raw"] == "started\n"
                      and session["child_ledger_raw"] == "", "child execution or missing independent startup/ledger")
            child_input = H.json_lines(session["child_input_raw"].encode())
            H.require([item.get("method") for item in child_input] == ["initialize", "notifications/initialized", "tools/list"],
                      "unexpected child traffic")
            client = H.json_lines(session["client_raw"].encode())
            H.require(H.json_lines(session["child_output_raw"].encode()) == client[:2], "discovery bytes changed")
            closure = session["closure"]
            H.require(closure.get("stdout_eof") is True and closure.get("reader_joined") is True
                      and closure.get("forced_cleanup") is False and type(closure.get("exit_code")) is int,
                      "incomplete/forced collector closure")
            if abnormal:
                H.require(closure["exit_code"] != 0, "unsupported protocol was not explicitly refused")
                diagnostic = {"queued-overlap": "concurrent MCP requests are not supported",
                              "queued-cancellation": "concurrent MCP requests are not supported",
                              "batch-refused": "unsupported MCP envelope", "replayed-id": "replayed MCP request"}[name]
                H.require(diagnostic in session["collector_raw"], "unrelated transport failure is not protocol-refusal evidence")
                H.require(len(client) == (3 if name == "replayed-id" else 2), "protected reply released after protocol refusal")
            else:
                H.require(closure["exit_code"] == 0 and session["child_closed_raw"] == "closed\n", "MCP child/collector did not close cleanly")
                H.require(len(client) == (3 if session["label"] == "fresh-after-refusal" else 4),
                          "missing/extra normal-session replies")
                follow = session["useful"]
                value = H.strict_json(follow["reply_raw"])
                H.require(value == client[-1] and value.get("id") == follow["request"]["id"]
                          and value.get("result", {}).get("isError") is not True
                          and value.get("result", {}).get("content") == [{"type": "text", "text": H.READ_TEXT}],
                          "useful continuation/result witness missing")
            if "create_reply_raw" in session:
                create_reply = H.strict_json(session["create_reply_raw"])
                request = next((value for value in row["submitted_creates"] if value["id"] == "create-" + session["label"]), None)
                H.require(request and create_reply == client[2] and create_reply.get("id") == request["id"]
                          and create_reply.get("jsonrpc") == "2.0" and isinstance(create_reply.get("result"), dict),
                          "original create response/released-byte identity missing")
                result = create_reply["result"]
                if name in {"destination-substitution", "content-substitution"}:
                    H.require(result.get("isError") is True and "Soup Wall withheld MCP invocation" in session["create_reply_raw"],
                              "substituted invocation was not visibly refused")
                else:
                    receipt = H.strict_json(result["content"][0]["text"])
                    own_execution = H.classify_rows(session["collector_raw"].encode(), "mcp_create_file_execution")
                    H.require(len(own_execution) == 1 and receipt.get("committed") is own_execution[0].get("committed")
                              and result.get("isError") is (not receipt["committed"]),
                              "released effect receipt contradicts actual broker outcome")
                    if name == "root-replacement-after-allow":
                        H.require(receipt.get("committed") is False and receipt.get("error") == "workspace_root_substituted",
                                  "unrelated failure is not root substitution refusal")
            elif not abnormal and session["label"] != "fresh-after-refusal":
                H.require(False, "normal invocation receipt missing")
            executions.extend(H.classify_rows(session["collector_raw"].encode(), "mcp_create_file_execution"))
        native = H.json_lines(row["native_audit_raw"].encode())
        opened = [item for item in native if item.get("event") == "native_session_start"]
        ended = [item for item in native if item.get("event") == "native_session_end"]
        H.require(len(opened) == len(ended) == expected_sessions and len({item.get("session") for item in opened}) == expected_sessions
                  and {item.get("session") for item in opened} == {item.get("session") for item in ended},
                  "native session cleanup/isolation missing")
        expected_create = 0 if name == "batch-refused" else 2 if name == "two-session-same-target" else 1
        for item in create:
            original = item["original"]
            request = next((request for request in row["submitted_creates"]
                            if request["id"] == original.get("resource_admission", {}).get("host_call_id")), None)
            H.require(request and original.get("args") == request["params"]["arguments"],
                      "original native request no longer matches submitted stdio arguments/host ID")
        H.require(len(create) == expected_create and all(item.get("upstream_status") == 200 for item in create),
                  "actual daemon create admission exchange missing")
        read_calls = [item for item in exchanges if item.get("original", {}).get("event") == "call"
                      and item["original"].get("tool") == "read_document"]
        H.require(len(read_calls) == (2 if name == "two-session-same-target" else 1)
                  and all(item.get("reply", {}).get("release") is True and item["reply"].get("verdict") == "allow"
                          and item.get("original") == item.get("forwarded") for item in read_calls),
                  "useful read did not obtain authentic native Allow")
        for call in read_calls:
            completions = [item for item in exchanges if item.get("original", {}).get("event") == "result"
                and item["original"].get("call_id") == call["reply"].get("call_id")]
            H.require(len(completions) == 1 and completions[0].get("reply", {}).get("release") is True,
                      "useful read result was not authentically released")
        if name in {"destination-substitution", "content-substitution"}:
            call = create[0]
            H.require(call["original"] != call["forwarded"] and call["original"]["resource_admission"] == call["forwarded"]["resource_admission"],
                      "original execution binding was not retained for substitution control")
            changed = "path" if name == "destination-substitution" else "content"
            expected = H.strict_json(H.canonical(call["original"]))
            expected["args"][changed] = call["forwarded"]["args"][changed]
            H.require(expected == call["forwarded"], "proxy changed fields beyond the selected argument")
            H.require(call["reply"].get("verdict") == "deny" and call["reply"].get("release") is False,
                      "actual daemon did not Deny substituted arguments")
            H.require(read_calls[0]["original"]["session_id"] == call["original"]["session_id"], "substitution used a replacement session")
        else:
            H.require(all(item["original"] == item["forwarded"] and item["reply"].get("verdict") == "allow"
                          and item["reply"].get("release") is True for item in create), "authentic original Allow was fabricated or absent")
        if name in {"queued-overlap", "queued-cancellation"}:
            H.require(create[0].get("held") is True and row["queued_at"] < row["release_at"]
                      and create[0]["upstream_completed_at"] <= row["queued_at"]
                      and row["native_session_end_before_release"] is True,
                      "queued frame/actual Allow/session cleanup handshake missing")
            stopped = [item for item in exchanges if item["original"].get("event") == "session_end"
                       and item["original"].get("session_id") == create[0]["original"]["session_id"]]
            H.require(len(stopped) == 1 and stopped[0]["reply"].get("release") is True
                      and stopped[0]["upstream_completed_at"] < row["release_at"],
                      "original native session was not genuinely ended before held receipt release")
            H.require(read_calls[0]["original"]["session_id"] != create[0]["original"]["session_id"],
                      "unsupported cancellation/overlap falsely claimed same-session recovery")
        if name == "root-replacement-after-allow":
            H.require(row["fixture_mutations"] and create[0]["upstream_completed_at"] <= row["root_replaced_at"] < row["release_at"],
                      "root replacement did not happen after actual Allow/before reply release")
            H.require(row["replacement_before"] == row["replacement_after"] and row["parked_before"] == row["parked_after"],
                      "root race changed original or replacement workspace")
            H.require(read_calls[0]["original"]["session_id"] == create[0]["original"]["session_id"], "root-race continuation changed sessions")
        committed = [item for item in executions if item.get("committed") is True]
        expected_commits = 1 if name in {"two-session-same-target", "replayed-id"} else 0
        H.require(len(committed) == expected_commits, "wrong number of actual broker commits")
        if name in {"destination-substitution", "content-substitution", "queued-overlap", "queued-cancellation", "batch-refused"}:
            H.require(executions == [], "blocked operation entered broker execution")
        if expected_commits:
            final = row["target_final"]
            H.require(final and final["mode"] == 0o600 and final["links"] == 1 and final["kind"] == 32768,
                      "committed file type/mode/link witness missing")
            winner = next((request for request in row["submitted_creates"] if request["id"] == committed[0].get("host_call_id")), None)
            H.require(winner is not None and final["sha256"] == H.sha(winner["params"]["arguments"]["content"].encode())
                      and final["bytes"] == len(winner["params"]["arguments"]["content"].encode())
                      and committed[0].get("committed_bytes") == final["bytes"], "winner file contains partial/mixed/different bytes")
            expected = dict(row["workspace_before"])
            expected["created.txt"] = final
            H.require(expected == row["workspace_after"], "unexpected extra file, mutation or staging leak")
        else:
            H.require(row["workspace_before"] == row["workspace_after"], "refused operation changed workspace")
        if name == "partial-write-os-limit":
            limits = row["configuration"]["os_file_size_limit"]
            H.require(limits.get("soft_bytes") == limits.get("hard_bytes") == 2048
                      and limits.get("wrapper_sha256") == H.sha(LIMIT_WRAPPER.read_bytes()),
                      "exact owned OS-limit wrapper/configuration witness missing")
            records = H.classify_rows(sessions[0]["collector_raw"].encode(), "sou54_os_file_size_limit")
            H.require(len(records) == 1 and records[0].get("rlimit_fsize") == [2048, 2048]
                      and records[0].get("sigxfsz_ignored") is True, "actual RLIMIT/SIGXFSZ launch witness missing")
            capture = sessions[0]["closure"].get("stderr_capture", {})
            H.require(capture.get("eof") is True and capture.get("error") is False
                      and capture.get("parent_owned_log") is True and type(capture.get("bytes")) is int and capture["bytes"] > 0,
                      "bounded parent stderr drain did not finish independently of child file-size limit")
            H.require(len(executions) == 1 and executions[0].get("committed") is False
                      and executions[0].get("error") == "stage_write_failed" and executions[0].get("staged_bytes") == 2048
                      and executions[0].get("committed_bytes") == 0 and executions[0].get("result_kind") == "error",
                      "real OS-limited partial stage was not recorded as 2048 bytes/zero commit")
            receipt_raw = sessions[0]["create_reply_raw"]
            receipt = H.strict_json(H.strict_json(receipt_raw)["result"]["content"][0]["text"])
            H.require(receipt.get("success") is False and receipt.get("created") is False and receipt.get("committed") is False
                      and receipt.get("error") == "stage_write_failed" and receipt.get("staged_bytes") == 2048
                      and receipt.get("committed_bytes") == 0,
                      "partial-write receipt hides staged bytes or invents a committed effect")
            completion = [item for item in exchanges if item["original"].get("event") == "result"
                          and item["original"].get("call_id") == create[0]["reply"].get("call_id")]
            H.require(len(completion) == 1 and completion[0]["original"].get("result_kind") == "error"
                      and completion[0]["original"].get("content") == receipt_raw
                      and completion[0]["reply"].get("verdict") == "allow" and completion[0]["reply"].get("release") is True
                      and completion[0].get("upstream_status") == 200,
                      "real native error-result inspection/release was bypassed or missing")
            H.require(read_calls[0]["original"]["session_id"] == create[0]["original"]["session_id"]
                      and len(row["submitted_creates"][0]["params"]["arguments"]["content"].encode()) == 4096,
                      "partial write did not preserve useful same-session continuation after the bounded 4096-byte attempt")
        if name == "batch-refused":
            H.require(isinstance(row["submitted_batch"], list) and len(row["submitted_batch"]) == 2,
                      "batch refusal lacks original batch input witness")
        if name == "replayed-id":
            H.require(row["replayed_frame"] == row["submitted_creates"][0], "replay did not retain exact original frame/ID")
        if name == "two-session-same-target":
            H.require(len({item["original"]["session_id"] for item in create}) == 2
                      and all(item.get("held") is True and item["upstream_completed_at"] < row["release_at"] for item in create),
                      "concurrent writers were not two actual admitted sessions")
            H.require(len(executions) == 2 and len([item for item in executions if item.get("committed") is False]) == 1,
                      "losing admitted executor failure/effect accounting missing")
            H.require({item["original"]["session_id"] for item in read_calls} == {item["original"]["session_id"] for item in create},
                      "concurrent sessions lost useful isolated continuation")
        return {"status": "pass", "reason": "actual authenticated daemon, broker effects, child ledger and released bytes agree"}
    except (ValueError, KeyError, TypeError, IndexError) as error:
        return {"status": "fail", "reason": str(error)}


def run_case(repo, binary, name, digest):
    started = time.monotonic()
    row = {"case": name, "sessions": [], "submitted_creates": [], "fixture_mutations": []}
    proxy = daemon = None
    collectors, logs = [], []
    with tempfile.TemporaryDirectory(prefix="sou54-races-", dir=Path(tempfile.gettempdir()).resolve()) as temporary:
        root = Path(temporary).resolve()
        home, workspace, outside = root / "home", root / "workspace", root / "outside"
        for path in (home, workspace, outside):
            path.mkdir(mode=0o700)
        (workspace / "inventory.txt").write_text(H.READ_TEXT, encoding="utf-8")
        (outside / "canary.txt").write_text("UNCHANGED-OUTSIDE-SOU54-RACE", encoding="utf-8")
        target = workspace / "created.txt"
        row.update(workspace_before=H.tree_snapshot(workspace), outside_before=H.tree_snapshot(outside))
        env = H.private_environment(home)
        try:
            install = subprocess.run([str(binary), "install"], env=env, cwd=root, stdin=subprocess.DEVNULL,
                                     capture_output=True, timeout=20)
            H.require(install.returncode == 0, "private Agent install failed")
            classifier = repo / "rule_baseline/rule_baseline.py"
            registry_bytes = H.canonical(H.registry(H.load_tools(), workspace, target, digest, H.sha(classifier.read_bytes())))
            registry_path, policy_path = root / "registry.json", root / "policy.yaml"
            registry_path.write_bytes(registry_bytes)
            policy_path.write_text("agent_policies: []\ndefault: allow\n", encoding="utf-8")
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                daemon_port = probe.getsockname()[1]
            config = {"port": daemon_port, "enforce": True, "policy": str(policy_path),
                      "native": {"registry_path": str(registry_path), "registry_sha256": H.sha(registry_bytes)}}
            config_path = home / ".agentfw/config.yaml"
            config_path.write_bytes(H.canonical(config))
            row["configuration"] = {"daemon_config_sha256": H.sha(config_path.read_bytes()),
                "registry": H.strict_json(registry_bytes), "registry_sha256": H.sha(registry_bytes),
                "policy_sha256": H.sha(policy_path.read_bytes()), "classifier_sha256": H.sha(classifier.read_bytes())}
            daemon_stream = (root / "daemon.log").open("wb")
            logs.append(daemon_stream)
            daemon = subprocess.Popen([str(binary), "serve"], env=env, cwd=root, stdout=daemon_stream,
                                      stderr=daemon_stream, start_new_session=True)
            H.require(H.healthy(daemon_port, daemon), "real enforcing Agent did not become healthy")
            proxy = NativeProxy(daemon_port, name)
            # The daemon has loaded its own port already. Only the collector's
            # private endpoint selection now changes; authority files stay pinned.
            config["port"] = proxy.port
            config_path.write_bytes(H.canonical(config))
            row["configuration"]["collector_config_sha256"] = H.sha(config_path.read_bytes())
            collector_env = dict(env, AGENTFW_CLASSIFIER="rule-baseline", AGENTFW_RULE_BASELINE=str(classifier),
                                 AGENTFW_CLASSIFIER_PYTHON=sys.executable, AGENTFW_WORKSPACE=str(workspace))

            def start(label):
                ledger, log_path = root / (label + "-child.jsonl"), root / (label + "-collector.log")
                log = log_path.open("wb")
                logs.append(log)
                command = [str(binary), "mcp", "--native-admission", "--id", "sou54", "--", sys.executable,
                           "-I", "-u", str(H.FIXTURE), "--ledger", str(ledger)]
                capture_stderr = name == "partial-write-os-limit" and label == "primary"
                if capture_stderr:
                    row["configuration"]["os_file_size_limit"] = {"soft_bytes": 2048, "hard_bytes": 2048,
                        "wrapper_sha256": H.sha(LIMIT_WRAPPER.read_bytes()), "stderr_transport": "pipe drained to parent-owned regular log"}
                    command = [sys.executable, "-I", "-u", str(LIMIT_WRAPPER), "--agentfw", str(binary), "--", *command[1:]]
                collector = H.Collector(command, collector_env, workspace, log, capture_stderr=capture_stderr)
                item = {"label": label, "collector": collector, "ledger": ledger, "log_path": log_path}
                collectors.append(item)
                handshake(collector)
                return item

            primary = start("primary")
            content = "x" * 4096 if name == "partial-write-os-limit" else H.UTF8 + "concurrent writer A\n"
            first = H.frame("create-primary", "create_file", {"path": "created.txt", "content": content})
            if name == "batch-refused":
                row["submitted_batch"] = [first, H.frame("batch-second", "create_file", {"path": "created.txt", "content": "batch"})]
                primary["collector"].send(row["submitted_batch"], reply=False)
            else:
                row["submitted_creates"].append(first)
                primary["collector"].send(first, reply=False)
            if name == "two-session-same-target":
                secondary = start("secondary")
                second = H.frame("create-secondary", "create_file", {"path": "created.txt", "content": H.UTF8 + "concurrent writer B\n"})
                row["submitted_creates"].append(second)
                secondary["collector"].send(second, reply=False)
            if proxy.hold:
                H.require(proxy.ready.wait(timeout=8), "real native Allow hold handshake missing")
            if name == "root-replacement-after-allow":
                parked = root / "original-root"
                workspace.rename(parked)
                workspace.mkdir(mode=0o700)
                (workspace / "replacement-canary.txt").write_text("KEEP-REPLACEMENT-ROOT", encoding="utf-8")
                row.update(root_replaced_at=time.monotonic(), parked_before=H.tree_snapshot(parked),
                           replacement_before=H.tree_snapshot(workspace))
                row["fixture_mutations"].append("After genuine native Allow, move original root and create distinct replacement root/canary; preserve both witnesses and restore original before continuation.")
            if name in {"queued-overlap", "queued-cancellation"}:
                queued = (H.frame("unsupported-overlap", "create_file", {"path": "created.txt", "content": "must-not-run"})
                          if name == "queued-overlap" else {"jsonrpc": "2.0", "method": "notifications/cancelled",
                          "params": {"requestId": first["id"], "reason": "SOU54 bounded cancellation before held Allow receipt"}})
                primary["collector"].send(queued, reply=False)
                row.update(queued_at=time.monotonic(), queued_frame=queued)
                row["native_session_end_before_release"] = proxy.session_ended.wait(timeout=5)
                H.require(row["native_session_end_before_release"], "cancelled/overlapped native session was not ended before receipt release")
            if proxy.hold:
                row["release_at"] = time.monotonic()
                proxy.release.set()
            if name not in {"batch-refused", "queued-overlap", "queued-cancellation"}:
                reply = receive(primary["collector"])
                H.require(reply, "primary create reply missing")
                primary["create_reply_raw"] = reply.decode()
                if name == "two-session-same-target":
                    reply = receive(secondary["collector"])
                    H.require(reply, "secondary create reply missing")
                    secondary["create_reply_raw"] = reply.decode()
                if name == "replayed-id":
                    row["replayed_frame"] = first
                    primary["collector"].send(first, reply=False)
            if name == "root-replacement-after-allow":
                row.update(parked_after=H.tree_snapshot(parked), replacement_after=H.tree_snapshot(workspace))
                workspace.rename(root / "replacement-root-observed")
                parked.rename(workspace)
                row["fixture_mutations"].append("Restore original root pathname only after refused create and snapshots, before same-session useful read; do not erase replacement contents.")
            if name in PROTOCOL:
                primary["closure"] = primary["collector"].close()
                primary["closed"] = True
                fresh = start("fresh-after-refusal")
                fresh["useful"] = useful(fresh["collector"], workspace, "fresh")
            else:
                primary["useful"] = useful(primary["collector"], workspace, "primary")
                if name == "two-session-same-target":
                    secondary["useful"] = useful(secondary["collector"], workspace, "secondary")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, queue.Empty) as error:
            row["error"] = type(error).__name__ + ": " + str(error)
        finally:
            if proxy:
                proxy.release.set()
            for item in collectors:
                if not item.get("closed"):
                    item["closure"] = item["collector"].close()
                item["closed"] = True
            H.stop_owned(daemon)
            if proxy:
                proxy.close()
                row["proxy_exchanges"] = proxy.rows
                row["proxy_closed_cleanly"] = proxy.closed_cleanly
            for log in logs:
                log.close()
            for item in collectors:
                ledger = item["ledger"]
                def read(path):
                    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
                row["sessions"].append({key: value for key, value in item.items() if key in {"label", "closure", "useful", "create_reply_raw"}} | {
                    "child_ledger_present": ledger.is_file(), "child_ledger_raw": read(ledger),
                    "child_started_raw": read(ledger.with_suffix(".started")), "child_closed_raw": read(ledger.with_suffix(".closed")),
                    "child_input_raw": read(ledger.with_suffix(".input")), "child_output_raw": read(ledger.with_suffix(".responses")),
                    "collector_raw": read(item["log_path"]), "client_raw": b"".join(item["collector"].received).decode()})
            if workspace.exists():
                row["workspace_after"] = H.tree_snapshot(workspace)
                row["target_final"] = row["workspace_after"].get("created.txt")
            row["outside_after"] = H.tree_snapshot(outside)
            audit = home / ".agentfw/audit.jsonl"
            row["native_audit_raw"] = audit.read_text() if audit.is_file() else ""
            log_path = root / "daemon.log"
            row["daemon_raw"] = log_path.read_text() if log_path.is_file() else ""
            tokens = [path.read_bytes().strip() for path in (home / ".agentfw/token", home / ".agentfw/native-token") if path.is_file()]
            encoded = json.dumps(row, ensure_ascii=False).encode()
            if any(token and token in encoded for token in tokens):
                row = {"case": name, "error": "unsafe credential retention refused; observations discarded"}
    row["duration_seconds"] = round(time.monotonic() - started, 6)
    row["owned_fixture_removed"] = not root.exists()
    row["grade"] = grade(row)
    return row


def run(args):
    repo, binary, output = args.repo.resolve(), args.agentfw.resolve(), args.output.resolve()
    H.require(not output.exists(), "output already exists")
    before = H.source_snapshot(repo)
    H.require(before == {"commit": args.expected_commit, "tracked_dirty": False}, "clean exact expected source required")
    digest = H.sha(binary.read_bytes())
    report = {"schema_version": "sou54-create-race-probe/1", "status": "incomplete", "acceptance_passed": False,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(), "source_before": before,
        "agentfw_sha256": digest, "driver_sha256": H.sha(Path(__file__).read_bytes()),
        "helper_sha256": H.sha((repo / "scripts/verify-sou54-create-file.py").read_bytes()),
        "fixture_sha256": H.sha(H.FIXTURE.read_bytes()), "environment": {"os": platform.system(),
        "architecture": platform.machine(), "python": platform.python_version()}, "cases": [],
        "limitations": ["Safe owned loopback fixtures; proxy never fabricates native Allow, and retains no Authorization headers.",
            "Root rename/replacement is an explicit fixture mutation; original and replacement snapshots are separate from executor effects.",
            "Queued unsupported overlap/cancellation and batch/replay intentionally terminate their session; useful recovery uses a fresh session.",
            "Deterministic native HTTP receipt gates cover one bounded race ordering, not every kernel scheduling interleaving.",
            "No arbitrary MCP server containment, external provider or product release acceptance is claimed."]}
    try:
        if platform.system() != "Linux":
            report["unsupported"] = "Linux is required for positive create/race execution"
        else:
            for name in CASES:
                row = run_case(repo, binary, name, digest)
                report["cases"].append(row)
                print(name + ": " + row["grade"]["status"] + " (" + row["grade"]["reason"] + ")", flush=True)
        report["source_after"] = H.source_snapshot(repo)
        report["source_binary_stable"] = before == report["source_after"] and H.sha(binary.read_bytes()) == digest
        if any(row["grade"]["status"] == "fail" for row in report["cases"]):
            report["status"] = "fail"
        elif ([row["case"] for row in report["cases"]] == list(CASES) and report["source_binary_stable"]
              and all(row["owned_fixture_removed"] for row in report["cases"])):
            report["status"] = "pass"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["error"] = type(error).__name__ + ": " + str(error)
    report["acceptance_passed"] = report["status"] == "pass"
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")
    print("SOU-54 native races: " + report["status"] + "; " + str(output))
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
        print(json.dumps({"status": "not_run", "processes_started": 0, "acceptance_passed": False, "cases": list(CASES)}))
        return 0
    if not all((args.agentfw, args.expected_commit, args.output)):
        parser.error("--run requires --agentfw, --expected-commit and fresh --output")
    try:
        return run(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("SOU-54 race probe incomplete (" + type(error).__name__ + "): " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
