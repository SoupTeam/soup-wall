#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Required real-server Linux MCP acceptance and actual installed Claude Code host.

Only --run starts owned processes. Missing prerequisites fail, never pass/skip.
The original pinned filesystem server performs useful reads. Owned FIFOs make
real overlap/cancellation reproducible. Claude uses a scripted local provider;
its interoperability result is separate from live-model efficacy (not tested).
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
TEXT = "SOU-62 useful read: café, қазақша, 日本語, 🥣.\n"
FIFO_TEXT = "SOU-62 independent FIFO execution witness.\n"
PROFILE = "sw-mcp/filesystem-readonly/1"
TOOL = "read_text_file"
READ_CASES = (
    ("read_file", {"path": "/workspace/notes.txt"}, TEXT),
    (TOOL, {"path": "/workspace/notes.txt"}, TEXT),
    ("read_multiple_files", {"paths": ["/workspace/notes.txt"]}, TEXT),
    ("list_directory", {"path": "/workspace"}, "notes.txt"),
    ("list_directory_with_sizes", {"path": "/workspace", "sortBy": "size"}, "notes.txt"),
    ("search_files", {"path": "/workspace", "pattern": "notes.txt"}, "/workspace/notes.txt"),
    ("get_file_info", {"path": "/workspace/notes.txt"}, "isFile: true"),
    ("list_allowed_directories", {}, "Allowed directories:\n/workspace"),
)
SANDBOX_WITNESSES = ("allowed_read", "workspace_write_denied", "outside_read_denied", "outside_write_denied",
    "egress_witness_calibrated", "egress_denied", "pathname_unix_socket_denied", "fifo_witness_calibrated",
    "fifo_write_denied", "inherited_env_absent", "host_descriptors_absent", "private_net_pid")


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INSTALL = load("sou62_install", "install-sou62-filesystem-profile.py")
DEMO = load("sou62_demo", "mcp-admission-demo.py")
REPLAY = load("sou62_sou97_replay", "sou97_runtime_replay.py")
DEFAULT_CLASSIFIER = ROOT / "rule_baseline/rule_baseline.py"


def default_classifier():
    return {"path": str(DEFAULT_CLASSIFIER), "file": DEFAULT_CLASSIFIER.name, "sha256": sha(DEFAULT_CLASSIFIER),
            "revision": None, "mode": "default"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    Path(path).chmod(0o600)


def sha(path):
    return INSTALL.sha(path)


def source():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True, timeout=15).strip()
    return {"commit": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
            "dirty": bool(git("status", "--porcelain"))}


def environment(home):
    env = {key: value for key, value in os.environ.items() if key in {"PATH", "LANG"}}
    env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home / "config"),
               XDG_CACHE_HOME=str(home / "cache"), TMPDIR=str(home), PYTHONDONTWRITEBYTECODE="1")
    return env


def snapshot(root):
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        metadata = path.lstat()
        item = {"kind": stat.S_IFMT(metadata.st_mode), "mode": stat.S_IMODE(metadata.st_mode),
                "device": metadata.st_dev, "inode": metadata.st_ino, "links": metadata.st_nlink}
        if stat.S_ISREG(metadata.st_mode):
            item.update(size=metadata.st_size, sha256=sha(path))
        elif stat.S_ISLNK(metadata.st_mode):
            item["target"] = os.readlink(path)
        result[str(path.relative_to(root))] = item
    return result


def key(identifier):
    require(type(identifier) in (str, int), "unsupported JSON-RPC id type")
    return (type(identifier).__name__, identifier)


class ProcessWitness:
    """Observe only owned process IDs/start times through Linux procfs."""
    def __init__(self, parent):
        self.parent, self.observed, self.stopped, self.final = parent, {}, threading.Event(), None
        self.sample()
        def observe():
            while not self.stopped.wait(0.01):
                self.sample()
        self.thread = threading.Thread(target=observe, daemon=True)
        self.thread.start()

    @staticmethod
    def identity(pid):
        try:
            raw = Path(f"/proc/{pid}/stat").read_text()
            fields = raw[raw.rfind(")") + 2:].split()
            return int(fields[19])
        except (OSError, ValueError, IndexError):
            return None

    def sample(self):
        pending, visited = [self.parent], set()
        while pending:
            pid = pending.pop()
            if pid in visited:
                continue
            visited.add(pid)
            identity = self.identity(pid)
            if identity is None:
                continue
            self.observed[(pid, identity)] = {"pid": pid, "start_time_ticks": identity, "parent_process": pid == self.parent}
            try:
                pending.extend(int(value) for value in Path(f"/proc/{pid}/task/{pid}/children").read_text().split())
            except (OSError, ValueError):
                pass

    def finish(self):
        if self.final is not None:
            return self.final
        self.stopped.set()
        self.thread.join(timeout=2)
        deadline = time.monotonic() + 5
        while True:
            alive = [row for (pid, start), row in self.observed.items() if self.identity(pid) == start]
            if not alive or time.monotonic() >= deadline:
                break
            time.sleep(0.02)
        rows = list(self.observed.values())
        self.final = {"observed": rows, "descendant_count": sum(not row["parent_process"] for row in rows),
                      "all_stopped": not alive and not self.thread.is_alive(), "remaining": alive}
        return self.final


class Client:
    """Independent client-side original byte transcript, drained continuously."""
    def __init__(self, command, env, cwd, stderr, label):
        self.label, self.sent, self.received, self.notifications = label, [], [], []
        self.lines = queue.Queue()
        self.forced_cleanup = False
        self.process = subprocess.Popen(command, env=env, cwd=cwd, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=stderr, start_new_session=True)
        self.process_witness = ProcessWitness(self.process.pid)
        def drain():
            while raw := self.process.stdout.readline(1024 * 1024 + 1):
                self.lines.put(raw)
            self.lines.put(None)
        self.reader = threading.Thread(target=drain, daemon=True)
        self.reader.start()

    def send(self, *frames):
        raw = b"".join(json.dumps(frame, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
                       for frame in frames)
        self.sent.extend(raw.splitlines(keepends=True))
        self.process.stdin.write(raw)
        self.process.stdin.flush()

    def receive(self, timeout=35):
        deadline = time.monotonic() + timeout
        while True:
            raw = self.lines.get(timeout=max(0.01, deadline - time.monotonic()))
            require(raw is not None, self.label + " closed before correlated response")
            require(len(raw) <= 1024 * 1024 and raw.endswith(b"\n"), "unbounded/incomplete client response")
            value = json.loads(raw)
            self.received.append(raw)
            if "id" not in value:
                self.notifications.append(value)
                continue
            key(value["id"])
            return value, raw

    def exchange(self, frame):
        self.send(frame)
        result, raw = self.receive()
        require(key(result["id"]) == key(frame["id"]), "JSON-RPC id/type correlation changed")
        return result, raw

    def initialize(self):
        result, _ = self.exchange({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "sou62-owned-acceptance", "version": "1"}}})
        require(result.get("result", {}).get("protocolVersion") == "2025-06-18", "protocol negotiation mismatch")
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        result, _ = self.exchange({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        return result

    def close(self):
        if self.process.stdin and not self.process.stdin.closed:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        try:
            self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            self.forced_cleanup = True
            os.killpg(self.process.pid, 9)
            self.process.wait(timeout=8)
        self.reader.join(timeout=3)
        self.process_witness.finish()
        return self.process.returncode

    def transcript(self):
        return {"sent": [raw.decode("utf-8") for raw in self.sent],
                "received": [raw.decode("utf-8") for raw in self.received],
                "sent_sha256": hashlib.sha256(b"".join(self.sent)).hexdigest(),
                "received_sha256": hashlib.sha256(b"".join(self.received)).hexdigest(),
                "pid": self.process.pid, "exit_code": self.process.returncode, "forced_cleanup": self.forced_cleanup,
                "process_cleanup": self.process_witness.final}


def call(identifier, arguments, tool=TOOL):
    return {"jsonrpc": "2.0", "id": identifier, "method": "tools/call", "params": {
        "name": tool, "arguments": arguments,
        "_meta": {"claudecode/toolUseId": "toolu_sou62_" + str(identifier).replace("-", "n"),
                  "progressToken": abs(identifier) if type(identifier) is int else 900}}}


def cancel(identifier):
    return {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {
        "requestId": identifier, "reason": "owned acceptance cancellation"}}


def result_text(response):
    result = response.get("result", {})
    require(not result.get("isError", False) and "error" not in response, "useful read refused: " + str(response)[:500])
    content = result.get("content")
    require(isinstance(content, list) and len(content) == 1 and content[0].get("type") == "text", "text result missing")
    text = content[0].get("text")
    require(result.get("structuredContent") == {"content": text}, "original structured content was not preserved")
    return text


def refused(response):
    return "error" in response or response.get("result", {}).get("isError") is True


def events(path):
    result = []
    if not path.exists():
        return result
    for line in path.read_bytes().splitlines():
        try:
            record = json.loads(line)
            if record.get("event") == "mcp_real_call":
                result.append(record)
        except (ValueError, UnicodeError):
            continue
    return result


def wait_event(path, predicate, reason, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        values = events(path)
        if predicate(values):
            return values
        time.sleep(0.02)
    raise ValueError(reason)


class FIFOWitness:
    """Owned parent writes only after the actual server has opened each FIFO."""
    def __init__(self, paths):
        self.release = threading.Event()
        self.records = [{"path": path.name, "reader_opened": False, "bytes_written": 0, "error": None} for path in paths]
        self.threads = []
        def writer(path, record):
            descriptor = None
            deadline = time.monotonic() + 25
            try:
                while time.monotonic() < deadline:
                    try:
                        descriptor = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
                        break
                    except OSError as error:
                        if error.errno != errno.ENXIO:
                            raise
                        time.sleep(0.01)
                require(descriptor is not None, "actual server never opened FIFO")
                record["reader_opened"] = True
                require(self.release.wait(timeout=max(0.01, deadline - time.monotonic())), "FIFO release barrier timed out")
                record["bytes_written"] = os.write(descriptor, FIFO_TEXT.encode("utf-8"))
            except Exception as error:
                record["error"] = str(error)
            finally:
                if descriptor is not None:
                    os.close(descriptor)
        for path, record in zip(paths, self.records):
            thread = threading.Thread(target=writer, args=(path, record), daemon=True)
            thread.start()
            self.threads.append(thread)

    def finish(self):
        self.release.set()
        for thread in self.threads:
            thread.join(timeout=30)
        require(all(not thread.is_alive() for thread in self.threads), "FIFO writer failed to stop")


def run_stdio(stack, report):
    log_path = stack.root / "collector.log"
    control_log = stack.root / "control.log"
    binary, node, package = stack.binary, stack.node, stack.install / "package"
    entry = package / "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"
    with control_log.open("wb") as log:
        control = Client([str(node), str(entry), str(stack.workspace)], stack.env, stack.workspace, log, "original server")
        try:
            manifest = control.initialize()
            upstream = json.loads((INSTALL.ASSETS / "upstream-tools-list.json").read_text(encoding="utf-8"))
            require(manifest["result"] == upstream["result"], "original installed server manifest changed")
            response, control_raw = control.exchange(call(10, {"path": str(stack.workspace / "notes.txt")}))
            require(result_text(response) == TEXT, "unwrapped original server read control failed")
            response, _ = control.exchange(call(11, {"path": str(stack.workspace / "control-created.txt"), "content": "owned control"}, "write_file"))
            require(not refused(response) and (stack.workspace / "control-created.txt").read_text() == "owned control",
                    "original server mutation positive control missing")
        finally:
            control.close()
        report["original_server_control"] = control.transcript()
    (stack.workspace / "control-created.txt").unlink()
    baseline = snapshot(stack.workspace)
    env = dict(stack.env, AGENTFW_MCP_SERVER_PROFILE=str(stack.install / "profile.json"),
               AGENTFW_CLASSIFIER="rule-baseline", AGENTFW_RULE_BASELINE=stack.classifier["path"],
               AGENTFW_CLASSIFIER_PYTHON=sys.executable)
    command = [str(binary), "mcp", "--native-admission", "--id", "sou62-filesystem", "--", str(node), str(entry), "/workspace"]
    with log_path.open("wb") as log:
        client = Client(command, env, stack.workspace, log, "protected real server")
        fifo = None
        try:
            manifest = client.initialize()
            require(manifest["result"] == upstream["result"], "protected original discovery changed")
            response, raw = client.exchange(call(10, {"path": "/workspace/notes.txt"}))
            require(result_text(response) == TEXT and raw == control_raw, "original useful result bytes changed")
            report["checks"].append({"case": "original-discovery-and-byte-exact-useful-read", "passed": True})
            schemas = {tool["name"]: hashlib.sha256(INSTALL.canonical(tool["inputSchema"])).hexdigest()
                       for tool in upstream["result"]["tools"]}
            report["readonly_tool_matrix"] = []
            for identifier, (tool, arguments, fragment) in enumerate(READ_CASES, 30):
                response, _ = client.exchange(call(identifier, arguments, tool))
                require(fragment in result_text(response), tool + " lost original useful output")
                report["readonly_tool_matrix"].append({"tool": tool, "arguments": arguments,
                    "schema_sha256": schemas[tool], "registry_sha256": sha(stack.install / "registry.json"),
                    "arguments_sha256": hashlib.sha256(INSTALL.canonical(arguments)).hexdigest(),
                    "response": response, "passed": True})
                report["checks"].append({"case": "actual-tool-" + tool, "passed": True})
            response, _ = client.exchange(call(38, {"path": "/workspace"}, "directory_tree"))
            if stack.classifier["mode"] == "candidate":
                # SOU-97 candidate only: the supported original read is admitted and returns the original tree.
                tree = json.loads(result_text(response))
                require(any(entry.get("name") == "notes.txt" for entry in tree), "candidate directory_tree lost the original tree")
                report["directory_tree_candidate_read"] = {"response": response, "schema_sha256": schemas["directory_tree"],
                    "registry_sha256": sha(stack.install / "registry.json"), "passed": True}
                report["checks"].append({"case": "candidate-directory-tree-admitted-original-read", "passed": True})
            else:
                require(refused(response) and "classifier_ask" in json.dumps(response), "unknown directory_tree classification was bypassed")
                report["directory_tree_classifier_refusal"] = {"response": response, "schema_sha256": schemas["directory_tree"],
                    "registry_sha256": sha(stack.install / "registry.json"), "passed": True}
                report["checks"].append({"case": "directory-tree-classifier-ask-preserved", "passed": True})
            response, _ = client.exchange(call(39, {"path": "/workspace/notes.txt"}))
            require(result_text(response) == TEXT, "classifier Ask broke useful follow-up")
            report["checks"].append({"case": "directory-tree-ask-useful-follow-up", "passed": True})
            fifo_paths = [stack.workspace / f"pending-{index}.fifo" for index in range(8)]
            fifo = FIFOWitness(fifo_paths)
            client.send(*[call(100 + index, {"path": "/workspace/" + path.name}) for index, path in enumerate(fifo_paths)])
            wait_event(log_path, lambda rows: max((row.get("active", 0) for row in rows), default=0) >= 8,
                       "eight actual calls were not active concurrently")
            deadline = time.monotonic() + 12
            while not fifo.records[0]["reader_opened"] and time.monotonic() < deadline:
                time.sleep(0.02)
            require(fifo.records[0]["reader_opened"], "in-flight cancellation lacked independent execution witness")
            client.send(*[call(108 + index, {"path": "/workspace/notes.txt"}) for index in range(8)])
            wait_event(log_path, lambda rows: any(row.get("host_call_id") == 115 and row.get("state") == "queued" for row in rows),
                       "selected queued cancellation target never queued")
            overloaded, _ = client.exchange(call(999, {"path": "/workspace/notes.txt"}))
            require(overloaded.get("error", {}).get("code") == -32003, "overload did not yield a correlated capacity refusal")
            report["overload_response"] = overloaded
            report["checks"].append({"case": "bounded-overload-refusal", "passed": True})
            client.send(cancel(100), cancel(115))
            replies = {}
            for _ in range(2):
                response, _ = client.receive(timeout=10)
                require(response["id"] in (100, 115) and response.get("error", {}).get("code") == -32800,
                        "queued/inflight cancellation did not yield immediate correlated -32800")
                replies[key(response["id"])] = response
            require(len(replies) == 2, "duplicate cancellation reply")
            fifo.finish()
            for _ in range(14):
                response, _ = client.receive()
                identifier = response["id"]
                require(key(identifier) not in replies and type(identifier) is int and 100 <= identifier <= 115,
                        "late/duplicate/unknown response reached client")
                require(result_text(response) == (FIFO_TEXT if identifier <= 107 else TEXT), "cross-call result contents changed")
                replies[key(identifier)] = response
            require(len(replies) == 16, "concurrent call capacity leaked")
            require(all(record["reader_opened"] and record["bytes_written"] == len(FIFO_TEXT.encode()) and record["error"] is None
                        for record in fifo.records), "independent actual execution witness incomplete")
            client.send(cancel(100), cancel(115), cancel("unknown-owned-id"))
            response, _ = client.exchange(call("follow-up", {"path": "/workspace/notes.txt"}))
            require(result_text(response) == TEXT, "late/unknown cancellation broke useful continuation")
            report["fifo_execution_witness"] = fifo.records
            report["concurrent_responses"] = list(replies.values())
            report["checks"].extend({"case": name, "passed": True} for name in (
                "eight-active-eight-queued", "inflight-cancellation", "queued-cancellation", "late-unknown-cancellation",
                "per-call-id-content-correlation", "same-session-useful-follow-up"))
            refusals = [
                ("unsupported-write", "write_file", {"path": "/workspace/new.txt", "content": "must not appear"}),
                ("unsupported-edit", "edit_file", {"path": "/workspace/notes.txt", "edits": [{"oldText": TEXT, "newText": "changed"}]}),
                ("unsupported-mkdir", "create_directory", {"path": "/workspace/new-dir"}),
                ("unsupported-move", "move_file", {"source": "/workspace/notes.txt", "destination": "/workspace/moved.txt"}),
                ("unsupported-media", "read_media_file", {"path": "/workspace/notes.txt"}),
                ("unknown-send", "send_http", {"url": stack.receiver.url, "body": "owned forbidden send"}),
                ("schema-enum", "list_directory_with_sizes", {"path": "/workspace", "sortBy": "invalid"}),
                ("schema-number", TOOL, {"path": "/workspace/notes.txt", "head": "1"}),
                ("schema-missing", TOOL, {}),
                ("schema-extra", TOOL, {"path": "/workspace/notes.txt", "unreviewed": True}),
            ]
            report["refusals"] = []
            for index, (name, tool, arguments) in enumerate(refusals, 200):
                response, _ = client.exchange(call(index, arguments, tool))
                require(refused(response), name + " was not refused")
                report["refusals"].append({"case": name, "response": response, "passed": True})
                response, _ = client.exchange(call(index + 1000, {"path": "/workspace/notes.txt"}))
                require(result_text(response) == TEXT, name + " unnecessarily killed unrelated useful reads")
            report["checks"].extend({"case": row["case"], "passed": True} for row in report["refusals"])
            # A string and integer with the same spelling are distinct JSON-RPC IDs.
            client.send(call(500, {"path": "/workspace/notes.txt"}), call("500", {"path": "/workspace/notes.txt"}))
            typed = [client.receive()[0] for _ in range(2)]
            require({key(item["id"]) for item in typed} == {("int", 500), ("str", "500")}
                    and all(result_text(item) == TEXT for item in typed), "typed JSON-RPC IDs collided")
            report["checks"].append({"case": "integer-string-id-separation", "passed": True})
        finally:
            if fifo:
                fifo.finish()
            client.close()
            report["protected_client"] = client.transcript()
    require(client.process.returncode == 0 and not client.forced_cleanup, "protected collector did not finish normally")
    require(client.process_witness.final["all_stopped"] and client.process_witness.final["descendant_count"] > 0,
            "independent protected server process cleanup incomplete")
    endings = []
    for raw in log_path.read_bytes().splitlines():
        try:
            value = json.loads(raw)
            if value.get("event") == "mcp_real_server_end":
                endings.append(value)
        except ValueError:
            pass
    require(len(endings) == 1 and endings[0].get("cleanup_verified") is True, "collector did not verify selected child cleanup")
    report["protected_cleanup_audit"] = endings[0]
    require(snapshot(stack.workspace) == baseline, "protected real server changed the reviewed workspace")
    require(stack.receiver.bodies == [], "forbidden send reached independent receiver")
    report["workspace_unchanged"] = True
    report["receiver_bodies"] = stack.receiver.bodies.copy()
    rows = events(log_path)
    report["transport_events"] = rows
    report["peak_active"] = max((row.get("active", 0) for row in rows), default=0)
    report["peak_queued"] = max((row.get("queued", 0) for row in rows), default=0)
    require(report["peak_active"] == 8 and report["peak_queued"] >= 8, "bounded concurrency witnesses missing")
    report["collector_log_sha256"] = sha(log_path)
    return command, env


def host_read_presentation(observed):
    """Validate the pinned Claude renderer's structured JSON, never a substring."""
    require(observed.get("is_error") is False, "actual host read was an error")
    original = observed.get("original_content")
    require(isinstance(original, str) and original == observed.get("text"), "unsupported actual host result presentation")
    rendered = re.sub(r"\n\n<system-reminder>\n<total_tokens>[0-9]+ tokens left</total_tokens>\n</system-reminder>$", "", original)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate actual host structured key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonfinite actual host JSON")
    value = json.loads(rendered, object_pairs_hook=pairs, parse_constant=constant)
    require(type(value) is dict and set(value) == {"content"} and value["content"] == TEXT,
            "actual host structured read differs from exact owned content")
    return {"representation": "structured_json", "content_sha256": hashlib.sha256(TEXT.encode("utf-8")).hexdigest(),
            "rendered_sha256": hashlib.sha256(original.encode("utf-8")).hexdigest()}


def host(stack, command, env, report):
    model = DEMO.ScriptedModel([])
    steps = [(TOOL, {"path": "/workspace/notes.txt"}),
             ("write_file", {"path": "/workspace/host-forbidden.txt", "content": "must not appear"}),
             (TOOL, {"path": "/workspace/notes.txt"})]
    def next_step(body):
        if not any(tool.get("name") == "mcp__demo__" + TOOL for tool in body.get("tools", [])):
            return [{"type": "text", "text": "ok"}]
        for message in body.get("messages", []):
            for block in message.get("content", []) if isinstance(message.get("content"), list) else []:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    content = block.get("content")
                    text = content if isinstance(content, str) else "".join(
                        part.get("text", "") for part in content or [] if isinstance(part, dict))
                    model.results[block.get("tool_use_id")] = {"is_error": bool(block.get("is_error")), "text": text,
                        "original_content": content, "original_tool_result": block}
        index = len([identifier for identifier in model.results if str(identifier).startswith("toolu_sou62_")])
        if index < len(steps):
            tool, arguments = steps[index]
            return [{"type": "tool_use", "id": f"toolu_sou62_{index}", "name": "mcp__demo__" + tool, "input": arguments}]
        return [{"type": "text", "text": "Owned MCP checks finished."}]
    model.next = next_step
    profile = stack.root / "claude-home"
    profile.mkdir(mode=0o700)
    project = profile / "project"
    project.mkdir()
    config = profile / "mcp.json"
    log = stack.root / "claude-collector.log"
    wrapper = profile / "collector.py"
    wrapper.write_text("import os,sys\nos.dup2(os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600),2)\nos.chdir(sys.argv[2])\nos.execve(sys.argv[3],sys.argv[3:],dict(os.environ))\n", encoding="utf-8")
    write(config, {"mcpServers": {"demo": {"command": sys.executable,
          "args": ["-I", str(wrapper), str(log), str(stack.workspace), *command], "env": env}}})
    host_env = environment(profile)
    host_env.update(ANTHROPIC_API_KEY="sou62-owned-scripted-provider-only", ANTHROPIC_BASE_URL=model.url,
                    CLAUDE_CONFIG_DIR=str(profile / ".claude"), CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
                    CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL="1", DISABLE_UPDATES="1",
                    HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9", NO_PROXY="127.0.0.1,localhost")
    baseline = snapshot(stack.workspace)
    try:
        process = subprocess.Popen([str(stack.claude), "--restricted", "-p", "Perform the owned MCP tool steps.", "--tools", "",
            "--allowedTools", "mcp__demo__read_text_file,mcp__demo__write_file", "--strict-mcp-config", "--mcp-config", str(config),
            "--no-session-persistence", "--output-format", "stream-json", "--verbose", "--permission-mode", "dontAsk",
            "--model", "claude-sonnet-4-20250514"], cwd=project, env=host_env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        process_witness = ProcessWitness(process.pid)
        try:
            stdout, stderr = process.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, 9)
            process.communicate(timeout=10)
            process_witness.finish()
            raise
        cleanup = process_witness.finish()
        result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
        require(cleanup["all_stopped"] and cleanup["descendant_count"] > 0, "actual host/MCP descendants remain alive")
        messages = []
        for line in result.stdout.splitlines():
            try:
                messages.append(json.loads(line))
            except ValueError:
                pass
        final = [item for item in messages if item.get("type") == "result"]
        initialized = [item for item in messages if item.get("type") == "system" and item.get("subtype") == "init"]
        uses = [block for item in messages if item.get("type") == "assistant"
                for block in item.get("message", {}).get("content", []) if block.get("type") == "tool_use"]
        write(stack.root / "claude-host-raw.json", {"messages": messages, "stderr": result.stderr.decode("utf-8", "replace"),
                                                  "provider_requests": [raw.decode("utf-8") for raw in model.requests]})
        version = subprocess.check_output([str(stack.claude), "--version"], text=True, timeout=15).strip()
        report["actual_claude_host"] = {"status": "incomplete", "exit_code": result.returncode,
            "claude_version": version, "claude_sha256": sha(stack.claude), "model_results": model.results, "host_tool_uses": uses,
            "provider_request_count": len(model.requests), "provider_requests_sha256": hashlib.sha256(b"".join(model.requests)).hexdigest(),
            "raw_output_sha256": hashlib.sha256(result.stdout).hexdigest(), "collector_log_sha256": sha(log) if log.is_file() else None,
            "process_cleanup": cleanup, "mcp_shutdown_graceful": None,
            "real_host_executed": True, "scripted_owned_provider": True, "live_model_efficacy_measured": False}
        protected_values = [host_env["ANTHROPIC_API_KEY"]]
        for name in ("token", "native-token"):
            protected = stack.home / ".agentfw" / name
            if protected.is_file():
                protected_values.append(protected.read_text(encoding="utf-8").strip())
        def sanitized(value):
            text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
            for secret in protected_values:
                if secret:
                    text = text.replace(secret, "<redacted-owned-credential>")
            return text
        def host_check(condition, reason):
            if not condition:
                diagnostic = {"event": "sou62_actual_host_failure", "reason": reason,
                    "exit_code": result.returncode, "claude_version": version,
                    "owned_model_results": sanitized(json.dumps(model.results, ensure_ascii=False))[:6000],
                    "host_tool_uses": uses, "stdout_tail": sanitized(result.stdout)[-3000:],
                    "stderr_tail": sanitized(result.stderr)[-3000:]}
                print(json.dumps(diagnostic, ensure_ascii=False), flush=True)
                raise ValueError(reason + "; owned model results=" + diagnostic["owned_model_results"])
        host_check(result.returncode == 0 and len(final) == 1 and not final[0].get("is_error"), "actual Claude Code did not finish")
        host_check(initialized and any(server.get("name") == "demo" and server.get("status") == "connected"
                                   for server in initialized[0].get("mcp_servers", [])), "actual host did not connect installed real server")
        host_check(uses == [{"type": "tool_use", "id": f"toolu_sou62_{index}", "name": "mcp__demo__" + tool, "input": args}
                         for index, (tool, args) in enumerate(steps)], "actual host did not propose exact owned read/write/follow-up")
        presentations = {}
        for index in (0, 2):
            identifier = f"toolu_sou62_{index}"
            try:
                presentations[identifier] = host_read_presentation(model.results.get(identifier, {}))
            except (ValueError, TypeError, KeyError) as error:
                host_check(False, "actual host/provider lacked exact structured read/follow-up: " + str(error))
        report["actual_claude_host"]["read_presentations"] = presentations
        host_check(model.results.get("toolu_sou62_1", {}).get("is_error") is True, "actual host forbidden write was not refused")
        host_check(snapshot(stack.workspace) == baseline and stack.receiver.bodies == [], "actual host caused unapproved effects")
        host_check(version == "2.1.251 (Claude Code)", "actual Claude Code version differs from selected host pin")
        report["actual_claude_host"]["status"] = "pass"
    finally:
        model.close()


def daemon_loss(stack, command, env, report):
    """A fresh actual session must not dispatch a FIFO read after daemon loss."""
    baseline = snapshot(stack.workspace)
    with (stack.root / "daemon-loss-collector.log").open("wb") as log:
        client = Client(command, env, stack.workspace, log, "daemon-loss real server")
        try:
            client.initialize()
            response, _ = client.exchange(call(700, {"path": "/workspace/notes.txt"}))
            require(result_text(response) == TEXT, "outage control read failed")
            DEMO.stop(stack.daemon)
            require(stack.daemon.poll() is not None, "owned daemon did not stop before outage call")
            client.send(call(701, {"path": "/workspace/pending-0.fifo"}))
            observed = None
            try:
                observed, _ = client.receive(timeout=8)
            except ValueError as error:
                require("closed before correlated response" in str(error), "unexpected outage parse failure")
            if observed is not None:
                require(key(observed["id"]) == key(701) and refused(observed), "daemon loss released unadmitted data")
            # No reader can open the FIFO if call admission refused before dispatch.
            try:
                descriptor = os.open(stack.workspace / "pending-0.fifo", os.O_WRONLY | os.O_NONBLOCK)
            except OSError as error:
                require(error.errno == errno.ENXIO, "outage FIFO probe failed unexpectedly")
            else:
                os.close(descriptor)
                raise ValueError("server opened the unadmitted outage FIFO")
            report["daemon_loss"] = {"status": "pass", "native_daemon_stopped_first": True,
                "unadmitted_fifo_reader_absent": True, "response": observed}
            report["checks"].append({"case": "daemon-loss-refuses-without-execution", "passed": True})
        finally:
            client.close()
            report.setdefault("daemon_loss", {"status": "fail"})["client"] = client.transcript()
    require(client.process_witness.final["all_stopped"] and client.process_witness.final["descendant_count"] > 0,
            "outage selected child cleanup incomplete")
    require(snapshot(stack.workspace) == baseline and stack.receiver.bodies == [], "outage caused unapproved effects")


def policy_controls(stack, report):
    before = snapshot(stack.workspace)
    calibration_body = b"sou62-owned-receiver-calibration"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(stack.receiver.url, calibration_body, method="POST"), timeout=5) as response:
        require(response.status == 200, "owned receiver calibration did not succeed")
    require(stack.receiver.bodies == [calibration_body.decode()], "independent receiver calibration missing")
    report["receiver_calibration"] = {"passed": True, "delivered_bytes": len(calibration_body),
                                      "body_sha256": hashlib.sha256(calibration_body).hexdigest()}
    stack.receiver.bodies.clear()
    commands = [
        ("clean-session-write-deny", ["guarded-delete", "--workspace", str(stack.workspace), "--path", "notes.txt"]),
        ("clean-session-network-deny", ["guarded-shell", "--workspace", str(stack.workspace),
            "--session", "sou62-clean-owned-post", "--", "curl", "--data", "sou62-owned-send-attempt", stack.receiver.url])]
    rows = []
    for name, arguments in commands:
        command = [str(stack.binary), *arguments]
        if name == "clean-session-write-deny":
            command.extend(["--session", "sou62-clean-" + name])
        result = subprocess.run(command, env=stack.env,
                                capture_output=True, text=True, timeout=20)
        rule = "filesystem-profile-deny-write" if name == "clean-session-write-deny" else "filesystem-profile-deny-network"
        require(result.returncode != 0 and "verdict=deny" in result.stderr and rule in result.stderr,
                name + " shipped policy did not hard Deny: " + result.stderr[-500:])
        rows.append({"case": name, "exit_code": result.returncode, "rule": rule, "verdict": "deny", "passed": True,
                     "proposal": "owned_http_post" if name == "clean-session-network-deny" else "guarded_file_delete"})
    require(snapshot(stack.workspace) == before and stack.receiver.bodies == [], "policy probe caused an effect")
    registry = json.loads((stack.install / "registry.json").read_text())
    declaration = next(tool for tool in registry["tools"] if tool["name"] == "move_file")
    token = (stack.home / ".agentfw/native-token").read_text().strip()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    session = "sou62-clean-destructive-policy"
    def native(event, **fields):
        value = {"contract_version": "sw-native/1", "registry_sha256": sha(stack.install / "registry.json"),
                 "session_id": session, "event": event, **fields}
        request = urllib.request.Request(f"http://127.0.0.1:{stack.port}/native/v1", INSTALL.canonical(value),
            {"Content-Type": "application/json", "Authorization": "Bearer " + token})
        with opener.open(request, timeout=10) as response:
            return json.loads(response.read(65537))
    require(native("session_start").get("release") is True, "clean native policy session did not open")
    try:
        receipt = native("call", tool="move_file", args={"source": "/workspace/notes.txt", "destination": "/workspace/moved.txt"},
                         schema_sha256=declaration["schema_sha256"])
        require(receipt.get("verdict") == "deny" and receipt.get("release") is False
                and "filesystem-profile-deny-destructive" in receipt.get("reason_codes", [])
                and receipt.get("call_id") is None, "actual declared destructive clean-session native call was not hard denied")
        rows.append({"case": "clean-session-destructive-deny", "verdict": "deny", "passed": True,
                     "rule": "filesystem-profile-deny-destructive", "receipt": receipt,
                     "schema_sha256": declaration["schema_sha256"], "registry_sha256": sha(stack.install / "registry.json")})
    finally:
        require(native("session_end").get("release") is True, "clean native policy session did not close")
    require(snapshot(stack.workspace) == before and stack.receiver.bodies == [], "native policy probe caused an effect")
    report["shipped_policy_controls"] = rows


def candidate_replay(stack, command, env, report):
    """SOU-97 candidate mode only: replay the frozen matrix through fresh protected sessions."""
    def open_session(index):
        log_path = stack.root / f"sou97-replay-collector-{index}.log"
        log = log_path.open("wb")
        client = Client(command, env, stack.workspace, log, f"sou97 replay session {index}")
        stack.replay_logs.append((client, log))
        client.initialize()
        return client, log_path

    def continuation(client, identifier):
        try:
            response, _ = client.exchange(call(identifier, {"path": "/workspace/notes.txt"}))
            return not refused(response) and result_text(response) == TEXT
        except ValueError:
            return False  # recorded as a failed continuation, never as success

    calibration_client, _ = open_session("calibration")
    try:
        calibration = REPLAY.calibrate(stack.workspace, snapshot, stack.witness_cls,
                                       lambda: continuation(calibration_client, 2999))
    finally:
        calibration_client.close()
    result, failures = REPLAY.replay("filesystem", open_session=open_session, events=events, snapshot=snapshot,
                                     workspace=stack.workspace, witness_cls=stack.witness_cls, receiver=stack.receiver,
                                     continuation=continuation, responses_path=stack.root / "sou97-replay-responses.jsonl",
                                     prepare=lambda case: REPLAY.seed_case(stack.workspace, case), restore=REPLAY.unseed_case)
    for client, log in stack.replay_logs:
        log.close()
        require(client.process_witness.final is None or client.process_witness.final["all_stopped"],
                "replay session cleanup incomplete")
    stack.sou97 = {"result": result, "failures": failures, "calibration": calibration}
    report["sou97_replay"] = {"cases": len(result["cases"]), "sessions": result["sessions"], "failures": failures,
                              "calibration": calibration}
    report["checks"].append({"case": "sou97-candidate-matrix-replay", "passed": not failures})


def write_sou97_evidence(stack, report, args):
    if stack.classifier["mode"] != "candidate":
        return
    replayed = getattr(stack, "sou97", None) or {"result": None, "failures": [{"case": None, "expected": "replay completed"}],
                                                 "calibration": {}}
    evidence = REPLAY.evidence(
        "filesystem", status=report["status"], source=report.get("source_before", {}), classifier=stack.classifier,
        replay_result=replayed["result"], failures=replayed["failures"], calibration=replayed["calibration"],
        identities={"agent_binary_sha256": report.get("binary_sha256"), "driver_sha256": report.get("driver_sha256"),
                    "replay_module_sha256": sha(ROOT / "scripts/sou97_runtime_replay.py"),
                    "installed_policy_sha256": report.get("installed_profile", {}).get("policy_sha256"),
                    "upstream_package": "@modelcontextprotocol/server-filesystem@2026.8.31"},
        runtime={name: digest for name, digest in (
            ("node", report.get("installed_profile", {}).get("profile", {}).get("runtimeSha256")),
            ("bwrap", report.get("installed_profile", {}).get("profile", {}).get("bwrapSha256")),
            ("package_tree", report.get("installed_profile", {}).get("profile", {}).get("packageTreeSha256")),
            ("sandbox_test_binary", report.get("sandbox_test_binary_sha256")),
            ("claude", report.get("claude_sha256"))) if digest},
        witnesses={"daemon_stopped": report.get("daemon_stopped") is True,
                   "workspace_unchanged": report.get("workspace_unchanged") is True,
                   "egress_bodies": len(stack.receiver.bodies)},
        error=report.get("error"))
    write(stack.root / "sou97-runtime-evidence.json", evidence)


def grade(report):
    """Reject incomplete evidence; a process exit or claimed pass is insufficient."""
    require(report["source_before"] == report["source_after"] and report["source_before"]["dirty"] is False,
            "source identity is incomplete")
    require(report["skipped"] == 0 and report["failed"] == 0, "required evidence was skipped or failed")
    for name in ("binary_sha256", "sandbox_test_binary_sha256", "driver_sha256", "claude_sha256"):
        require(re.fullmatch(r"[a-f0-9]{64}", report[name]) is not None, "exact binary/source witness missing")
    require(report["required_positive_sandbox"]["status"] == "pass"
            and report["required_positive_sandbox"]["exit_code"] == 0
            and all(report["required_positive_sandbox"]["witnesses"].get(name) is True for name in SANDBOX_WITNESSES),
            "required positive sandbox missing")
    matrix = report["readonly_tool_matrix"]
    require(len(matrix) == len(READ_CASES), "actual read-only tool matrix incomplete")
    for row, (tool, arguments, fragment) in zip(matrix, READ_CASES):
        require(row["tool"] == tool and row["arguments"] == arguments and row["passed"] is True
                and fragment in result_text(row["response"])
                and row["registry_sha256"] == report["installed_profile"]["registry_sha256"]
                and row["arguments_sha256"] == hashlib.sha256(INSTALL.canonical(arguments)).hexdigest(), "actual tool matrix binding changed")
    if report.get("classifier", {}).get("mode") == "candidate":
        tree_read = report["directory_tree_candidate_read"]
        require(tree_read["passed"] is True and not refused(tree_read["response"])
                and any(entry.get("name") == "notes.txt" for entry in json.loads(result_text(tree_read["response"]))),
                "candidate directory_tree admitted read missing")
        replayed = report["sou97_replay"]
        require(replayed["failures"] == [] and replayed["cases"] > 0, "candidate matrix replay failed")
    else:
        tree_refusal = report["directory_tree_classifier_refusal"]
        require(tree_refusal["passed"] is True and refused(tree_refusal["response"])
                and "classifier_ask" in json.dumps(tree_refusal["response"]), "directory tree unknown Ask was bypassed")
    require(report["peak_active"] == 8 and report["peak_queued"] >= 8, "multiple pending execution not witnessed")
    witnesses = report["fifo_execution_witness"]
    require(len(witnesses) == 8 and all(item["reader_opened"] is True and item["bytes_written"] == len(FIFO_TEXT.encode())
            and item["error"] is None for item in witnesses), "independent execution witness missing")
    replies = report["concurrent_responses"]
    require(len(replies) == 16 and {key(item["id"]) for item in replies} == {("int", identifier) for identifier in range(100, 116)},
            "concurrent correlation incomplete")
    for item in replies:
        identifier = item["id"]
        if identifier in (100, 115):
            require(item.get("error", {}).get("code") == -32800, "cancellation was not correlated")
        else:
            require(result_text(item) == (FIFO_TEXT if identifier <= 107 else TEXT), "cross-call release changed")
    require(report["overload_response"].get("error", {}).get("code") == -32003, "capacity refusal missing")
    require(report["daemon_loss"]["status"] == "pass" and report["daemon_loss"]["native_daemon_stopped_first"] is True
            and report["daemon_loss"]["unadmitted_fifo_reader_absent"] is True, "daemon loss containment proof missing")
    refusals = report["refusals"]
    require(len(refusals) == 10 and len({row["case"] for row in refusals}) == 10
            and all(row["passed"] is True and refused(row["response"]) for row in refusals), "unsupported/schema refusal missing")
    require(report["workspace_unchanged"] is True and report["receiver_bodies"] == [], "unapproved effect witnessed")
    require(all(report[name] is True for name in ("daemon_stopped", "private_profile_removed", "installed_profile_unchanged", "runtime_unchanged")),
            "cleanup or immutable runtime identity incomplete")
    cleanup = report["protected_client"]
    require(cleanup["exit_code"] == 0 and cleanup["forced_cleanup"] is False
            and cleanup["process_cleanup"]["all_stopped"] is True and cleanup["process_cleanup"]["descendant_count"] > 0
            and report["protected_cleanup_audit"]["cleanup_verified"] is True, "normal selected server cleanup unverified")
    require(report["receiver_calibration"]["passed"] is True and report["receiver_calibration"]["delivered_bytes"] > 0,
            "independent receiver was not calibrated")
    policy = report["shipped_policy_controls"]
    require(len(policy) == 3 and all(row["verdict"] == "deny" and row["passed"] is True for row in policy),
            "installed clean-session policy proof missing")
    host = report["actual_claude_host"]
    for index in (0, 2):
        identifier = f"toolu_sou62_{index}"
        require(host_read_presentation(host["model_results"][identifier]) == host["read_presentations"][identifier],
                "actual host read presentation receipt differs")
    require(host["model_results"]["toolu_sou62_1"]["is_error"] is True, "actual host write refusal missing")
    require(isinstance(host.get("collector_log_sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", host["collector_log_sha256"]) is not None,
            "actual host collector log identity missing")
    require(host["status"] == "pass" and host["exit_code"] == 0 and host["real_host_executed"] is True
            and host["scripted_owned_provider"] is True and host["live_model_efficacy_measured"] is False
            and host["process_cleanup"]["all_stopped"] is True and host["process_cleanup"]["descendant_count"] > 0
            and host["claude_sha256"] == report["claude_sha256"] and host["claude_version"] == "2.1.251 (Claude Code)",
            "actual installed Claude host evidence missing")


def run(args):
    output, binary, node, bwrap, claude, tests = [path.resolve() for path in (
        args.output, args.agentfw, args.node, args.bwrap, args.claude, args.sandbox_test_binary)]
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "required positive acceptance needs Linux x86-64")
    require(all(path.is_file() for path in (binary, node, bwrap, claude, tests)), "all exact runtime/build prerequisites are required")
    require(not output.exists() and not output.is_relative_to(ROOT), "output must be a new directory outside the candidate")
    before = source()
    require(before["commit"] == args.expected_commit and not before["dirty"], "clean exact candidate required")
    output.mkdir(mode=0o700, parents=True)
    report = {"format": "sou62-real-mcp-acceptance/1", "status": "incomplete", "observed_at": datetime.now(timezone.utc).isoformat(),
              "source_before": before, "binary_sha256": sha(binary), "sandbox_test_binary_sha256": sha(tests),
              "driver_sha256": sha(Path(__file__)), "claude_sha256": sha(claude), "checks": [], "passed": 0, "failed": 0, "skipped": 0,
              "live_model_efficacy_measured": False, "environment": {"system": platform.system(), "kernel": platform.release(),
              "architecture": platform.machine(), "python": platform.python_version()}}
    from types import SimpleNamespace
    stack = SimpleNamespace(root=output, binary=binary, node=node, claude=claude, replay_logs=[])
    stack.classifier = (REPLAY.classifier_identity(args.classifier_script, args.classifier_sha256)
                        if args.classifier_script else default_classifier())
    report["classifier"] = {k: v for k, v in stack.classifier.items() if k != "path"}
    if stack.classifier["mode"] == "candidate":
        stack.witness_cls = load("sou62_sou97_witness", "verify-sou68-real-mcp.py").RepositoryWitness
    daemon = None
    receiver = stack.receiver = DEMO.Receiver()
    try:
        with tempfile.TemporaryDirectory(prefix="sou62-owned-") as temporary:
            private = Path(temporary)
            stack.workspace = private / "workspace"
            stack.workspace.mkdir(mode=0o700)
            (stack.workspace / "notes.txt").write_text(TEXT, encoding="utf-8")
            for index in range(8):
                os.mkfifo(stack.workspace / f"pending-{index}.fifo", 0o600)
            stack.install = private / "installed-profile"
            INSTALL.install(stack.install, stack.workspace, node, bwrap, args.npm)
            report["installed_profile"] = json.loads((stack.install / "installation.json").read_text())
            stack.home = private / "home"
            stack.home.mkdir(mode=0o700)
            stack.env = environment(stack.home)
            subprocess.run([str(binary), "install"], env=stack.env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, check=True, timeout=30)
            port = stack.port = DEMO.free_port()
            config = {"port": port, "enforce": True, "max_record_bytes": 1048576, "policy": str(stack.install / "policy.yaml"),
                      "native": {"registry_path": str(stack.install / "registry.json"), "registry_sha256": sha(stack.install / "registry.json")}}
            write(stack.home / ".agentfw/config.yaml", config)
            positive_env = dict(stack.env, SOU62_SANDBOX_TEST_PROFILE=str(stack.install / "profile.json"),
                                SOU86_TEST_AGENTFW=str(binary))
            try:
                positive = subprocess.run([str(tests), "selected_server_sandbox_isolates_real_node", "--ignored", "--nocapture"],
                                          env=positive_env, capture_output=True, timeout=90)
            except subprocess.TimeoutExpired as error:
                partial = (error.stdout or b"") + (error.stderr or b"")
                (output / "sandbox-positive.log").write_bytes(partial)
                print(json.dumps({"event": "sou62_required_sandbox_timeout", "timeout_seconds": 90,
                                  "owned_probe_output_tail": partial[-6000:].decode("utf-8", "replace")}), flush=True)
                raise
            (output / "sandbox-positive.log").write_bytes(positive.stdout + positive.stderr)
            marker = positive.stdout + positive.stderr
            witnesses = {name: (name + "=true").encode() in marker for name in SANDBOX_WITNESSES}
            positive_passed = (positive.returncode == 0 and b"SOU62_SANDBOX_POSITIVE" in marker and all(witnesses.values())
                               and re.search(rb"1 passed; 0 failed", positive.stdout))
            if not positive_passed:
                # Only the owned Rust/Node sandbox probe runs here. Keep its
                # bounded failure visible even if artifact download is unavailable.
                diagnostic = {"event": "sou62_required_sandbox_failure", "exit_code": positive.returncode,
                              "witnesses": witnesses, "owned_probe_output_tail": marker[-6000:].decode("utf-8", "replace")}
                print(json.dumps(diagnostic, ensure_ascii=False), flush=True)
            require(positive_passed, "required positive sandbox acceptance failed; exit=" + str(positive.returncode)
                    + "; missing=" + ",".join(name for name, passed in witnesses.items() if not passed)
                    + "; owned probe tail=" + marker[-6000:].decode("utf-8", "replace"))
            report["required_positive_sandbox"] = {"status": "pass", "exit_code": positive.returncode,
                                                    "log_sha256": sha(output / "sandbox-positive.log"), "witnesses": witnesses}
            with (output / "daemon.log").open("wb") as log:
                daemon = stack.daemon = subprocess.Popen([str(binary), "serve"], env=stack.env, stdout=log, stderr=log)
                require(DEMO.wait_healthy(port, daemon), "owned enforcing daemon failed to start")
                policy_controls(stack, report)
                command, env = run_stdio(stack, report)
                host(stack, command, env, report)
                if stack.classifier["mode"] == "candidate":
                    candidate_replay(stack, command, env, report)
                daemon_loss(stack, command, env, report)
            report["daemon_stopped"] = daemon.poll() is not None
            report["installed_profile_unchanged"] = (
                sha(stack.install / "profile.json") == report["installed_profile"]["profile_sha256"]
                and sha(stack.install / "policy.yaml") == report["installed_profile"]["policy_sha256"]
                and sha(stack.install / "registry.json") == report["installed_profile"]["registry_sha256"]
                and INSTALL.tree_sha(stack.install / "package") == report["installed_profile"]["profile"]["packageTreeSha256"]
                and all(sha(stack.install / notice["path"]) == notice["sha256"] for notice in report["installed_profile"]["upstream_notices"]))
            report["runtime_unchanged"] = (sha(node) == report["installed_profile"]["profile"]["runtimeSha256"]
                and sha(bwrap) == report["installed_profile"]["profile"]["bwrapSha256"]
                and sha(claude) == report["claude_sha256"] and sha(tests) == report["sandbox_test_binary_sha256"])
            require(report["installed_profile_unchanged"] and report["runtime_unchanged"], "installed package/profile/policy/runtime identity drifted")
        report["private_profile_removed"] = not private.exists()
        report["source_after"] = source()
        require(report["source_after"] == before and sha(binary) == report["binary_sha256"], "candidate changed during acceptance")
        require(report["private_profile_removed"] and report["daemon_stopped"], "owned runtime cleanup incomplete")
        grade(report)
        report["status"] = "pass"
        report["passed"] = len(report["checks"]) + len(report["shipped_policy_controls"]) + 2
    except Exception as error:
        report["status"], report["failed"], report["error"] = "fail", 1, type(error).__name__ + ": " + str(error)
    finally:
        if daemon is not None:
            DEMO.stop(daemon)
        receiver.close()
        write(output / "report.json", report)
        write_sou97_evidence(stack, report, args)
    print(json.dumps({"status": report["status"], "passed": report["passed"], "failed": report["failed"],
                      "skipped": report["skipped"], "error": report.get("error"), "report": str(output / "report.json")}))
    return 0 if report["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--bwrap", type=Path, required=True)
    parser.add_argument("--claude", type=Path, required=True)
    parser.add_argument("--sandbox-test-binary", type=Path, required=True)
    parser.add_argument("--npm", type=Path, default=Path(shutil.which("npm") or "npm"))
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--classifier-script", type=Path, help="SOU-97 opt-in candidate classifier (default: frozen baseline)")
    parser.add_argument("--classifier-sha256", help="required exact sha256 of --classifier-script")
    args = parser.parse_args()
    if bool(args.classifier_script) != bool(args.classifier_sha256):
        parser.error("--classifier-script and --classifier-sha256 must be given together")
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False, "required_positive_sandbox": True,
                          "profile": PROFILE, "real_server": "@modelcontextprotocol/server-filesystem@2026.8.31",
                          "actual_claude_host_required": True, "scripted_owned_provider": True, "live_model": False}))
        return 0
    try:
        return run(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "fail", "failed": 1, "skipped": 0, "error": str(error)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
