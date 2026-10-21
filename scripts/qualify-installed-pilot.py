#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One development-only installed Linux/WSL pilot exercise (SOU-100).

No live provider, kit builder, installer replacement or user profile is used.
The caller supplies an exact selection made after the normal locked build.
Preparation reuses the original filesystem/Git profile installers. Runtime
Agent, classifiers, profiles and host project live outside the source checkout.
Missing prerequisites and incomplete positives return nonzero with a report.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from pilot_qualification import CASES, LIMITS, Failure, canonical, digest, measure, new_report, require, sha, write_report
import wsl_preflight

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load("pilot_filesystem", "verify-sou62-real-mcp.py")
GIT = load("pilot_git", "verify-sou68-real-mcp.py")
SHARED = load("pilot_shared", "verify-sou62-sou63-combined.py")
RESOURCE = load("pilot_bounded_capture", "verify-sou79-resource-budgets.py")
EXECUTABLE_ROLES = ("agentfw", "git_launcher", "sandbox_tests", "node", "npm", "bwrap", "git", "claude", "python")
ARTIFACT_ROLES = ("filesystem_classifier", "git_classifier", "policy")
ROLES = EXECUTABLE_ROLES + ARTIFACT_ROLES
TOOLS = {"filesystem": ("read_text_file", "list_directory", "write_file"),
         "git": ("git_show", "git_status", "git_diff", "git_reset")}
POINTER = "/workspace/forbidden.fifo\n"
NOTES = "Owned pilot working notes: inspect the pending change; café, қазақша.\n"
# The filesystem-only proof policy denies even a LOW heuristic finding. Its
# long-base64 signal also matches ordinary Git object IDs. Keep the existing
# rules, but use an explicit pilot threshold rather than altering a detector,
# suppressing Git metadata or presenting that stricter policy as useful here.
PILOT_POLICY = SHARED.PROOF_POLICY.replace(
    "when: { detector: injection, facet: tool_result }",
    "when: { detector: injection, facet: tool_result, min_severity: medium }")


def private_json(path, value):
    BASE.write(path, value)


def owned_bytes(path, value):
    with Path(path).open("xb") as stream:
        Path(path).chmod(0o600)
        stream.write(value)


def strict_json(raw):
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result, "duplicate_json_input_key")
            result[name] = value
        return result
    def invalid(_):
        raise Failure("nonfinite_json_input")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def source():
    result = BASE.source()
    files = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT, timeout=15).split(b"\0")
    result["files_sha256"] = digest({os.fsdecode(name): sha(ROOT / os.fsdecode(name)) for name in files if name})
    return result


def validate_selection(selection, expected):
    require(selection.get("format") == "sw-installed-pilot-selection/2", "selection_version")
    before = source()
    require(not before["dirty"] and before["commit"] == expected
            and selection["source"] == before, "candidate_source_mismatch")
    require(set(selection["files"]) == set(ROLES), "selection_roles_mismatch")
    expectation = selection.get("expected_refusal", {})
    require(set(expectation) == {"verdict", "rule"} and expectation["verdict"] in ("ask", "deny")
            and isinstance(expectation["rule"], str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", expectation["rule"]),
            "forbidden_action_expectation_required")
    paths = {}
    for role in ROLES:
        item = selection["files"][role]
        require(Path(item["path"]).is_absolute(), "absolute_selected_path_required")
        unavailable = "selected_executable_unavailable" if role in EXECUTABLE_ROLES else "selected_artifact_unavailable"
        changed = "selected_executable_changed" if role in EXECUTABLE_ROLES else "selected_artifact_changed"
        require(Path(item["path"]).is_file(), unavailable)
        path = Path(item["path"]).resolve(strict=True)
        require(path.is_file() and (os.access(path, os.X_OK) if role in EXECUTABLE_ROLES
                else path.stat().st_size <= 1024 * 1024), unavailable)
        require(re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) and sha(path) == item["sha256"],
                changed)
        paths[role] = path
    return before, paths


def result_injection_refusal(response, rows, host, agent):
    refusals = [row for row in rows if row.get("event") == "native_result"
                and row.get("host_session") == host and row.get("agent_id") == agent
                and row.get("tool") == "git_show" and row.get("verdict") == "deny"
                and row.get("released") is False and row.get("shadow") is False
                and any(finding.get("detector") == "injection" for finding in row.get("findings", []))]
    require(len(refusals) == 1 and isinstance(refusals[0].get("rule"), str)
            and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", refusals[0]["rule"]), "native_injection_refusal_missing")
    require(BASE.refused(response) and refusals[0]["rule"] in json.dumps(response)
            and GIT.INJECTION not in json.dumps(response), "git_injection_result_released")
    return {"verdict": "deny", "rule": refusals[0]["rule"], "released": False,
            "native_audit_sha256": digest(refusals[0])}


class BoundedStream:
    """Drain continuously; retain bounded owned output, never block the child."""
    def __init__(self, stream):
        self.data, self.total, self.error, self.hash = bytearray(), 0, None, hashlib.sha256()
        def drain():
            try:
                while raw := os.read(stream.fileno(), 65536):
                    self.total += len(raw)
                    self.hash.update(raw)
                    self.data.extend(raw[:max(0, LIMITS["host_bytes"] - len(self.data))])
            except OSError:
                self.error = "stream_read_failed"
            finally:
                stream.close()
        self.thread = threading.Thread(target=drain, daemon=True)
        self.thread.start()

    def finish(self):
        self.thread.join(timeout=3)
        require(not self.thread.is_alive() and self.error is None, "stream_incomplete")
        require(self.total <= LIMITS["host_bytes"], "host_output_limit")
        return bytes(self.data)


class BoundedRequests(list):
    """Apply the provider bound even to auxiliary/count-token requests."""
    def __init__(self):
        super().__init__()
        self.bytes = 0

    def append(self, raw):
        require(type(raw) is bytes and len(self) < LIMITS["provider_requests"]
                and self.bytes + len(raw) <= LIMITS["host_bytes"], "provider_request_bound")
        self.bytes += len(raw)
        super().append(raw)


class Client(BASE.Client):
    def __init__(self, command, env, cwd, stderr, label):
        self.label, self.sent, self.received, self.notifications = label, [], [], []
        self.forced_cleanup, self.closed = False, False
        self.unexpected_replies, self.stream_evidence = [], None
        self.process = subprocess.Popen(command, env=env, cwd=cwd, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=stderr, start_new_session=True)
        self.process_witness = BASE.ProcessWitness(self.process.pid)
        # Reuse the accepted bounded protocol observer. The parent base client
        # is convenient for exchanges, but its unbounded queue is unsuitable
        # for an installed-candidate qualification of unexpected/late output.
        self.capture = RESOURCE.Capture(self.process.stdout, True)
        self.lines, self.reader = self.capture.frames, self.capture.thread

    def close(self):
        if self.closed:
            return self.process.returncode
        result = super().close()
        self.stream_evidence = self.capture.finish()
        while True:
            try:
                raw = self.lines.get_nowait()
            except queue.Empty:
                break
            if raw is None:
                continue
            self.received.append(raw)
            value = strict_json(raw)
            if "id" in value:
                self.unexpected_replies.append(value["id"])
            else:
                self.notifications.append(value)
        self.closed = True
        return result

    def validate_capture(self):
        require(self.closed and self.stream_evidence["error"] is None
                and self.stream_evidence["thread_stopped"] is True
                and self.stream_evidence["bytes"] <= LIMITS["host_bytes"]
                and not self.unexpected_replies, "client_wire_observation_incomplete")

    def receive(self, timeout=35):
        value, raw = super().receive(timeout)
        require(strict_json(raw) == value, "client_wire_parse_changed")
        return value, raw

    def transcript(self):
        return {**super().transcript(), "stream_capture": self.stream_evidence,
                "unexpected_reply_ids": self.unexpected_replies}

    def initialize(self):
        protocol = "2025-11-25" if self.kind == "git" else "2025-06-18"
        response, _ = self.exchange({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": protocol, "capabilities": {}, "clientInfo": {"name": "installed-pilot", "version": "1"}}})
        require(response.get("result", {}).get("protocolVersion") == protocol, "original_protocol_changed")
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        response, _ = self.exchange({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        assets = GIT.INSTALL.ASSETS if self.kind == "git" else BASE.INSTALL.ASSETS
        original = json.loads((assets / "upstream-tools-list.json").read_text())["result"]
        require(response.get("result") == original, "original_manifest_changed")
        return response


def text(response, kind):
    return GIT.text(response) if kind == "git" else BASE.result_text(response)


def frame(identifier, kind, tool, arguments):
    value = BASE.call(identifier, arguments, tool)
    if kind == "git":
        value["params"]["arguments"] = {"repo_path": "/workspace", **arguments}
    return value


def host_text(value, kind):
    require(value.get("is_error") is False, "host_useful_result_missing")
    if kind == "git" and isinstance(value.get("content"), list):
        blocks = value["content"]
        require(0 < len(blocks) <= 32 and all(type(block) is dict and set(block) == {"type", "text"}
                and block["type"] == "text" and isinstance(block["text"], str) for block in blocks),
                "host_original_text_blocks_changed")
        return "".join(block["text"] for block in blocks)
    require(isinstance(value.get("content"), str), "host_useful_result_missing")
    content = re.sub(r"\n\n?<system-reminder>\n<total_tokens>[0-9]+ tokens left</total_tokens>\n</system-reminder>$",
                     "", value["content"])
    if kind == "filesystem":
        def pairs(items):
            result = {}
            for name, item in items:
                require(name not in result, "host_duplicate_structured_key")
                result[name] = item
            return result
        def invalid_constant(_):
            raise Failure("host_nonfinite_structured_value")
        value = json.loads(content, object_pairs_hook=pairs, parse_constant=invalid_constant)
        require(type(value) is dict and set(value) == {"content"} and isinstance(value["content"], str),
                "host_original_structured_content_changed")
        return value["content"]
    return content


class Pilot:
    def __init__(self, private, output, paths, report, expected_refusal=None):
        self.private, self.output, self.paths, self.report = private, output, paths, report
        self.selected_sha256 = report.get("selected_sha256") or {role: sha(path) for role, path in paths.items()}
        self.clients, self.logs, self.hosts, self.secrets, self.bindings = [], [], [], [], []
        self.daemon = self.daemon_witness = self.unrelated = None
        self.installed, self.baseline, self.controls = {}, None, {}
        self.expected_refusal = expected_refusal or {"verdict": "ask", "rule": SHARED.RULE}
        self.home = private / "home"
        self.home.mkdir(mode=0o700)
        self.receiver = BASE.DEMO.Receiver()
        self.env = BASE.environment(self.home)
        self.env["PATH"] = str(paths["node"].parent) + os.pathsep + os.defpath
        self.env["GIT_CONFIG_NOSYSTEM"] = "1"
        self.env["GIT_CONFIG_GLOBAL"] = "/dev/null"
        self.env["GIT_PYTHON_GIT_EXECUTABLE"] = str(paths["git"])
        self.env["GIT_OPTIONAL_LOCKS"] = "0"

    def audit(self):
        path = self.home / ".agentfw/audit.jsonl"
        require(path.stat().st_size <= 8 * 1024 * 1024, "audit_bound")
        return [json.loads(line) for line in path.read_bytes().splitlines() if line]

    def redact(self, raw):
        for secret in self.secrets:
            raw = raw.replace(secret.encode(), b"[REDACTED]")
        return raw

    def retain_json(self, name, value):
        raw = self.redact(canonical(value))
        require(len(raw) <= LIMITS["host_bytes"], "owned_evidence_byte_limit")
        target = self.output / name
        owned_bytes(target, raw + b"\n")
        return {"file": name, "sha256": sha(target), "complete": True}

    def http(self, route):
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}" + route,
                                        headers={"Authorization": "Bearer " + self.native_token})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5) as response:
            raw = response.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "instance_response_bound")
        return json.loads(raw)

    def stale_authority_refusal(self, host, proof):
        # Collector stderr deliberately hides rejected HTTP response bodies.
        # Observe the same old grant at the native boundary independently;
        # neither the generic collector error nor EOF proves instance fencing.
        body = {"contract_version": "sw-native/1", "registry_sha256": self.registry_sha256,
                "session_id": "pilot-replay-" + uuid.uuid4().hex, "event": "session_start",
                "host_session": host, "server_id": "filesystem", "child_authority": proof}
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}/native/v1", canonical(body),
            headers={"Authorization": "Bearer " + self.native_token, "Content-Type": "application/json"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=10):
                raise Failure("stale_authority_was_accepted")
        except urllib.error.HTTPError as error:
            with error:
                raw = error.read(16385)
            require(error.code == 409 and len(raw) <= 16384, "stale_authority_wrong_http_failure")
            reply = strict_json(raw)
            require(reply.get("contract_version") == "sw-native/1" and reply.get("release") is False
                    and reply.get("error_code") == "native_child_authority_instance_mismatch",
                    "stale_grant_explicit_refusal_missing")
            return {"status": error.code, "error_code": reply["error_code"], "release": False,
                    "response_sha256": hashlib.sha256(raw).hexdigest()}

    def start_daemon(self):
        log = (self.private / ("daemon-" + str(len(self.logs)) + ".log")).open("wb")
        self.logs.append(log)
        self.daemon = subprocess.Popen([str(self.binary), "serve"], env=self.env, cwd=self.workspace,
                                       stdout=log, stderr=log, start_new_session=True)
        self.daemon_witness = BASE.ProcessWitness(self.daemon.pid)
        require(BASE.DEMO.wait_healthy(self.port, self.daemon), "installed_daemon_unavailable")
        self.native_token = (self.home / ".agentfw/native-token").read_text().strip()
        self.secrets.extend((self.native_token, (self.home / ".agentfw/token").read_text().strip()))
        return self.http("/native/v1/instance")["instance_id"]

    def prepare(self, fault=None):
        installed = self.private / "installed"
        installed.mkdir(mode=0o700)
        self.binary, self.launcher = installed / "agentfw", installed / "agentfw-git-sandbox"
        for role, target in (("agentfw", self.binary), ("git_launcher", self.launcher)):
            shutil.copyfile(self.paths[role], target)
            target.chmod(0o700)
            require(sha(target) == self.selected_sha256[role], "staged_binary_changed")
        self.classifiers = {}
        for kind in TOOLS:
            selected = self.paths[kind + "_classifier"]
            target = installed / (kind + "-classifier.py")
            shutil.copyfile(selected, target)
            target.chmod(0o600)
            if fault == "changed-asset" and kind == "filesystem":
                with target.open("ab") as stream:
                    stream.write(b"\n# controlled invalid asset\n")
            require(sha(target) == self.selected_sha256[kind + "_classifier"], "staged_classifier_changed")
            self.classifiers[kind] = target
        policy = installed / "policy.yaml"
        shutil.copyfile(self.paths["policy"], policy)
        policy.chmod(0o600)
        self.policy_sha256 = sha(policy)
        require(self.policy_sha256 == self.selected_sha256["policy"], "staged_policy_changed")
        self.prepare_workspaces()
        self.installs = {kind: self.private / (kind + "-profile") for kind in TOOLS}
        BASE.INSTALL.install(self.installs["filesystem"], self.workspace, self.paths["node"],
                             self.paths["bwrap"], self.paths["npm"])
        GIT.INSTALL.install(self.installs["git"], self.git_workspace, self.paths["git"], sha(self.paths["git"]),
                            self.paths["bwrap"], self.launcher)
        tools = []
        for kind, path in self.installs.items():
            registry = json.loads((path / "registry.json").read_text())
            tools.extend(registry["tools"])
            self.installed[kind] = {"profile_sha256": sha(path / "profile.json"),
                "package_sha256": BASE.INSTALL.tree_sha(path / "package"),
                "registry_sha256": sha(path / "registry.json"), "classifier_sha256": sha(self.classifiers[kind])}
        require(len({tool["name"] for tool in tools}) == len(tools), "merged_registry_tool_collision")
        registry = installed / "registry.json"
        private_json(registry, {"contract_version": "sw-native/1", "registry_id": "installed-development-pilot-v1", "tools": tools})
        self.registry_sha256 = sha(registry)
        subprocess.run([str(self.binary), "install"], env=self.env, cwd=self.workspace,
                       capture_output=True, stdin=subprocess.DEVNULL, timeout=30, check=True)
        self.port = BASE.DEMO.free_port()
        private_json(self.home / ".agentfw/config.yaml", {"port": self.port, "enforce": True, "max_record_bytes": 1048576,
            "policy": str(policy), "native": {"registry_path": str(registry), "registry_sha256": self.registry_sha256}})
        self.config_sha256 = sha(self.home / ".agentfw/config.yaml")
        self.baseline = BASE.snapshot(self.workspace)
        self.git_baseline = BASE.snapshot(self.git_workspace)
        self.sentinel = self.private / "unrelated.txt"
        self.sentinel.write_text("owned unrelated survivor\n", encoding="utf-8")
        self.sentinel_sha256 = sha(self.sentinel)
        self.unrelated = subprocess.Popen([str(self.paths["python"]), "-I", "-c", "import time; time.sleep(1800)"],
                                         env=self.env, cwd=self.private, start_new_session=True)
        self.unrelated_start = BASE.ProcessWitness.identity(self.unrelated.pid)
        instance = self.start_daemon()
        return {"source_independent_runtime": True, "agentfw_sha256": sha(self.binary),
                "profiles": self.installed, "policy_sha256": self.policy_sha256,
                "registry_sha256": self.registry_sha256, "config_sha256": self.config_sha256,
                "instance_id": instance, "policy_scope": "explicit-selected-policy",
                "expected_refusal": self.expected_refusal,
                "classifier_scope": "explicit-selected-single-file-rule-baselines"}

    def prepare_workspaces(self):
        # The accepted Git profile refuses special files anywhere in its tree.
        # Filesystem FIFO execution witnesses therefore belong to a separate
        # owned workspace, not to the repository or an excluded subtree.
        self.workspace = self.private / "filesystem-workspace"
        self.workspace.mkdir(mode=0o700)
        self.git_workspace = self.private / "git-workspace"
        self.git_injection_revision = GIT.prepare_repo(self.git_workspace, self.paths["git"], self.env)
        (self.workspace / "guide.txt").write_text(BASE.TEXT, encoding="utf-8")
        (self.workspace / "notes.txt").write_text(NOTES, encoding="utf-8")
        (self.workspace / "source.txt").write_text(POINTER, encoding="utf-8")
        for name in ("forbidden.fifo", "outage.fifo", *(f"parallel-{i}.fifo" for i in range(9))):
            os.mkfifo(self.workspace / name, 0o600)

    def workspace_for(self, kind):
        return self.git_workspace if kind == "git" else self.workspace

    def mint(self, host, kind, agent):
        instance = self.http("/native/v1/instance")
        require(instance["registry_sha256"] == self.registry_sha256, "active_registry_changed")
        result = subprocess.run([str(self.binary), "child-authority", "mint", "--session", host,
            "--server", kind, "--agent-id", agent, "--instance-id", instance["instance_id"],
            "--tools", ",".join(TOOLS[kind]), "--ttl-seconds", "300"],
            env=self.env, cwd=self.workspace, capture_output=True, check=True, timeout=15)
        proof = result.stdout.decode().strip()
        self.secrets.append(proof)
        claims = json.loads(base64.urlsafe_b64decode(proof + "=" * (-len(proof) % 4)))
        require(claims["host_session"] == host and claims["agent_id"] == agent
                and claims["server_id"] == kind and claims["nonce"].startswith(instance["instance_id"] + ".")
                and len(claims["granted_tools"]) == len(TOOLS[kind]) and set(claims["granted_tools"]) == set(TOOLS[kind]),
                "minted_authority_identity_changed")
        self.bindings.append({"host_session": host, "agent_id": agent, "server_id": kind,
                              "instance_id": instance["instance_id"], "tools": claims["granted_tools"],
                              "proof_sha256": hashlib.sha256(proof.encode()).hexdigest()})
        return proof

    def command(self, kind, direct=False):
        profile = json.loads((self.installs[kind] / "profile.json").read_text())
        if kind == "git":
            server = [profile["runtimePath"], "-I", "-B", "-m", "mcp_server_git", "--repository",
                      str(self.git_workspace) if direct else "/workspace"]
        else:
            server = [profile["runtimePath"], str(Path(profile["packageRoot"]) /
                      "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"),
                      str(self.workspace) if direct else "/workspace"]
        return server if direct else [str(self.binary), "mcp", "--native-admission", "--id", kind, "--", *server]

    def collector_env(self, kind, host, proof):
        return dict(self.env, AGENTFW_WORKSPACE=str(self.workspace_for(kind)),
            AGENTFW_MCP_SERVER_PROFILE=str(self.installs[kind] / "profile.json"),
            AGENTFW_CLASSIFIER="rule-baseline", AGENTFW_RULE_BASELINE=str(self.classifiers[kind]),
            AGENTFW_CLASSIFIER_PYTHON=str(self.paths["python"]), AGENTFW_HOST_SESSION=host,
            AGENTFW_CHILD_AUTHORITY=proof, AGENTFW_NATIVE_LIVENESS="true", AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS="4")

    @contextmanager
    def client(self, kind, host=None, agent=None, direct=False, proof=None):
        host, agent = host or str(uuid.uuid4()), agent or ("probe-" + uuid.uuid4().hex[:8])
        label = str(len(self.clients)) + "-" + kind
        log_path = self.private / (label + ".log")
        log = log_path.open("wb")
        self.logs.append(log)
        env = self.env if direct else self.collector_env(kind, host, proof or self.mint(host, kind, agent))
        client = Client(self.command(kind, direct), env, self.workspace_for(kind), log, label)
        client.kind, client.log_path, client.host_session, client.agent_id = kind, log_path, host, agent
        self.clients.append(client)
        try:
            client.initialize()
            yield client
        finally:
            client.close()

    def sandbox(self):
        evidence = {}
        for kind, test, marker, variable in (
            ("filesystem", "selected_server_sandbox_isolates_real_node", b"SOU62_SANDBOX_POSITIVE", "SOU62_SANDBOX_TEST_PROFILE"),
            ("git", "selected_git_sandbox_isolates_real_python_and_git", b"SOU68_SANDBOX_POSITIVE", "SOU68_SANDBOX_TEST_PROFILE")):
            result = subprocess.run([str(self.paths["sandbox_tests"]), test, "--ignored", "--nocapture"],
                env=dict(self.env, **{variable: str(self.installs[kind] / "profile.json"), "SOU86_TEST_AGENTFW": str(self.binary)}),
                cwd=self.private, capture_output=True, timeout=90)
            raw = result.stdout + result.stderr
            owned_bytes(self.output / (kind + "-sandbox.log"), raw)
            require(result.returncode == 0 and marker in raw and b"1 passed; 0 failed" in result.stdout,
                    "required_sandbox_positive_failed")
            if kind == "filesystem":
                require(all((name + "=true").encode() in raw for name in BASE.SANDBOX_WITNESSES), "sandbox_witness_missing")
            evidence[kind] = {"exit_code": 0, "log_sha256": hashlib.sha256(raw).hexdigest(), "executed_tests": 1}
        return evidence

    def preserve(self):
        require(BASE.snapshot(self.workspace) == self.baseline, "workspace_effect_detected")
        require(BASE.snapshot(self.git_workspace) == self.git_baseline, "repository_effect_detected")
        require(self.receiver.bodies == [], "forbidden_delivery_detected")
        require(self.unrelated.poll() is None and BASE.ProcessWitness.identity(self.unrelated.pid) == self.unrelated_start,
                "unrelated_process_lost")
        require(sha(self.sentinel) == self.sentinel_sha256, "unrelated_file_changed")
        return {"workspace_snapshot_sha256": digest(self.baseline), "repository_snapshot_sha256": digest(self.git_baseline),
                "unrelated_file_sha256": self.sentinel_sha256,
                "unrelated_process_alive": True, "receiver_deliveries": 0}

    def calibrate(self):
        # Independent originals first: the same pinned servers must actually
        # read the owned bytes and cause a controlled mutation without a gate.
        for kind, calls in (("filesystem", (("read_text_file", {"path": str(self.workspace / "guide.txt")}),
                                              ("read_text_file", {"path": str(self.workspace / "notes.txt")}))),
                            ("git", (("git_show", {"repo_path": str(self.git_workspace), "revision": "HEAD"}),
                                     ("git_status", {"repo_path": str(self.git_workspace)}),
                                     ("git_diff", {"repo_path": str(self.git_workspace), "target": "HEAD", "context_lines": 3})))):
            with self.client(kind, direct=True) as client:
                for identifier, (tool, arguments) in enumerate(calls, 10):
                    response, _ = client.exchange(BASE.call(identifier, arguments, tool))
                    self.controls[(kind, tool, "guide" if arguments.get("path", "").endswith("guide.txt") else "default")] = text(response, kind)
                if kind == "filesystem":
                    target = self.workspace / "calibrated-write.txt"
                    response, _ = client.exchange(BASE.call(30, {"path": str(target), "content": "owned calibration"}, "write_file"))
                    require(not BASE.refused(response) and target.read_text() == "owned calibration", "write_witness_not_calibrated")
                    target.unlink()
                else:
                    response, _ = client.exchange(BASE.call(31, {"repo_path": str(self.git_workspace),
                        "revision": self.git_injection_revision}, "git_show"))
                    require(GIT.INJECTION in GIT.text(response), "original_injection_not_calibrated")
        # Every negative FIFO is first read through the exact installed path.
        # The observer is not allowed to infer prevention from an absent reader
        # when it has never seen this inode's real reader.
        calibrations = {}
        for name in ("forbidden.fifo", "outage.fifo", "parallel-8.fifo"):
            fifo = SHARED.FifoProbe(self.workspace / name)
            try:
                with self.client("filesystem") as client:
                    response, _ = client.exchange(frame(40, "filesystem", "read_text_file", {"path": "/workspace/" + name}))
                    require(BASE.result_text(response) == BASE.FIFO_TEXT, "fifo_calibration_result_changed")
            finally:
                record = fifo.finish()
            require(record["reader_seen"] and record["bytes_written"] == len(BASE.FIFO_TEXT.encode()), "fifo_witness_not_calibrated")
            calibrations[name] = record
        watch = GIT.RepositoryWitness(self.git_workspace / ".git")
        try:
            with self.client("git") as client:
                watch.drain()
                response, _ = client.exchange(frame(45, "git", "git_show", {"revision": "HEAD"}))
                require(GIT.text(response) == self.controls[("git", "git_show", "default")], "git_witness_control_not_useful")
                git_opens = watch.drain()
                require(git_opens > 0, "git_open_witness_not_calibrated")
                response, _ = client.exchange(frame(46, "git", "git_show", {"revision": self.git_injection_revision}))
                injection_refusal = result_injection_refusal(response, self.audit(), client.host_session, client.agent_id)
        finally:
            watch.close()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(urllib.request.Request(self.receiver.url, data=b"owned receiver calibration"), timeout=5) as response:
            require(response.status == 200, "receiver_calibration_failed")
        require(self.receiver.bodies == ["owned receiver calibration"], "receiver_witness_not_calibrated")
        self.receiver.bodies.clear()
        require(self.controls[("filesystem", "read_text_file", "guide")] == BASE.TEXT, "original_useful_content_changed")
        original_evidence = self.retain_json("original-server-results.json", {"/".join(key): value for key, value in self.controls.items()})
        return {"original_results": {"/".join(key): hashlib.sha256(value.encode()).hexdigest() for key, value in self.controls.items()},
                "fifo": calibrations, "git_original_opens": git_opens,
                "git_history_with_object_id_useful": True, "original_injection_result_withheld": True,
                "injection_refusal": injection_refusal,
                "original_write_observed": True, "receiver_positive_observed": True,
                "original_evidence": original_evidence, **self.preserve()}

    def host(self, label, batches, before_batch=None, host=None, proofs=None):
        """Run the actual selected host. A batch is one provider parallel proposal.

        The local provider observes the original returned tool results. It does
        not classify calls or fabricate server results. All host proposals and
        successful bytes are checked after the process exits.
        """
        host = host or str(uuid.uuid4())
        directory = self.private / ("host-" + label)
        directory.mkdir(mode=0o700)
        project = directory / "project"
        project.mkdir(mode=0o700)
        wrapper = directory / "collector.py"
        wrapper.write_text("import os,sys\nos.dup2(os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600),2)\n"
                           "os.chdir(sys.argv[2])\nos.execve(sys.argv[3],sys.argv[3:],dict(os.environ))\n")
        proofs = proofs or {kind: self.mint(host, kind, label + "-" + kind) for kind in TOOLS}
        config = directory / "mcp.json"
        private_json(config, {"mcpServers": {kind: {"command": str(self.paths["python"]),
            "args": ["-I", str(wrapper), str(directory / (kind + ".log")), str(self.workspace_for(kind)), *self.command(kind)],
            "env": self.collector_env(kind, host, proofs[kind])} for kind in TOOLS}})
        expected, index = [], 0
        for batch in batches:
            proposals = []
            for kind, tool, arguments in batch:
                arguments = {"repo_path": "/workspace", **arguments} if kind == "git" else arguments
                proposals.append({"type": "tool_use", "id": f"toolu_pilot_{index}",
                                  "name": f"mcp__{kind}__{tool}", "input": arguments})
                index += 1
            expected.append(proposals)
        model = BASE.DEMO.ScriptedModel([])
        model.requests = BoundedRequests()
        offered, callbacks, provider_errors = set(), set(), []
        latencies, proposed_at = {}, {}
        lock = threading.Lock()
        def next_step(body):
            with lock:
                try:
                    require(len(model.requests) <= LIMITS["provider_requests"], "provider_request_bound")
                    names = {row.get("name") for row in body.get("tools", [])}
                    required = {"mcp__filesystem__read_text_file", "mcp__git__git_show"}
                    if not required.issubset(names):
                        return [{"type": "text", "text": "Owned auxiliary request."}]
                    for message in body.get("messages", []):
                        for block in message.get("content", []) if isinstance(message.get("content"), list) else []:
                            if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id") in offered:
                                identifier = block["tool_use_id"]
                                observed = {"is_error": bool(block.get("is_error")), "content": block.get("content")}
                                require(identifier not in model.results or model.results[identifier] == observed,
                                        "host_result_changed_on_retry")
                                model.results[identifier] = observed
                                latencies.setdefault(identifier, round((time.monotonic() - proposed_at[identifier]) * 1000, 3))
                    for batch_index, proposals in enumerate(expected):
                        identifiers = {row["id"] for row in proposals}
                        if identifiers.issubset(model.results):
                            continue
                        if before_batch and batch_index not in callbacks:
                            before_batch(batch_index, model.results)
                            callbacks.add(batch_index)
                        for identifier in identifiers:
                            proposed_at.setdefault(identifier, time.monotonic())
                        offered.update(identifiers)
                        return proposals
                    return [{"type": "text", "text": "Owned installed-pilot exercise completed."}]
                except Exception as error:
                    provider_errors.append(type(error).__name__)
                    return [{"type": "text", "text": "Owned exercise could not continue."}]
        model.next = next_step
        env = BASE.environment(directory)
        env.update(PATH=os.defpath, ANTHROPIC_API_KEY="owned-scripted-pilot-no-provider-key", ANTHROPIC_BASE_URL=model.url,
            CLAUDE_CONFIG_DIR=str(directory / ".claude"), CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
            CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL="1", DISABLE_UPDATES="1", DISABLE_AUTOUPDATER="1",
            ENABLE_CLAUDEAI_MCP_SERVERS="false", CLAUDE_CODE_DISABLE_CLAUDE_MDS="1", CLAUDE_CODE_DISABLE_AUTO_MEMORY="1",
            API_TIMEOUT_MS="10000", CLAUDE_CODE_MAX_RETRIES="0", HTTP_PROXY="http://127.0.0.1:9",
            HTTPS_PROXY="http://127.0.0.1:9", NO_PROXY="127.0.0.1,localhost,::1")
        command = [str(self.paths["claude"]), "--restricted", "-p", "Run the owned installed-pilot proposals.",
            "--tools", "", "--allowedTools", ",".join(f"mcp__{kind}__{tool}" for kind in TOOLS for tool in TOOLS[kind]),
            "--strict-mcp-config", "--mcp-config", str(config), "--session-id", host, "--no-session-persistence",
            "--output-format", "stream-json", "--verbose", "--permission-mode", "dontAsk", "--model", "claude-sonnet-4-20250514"]
        process = witness = None
        timed_out = False
        started = time.monotonic()
        try:
            process = subprocess.Popen(command, cwd=project, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            witness = BASE.ProcessWitness(process.pid)
            stdout, stderr = BoundedStream(process.stdout), BoundedStream(process.stderr)
            try:
                process.wait(timeout=150)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
            raw, error_output = stdout.finish(), stderr.finish()
            cleanup = witness.finish()
            # Original owned frames remain private; public report contains only
            # digests/counts. Even failed/late output is retained for diagnosis.
            safe_raw, safe_error = self.redact(raw), self.redact(error_output)
            owned_bytes(self.output / (label + "-host.jsonl"), safe_raw)
            owned_bytes(self.output / (label + "-host.stderr"), safe_error)
            provider_record = self.retain_json(label + "-provider-results.json", {
                "proposed_batches": expected, "observed_tool_results": model.results,
                "provider_requests": len(model.requests), "latencies_ms": latencies})
            messages = [json.loads(line) for line in raw.splitlines() if line.startswith(b"{")]
            initial = [r for r in messages if r.get("type") == "system" and r.get("subtype") == "init"]
            finals = [r for r in messages if r.get("type") == "result"]
            uses = [block for row in messages if row.get("type") == "assistant"
                    for block in row.get("message", {}).get("content", []) if block.get("type") == "tool_use"]
            evidence = {"host_session": host, "exit_code": process.returncode, "timed_out": timed_out,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 3), "tool_proposals": len(uses),
                "parallel_proposal_batches": sum(len(batch) > 1 for batch in batches),
                "proposal_sha256": digest(uses), "returned_results_sha256": digest(model.results),
                "provider_requests": len(model.requests), "provider_requests_sha256": hashlib.sha256(b"".join(model.requests)).hexdigest(),
                "host_output_sha256": hashlib.sha256(raw).hexdigest(), "latencies_ms": latencies,
                "provider_result_evidence": provider_record,
                "process_cleanup": cleanup, "actual_host": True, "provider": "owned-scripted-loopback",
                "live_model_effectiveness": "not_measured"}
            self.hosts.append(evidence)
            require(raw == safe_raw and error_output == safe_error, "host_credential_exposure")
            require(not provider_errors and not timed_out and process.returncode == 0 and len(finals) == 1
                    and not finals[0].get("is_error"), "actual_host_incomplete")
            require(len(initial) == 1 and initial[0].get("session_id") == host, "actual_host_session_changed")
            require({r.get("name") for r in initial[0].get("mcp_servers", []) if r.get("status") == "connected"} == set(TOOLS),
                    "actual_host_two_servers_not_connected")
            require(uses == [row for batch in expected for row in batch]
                    and set(model.results) == {row["id"] for batch in expected for row in batch}, "actual_host_proposals_incomplete")
            require(cleanup["all_stopped"] and cleanup["descendant_count"] >= 2, "actual_host_cleanup_incomplete")
            return evidence, model.results
        finally:
            if process is not None and process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
            if witness is not None:
                witness.finish()
            model.close()

    def workflows(self, second=False):
        batches = ([[("filesystem", "read_text_file", {"path": "/workspace/guide.txt"}),
                     ("git", "git_show", {"revision": "HEAD"})]] if not second else
                   [[("filesystem", "read_text_file", {"path": "/workspace/notes.txt"}),
                     ("git", "git_diff", {"target": "HEAD", "context_lines": 3})]])
        evidence, results = self.host("inspect" if second else "read", batches)
        if any(row.get("is_error") is True for row in results.values()):
            self.report["benign_workflows"]["false_interruptions"] += 1
            self.report["benign_workflows"]["incomplete"] -= 1
            raise Failure("benign_workflow_false_interruption")
        expected = (self.controls[("filesystem", "read_text_file", "default" if second else "guide")],
                    self.controls[("git", "git_diff" if second else "git_show", "default")])
        for index, kind in enumerate(TOOLS):
            require(host_text(results[f"toolu_pilot_{index}"], kind) == expected[index], "actual_host_useful_bytes_changed")
        preserved = self.preserve()
        self.report["benign_workflows"]["completed"] += 1
        self.report["benign_workflows"]["incomplete"] -= 1
        return {"host": evidence, "useful_content_sha256": [hashlib.sha256(value.encode()).hexdigest() for value in expected], **preserved}

    def refusal(self):
        probe = SHARED.FifoProbe(self.workspace / "forbidden.fifo")
        watch = GIT.RepositoryWitness(self.git_workspace / ".git")
        git_observations = {}
        def observe(index, results):
            if index == 2:
                watch.drain()
            elif index == 3:
                git_observations["opens_during_refused_mutator"] = watch.drain()
                require(git_observations["opens_during_refused_mutator"] == 0, "refused_git_mutator_accessed_repository")
        try:
            evidence, results = self.host("untrusted", [
                [("filesystem", "read_text_file", {"path": "/workspace/source.txt"})],
                [("filesystem", "read_text_file", {"path": "/workspace/forbidden.fifo"})],
                [("git", "git_reset", {})],
                [("filesystem", "read_text_file", {"path": "/workspace/guide.txt"}), ("git", "git_show", {"revision": "HEAD"})]],
                before_batch=observe)
            require(host_text(results["toolu_pilot_0"], "filesystem") == POINTER, "untrusted_source_not_encountered")
            blocked = results["toolu_pilot_1"]
            require(blocked["is_error"] is True and isinstance(blocked["content"], str)
                    and self.expected_refusal["rule"] in blocked["content"] and BASE.FIFO_TEXT not in blocked["content"],
                    "actual_host_refusal_not_preserved")
            git_refusal = results["toolu_pilot_2"]
            require(git_refusal["is_error"] is True and isinstance(git_refusal["content"], str)
                    and "explicitly unsupported in the read-only profile" in git_refusal["content"],
                    "actual_host_git_mutator_not_refused")
            require(host_text(results["toolu_pilot_3"], "filesystem") == BASE.TEXT
                    and host_text(results["toolu_pilot_4"], "git") == self.controls[("git", "git_show", "default")],
                    "refusal_broke_useful_continuation")
            rows = [r for r in self.audit() if r.get("event") == "native_call" and r.get("host_session") == evidence["host_session"]]
            refusals = [r for r in rows if r.get("rule") == self.expected_refusal["rule"] and r.get("released") is False
                        and r.get("verdict") == self.expected_refusal["verdict"]]
            require(len(refusals) == 1 and refusals[0].get("taint", {}).get("source_name") == "filesystem", "shared_untrusted_risk_witness_missing")
            # Selected read-only profiles refuse mutators before native call
            # admission. Do not invent a policy Deny record for that boundary.
            require(not any(r.get("tool") == "git_reset" for r in rows), "unsupported_git_mutator_reached_native_call")
        finally:
            record = probe.finish()
            watch.close()
        require(not record["reader_seen"] and record["bytes_written"] == 0, "refused_call_executed")
        self.refused_host = evidence["host_session"]
        return {"host": evidence, "fifo": record, "native_refusal_count": 1, "expected_refusal": self.expected_refusal,
                "git_refusal_boundary": "selected-profile-before-native-admission", **git_observations, **self.preserve()}

    def independent(self):
        probe = SHARED.FifoProbe(self.workspace / "forbidden.fifo")
        try:
            evidence, results = self.host("independent", [[("filesystem", "read_text_file", {"path": "/workspace/forbidden.fifo"}),
                                                          ("git", "git_show", {"revision": "HEAD"})]])
            require(host_text(results["toolu_pilot_0"], "filesystem") == BASE.FIFO_TEXT
                    and host_text(results["toolu_pilot_1"], "git") == self.controls[("git", "git_show", "default")],
                    "independent_session_interrupted")
        finally:
            record = probe.finish()
        require(record["reader_seen"] and evidence["host_session"] != self.refused_host, "independent_session_not_separate")
        return {"host": evidence, "same_fifo_read": record, **self.preserve()}

    def parallel(self):
        host = str(uuid.uuid4())
        with self.client("filesystem", host, "parallel-filesystem") as client, self.client("git", host, "parallel-git") as sibling:
            fifo = BASE.FIFOWitness([self.workspace / f"parallel-{i}.fifo" for i in range(8)])
            queued = SHARED.FifoProbe(self.workspace / "parallel-8.fifo")
            try:
                client.send(*(frame(100 + i, "filesystem", "read_text_file", {"path": f"/workspace/parallel-{i}.fifo"}) for i in range(8)))
                deadline = time.monotonic() + 12
                while not all(row["reader_opened"] for row in fifo.records) and time.monotonic() < deadline:
                    time.sleep(0.01)
                require(all(row["reader_opened"] for row in fifo.records), "parallel_execution_not_observed")
                # The unrelated installed Git server must remain useful while
                # all eight filesystem execution slots are actually blocked.
                git_response, _ = sibling.exchange(frame(10, "git", "git_show", {"revision": "HEAD"}))
                require(GIT.text(git_response) == self.controls[("git", "git_show", "default")], "parallel_sibling_interrupted")
                client.send(frame(108, "filesystem", "read_text_file", {"path": "/workspace/parallel-8.fifo"}))
                BASE.wait_event(client.log_path, lambda rows: any(row.get("host_call_id") == 108 and row.get("state") == "queued" for row in rows),
                                "queued_call_not_observed")
                client.send(BASE.cancel(108))
                response, _ = client.receive(timeout=10)
                require(response.get("id") == 108 and response.get("error", {}).get("code") == -32800, "queued_cancel_not_correlated")
                client.send(BASE.cancel(100))
                response, _ = client.receive(timeout=10)
                require(response.get("id") == 100 and response.get("error", {}).get("code") == -32800, "active_cancel_not_correlated")
                fifo.finish()
                replies = [client.receive(timeout=20)[0] for _ in range(7)]
                require({BASE.key(row["id"]) for row in replies} == {BASE.key(i) for i in range(101, 108)}
                        and all(BASE.result_text(row) == BASE.FIFO_TEXT for row in replies), "parallel_results_incomplete")
                continuation, _ = client.exchange(frame(120, "filesystem", "read_text_file", {"path": "/workspace/guide.txt"}))
                require(BASE.result_text(continuation) == BASE.TEXT, "cancelled_capacity_not_reusable")
            finally:
                fifo.finish()
                queued_record = queued.finish()
            require(not queued_record["reader_seen"] and queued_record["bytes_written"] == 0, "queued_cancel_executed")
            require(all(row["reader_opened"] and row["bytes_written"] == len(BASE.FIFO_TEXT.encode()) and row["error"] is None
                        for row in fifo.records), "parallel_execution_witness_incomplete")
            wire = client.transcript()
            evidence = {"driver_scope": "explicit-MCP-client-on-the-same-installed-product",
                "active_original_calls": 8, "cancelled": {"inflight_executed": 1, "queued_not_executed": 1},
                "useful_correlated_results": 7, "fifo": fifo.records, "queued_fifo": queued_record,
                "sibling_useful": True, "same_session_follow_up": True,
                "sent_sha256": wire["sent_sha256"], "received_sha256": wire["received_sha256"],
                "client_wire_file": f"client-{self.clients.index(client):02d}-wire.json"}
        return {**evidence, **self.preserve()}

    def collector_recovery(self):
        host = str(uuid.uuid4())
        with self.client("git", host, "surviving-git") as sibling:
            with self.client("filesystem", host, "interrupted-filesystem") as client:
                response, _ = client.exchange(frame(10, "filesystem", "read_text_file", {"path": "/workspace/guide.txt"}))
                require(BASE.result_text(response) == BASE.TEXT, "collector_precrash_useful_missing")
                starts = [r for r in self.audit() if r.get("event") == "native_session_start" and r.get("host_session") == host
                          and r.get("agent_id") == "interrupted-filesystem"]
                require(len(starts) == 1, "collector_epoch_ambiguous")
                epoch = starts[0]["session"]
                start_ticks = BASE.ProcessWitness.identity(client.process.pid)
                require(start_ticks is not None and client.process_witness.observed, "collector_identity_unobserved")
                started = time.monotonic()
                # Signal only this owned collector. Descendants and native
                # capacity must be reclaimed by production, not by the driver.
                require(BASE.ProcessWitness.identity(client.process.pid) == start_ticks, "collector_pid_reused")
                client.process.send_signal(signal.SIGKILL)
                client.process.wait(timeout=5)
                process_cleanup = client.process_witness.finish()
                require(client.process.returncode == -signal.SIGKILL and process_cleanup["all_stopped"]
                        and process_cleanup["descendant_count"] > 0, "collector_descendants_not_reclaimed")
                deadline = started + LIMITS["recovery_seconds"]
                expired = []
                while time.monotonic() < deadline:
                    expired = [r for r in self.audit() if r.get("event") == "native_session_expired" and r.get("session") == epoch]
                    if expired:
                        break
                    time.sleep(0.05)
                require(len(expired) == 1 and time.monotonic() <= deadline, "collector_capacity_not_reclaimed")
                reclaimed_ms = round((time.monotonic() - started) * 1000, 3)
                client.expected_exit = -signal.SIGKILL
            response, _ = sibling.exchange(frame(10, "git", "git_show", {"revision": "HEAD"}))
            require(GIT.text(response) == self.controls[("git", "git_show", "default")], "collector_crash_killed_sibling")
            with self.client("filesystem", host, "interrupted-filesystem") as replacement:
                response, _ = replacement.exchange(frame(10, "filesystem", "read_text_file", {"path": "/workspace/guide.txt"}))
                require(BASE.result_text(response) == BASE.TEXT, "collector_reconnection_not_useful")
                new_starts = [r for r in self.audit() if r.get("event") == "native_session_start" and r.get("host_session") == host
                              and r.get("agent_id") == "interrupted-filesystem"]
                require(len(new_starts) == 2 and new_starts[-1]["session"] != epoch, "collector_epoch_resurrected")
        return {"signal": "SIGKILL", "session_end_sent": False, "reclaimed_ms": reclaimed_ms,
                "old_epoch_sha256": digest(epoch), "new_epoch_sha256": digest(new_starts[-1]["session"]),
                "process_cleanup": process_cleanup, "surviving_sibling_useful": True,
                "reconnected_useful": True, **self.preserve()}

    def daemon_recovery(self):
        old_instance = self.http("/native/v1/instance")["instance_id"]
        host = str(uuid.uuid4())
        proofs = {kind: self.mint(host, kind, "outage-" + kind) for kind in TOOLS}
        probe = SHARED.FifoProbe(self.workspace / "outage.fifo")
        observations = {}
        def interrupt(index, results):
            if index == 1:
                require(host_text(results["toolu_pilot_0"], "filesystem") == BASE.TEXT, "outage_precontrol_not_useful")
                self.daemon.send_signal(signal.SIGKILL)
                self.daemon.wait(timeout=5)
                require(self.daemon.returncode == -signal.SIGKILL, "daemon_not_interrupted")
                observations["stopped_before_proposal"] = True
        try:
            evidence, results = self.host("outage", [
                [("filesystem", "read_text_file", {"path": "/workspace/guide.txt"})],
                [("filesystem", "read_text_file", {"path": "/workspace/outage.fifo"})]],
                before_batch=interrupt, host=host, proofs=proofs)
            require(observations.get("stopped_before_proposal") is True and results["toolu_pilot_1"]["is_error"] is True,
                    "host_outage_not_observed")
        finally:
            record = probe.finish()
        require(not record["reader_seen"] and record["bytes_written"] == 0, "outage_call_executed")
        require(self.daemon_witness.finish()["all_stopped"], "old_daemon_tree_remains")
        started = time.monotonic()
        new_instance = self.start_daemon()
        require(new_instance != old_instance, "daemon_instance_resurrected")
        # An EOF or generic request error alone proves nothing. Also obtain the
        # explicit native instance-mismatch response for the same old grant.
        refused = None
        try:
            with self.client("filesystem", host, "outage-filesystem", proof=proofs["filesystem"]) as stale:
                refused = stale
                raise Failure("stale_collector_initialized")
        except ValueError:
            refused = self.clients[-1]
            refusal_log = refused.log_path.read_bytes()
            require(refused.process.returncode == 1 and b"MCP admission request rejected" in refusal_log
                    and not refused.received, "stale_collector_not_refused")
            refused.expected_exit = refused.process.returncode
        native_refusal = self.stale_authority_refusal(host, proofs["filesystem"])
        require(time.monotonic() - started <= LIMITS["recovery_seconds"], "daemon_recovery_deadline")
        fresh, fresh_results = self.host("fresh", [[("filesystem", "read_text_file", {"path": "/workspace/guide.txt"}),
                                                   ("git", "git_show", {"revision": "HEAD"})]])
        require(fresh["host_session"] != host and host_text(fresh_results["toolu_pilot_0"], "filesystem") == BASE.TEXT
                and host_text(fresh_results["toolu_pilot_1"], "git") == self.controls[("git", "git_show", "default")],
                "fresh_conversation_not_useful")
        return {"outage_host": evidence, "outage_fifo": record, "stopped_before_proposal": True,
                "outcome": "technical-unavailability-not-policy-deny", "old_instance_id": old_instance,
                "new_instance_id": new_instance, "stale_authority_refusal": "native_child_authority_instance_mismatch",
                "native_refusal": native_refusal,
                "fresh_host": fresh, "old_context_resumed": False, **self.preserve()}

    def cleanup(self):
        errors = []
        if self.baseline is not None:
            try:
                self.preserve()
            except Exception:
                errors.append("effect_or_survivor_changed")
        for client in reversed(self.clients):
            try:
                client.close()
                client.validate_capture()
                require(not client.forced_cleanup and client.process_witness.final["all_stopped"], "client_cleanup_incomplete")
                require(client.process.returncode == getattr(client, "expected_exit", 0), "unexpected_client_exit")
            except Exception:
                errors.append("client_cleanup_failed")
                # Emergency cleanup cannot turn the failed witness green. Pin
                # each observed owned descendant by start time; never signal
                # an unobserved process, a recycled PID or the unrelated guard.
                for (pid, start) in list(client.process_witness.observed):
                    if pid != os.getpid() and BASE.ProcessWitness.identity(pid) == start:
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
        if self.daemon is not None:
            BASE.DEMO.stop(self.daemon)
            self.daemon.wait(timeout=10)
            if self.daemon_witness and not self.daemon_witness.finish()["all_stopped"]:
                errors.append("daemon_cleanup_failed")
        survivor = self.unrelated is not None and self.unrelated.poll() is None
        if self.unrelated is not None:
            BASE.DEMO.stop(self.unrelated)
            self.unrelated.wait(timeout=10)
        self.receiver.close()
        for log in self.logs:
            log.close()
        if self.baseline is not None:
            try:
                require(sha(self.binary) == sha(self.paths["agentfw"]) and sha(self.launcher) == sha(self.paths["git_launcher"]),
                        "installed_binary_changed")
                require(sha(self.home / ".agentfw/config.yaml") == self.config_sha256
                        and sha(self.private / "installed/registry.json") == self.registry_sha256
                        and sha(self.private / "installed/policy.yaml") == self.policy_sha256, "installed_configuration_changed")
                for kind, profile in self.installed.items():
                    require(sha(self.installs[kind] / "profile.json") == profile["profile_sha256"]
                            and sha(self.installs[kind] / "registry.json") == profile["registry_sha256"]
                            and BASE.INSTALL.tree_sha(self.installs[kind] / "package") == profile["package_sha256"]
                            and sha(self.classifiers[kind]) == profile["classifier_sha256"], "installed_asset_changed")
            except Exception:
                errors.append("installed_identity_changed")
        retained = self.retain()
        require(not errors, "installed_runtime_cleanup_failed")
        return {"client_count": len(self.clients), "hosts": len(self.hosts), "all_owned_processes_stopped": True,
                "unrelated_survived_until_teardown": survivor, "forced_cleanup": False, "retained": retained}

    def retain(self):
        """Keep bounded failed/late owned evidence before deleting the stage.

        Never retain the host configuration, environment or bearer/proof files.
        Audit has no owner capability; known private tokens are also redacted
        from log diagnostics. This is not a general user-data scrubber.
        """
        retained = []
        paths = sorted(self.private.glob("*.log")) + sorted(self.private.glob("host-*/*.log"))
        if hasattr(self, "home"):
            audit = self.home / ".agentfw/audit.jsonl"
            if audit.exists():
                paths.append(audit)
        for index, path in enumerate(paths):
            with path.open("rb") as stream:
                raw = stream.read(LIMITS["host_bytes"] + 1)
            complete = len(raw) <= LIMITS["host_bytes"]
            raw = raw[:LIMITS["host_bytes"]]
            raw = self.redact(raw)
            target = self.output / (f"owned-{index:02d}-" + path.name)
            target.write_bytes(raw)
            target.chmod(0o600)
            retained.append({"file": target.name, "sha256": sha(target), "complete": complete})
        for index, client in enumerate(self.clients):
            retained.append(self.retain_json(f"client-{index:02d}-wire.json", client.transcript()))
        require(len(retained) <= 64 and all(row["complete"] for row in retained), "owned_evidence_incomplete")
        return retained


def negative_controls(args):
    outcomes = []
    expected = {"bad-candidate": "candidate_source_mismatch", "missing-sandbox": "selected_executable_unavailable",
                "changed-asset": "staged_classifier_changed"}
    for name, reason in expected.items():
        output = args.output / ("negative-" + name)
        command = [sys.executable, "-B", str(Path(__file__).resolve()), "--run", "--selection", str(args.selection),
                   "--expected-commit", args.expected_commit, "--output", str(output), "--fault", name]
        if getattr(args, "wsl_root", None):
            command.extend(["--wsl-root", str(args.wsl_root)])
        result = subprocess.run(command,
            env={key: value for key, value in os.environ.items() if key in ("PATH", "LANG")},
            cwd=ROOT, capture_output=True, timeout=30)
        report = json.loads((output / "report.json").read_text())
        require(result.returncode == 1 and report["status"] == "failed"
                and report["cases"][0]["reason"] == reason
                and all(row["status"] != "passed" for row in report["cases"] if row["id"] != "final-cleanup")
                and report["host_runs"] == [] and report["bindings"] == [], "bad_input_qualification_did_not_fail")
        outcomes.append({"input": name, "exit_code": result.returncode, "reason": reason,
                         "result_sha256": sha(output / "report.json")})
    return {"required": 3, "rejected": outcomes}


def run(args):
    args.output = args.output.resolve()
    require(not args.output.exists() and not args.output.is_relative_to(ROOT), "new_external_output_required")
    args.output.mkdir(mode=0o700, parents=True)
    report = new_report()
    report["driver_sha256"] = sha(__file__)
    report["environment"] = {"os": platform.system(), "machine": platform.machine(), "kernel": platform.release(),
                             "python": platform.python_version()}
    pilot = None
    private = None
    selected = {}
    def prepare():
        nonlocal pilot, private, selected
        require(args.selection.stat().st_size <= 65536, "selection_byte_limit")
        selection = strict_json(args.selection.read_bytes())
        if args.fault == "bad-candidate":
            selection["source"]["commit"] = "0" * 40
        if args.fault == "missing-sandbox":
            selection["files"]["bwrap"]["path"] = str(args.output / "absent-bwrap")
        before, paths = validate_selection(selection, args.expected_commit)
        selected = paths
        report["source_before"] = before
        report["selection_format"] = selection["format"]
        report["selected_sha256"] = {key: selection["files"][key]["sha256"] for key in paths}
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "linux_x86_64_required")
        # Prerequisite validation happens before profile downloads or execution.
        wsl_root = getattr(args, "wsl_root", None)
        if wsl_root is not None:
            report["wsl_preflight"] = wsl_preflight.inspect(wsl_root, paths, output=args.output)
            require(report["wsl_preflight"]["status"] == "ready", "wsl_prerequisites_not_ready")
        private = tempfile.TemporaryDirectory(prefix="installed-pilot-", dir=wsl_root)
        pilot = Pilot(Path(private.name), args.output, paths, report, selection["expected_refusal"])
        version = subprocess.check_output([str(paths["claude"]), "--version"], env=pilot.env, cwd=pilot.private,
                                          timeout=15, text=True).strip()
        host_package = json.loads((ROOT / "profiles/mcp/filesystem-readonly-v1/claude-host/package.json").read_text())
        require(version == host_package["dependencies"]["@anthropic-ai/claude-code"] + " (Claude Code)", "selected_host_version_changed")
        report["claude_version"] = version
        return pilot.prepare(args.fault)
    def step(name, action, timeout=None):
        def observed():
            try:
                return action()
            except Exception as error:
                raw = traceback.format_exc().encode("utf-8")
                for secret in pilot.secrets if pilot else []:
                    raw = raw.replace(secret.encode(), b"[REDACTED]")
                path = args.output / (name + "-failure.txt")
                path.write_bytes(raw[:65536])
                path.chmod(0o600)
                next(row for row in report["cases"] if row["id"] == name)["evidence"]["diagnostic_sha256"] = sha(path)
                if isinstance(error, GIT.INSTALL.RuntimeLibrariesUnavailable):
                    evidence = next(row for row in report["cases"] if row["id"] == name)["evidence"]
                    evidence["missing_runtime_libraries"] = error.missing_libraries
                    evidence["next_step"] = "Install the Ubuntu runtime packages providing these SONAMEs, then retry in a new output directory."
                    raise Failure("git_runtime_libraries_unavailable") from error
                raise
        return measure(report, name, observed, timeout=timeout)
    ready = step("exact-installed-inputs", prepare, timeout=LIMITS["setup_seconds"])
    if report["cases"][0]["reason"] == "linux_x86_64_required":
        report["cases"][0]["status"] = "unsupported"
    try:
        if ready:
            step("bad-input-controls", lambda: negative_controls(args))
            calibrated = step("sandbox-positive", pilot.sandbox)
            calibrated = calibrated and step("witness-calibration", pilot.calibrate)
            if calibrated:
                for name, action in (("read-and-history", lambda: pilot.workflows(False)),
                                     ("inspect-and-diff", lambda: pilot.workflows(True)),
                                     ("untrusted-input-refusal", pilot.refusal),
                                     ("independent-conversation", pilot.independent),
                                     ("parallel-cancellation", pilot.parallel),
                                     ("collector-recovery", pilot.collector_recovery),
                                     ("daemon-fresh-conversation", pilot.daemon_recovery)):
                    step(name, action)
                    # Daemon failure is last. Earlier independent cases still
                    # run after a failed positive; no implicit green fallback.
    finally:
        cleanup_evidence = {}
        def cleanup():
            try:
                if pilot is not None:
                    cleanup_evidence.update(pilot.cleanup())
            finally:
                try:
                    if private is not None:
                        private.cleanup()
                        require(not Path(private.name).exists(), "private_installation_remains")
                finally:
                    # Failed cleanup is still evidence on an exact candidate.
                    # Preserve the closing source identity even when the
                    # runtime outcome itself must remain failed.
                    report["source_after"] = source()
            require(report.get("source_before") == report["source_after"], "candidate_changed_during_run")
            require(all(sha(path) == report["selected_sha256"][key] for key, path in selected.items()), "selected_runtime_changed_during_run")
            require(pilot is not None, "runtime_not_started")
            return {**cleanup_evidence, "private_installation_removed": True, "source_and_inputs_unchanged": True}
        if pilot is not None:
            step("final-cleanup", cleanup)
        elif private is not None:
            private.cleanup()
        report["bindings"] = pilot.bindings if pilot else []
        report["host_runs"] = pilot.hosts if pilot else []
        report["remaining_blockers"] = [{"case": row["id"], "status": row["status"], "reason": row["reason"]}
                                        for row in report["cases"] if row["status"] != "passed"]
        write_report(args.output / "report.json", report)
    print(json.dumps({key: report[key] for key in ("format", "status", "required", "counts", "benign_workflows")}))
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--wsl-root", type=Path,
                        help="Opt in to WSL2 checks and stage under this existing private /home directory.")
    parser.add_argument("--wsl-preflight", action="store_true",
                        help="Inspect WSL prerequisites only; never start the installed pilot or download assets.")
    parser.add_argument("--fault", choices=("bad-candidate", "missing-sandbox", "changed-asset"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.wsl_preflight:
        if args.run or not args.wsl_root:
            parser.error("--wsl-preflight requires --wsl-root and cannot be combined with --run")
        if bool(args.selection) != bool(args.expected_commit):
            parser.error("Supply --selection and --expected-commit together")
        paths = None
        try:
            if args.selection:
                require(args.selection.stat().st_size <= 65536, "selection_byte_limit")
                _, paths = validate_selection(strict_json(args.selection.read_bytes()), args.expected_commit)
            report = wsl_preflight.inspect(args.wsl_root, paths, output=args.output)
        except (Failure, OSError, ValueError, KeyError, TypeError) as error:
            # Selection paths and parser messages may contain private operator data.
            # Preserve a static actionable reason, never a traceback or raw input.
            status = "unavailable" if isinstance(error, OSError) else "incompatible"
            reason = error.code if isinstance(error, Failure) else (
                "selection_unreadable" if isinstance(error, OSError) else "selection_invalid")
            report = {"format": "sw-wsl-preflight/1", "scope": "prerequisites_only",
                      "status": status, "active_protection": "not_measured",
                      "runtime_qualification": "not_executed", "checks": [
                          {"id": "runtime_selection", "status": status, "reason": reason,
                           "next_step": "Supply a readable exact pilot selection for the clean expected commit.",
                           "evidence": {}}]}
        print(json.dumps(report, indent=2))
        return 0 if report["status"] == "ready" else 1
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False, "cases": CASES, "limits": LIMITS,
                          "live_provider": False, "runtime_downloads": "existing-pinned-profile-installers-only"}))
        return 0
    if not all((args.selection, args.expected_commit, args.output)):
        parser.error("--run requires --selection, --expected-commit and --output")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())


