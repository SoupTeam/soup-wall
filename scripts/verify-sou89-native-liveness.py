#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-89 generic component acceptance (cross-platform daemon & collector protocol suite).

Notice: Selected production filesystem and Git acceptance with real Node @modelcontextprotocol/server-filesystem
and GitRig profiles is implemented in scripts/verify-sou89-selected-liveness.py (Linux required).

Verifies that:
1. Abrupt collector SIGKILL without session_end reclaims capacity autonomously
   within a predeclared finite cleanup deadline without needing any incoming request.
2. Idle daemon sweeps and expires dead leased sessions with no HTTP traffic.
3. Repeated crash/reconnect beyond 64 collector sessions does not exhaust capacity.
4. Healthy-idle collectors renew leases and remain useful across multiple lease periods.
5. Active sibling collectors remain completely isolated and unaffected by peer loss.
6. Stale and forged renewals (replay sequence, wrong epoch, instance mismatch, forged owner token) are rejected.
7. Old results or replays from expired/retired sessions cannot authorize or release effects.
8. Parent expiration cascades to child sessions.
9. Daemon restart causes collectors to observe uncertainty, halt execution, and clean up.

Usage:
    verify-sou89-native-liveness.py --binary target/debug/agentfw --out DIR
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request

sys.dont_write_bytecode = True

os.environ["no_proxy"] = "*"
os.environ["NO_PROXY"] = "*"
urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))

NATIVE_CONTRACT = "sw-native/1"
LIVENESS_CONTRACT = "sw-native-liveness/1"
DEFAULT_LEASE_SECS = 4
CLEANUP_DEADLINE_SECS = 8.0
TOOL_SCHEMA = {
    "type": "object",
    "properties": {"name": {"type": "string"}},
    "required": ["name"],
    "additionalProperties": False,
}
TOOL_SCHEMA_SHA256 = hashlib.sha256(
    json.dumps(TOOL_SCHEMA, sort_keys=True, separators=(",", ":")).encode("utf-8")
).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_post(url: str, token: str, data: dict, timeout: float = 5.0) -> tuple[int, dict]:
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            resp_body = json.loads(resp.read().decode("utf-8"))
            return status, resp_body
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            resp_body = json.loads(e.read().decode("utf-8"))
        except Exception:
            resp_body = {"error": str(e)}
        return status, resp_body


def http_get(url: str, token: str, timeout: float = 5.0) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            resp_body = json.loads(resp.read().decode("utf-8"))
            return status, resp_body
    except urllib.error.HTTPError as e:
        status = e.code
        try:
            resp_body = json.loads(e.read().decode("utf-8"))
        except Exception:
            resp_body = {"error": str(e)}
        return status, resp_body


class DaemonFixture:
    def __init__(self, binary_path: Path, temp_dir: Path, lease_secs: int = DEFAULT_LEASE_SECS):
        self.binary_path = binary_path.resolve()
        self.temp_dir = temp_dir.resolve()
        self.home = (self.temp_dir / ".agentfw").resolve()
        self.home.mkdir(parents=True, exist_ok=True)
        self.port = find_free_port()
        self.lease_secs = lease_secs
        self.process: subprocess.Popen | None = None
        self.native_token = "native-fixture-token-0123456789"
        self.token = "hook-fixture-token-9876543210"

        # Write valid registry JSON
        registry_file = (self.home / "registry.json").resolve()
        registry_content = {
            "contract_version": NATIVE_CONTRACT,
            "registry_id": "sou89-acceptance-registry",
            "tools": [
                {
                    "name": "read_document",
                    "schema_sha256": TOOL_SCHEMA_SHA256,
                    "action_class": "read_only",
                    "result_provenance": "untrusted",
                    "egress": [],
                }
            ],
        }
        registry_bytes = json.dumps(registry_content, sort_keys=True).encode("utf-8")
        registry_file.write_bytes(registry_bytes)
        self.registry_sha256 = hashlib.sha256(registry_bytes).hexdigest()

        # Write tokens
        (self.home / "token").write_text(self.token, encoding="utf-8")
        (self.home / "native-token").write_text(self.native_token, encoding="utf-8")

        cfg_yaml = f"""bind: "127.0.0.1"
port: {self.port}
enforce: true
native:
  registry_path: "{registry_file}"
  registry_sha256: "{self.registry_sha256}"
  liveness:
    default_lease_seconds: {self.lease_secs}
    max_lease_seconds: 60
    maintenance_interval_ms: 100
"""
        (self.home / "config.yaml").write_text(cfg_yaml, encoding="utf-8")

    def start(self):
        env = os.environ.copy()
        env["HOME"] = str(self.temp_dir)
        cmd = [str(self.binary_path), "serve"]
        self.process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.time() + 20.0
        last_err = "No attempts made"
        while time.time() < deadline:
            if self.process.poll() is not None:
                out, err = self.process.communicate()
                raise RuntimeError(f"Daemon process died early with code {self.process.returncode}. Stderr: {err}\nStdout: {out}")
            try:
                status, body = http_get(f"http://127.0.0.1:{self.port}/health", self.token, timeout=1.0)
                if status == 200:
                    break
                last_err = f"Status {status}: {body}"
            except Exception as e:
                last_err = str(e)
            time.sleep(0.2)
        else:
            self.stop()
            raise RuntimeError(f"Daemon failed to respond to health check on port {self.port}. Last error: {last_err}")

    def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = None

    @property
    def native_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/native/v1"

    @property
    def liveness_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/native/liveness/v1"

    @property
    def instance_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/native/v1/instance"

    def get_instance_info(self) -> tuple[str, str, list]:
        status, body = http_get(self.instance_url, self.native_token)
        assert status == 200, f"Failed to get instance info: {body}"
        return body["instance_id"], body["registry_sha256"], body.get("bindings", [])

    def mint_child_authority(
        self,
        session: str,
        server: str,
        ttl_seconds: int = 300,
        tools: list[str] | None = None,
        agent_id: str | None = None,
        parent_id: str | None = None,
        parent_binding: str | None = None,
        instance_id: str | None = None,
    ) -> str:
        cmd = [
            str(self.binary_path),
            "child-authority",
            "mint",
            "--session",
            session,
            "--server",
            server,
            "--ttl-seconds",
            str(ttl_seconds),
        ]
        if tools:
            for t in tools:
                cmd.extend(["--tools", t])
        if agent_id:
            cmd.extend(["--agent-id", agent_id])
        if parent_id:
            cmd.extend(["--parent-id", parent_id])
        if parent_binding:
            cmd.extend(["--parent-binding", parent_binding])
        if instance_id:
            cmd.extend(["--instance-id", instance_id])
        env = os.environ.copy()
        env["HOME"] = str(self.temp_dir)
        out = subprocess.check_output(cmd, env=env, text=True)
        return out.strip()

    def spawn_collector(
        self,
        server_id: str,
        session_id: str | None = None,
        host_session: str | None = None,
        child_authority: str | None = None,
        lease_secs: int | None = None,
        server_script_path: Path | None = None,
    ) -> tuple[subprocess.Popen, Path]:
        if server_script_path is None:
            notes_dir = self.temp_dir / "notes"
            notes_dir.mkdir(exist_ok=True)
            note_file = notes_dir / "testnote.txt"
            note_file.write_text("SOU-89 verified effect: note read.\n", encoding="utf-8")
            schema_repr = repr(json.dumps(TOOL_SCHEMA))
            note_path_repr = repr(str(note_file))
            server_script = f'''import sys, json, pathlib
SCHEMA = json.loads({schema_repr})
NOTE_PATH = pathlib.Path({note_path_repr})
for line in sys.stdin:
    if not line.strip():
        continue
    req = json.loads(line)
    m = req.get("method")
    if m == "initialize":
        res = {{"protocolVersion": "2024-11-05", "capabilities": {{"tools": {{}}}}, "serverInfo": {{"name": "sou89-fs", "version": "1"}}}}
    elif m == "tools/list":
        res = {{"tools": [{{"name": "read_document", "description": "Read a document", "inputSchema": SCHEMA}}]}}
    elif m == "tools/call":
        actual_content = NOTE_PATH.read_text(encoding="utf-8").strip()
        res = {{"content": [{{"type": "text", "text": actual_content}}]}}
    else:
        continue
    out = json.dumps({{"jsonrpc": "2.0", "id": req["id"], "result": res}})
    sys.stdout.write(out + chr(10))
    sys.stdout.flush()
'''
            server_script_path = self.temp_dir / f"server_{server_id}.py"
            server_script_path.write_text(server_script, encoding="utf-8")

        env = os.environ.copy()
        env["HOME"] = str(self.temp_dir)
        env["AGENTFW_NATIVE_LIVENESS"] = "true"
        if lease_secs is not None:
            env["AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS"] = str(lease_secs)
        else:
            env["AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS"] = str(self.lease_secs)
        if session_id:
            env["AGENTFW_MCP_SESSION"] = session_id

        cmd = [
            str(self.binary_path),
            "mcp",
            "--native-admission",
            "--id",
            server_id,
        ]
        if host_session:
            cmd.extend(["--host-session", host_session])
        if child_authority:
            cmd.extend(["--child-authority", child_authority])
        cmd.extend(["--", sys.executable, str(server_script_path)])

        proc = subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return proc, server_script_path


def test_abrupt_sigkill_without_session_end(daemon: DaemonFixture) -> dict:
    instance_id, registry_sha256, _ = daemon.get_instance_info()
    session_id = f"collector-sigkill-{int(time.time() * 1000)}"

    # 1. Spawn real agentfw mcp collector subprocess
    collector_proc, _ = daemon.spawn_collector(
        "sigkill-collector",
        session_id=session_id,
        lease_secs=daemon.lease_secs,
    )
    collector_pid = collector_proc.pid

    # 2. Handshake initialize over stdio JSON-RPC
    init_msg = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    }) + "\n"
    collector_proc.stdin.write(init_msg)
    collector_proc.stdin.flush()
    init_line = collector_proc.stdout.readline()
    assert init_line, "Collector failed to respond to initialize"
    assert collector_proc.poll() is None, "Collector process must be actively running"

    # 3. Verify session is enrolled and active in daemon liveness
    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "status",
        },
    )
    assert status == 200 and body.get("status") == "active", f"Session must be active on daemon: {body}"

    # 4. Send abrupt SIGKILL to the real collector process
    start_time = time.time()
    os.kill(collector_pid, signal.SIGKILL)
    collector_proc.wait(timeout=3.0)
    assert collector_proc.poll() is not None, "Collector process must have exited"

    # Sleep past lease duration (daemon maintenance worker runs at 100ms interval)
    time.sleep(daemon.lease_secs + 1.0)

    # 5. Independent witness: query status without sending any session_end
    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "status",
        },
    )
    elapsed = time.time() - start_time
    assert elapsed <= CLEANUP_DEADLINE_SECS, f"Cleanup exceeded deadline: {elapsed}s > {CLEANUP_DEADLINE_SECS}s"
    assert status == 404, f"Expected 404 session unknown after autonomous cleanup, got {status} ({body})"

    return {
        "scenario": "abrupt_sigkill_without_session_end",
        "passed": True,
        "collector_pid": collector_pid,
        "cleanup_seconds": round(elapsed, 3),
        "deadline_seconds": CLEANUP_DEADLINE_SECS,
    }


def test_idle_daemon_expiry_without_new_request(daemon: DaemonFixture) -> dict:
    instance_id, registry_sha256, _ = daemon.get_instance_info()
    session_id = f"collector-idle-{int(time.time() * 1000)}"

    status, body = http_post(
        daemon.native_url,
        daemon.native_token,
        {
            "contract_version": NATIVE_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "event": "session_start",
        },
    )
    assert status == 200
    owner_token = body["owner_token"]

    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "enroll",
            "lease_seconds": 2,
            "owner_token": owner_token,
        },
    )
    assert status == 200
    epoch = body["epoch"]

    # Sleep past lease duration with zero requests sent to the daemon
    time.sleep(3.2)

    # Witness: session is dead and attempt to renew is rejected
    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "renew",
            "epoch": epoch,
            "lease_seq": 2,
        },
    )
    assert status in (404, 409), f"Expected dead session renewal rejection, got {status} ({body})"

    return {
        "scenario": "idle_daemon_expiry_without_new_request",
        "passed": True,
    }


def test_repeated_crash_reconnect_beyond_64(daemon: DaemonFixture) -> dict:
    instance_id, registry_sha256, _ = daemon.get_instance_info()
    iterations = 70  # Exceeds MAX_SESSIONS = 64
    batch_size = 14
    batches = iterations // batch_size

    count = 0
    for b in range(batches):
        procs = []
        for i in range(batch_size):
            sid = f"churn-collector-{b}-{i}-{int(time.time() * 1000)}"
            proc, _ = daemon.spawn_collector(
                f"sou89-churn-{b}-{i}",
                session_id=sid,
                lease_secs=1,
            )
            # Initialize collector via JSON-RPC to establish authenticated session & enrollment
            req = json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "churn-collector", "version": "1"},
                },
            }) + "\n"
            proc.stdin.write(req)
            proc.stdin.flush()
            line = proc.stdout.readline()
            assert line and "result" in json.loads(line), f"Collector init failed at batch {b} item {i}"
            procs.append(proc)
            count += 1

        # Abruptly SIGKILL each collector without sending session_end or retire
        for proc in procs:
            try:
                os.kill(proc.pid, signal.SIGKILL)
                proc.wait(timeout=2.0)
            except (OSError, subprocess.TimeoutExpired):
                pass

        # Daemon maintenance loop sweeps expired 1s leases autonomously; wait 1.6s
        time.sleep(1.6)

    return {
        "scenario": "repeated_crash_reconnect_beyond_64",
        "passed": True,
        "iterations": count,
    }


def test_healthy_idle_useful_renewal(daemon: DaemonFixture) -> dict:
    session_id = f"collector-healthy-{int(time.time() * 1000)}"
    collector_proc, _ = daemon.spawn_collector(
        "sou89-filesystem-server",
        session_id=session_id,
        lease_secs=2,
    )

    def rpc(msg: dict) -> dict:
        collector_proc.stdin.write(json.dumps(msg) + "\n")
        collector_proc.stdin.flush()
        line = collector_proc.stdout.readline()
        assert line, f"Collector closed stdout unexpectedly on request: {msg}"
        return json.loads(line)

    # 1. Initialize
    init_res = rpc({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1"},
        },
    })
    assert "result" in init_res, f"Initialize failed: {init_res}"

    # 2. Initialized notification
    collector_proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    collector_proc.stdin.flush()
    time.sleep(0.1)

    # 3. tools/list
    list_res = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert "result" in list_res, f"Tools list failed: {list_res}"

    # 4. Useful work 1
    call1 = rpc({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "read_document", "arguments": {"name": "testnote"}},
    })
    assert (
        call1.get("result", {}).get("content", [{}])[0].get("text")
        == "SOU-89 verified effect: note read."
    ), f"Call 1 unexpected result: {call1}"

    # 5. Idle period across multiple renewal intervals (2s lease -> sleep 3.5s while collector renews)
    time.sleep(3.5)

    # 6. Useful work 2 after autonomous renewal
    call2 = rpc({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "read_document", "arguments": {"name": "testnote"}},
    })
    assert (
        call2.get("result", {}).get("content", [{}])[0].get("text")
        == "SOU-89 verified effect: note read."
    ), f"Call 2 unexpected result: {call2}"

    # 7. Clean shutdown
    collector_proc.stdin.close()
    collector_proc.wait(timeout=3.0)
    assert collector_proc.returncode == 0, f"Collector must exit cleanly with 0, got {collector_proc.returncode}"

    return {
        "scenario": "healthy_idle_useful_renewal",
        "passed": True,
        "useful_calls_completed": 2,
    }


def test_active_sibling_isolation(daemon: DaemonFixture) -> dict:
    instance_id, registry_sha256, _ = daemon.get_instance_info()
    sid_a = f"collector-sibling-a-{int(time.time() * 1000)}"
    sid_b = f"collector-sibling-b-{int(time.time() * 1000)}"

    # Spawn both real collector processes as siblings of the same server
    proc_a, _ = daemon.spawn_collector("sou89-filesystem-server", session_id=sid_a, lease_secs=2)
    proc_b, _ = daemon.spawn_collector("sou89-filesystem-server", session_id=sid_b, lease_secs=10)

    def rpc(p: subprocess.Popen, msg: dict) -> dict:
        p.stdin.write(json.dumps(msg) + "\n")
        p.stdin.flush()
        line = p.stdout.readline()
        assert line, f"Collector closed stdout unexpectedly on request: {msg}"
        return json.loads(line)

    # Initialize both collectors
    init_msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "sibling-test", "version": "1"},
        },
    }
    init_a = rpc(proc_a, init_msg)
    assert "result" in init_a, f"Init A failed: {init_a}"
    init_b = rpc(proc_b, init_msg)
    assert "result" in init_b, f"Init B failed: {init_b}"

    for p in (proc_a, proc_b):
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        p.stdin.flush()
    time.sleep(0.1)

    # Discovery on both collectors
    list_msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    list_a = rpc(proc_a, list_msg)
    assert "result" in list_a, f"Tools list A failed: {list_a}"
    list_b = rpc(proc_b, list_msg)
    assert "result" in list_b, f"Tools list B failed: {list_b}"

    # Useful work on both before crash: read testnote.txt from disk
    call_msg = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "read_document", "arguments": {"name": "testnote"}},
    }
    call_a = rpc(proc_a, call_msg)
    assert call_a.get("result", {}).get("content", [{}])[0].get("text") == "SOU-89 verified effect: note read."
    call_b = rpc(proc_b, call_msg)
    assert call_b.get("result", {}).get("content", [{}])[0].get("text") == "SOU-89 verified effect: note read."

    # Abruptly kill Sibling A with SIGKILL without session_end
    try:
        os.kill(proc_a.pid, signal.SIGKILL)
        proc_a.wait(timeout=2.0)
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Wait 3.2s for A's 2s lease to expire and be swept autonomously by daemon maintenance
    time.sleep(3.2)

    # Witness: A is dead and reclaimed in daemon liveness status
    status, _ = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": sid_a,
            "instance_id": instance_id,
            "action": "status",
        },
    )
    assert status == 404, f"Expected A to be reclaimed, got status {status}"

    # Witness: B is completely unaffected, remains active, and executes another useful call over its live process
    call_b2 = rpc(proc_b, {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "read_document", "arguments": {"name": "testnote"}},
    })
    assert call_b2.get("result", {}).get("content", [{}])[0].get("text") == "SOU-89 verified effect: note read."

    # Clean shutdown of B
    proc_b.stdin.close()
    proc_b.wait(timeout=3.0)
    assert proc_b.returncode == 0, f"Sibling B must exit cleanly with 0, got {proc_b.returncode}"

    return {
        "scenario": "active_sibling_isolation",
        "passed": True,
        "sibling_survived_and_useful": True,
    }


def test_stale_and_forged_renewals(daemon: DaemonFixture) -> dict:
    instance_id, registry_sha256, _ = daemon.get_instance_info()
    session_id = f"collector-forged-{int(time.time() * 1000)}"

    status, body = http_post(
        daemon.native_url,
        daemon.native_token,
        {
            "contract_version": NATIVE_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "event": "session_start",
        },
    )
    assert status == 200
    owner_token = body["owner_token"]

    # Forged: missing owner token
    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "enroll",
            "lease_seconds": 15,
        },
    )
    assert status == 403 and body.get("error_code") == "native_liveness_owner_token_required"

    # Forged: wrong owner token
    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "enroll",
            "lease_seconds": 15,
            "owner_token": "wrong-token",
        },
    )
    assert status == 403 and body.get("error_code") == "native_liveness_owner_mismatch"

    # Legitimate enroll
    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "enroll",
            "lease_seconds": 15,
            "owner_token": owner_token,
        },
    )
    assert status == 200
    epoch = body["epoch"]

    # Re-enrollment rejected
    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "enroll",
            "lease_seconds": 15,
            "owner_token": owner_token,
        },
    )
    assert status == 409 and body.get("error_code") == "native_liveness_already_enrolled"

    # Valid renew seq 2
    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "renew",
            "epoch": epoch,
            "lease_seq": 2,
        },
    )
    assert status == 200

    # Stale/replay seq 2 rejected
    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "renew",
            "epoch": epoch,
            "lease_seq": 2,
        },
    )
    assert status == 409 and body.get("error_code") == "native_liveness_seq_stale"

    # Epoch mismatch rejected
    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "renew",
            "epoch": "wrong-epoch",
            "lease_seq": 3,
        },
    )
    assert status == 403 and body.get("error_code") == "native_liveness_epoch_mismatch"

    # Instance mismatch rejected
    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": "wrong-instance-id",
            "action": "renew",
            "epoch": epoch,
            "lease_seq": 3,
        },
    )
    assert status == 409 and body.get("error_code") == "native_instance_mismatch"

    # Clean up
    http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "retire",
            "epoch": epoch,
        },
    )

    return {
        "scenario": "stale_and_forged_renewals",
        "passed": True,
    }


def test_old_result_replay_rejected(daemon: DaemonFixture) -> dict:
    instance_id, registry_sha256, _ = daemon.get_instance_info()
    session_id = f"collector-replay-{int(time.time() * 1000)}"

    status, body = http_post(
        daemon.native_url,
        daemon.native_token,
        {
            "contract_version": NATIVE_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "event": "session_start",
        },
    )
    assert status == 200
    owner_token = body["owner_token"]

    status, body = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "enroll",
            "lease_seconds": 15,
            "owner_token": owner_token,
        },
    )
    assert status == 200
    epoch = body["epoch"]

    # Execute a tool call
    status, body = http_post(
        daemon.native_url,
        daemon.native_token,
        {
            "contract_version": NATIVE_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "event": "call",
            "tool": "read_document",
            "args": {},
            "schema_sha256": TOOL_SCHEMA_SHA256,
        },
    )
    assert status == 200
    call_id = body.get("call_id")

    # Explicitly retire the session
    status, _ = http_post(
        daemon.liveness_url,
        daemon.native_token,
        {
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "instance_id": instance_id,
            "action": "retire",
            "epoch": epoch,
        },
    )
    assert status == 200

    # Sending a result for retired session cannot release or be accepted
    status, body = http_post(
        daemon.native_url,
        daemon.native_token,
        {
            "contract_version": NATIVE_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": session_id,
            "event": "result",
            "call_id": call_id,
            "tool": "read_document",
            "args": {},
            "result_kind": "text",
            "content": "stale content",
            "delivery": "model",
        },
    )
    assert status in (404, 409), f"Expected result rejection on retired session, got {status} ({body})"

    return {
        "scenario": "old_result_replay_rejected",
        "passed": True,
    }


def test_parent_expiration_cascades_to_children(daemon: DaemonFixture) -> dict:
    instance_id, registry_sha256, _ = daemon.get_instance_info()

    # 1. Mint root parent authority via real agentfw child-authority mint
    parent_token = daemon.mint_child_authority(
        session="host-root",
        server="docs-server",
        ttl_seconds=120,
        tools=["read_document"],
        agent_id="orch-1",
        instance_id=instance_id,
    )

    parent_sid = f"parent-cascade-{int(time.time() * 1000)}"
    status, body = http_post(
        daemon.native_url,
        daemon.native_token,
        {
            "contract_version": NATIVE_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": parent_sid,
            "event": "session_start",
            "host_session": "host-root",
            "server_id": "docs-server",
            "child_authority": parent_token,
        },
    )
    assert status == 200 and body.get("verdict") == "allow", f"Parent start failed: {body}"
    parent_owner = body["owner_token"]

    _, _, bindings = daemon.get_instance_info()
    parent_binding = [b for b in bindings if b.get("agent_id") == "orch-1"][0]["binding_sha256"]

    # 2. Mint child authority bound to parent
    child_token = daemon.mint_child_authority(
        session="host-root",
        server="docs-server",
        ttl_seconds=120,
        tools=["read_document"],
        agent_id="child-agent",
        parent_id="orch-1",
        parent_binding=parent_binding,
        instance_id=instance_id,
    )

    child_sid = f"child-cascade-{int(time.time() * 1000)}"
    status, body = http_post(
        daemon.native_url,
        daemon.native_token,
        {
            "contract_version": NATIVE_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": child_sid,
            "event": "session_start",
            "host_session": "host-root",
            "server_id": "docs-server",
            "child_authority": child_token,
        },
    )
    assert status == 200 and body.get("verdict") == "allow", f"Child start failed: {body}"
    child_owner = body["owner_token"]

    _, _, bindings = daemon.get_instance_info()
    child_binding = [b for b in bindings if b.get("agent_id") == "child-agent"][0]["binding_sha256"]

    # 3. Mint grandchild authority bound to child
    grandchild_token = daemon.mint_child_authority(
        session="host-root",
        server="docs-server",
        ttl_seconds=120,
        tools=["read_document"],
        agent_id="grandchild-agent",
        parent_id="child-agent",
        parent_binding=child_binding,
        instance_id=instance_id,
    )

    grandchild_sid = f"grandchild-cascade-{int(time.time() * 1000)}"
    status, body = http_post(
        daemon.native_url,
        daemon.native_token,
        {
            "contract_version": NATIVE_CONTRACT,
            "registry_sha256": registry_sha256,
            "session_id": grandchild_sid,
            "event": "session_start",
            "host_session": "host-root",
            "server_id": "docs-server",
            "child_authority": grandchild_token,
        },
    )
    assert status == 200 and body.get("verdict") == "allow", f"Grandchild start failed: {body}"
    grandchild_owner = body["owner_token"]

    # 4. Enroll all three: parent has short 2s lease, descendants have 60s leases
    for sid, owner, lease in [
        (parent_sid, parent_owner, 2),
        (child_sid, child_owner, 60),
        (grandchild_sid, grandchild_owner, 60),
    ]:
        status, body = http_post(
            daemon.liveness_url,
            daemon.native_token,
            {
                "contract_version": LIVENESS_CONTRACT,
                "registry_sha256": registry_sha256,
                "session_id": sid,
                "instance_id": instance_id,
                "action": "enroll",
                "lease_seconds": lease,
                "owner_token": owner,
            },
        )
        assert status == 200 and body.get("status") == "active", f"Enroll failed for {sid}: {body}"

    # 5. Sleep past parent lease duration (2s lease -> sleep 3.2s)
    time.sleep(3.2)

    # 6. Witness: parent expiry must cascade to all descendants autonomously
    for sid in (parent_sid, child_sid, grandchild_sid):
        status, body = http_post(
            daemon.liveness_url,
            daemon.native_token,
            {
                "contract_version": LIVENESS_CONTRACT,
                "registry_sha256": registry_sha256,
                "session_id": sid,
                "instance_id": instance_id,
                "action": "status",
            },
        )
        assert status == 404, f"Expected 404 for cascaded session {sid}, got {status} ({body})"

    return {
        "scenario": "parent_expiration_cascades_to_children",
        "passed": True,
        "hierarchy_levels": 3,
        "parent_session": parent_sid,
        "child_session": child_sid,
        "grandchild_session": grandchild_sid,
    }


def test_daemon_restart_causes_uncertainty(binary_path: Path, temp_dir: Path) -> dict:
    home_dir = temp_dir / "restart_test"
    daemon1 = DaemonFixture(binary_path, home_dir, lease_secs=2)
    daemon1.start()

    collector_proc: subprocess.Popen | None = None
    try:
        inst1, reg1, _ = daemon1.get_instance_info()
        sid = f"collector-restart-{int(time.time() * 1000)}"

        # 1. Spawn real agentfw mcp collector on daemon 1
        collector_proc, _ = daemon1.spawn_collector(
            "restart-collector",
            session_id=sid,
            lease_secs=2,
        )

        init_msg = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        }) + "\n"
        collector_proc.stdin.write(init_msg)
        collector_proc.stdin.flush()
        init_line = collector_proc.stdout.readline()
        assert init_line, "Collector failed to initialize on daemon 1"
        assert collector_proc.poll() is None, "Collector process must be actively running"
    finally:
        daemon1.stop()

    # 2. Restart daemon on same port from same home directory
    daemon2 = DaemonFixture(binary_path, home_dir, lease_secs=2)
    daemon2.port = daemon1.port
    # Ensure config.yaml matches same port
    cfg_yaml = f"""bind: "127.0.0.1"
port: {daemon2.port}
enforce: true
native:
  registry_path: "{daemon2.home / 'registry.json'}"
  registry_sha256: "{daemon2.registry_sha256}"
  liveness:
    default_lease_seconds: 2
    max_lease_seconds: 60
    maintenance_interval_ms: 100
"""
    (daemon2.home / "config.yaml").write_text(cfg_yaml, encoding="utf-8")
    daemon2.start()

    try:
        inst2, _, _ = daemon2.get_instance_info()
        assert inst1 != inst2, "Restarted daemon must generate a fresh instance ID"

        # 3. Running collector observes uncertainty on renewal attempt and halts execution
        try:
            collector_proc.wait(timeout=6.0)
            assert collector_proc.poll() is not None, "Collector must terminate after daemon restart uncertainty"
        except subprocess.TimeoutExpired:
            collector_proc.kill()
            collector_proc.wait()
            raise AssertionError("Collector failed to terminate upon daemon restart uncertainty within 6.0s!")

        # 4. Attempt to renew with old instance ID directly is rejected as conflict
        status, body = http_post(
            daemon2.liveness_url,
            daemon2.native_token,
            {
                "contract_version": LIVENESS_CONTRACT,
                "registry_sha256": reg1,
                "session_id": sid,
                "instance_id": inst1,
                "action": "renew",
                "epoch": "old-epoch",
                "lease_seq": 2,
            },
        )
        assert status == 409 and body.get("error_code") == "native_instance_mismatch"
    finally:
        daemon2.stop()

    return {
        "scenario": "daemon_restart_causes_uncertainty",
        "passed": True,
        "first_instance": inst1,
        "second_instance": inst2,
        "collector_exit_witness": collector_proc.returncode,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/agentfw"))
    parser.add_argument("--out", type=Path, default=Path("target/sou89-acceptance"))
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    report_file = args.out / "native-liveness-acceptance.json"

    if not args.binary.is_file():
        print(f"agentfw binary not found at {args.binary}")
        sys.exit(1)

    print(f"Running SOU-89 production liveness acceptance against {args.binary} on {platform.system()}...")
    results = []
    overall_passed = True

    with tempfile.TemporaryDirectory() as td:
        temp_dir = Path(td)
        daemon = DaemonFixture(args.binary, temp_dir)
        daemon.start()

        scenarios = [
            ("abrupt_sigkill_without_session_end", lambda: test_abrupt_sigkill_without_session_end(daemon)),
            ("idle_daemon_expiry_without_new_request", lambda: test_idle_daemon_expiry_without_new_request(daemon)),
            ("repeated_crash_reconnect_beyond_64", lambda: test_repeated_crash_reconnect_beyond_64(daemon)),
            ("healthy_idle_useful_renewal", lambda: test_healthy_idle_useful_renewal(daemon)),
            ("active_sibling_isolation", lambda: test_active_sibling_isolation(daemon)),
            ("stale_and_forged_renewals", lambda: test_stale_and_forged_renewals(daemon)),
            ("old_result_replay_rejected", lambda: test_old_result_replay_rejected(daemon)),
            ("parent_expiration_cascades_to_children", lambda: test_parent_expiration_cascades_to_children(daemon)),
            ("daemon_restart_causes_uncertainty", lambda: test_daemon_restart_causes_uncertainty(args.binary, temp_dir)),
        ]

        try:
            for name, test_fn in scenarios:
                t0 = time.time()
                try:
                    res = test_fn()
                    res["elapsed_seconds"] = round(time.time() - t0, 3)
                    results.append(res)
                    print(f"  [PASS] {name} ({res['elapsed_seconds']}s)")
                except Exception as e:
                    overall_passed = False
                    err_info = {
                        "scenario": name,
                        "passed": False,
                        "error": str(e),
                        "traceback": traceback.format_exc(),
                        "elapsed_seconds": round(time.time() - t0, 3),
                    }
                    results.append(err_info)
                    print(f"  [FAIL] {name}: {e}")
        finally:
            daemon.stop()

    summary = {
        "suite": "sou89-generic-component-acceptance",
        "kind": "generic-protocol-component-checks",
        "selected_production_acceptance": False,
        "contract": LIVENESS_CONTRACT,
        "platform": platform.system(),
        "machine": platform.machine(),
        "passed": overall_passed and all(r.get("passed") for r in results),
        "total_scenarios": len(results),
        "passed_scenarios": sum(1 for r in results if r.get("passed")),
        "results": results,
    }

    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print("\n" + json.dumps(summary, indent=2))
    if not summary["passed"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
