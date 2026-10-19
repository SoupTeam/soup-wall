#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in native standard-user Windows aggregate MCP budget acceptance.

No execution without --run. Run from a private directory outside the checkout.
Only typed counters, public fixture hashes and fixed failure codes are retained.
All positive cases are mandatory; no skip, fallback or forced-cleanup pass.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes as W
import hashlib
import http.client
import json
import os
import platform
from pathlib import Path
import queue
import socket
import subprocess
import sys
import threading
import time

FORMAT = "sou96-windows-mcp-budgets/1"
CONFIG_FORMAT = "sw-mcp/windows-job-budget/1"
TEXT = "SOU-96 useful owned bytes: 7 widgets; café.\n"
EFFECT = b"SOU-96 already executed effect.\n"
SCHEMA = {"type": "object", "properties": {}, "additionalProperties": False}
CASES = ("useful", "breakaway", "memory", "memory-hard", "process", "cpu", "wall", "cancel", "collector-death",
         "restart-0", "restart-1", "restart-2", "restart-3", "restart-4", "restart-5",
         "missing-config", "invalid-config", "unsafe-acl", "spawn-failure", "transparent-refusal")
REFUSALS = {"missing-config": "windows_budget_configuration_refused",
            "invalid-config": "windows_budget_configuration_refused",
            "unsafe-acl": "windows_budget_configuration_refused",
            "spawn-failure": "native_child_spawn",
            "transparent-refusal": "windows_budget_native_admission_required"}


def refusal_code(stderr):
    # Only fixed known diagnostics, never retain arbitrary startup text/paths.
    markers = {b"windows_budget_configuration_refused": "windows_budget_configuration_refused",
               b"native_child_spawn": "native_child_spawn",
               b"Windows MCP resource budgets require native admission": "windows_budget_native_admission_required"}
    found = {code for marker, code in markers.items() if marker in stderr}
    return next(iter(found)) if len(found) == 1 else None


BASE_CONFIG = {"format": CONFIG_FORMAT, "memoryMaxBytes": 256 * 1024**2,
               "memoryPressureBytes": 160 * 1024**2, "activeProcessMax": 12,
               "cpuUserMillis": 10000, "wallMillis": 20000}


def require(value, code):
    if not value:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def save(path, value):
    temporary = path.with_name(path.name + ".tmp-" + str(threading.get_ident()))
    temporary.write_bytes(canonical(value) + b"\n")
    os.replace(temporary, path)


class Basic(ctypes.Structure):
    _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64), ("flags", W.DWORD),
                ("minimum", ctypes.c_size_t), ("maximum", ctypes.c_size_t), ("active", W.DWORD),
                ("affinity", ctypes.c_size_t), ("priority", W.DWORD), ("scheduling", W.DWORD)]


class IO(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]


class Extended(ctypes.Structure):
    _fields_ = [("basic", Basic), ("io", IO), ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]


class ProcessEntry(ctypes.Structure):
    _fields_ = [("size", W.DWORD), ("usage", W.DWORD), ("pid", W.DWORD), ("heap", ctypes.c_size_t),
                ("module", W.DWORD), ("threads", W.DWORD), ("parent", W.DWORD),
                ("priority", W.LONG), ("flags", W.DWORD), ("name", W.WCHAR * 260)]


class Memory(ctypes.Structure):
    _fields_ = [("size", W.DWORD), ("faults", W.DWORD)] + [
        (name, ctypes.c_size_t) for name in ("peak_ws", "working_set", "peak_paged", "paged",
                                           "peak_nonpaged", "nonpaged", "pagefile", "peak_pagefile", "private")]


class Windows:
    def __init__(self):
        require(os.name == "nt", "native_windows_required")
        self.k = ctypes.WinDLL("kernel32", use_last_error=True)
        self.p = ctypes.WinDLL("psapi", use_last_error=True)
        signatures = {
            "CreateJobObjectW": ([ctypes.c_void_p, W.LPCWSTR], W.HANDLE),
            "SetInformationJobObject": ([W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD], W.BOOL),
            "AssignProcessToJobObject": ([W.HANDLE, W.HANDLE], W.BOOL),
            "GetCurrentProcess": ([], W.HANDLE),
            "CloseHandle": ([W.HANDLE], W.BOOL),
            "OpenProcess": ([W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
            "WaitForSingleObject": ([W.HANDLE, W.DWORD], W.DWORD),
            "GetProcessTimes": ([W.HANDLE] + [ctypes.POINTER(W.FILETIME)] * 4, W.BOOL),
            "CreateToolhelp32Snapshot": ([W.DWORD, W.DWORD], W.HANDLE),
            "Process32FirstW": ([W.HANDLE, ctypes.POINTER(ProcessEntry)], W.BOOL),
            "Process32NextW": ([W.HANDLE, ctypes.POINTER(ProcessEntry)], W.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.k, name)
            function.argtypes, function.restype = args, result
        self.p.GetProcessMemoryInfo.argtypes = [W.HANDLE, ctypes.POINTER(Memory), W.DWORD]
        self.p.GetProcessMemoryInfo.restype = W.BOOL
        # An outer finite Job contains the harness BEFORE any fixture or Agent.
        # Its handle is private and intentionally lives until process exit.
        self.outer = self.k.CreateJobObjectW(None, None)
        require(self.outer, "outer_job_create")
        limits = Extended()
        limits.basic.flags = 0x2000 | 0x200 | 0x8 | 0x4
        limits.basic.active, limits.basic.job_time = 64, 120 * 10_000_000
        limits.job_memory = 1024**3
        require(self.k.SetInformationJobObject(self.outer, 9, ctypes.byref(limits), ctypes.sizeof(limits)),
                "outer_finite_limits")
        require(self.k.AssignProcessToJobObject(self.outer, self.k.GetCurrentProcess()), "outer_job_assign")

    def times(self, handle):
        values = [W.FILETIME() for _ in range(4)]
        require(self.k.GetProcessTimes(handle, *(ctypes.byref(v) for v in values)), "process_time_witness")
        return [v.dwLowDateTime + (v.dwHighDateTime << 32) for v in values]

    def snapshot(self):
        handle = self.k.CreateToolhelp32Snapshot(2, 0)
        require(handle and handle != ctypes.c_void_p(-1).value, "process_snapshot")
        try:
            entry, rows = ProcessEntry(), []
            entry.size = ctypes.sizeof(entry)
            ok = self.k.Process32FirstW(handle, ctypes.byref(entry))
            while ok:
                rows.append((int(entry.pid), int(entry.parent)))
                require(len(rows) <= 65536, "process_snapshot_bound")
                ok = self.k.Process32NextW(handle, ctypes.byref(entry))
            require(ctypes.get_last_error() == 18, "process_snapshot_incomplete")
            return rows
        finally:
            self.k.CloseHandle(handle)


class Witness:
    """Kernel handles and birth times, independent of Agent reports/PID files."""
    def __init__(self, api, process):
        self.api, self.process, self.handles, self.rows = api, process, {}, {}
        self.peak_alive, self.peak_private, self.error = 0, 0, None
        self.stop = threading.Event()
        self.sample()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def sample(self):
        known = {self.process.pid} | set(self.handles)
        snapshot = self.api.snapshot()
        for _ in range(32):
            expanded = known | {pid for pid, parent in snapshot if parent in known}
            if expanded == known:
                break
            known = expanded
        require(len(known) <= 64, "owned_process_count_bound")
        for pid in known:
            if pid not in self.handles:
                handle = self.api.k.OpenProcess(0x1000 | 0x10 | 0x100000, False, pid)
                if not handle:
                    continue  # Short-lived rows cannot provide positive evidence.
                created, _, _, _ = self.api.times(handle)
                self.handles[pid] = handle
                self.rows[pid] = {"pid": pid, "created_100ns": created, "peak_private_bytes": 0,
                                  "cpu_user_100ns": 0, "cpu_kernel_100ns": 0}
        alive, private = 0, 0
        for pid, handle in self.handles.items():
            created, _, kernel, user = self.api.times(handle)
            row = self.rows[pid]
            require(created == row["created_100ns"], "process_identity_changed")
            row.update(cpu_user_100ns=user, cpu_kernel_100ns=kernel)
            row["stopped"] = self.api.k.WaitForSingleObject(handle, 0) == 0
            if not row["stopped"]:
                alive += 1
                memory = Memory()
                memory.size = ctypes.sizeof(memory)
                if not self.api.p.GetProcessMemoryInfo(handle, ctypes.byref(memory), ctypes.sizeof(memory)):
                    require(self.api.k.WaitForSingleObject(handle, 0) == 0, "process_memory_witness")
                    continue
                row["peak_private_bytes"] = max(row["peak_private_bytes"], memory.private)
                private += memory.private
        self.peak_alive = max(self.peak_alive, alive)
        self.peak_private = max(self.peak_private, private)

    def loop(self):
        try:
            while not self.stop.wait(0.005):
                self.sample()
        except Exception as error:
            self.error = type(error).__name__

    def finish(self):
        self.stop.set()
        self.thread.join(5)
        try:
            self.sample()
        except Exception as error:
            self.error = type(error).__name__
        result = {"processes": list(self.rows.values()), "peak_owned_processes": self.peak_alive,
                  "peak_aggregate_private_bytes": self.peak_private, "observer_error": self.error,
                  "observer_stopped": not self.thread.is_alive(),
                  "all_stopped": all(row.get("stopped") for row in self.rows.values())}
        for handle in self.handles.values():
            self.api.k.CloseHandle(handle)
        return result


class Capture:
    def __init__(self, stream):
        self.stream, self.data, self.frames, self.error = stream, bytearray(), queue.Queue(maxsize=64), None
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()

    def read(self):
        try:
            while True:
                line = self.stream.readline(16385)
                if not line:
                    return
                require(len(line) <= 16384 and len(self.data) + len(line) <= 256 * 1024, "capture_bound")
                self.data.extend(line)
                self.frames.put_nowait(line)
        except Exception as error:
            self.error = type(error).__name__

    def finish(self):
        self.thread.join(5)
        return bytes(self.data)


SERVER = r'''
import ctypes, json, os, subprocess, sys, time
from pathlib import Path
root, mode = Path(sys.argv[1]), sys.argv[2]
if mode.startswith('worker-'):
 role=mode[7:]; (root/('worker-'+str(os.getpid()))).write_text(role)
 if role=='memory':
  blocks=[]
  for _ in range(64):
   blocks.append(bytearray(1024*1024)); time.sleep(.05)
 elif role=='memory-hard':
  (root/('allocation-attempt-'+str(os.getpid()))).write_text('96MiB')
  try: block=bytearray(96*1024*1024)
  except MemoryError: (root/('allocation-refused-'+str(os.getpid()))).write_text('refused')
 elif role=='cpu':
  stop=time.monotonic()+15; counter=0
  while time.monotonic()<stop: counter+=1
 time.sleep(20); raise SystemExit(0)
(root/'started').write_text(str(os.getpid()))
schema={'type':'object','properties':{},'additionalProperties':False}
for raw in sys.stdin:
 request=json.loads(raw); method=request.get('method')
 if method=='initialize':
  result={'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'sou96-owned','version':'1'}}
 elif method=='tools/list':
  result={'tools':[{'name':name,'inputSchema':schema} for name in ('read_metadata','exercise')]}
 elif method=='tools/call':
  name=request['params']['name']
  if name=='read_metadata': result={'content':[{'type':'text','text':(root/'source.txt').read_text(encoding='utf-8')}]}
  else:
   (root/'effect.txt').write_bytes(b'SOU-96 already executed effect.\n')
   if mode=='breakaway':
    try:
     subprocess.Popen([sys.executable,'-I','-u',__file__,str(root),'worker-idle'],creationflags=subprocess.CREATE_BREAKAWAY_FROM_JOB,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
     (root/'escaped').write_text('escape')
    except OSError: (root/'breakaway-refused').write_text('refused')
    result={'content':[{'type':'text','text':'SOU96_BREAKAWAY_REFUSED'}]}
    os.write(1,json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result},separators=(',',':')).encode()+b'\n')
    continue
   role=mode if mode in ('memory','memory-hard','cpu') else 'idle'
   count=3 if mode in ('memory','memory-hard','cpu') else 8 if mode=='process' else 2
   children=[]
   for _ in range(count):
    try: children.append(subprocess.Popen([sys.executable,'-I','-u',__file__,str(root),'worker-'+role],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
    except OSError: (root/'spawn-refused').write_text('refused'); break
    time.sleep(.05)
   time.sleep(20)
   result={'content':[{'type':'text','text':'SOU96_LATE_RESULT_MUST_BE_WITHHELD'}]}
 else: continue
 os.write(1,json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result},ensure_ascii=False,separators=(',',':')).encode()+b'\n')
'''


def private_file(path):
    identity = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, check=True, timeout=10)
    import re
    sids = re.findall(rb"S-1-5-21-(?:[0-9]+-){3}[0-9]+", identity.stdout)
    require(len(sids) == 1, "standard_user_sid_missing")
    result = subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                             "*" + sids[0].decode() + ":F", "*S-1-5-18:F"], capture_output=True, timeout=10)
    require(result.returncode == 0, "configuration_acl_setup")


class Rig:
    def __init__(self, api, binary, root):
        self.api, self.binary, self.root = api, binary, root
        home = root / "home"
        self.audit_path = home / ".agentfw/audit.jsonl"
        home.mkdir()
        self.env = {key: value for key, value in os.environ.items() if key.upper() in
                    {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "SYSTEMDRIVE"}}
        self.env.update(HOME=str(home), USERPROFILE=str(home), APPDATA=str(home / "appdata"),
                        LOCALAPPDATA=str(home / "localappdata"), TEMP=str(root), TMP=str(root),
                        AGENTFW_WORKSPACE=str(root), AGENTFW_NATIVE_LIVENESS="1",
                        AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS="2")
        result = subprocess.run([str(binary), "install"], env=self.env, capture_output=True, timeout=30)
        require(result.returncode == 0, "owned_agent_install_failed")
        registry = {"contract_version": "sw-native/1", "registry_id": "sou96-owned", "tools": [
            {"name": name, "schema_sha256": sha(canonical(SCHEMA)), "action_class": action,
             "result_provenance": "local_system", "egress": []}
            for name, action in (("read_metadata", "read_only"), ("exercise", "side_effecting"))]}
        save(root / "registry.json", registry)
        policy = root / "policy.yaml"
        policy.write_text("agent_policies: []\ndefault: allow\n", encoding="utf-8")
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        config = {"port": self.port, "enforce": True, "policy": str(policy), "native": {
            "registry_path": str(root / "registry.json"), "registry_sha256": sha((root / "registry.json").read_bytes())}}
        save(home / ".agentfw/config.yaml", config)
        self.identities = {"registry_sha256": sha((root / "registry.json").read_bytes()), "policy_sha256": sha(policy.read_bytes()),
                           "agent_configuration_sha256": sha((home / ".agentfw/config.yaml").read_bytes())}
        self.clients = []
        self.server = root / "owned-server.py"
        self.server.write_text(SERVER, encoding="utf-8", newline="")
        self.daemon = subprocess.Popen([str(binary), "serve"], env=self.env, cwd=root,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.daemon_out, self.daemon_err = Capture(self.daemon.stdout), Capture(self.daemon.stderr)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            require(self.daemon.poll() is None, "owned_daemon_start_failed")
            try:
                connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=1)
                connection.request("GET", "/health")
                if connection.getresponse().status == 200:
                    connection.close()
                    return
                connection.close()
            except OSError:
                pass
            time.sleep(.05)
        raise ValueError("owned_daemon_deadline")

    def close(self):
        self.daemon.kill()
        self.daemon.wait(10)
        return {"stdout_sha256": sha(self.daemon_out.finish()), "stderr_sha256": sha(self.daemon_err.finish())}

    def audit(self):
        raw = self.audit_path.read_bytes() if self.audit_path.exists() else b""
        require(len(raw) <= 2 * 1024**2, "audit_witness_bound")
        # Ignore only a final partial append, then retry for terminal witnesses.
        lines = raw.split(b"\n")[:-1]
        return [json.loads(line) for line in lines if line]


class Client:
    def __init__(self, rig, name):
        self.rig, self.name = rig, name
        self.root = rig.root / name
        self.root.mkdir()
        (self.root / "source.txt").write_text(TEXT, encoding="utf-8", newline="")
        config = dict(BASE_CONFIG)
        if name == "sibling":
            config["wallMillis"] = 180000
        mode = "wall" if name.startswith("restart-") else name
        if mode == "process":
            config["activeProcessMax"] = 6
        if mode == "cpu":
            config["cpuUserMillis"] = 1000
        if mode == "memory-hard":
            config["memoryPressureBytes"] = config["memoryMaxBytes"] - 65536
        if mode == "wall":
            config["wallMillis"] = 5000
        self.config = config
        self.start_index = sum(item.get("event") == "native_session_start" for item in rig.audit())
        path = self.root / "budget.json"
        save(path, config if name != "invalid-config" else {**config, "wallMillis": 0})
        if name != "unsafe-acl":
            private_file(path)
        env = dict(rig.env, AGENTFW_MCP_WINDOWS_BUDGET=str(path))
        if name == "missing-config":
            env["AGENTFW_MCP_WINDOWS_BUDGET"] = str(self.root / "absent.json")
        command = [str(rig.binary), "mcp"]
        if name != "transparent-refusal":
            command += ["--native-admission"]
        command += ["--id", "sou96-" + name, "--", sys.executable, "-I", "-u", str(rig.server), str(self.root), mode]
        if name == "spawn-failure":
            command = command[:command.index("--") + 1] + [str(self.root / "absent.exe")]
        self.started = time.monotonic()
        self.process = subprocess.Popen(command, env=env, cwd=rig.root, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rig.clients.append(self.process)
        self.witness = Witness(rig.api, self.process)
        self.out, self.err = Capture(self.process.stdout), Capture(self.process.stderr)
        self.useful = False

    def send(self, value):
        self.process.stdin.write(canonical(value) + b"\n")
        self.process.stdin.flush()

    def exchange(self, value):
        self.send(value)
        result = json.loads(self.out.frames.get(timeout=8))
        require(result.get("id") == value["id"] and "error" not in result, "protocol_result_missing")
        return result

    def initialize(self):
        self.exchange({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "sou96", "version": "1"}}})
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        result = self.exchange({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        require(len(result.get("result", {}).get("tools", [])) == 2, "manifest_missing")
        self.read(3)

    def read(self, identifier):
        result = self.exchange({"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                                "params": {"name": "read_metadata", "arguments": {}}})
        require(result.get("result") == {"content": [{"type": "text", "text": TEXT}]}, "useful_content_changed")
        self.useful = True

    def exercise(self):
        self.send({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "exercise", "arguments": {}}})
        deadline = time.monotonic() + 5
        while not (self.root / "effect.txt").exists() and time.monotonic() < deadline:
            time.sleep(.005)
        require((self.root / "effect.txt").read_bytes() == EFFECT, "executed_effect_missing")

    def finish(self, expect_failure):
        forced = False
        try:
            self.process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            forced = True
            self.process.kill()
            self.process.wait(5)
        deadline = time.monotonic() + 4
        while any(self.rig.api.k.WaitForSingleObject(handle, 0) != 0 for pid, handle in self.witness.handles.items()
                  if pid != self.process.pid) and time.monotonic() < deadline:
            time.sleep(.01)
        proof = self.witness.finish()
        stdout, stderr = self.out.finish(), self.err.finish()
        audit = self.rig.audit()
        starts = [item for item in audit if item.get("event") == "native_session_start"]
        epoch = starts[self.start_index].get("session") if len(starts) > self.start_index else None
        deadline = time.monotonic() + 5
        terminal = []
        while epoch and time.monotonic() < deadline:
            audit = self.rig.audit()
            terminal = [item for item in audit if item.get("session") == epoch
                        and item.get("event") in {"native_session_retired", "native_session_expired"}]
            if terminal:
                break
            time.sleep(.02)
        native_calls = sum(item.get("session") == epoch and item.get("event") == "native_call" for item in audit)
        native_results = sum(item.get("session") == epoch and item.get("event") == "native_result" for item in audit)
        events = []
        for line in stderr.splitlines():
            try:
                event = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if event.get("event") == "mcp_windows_budget_end":
                events.append(event)
        row = {"case": self.name, "configuration": self.config, "configuration_file_sha256": sha((self.root / "budget.json").read_bytes()),
               "collector_pid": self.process.pid,
               "native_epoch_sha256": sha(epoch.encode()) if epoch else None,
               "native_terminal": terminal[-1].get("event") if terminal else None,
               "native_calls": native_calls, "native_results": native_results,
               "capture_complete": not self.out.thread.is_alive() and not self.err.thread.is_alive()
                    and self.out.error is None and self.err.error is None,
               "useful": self.useful, "elapsed_seconds": time.monotonic() - self.started,
               "exit_code": self.process.returncode, "forced_cleanup": forced, "witness": proof,
               "stdout_bytes": len(stdout), "stdout_sha256": sha(stdout), "stderr_bytes": len(stderr),
               "stderr_sha256": sha(stderr), "budget_events": events,
               "launch_refusal_code": refusal_code(stderr),
               "late_result_released": b"SOU96_LATE_RESULT_MUST_BE_WITHHELD" in stdout,
               "server_started": (self.root / "started").exists(),
               "breakaway_refused": (self.root / "breakaway-refused").exists() and not (self.root / "escaped").exists(),
               "allocation_attempts": len(list(self.root.glob("allocation-attempt-*"))),
               "allocation_refusals": len(list(self.root.glob("allocation-refused-*"))),
               "executed_effect_retained": (self.root / "effect.txt").exists() and (self.root / "effect.txt").read_bytes() == EFFECT}
        row["passed"] = (not forced and proof["all_stopped"] and proof["observer_error"] is None
                         and proof["observer_stopped"] and row["capture_complete"] and not row["late_result_released"]
                         and ((self.process.returncode != 0) if expect_failure else self.process.returncode == 0))
        return row


def grade(row):
    require(row["passed"], "owned_process_or_release_failure")
    name = row["case"]
    proof = row["witness"]
    require(row["capture_complete"] and not row["forced_cleanup"] and not row["late_result_released"]
            and proof["observer_stopped"] and proof["observer_error"] is None and proof["all_stopped"]
            and len(proof["processes"]) > 0 and all(p.get("stopped") is True for p in proof["processes"]),
            "independent_cleanup_or_release_failure")
    require((row["exit_code"] == 0) if name in {"useful", "breakaway", "sibling"} else (row["exit_code"] != 0),
            "unexpected_collector_exit")
    if name in {"missing-config", "invalid-config", "unsafe-acl", "spawn-failure", "transparent-refusal"}:
        require(not row["server_started"], "refusal_executed_server")
        require(row.get("launch_refusal_code") == REFUSALS[name], "wrong_launch_refusal_reason")
        return
    require(row["useful"], "useful_work_missing")
    require(row["native_epoch_sha256"] is not None and row["native_terminal"] in {
        "native_session_retired", "native_session_expired"}, "native_pending_authority_not_closed")
    if name not in {"useful", "breakaway", "sibling"}:
        require(row["native_calls"] > row["native_results"] >= 1, "pending_call_witness_missing")
    if name == "collector-death":
        require(row["native_terminal"] == "native_session_expired", "collector_death_not_autonomously_expired")
        require(len(row["witness"]["processes"]) >= 4, "collector_death_tree_missing")
        return
    events = row["budget_events"]
    require(len(events) == 1 and events[0].get("cleanup_verified") is True, "budget_cleanup_evidence_missing")
    budget = events[0]["budget"]
    require(budget.get("launch_ownership") == "job_list_before_execution", "atomic_launch_evidence_missing")
    require(budget.get("configuration") == row["configuration"], "configuration_identity_mismatch")
    ordered = {key: row["configuration"][key] for key in ("format", "memoryMaxBytes", "memoryPressureBytes",
                                                         "activeProcessMax", "cpuUserMillis", "wallMillis")}
    require(budget.get("configuration_sha256") == sha(json.dumps(ordered, separators=(",", ":")).encode()),
            "budget_identity_hash_mismatch")
    observed = budget["observed"]
    require(observed.get("closed") is True, "budget_monitor_not_closed")
    require(observed["peak_committed_bytes"] <= row["configuration"]["memoryMaxBytes"], "hard_memory_exceeded")
    require(observed["peak_active_processes"] <= row["configuration"]["activeProcessMax"], "process_cap_exceeded")
    require(events[0].get("effects_rolled_back") is False, "false_rollback_claim")
    if name in {"useful", "breakaway", "sibling"}:
        require(observed["reason"] is None, "useful_budget_failed")
        if name == "breakaway":
            require(row["breakaway_refused"], "job_breakaway_not_refused")
        return
    require(row["executed_effect_retained"], "executed_effect_not_retained")
    if name == "cancel":
        return
    reason = observed["reason"]
    require(reason is not None, "terminal_reason_missing")
    descendants = [p for p in row["witness"]["processes"] if p["pid"] != row["collector_pid"]]
    require(len(descendants) >= 3, "real_descendant_witness_missing")
    if name == "memory":
        require(reason in {"windows_budget_memory_pressure", "windows_budget_memory_limit"}, "wrong_memory_reason")
        require(observed["peak_committed_bytes"] >= row["configuration"]["memoryPressureBytes"], "aggregate_pressure_missing")
        require(row["witness"]["peak_aggregate_private_bytes"] >= 100 * 1024**2, "independent_allocation_missing")
        require(sum(p["peak_private_bytes"] >= 24 * 1024**2 for p in descendants) >= 2, "independent_descendant_allocations_missing")
        require(max(p["peak_private_bytes"] for p in descendants) < row["configuration"]["memoryPressureBytes"], "not_aggregate_memory")
    elif name == "memory-hard":
        require(reason in {"windows_budget_memory_limit", "windows_budget_memory_pressure"}, "wrong_hard_memory_reason")
        require(row["allocation_attempts"] >= 2 and row["allocation_refusals"] >= 1, "actual_allocation_refusal_missing")
        require(sum(p["peak_private_bytes"] >= 64 * 1024**2 for p in descendants) >= 2,
                "independent_hard_memory_allocations_missing")
    elif name == "process":
        require(reason in {"windows_budget_process_saturation", "windows_budget_process_limit"}, "wrong_process_reason")
        require(observed["total_processes"] >= 6 and row["witness"]["peak_owned_processes"] >= 5, "independent_process_pressure_missing")
    elif name == "cpu":
        require(reason == "windows_budget_cpu_time", "wrong_cpu_reason")
        actual = sum(p["cpu_user_100ns"] for p in descendants)
        limit = row["configuration"]["cpuUserMillis"] * 10000
        require(limit * .75 <= actual <= limit + 15_000_000, "independent_cpu_limit_missing")
    else:
        require(reason == "windows_budget_wall_deadline", "wrong_wall_reason")
        wall_seconds = row["configuration"]["wallMillis"] / 1000
        require(wall_seconds <= row["elapsed_seconds"] <= wall_seconds + 8, "wall_cleanup_late")


def grade_report(report):
    require(report.get("format") == FORMAT and report.get("status") == "pass", "report_incomplete")
    rows = report["cases"]
    require(len(rows) == len(CASES) and {row["case"] for row in rows} == set(CASES)
            and report.get("not_run") == [], "required_case_missing_or_duplicated")
    require(report.get("standard_user") is True and report.get("administrator_group_present") is False,
            "standard_user_witness_missing")
    for row in rows:
        grade(row)
        require(row.get("sibling_useful") is True, "sibling_followup_missing")
    restarts = [row["native_epoch_sha256"] for row in rows if row["case"].startswith("restart-")]
    require(len(set(restarts)) == 6, "restart_reused_native_epoch")
    sibling = report["sibling"]
    require(sibling.get("case") == "sibling", "independent_sibling_missing")
    grade(sibling)


def run(args):
    root = args.output.resolve()
    require(not any((parent / ".git").exists() for parent in [root, *root.parents, Path.cwd(), *Path.cwd().parents]),
            "acceptance_must_run_outside_checkout")
    require(not root.exists(), "evidence_directory_exists")
    root.mkdir(parents=True)
    require(len(args.source_commit) == 40 and all(c in "0123456789abcdef" for c in args.source_commit), "source_identity_invalid")
    report = {"format": FORMAT, "status": "incomplete", "source_commit": args.source_commit,
              "source_manifest_sha256": sha(args.source_manifest.read_bytes()),
              "binary_sha256": sha(args.agentfw.read_bytes()), "harness_sha256": sha(Path(__file__).read_bytes()),
              "windows_version": platform.version(), "architecture": platform.machine(),
              "python_version": platform.python_version(), "python_binary_sha256": sha(Path(sys.executable).read_bytes()),
              "fixture_sha256": sha(SERVER.encode()),
              "native_liveness": {"enabled": True, "lease_seconds": 2}, "pointer_bits": ctypes.sizeof(ctypes.c_void_p) * 8,
              "standard_user": False, "administrator_group_present": None,
              "outer_limits": {"committed_memory_bytes": 1024**3, "processes": 64, "cpu_user_seconds": 120, "wall_seconds": 240},
              "cases": [], "error": None}
    save(root / "results.json", report)
    manifest = json.loads(args.source_manifest.read_bytes())
    require(manifest.get("commit") == args.source_commit and len(manifest.get("files", {})) > 0,
            "source_manifest_identity_mismatch")
    require(all(not Path(name).is_absolute() and ".." not in Path(name).parts
                and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
                for name, digest in manifest["files"].items()), "source_manifest_invalid")
    def watchdog():
        time.sleep(240)
        report["error"], report["status"] = "outer_wall_deadline", "incomplete"
        save(root / "results.json", report)
        os._exit(124)  # Kernel closes private kill-on-close outer Job handle.
    threading.Thread(target=watchdog, daemon=True).start()
    rig = peer = None
    try:
        who = subprocess.run(["whoami", "/all", "/fo", "csv"], capture_output=True, check=True, timeout=10)
        require(b"S-1-5-32-544" not in who.stdout, "genuine_standard_user_required")
        require(ctypes.WinDLL("shell32").IsUserAnAdmin() == 0, "non_elevated_user_required")
        report.update(standard_user=True, administrator_group_present=False)
        api = Windows()
        rig = Rig(api, args.agentfw.resolve(), root)
        report.update(rig.identities)
        peer = Client(rig, "sibling")
        peer.initialize()
        peer_read_id = 10
        for name in CASES:
            report["active_case"] = name
            save(root / "results.json", report)
            client = Client(rig, name)
            expected_failure = name not in {"useful", "breakaway"}
            if name not in {"missing-config", "invalid-config", "unsafe-acl", "spawn-failure", "transparent-refusal"}:
                client.initialize()
                if name == "useful":
                    client.process.stdin.close()
                else:
                    client.exercise()
                    if name == "breakaway":
                        result = json.loads(client.out.frames.get(timeout=8))
                        require(result.get("id") == 4 and result.get("result") == {
                            "content": [{"type": "text", "text": "SOU96_BREAKAWAY_REFUSED"}]}, "breakaway_result_missing")
                        client.read(5)
                        client.process.stdin.close()
                    if name in {"cancel", "collector-death"}:
                        time.sleep(.4)
                        if name == "cancel":
                            client.send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 4}})
                        else:
                            client.process.kill()
            row = client.finish(expected_failure)
            report["cases"].append(row)
            save(root / "results.json", report)
            try:
                grade(row)
                peer_read_id += 1
                peer.read(peer_read_id)
                row["sibling_useful"] = True
            except Exception as error:
                row["passed"], row["failure_code"] = False, str(error) if isinstance(error, ValueError) else type(error).__name__
            save(root / "results.json", report)
        peer.process.stdin.close()
        sibling = peer.finish(False)
        report["sibling"] = sibling
        require(sibling["passed"] and sibling["useful"], "sibling_cleanup_failed")
        require(len(report["cases"]) == len(CASES) and all(row["passed"] and row.get("sibling_useful") for row in report["cases"]), "acceptance_failed")
        report["status"], report["not_run"] = "pass", []
        grade_report(report)
    except Exception as error:
        report["status"], report["error"] = "fail", str(error) if isinstance(error, ValueError) else type(error).__name__
    finally:
        if rig:
            # A private fallback cannot repair a failed row or earn a pass.
            for owned in rig.clients:
                if owned.poll() is None:
                    report["status"], report["error"] = "fail", "unfinished_owned_collector"
                    owned.kill()
                    owned.wait(5)
            report["daemon_capture"] = rig.close()
        report["not_run"] = [name for name in CASES if name not in {row["case"] for row in report["cases"]}]
        save(root / "results.json", report)
    return 0 if report["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--grade-report", type=Path)
    parser.add_argument("--agentfw", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-commit")
    parser.add_argument("--source-manifest", type=Path)
    args = parser.parse_args()
    if args.grade_report and not args.run:
        require(args.grade_report.stat().st_size <= 2 * 1024**2, "report_bound")
        grade_report(json.loads(args.grade_report.read_bytes()))
        print("complete_windows_budget_report_passed")
        return 0
    if not args.run or args.grade_report:
        parser.error("execution requires --run")
    if not all((args.agentfw, args.output, args.source_commit, args.source_manifest)):
        parser.error("execution requires binary, output and exact source identities")
    if os.name != "nt":
        print("native_windows_required", file=sys.stderr)
        return 2
    return run(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        # Startup failures may precede results.json. Retain a bounded, sanitized
        # exception identity; never publish traceback source lines or arguments.
        import traceback
        frames = traceback.extract_tb(error.__traceback__)[-6:]
        diagnostic = {"format": "sou96-windows-budget-bootstrap/1", "status": "fail",
                      "exception_type": type(error).__name__, "errno": getattr(error, "errno", None),
                      "winerror": getattr(error, "winerror", None),
                      "frames": [{"function": frame.name, "line": frame.lineno} for frame in frames]}
        if "--run" in sys.argv and "--output" in sys.argv:
            destination = Path(sys.argv[sys.argv.index("--output") + 1])
            destination.mkdir(parents=True, exist_ok=True)
            save(destination / "bootstrap.json", diagnostic)
        print(json.dumps(diagnostic), file=sys.stderr)
        raise SystemExit(1)
