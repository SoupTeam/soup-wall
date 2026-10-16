#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-48 real-process acceptance for native MCP Ask approval (Linux/macOS).

Runs the real `agentfw serve` daemon, the real `agentfw mcp --native-admission`
collector, a disposable fixture MCP server, and an independent HTTP receiver that
the fixture server calls when (and only when) it executes `delete_note`. The
operator side is the real `agentfw native-approval` CLI. Nothing here is a
model, dataset, or generalization claim; it demonstrates the control flow.

Usage: native-approval-acceptance.py --binary target/debug/agentfw --out DIR
Writes DIR/native-approval-acceptance.json and prints a short summary.
"""
import argparse
import hashlib
import http.server
import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

SERVER = r'''
import json, sys, urllib.request
ledger, receiver = sys.argv[1], sys.argv[2]
S = {
 'read_document': {'type':'object','properties':{},'additionalProperties':False},
 'delete_note': {'type':'object','properties':{'name':{'type':'string'}},'required':['name'],'additionalProperties':False},
 'grant_admin': {'type':'object','properties':{'name':{'type':'string'}},'required':['name'],'additionalProperties':False},
}
for raw in sys.stdin:
    req = json.loads(raw); m = req.get('method')
    if m == 'initialize':
        out = {'jsonrpc':'2.0','id':req['id'],'result':{'protocolVersion':'2024-11-05','capabilities':{'tools':{}},'serverInfo':{'name':'fixture','version':'1'}}}
    elif m == 'tools/list':
        out = {'jsonrpc':'2.0','id':req['id'],'result':{'tools':[{'name':n,'inputSchema':s} for n,s in S.items()]}}
    elif m == 'tools/call':
        with open(ledger,'a',encoding='utf-8',newline='') as f: f.write(raw)
        name = req['params']['name']
        if name in ('delete_note','grant_admin'):
            body = json.dumps({'tool':name,'arguments':req['params'].get('arguments')}).encode()
            urllib.request.urlopen(urllib.request.Request(receiver, data=body, method='POST'), timeout=5).read()
        out = {'jsonrpc':'2.0','id':req['id'],'result':{'content':[{'type':'text','text':'ok '+name}]}}
    else:
        continue
    print(json.dumps(out, separators=(',',':')), flush=True)
'''

POLICY = (
    "agent_policies:\n"
    "  - name: fixture-destructive-confirmation\n    when: { action_class: destructive }\n    action: ask\n"
    "  - name: fixture-privilege-deny\n    when: { action_class: privilege_changing }\n    action: deny\n"
    "default: allow\n"
)

DELETE = '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"delete_note","arguments":{"name":"inventory"},"_meta":{"claudecode/toolUseId":"toolu_demo","progressToken":0}}}'
READ = '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_document","arguments":{}}}'
ADMIN = '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"grant_admin","arguments":{"name":"root"}}}'


def sha(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode()).hexdigest()


def schema_sha(schema):
    return sha(json.dumps(schema, sort_keys=True, separators=(",", ":")))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Receiver:
    def __init__(self):
        self.hits = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("content-length", 0))
                outer.hits.append(json.loads(self.rfile.read(n)))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


class Rig:
    def __init__(self, binary, root, approval, wait, ttl=60):
        self.binary, self.root = binary, root
        self.home = os.path.join(root, ".agentfw")
        os.makedirs(self.home, exist_ok=True)
        self.port = free_port()
        self.receiver = Receiver()
        self.ledger = os.path.join(root, "executed.jsonl")
        self.wait = wait if approval else 0
        read = {"type": "object", "properties": {}, "additionalProperties": False}
        name = {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"], "additionalProperties": False}
        registry = {"contract_version": "sw-native/1", "registry_id": "sou48-acceptance", "tools": [
            {"name": "read_document", "schema_sha256": schema_sha(read), "action_class": "read_only", "result_provenance": "local_system", "egress": []},
            {"name": "delete_note", "schema_sha256": schema_sha(name), "action_class": "destructive", "result_provenance": "local_system", "egress": []},
            {"name": "grant_admin", "schema_sha256": schema_sha(name), "action_class": "privilege_changing", "result_provenance": "local_system", "egress": []},
        ]}
        reg_bytes = json.dumps(registry).encode()
        self.registry_sha = sha(reg_bytes)
        reg_path = os.path.join(root, "registry.json")
        open(reg_path, "wb").write(reg_bytes)
        policy_path = os.path.join(root, "policy.yaml")
        open(policy_path, "w").write(POLICY)
        cfg = f"port: {self.port}\nenforce: true\npolicy: '{policy_path}'\nnative:\n  registry_path: '{reg_path}'\n  registry_sha256: '{self.registry_sha}'\n"
        if approval:
            cfg += f"  approval:\n    ttl_seconds: {ttl}\n"
        self.config_text = cfg
        open(os.path.join(self.home, "config.yaml"), "w").write(cfg)
        open(os.path.join(root, "server.py"), "w").write(SERVER)
        self.env = dict(os.environ, HOME=root)
        self.daemon = None
        self.gateway = None

    def start_daemon(self):
        self.daemon_log = open(os.path.join(self.root, "daemon.log"), "ab")
        self.daemon = subprocess.Popen([self.binary, "serve"], env=self.env, stdout=self.daemon_log, stderr=self.daemon_log)
        for _ in range(1200):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("daemon did not start: " + open(os.path.join(self.root, "daemon.log"), errors="replace").read()[-800:])

    def stop_daemon(self):
        if self.daemon:
            self.daemon.terminate()
            self.daemon.wait(10)
            self.daemon = None

    def start_gateway(self):
        args = [self.binary, "mcp", "--native-admission"]
        if self.wait:
            args += ["--native-approval-wait-seconds", str(self.wait)]
        args += ["--id", "fixture", "--", sys.executable, "-I", "-u", os.path.join(self.root, "server.py"), self.ledger, f"http://127.0.0.1:{self.receiver.port}/"]
        self.gateway = subprocess.Popen(args, env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.lines = queue.Queue()
        threading.Thread(target=lambda: [self.lines.put(l) for l in self.gateway.stdout], daemon=True).start()
        self.exchange('{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}')
        self.exchange('{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}')

    def send(self, frame):
        self.gateway.stdin.write(frame + "\n")
        self.gateway.stdin.flush()

    def recv(self, timeout=15):
        try:
            return json.loads(self.lines.get(timeout=timeout))
        except queue.Empty:
            return None

    def exchange(self, frame, timeout=15):
        self.send(frame)
        return self.recv(timeout)

    def cli(self, *args):
        p = subprocess.run([self.binary, "native-approval", *args], env=self.env, capture_output=True, text=True)
        return p.returncode, p.stdout, p.stderr

    def pending(self, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            code, out, _ = self.cli("list")
            rows = json.loads(out) if code == 0 and out.strip() else []
            if rows:
                return rows
            time.sleep(0.1)
        return []

    def executed(self):
        try:
            return open(self.ledger, encoding="utf-8", newline="").read().splitlines()
        except FileNotFoundError:
            return []

    def witnesses(self):
        return {"child_calls": len(self.executed()), "receiver_hits": len(self.receiver.hits)}

    def close(self):
        if self.gateway and self.gateway.poll() is None:
            self.gateway.kill()
        self.stop_daemon()


def text(reply):
    return json.dumps(reply)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    binary = os.path.abspath(a.binary)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(a.out, exist_ok=True)
    results, checks = [], []

    def check(name, ok, **detail):
        checks.append(ok)
        results.append({"control": name, "passed": bool(ok), **detail})
        print(("PASS " if ok else "FAIL ") + name)

    tmp = tempfile.mkdtemp(prefix="sou48-")
    try:
        # 1. positive: zero effects before approval; one approval -> one original call.
        r = Rig(binary, os.path.join(tmp, "positive"), True, 30)
        r.start_daemon(); r.start_gateway()
        r.send(DELETE)
        rows = r.pending()
        before = r.witnesses()
        code, out, _ = r.cli("inspect", rows[0]["pending_id"])
        binding = rows[0]["binding_sha256"]
        check("zero_effects_before_approval", len(rows) == 1 and before == {"child_calls": 0, "receiver_hits": 0}, witnesses=before, pending_id=rows[0]["pending_id"], binding_sha256=binding)
        wrong = r.cli("approve", rows[0]["pending_id"], "--binding", "0" * 64)
        check("approval_with_wrong_digest_refused", wrong[0] != 0 and r.witnesses() == before)
        ok = r.cli("approve", rows[0]["pending_id"], "--binding", binding)
        reply = r.recv()
        after = r.witnesses()
        check("one_correct_approval_one_original_invocation",
              ok[0] == 0 and reply and reply.get("id") == 3 and "ok delete_note" in text(reply)
              and after == {"child_calls": 1, "receiver_hits": 1}
              and r.executed()[0] + "\n" == DELETE + "\n"
              and r.receiver.hits[0] == {"tool": "delete_note", "arguments": {"name": "inventory"}},
              witnesses=after, released_reply=reply, child_received_original_bytes=r.executed()[0] == DELETE)
        again = r.cli("approve", rows[0]["pending_id"], "--binding", binding)
        check("replay_of_spent_approval_refused", again[0] != 0 and r.witnesses() == after)
        cont = r.exchange(READ)
        check("normal_continuation_after_approved_call", cont and "ok read_document" in text(cont) and r.witnesses()["child_calls"] == 2, reply=cont)
        audit = open(os.path.join(r.home, "audit.jsonl")).read()
        check("audit_has_ids_and_digests_not_arguments", "native_approval_requested" in audit and binding in audit and "inventory" not in audit)
        r.close()

        # 2. reject
        r = Rig(binary, os.path.join(tmp, "reject"), True, 30)
        r.start_daemon(); r.start_gateway()
        r.send(DELETE); rows = r.pending()
        r.cli("reject", rows[0]["pending_id"])
        reply = r.recv()
        check("reject_runs_nothing", reply and "native_approval_rejected" in text(reply) and r.witnesses() == {"child_calls": 0, "receiver_hits": 0}, reply=reply)
        late = r.cli("approve", rows[0]["pending_id"], "--binding", rows[0]["binding_sha256"])
        check("approve_after_reject_refused", late[0] != 0 and r.witnesses()["child_calls"] == 0)
        r.close()

        # 3. timeout
        r = Rig(binary, os.path.join(tmp, "timeout"), True, 2)
        r.start_daemon(); r.start_gateway()
        reply = r.exchange(DELETE, timeout=20)
        check("timeout_runs_nothing", reply and "native_approval_timeout" in text(reply) and r.witnesses() == {"child_calls": 0, "receiver_hits": 0}, reply=reply)
        r.close()

        # 4. hard Deny is not rescued even with an operator available.
        r = Rig(binary, os.path.join(tmp, "deny"), True, 30)
        r.start_daemon(); r.start_gateway()
        reply = r.exchange(ADMIN)
        check("hard_deny_not_rescuable", reply and "isError" in text(reply) and not r.cli("list")[1].strip().strip("[]").strip() and r.witnesses() == {"child_calls": 0, "receiver_hits": 0}, reply=reply)
        r.close()

        # 5. concurrent client input closes the pending call.
        r = Rig(binary, os.path.join(tmp, "concurrent"), True, 30)
        r.start_daemon(); r.start_gateway()
        r.send(DELETE); rows = r.pending()
        r.send(READ)
        try:
            rc = r.gateway.wait(10)
        except subprocess.TimeoutExpired:
            rc = None
        late = r.cli("approve", rows[0]["pending_id"], "--binding", rows[0]["binding_sha256"])
        check("concurrent_input_closes_pending", rc not in (None, 0) and late[0] != 0 and r.witnesses() == {"child_calls": 0, "receiver_hits": 0}, gateway_exit=rc)
        r.close()

        # 6. daemon restart cannot rescue.
        r = Rig(binary, os.path.join(tmp, "restart"), True, 30)
        r.start_daemon(); r.start_gateway()
        r.send(DELETE); rows = r.pending()
        r.stop_daemon(); r.start_daemon()
        late = r.cli("approve", rows[0]["pending_id"], "--binding", rows[0]["binding_sha256"])
        reply = r.recv()
        check("restart_cannot_be_rescued", late[0] != 0 and r.witnesses() == {"child_calls": 0, "receiver_hits": 0}, reply=reply)
        r.close()

        # 7. default config (no approval section, no wait flag): current refusal.
        r = Rig(binary, os.path.join(tmp, "default"), False, 0)
        r.start_daemon(); r.start_gateway()
        reply = r.exchange(DELETE)
        listing = r.cli("list")
        check("default_config_keeps_refusal", reply and "isError" in text(reply) and "fixture-destructive-confirmation" in text(reply) and r.witnesses() == {"child_calls": 0, "receiver_hits": 0} and listing[1].strip() in ("", "[]"), reply=reply)
        r.close()
        identities = {
            "binary_sha256": sha(open(binary, "rb").read()),
            "registry_sha256": r.registry_sha,
            "config_sha256_default": sha(r.config_text),
            "source_sha256": {
                rel: sha(open(os.path.join(root, rel), "rb").read().replace(b"\r\n", b"\n"))
                for rel in (
                    "crates/agentfw/src/native/approval.rs",
                    "crates/agentfw/src/native.rs",
                    "crates/agentfw/src/mcp/admission.rs",
                    "crates/agentfw/src/main.rs",
                    "crates/agentfw/src/grant.rs",
                )
            },
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=root).stdout.strip()
    evidence = {"contract": "sou48-acceptance/1", "base_git_head": commit, "identities": identities,
                "passed": all(checks), "controls": results,
                "note": "Control-flow demonstration with a disposable fixture; no model, dataset or generalization claim."}
    path = os.path.join(a.out, "native-approval-acceptance.json")
    open(path, "w").write(json.dumps(evidence, indent=2) + "\n")
    print(f"{sum(checks)}/{len(checks)} controls passed -> {path}")
    sys.exit(0 if all(checks) else 1)


if __name__ == "__main__":
    main()
