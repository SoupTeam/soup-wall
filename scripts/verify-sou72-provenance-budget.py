#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Owned Linux provenance-budget acceptance through the production native/MCP path.

Only --run executes processes. Prerequisite failures never become skips. The
fixture owns synthetic data and disposable publication files; no live model,
external service or private dataset is used. Charged retention and sampled RSS
are different measurements.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sou72_runtime_helpers", ROOT / "scripts/verify-sou62-real-mcp.py")
BASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASE)
CONTRACT = "sw-native/1"
FORMAT = "sou72-provenance-budget/1"
EARLY = "/owned/reference-000017.txt"
USEFUL = "Inventory: 7 red widgets. Caf\u00e9, \u049b\u0430\u0437\u0430\u049b\u0448\u0430, \u65e5\u672c\u8a9e, \U0001f963."
LIMITS = {"per_session_bytes": 65536, "total_bytes": 262144, "max_sessions": 8,
    "max_input_bytes": 32768, "max_source_bytes": 128, "max_literal_bytes": 1024, "max_session_id_bytes": 128}
CHECKS = {"calibrated-independent-publication", "below-budget-useful-work", "duplicate-accounting-stable",
    "per-session-plateau-and-early-reuse-ask", "unrecordable-result-withheld", "single-use-approval-stays-incomplete",
    "useful-continuation-and-hard-deny", "global-budget-plateau", "session-capacity-recovery",
    "shared-history-survives-child-exit-and-reconnect", "failed-and-cancelled-outcomes", "owned-cleanup", "exact-source-and-limits"}
SECRETS = []

PAYLOAD_SOURCE = r'''
EARLY = "/owned/reference-000017.txt"
USEFUL = "Inventory: 7 red widgets. Caf\u00e9, \u049b\u0430\u0437\u0430\u049b\u0448\u0430, \u65e5\u672c\u8a9e, \U0001f963."
def payload(case, index=0):
    if case == 'early': return 'Owned synthetic reference: '+EARLY+'. Review the inventory record before publishing.'
    if case == 'useful': return USEFUL
    if case == 'duplicate': return 'Owned repeated reference /owned/duplicate-000091.txt with the same inventory information.'
    if case == 'oversized': return 'UNTRACKABLE-OWNED-RESULT https://owned.invalid/'+('\u00e9'*1100)+'/note'
    if case == 'load':
        return ' '.join('https://h%04d%03d.invalid/x'%(index,n) for n in range(16))
    if case == 'failed': return 'Owned failure reference /owned/failed-000042.txt'
    if case == 'gated': return 'CANCELLED-OWNED-RESULT /owned/cancelled-000043.txt'
    raise ValueError('unknown owned case')
'''
exec(compile(PAYLOAD_SOURCE, "<owned-payload>", "exec"))

SCHEMAS = {
    "read_metadata": {"type": "object", "properties": {"case": {"type": "string"}, "index": {"type": "integer"}}, "required": ["case"], "additionalProperties": False},
    "publish_note": {"type": "object", "properties": {"name": {"type": "string"}, "note": {"type": "string"}}, "required": ["name", "note"], "additionalProperties": False},
    "grant_admin": {"type": "object", "properties": {}, "additionalProperties": False},
}
SERVER = PAYLOAD_SOURCE + r'''
import json, os, re, sys, time
from pathlib import Path
root = Path(sys.argv[1])
schemas = json.loads(sys.argv[2])
for raw in sys.stdin:
    request = json.loads(raw)
    method = request.get('method')
    if method == 'initialize':
        reply = {'jsonrpc':'2.0','id':request['id'],'result':{'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'sou72-owned','version':'1'}}}
    elif method == 'tools/list':
        reply = {'jsonrpc':'2.0','id':request['id'],'result':{'tools':[{'name':name,'inputSchema':schema} for name,schema in schemas.items()]}}
    elif method == 'tools/call':
        name, args = request['params']['name'], request['params'].get('arguments', {})
        with (root/'executed.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'id':request['id'],'tool':name,'args':args}, separators=(',',':'))+'\n')
        if name == 'read_metadata':
            case = args['case']
            if case == 'gated':
                (root/'gated-started').write_text('ready')
                deadline = time.monotonic()+20
                while not (root/'release-gated').exists():
                    if time.monotonic() >= deadline: raise TimeoutError('owned result barrier timed out')
                    time.sleep(0.01)
            if case == 'failed':
                reply = {'jsonrpc':'2.0','id':request['id'],'error':{'code':-32603,'message':payload(case)}}
            else:
                reply = {'jsonrpc':'2.0','id':request['id'],'result':{'content':[{'type':'text','text':payload(case,args.get('index',0))}]}}
        elif name == 'publish_note':
            if not re.fullmatch(r'[a-z0-9-]{1,64}', args['name']): raise ValueError('invalid owned publication leaf')
            with (root/'published'/args['name']).open('xb') as stream:
                stream.write(args['note'].encode('utf-8')); stream.flush(); os.fsync(stream.fileno())
            reply = {'jsonrpc':'2.0','id':request['id'],'result':{'content':[{'type':'text','text':'Owned note published.'}]}}
        elif name == 'grant_admin':
            (root/'unexpected-admin').write_text('unexpected execution')
            reply = {'jsonrpc':'2.0','id':request['id'],'result':{'content':[{'type':'text','text':'unexpected'}]}}
        else: raise ValueError('unknown owned tool')
    else: continue
    print(json.dumps(reply,ensure_ascii=False,separators=(',',':')), flush=True)
'''
POLICY = "agent_policies:\n  - name: owned-hard-deny\n    when: {action_class: privilege_changing}\n    action: deny\ndefault: allow\n"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def digest(value):
    return sha_bytes(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode())


def redact(value):
    value = str(value)
    for secret in SECRETS:
        if secret:
            value = value.replace(secret, "[REDACTED]")
    return value


def write(path, value):
    path.write_text(redact(json.dumps(value, indent=2, ensure_ascii=False)) + "\n", encoding="utf-8")
    path.chmod(0o600)


def evidence_reply(reply, raw):
    return {"id": reply.get("id"), "refused": refused(reply), "rpc_error": "error" in reply,
        "bytes": len(raw), "sha256": sha_bytes(raw)}


def refused(reply):
    return reply.get("result", {}).get("isError") is True


def result_text(reply):
    return "".join(block.get("text", "") for block in reply.get("result", {}).get("content", []))


def publication(root, name):
    path = root / "published" / name
    if not path.exists():
        return {"exists": False, "bytes": 0}
    info = path.lstat()
    require(path.is_file() and not path.is_symlink() and info.st_nlink == 1, "publication witness is not an owned regular file")
    data = path.read_bytes()
    return {"exists": True, "bytes": len(data), "sha256": sha_bytes(data), "inode": info.st_ino}


def bounded_usage(sample, limits):
    require(sample["accounting_revision"] == "sw-provenance-storage/1", "unsupported provenance accounting revision")
    require(sample["limits"] == limits, "runtime effective provenance limits differ from configuration")
    usage = sample["usage"]
    for name in ("retained_bytes", "max_session_retained_bytes", "sessions", "incomplete_sessions", "fingerprints", "literals"):
        require(type(usage[name]) is int and usage[name] >= 0, "missing or invalid charged accounting")
    require(usage["retained_bytes"] <= limits["total_bytes"] and usage["max_session_retained_bytes"] <= limits["per_session_bytes"]
        and usage["sessions"] <= limits["max_sessions"] and usage["incomplete_sessions"] <= usage["sessions"], "retained provenance exceeded a declared bound")


class RSS:
    """Bounded owned Linux observations, never used as retained-byte proof."""
    def __init__(self, pid):
        self.pid, self.samples, self.stop_event = pid, [], threading.Event()
        def sample():
            while not self.stop_event.is_set():
                try:
                    text = Path(f"/proc/{pid}/status").read_text()
                    match = re.search(r"^VmRSS:\s+(\d+) kB$", text, re.M)
                    if match and len(self.samples) < 2048:
                        self.samples.append({"at_monotonic": round(time.monotonic(), 3), "rss_bytes": int(match.group(1))*1024})
                except OSError:
                    pass
                self.stop_event.wait(0.05)
        self.thread = threading.Thread(target=sample, daemon=True)
        self.thread.start()

    def finish(self):
        self.stop_event.set(); self.thread.join(timeout=2)
        return {"kind": "sampled_process_rss_not_tracker_budget", "pid": self.pid, "samples": self.samples,
            "sample_count": len(self.samples), "max_rss_bytes": max((row["rss_bytes"] for row in self.samples), default=None)}


class Client(BASE.Client):
    def __init__(self, rig, name, wait=0, host=None, proof=None):
        self.root = rig.private / name
        self.root.mkdir(mode=0o700)
        (self.root / "published").mkdir(mode=0o700)
        env = dict(rig.env)
        if host is not None:
            env.update(AGENTFW_HOST_SESSION=host, AGENTFW_CHILD_AUTHORITY=proof)
        command = [str(rig.binary), "mcp", "--native-admission", "--id", name]
        if wait:
            command += ["--native-approval-wait-seconds", str(wait)]
        command += ["--", sys.executable, "-I", "-u", str(rig.server), str(self.root), json.dumps(SCHEMAS)]
        log = (rig.output / (name+"-collector.log")).open("wb")
        rig.logs.append(log)
        super().__init__(command, env, rig.private, log, name)
        self.rss = RSS(self.process.pid)
        self.next_id = 3
        rig.clients.append(self)

    def call(self, tool, arguments):
        identifier = self.next_id
        self.next_id += 1
        return {"jsonrpc":"2.0", "id":identifier, "method":"tools/call", "params":{"name":tool,"arguments":arguments}}

    def read(self, case="useful", index=0):
        return self.exchange(self.call("read_metadata", {"case":case,"index":index}))

    def publication_calls(self):
        path = self.root / "executed.jsonl"
        return sum(json.loads(line).get("tool") == "publish_note" for line in path.read_text().splitlines()) if path.exists() else 0

    def audit_call(self, rig, identifier):
        rows = [row for row in rig.audit() if row.get("event") == "native_call" and row.get("tool") == "publish_note"]
        require(rows, "publication native audit missing")
        return rows[-1]

    def close(self):
        result = super().close()
        if not hasattr(self, "rss_report"):
            self.rss_report = self.rss.finish()
        return result


class Rig:
    def __init__(self, binary, output, name, limits=None, approval=False):
        self.binary, self.output = binary, output
        self.temporary = tempfile.TemporaryDirectory(prefix="sou72-"+name+"-")
        self.private = Path(self.temporary.name).resolve()
        self.home = self.private / "home"
        self.home.mkdir(mode=0o700)
        self.env = BASE.environment(self.home)
        self.clients, self.logs, self.samples = [], [], []
        self.limits = dict(limits or LIMITS)
        self.server = self.private / "server.py"
        self.server.write_text(SERVER, encoding="utf-8")
        install = subprocess.run([str(binary), "install"], env=self.env, capture_output=True, timeout=30)
        require(install.returncode == 0, "private Agent bootstrap failed")
        registry = {"contract_version": CONTRACT, "registry_id": "sou72-owned", "tools": [
            {"name": name, "schema_sha256": digest(schema), "action_class": action, "result_provenance": provenance, "egress": []}
            for (name,schema),action,provenance in zip(SCHEMAS.items(), ("read_only","side_effecting","privilege_changing"), ("untrusted","local_system","local_system"))]}
        self.registry = self.private / "registry.json"
        write(self.registry, registry)
        self.registry_sha = BASE.sha(self.registry)
        policy = self.private / "policy.yaml"
        policy.write_text(POLICY, encoding="utf-8")
        self.port = BASE.DEMO.free_port()
        native = {"registry_path": str(self.registry), "registry_sha256":self.registry_sha}
        if approval:
            native["approval"] = {"ttl_seconds":60}
        self.config = {"port":self.port,"enforce":True,"policy":str(policy),"native":native,"provenance":self.limits}
        write(self.home / ".agentfw/config.yaml", self.config)
        self.config_sha = BASE.sha(self.home / ".agentfw/config.yaml")
        log = (output / (name+"-daemon.log")).open("wb")
        self.logs.append(log)
        self.daemon = subprocess.Popen([str(binary), "serve"], env=self.env, stdout=log, stderr=log)
        self.process_witness = BASE.ProcessWitness(self.daemon.pid)
        self.rss = RSS(self.daemon.pid)
        try:
            require(BASE.DEMO.wait_healthy(self.port, self.daemon), "owned enforcing daemon unavailable")
            self.native_token = (self.home/".agentfw/native-token").read_text().strip()
            SECRETS.extend((self.native_token, (self.home/".agentfw/token").read_text().strip()))
            self.sample()
        except Exception:
            BASE.DEMO.stop(self.daemon)
            self.daemon.wait(timeout=10)
            self.process_witness.finish(); self.rss.finish()
            for owned_log in self.logs:
                owned_log.close()
            self.temporary.cleanup()
            raise

    def http(self):
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}/native/v1/instance", headers={"Authorization":"Bearer "+self.native_token})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=10) as response:
            raw = response.read(131073)
        require(len(raw) <= 131072, "unbounded native diagnostics")
        value = json.loads(raw)
        require(value["registry_sha256"] == self.registry_sha, "native diagnostics registry mismatch")
        return value

    def sample(self):
        sample = self.http()["provenance"]
        bounded_usage(sample, self.limits)
        require(len(self.samples) < 256, "bounded accounting sample storage exhausted")
        self.samples.append(sample)
        return sample

    def audit(self):
        path = self.home / ".agentfw/audit.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def cli(self, *arguments):
        return subprocess.run([str(self.binary), "native-approval", *arguments], env=self.env, capture_output=True, timeout=15)

    def pending(self, client=None):
        deadline = time.monotonic()+5
        while time.monotonic() < deadline:
            if client is not None and not client.lines.empty():
                raw = client.lines.get_nowait()
                if raw is not None:
                    client.received.append(raw)
                    raise ValueError("approval replaced by correlated response: "+redact(raw.decode(errors="replace"))[:1000])
                raise ValueError("collector closed before pending approval")
            result = self.cli("list")
            rows = json.loads(result.stdout) if result.returncode == 0 and result.stdout.strip() else []
            if rows:
                return rows
            time.sleep(0.025)
        raise ValueError("native Ask did not create pending approval")

    def mint(self, host, server, agent):
        instance = self.http()
        result = subprocess.run([str(self.binary), "child-authority", "mint", "--session", host, "--server", server,
            "--agent-id", agent, "--instance-id", instance["instance_id"], "--tools", ",".join(SCHEMAS), "--ttl-seconds", "300"],
            env=self.env, capture_output=True, timeout=15)
        require(result.returncode == 0, "scoped authority mint failed")
        proof = result.stdout.decode().strip()
        SECRETS.append(proof)
        return proof

    def close(self):
        for client in reversed(self.clients):
            client.close()
        BASE.DEMO.stop(self.daemon)
        self.daemon.wait(timeout=10)
        cleanup = {"daemon_stopped":self.daemon.poll() is not None,"daemon":self.process_witness.finish(),
            "clients":[{"exit_code":client.process.returncode,"process_cleanup":client.process_witness.finish()} for client in self.clients]}
        transcripts = [{"label":client.label,**client.transcript()} for client in self.clients]
        audit = self.audit()
        for log in self.logs:
            log.close()
        self.temporary.cleanup()
        require(len(audit) <= 2048 and len(json.dumps(audit).encode()) <= 2*1024*1024, "owned audit evidence exceeds bounded storage")
        require(len(transcripts) <= 8 and len(json.dumps(transcripts).encode()) <= 2*1024*1024, "owned client evidence exceeds bounded storage")
        result = {"client_transcripts":transcripts,"client_transcripts_sha256":digest(transcripts),
            "owned_native_audit":audit,"owned_native_audit_sha256":digest(audit),
            "limits":self.limits,"config_sha256":self.config_sha,"registry_sha256":self.registry_sha,
            "policy_sha256":sha_bytes(POLICY.encode()),"samples":self.samples,"rss":{"daemon":self.rss.finish(),
            "collectors":[client.rss_report for client in self.clients]},"cleanup":cleanup}
        result["cleanup"]["private_profile_removed"] = not self.private.exists()
        result["cleanup"]["all_stopped"] = cleanup["daemon"]["all_stopped"] and all(row["process_cleanup"]["all_stopped"] for row in cleanup["clients"])
        return result


def ask(rig, client, name, approve=False):
    before = publication(client.root, name)
    calls_before = client.publication_calls()
    require(before["exists"] is False, "owned Ask destination already exists")
    request = client.call("publish_note", {"name":name,"note":EARLY})
    client.send(request)
    pending = rig.pending(client)
    require(len(pending) == 1, "exactly one native pending call required")
    no_effect = publication(client.root,name) == before
    row = pending[0]
    command = ("approve",row["pending_id"],"--binding",row["binding_sha256"]) if approve else ("reject",row["pending_id"])
    result = rig.cli(*command)
    require(result.returncode == 0, "operator approval/rejection failed")
    reply, raw = client.receive()
    require(reply["id"] == request["id"], "Ask response correlation changed")
    native = client.audit_call(rig, request["id"])
    return {"no_effect_before_decision":no_effect,"before":before,"after":publication(client.root,name),
        "reply":evidence_reply(reply,raw),"rule":native.get("rule"),"incomplete":native.get("provenance_incomplete") is True,"taint_present":native.get("taint") is not None,
        "backend_calls_before":calls_before,"backend_calls_after":client.publication_calls(),
        "pending_id":row["pending_id"],"binding_sha256":row["binding_sha256"]}


def pressure(rig, client, count=40):
    admitted, refused_count = 0, 0
    for index in range(count):
        reply, _ = client.read("load", index)
        if refused(reply):
            refused_count += 1
            require("native_provenance_unrecordable" in result_text(reply), "unexpected pressure refusal")
        else:
            require(result_text(reply) == payload("load",index), "admitted pressure result changed")
            admitted += 1
        if index % 4 == 0 or index == count-1:
            rig.sample()
    return {"attempted":count,"admitted":admitted,"refused":refused_count}


def primary(rig, report):
    client = Client(rig,"primary",wait=8)
    client.initialize()
    reply,_ = client.read("early")
    require(result_text(reply) == payload("early"), "below-budget early read failed")
    reply,raw = client.exchange(client.call("publish_note",{"name":"calibration","note":EARLY}))
    calibrated = publication(client.root,"calibration")
    native = client.audit_call(rig,reply["id"])
    report["calibration"] = {"reply":evidence_reply(reply,raw),"file":calibrated,"expected_sha256":sha_bytes(EARLY.encode()),
        "early_taint_present":native.get("taint") is not None,"native_allow":native.get("released") is True,"binding_sha256":native.get("binding_sha256")}
    reply,_ = client.read("duplicate")
    require(result_text(reply) == payload("duplicate"), "duplicate positive result missing")
    before = rig.sample()["usage"]["retained_bytes"]
    for _ in range(8):
        reply,_ = client.read("duplicate")
        require(result_text(reply) == payload("duplicate"), "duplicate result changed")
    report["duplicate"] = {"before":before,"after":rig.sample()["usage"]["retained_bytes"],"repetitions":8}
    report["pressure"] = pressure(rig,client)
    report["early_refusal"] = ask(rig,client,"without-approval")
    reply,raw = client.read("oversized")
    report["unrecordable"] = {"reply":evidence_reply(reply,raw),"reason_present":"native_provenance_unrecordable" in result_text(reply),
        "original_marker_absent":b"UNTRACKABLE-OWNED-RESULT" not in raw,"declared_payload_bytes":len(payload("oversized").encode())}
    report["approved"] = ask(rig,client,"approved-once",approve=True)
    approved = report["approved"]
    report["approval_replay_refused"] = rig.cli("approve",approved["pending_id"],"--binding",approved["binding_sha256"]).returncode != 0
    report["after_approval_refusal"] = ask(rig,client,"after-approval")
    reply,raw = client.read()
    report["continuation"] = {"reply":evidence_reply(reply,raw),"useful":result_text(reply) == USEFUL}
    reply,raw = client.exchange(client.call("grant_admin",{}))
    report["hard_deny"] = {"reply":evidence_reply(reply,raw),"rule_present":"owned-hard-deny" in result_text(reply),
        "effect_absent":not (client.root/"unexpected-admin").exists(),"pending_empty":json.loads(rig.cli("list").stdout or b"[]") == []}
    peer = Client(rig,"peer")
    peer.initialize()
    reply,raw = peer.exchange(peer.call("publish_note",{"name":"peer-useful","note":"Owned independent session."}))
    report["peer"] = {"reply":evidence_reply(reply,raw),"file":publication(peer.root,"peer-useful")}
    reply,raw = client.read("failed")
    report["rpc_failure"] = {"reply":evidence_reply(reply,raw),"original_error_delivered":"error" in reply and reply["error"].get("message") == payload("failed")}
    rig.sample()
    gated = client.call("read_metadata",{"case":"gated","index":0})
    client.send(gated)
    deadline = time.monotonic()+5
    while not (client.root/"gated-started").exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    require((client.root/"gated-started").exists(), "owned cancellation execution barrier not reached")
    client.send({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":gated["id"]}})
    client.process.wait(timeout=10)
    client.close()
    trailing_output = []
    while True:
        try:
            raw = client.lines.get_nowait()
        except queue.Empty:
            break
        if raw is not None:
            trailing_output.append(raw)
    all_output = client.received + trailing_output
    client.received = all_output
    report["cancelled"] = {"call_was_dispatched":True,"collector_exit_code":client.process.returncode,
        "original_marker_absent":all(b"CANCELLED-OWNED-RESULT" not in raw for raw in all_output),
        "client_output_sha256":sha_bytes(b"".join(all_output)),"trailing_frame_count":len(trailing_output),
        "published_file_absent":publication(client.root,"cancelled")["exists"] is False}


def capacity(rig, report):
    first,second = Client(rig,"capacity-a"),Client(rig,"capacity-b")
    first.initialize(); second.initialize()
    before = rig.sample()
    third = Client(rig,"capacity-refused")
    third.process.wait(timeout=10)
    refused_before_spawn = not (third.root/"executed.jsonl").exists()
    first.close()
    after_end = rig.sample()
    replacement = Client(rig,"capacity-replacement")
    replacement.initialize()
    reply,raw = replacement.read()
    report["capacity"] = {"before":before,"after_end":after_end,"refused_exit_code":third.process.returncode,
        "refused_no_execution":refused_before_spawn,"capacity_reason":"native_provenance_context_capacity" in (rig.output/"capacity-refused-collector.log").read_text(),"replacement_useful":result_text(reply) == USEFUL,"reply":evidence_reply(reply,raw)}


def shared(rig, report):
    host = str(uuid.uuid4())
    proof = rig.mint(host,"shared-a","agent-a")
    first = Client(rig,"shared-a",host=host,proof=proof)
    first.initialize(); first.read("early")
    load = pressure(rig,first,count=24)
    second_proof = rig.mint(host,"shared-b","agent-b")
    second = Client(rig,"shared-b",host=host,proof=second_proof)
    second.initialize()
    first.close()
    def attempt(client,name):
        reply,raw = client.exchange(client.call("publish_note",{"name":name,"note":EARLY}))
        return {"reply":evidence_reply(reply,raw),"ask_reason":"taint-history-incomplete" in result_text(reply),
            "effect_absent":not publication(client.root,name)["exists"]}
    after_exit = attempt(second,"after-child-exit")
    reconnect = Client(rig,"shared-a-reconnect",host=host,proof=rig.mint(host,"shared-a-reconnect","agent-a"))
    reconnect.initialize()
    after_reconnect = attempt(reconnect,"after-reconnect")
    report["shared"] = {"host_session":host,"proof_sha256":sha_bytes(proof.encode()),"pressure":load,
        "after_child_exit":after_exit,"after_reconnect":after_reconnect,"usage":rig.sample()}


def verify_process_cleanup(value):
    require(value["all_stopped"] is True and value["remaining"] == [] and value["observed"], "raw process cleanup witness missing")
    require(value["descendant_count"] == sum(row["parent_process"] is False for row in value["observed"]), "process descendant count differs from observations")
    for row in value["observed"]:
        require(type(row["pid"]) is int and row["pid"] > 0 and type(row["start_time_ticks"]) is int and row["start_time_ticks"] >= 0, "owned process identity missing")


def verify_owned_evidence(rig):
    audit,transcripts = rig["owned_native_audit"],rig["client_transcripts"]
    require(audit and transcripts and digest(audit) == rig["owned_native_audit_sha256"]
        and digest(transcripts) == rig["client_transcripts_sha256"], "owned original evidence hash mismatch")
    require(len(audit) <= 2048 and len(transcripts) <= 8 and len(json.dumps(audit).encode()) <= 2*1024*1024
        and len(json.dumps(transcripts).encode()) <= 2*1024*1024, "unbounded owned original evidence")
    labels = set()
    for transcript in transcripts:
        require(transcript["label"] not in labels, "duplicate owned client label")
        labels.add(transcript["label"])
        for direction in ("sent","received"):
            raw = b"".join(frame.encode() for frame in transcript[direction])
            require(sha_bytes(raw) == transcript[direction+"_sha256"], "owned original transcript hash mismatch")
            require(len(transcript[direction]) <= 256, "unbounded owned original transcript")
            for frame in transcript[direction]:
                json.loads(frame)
        verify_process_cleanup(transcript["process_cleanup"])
    return audit,{row["label"]:row for row in transcripts}


def verify_receipt(section, transcript):
    evidence = section["reply"]
    matches = [raw.encode() for raw in transcript["received"] if json.loads(raw).get("id") == evidence["id"]]
    require(len(matches) == 1, "critical response absent/ambiguous in original client output")
    raw = matches[0]
    require(evidence_reply(json.loads(raw),raw) == evidence, "critical response summary differs from original client bytes")


def grade(report):
    require(report["format"] == FORMAT and report["skipped"] == 0 and report["failed"] == 0, "required acceptance was skipped or has wrong format")
    require(report["source_before"] == report["source_after"] and not report["source_before"]["dirty"], "source changed or was dirty")
    for name in ("binary_sha256","driver_sha256","fixture_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}",report[name]) is not None, "exact artifact hash missing")
    require(report["binary_unchanged"] is True, "Agent binary changed")
    require(set(report["rigs"]) == {"primary","global","capacity","shared"}, "required runtime rig missing/extra")
    native_audit,clients = verify_owned_evidence(report["rigs"]["primary"])
    for name in ("calibration","early_refusal","unrecordable","approved","after_approval_refusal","continuation","hard_deny","rpc_failure"):
        verify_receipt(report[name],clients["primary"])
    for name in ("early_refusal","after_approval_refusal"):
        current = report[name]
        requests = [json.loads(raw) for raw in clients["primary"]["sent"] if json.loads(raw).get("id") == current["reply"]["id"]]
        require(len(requests) == 1 and requests[0].get("method") == "tools/call", "Ask original invocation missing")
        expected_args = digest(requests[0]["params"]["arguments"])
        paired = False
        for index,row in enumerate(native_audit):
            if row.get("event") != "native_approval_requested" or row.get("binding_sha256") != current["binding_sha256"]:
                continue
            previous = native_audit[index-1] if index else {}
            paired |= row.get("approval_id") == current["pending_id"] and row.get("args_sha256") == expected_args \
                and previous.get("event") == "native_call" and previous.get("session") == row.get("session") \
                and previous.get("tool") == row.get("tool") == "publish_note" \
                and previous.get("rule") == "taint-history-incomplete" and previous.get("provenance_incomplete") is True \
                and previous.get("released") is False
        require(paired, "Ask/approval binding chronology is absent from original native audit")
    require(any(row.get("event") == "native_result" and row.get("released") is False
        and "native_provenance_unrecordable" in row.get("reason_codes",[]) for row in native_audit), "unrecordable result absent from original audit")
    calibrated = report["calibration"]
    require(not calibrated["reply"]["refused"] and calibrated["native_allow"] and calibrated["early_taint_present"]
        and calibrated["file"]["exists"] and calibrated["file"]["sha256"] == calibrated["expected_sha256"], "independent useful execution calibration missing")
    require(report["duplicate"]["before"] == report["duplicate"]["after"] and report["duplicate"]["repetitions"] >= 8, "duplicate accounting grew")
    require(report["pressure"]["admitted"] >= 16, "insufficient admitted pressure")
    early = report["early_refusal"]
    require(early["no_effect_before_decision"] and early["reply"]["refused"] and not early["after"]["exists"]
        and early["rule"] == "taint-history-incomplete" and early["incomplete"] and not early["taint_present"]
        and early["backend_calls_before"] == early["backend_calls_after"], "early eviction was not witnessed as Ask with zero publication")
    overflow = report["unrecordable"]
    require(overflow["reply"]["refused"] and overflow["reason_present"] and overflow["original_marker_absent"], "unrecordable content reached client")
    approved = report["approved"]
    require(approved["no_effect_before_decision"] and not approved["reply"]["refused"] and approved["after"]["exists"]
        and approved["after"]["sha256"] == sha_bytes(EARLY.encode()) and report["approval_replay_refused"]
        and approved["backend_calls_after"] == approved["backend_calls_before"]+1, "single-use approval evidence missing")
    later = report["after_approval_refusal"]
    require(later["reply"]["refused"] and later["rule"] == "taint-history-incomplete" and later["incomplete"]
        and later["no_effect_before_decision"] and later["backend_calls_before"] == later["backend_calls_after"]
        and not later["after"]["exists"], "approval cleared incomplete history or allowed an unapproved effect")
    require(report["continuation"]["useful"] and not report["peer"]["reply"]["refused"] and report["peer"]["file"]["exists"], "useful continuation/isolation missing")
    require(all(report["hard_deny"][key] for key in ("rule_present","effect_absent","pending_empty")) and report["hard_deny"]["reply"]["refused"], "hard Deny was weakened")
    require(report["global_pressure"]["admitted"] >= 16 and len(report["rigs"]["global"]["samples"]) >= 8, "global stress evidence missing")
    c = report["capacity"]
    require(c["refused_exit_code"] not in (None,0) and c["refused_no_execution"] and c["capacity_reason"] and c["replacement_useful"]
        and c["after_end"]["usage"]["sessions"] < c["before"]["usage"]["sessions"], "legitimate end did not recover session capacity")
    for name in ("after_child_exit","after_reconnect"):
        row = report["shared"][name]
        require(row["reply"]["refused"] and row["ask_reason"] and row["effect_absent"], "shared history reset after lifecycle event")
    require(report["rpc_failure"]["original_error_delivered"] and report["cancelled"]["call_was_dispatched"]
        and report["cancelled"]["collector_exit_code"] not in (None,0) and report["cancelled"]["original_marker_absent"], "failed/cancelled outcomes missing")
    for name,rig in report["rigs"].items():
        expected = dict(LIMITS, **({"total_bytes":98304} if name == "global" else {"max_sessions":2} if name == "capacity" else {}))
        require(rig["limits"] == expected, "runtime rig limits differ from the declared procedure")
        for key in ("config_sha256","registry_sha256","policy_sha256"):
            require(re.fullmatch(r"[0-9a-f]{64}",rig[key]) is not None, "runtime configuration identity missing")
        require(rig["policy_sha256"] == sha_bytes(POLICY.encode()), "runtime policy differs from owned procedure")
        verify_owned_evidence(rig)
        verify_process_cleanup(rig["cleanup"]["daemon"])
        for process in rig["cleanup"]["clients"]:
            verify_process_cleanup(process["process_cleanup"])
        require(rig["samples"], "accounting samples missing")
        for sample in rig["samples"]:
            bounded_usage(sample,rig["limits"])
        require(rig["cleanup"]["all_stopped"] and rig["cleanup"]["daemon_stopped"] and rig["cleanup"]["private_profile_removed"], "owned cleanup incomplete")
        require(rig["rss"]["daemon"]["kind"] == "sampled_process_rss_not_tracker_budget" and rig["rss"]["daemon"]["sample_count"] > 0, "separate RSS observations missing")
    primary_samples = report["rigs"]["primary"]["samples"]
    require(any(sample["usage"]["incomplete_sessions"] > 0 for sample in primary_samples), "saturation was not observed")
    require(max(sample["usage"]["max_session_retained_bytes"] for sample in primary_samples) >= report["rigs"]["primary"]["limits"]["per_session_bytes"]//2, "per-session budget plateau was not reached")
    require(max(sample["usage"]["retained_bytes"] for sample in report["rigs"]["global"]["samples"]) >= report["rigs"]["global"]["limits"]["total_bytes"]//2, "global budget pressure was not reached")
    require(report["rigs"]["global"]["limits"]["total_bytes"] < 2*report["rigs"]["global"]["limits"]["per_session_bytes"], "global stress does not constrain combined sessions")
    report["checks"] = [{"case":name,"passed":True} for name in sorted(CHECKS)]


def run(args):
    require(platform.system() == "Linux", "required positive acceptance needs Linux procfs")
    binary,output = args.agentfw.resolve(),args.output.resolve()
    require(binary.is_file() and os.access(binary,os.X_OK), "exact Agent binary required")
    require(not output.exists() and not output.is_relative_to(ROOT), "output must be new and outside candidate")
    before = BASE.source()
    require(not before["dirty"] and before["commit"] == args.expected_commit, "clean exact candidate required")
    output.mkdir(parents=True,mode=0o700)
    report = {"format":FORMAT,"status":"incomplete","observed_at":datetime.now(timezone.utc).isoformat(),"skipped":0,"passed":0,"failed":0,
        "source_before":before,"binary_sha256":BASE.sha(binary),"driver_sha256":BASE.sha(Path(__file__)),"fixture_sha256":sha_bytes(SERVER.encode()),
        "live_model_efficacy_measured":False,"rigs":{},"checks":[]}
    try:
        for name,limits,approval in (("primary",LIMITS,True),("global",dict(LIMITS,total_bytes=98304),False),
                ("capacity",dict(LIMITS,max_sessions=2),False),("shared",LIMITS,False)):
            rig = Rig(binary,output,name,limits,approval)
            try:
                if name == "primary":
                    primary(rig,report)
                elif name == "global":
                    first,second = Client(rig,"global-a"),Client(rig,"global-b")
                    first.initialize(); second.initialize()
                    a,b = pressure(rig,first,count=24),pressure(rig,second,count=24)
                    report["global_pressure"] = {key:a[key]+b[key] for key in a}
                elif name == "capacity":
                    capacity(rig,report)
                else:
                    shared(rig,report)
            finally:
                report["rigs"][name] = rig.close()
        report["source_after"] = BASE.source()
        report["binary_unchanged"] = BASE.sha(binary) == report["binary_sha256"]
        grade(report)
        report["status"],report["passed"] = "pass",len(report["checks"])
    except Exception as error:
        report["status"],report["failed"],report["error"] = "fail",1,redact(type(error).__name__+": "+str(error))[:2000]
        tails = {path.name:redact(path.read_text(errors="replace")[-1500:]) for path in sorted(output.glob("*.log"))[-6:]}
        print(json.dumps({"event":"sou72_acceptance_failure","error":report["error"],"owned_log_tails":tails}),flush=True)
    finally:
        write(output/"report.json",report)
    print(json.dumps({"status":report["status"],"passed":report["passed"],"failed":report["failed"],"skipped":0,
        "error":report.get("error"),"report":str(output/"report.json")}))
    return 0 if report["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",action="store_true")
    parser.add_argument("--agentfw",type=Path,required=True)
    parser.add_argument("--expected-commit",required=True)
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status":"plan","executed":False,"required_linux":True,"native_mcp":True,"live_model":False}))
        return 0
    try:
        return run(args)
    except Exception as error:
        print(json.dumps({"status":"fail","failed":1,"skipped":0,"error":redact(type(error).__name__+": "+str(error))[:2000]}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
