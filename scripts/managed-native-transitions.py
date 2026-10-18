#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Disposable SOU-82 acceptance: signed HTTPS updates during original MCP reads.

Reuses the accepted Console TLS/database fixtures and original FS/Git installers,
clients and kernel witnesses. Never contacts a model or uses an operator home.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import urllib.error
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TLS = load("sou82_tls", "managed-policy-tls-demo.py")
FS = load("sou82_fs", "verify-sou62-real-mcp.py")
GIT = load("sou82_git", "verify-sou68-real-mcp.py")
SHARED = load("sou82_shared", "verify-sou62-sou63-combined.py")
require, sha = FS.require, FS.sha
EXPECTED = {
    "original-filesystem-and-git-positive-controls", "shared-release-lock-defers-activation-and-ack",
    "wrong-digest-and-stale-ack-refused", "original-git-denied-without-repository-open",
    "dispatched-filesystem-read-observed-and-result-withheld", "queued-filesystem-read-never-opened",
    "higher-sequence-rollback-restores-useful-work", "same-collectors-through-transitions",
    "old-ask-approval-cannot-authorize-after-policy-switch", "shared-host-risk-survives-switch",
    "tampered-bundle-keeps-last-accepted-policy", "outage-keeps-runtime-and-useful-work",
    "console-restart-preserves-deployments", "agent-restart-restores-cache-and-retires-old-session",
    "source-runtime-and-profile-identities-unchanged", "owned-resources-cleaned",
}


def check(report, name, evidence):
    require(name in EXPECTED and name not in report["checks"], "unknown or repeated check")
    report["checks"][name] = evidence
    print("PASS: " + name, flush=True)


def call_fs(identifier, path="notes.txt"):
    return FS.call(identifier, {"path": "/workspace/" + path})


def policy(base, mode):
    if mode == "allow":
        return base
    condition = "taint: [mcp], action_class: read_only" if mode == "taint" else "action_class: read_only"
    action = "deny" if mode in ("deny", "taint") else "ask"
    rule = f"  - name: sou82-{mode}-read\n    when: {{ {condition} }}\n    action: {action}\n"
    require("agent_policies:\n" in base, "installed policy lacks its rules")
    return base.replace("agent_policies:\n", "agent_policies:\n" + rule, 1)


def wait(label, predicate, timeout=45):
    return TLS.wait_for(label, lambda: predicate() or None, timeout=timeout)


def set_mode(path, mode):
    staging = path.with_suffix(".next")
    staging.write_text(json.dumps(mode))
    os.replace(staging, path)


def public_deployment(row):
    return {k: row[k] for k in ("revision", "deployment_sequence", "policy_sha256", "status", "rollback") if k in row}


def api(method, url, data=None, headers=None, expected=200):
    try:
        status, body = TLS.request(method, url, data, headers)
    except urllib.error.HTTPError as error:
        status, body = error.code, None
    require(status == expected, f"owned API expected {expected}, got {status}: {url.split('/')[3:]}")
    return body


def run(args):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 required")
    before = FS.source()
    require(before["commit"] == args.expected_commit and not before["dirty"], "clean exact source required")
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), "new evidence directory outside source required")
    output.mkdir(parents=True, mode=0o700)
    binaries = {k: getattr(args, k).resolve(strict=True) for k in ("agentfw", "console", "git", "node", "bwrap", "git_launcher")}
    report = {"format": "sou82-managed-native/1", "status": "incomplete", "backend": args.backend,
              "source_before": before, "binary_sha256": {k: sha(v) for k, v in binaries.items()},
              "driver_sha256": sha(__file__), "checks": {}, "ordering": [], "agents": {}, "cleanup": {},
              "live_model_efficacy_measured": False, "fleet_atomicity_claimed": False, "skipped": 0}
    private = None
    clients, processes, secret_values = [], [], []
    try:
        with tempfile.TemporaryDirectory(prefix="sou82-owned-") as folder, ExitStack() as stack:
            private = Path(folder)
            console_dir = private / "console"
            console_dir.mkdir()
            admin, seed = secrets.token_urlsafe(32), secrets.token_hex(32)
            secret_values.extend([admin, seed])
            console_env = FS.environment(console_dir)
            console_env.update(LLM_FW_ADMIN_TOKEN=admin, SOUP_AGENT_POLICY_SEED_HEX=seed,
                               SOUP_AGENT_POLICY_KEY_ID="sou82-owned-issuer")
            cp = TLS.port()
            database_config = f'  backend: sqlite\n  database_path: "{private / "managed.sqlite"}"\n'
            if args.backend == "postgres":
                helpers = load("sou82_database", "keycloak-oidc-acceptance.py")
                ca, (cert, key), _ = helpers.vendor.certificate_files(private)
                console_env["LLM_FW_POSTGRES_CA_CERT_FILE"] = str(ca)
                database = helpers.FixtureDatabase(private, console_env, stack, postgres=True, cert=cert, key=key)
                database_config = database.configuration()
                secret_values.append(console_env["SOUP_OIDC_FIXTURE_DATABASE_URL"])
            (console_dir / "firewall.yaml").write_text(
                f'bind: "0.0.0.0:{cp}"\ntenant_store:\n  enabled: true\n' + database_config)
            if args.backend == "postgres":
                subprocess.run([str(binaries["console"]), "migrate"], cwd=console_dir, env=console_env,
                               capture_output=True, check=True, timeout=90)
            console_url = f"http://127.0.0.1:{cp}"
            admin_headers = {"x-llm-firewall-admin-token": "Bearer " + admin}

            def start_console():
                child = TLS.proc(stack, [str(binaries["console"])], console_dir, console_env, private / "console.log")
                processes.append(child)
                wait("Console ready", lambda: api("GET", console_url + "/healthz"))
                return child

            console = start_console()
            tenant = api("POST", console_url + "/admin/v1/tenants", {"name": "sou82-owned"}, admin_headers, 201)["id"]
            issuer = api("GET", console_url + "/admin/v1/managed-issuer", headers=admin_headers)
            origin, ca, tls, _, ca_hash, address = TLS.https_edge(stack, private, cp)
            TLS.set_edge_mode(tls, "proxy")
            report["transport"] = {"origin": origin, "ca_sha256": ca_hash, "address": address,
                "edge_source_sha256": sha(ROOT / "scripts/fixtures/managed_policy_tls_edge.py"),
                "scope": "verified HTTPS to owned nonloopback edge; bridge-local HTTP to actual Console"}

            def ordering(event, **fields):
                report["ordering"].append({"index": len(report["ordering"]), "monotonic_ns": time.monotonic_ns(),
                                           "event": event, **fields})

            def health(a):
                return api("GET", a.url + "/health")

            def active(a, seq):
                def current():
                    h = health(a)
                    return h["managed_policy"] if (h.get("managed_policy") or {}).get("deployment_sequence") == seq else None
                observed = wait("active " + a.name + " " + str(seq), current, timeout=20)
                ordering("observed-active", agent=a.name, **observed)
                return observed

            def deployments(a):
                return api("GET", a.base + "/deployments", headers=admin_headers)

            def applied(a, seq):
                def current():
                    return next((r for r in deployments(a) if r["deployment_sequence"] == seq and r["status"] == "applied"), None)
                result = wait("applied ACK", current, timeout=15)
                ordering("console-applied-ack", agent=a.name, **public_deployment(result))
                return public_deployment(result)

            def deploy(a, revision, rollback=False):
                row = api("POST", a.base + f"/revisions/{revision}/deploy", {"rollback": rollback}, admin_headers, 201)
                ordering("issued", agent=a.name, **public_deployment(row))
                return row["deployment_sequence"]

            def start_agent(a):
                child = TLS.proc(stack, [str(binaries["agentfw"]), "serve"], private, a.env, private / (a.name + ".log"))
                processes.append(child)
                wait("Agent ready", lambda: health(a))
                a.process = child
                return child

            agents = []
            for name in ("filesystem", "git"):
                root = private / name
                root.mkdir()
                home, workspace, installed = root / "home", root / "workspace", root / "installed"
                home.mkdir(mode=0o700)
                env = FS.environment(home)
                if name == "filesystem":
                    workspace.mkdir()
                    (workspace / "notes.txt").write_text(FS.TEXT)
                    (workspace / "source.txt").write_text("/workspace/shared-pending.fifo\n")
                    for path in ["shared-pending.fifo", "old-ask.fifo", *[f"active-{i}.fifo" for i in range(8)],
                                 *[f"queued-{i}.fifo" for i in range(8)]]:
                        os.mkfifo(workspace / path, 0o600)
                    FS.INSTALL.install(installed, workspace, binaries["node"], binaries["bwrap"], args.npm)
                else:
                    GIT.prepare_repo(workspace, binaries["git"], env)
                    GIT.INSTALL.install(installed, workspace, binaries["git"], sha(binaries["git"]), binaries["bwrap"], binaries["git_launcher"])
                installation = json.loads((installed / "installation.json").read_text())
                report["agents"][name] = {"installation": installation, "deployments": []}
                a = SimpleNamespace(name=name, home=home, workspace=workspace, install=installed, env=env,
                    registry_sha256=sha(installed / "registry.json"), binary=binaries["agentfw"], node=binaries["node"])
                a.port = TLS.port()
                a.url = f"http://127.0.0.1:{a.port}"
                a.base = console_url + f"/admin/v1/tenants/{tenant}/agents/{name}"
                enrollment = api("POST", console_url + f"/admin/v1/tenants/{tenant}/agents", {"agent_id": name}, admin_headers, 201)
                a.token = enrollment["token"]
                secret_values.append(a.token)
                subprocess.run([str(binaries["agentfw"]), "install"], env=env, capture_output=True, check=True, timeout=30)
                FS.write(home / ".agentfw/config.yaml", {"port": a.port, "enforce": True, "max_record_bytes": 1048576,
                    "policy": str(installed / "policy.yaml"), "native": {"registry_path": str(installed / "registry.json"),
                    "registry_sha256": a.registry_sha256, "approval": {"ttl_seconds": 120}}})
                a.env.update(SOUP_MANAGED_AGENT_CONSOLE=origin, SOUP_MANAGED_AGENT_TLS_CA_FILE=str(ca),
                    SOUP_MANAGED_AGENT_TOKEN=a.token, SOUP_MANAGED_AGENT_TENANT=tenant, SOUP_MANAGED_AGENT_ID=name,
                    SOUP_MANAGED_AGENT_KEY_ID="sou82-owned-issuer", SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX=issuer["public_key_hex"])
                for mode in ("allow", "deny", "ask", "taint"):
                    body = policy((installed / "policy.yaml").read_text(), mode)
                    api("POST", a.base + "/revisions", {"revision": mode, "policy_yaml": body}, admin_headers, 201)
                    api("POST", a.base + f"/revisions/{mode}/approve", {}, admin_headers, 204)
                deploy(a, "allow")
                start_agent(a)
                active(a, 1)
                applied(a, 1)
                a.hook_token = (home / ".agentfw/token").read_text().strip()
                a.native_token = (home / ".agentfw/native-token").read_text().strip()
                secret_values.extend([a.hook_token, a.native_token])
                agents.append(a)
            fs, git = agents

            def native(a, route, value=None):
                return api("GET" if value is None else "POST", a.url + route, value,
                           {"Authorization": "Bearer " + a.native_token})

            host = str(uuid.uuid4())
            def collector(a, label):
                env = dict(a.env, AGENTFW_MCP_SERVER_PROFILE=str(a.install / "profile.json"),
                    AGENTFW_CLASSIFIER="rule-baseline", AGENTFW_CLASSIFIER_PYTHON=sys.executable)
                if a.name == "filesystem":
                    instance = native(a, "/native/v1/instance")
                    proof = subprocess.check_output([str(a.binary), "child-authority", "mint", "--session", host,
                        "--server", label, "--agent-id", label, "--instance-id", instance["instance_id"],
                        "--tools", "read_text_file", "--ttl-seconds", "300"], env=a.env, timeout=20, text=True).strip()
                    secret_values.append(proof)
                    env.update(AGENTFW_HOST_SESSION=host, AGENTFW_CHILD_AUTHORITY=proof,
                               AGENTFW_RULE_BASELINE=str(ROOT / "rule_baseline/rule_baseline.py"))
                    command = [str(a.binary), "mcp", "--native-admission", "--id", label, "--", str(a.node),
                               str(a.install / "package/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"), "/workspace"]
                    cls = FS.Client
                else:
                    env["AGENTFW_RULE_BASELINE"] = str(ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py")
                    command = [str(a.binary), "mcp", "--native-admission", "--id", label, "--",
                        str(a.install / "package/python/bin/python3.11"), "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"]
                    cls = GIT.Client
                log_path = output / (label + ".log")
                log = stack.enter_context(log_path.open("wb"))
                client = cls(command, env, a.workspace, log, label)
                clients.append(client)
                stack.callback(client.close)
                client.initialize()
                client.log_path = log_path
                return client

            reader, sibling, git_client = collector(fs, "fs-reader"), collector(fs, "fs-sibling"), collector(git, "git-reader")
            original_pids = [c.process.pid for c in clients]
            require(FS.result_text(reader.exchange(call_fs(10))[0]) == FS.TEXT, "initial filesystem read failed")
            require("SOU-68 synthetic initial commit" in GIT.text(git_client.exchange(GIT.call(10))[0]), "initial Git read failed")
            check(report, "original-filesystem-and-git-positive-controls", {"pids": original_pids, "host_session": host})

            # Independent process owns the same kernel lock as a trusted collector.
            # Holding it models the admitted-but-not-yet-dispatched boundary.
            with (git.home / ".agentfw/managed-native-boundary.lock").open("r+b") as boundary:
                fcntl.flock(boundary, fcntl.LOCK_SH)
                seq = deploy(git, "deny")
                wait("deferred activation", lambda: health(git)["managed_transport"]["state"] == "activation_pending", timeout=10)
                require(health(git)["managed_policy"]["deployment_sequence"] == 1, "busy activation changed evaluator")
                rows = deployments(git)
                row = next(r for r in rows if r["deployment_sequence"] == seq)
                require(row["status"] not in ("applied", "rejected"), "busy activation was falsely ACKed")
                for sequence, digest in [(seq, "0" * 64), (1, row["policy_sha256"])]:
                    api("POST", console_url + "/agent/v1/policy/ack", {"deployment_sequence": sequence,
                        "revision": "deny", "policy_sha256": digest, "status": "applied"},
                        {"Authorization": "Bearer " + git.token}, 409)
                check(report, "wrong-digest-and-stale-ack-refused", {"http_status": 409, "sequence": seq})
                check(report, "shared-release-lock-defers-activation-and-ack", public_deployment(row))
            active(git, seq)
            applied(git, seq)
            witness = GIT.RepositoryWitness(git.workspace)
            try:
                result = git_client.exchange(GIT.call(11))[0]
                require(FS.refused(result) and "sou82-deny-read" in json.dumps(result), "Git call was not policy denied")
                require(witness.drain() == 0, "denied Git call opened the repository")
            finally:
                witness.close()
            check(report, "original-git-denied-without-repository-open", {"response": result, "kernel_open_count": 0})

            fifo = FS.FIFOWitness([fs.workspace / f"active-{i}.fifo" for i in range(8)])
            stack.callback(fifo.finish)
            probes = [SHARED.FifoProbe(fs.workspace / f"queued-{i}.fifo") for i in range(8)]
            for probe in probes:
                stack.callback(probe.finish)
            reader.send(*[call_fs(100 + i, f"active-{i}.fifo") for i in range(8)])
            wait("real filesystem reader", lambda: any(r["reader_opened"] for r in fifo.records), timeout=10)
            FS.wait_event(reader.log_path, lambda rows: sum(r.get("state") == "inflight" for r in rows) >= 9,
                          "eight original calls did not dispatch")
            reader.send(*[call_fs(108 + i, f"queued-{i}.fifo") for i in range(8)])
            FS.wait_event(reader.log_path, lambda rows: any(r.get("host_call_id") == 115 and r.get("state") == "queued" for r in rows),
                          "last stale request did not queue")
            seq = deploy(fs, "deny")
            active(fs, seq)
            applied(fs, seq)
            ordering("reader-existed-before-policy-deny", observed_readers=sum(r["reader_opened"] for r in fifo.records))
            fifo.finish()
            replies = {}
            for _ in range(16):
                response, _ = reader.receive()
                require(response["id"] not in replies, "duplicate read response")
                replies[response["id"]] = response
            require(set(replies) == set(range(100, 116)), "queued/inflight responses missing")
            require(all(FS.refused(r) and FS.FIFO_TEXT not in json.dumps(r) for r in replies.values()), "stale read/result escaped")
            require(all("native_policy_transition_result_refused" in json.dumps(replies[i]) for i in range(100, 108)), "inflight result did not revalidate")
            records = [p.finish() for p in probes]
            require(all(not r["reader_seen"] for r in records), "stale queued operation executed")
            check(report, "dispatched-filesystem-read-observed-and-result-withheld", {"fifo": fifo.records,
                  "result_ids": list(range(100, 108)), "effect_undone": False})
            check(report, "queued-filesystem-read-never-opened", {"probes": records, "responses": [replies[i] for i in range(108, 116)]})

            for a in agents:
                seq = deploy(a, "allow", rollback=True)
                active(a, seq)
                applied(a, seq)
            require(FS.result_text(reader.exchange(call_fs(200))[0]) == FS.TEXT, "filesystem rollback lost useful read")
            require("SOU-68 synthetic initial commit" in GIT.text(git_client.exchange(GIT.call(200))[0]), "Git rollback lost useful read")
            check(report, "higher-sequence-rollback-restores-useful-work", {"sequences": [health(a)["managed_policy"] for a in agents]})
            require(all(c.process.poll() is None for c in clients), "a collector restarted during transition")
            check(report, "same-collectors-through-transitions", {"pids": original_pids})

            # The supported native operator approval surface is tested directly;
            # selected real-server collectors still refuse Ask without prompting.
            seq = deploy(fs, "ask")
            active(fs, seq)
            registry = json.loads((fs.install / "registry.json").read_text())
            tool = next(t for t in registry["tools"] if t["name"] == "read_media_file")
            native_base = {"contract_version": "sw-native/1", "registry_sha256": fs.registry_sha256, "session_id": "sou82-old-ask"}
            native(fs, "/native/v1", {**native_base, "event": "session_start", "policy_transition": "sw-managed-native/1"})
            fields = {"tool": tool["name"], "args": {"path": "/workspace/old-ask.fifo"}, "schema_sha256": tool["schema_sha256"]}
            approval = native(fs, "/native/approval/v1", {**native_base, **fields, "action": "request", "source": "daemon"})
            subprocess.run([str(fs.binary), "native-approval", "approve", approval["pending_id"], "--binding", approval["binding_sha256"]],
                           env=fs.env, capture_output=True, check=True, timeout=20)
            positive = native(fs, "/native/v1", {**native_base, **fields, "event": "call", "approval_id": approval["pending_id"]})
            require(positive["release"], "native approval positive control failed before switch")
            approval = native(fs, "/native/approval/v1", {**native_base, **fields, "action": "request", "source": "daemon"})
            subprocess.run([str(fs.binary), "native-approval", "approve", approval["pending_id"], "--binding", approval["binding_sha256"]],
                           env=fs.env, capture_output=True, check=True, timeout=20)
            seq = deploy(fs, "ask")  # same YAML, NEW sequence still retires authority
            active(fs, seq)
            probe = SHARED.FifoProbe(fs.workspace / "old-ask.fifo")
            try:
                stale = native(fs, "/native/v1", {**native_base, **fields, "event": "call",
                    "approval_id": approval["pending_id"]})
                require(not stale["release"] and "stale_policy" in json.dumps(stale), "old Ask grant survived new sequence")
            finally:
                record = probe.finish()
            require(not record["reader_seen"], "old Ask control unexpectedly executed")
            native(fs, "/native/v1", {**native_base, "event": "session_end"})
            check(report, "old-ask-approval-cannot-authorize-after-policy-switch", {"positive_receipt": positive, "receipt": stale, "probe": record,
                  "scope": "native API approval control using a legacy registry entry; no media execution or new selected-server Ask UI"})

            seq = deploy(fs, "allow", rollback=True)
            active(fs, seq)
            require(FS.result_text(reader.exchange(call_fs(210, "source.txt"))[0]) == "/workspace/shared-pending.fifo\n", "shared source missing")
            seq = deploy(fs, "taint")
            active(fs, seq)
            probe = SHARED.FifoProbe(fs.workspace / "shared-pending.fifo")
            try:
                result = sibling.exchange(call_fs(211, "shared-pending.fifo"))[0]
                require(FS.refused(result) and "sou82-taint-read" in json.dumps(result), "shared taint lost at switch")
            finally:
                record = probe.finish()
            require(not record["reader_seen"], "shared tainted operation ran")
            require(FS.result_text(sibling.exchange(call_fs(212))[0]) == FS.TEXT, "unrelated safe read was blanket-denied")
            check(report, "shared-host-risk-survives-switch", {"host_session": host, "response": result, "probe": record})

            # Invalid candidate and unavailable transport retain the accepted evaluator.
            prior = health(git)["managed_policy"]
            mode_path = tls / "mode.json"
            mode = json.loads(mode_path.read_text())
            mode["tamper_policy"] = True
            set_mode(mode_path, mode)
            rejected = deploy(git, "deny")
            wait("tampered deployment rejected", lambda: any(r["deployment_sequence"] == rejected and r["status"] == "rejected" for r in deployments(git)), timeout=15)
            require(health(git)["managed_policy"] == prior, "tampered bundle changed runtime")
            require("SOU-68 synthetic initial commit" in GIT.text(git_client.exchange(GIT.call(220))[0]), "tamper stopped accepted work")
            check(report, "tampered-bundle-keeps-last-accepted-policy", {"active": prior, "rejected_sequence": rejected})
            mode["tamper_policy"] = False
            mode["mode"] = "outage"
            set_mode(mode_path, mode)
            wait("outage observed", lambda: all(health(a)["managed_transport"]["state"] == "offline" for a in agents), timeout=15)
            require(health(git)["managed_policy"] == prior, "outage changed accepted revision")
            require("SOU-68 synthetic initial commit" in GIT.text(git_client.exchange(GIT.call(221))[0]), "offline useful read failed")
            check(report, "outage-keeps-runtime-and-useful-work", {"health": [health(a)["managed_policy"] for a in agents]})
            saved = {a.name: deployments(a) for a in agents}
            console.terminate()
            console.wait(timeout=8)
            console = start_console()
            require(all(deployments(a) == saved[a.name] for a in agents), "Console restart changed deployment history")
            check(report, "console-restart-preserves-deployments", {"counts": {k: len(v) for k, v in saved.items()}})
            old_instance = native(git, "/native/v1/instance")["instance_id"]
            git.process.terminate()
            git.process.wait(timeout=8)
            start_agent(git)
            require(health(git)["managed_policy"] == prior, "offline Agent restart lost accepted cache")
            new_instance = native(git, "/native/v1/instance")["instance_id"]
            require(old_instance != new_instance, "daemon restart retained session instance")
            git_client.send(GIT.call(222))
            wait("old collector refuses lost daemon session", lambda: git_client.process.poll() is not None, timeout=10)
            replacement = collector(git, "git-restarted")
            require("SOU-68 synthetic initial commit" in GIT.text(replacement.exchange(GIT.call(223))[0]), "restarted accepted policy lost useful work")
            check(report, "agent-restart-restores-cache-and-retires-old-session", {"active": prior,
                  "old_instance": old_instance, "new_instance": new_instance, "old_collector_exit": git_client.process.returncode})
            # New higher sequence can recover after the invalid candidate too.
            seq = deploy(git, "allow", rollback=True)
            mode["mode"] = "proxy"
            set_mode(mode_path, mode)
            active(git, seq)
            applied(git, seq)
            for a in agents:
                report["agents"][a.name]["deployments"] = [public_deployment(r) for r in deployments(a)]
                installation = report["agents"][a.name]["installation"]
                require(sha(a.install / "profile.json") == installation["profile_sha256"]
                    and sha(a.install / "registry.json") == installation["registry_sha256"]
                    and sha(a.install / "policy.yaml") == installation["policy_sha256"], "installed profile identity changed")
                installer = FS.INSTALL if a.name == "filesystem" else GIT.INSTALL
                require(installer.tree_sha(a.install / "package") == installation["profile"]["packageTreeSha256"], "original package changed")
            require(FS.source() == before and all(sha(v) == report["binary_sha256"][k] for k, v in binaries.items()), "source/runtime changed")
            check(report, "source-runtime-and-profile-identities-unchanged", {"source_after": FS.source()})
        require(not private.exists() and all(p.poll() is not None for p in processes), "private resources survived cleanup")
        require(all(c.process_witness.final.get("all_stopped") for c in clients), "collector descendants survived cleanup")
        report["cleanup"] = {"private_directory_removed": True, "processes_stopped": True,
                             "clients": [c.transcript() for c in clients]}
        check(report, "owned-resources-cleaned", {"client_count": len(clients), "daemon_count": len(processes)})
        require(set(report["checks"]) == EXPECTED, "acceptance checks missing")
        report["status"] = "pass"
    except Exception as error:
        report["status"] = "fail"
        # Exception messages can contain an owned subprocess environment/URL.
        message = str(error)
        for secret in secret_values:
            message = message.replace(secret, "[REDACTED]")
        report["error"] = type(error).__name__ + ": " + message[:2000]
    finally:
        report["source_after"] = FS.source()
        report["cleanup"]["private_directory_removed"] = private is not None and not private.exists()
        rendered = json.dumps(report, indent=2)
        for secret in secret_values:
            rendered = rendered.replace(secret, "[REDACTED]")
        (output / "report.json").write_text(rendered)
    print(json.dumps({"status": report["status"], "passed": len(report["checks"]), "error": report.get("error")}))
    return 0 if report["status"] == "pass" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=("sqlite", "postgres"), required=True)
    for key in ("agentfw", "console", "node", "npm", "git", "git-launcher", "bwrap", "output"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
