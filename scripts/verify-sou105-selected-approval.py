#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in exact-source Linux acceptance against both pinned original servers.

Private synthetic workspaces only. CLI decisions are explicit authorization,
not evidence of physical human presence. No paid provider / model / training.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import re
import signal
import shutil
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load("sou105_fs", "verify-sou62-real-mcp.py")
GIT = load("sou105_git", "verify-sou68-real-mcp.py")
require, sha, write = BASE.require, BASE.sha, BASE.write
FORMAT = "sw-mcp/selected-approval-acceptance/1"
CASES = ("approve", "reject", "expire", "timeout", "cancel", "wrong_binding", "classifier_change", "profile_change",
         "disconnect", "collector_death", "restart", "default", "deny")


def trace_effects(path, kind, git_path=None, target="/workspace/notes.txt", evidence=None, git_revision=None):
    """Kernel syscall witness, independent of daemon/collector verdict logging.

    The pinned git_show implementation uses GitPython's diff-tree for a root
    commit, not the Git CLI's show subcommand. Count its exact successful patch
    execution (not launcher attempts, failed searches or returned payloads).
    FS counts successful read-only opens of the exact synthetic target.
    """
    raw = path.read_bytes() if path.exists() else b""
    require(len(raw) <= 32 * 1024 * 1024, "syscall witness exceeded bound")
    rows, unfinished = [], {}
    for line in raw.decode("utf-8", errors="strict").splitlines():
        entry = re.match(r"\s*(\d+)\s+(.*)", line)
        prefix, rest = entry.groups() if entry else ("single-process", line)
        if "<unfinished ...>" in rest:
            unfinished[prefix] = rest.split("<unfinished ...>")[0]
        elif "resumed>" in rest and prefix in unfinished:
            rows.append(unfinished.pop(prefix) + rest.split("resumed>", 1)[1])
        else:
            rows.append(line)
    git_commands = []
    if kind == "git":
        executable = str(git_path or "/mcp-runtime/git")
        require(git_revision is not None and re.fullmatch(r"[0-9a-f]{40}", git_revision), "exact synthetic Git revision required")
        pattern = re.compile(r'execve\(' + re.escape(json.dumps(executable)) + r', (\[.*\]), .*\) += 0$')
        matched = []
        for row in rows:
            match = pattern.search(row)
            if not match:
                continue
            argv = json.loads(match.group(1))
            require(isinstance(argv, list) and len(argv) <= 64 and all(isinstance(a, str) for a in argv), "invalid pinned Git argv witness")
            git_commands.append(argv)
            if all(argument in argv for argument in ("diff-tree", git_revision, "--root", "-p")):
                matched.append(row)
    else:
        pattern = re.compile(r'openat\([^,]+, ' + re.escape(json.dumps(target)) + r', O_RDONLY(?:\|[^)]*)?\) += [0-9]+$')
        matched = [row for row in rows if pattern.search(row)]
    if evidence is not None:
        write(evidence, {"kind": kind, "trace_sha256": BASE.hashlib.sha256(raw).hexdigest(),
                         "successful_target_syscalls": matched, "effects": len(matched),
                         "raw_trace_exported": False, "git_revision": git_revision,
                         # Only the exact pinned Git executable's synthetic
                         # argv is retained, never collector authority argv.
                         "pinned_git_commands": git_commands[-64:]})
    return len(matched)


def command(args, env, *words, success=True):
    result = subprocess.run([str(args.agentfw), *words], env=env, cwd=ROOT,
                            capture_output=True, text=True, timeout=15)
    if words[:2] in (("native-approval", "approve"), ("native-approval", "reject")):
        # These decisions contain only synthetic pending IDs/bindings, never a
        # child-authority token. Keep failed/late CLI diagnostics too.
        with (args.output / "operator-decisions.log").open("a") as log:
            log.write(json.dumps({"command": words, "exit_code": result.returncode,
                                  "stdout": result.stdout[:4096], "stderr": result.stderr[:4096]}) + "\n")
    require((result.returncode == 0) == success,
            "operator command outcome mismatch: " + " ".join(words[:2]) + " exit=" + str(result.returncode))
    return result.stdout.strip()


def pending(args, env, timeout=5, empty=False):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = json.loads(command(args, env, "native-approval", "list"))
        if empty and not rows:
            return []
        if not empty and len(rows) == 1:
            return rows[0]
        time.sleep(.025)
    raise ValueError("pending approval state missed declared deadline")


def refused_response(client, timeout=8):
    response, _ = client.receive(timeout=timeout)
    return type(response.get("id")) is int and response["id"] == 50 and BASE.refused(response)


def approved_response(client, evidence):
    # Match the common independent client's 35-second observation budget.
    # Approval has already been explicitly decided: this does not extend the
    # collector's 25-second pending wait, broker TTL or any negative-case bound.
    evidence["approved_response_budget_ms"] = 35000
    started = time.monotonic()
    try:
        return client.receive(timeout=35)
    except queue.Empty:
        raise ValueError("approved original response not observed within 35 seconds") from None
    finally:
        evidence["approved_response_elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)


def inspected_output(text, pending_id, binding):
    # The accepted CLI prints one JSON record followed by its exact operator
    # command hint. Keep that interface and reject arbitrary trailing output.
    record, end = json.JSONDecoder().raw_decode(text)
    hint = ("To approve exactly this call:\n  agentfw native-approval approve "
            + pending_id + " --binding " + binding)
    require(isinstance(record, dict) and record.get("pending_id") == pending_id
            and record.get("binding_sha256") == binding and text[end:].strip() == hint,
            "operator inspect identity or command hint changed")
    return record


class Rig:
    def __init__(self, args, root, kind):
        self.args, self.root, self.kind = args, root, kind
        # strace sees the collector's private child-authority argv. Keep raw
        # traces outside the exported artifact tree, even on failure. Export
        # only digests, calibrated counts and synthetic MCP transcripts.
        self.trace_root = args.output.parent / ("." + args.output.name + "-syscalls-private") / kind
        self.trace_root.mkdir(mode=0o700, parents=True)
        self.home, self.workspace = root / "home", root / "workspace"
        self.target = "credentials.txt"
        self.home.mkdir(parents=True, mode=0o700)
        self.env = BASE.environment(self.home)
        self.env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1",
                        GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
                        GIT_PYTHON_GIT_EXECUTABLE=str(args.git))
        self.installed = root / "installed"
        shutil.copytree(ROOT / "rule_baseline", root / "classifier")
        self.classifier = root / "classifier" / ("git_readonly_v1/rule_baseline.py" if kind == "git" else "rule_baseline.py")
        if kind == "git":
            GIT.prepare_repo(self.workspace, args.git, self.env)
            self.git_revision = subprocess.check_output([str(args.git), "rev-parse", "HEAD"], cwd=self.workspace,
                                                       env=self.env, text=True, timeout=5).strip()
            GIT.INSTALL.install(self.installed, self.workspace, args.git, sha(args.git), args.bwrap, args.git_launcher)
        else:
            self.workspace.mkdir(mode=0o700)
            (self.workspace / "notes.txt").write_text("SOU105 synthetic useful inventory: 7 red widgets\n")
            if kind != "create":
                (self.workspace / self.target).write_text("SOU105 synthetic useful inventory: 7 red widgets\n")
            installer = BASE.SOU83_INSTALL if kind == "create" else BASE.INSTALL
            installer.install(self.installed, self.workspace, args.node, args.bwrap, args.npm)
        command(args, self.env, "install")
        self.profile = json.loads((self.installed / "profile.json").read_text())
        self.registry = self.installed / "registry.json"
        self.tools = [t["name"] for t in json.loads(self.registry.read_text())["tools"] if t.get("mcp_result_profile")]
        self.policy = self.root / "approval-policy.yaml"
        self.port = BASE.DEMO.free_port()
        self.config = {"port": self.port, "enforce": True, "policy": str(self.policy), "native": {
            "registry_path": str(self.registry), "registry_sha256": sha(self.registry),
            "approval": {"ttl_seconds": 30},
            "liveness": {"default_lease_seconds": 2, "max_lease_seconds": 60, "maintenance_interval_ms": 100}}}
        write(self.home / ".agentfw/config.yaml", self.config)
        self.clients, self.daemons = [], []
        self.start()

    def start(self, deny=False):
        sensitive = ", touches_sensitive_path: true" if self.kind == "filesystem" and not deny else ""
        action = "side_effecting" if self.kind == "create" else "read_only"
        self.policy.write_text("agent_policies:\n  - name: selected-reviewed-action\n    when: { action_class: " + action + sensitive + " }\n    action: "
                               + ("deny" if deny else "ask") + "\ndefault: allow\n")
        out = (self.root / f"daemon-{len(self.daemons)}.stdout.log").open("wb")
        err = (self.root / f"daemon-{len(self.daemons)}.stderr.log").open("wb")
        self.daemon = subprocess.Popen([str(self.args.agentfw), "serve"], env=self.env, stdout=out, stderr=err)
        out.close(); err.close()
        witness = BASE.ProcessWitness(self.daemon.pid)
        self.daemons.append((self.daemon, witness))
        if not BASE.DEMO.wait_healthy(self.port, self.daemon):
            # __init__ may fail before its caller owns the Rig. Reap here too,
            # retaining the failed startup instead of losing its cleanup proof.
            BASE.DEMO.stop(self.daemon)
            self.daemon.wait(timeout=8)
            write(self.root / "daemon-startup-failure.witness.json", {
                "exit_code": self.daemon.returncode, "process": witness.finish(),
                "config_sha256": sha(self.home / ".agentfw/config.yaml"),
                "stderr_sha256": sha(self.root / f"daemon-{len(self.daemons)-1}.stderr.log")})
            raise ValueError("owned enforcing daemon unavailable")

    def stop(self):
        BASE.DEMO.stop(self.daemon)
        self.daemon.wait(timeout=8)

    def client(self, label, wait=6, direct=False):
        profile = self.profile
        server = ([profile["runtimePath"], "-I", "-B", "-m", "mcp_server_git", "--repository",
                   str(self.workspace) if direct else "/workspace"] if self.kind == "git" else
                  [profile["runtimePath"], str(Path(profile["packageRoot"]) / "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"),
                   str(self.workspace) if direct else "/workspace"])
        env = dict(self.env)
        if direct:
            actual = server
        else:
            # Read the current exact instance through the accepted authenticated
            # CLI. No copied identity from a previous daemon is redeemable.
            native_token = (self.home / ".agentfw/native-token").read_text().strip()
            request = urllib.request.Request(f"http://127.0.0.1:{self.port}/native/v1/instance",
                                             headers={"Authorization": "Bearer " + native_token})
            with urllib.request.urlopen(request, timeout=5) as reply:
                instance = json.load(reply)["instance_id"]
            token = command(self.args, env, "child-authority", "mint", "--session", "host-" + label,
                            "--server", "sou105-selected", "--agent-id", "agent-" + label,
                            "--instance-id", instance, "--ttl-seconds", "120", "--tools", ",".join(self.tools))
            env.update(AGENTFW_MCP_SERVER_PROFILE=str(self.installed / "profile.json"),
                       AGENTFW_CLASSIFIER="rule-baseline", AGENTFW_CLASSIFIER_PYTHON=os.sys.executable,
                       AGENTFW_RULE_BASELINE=str(self.classifier),
                       AGENTFW_NATIVE_LIVENESS="true", AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS="2",
                       AGENTFW_MCP_SESSION="collector-" + label)
            actual = [str(self.args.agentfw), "mcp", "--native-admission", "--id", "sou105-selected",
                      "--host-session", "host-" + label, "--child-authority", token,
                      "--native-approval-wait-seconds", str(wait), "--", *server]
        trace = self.trace_root / (label + ".syscalls.log")
        stderr = self.root / (label + ".stderr.log")
        with stderr.open("wb") as log:
            client = BASE.Client([str(self.args.strace), "-f", "--seccomp-bpf", "-qq", "-s", "4096", "-e", "trace=openat,execve",
                                  "-o", str(trace), "--", *actual], env, self.workspace, log, label)
        self.clients.append(client)
        # Git's protocol pin differs from the older filesystem negotiated pin.
        protocol = "2025-11-25" if self.kind == "git" else "2025-06-18"
        result, _ = client.exchange({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": protocol, "capabilities": {}, "clientInfo": {"name": "sou105-acceptance", "version": "1"}}})
        require(result.get("result", {}).get("protocolVersion") == protocol, "original protocol pin changed")
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        listing, _ = client.exchange({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        assets = GIT.INSTALL.ASSETS if self.kind == "git" else BASE.INSTALL.ASSETS
        require(listing.get("result") == json.loads((assets / "upstream-tools-list.json").read_text())["result"],
                "original manifest changed")
        return client, trace, stderr

    def frame(self, identifier=50, direct=False):
        if self.kind == "git":
            return {"jsonrpc": "2.0", "id": identifier, "method": "tools/call", "params": {
                "name": "git_show", "arguments": {"repo_path": str(self.workspace) if direct else "/workspace", "revision": "HEAD"}}}
        return {"jsonrpc": "2.0", "id": identifier, "method": "tools/call", "params": {
            "name": "read_text_file", "arguments": {"path": str(self.workspace / self.target) if direct else "/workspace/" + self.target}}}

    def effects(self, trace, direct=False):
        return trace_effects(trace, self.kind, self.args.git if direct else None,
                             str(self.workspace / self.target) if direct else "/workspace/" + self.target,
                             self.root / (trace.stem + ".witness.json"), getattr(self, "git_revision", None))

    def close(self):
        cleanup = []
        for client in self.clients:
            client.close()
            cleanup.append(client.transcript())
        self.stop()
        daemons = [witness.finish() for _, witness in self.daemons]
        require(all(row["process_cleanup"]["all_stopped"] and not row["forced_cleanup"] for row in cleanup),
                "collector/original process cleanup not independently verified")
        require(all(row["all_stopped"] for row in daemons), "daemon process cleanup unverified")
        return {"clients": cleanup, "daemons": daemons}


def qualify(rig, report):
    args = rig.args
    original, trace, _ = rig.client("direct-calibration", direct=True)
    require(rig.effects(trace, True) == 0, "witness not quiet before calibration")
    direct, original_raw = original.exchange(rig.frame(direct=True))
    require(not BASE.refused(direct), "actual unwrapped original positive failed")
    time.sleep(.05)
    require(rig.effects(trace, True) == 1, "kernel execution witness did not calibrate to one useful original call")
    original.close()
    report["calibration"] = {"effects": 1, "result_sha256": BASE.hashlib.sha256(original_raw).hexdigest(),
                             "syscall_trace_sha256": sha(trace), "raw_trace_exported": False,
                             "git_revision": getattr(rig, "git_revision", None)}
    for case in CASES:
        if case in ("expire", "timeout"):
            # Separate the real broker TTL from a shorter collector wait. A
            # local wait timeout alone is not proof of daemon grant expiry.
            rig.stop()
            rig.config["native"]["approval"]["ttl_seconds"] = 1 if case == "expire" else 30
            write(rig.home / ".agentfw/config.yaml", rig.config)
            rig.start()
        if case == "deny":
            rig.stop(); rig.start(deny=True)
        client, trace, stderr = rig.client(case, wait=1 if case == "timeout" else (0 if case == "default" else 25))
        row = {"case": case, "passed": False}
        report["cases"].append(row)
        require(rig.effects(trace) == 0, "unexpected target execution at startup")
        client.send(rig.frame())
        if case in ("deny", "default"):
            response, _ = client.receive(timeout=8)
            require(BASE.refused(response) and response["id"] == 50, "default/Deny did not refuse original ID")
            pending(args, rig.env, empty=True)
        else:
            waiting = pending(args, rig.env)
            output = command(args, rig.env, "native-approval", "inspect", waiting["pending_id"])
            (rig.root / (case + ".operator-inspect.log")).write_text(output + "\n")
            inspected = inspected_output(output, waiting["pending_id"], waiting["binding_sha256"])
            require(inspected["args"] == rig.frame()["params"]["arguments"], "operator inspected different arguments")
            require(inspected["selected_invocation"]["host_call_id"] == 50, "operator inspected different host request")
            require(inspected["selected_invocation"]["request_sha256"] == BASE.hashlib.sha256(client.sent[-1]).hexdigest(),
                    "operator binding does not freeze the original host frame")
            time.sleep(.15)
            require(rig.effects(trace) == 0, "original server executed before explicit approval")
            row["preapproval_effects"] = 0
            row["binding_sha256"] = waiting["binding_sha256"]
            row["broker_ttl_ms"] = inspected["expires_at_ms"] - inspected["created_at_ms"]
            if case == "approve":
                command(args, rig.env, "native-approval", "approve", waiting["pending_id"], "--binding", waiting["binding_sha256"])
                response, raw = approved_response(client, row)
                require(raw == original_raw and not BASE.refused(response), "original admitted bytes changed / useful approval refused")
                require(rig.effects(trace) == 1, "approved invocation did not dispatch exactly once")
                command(args, rig.env, "native-approval", "approve", waiting["pending_id"], "--binding", waiting["binding_sha256"], success=False)
                # A useful concurrent peer can be approved independently while
                # another call on the first relay is still waiting.
                # Initialize the independently pinned/sandboxed peer before
                # starting the timed follow-up. strace startup is substantial;
                # it is not part of an outstanding operator decision.
                peer, peer_trace, _ = rig.client("useful-peer")
                client.send(rig.frame(51))
                first = pending(args, rig.env)
                if rig.kind == "filesystem":
                    neutral = rig.frame(52)
                    neutral["params"]["arguments"]["path"] = "/workspace/notes.txt"
                    client.send(neutral)
                    reply, _ = client.receive(timeout=5)
                    require(reply.get("id") == 52 and not BASE.refused(reply)
                            and "7 red widgets" in json.dumps(reply), "same-relay Allow peer blocked by pending Ask")
                    require(rig.effects(trace) == 1, "pending sensitive follow-up executed before approval")
                    row["same_relay_allow_peer"] = True
                peer.send(rig.frame(70))
                deadline = time.monotonic() + 5
                while True:
                    rows = json.loads(command(args, rig.env, "native-approval", "list"))
                    other = next((item for item in rows if item["pending_id"] != first["pending_id"]), None)
                    if other: break
                    require(time.monotonic() < deadline, "useful peer was blocked by pending relay")
                    time.sleep(.025)
                command(args, rig.env, "native-approval", "approve", other["pending_id"], "--binding", other["binding_sha256"])
                require(not BASE.refused(peer.receive()[0]) and rig.effects(peer_trace) == 1, "independent useful peer failed")
                require(rig.effects(trace) == 1, "pending follow-up dispatched without its approval")
                command(args, rig.env, "native-approval", "approve", first["pending_id"], "--binding", first["binding_sha256"])
                require(not BASE.refused(client.receive()[0]) and rig.effects(trace) == 2, "useful same-relay follow-up failed")
                require(peer.close() == 0, "useful peer did not close cleanly")
                row["useful_peer_and_followup"] = True
            elif case in ("reject", "wrong_binding"):
                if case == "wrong_binding":
                    command(args, rig.env, "native-approval", "approve", waiting["pending_id"], "--binding", "0" * 64, success=False)
                    require(rig.effects(trace) == 0, "wrong binding dispatched")
                command(args, rig.env, "native-approval", "reject", waiting["pending_id"])
                require(refused_response(client), "operator rejection lost the original refusal ID")
            elif case == "cancel":
                client.send(BASE.cancel(50))
                require(refused_response(client), "host cancellation lost the original refusal ID")
            elif case in ("expire", "timeout"):
                require(refused_response(client), "expiry/timeout lost the original refusal ID")
                require(row["broker_ttl_ms"] == (1000 if case == "expire" else 30000),
                        "broker TTL and collector wait control were conflated")
                command(args, rig.env, "native-approval", "approve", waiting["pending_id"], "--binding", waiting["binding_sha256"], success=False)
            elif case in ("classifier_change", "profile_change"):
                asset = rig.classifier if case == "classifier_change" else rig.installed / "profile.json"
                saved = asset.read_bytes()
                try:
                    if case == "classifier_change": asset.write_bytes(saved + b"\n# private stale-asset control\n")
                    else:
                        changed = json.loads(saved); changed["runtimeSha256"] = "0" * 64
                        write(asset, changed)
                    command(args, rig.env, "native-approval", "approve", waiting["pending_id"], "--binding", waiting["binding_sha256"])
                    require(refused_response(client, timeout=10), "changed asset resumed or lost the original ID")
                finally:
                    asset.write_bytes(saved)
            elif case == "disconnect":
                client.process.stdin.close()
            elif case == "collector_death":
                client.process_witness.sample()
                pids = []
                for pid, start in client.process_witness.observed:
                    try:
                        argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
                        if BASE.ProcessWitness.identity(pid) == start and argv[0] == os.fsencode(args.agentfw) and b"mcp" in argv:
                            pids.append(pid)
                    except OSError:
                        pass
                require(len(pids) == 1, "one exact owned collector process required")
                os.kill(pids[0], signal.SIGKILL)
            elif case == "restart":
                rig.stop(); rig.start()
                command(args, rig.env, "native-approval", "approve", waiting["pending_id"], "--binding", waiting["binding_sha256"], success=False)
            pending(args, rig.env, timeout=8, empty=True)
        time.sleep(.05)
        row["effects"] = rig.effects(trace)
        require(row["effects"] == (2 if case == "approve" else 0), "forbidden or repeated original dispatch")
        client.close()
        require(rig.effects(trace) == row["effects"], "late original dispatch after terminal outcome")
        row["syscall_trace_sha256"] = sha(trace)
        row["raw_trace_exported"] = False
        require(case in ("collector_death", "restart") or client.process.returncode == 0,
                "ordinary continuation did not close cleanly")
        row["passed"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    for name in ("agentfw", "node", "npm", "git", "bwrap", "git-launcher", "strace", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    report = {"format": FORMAT, "status": "failed", "families": {}, "physical_human_presence_proved": False,
              "trace_requested": {"mode": "seccomp-bpf", "fallback_possible": True,
                                  "syscalls": "openat,execve"}}
    output = args.output.resolve(); output.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "required native Linux x86-64 unavailable; no fallback")
        for name in ("agentfw", "node", "npm", "git", "bwrap", "git_launcher", "strace"):
            setattr(args, name, getattr(args, name).resolve(strict=True))
        report["source_before"] = BASE.source()
        require(report["source_before"]["commit"] == args.expected_commit and not report["source_before"]["dirty"], "exact clean source required")
        report["files"] = {name: sha(getattr(args, name)) for name in ("agentfw", "node", "npm", "git", "bwrap", "git_launcher", "strace")}
        report["classifier_python"] = {"sha256": sha(Path(os.sys.executable).resolve()), "version": platform.python_version()}
        report["source_files"] = {str(p.relative_to(ROOT)): sha(p) for p in [Path(__file__), ROOT / "crates/agentfw/src/native/approval.rs",
            ROOT / "crates/agentfw/src/native.rs", ROOT / "crates/agentfw/src/mcp/admission/real_server.rs",
            ROOT / "crates/agentfw/src/mcp/server_profile.rs", ROOT / "rule_baseline/rule_baseline.py", ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py"]}
        for kind in ("filesystem", "git"):
            family = report["families"][kind] = {"cases": []}
            rig = None
            try:
                rig = Rig(args, output / kind, kind)
                family["installation"] = json.loads((rig.installed / "installation.json").read_text())
                family["config_sha256"] = sha(rig.home / ".agentfw/config.yaml")
                qualify(rig, family)
            finally:
                if rig is not None: family["cleanup"] = rig.close()
        report["source_after"] = BASE.source()
        require(report["source_after"] == report["source_before"], "source changed during acceptance")
        require(all([row["case"] for row in data["cases"]] == list(CASES) and all(row["passed"] for row in data["cases"])
                    for data in report["families"].values()), "required acceptance missing")
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)[:1000]
    finally:
        write(output / "report.json", report)
    print(json.dumps({"status": report["status"], "error": report.get("error"),
                      "cases": {k: len(v["cases"]) for k, v in report["families"].items()}}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
