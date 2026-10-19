# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import time

SPEC = importlib.util.spec_from_file_location("windows_self_test", Path(__file__).with_name("test-windows-self-test.py"))
BOUNDARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOUNDARY)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_live_journal(path):
    import msvcrt
    handle = BOUNDARY.K.CreateFileW(str(path), 0x80000000, 7, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError("live journal is unavailable")
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        BOUNDARY.K.CloseHandle(handle)
        raise
    with os.fdopen(descriptor, "rb") as stream:
        data = stream.read(256 * 1024 + 1)
    require(len(data) <= 256 * 1024, "live journal exceeds its bound")
    return json.loads(data)


class Acceptance:
    def __init__(self, args, root):
        self.args, self.root, self.results = args, root, []
        whoami = Path(os.environ["SystemRoot"]) / "System32/whoami.exe"
        identity = subprocess.run([str(whoami), "/user", "/fo", "csv", "/nh"], capture_output=True, check=True, timeout=10)
        self.sid = re.findall(rb"S-1-5-21-(?:[0-9]+-){3}[0-9]+", identity.stdout)[0].decode("ascii")
        self.agent = root / "agentfw.exe"
        shutil.copyfile(args.agent, self.agent)
        self.seal(self.agent)
        runtime = root / "python"
        shutil.copytree(Path(sys.executable).parent, runtime,
                        ignore=shutil.ignore_patterns("site-packages", "__pycache__", "Scripts", "Doc", "tcl"))
        self.seal(runtime)
        self.python = runtime / Path(sys.executable).name
        self.seal(self.python)
        self.baseline = root / "rule_baseline.py"
        shutil.copyfile(args.baseline, self.baseline)
        self.seal(self.baseline)
        self.policy = root / "policy.yaml"
        shutil.copyfile(args.policy, self.policy)
        self.seal(self.policy)
        self.registry = root / "registry.json"
        tools = [
            {"name": "read_document", "schema": {"type": "object", "properties": {"name": {"type": "string"}},
                "required": ["name"], "additionalProperties": False}, "action": "read_only", "result": "untrusted", "egress": []},
            {"name": "send_http", "schema": {"type": "object", "properties": {"url": {"type": "string"}, "body": {"type": "string"}},
                "required": ["url", "body"], "additionalProperties": False}, "action": "network", "result": "local_system",
                "egress": [{"pointer": "/url", "kind": "url_host", "optional": False}]},
        ]
        self.write(self.registry, json.dumps({"contract_version": "sw-native/1", "registry_id": "sou90-controlled-notes", "tools": [
            {"name": tool["name"], "schema_sha256": hashlib.sha256(json.dumps(tool["schema"], sort_keys=True,
                separators=(",", ":")).encode()).hexdigest(), "action_class": tool["action"],
             "result_provenance": tool["result"], "egress": tool["egress"]} for tool in tools]}).encode())
        self.state = self.directory("state")
        self.profile = self.directory("profile")
        self.home = self.profile / ".agentfw"
        self.notes = self.directory("notes")
        self.write(self.notes / "project-notes.txt", b"Controlled onboarding notes.")
        self.write(self.notes / "checklist.txt", b"Controlled continuation notes.")
        self.write(self.notes / "vendor-reply.txt", b"Controlled vendor note.")
        self.receiver = socket.socket()
        self.receiver.bind(("127.0.0.1", 0))
        self.receiver.listen()
        self.receiver.setblocking(False)
        self.ledger = root / "executed.jsonl"
        self.responses = root / "responses.jsonl"
        self.write(self.ledger, b"")
        self.write(self.responses, b"")
        self.host = root / "host.json"
        server = {"command": str(self.agent), "args": ["self-test-fixture", "--notes", str(self.notes),
            "--ledger", str(self.ledger), "--responses", str(self.responses),
            "--recipient", f"http://127.0.0.1:{self.receiver.getsockname()[1]}/capture"]}
        self.original = {"mcpServers": {"notes": server, "unrelated": {"command": "operator-sentinel", "env": {"KEEP": "unchanged"}}},
                         "settings": {"theme": "operator-sentinel"}}
        self.write(self.host, json.dumps(self.original).encode())
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.values = {
            "agent": self.agent, "agent-sha256": digest(self.agent), "python": self.python,
            "python-sha256": digest(self.python), "classifier": self.baseline,
            "classifier-sha256": digest(self.baseline), "registry": self.registry,
            "registry-sha256": digest(self.registry), "policy": self.policy, "policy-sha256": digest(self.policy),
            "host-config": self.host, "server": "notes", "home": self.home, "state-directory": self.state,
            "workspace": self.root, "report": self.root / "self-test.json", "port": self.port,
        }
        self.operator_profile = self.directory("unrelated-profile")
        self.operator_file = self.operator_profile / "operator.json"
        self.write(self.operator_file, b'{"operator-sentinel":"unchanged"}')
        self.operator_hash = digest(self.operator_file)
        self.env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", TEMP=str(root), TMP=str(root),
                        USERPROFILE=str(self.operator_profile))
        self.unrelated = subprocess.Popen([sys.executable, "-I", "-c", "import sys; sys.stdin.buffer.read()"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.confirmation = None

    def seal(self, path):
        require(path.is_relative_to(self.root), "ACL target is outside the owned fixture")
        flags = "(OI)(CI)F" if path.is_dir() else "F"
        result = subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
            f"*{self.sid}:{flags}", f"*S-1-5-18:{flags}"], capture_output=True, timeout=15)
        require(result.returncode == 0, "could not restrict a fresh fixture path")

    def directory(self, name):
        path = self.root / name
        path.mkdir()
        self.seal(path)
        return path

    def write(self, path, value):
        with path.open("xb") as stream:
            stream.write(value)
        self.seal(path)

    def command(self, operation, **overrides):
        if operation in ("preview", "apply"):
            values = dict(self.values, **overrides)
        else:
            values = {"state-directory": self.state}
        return [str(self.agent), "onboard-windows", operation] + [
            str(item) for key, value in values.items() for item in ("--" + key, value)]

    def invoke(self, operation, success=True, **overrides):
        result = subprocess.run(self.command(operation, **overrides), cwd=self.root, env=self.env,
                                capture_output=True, timeout=180)
        if success and result.returncode != 0:
            raise RuntimeError(result.stderr.decode(errors="replace")[-2000:])
        require(success or result.returncode != 0, "refused operation unexpectedly succeeded")
        return json.loads(result.stdout) if success else None

    def record(self, name, function):
        started = time.monotonic()
        try:
            observed = function()
            self.results.append({"id": name, "status": "passed", "duration_ms": round((time.monotonic() - started) * 1000),
                                 "observed": observed})
            print("PASS", name, flush=True)
        except Exception as error:
            self.results.append({"id": name, "status": "failed", "error_type": type(error).__name__})
            print("FAIL", name, str(error), flush=True)
            raise

    def preview(self):
        before = digest(self.host)
        result = self.invoke("preview")
        require(digest(self.host) == before and not self.home.exists() and not (self.state / "onboarding.json").exists(),
                "preview changed operator state")
        self.confirmation = result["confirmation"]
        return {"read_only": True, "confirmation_bound": True}

    def stale(self):
        self.invoke("apply", success=False, confirm="0" * 64)
        require(not self.home.exists(), "invalid confirmation created an Agent home")
        before = self.host.read_bytes()
        value = json.loads(before)
        value["settings"]["theme"] = "edited after preview"
        self.host.write_text(json.dumps(value), encoding="utf-8")
        changed = digest(self.host)
        try:
            self.invoke("apply", success=False, confirm=self.confirmation)
            require(not self.home.exists() and digest(self.host) == changed, "stale preview changed operator state")
        finally:
            self.host.write_bytes(before)
        return {"no_agent_home_created": True, "edited_host_preserved": True}

    def wrong_hashes(self):
        for key in ("agent-sha256", "python-sha256", "classifier-sha256", "registry-sha256", "policy-sha256"):
            self.invoke("preview", success=False, **{key: "0" * 64})
        return {"five_wrong_hashes_refused": True}

    def occupied(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.setblocking(False)
            self.invoke("preview", success=False, port=listener.getsockname()[1])
            try:
                connection, _ = listener.accept()
                connection.close()
                raise AssertionError("foreign listener received preview traffic")
            except BlockingIOError:
                pass
        return {"foreign_port_preserved": True, "connections": 0}

    def apply(self):
        result = self.invoke("apply", confirm=self.confirmation)
        require(result["configured"] and result["daemon_verified"], "apply did not verify the real daemon")
        require(result["synthetic_protection"] == "not_witnessed", "apply inferred synthetic protection")
        require(result["host_reload"] == "pending_explicit_host_reload", "host reload was inferred")
        return {"configured": True, "daemon_verified": True, "host_reload_pending": True}

    def verify(self):
        result = self.invoke("verify")
        require(result["synthetic_protection"] == "witnessed" and result["daemon_verified"], "self-test did not pass")
        report = read(self.root / "self-test.json")
        require(report["result"] == "passed" and report["cleanup"]["final_effects"]["no_unexpected_effects"], "invalid independent self-test effects")
        shutil.copyfile(self.root / "self-test.json", self.args.out / "self-test.json")
        return {"self_test_scenarios": len(report["scenarios"]), "protected_send_executions": report["scenarios"][2]["observed"]["mcp_child_executions"]}

    def probe(self):
        lifecycle = read(self.home / "versions" / "lifecycle.json")
        agent = self.home / "versions" / lifecycle["active"]["binary"]
        command = [str(agent), "mcp-connection", "inspect", "--path", str(self.host), "--server", "notes",
                   "--home", str(self.home), "--agent", str(agent), "--runtime", str(self.home / "runtime.json"),
                   "--probe-tool", "read_document", "--probe-args", '{"name":"project-notes"}']
        result = subprocess.run(command, cwd=self.root, env=self.env, capture_output=True, timeout=20)
        require(result.returncode == 0 and json.loads(result.stdout)["status"] == "verified_for_this_probe", "configured connection useful read failed")
        calls = [json.loads(line) for line in self.ledger.read_text().splitlines()]
        require(calls and all(call["params"]["name"] == "read_document" for call in calls), "unexpected MCP child execution")
        return {"useful_read_executed": True, "no_send_execution": True}

    def conflict(self):
        before = self.host.read_bytes()
        changed = json.loads(before)
        changed["mcpServers"]["notes"]["args"].append("--operator-edit")
        self.host.write_text(json.dumps(changed), encoding="utf-8")
        modified = digest(self.host)
        try:
            self.invoke("recover", success=False)
            require(digest(self.host) == modified, "selected-entry conflict was overwritten")
        finally:
            self.host.write_bytes(before)
        baseline = self.baseline.read_bytes()
        self.baseline.write_bytes(baseline + b"\nraise RuntimeError('controlled operator edit')\n")
        changed = digest(self.baseline)
        try:
            self.invoke("recover", success=False)
            require(digest(self.baseline) == changed, "changed classifier source was overwritten")
        finally:
            self.baseline.write_bytes(baseline)
        return {"operator_edit_preserved": True, "classifier_edit_refused": True}

    def daemon_loss(self):
        process = read(self.home / "versions" / "lifecycle.json")["process"]
        kernel = BOUNDARY.K
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateProcess.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x100001, False, process["pid"])
        require(handle, "owned daemon process handle unavailable")
        try:
            require(kernel.TerminateProcess(handle, 1), "could not interrupt the owned daemon")
            require(kernel.WaitForSingleObject(handle, 10000) == 0, "owned daemon did not exit")
        finally:
            kernel.CloseHandle(handle)
        with socket.socket() as foreign:
            foreign.bind(("127.0.0.1", self.port))
            foreign.listen()
            foreign.setblocking(False)
            self.invoke("recover", success=False)
            try:
                connection, _ = foreign.accept()
                connection.close()
                raise AssertionError("recovery sent credentials to a foreign listener")
            except BlockingIOError:
                pass
        self.invoke("verify", success=False)
        before = digest(self.ledger)
        entry = read(self.host)["mcpServers"]["notes"]
        frames = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "onboarding", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "send_http", "arguments": {
                "url": f"http://127.0.0.1:{self.receiver.getsockname()[1]}/capture", "body": "synthetic onboarding test"}}},
        ]
        refused = subprocess.run([entry["command"], *entry["args"]], cwd=self.root, env=self.env,
            input=b"".join(json.dumps(frame).encode() + b"\n" for frame in frames), capture_output=True, timeout=20)
        require(refused.returncode != 0 and digest(self.ledger) == before,
                "daemon loss allowed a call into the original MCP child")
        try:
            connection, _ = self.receiver.accept()
            connection.close()
            raise AssertionError("daemon-loss send reached receiver")
        except BlockingIOError:
            pass
        result = self.invoke("recover")
        require(result["configured"] and result["daemon_verified"], "recovery did not restore the owned daemon")
        return {"failed_verification_refused": True, "recovery_verified": True,
                "daemon_loss_child_executions": 0, "daemon_loss_receiver_connections": 0,
                "foreign_recovery_listener_connections": 0}

    def sentinels(self):
        current = read(self.host)
        require(current["mcpServers"]["unrelated"] == self.original["mcpServers"]["unrelated"]
                and current["settings"] == self.original["settings"], "unrelated host settings changed")
        require(self.unrelated.poll() is None, "unrelated process stopped")
        require(digest(self.operator_file) == self.operator_hash, "unrelated operator file changed")
        try:
            connection, _ = self.receiver.accept()
            connection.close()
            raise AssertionError("unexpected original-server send reached receiver")
        except BlockingIOError:
            pass
        return {"unrelated_config_preserved": True, "unrelated_process_preserved": True,
                "operator_file_preserved": True, "receiver_connections": 0}

    def remove(self):
        result = self.invoke("remove")
        require(result["phase"] == "removed", "removal did not finish")
        require(read(self.host) == self.original, "removal did not restore the original selected entry")
        repeated = self.invoke("remove")
        require(repeated["phase"] == "removed", "removal is not idempotent")
        require(self.unrelated.poll() is None and digest(self.operator_file) == self.operator_hash,
                "removal affected an unrelated operator process or file")
        return {"original_entry_restored": True, "idempotent": True}

    def interruption(self, phase):
        saved = (self.values, self.state, self.home, self.host)
        case = self.directory("interrupted-" + phase)
        for name in ("state", "profile"):
            (case / name).mkdir()
            self.seal(case / name)
        self.state = case / "state"
        self.home = case / "profile" / ".agentfw"
        self.host = case / "host.json"
        self.write(self.host, json.dumps(self.original).encode())
        self.values = dict(self.values, **{"state-directory": self.state, "home": self.home,
            "host-config": self.host, "report": case / "self-test.json"})
        child = None
        try:
            confirmation = self.invoke("preview")["confirmation"]
            child = subprocess.Popen(self.command("apply", confirm=confirmation, **{"pause-after": phase}),
                cwd=self.root, env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 120
            reached = False
            while time.monotonic() < deadline and child.poll() is None:
                journal = self.state / "onboarding.json"
                if journal.exists():
                    try:
                        reached = read_live_journal(journal)["phase"] == phase
                    except (OSError, ValueError):
                        continue
                    if reached:
                        break
                time.sleep(0.02)
            require(reached and child.poll() is None, "apply did not reach the requested live checkpoint")
            at_checkpoint = read(self.host)["mcpServers"]["notes"]
            require((at_checkpoint == self.original["mcpServers"]["notes"]) == (phase != "connected"),
                    "host publication did not match the checkpoint")
            child.kill()
            child.communicate(timeout=10)
            recovered = self.invoke("recover")
            require(recovered["configured"] and recovered["daemon_verified"], "interrupted setup did not recover")
            self.probe()
            self.invoke("remove")
            require(read(self.host) == self.original, "interrupted setup removal lost the original entry")
            return {"interrupted_at": phase, "recovered": True, "useful_read": True,
                    "expected_host_state_at_checkpoint": True, "original_entry_restored": True}
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
            try:
                if (self.state / "onboarding.json").exists():
                    self.invoke("remove")
            finally:
                self.values, self.state, self.home, self.host = saved

    def execute(self):
        cases = [
            ("read_only_preview", self.preview), ("wrong_confirmation", self.stale),
            ("five_asset_hash_refusals", self.wrong_hashes), ("foreign_port_preserved", self.occupied),
        ]
        cases += [("interrupted_" + phase, lambda phase=phase: self.interruption(phase))
                  for phase in ("prepared", "configured", "installed", "daemon_started", "publishing", "connected")]
        cases += [
            ("transactional_apply", self.apply), ("installed_self_test", self.verify),
            ("configured_connection_useful_read", self.probe), ("operator_conflict_preserved", self.conflict),
            ("daemon_loss_and_recovery", self.daemon_loss), ("useful_read_after_recovery", self.probe),
            ("unrelated_settings_and_receiver", self.sentinels), ("owned_idempotent_removal", self.remove),
        ]
        for name, function in cases:
            self.record(name, function)

    def close(self):
        try:
            if (self.state / "onboarding.json").exists():
                self.invoke("remove")
        finally:
            self.receiver.close()
            if self.unrelated.poll() is None:
                self.unrelated.stdin.close()
                self.unrelated.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=Path(__file__).resolve().parents[1] / "crates/agent/policies/agent-default.yaml")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-commit")
    args = parser.parse_args()
    require(args.source_commit is None or re.fullmatch(r"[0-9a-f]{40}", args.source_commit), "invalid source commit")
    require(os.name == "nt" and not ctypes.windll.shell32.IsUserAnAdmin(), "a non-elevated native Windows token is required")
    require(not args.out.exists(), "fresh evidence directory required")
    args.out.mkdir(parents=True)
    with BOUNDARY.owned_stage() as root:
        suite = Acceptance(args, root)
        try:
            suite.execute()
        finally:
            try:
                suite.close()
            finally:
                report = {"schema_version": "sou90-windows-onboarding-acceptance/1",
                    "status": "passed" if len(suite.results) == 18 and all(case["status"] == "passed" for case in suite.results) else "failed",
                    "native_windows": True, "elevated": False, "platform": platform.platform(),
                    "source_commit": args.source_commit,
                    "administrator_group_present": b"S-1-5-32-544" in subprocess.run(
                        [str(Path(os.environ["SystemRoot"]) / "System32/whoami.exe"), "/groups", "/fo", "csv"],
                        capture_output=True, check=True, timeout=10).stdout,
                    "agent_sha256": digest(args.agent), "classifier_sha256": digest(args.baseline),
                    "python_sha256": digest(suite.python), "registry_sha256": digest(suite.registry),
                    "policy_sha256": digest(suite.policy), "driver_sha256": digest(__file__),
                    "checks": suite.results, "passed": sum(case["status"] == "passed" for case in suite.results),
                    "failed": sum(case["status"] == "failed" for case in suite.results)}
                (args.out / "acceptance.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
