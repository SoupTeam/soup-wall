#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Opt-in acceptance of the Linux user service on a real user manager.

No container/mock manager substitutes for this check. Only a unique temporary
profile and its owned unit are modified. Reports exclude tokens and payloads.
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
import shutil
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[1]
CORE_CASES = ("preview_install", "start_and_mcp", "crash_recovery", "stop_stays_stopped",
              "restart_limit", "modified_unit_refused", "cleanup_preserves_data")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def grade(report):
    rows = report.get("cases", [])
    names = [row.get("name") for row in rows]
    return ("error" not in report and "cleanup_error" not in report
            and report.get("manager_verified") is True and set(names) == set(CORE_CASES)
            and len(names) == len(CORE_CASES)
            and all(row.get("status") == "passed" for row in rows))


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_demo():
    spec = importlib.util.spec_from_file_location("service_mcp_demo", REPO / "scripts/mcp-admission-demo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Acceptance:
    def __init__(self, binary, report):
        self.report = report
        self.demo = load_demo()
        self.root = Path(tempfile.mkdtemp(prefix="agentfw-service-acceptance-")).resolve()
        self.home = self.root / ".agentfw"
        self.home.mkdir(mode=0o700)
        self.binary = self.root / "agentfw"
        # Build tools can hard-link artifacts. Never adopt a linked service executable.
        shutil.copyfile(binary, self.binary)
        self.binary.chmod(0o700)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTFW_")}
        self.env.update(HOME=str(self.root), AGENTFW_CLASSIFIER="rule-baseline",
                        AGENTFW_RULE_BASELINE=str(REPO / "rule_baseline/rule_baseline.py"),
                        AGENTFW_CLASSIFIER_PYTHON=sys.executable)
        self.name = None
        self.receiver = None
        self.notes = self.root / "notes"
        self.notes.mkdir()
        (self.notes / "inventory.txt").write_text("Service acceptance: 7 local widgets.", encoding="utf-8")
        self.ledger = self.root / "executed.jsonl"
        registry = self.demo.registry(self.demo.load_fixture().TOOLS)
        (self.root / "registry.json").write_bytes(registry)
        (self.root / "policy.yaml").write_text(self.demo.POLICY, encoding="utf-8")
        config = {"port": self.demo.free_port(), "enforce": True, "policy": str(self.root / "policy.yaml"),
                  "native": {"registry_path": str(self.root / "registry.json"),
                             "registry_sha256": hashlib.sha256(registry).hexdigest()}}
        (self.home / "config.yaml").write_text(json.dumps(config), encoding="utf-8")
        self.expected_config = sha(self.home / "config.yaml")
        (self.home / "unrelated.txt").write_text("preserve", encoding="utf-8")
        self.report.update(profile=str(self.home), binary_sha256=sha(self.binary),
                           config_sha256=self.expected_config, registry_sha256=config["native"]["registry_sha256"])

    def command(self, *args, success=True, env=None):
        result = subprocess.run([str(self.binary), *map(str, args)], env=env or self.env,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=100)
        require((result.returncode == 0) == success, f"unexpected exit for {args[0]} {args[-1] if args[0] == 'service' else args[1]}: {result.returncode}")
        return result.stdout

    def service(self, action, **kwargs):
        return self.command("service", "--home", self.home, action, **kwargs)

    def inspect(self):
        return json.loads(self.service("inspect"))

    def systemctl(self, *args):
        result = subprocess.run(["/usr/bin/systemctl", "--user", "--no-pager", *args, self.name],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
        require(result.returncode == 0, f"systemctl {args[0]} failed: {result.returncode}")

    def wait_ready(self, old=None):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            observed = self.inspect()
            if (observed.get("ready") is True and observed.get("systemd", {}).get("ActiveState") == "active"
                    and (old is None or observed["health"]["instance"] != old["instance"])):
                return observed["health"]
            time.sleep(.2)
        raise AssertionError("authenticated service readiness timed out")

    def mcp(self):
        if self.receiver is None:
            self.receiver = self.demo.Receiver()
        command = [str(self.binary), "mcp", "--native-admission", "--id", "service-acceptance", "--",
                   sys.executable, "-I", "-u", str(self.demo.FIXTURE), "--notes", str(self.notes),
                   "--ledger", str(self.ledger), "--recipient", self.receiver.url]
        results = []
        with open(os.devnull, "wb") as diagnostics:
            harness = self.demo.Harness(command, self.env, diagnostics)
            try:
                initialized = harness.send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                    "protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "service-acceptance", "version": "1"}}}))
                require(initialized is not None, "MCP initialize failed")
                harness.send('{"jsonrpc":"2.0","method":"notifications/initialized"}', reply=False)
                listed = harness.send('{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
                require(listed is not None and "result" in json.loads(listed), "pinned manifest was not delivered")
                for call_id, tool, expected in [(3, "read_document", "allow"), (4, "delete_note", "deny")]:
                    before = len(self.demo.lines(self.ledger))
                    started = time.monotonic()
                    frame, raw = harness.call(call_id, tool, {"name": "inventory"})
                    require(raw is not None, "MCP result was not delivered")
                    reply = json.loads(raw)
                    result = reply.get("result", {})
                    text = reply.get("error", {}).get("message") or (result.get("content") or [{}])[0].get("text", "")
                    outcome = self.demo.outcome_of(text, bool(reply.get("error")) or result.get("isError"))
                    ledger = self.demo.lines(self.ledger)[before:]
                    require(outcome == expected and reply.get("id") == call_id, "MCP verdict or call ID mismatch")
                    require(len(ledger) == (1 if expected == "allow" else 0), "independent execution ledger mismatch")
                    if expected == "allow":
                        require(ledger == [frame.encode() + b"\n"], "original arguments or call identifier changed")
                        require(raw == self.demo.lines(self.ledger.with_suffix(".responses"))[-1], "original allowed result changed")
                    require((self.notes / "inventory.txt").exists(), "denied deletion reached the executor")
                    results.append({"expected": expected, "actual": outcome, "execution_count": len(ledger),
                                    "id_preserved": True, "latency_ms": round((time.monotonic()-started)*1000, 2)})
            finally:
                harness.close()
        return results

    def preview_install(self):
        self.command("lifecycle", "install", "one", self.binary, "--sha256", sha(self.binary))
        preview = json.loads(self.service("preview"))
        require(not (self.home / "service").exists(), "preview mutated the profile")
        self.name = preview["unit_name"]
        self.unit = Path(preview["unit_path"])
        self.service("install")
        self.service("install")
        state = self.inspect()
        require(state["ready"] is False and state["systemd"]["UnitFileState"] == "static", "installation started or enabled the service")
        return {"unit_name": self.name, "autostart": False}

    def start_and_mcp(self):
        self.service("start")
        health = self.wait_ready()
        self.token = (self.home / "token").read_text().strip()
        self.audit_before = (self.home / "audit.jsonl").read_bytes() if (self.home / "audit.jsonl").exists() else b""
        return {"health": health, "mcp": self.mcp()}

    def crash_recovery(self):
        before = self.wait_ready()
        start = time.monotonic()
        self.systemctl("kill", "--kill-whom=main", "--signal=SIGKILL")
        after = self.wait_ready(before)
        require(before["pid"] != after["pid"], "crash recovery did not replace the PID")
        return {"before": before, "after": after, "recovery_ms": round((time.monotonic()-start)*1000, 2), "mcp": self.mcp()}

    def stop_stays_stopped(self):
        self.service("stop")
        time.sleep(4)
        state = self.inspect()
        require(state["ready"] is False and state["systemd"]["MainPID"] == "0"
                and state["systemd"]["ActiveState"] == "inactive", "explicit stop was not preserved")
        return {"observed_stopped_seconds": 4}

    def restart_limit(self):
        # A stopped static unit may be garbage-collected; do not reset its counters.
        started_at = time.time()
        self.service("start")
        starts = []
        for index in range(3):
            starts.append(self.wait_ready())
            self.systemctl("kill", "--kill-whom=main", "--signal=SIGKILL")
            if index < 2:
                self.wait_ready(starts[-1])
        deadline = time.monotonic()+40
        while time.monotonic() < deadline:
            state = self.inspect()
            journal = subprocess.run(["journalctl", "--user", "-u", self.name, "--since", f"@{started_at:.6f}",
                                      "--output=json", "--no-pager", "-n", "80"], capture_output=True, text=True, timeout=10)
            limit_seen = journal.returncode == 0 and any(
                event.get("USER_UNIT") == self.name and event.get("CODE_FUNC") == "unit_test_start_limit"
                and event.get("SYSLOG_IDENTIFIER") == "systemd" and event.get("_UID") == str(os.getuid())
                for event in (json.loads(line) for line in journal.stdout.splitlines()))
            if limit_seen and state.get("systemd", {}).get("ActiveState") == "failed":
                require(state["ready"] is False and state["systemd"]["MainPID"] == "0", "rate-limited unit is still running")
                self.service("stop")
                return {"starts": starts, "result": state["systemd"]["Result"],
                        "start_limit_confirmed_by_manager_journal": True}
            time.sleep(.2)
        raise AssertionError("three crashes did not reach the configured start limit")

    def modified_unit_refused(self):
        original = self.unit.read_bytes()
        try:
            self.unit.write_bytes(original+b"\n# unexpected modification\n")
            self.service("start", success=False)
            self.service("uninstall", success=False)
            require(self.unit.exists(), "modified unit was deleted")
            require(self.inspect()["ready"] is False, "modified unit was accepted")
        finally:
            self.unit.write_bytes(original)
            # The test restores its deliberate edit; the production CLI correctly
            # refuses a stale loaded definition until an operator reloads it.
            subprocess.run(["/usr/bin/systemctl", "--user", "daemon-reload"], check=True,
                           capture_output=True, timeout=45)
        return {"modified_unit_preserved": True}

    def cleanup_preserves_data(self):
        audit = (self.home / "audit.jsonl").read_bytes()
        self.service("uninstall")
        self.service("uninstall")
        require(not self.unit.exists() and not (self.home / "service/ownership.json").exists(), "owned registration remains")
        require(sha(self.home / "config.yaml") == self.expected_config, "configuration changed")
        require((self.home / "token").read_text().strip() == self.token, "token changed")
        require((self.home / "audit.jsonl").read_bytes() == audit, "audit changed during uninstall")
        require((self.home / "unrelated.txt").read_text() == "preserve", "unrelated file changed")
        require((self.home / "versions/agentfw-one").exists(), "uninstall deleted installed versions")
        encoded = json.dumps(self.report).encode()
        require(self.token.encode() not in encoded and b"Service acceptance: 7 local widgets." not in encoded, "report contains token or payload")
        return {"configuration_preserved": True, "token_preserved": True, "audit_preserved": True,
                "versions_preserved": True, "diagnostics_sanitized": True}

    def cleanup(self):
        if self.receiver:
            self.receiver.close()
        if (self.home / "service/ownership.json").exists():
            self.service("uninstall")
        shutil.rmtree(self.root)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly authorize a unique temporary user service")
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.run:
        parser.error("no changes made: pass --run to execute the real-manager acceptance")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        report = {"format_version": 1, "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
                  "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=REPO)),
                  "recorded_at": datetime.now(timezone.utc).isoformat(), "environment": {"platform": platform.platform(), "uid": os.getuid()},
                  "manager_verified": False, "cases": [], "limitations": ["Selected trusted local MCP fixture; no arbitrary-server containment claim."]}
        runner = None
        try:
            manager = subprocess.run(["/usr/bin/systemctl", "--user", "show", "--property=Version"], capture_output=True, text=True, timeout=15)
            require(manager.returncode == 0 and manager.stdout.startswith("Version="), "real user manager is unavailable; acceptance remains unverified")
            report["environment"]["systemd"] = manager.stdout.strip()
            report["manager_verified"] = True
            runner = Acceptance(args.agentfw.resolve(strict=True), report)
            for name in CORE_CASES:
                started = time.monotonic()
                try:
                    evidence = getattr(runner, name)()
                    row = {"name": name, "status": "passed", "evidence": evidence}
                except Exception as error:
                    row = {"name": name, "status": "failed", "error": str(error)}
                    report["cases"].append(row)
                    raise
                row["elapsed_ms"] = round((time.monotonic()-started)*1000, 2)
                report["cases"].append(row)
                print(f"{name}: passed", flush=True)
        except Exception as error:
            report["error"] = str(error)
        finally:
            if runner:
                try:
                    runner.cleanup()
                except Exception:
                    report["cleanup_error"] = "owned temporary service could not be removed; inspect the recorded profile"
            seen = {row["name"] for row in report["cases"]}
            report["cases"].extend({"name": name, "status": "not_run"} for name in CORE_CASES if name not in seen)
            report["passed"] = grade(report) and "cleanup_error" not in report
            json.dump(report, output, indent=2)
            output.write("\n")
        print(f"Report: {args.output}; passed={report['passed']}")
        return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
