#!/usr/bin/env python3
"""Exercise terminal decisions through the actual Claude host and original MCP servers."""
from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import signal
import subprocess
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("inbox_original_ask", ROOT / "scripts/qualify-pilot-ask.py")
ASK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ASK)
require = ASK.require


class Terminal:
    def __init__(self, pilot):
        import pty
        import termios
        master, slave = pty.openpty()
        settings = termios.tcgetattr(slave)
        settings[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, settings)
        self.master, self.text, self.cursor, self.closed = master, "", 0, False
        command = [str(pilot.setup.binary), "pilot-approval", "--home", str(pilot.setup.home),
                   "--run", pilot.run_id, "watch", "--refresh-seconds", "1"]
        try:
            self.process = subprocess.Popen(command, cwd=pilot.root, env=pilot.setup.env,
                stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        finally:
            os.close(slave)
        self.expect("Each decision needs inspection.")

    def read(self, seconds=.1):
        if select.select([self.master], [], [], seconds)[0]:
            try:
                data = os.read(self.master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    return False
                raise
            require(len(self.text) + len(data) <= 1024 * 1024, "terminal_capture_limit")
            self.text += data.decode("ascii", errors="strict")
            return bool(data)
        return True

    def expect(self, marker, seconds=10):
        deadline = time.monotonic() + seconds
        while marker not in self.text[self.cursor:]:
            require(time.monotonic() < deadline, "terminal_marker_timeout")
            if not self.read():
                require(marker in self.text[self.cursor:], "terminal_closed_before_marker")
        end = self.text.index(marker, self.cursor) + len(marker)
        result, self.cursor = self.text[self.cursor:end], end
        return result

    def send(self, command):
        require(len(command) <= 128 and command.isascii(), "harness_command_bound")
        os.write(self.master, command.encode() + b"\n")

    def inspect(self, identifier, number):
        self.expect(identifier)
        self.send(f"inspect {number}")
        shown = self.expect("Type approve or reject for this inspected binding.")
        decoder = json.JSONDecoder()
        for offset, char in enumerate(shown):
            if char != "{":
                continue
            try:
                value, _ = decoder.raw_decode(shown[offset:])
            except ValueError:
                continue
            if value.get("pending_id") == identifier and "args" in value:
                return value
        raise ValueError("complete_inspection_missing")

    def close(self):
        if self.closed:
            return
        if self.process.poll() is None:
            self.send("quit")
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        while self.read(0):
            if not select.select([self.master], [], [], 0)[0]:
                break
        os.close(self.master)
        self.closed = True


class InboxPilot(ASK.Pilot):
    terminals = []
    observations = []

    def __init__(self, *args, **kwargs):
        self.watcher = None
        self.guards_checked = False
        super().__init__(*args, **kwargs)

    def open(self):
        terminal = Terminal(self)
        self.terminals.append(terminal)
        return terminal

    def waiting(self):
        row = super().waiting()
        if self.watcher is None:
            self.watcher = self.open()
        return row

    def check_exit_controls(self):
        terminal = self.open()
        terminal.send("approve")
        terminal.expect("Use inspect N, then approve or reject;")
        terminal.send("")
        os.write(terminal.master, b"\x04")
        require(terminal.process.wait(timeout=5) == 0, "eof_did_not_close_watcher")
        require(self.process.poll() is None and self.undispatched(), "eof_affected_run")
        terminal = self.open()
        os.kill(terminal.process.pid, signal.SIGINT)
        require(terminal.process.wait(timeout=5) == -signal.SIGINT, "watcher_sigint_outcome")
        require(self.process.poll() is None and self.undispatched(), "sigint_affected_run")
        self.observations.append({"profile": self.kind, "case": "empty_uninspected_eof_sigint",
                                  "passed": True, "dispatched": 0, "run_remained_live": True})
        self.guards_checked = True

    def operator(self, *words, success=True, without_home=False):
        if words[0] not in ("inspect", "approve", "reject") or not success:
            return super().operator(*words, success=success, without_home=without_home)
        if not self.guards_checked:
            self.check_exit_controls()
        if self.watcher is None or self.watcher.process.poll() is not None:
            self.watcher = self.open()
        if words[0] == "inspect":
            rows = super().operator("list")
            number = next(i + 1 for i, row in enumerate(rows) if row["pending_id"] == words[1])
            return self.watcher.inspect(words[1], number)
        if words[0] == "approve":
            rows = super().operator("list")
            number = next(i + 1 for i, row in enumerate(rows) if row["pending_id"] == words[1])
            peer = self.open()
            peer.inspect(words[1], number)
            watchers = (self.watcher, peer)
            offsets = [len(w.text) for w in watchers]
            for watcher in watchers:
                watcher.send("approve")
            deadline = time.monotonic() + 8
            marker = '"decision":"approve"'
            while not any(marker in w.text[offset:] for w, offset in zip(watchers, offsets)):
                require(time.monotonic() < deadline, "concurrent_decision_timeout")
                for watcher in watchers:
                    watcher.read(.05)
            peer.close()
            self.watcher.read(.1)
            submitted = sum(w.text[offset:].count(marker) for w, offset in zip(watchers, offsets))
            require(submitted == 1, "concurrent_decision_not_single_use")
            self.observations.append({"profile": self.kind, "case": "concurrent_terminal_approval",
                                      "submitted": submitted, "passed": True})
        else:
            self.watcher.send("reject")
            self.watcher.expect('"state":"rejected"')
        self.observations.append({"profile": self.kind, "case": "terminal_" + words[0], "passed": True})
        return {"state": "decision_submitted" if words[0] == "approve" else "rejected"}

    def close(self):
        if self.watcher and self.watcher.process.poll() is None and self.process.poll() is not None:
            try:
                self.watcher.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise ValueError("watcher_survived_unavailable_run") from None
        if self.watcher:
            self.observations.append({"profile": self.kind, "case": "watcher_after_run",
                                      "exited": self.watcher.process.poll() is not None,
                                      "passed": self.watcher.process.poll() is not None})
        super().close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("agentfw", "git-launcher", "claude", "node", "npm", "bwrap", "git", "strace", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.output, 0o700)
    report = {"contract_version": "sw-ask-inbox-acceptance/1", "status": "incomplete",
              "real_host_executed": False, "scripted_owned_provider": True, "paid_api_calls": 0,
              "physical_human_presence_proven": False, "platform": platform.system(),
              "release": platform.release(), "container": Path("/.dockerenv").exists()}
    try:
        source = ASK.BASE.source()
        os_release = platform.freedesktop_os_release()
        report["os"] = {key: os_release.get(key) for key in ("ID", "VERSION_ID")}
        require(os_release.get("ID") == "ubuntu" and os_release.get("VERSION_ID") == "24.04"
                and not report["container"], "native_ubuntu_2404_required")
        require(source["commit"] == args.expected_commit and not source["dirty"], "exact_clean_source_required")
        report["expected_commit"] = args.expected_commit
        with tempfile.TemporaryDirectory(prefix="sou135-private-") as private:
            ASK.Pilot = InboxPilot
            try:
                ASK.qualify(args, Path(private), report)
            finally:
                for terminal in InboxPilot.terminals:
                    terminal.close()
                report["terminal_controls"] = InboxPilot.observations
                report["transcript_sha256"] = [hashlib.sha256(t.text.encode()).hexdigest()
                                                for t in InboxPilot.terminals]
                report["raw_transcripts_exported"] = False
        require(any(r["case"] == "terminal_approve" for r in report["terminal_controls"]), "approval_not_exercised")
        require(any(r["case"] == "terminal_reject" for r in report["terminal_controls"]), "rejection_not_exercised")
        require(len(report["cases"]) == 14 and all(r["passed"] for r in report["cases"]), "incomplete_original_cases")
    except Exception as error:
        report.update(status="failed", error_type=type(error).__name__,
            error_location=[{"function": frame.name, "line": frame.lineno}
                            for frame in traceback.extract_tb(error.__traceback__)[-6:]])
        if isinstance(error, ValueError) and str(error).isascii() and len(str(error)) < 128:
            report["error"] = str(error)
    ASK.BASE.write(args.output / "qualification.json", report)
    os.chmod(args.output / "qualification.json", 0o600)
    print(json.dumps({key: report.get(key) for key in ("status", "error", "error_type")}))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
