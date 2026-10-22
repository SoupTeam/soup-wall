#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-102 prepared installed-classifier acceptance on the pinned original Linux FS MCP.

Owned synthetic data only. The real collector runs the installed rule-package
classifier with AGENTFW_CLASSIFIER_PREPARE=1 in front of the original filesystem
server. Effects are witnessed independently by a kernel syscall trace of the
original server (successful read-only opens of the exact synthetic file), never
by collector or daemon logging. Failed runs are kept by the caller.

Not demonstrated here (the installed package bytes are immutable, so no honest
worker can be made to lie): a mismatched ready identity and a late reply. Those
are covered by the worker-level tests in crates/agentfw/tests/classifier_runtime*.rs.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BASE = load("sou102_fs", ROOT / "scripts/verify-sou62-real-mcp.py")
ASK = load("sou102_witness", ROOT / "scripts/verify-sou105-selected-approval.py")
GIT = load("sou102_git", ROOT / "scripts/verify-sou68-real-mcp.py")
require, write, sha = BASE.require, BASE.write, BASE.sha
FORMAT = "sw-classifier/prepared-acceptance/1"
TEXT = BASE.TEXT
NOTES = "/workspace/notes.txt"
GIT_MARKER = "SOU-68 synthetic initial commit"
PREPARE_MAX_SECONDS = 2.5  # outer 2 s collector deadline plus scheduling slack; never raised


# ----------------------------------------------------------------- process helpers
def children(pid):
    """Children of every thread: a worker started from a blocking-pool thread is not listed under the main one."""
    found = []
    try:
        for task in Path(f"/proc/{pid}/task").iterdir():
            try:
                found.extend(int(v) for v in (task / "children").read_text().split())
            except (OSError, ValueError):
                continue
    except OSError:
        pass
    return found


def descendants(root):
    found, pending = [], [root]
    while pending:
        for child in children(pending.pop()):
            found.append(child)
            pending.append(child)
    return found


def cmdline(pid):
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return []


def running(pid):
    """A killed child stays a zombie until its parent reaps it; a zombie is not running."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return False
    return stat[stat.rfind(")") + 2:][:1] != "Z"


def wait_gone(pid, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not running(pid):
            return True
        time.sleep(0.02)
    return False


class Collector:
    def __init__(self, ctx, label, prepare, trace):
        self.ctx, self.label, self.prepare = ctx, label, prepare
        self.stderr = ctx.output / f"{label}.collector.log"
        self.trace = ctx.private / f"{label}.syscalls" if trace else None
        env = dict(ctx.env)
        if prepare:
            env["AGENTFW_CLASSIFIER_PREPARE"] = "1"
        if ctx.server == "git":
            server = [ctx.profile["runtimePath"], "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"]
        else:
            server = [ctx.profile["runtimePath"],
                      str(Path(ctx.profile["packageRoot"]) / "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"),
                      "/workspace"]
        command = [str(ctx.args.agentfw), "mcp", "--native-admission", "--id", "sou102-" + ctx.server, "--", *server]
        if trace:
            command = [str(ctx.args.strace), "-f", "-qq", "-s", "4096", "-e", "trace=openat,execve",
                       "-o", str(self.trace), "--", *command]
        self.started = time.monotonic()
        with self.stderr.open("wb") as log:
            self.client = BASE.Client(command, env, ctx.workspace, log, label)
        self.closed = None

    # -- observations
    def events(self, name):
        result = []
        if self.stderr.exists():
            for line in self.stderr.read_bytes().splitlines():
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if isinstance(value, dict) and value.get("event") == name:
                    result.append(value)
        return result

    def pid(self):
        if self.trace is None:
            return self.client.process.pid
        for pid in descendants(self.client.process.pid):
            argv = cmdline(pid)
            if argv and argv[0] == str(self.ctx.args.agentfw).encode() and b"mcp" in argv:
                return pid
        raise ValueError("collector process not found")

    def workers(self):
        interpreter = str(self.ctx.python).encode()
        result = []
        for pid in descendants(self.pid()):
            argv = cmdline(pid)
            try:
                exe = os.readlink(f"/proc/{pid}/exe").encode()
            except OSError:
                continue
            if exe == interpreter and b"-I" in argv and running(pid):
                result.append(pid)
        return result

    def reads(self, evidence=None):
        require(self.trace is not None, "syscall witness not enabled")
        if self.ctx.server == "git":
            return ASK.trace_effects(self.trace, "git", git_path="/mcp-runtime/git", evidence=evidence,
                                     git_revision=self.ctx.git_revision)
        return ASK.trace_effects(self.trace, "filesystem", target=NOTES, evidence=evidence)

    def wait_ready_event(self, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready = self.events("mcp_classifier_ready")
            if ready:
                return ready, time.monotonic() - self.started
            time.sleep(0.005)
        raise ValueError(self.label + ": no readiness event")

    def initialize(self):
        if self.ctx.server == "git":
            # The Git server pins a newer protocol revision than the filesystem client helper.
            protocol = "2025-11-25"
            result, _ = self.client.exchange({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": protocol, "capabilities": {}, "clientInfo": {"name": "sou102-acceptance", "version": "1"}}})
            require(result.get("result", {}).get("protocolVersion") == protocol, "original protocol pin changed")
            self.client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            listing, _ = self.client.exchange({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            assets = GIT.INSTALL.ASSETS
        else:
            listing = self.client.initialize()
            assets = BASE.INSTALL.ASSETS
        manifest = json.loads((assets / "upstream-tools-list.json").read_text())["result"]
        require(listing.get("result") == manifest, "original discovery changed")
        return time.monotonic() - self.started

    def frame(self, identifier):
        if self.ctx.server == "git":
            return {"jsonrpc": "2.0", "id": identifier, "method": "tools/call", "params": {
                "name": "git_show", "arguments": {"repo_path": "/workspace", "revision": "HEAD"}}}
        return BASE.call(identifier, {"path": NOTES})

    def useful(self, response):
        """The original server's own useful result."""
        if self.ctx.server == "git":
            result = response.get("result", {})
            require("error" not in response and not result.get("isError", False), "useful Git read refused: " + str(response)[:300])
            text = "".join(block.get("text", "") for block in result.get("content", []) if block.get("type") == "text")
            require(GIT_MARKER in text, "original Git result missing")
            return True
        return BASE.result_text(response) == TEXT

    def call(self, identifier, expect):
        before = self.reads() if self.trace else None
        began = time.monotonic()
        response, raw = self.client.exchange(self.frame(identifier))
        elapsed = time.monotonic() - began
        after = self.reads() if self.trace else None
        dispatch = [e for e in BASE.events(self.stderr) if e.get("host_call_id") == identifier and e.get("state") == "inflight"]
        row = {"id": identifier, "latency_ms": round(elapsed * 1000, 3), "response": response, "dispatch_events": dispatch,
               "reads_before": before, "reads_after": after}
        if expect == "ok":
            require(self.useful(response), "useful original result missing")
            require(dispatch and all(e["execution_dispatched"] is True for e in dispatch), "collector dispatch absent")
            if self.trace:
                require(after == before + 1, "independent witness: exactly one useful read expected")
        else:
            require(BASE.refused(response), "call was not refused: " + str(response)[:300])
            require(not dispatch, "refused call was dispatched by the collector")
            if self.trace:
                require(after == before, "independent witness: a refused call reached the original server")
            row["error"] = response.get("error", {}).get("message", "")
        return row

    def close(self):
        code = self.client.close()
        self.closed = {"exit_code": code, "transcript_pid": self.client.process.pid,
                       "forced_cleanup": self.client.forced_cleanup, "process_cleanup": self.client.process_witness.final}
        return self.closed


class Context:
    pass


# ----------------------------------------------------------------- scenarios
def installed_file(ctx):
    files = list((ctx.home / ".agentfw/classifier/packages").glob("*/rule_baseline.py"))
    require(len(files) == 1, "exactly one installed classifier package expected")
    return files[0]


def alter(path):
    original = (path.read_bytes(), path.stat().st_mode & 0o7777)
    os.chmod(path, 0o600)
    path.write_bytes(original[0] + b"# altered\n")
    return original


def restore(path, original):
    os.chmod(path, 0o600)
    path.write_bytes(original[0])
    os.chmod(path, original[1])


def scenario_main(ctx, report):
    a = Collector(ctx, "collector-a", prepare=True, trace=True)
    cases = report["cases"]
    try:
        ready, ready_after = a.wait_ready_event()
        a.initialize()
        require(len(ready) == 1 and ready[0]["readiness"]["start_sequence"] == 1, "one startup readiness expected")
        pid0 = ready[0]["readiness"]["worker_pid"]
        require(a.workers() == [pid0], "readiness must name the one running owned worker")
        require(a.reads() == 0 and not a.events("mcp_classification"), "nothing classified or read before the first call")
        cases.append({"case": "ready-before-first-call", "readiness": ready[0]["readiness"], "worker_pids": a.workers(),
                      "ready_after_start_ms": round(ready_after * 1000, 1), "passed": True})

        row = a.call(100, "ok")
        require(a.workers() == [pid0], "first call must reuse the prepared worker")
        require(len(a.events("mcp_classifier_ready")) == 1, "no second preparation for the first call")
        classified = a.events("mcp_classification")
        require(len(classified) == 1 and classified[0]["source"] == "rule-baseline/packaged-worker", "packaged worker classified")
        cases.append({"case": "first-useful-call", "worker_pid": pid0, **row, "passed": True})
        row = a.call(101, "ok")
        require(a.workers() == [pid0], "continuation reuses the same worker")
        cases.append({"case": "continuation", "worker_pid": pid0, **row, "passed": True})

        # Session isolation: a second collector on the same profile owns its own worker.
        b = Collector(ctx, "collector-b", prepare=True, trace=True)
        try:
            b_ready, _ = b.wait_ready_event()
            b.initialize()
            pid_b = b_ready[0]["readiness"]["worker_pid"]
            require(pid_b != pid0 and b.workers() == [pid_b] and a.workers() == [pid0], "workers must not be shared")
            row_b = b.call(100, "ok")
            reads_b = b.reads(ctx.output / "collector-b.witness.json")
        finally:
            b.close()
        require(wait_gone(pid_b) and running(pid0), "closing one session must not touch the other worker")
        cases.append({"case": "session-isolation", "worker_a": pid0, "worker_b": pid_b, "b_reads": reads_b, **row_b, "passed": True})
        row = a.call(102, "ok")
        require(a.workers() == [pid0], "isolated session keeps working")

        # Killed worker: replaced before the next dispatch.
        os.kill(pid0, signal.SIGKILL)
        require(wait_gone(pid0), "killed worker did not exit")
        row = a.call(103, "ok")
        workers = a.workers()
        require(len(workers) == 1 and workers[0] != pid0, f"a fresh worker must replace the killed one: old={pid0} now={workers}")
        pid1 = workers[0]
        cases.append({"case": "killed-worker-replaced-before-dispatch", "old_pid": pid0, "new_pid": pid1, **row, "passed": True})

        # Hung worker: that call is refused within the unchanged deadline, the next recovers.
        os.kill(pid1, signal.SIGSTOP)
        row = a.call(104, "refused")
        require(row["latency_ms"] < PREPARE_MAX_SECONDS * 1000, "refusal exceeded the unchanged outer deadline")
        require("classifier_" in row["error"] and "policy not reached" in row["error"], "unexpected refusal label")
        require(wait_gone(pid1), "the hung worker must be retired and reaped")
        cases.append({"case": "hung-worker-refused-within-deadline", "old_pid": pid1, **row, "passed": True})
        row = a.call(105, "ok")
        workers = a.workers()
        require(len(workers) == 1 and workers[0] != pid1, "recovery uses a fresh worker")
        pid2 = workers[0]
        cases.append({"case": "recovery-after-hang", "new_pid": pid2, **row, "passed": True})

        # Altered assets plus a lost worker: refused before dispatch, nothing started.
        path = installed_file(ctx)
        original = alter(path)
        try:
            os.kill(pid2, signal.SIGKILL)
            require(wait_gone(pid2), "worker did not exit")
            row = a.call(106, "refused")
            require("classifier_not_ready" in row["error"], "expected classifier_not_ready: " + row["error"])
            require(a.workers() == [], "no worker may be started from altered files")
            require(len(a.events("mcp_classifier_not_ready")) == 1, "one not-ready event expected")
            cases.append({"case": "altered-assets-lost-worker-refused", **row, "worker_pids": a.workers(), "passed": True})
        finally:
            restore(path, original)
        row = a.call(107, "ok")
        workers = a.workers()
        require(len(workers) == 1, "recovery after restoring the exact bytes")
        cases.append({"case": "recovery-after-restore", "new_pid": workers[0], **row, "passed": True})
        report["witness_a"] = a.reads(ctx.output / "collector-a.witness.json")
    finally:
        a.close()
    report["collector_a_cleanup"] = a.closed
    require(a.closed["exit_code"] == 0 and not a.closed["forced_cleanup"] and a.closed["process_cleanup"]["all_stopped"],
            "collector or descendants were not reaped")


def scenario_no_call_exit(ctx, report):
    c = Collector(ctx, "collector-no-call", prepare=True, trace=True)
    try:
        ready, _ = c.wait_ready_event()
        c.initialize()
        pid = ready[0]["readiness"]["worker_pid"]
        require(running(pid), "prepared worker must be running")
    finally:
        closed = c.close()
    require(closed["exit_code"] == 0 and closed["process_cleanup"]["all_stopped"] and wait_gone(pid),
            "prepared worker must be reaped when the collector exits without a call")
    report["cases"].append({"case": "reaped-when-no-call-is-made", "worker_pid": pid, "reads": c.reads(ctx.output / "collector-no-call.witness.json"),
                            "cleanup": closed, "passed": True})
    require(report["cases"][-1]["reads"] == 0, "no call, no read")


def scenario_startup_failure(ctx, report):
    path = installed_file(ctx)
    original = alter(path)
    c = None
    try:
        c = Collector(ctx, "collector-startup-failure", prepare=True, trace=True)
        failed = False
        try:
            c.client.initialize()
        except Exception as error:  # the collector must exit before serving anything
            failed = True
            message = str(error)
        require(failed, "a collector with an altered package must not serve")
        time.sleep(0.3)
    finally:
        if c is not None:
            closed = c.close()
        restore(path, original)
    log = c.stderr.read_text(errors="replace")
    require(closed["exit_code"] not in (0, None), "startup failure must exit non-zero")
    require("no longer verifies" in log and not c.events("mcp_classifier_ready"), "actionable startup error expected")
    require(c.reads() == 0 and closed["process_cleanup"]["all_stopped"], "nothing dispatched or left behind")
    report["cases"].append({"case": "startup-failure-before-any-call", "exit_code": closed["exit_code"], "client_error": message[:200],
                            "reads": 0, "cleanup": closed, "passed": True})


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))]


def summary(values):
    return {"n": len(values), "p50_ms": round(statistics.median(values), 2), "max_ms": round(max(values), 2),
            "p95_ms": round(percentile(values, 0.95), 2)} if values else {"n": 0}


def scenario_latency(ctx, report, rounds):
    out = {"rounds": rounds, "note": "No syscall tracing here: tracing would inflate process start times.",
           "lazy": {"first_call_ms": [], "warm_call_ms": [], "failures": []},
           "prepared": {"startup_to_ready_ms": [], "first_call_ms": [], "warm_call_ms": [], "failures": []}}
    for mode in ("lazy", "prepared"):
        for index in range(rounds):
            c = Collector(ctx, f"latency-{mode}-{index}", prepare=mode == "prepared", trace=False)
            try:
                if mode == "prepared":
                    _, ready_after = c.wait_ready_event()
                    out[mode]["startup_to_ready_ms"].append(ready_after * 1000)
                c.initialize()
                for number in range(4):
                    row = c.call(100 + number, "ok")
                    out[mode]["first_call_ms" if number == 0 else "warm_call_ms"].append(row["latency_ms"])
            except Exception as error:
                out[mode]["failures"].append(str(error)[:300])
            finally:
                c.close()
    for mode in ("lazy", "prepared"):
        for name in list(out[mode]):
            if name.endswith("_ms"):
                out[mode][name + "_summary"] = summary(out[mode][name])
    report["latency"] = out
    require(not out["lazy"]["failures"] and not out["prepared"]["failures"], "latency runs had failures (kept in the report)")


# ----------------------------------------------------------------- run
def run(args, report):
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "native Linux x86-64 required; no fallback/skip")
    report["source_before"] = BASE.source()
    names = ("agentfw", "bwrap", "strace") + (("git", "git_launcher") if args.server == "git" else ("node", "npm"))
    report["server"] = args.server
    report["runtime"] = {name: sha(getattr(args, name)) for name in names}
    ctx = Context()
    ctx.args, ctx.output, ctx.server = args, args.output, args.server
    ctx.python = args.python
    report["python"] = {"path": str(args.python), "sha256": sha(args.python), "version": platform.python_version()}
    ctx.workspace, ctx.home, installed = args.output / "workspace", args.output / "home", args.output / "installed"
    ctx.private = args.output.parent / ("." + args.output.name + "-private-syscalls")
    ctx.home.mkdir(mode=0o700); ctx.private.mkdir(mode=0o700)
    env = BASE.environment(ctx.home)
    if args.server == "git":
        env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_OPTIONAL_LOCKS="0",
                   GIT_TERMINAL_PROMPT="0", GIT_PYTHON_GIT_EXECUTABLE=str(args.git))
        GIT.prepare_repo(ctx.workspace, args.git, env)
        ctx.git_revision = subprocess.check_output([str(args.git), "rev-parse", "HEAD"], cwd=ctx.workspace, env=env,
                                                   text=True, timeout=5).strip()
        report["git_revision"] = ctx.git_revision
        GIT.INSTALL.install(installed, ctx.workspace, args.git, sha(args.git), args.bwrap, args.git_launcher)
    else:
        ctx.workspace.mkdir(mode=0o700)
        (ctx.workspace / "notes.txt").write_text(TEXT, encoding="utf-8")
        BASE.INSTALL.install(installed, ctx.workspace, args.node, args.bwrap, args.npm)
    ctx.profile = json.loads((installed / "profile.json").read_text())
    report["installation"] = json.loads((installed / "installation.json").read_text())
    subprocess.run([str(args.agentfw), "install"], env=env, stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
    archive = args.output / "classifier-frozen.pkg"
    subprocess.run([str(args.agentfw), "classifier-package", "build", "--classifier", "frozen", "--source", str(ROOT),
                    "--out", str(archive)], env=env, capture_output=True, check=True, timeout=60)
    subprocess.run([str(args.agentfw), "classifier-package", "install", str(archive), "--python", str(args.python)],
                   env=env, capture_output=True, check=True, timeout=60)
    report["classifier_archive_sha256"] = sha(archive)
    port = BASE.DEMO.free_port()
    config = {"port": port, "enforce": True, "policy": str(installed / "policy.yaml"), "audit": str(args.output / "native-audit.jsonl"),
              "native": {"registry_path": str(installed / "registry.json"), "registry_sha256": sha(installed / "registry.json")}}
    write(ctx.home / ".agentfw/config.yaml", config)
    env.update(AGENTFW_MCP_SERVER_PROFILE=str(installed / "profile.json"), AGENTFW_CLASSIFIER="rule-package")
    ctx.env = env
    daemon = None
    try:
        with (args.output / "daemon.log").open("wb") as log:
            daemon = subprocess.Popen([str(args.agentfw), "serve"], env=env, stdout=log, stderr=log)
        require(BASE.DEMO.wait_healthy(port, daemon), "owned enforcing daemon failed startup")
        scenario_main(ctx, report)
        scenario_no_call_exit(ctx, report)
        scenario_startup_failure(ctx, report)
        scenario_latency(ctx, report, args.rounds)
    finally:
        if daemon is not None:
            BASE.DEMO.stop(daemon)
    report["source_after"] = BASE.source()
    report["not_demonstrated"] = ["mismatched ready identity (worker-level tests only)", "late reply (worker-level tests only)"]
    if args.server == "git":
        report["classifier_scope"] = ("the frozen installed classifier reads git_show as read but leaves git_status/git_log/git_diff "
                                      "unknown, so git_show is the only useful call here")
    else:
        report["not_demonstrated"].append("original Git MCP server (see the Git report)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    parser.add_argument("--server", choices=("filesystem", "git"), default="filesystem")
    for name in ("agentfw", "bwrap", "strace", "python", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("node", "npm", "git", "git-launcher"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args()
    args.output = args.output.resolve()
    require(not args.output.exists() and not args.output.is_relative_to(ROOT), "new output outside checkout required")
    args.output.mkdir(mode=0o700, parents=True)
    report = {"format": FORMAT, "status": "failed", "cases": []}
    try:
        needed = ("agentfw", "bwrap", "strace", "python") + (("git", "git_launcher") if args.server == "git" else ("node", "npm"))
        for name in needed:
            require(getattr(args, name) is not None, "--" + name.replace("_", "-") + " is required for " + args.server)
            setattr(args, name, getattr(args, name).resolve(strict=True))
        run(args, report)
        report["status"] = "passed"
    except Exception as error:
        report["error"] = str(error)[:2000]
    finally:
        write(args.output / "report.json", report)
    print(json.dumps({"status": report["status"], "cases": len(report["cases"]), "error": report.get("error")}, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
