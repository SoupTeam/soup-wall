#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""DIAGNOSTIC ONLY: does the pinned original Git MCP server terminate under the SOU-68 overlap pattern?

Never acceptance evidence. It does not run the protected chain, native policy, the classifier or the
sandbox, and nothing it writes is read by the SOU-68 driver or the SOU-97 gate. It starts the unwrapped
pinned server (as protected() already does for calibration) on an owned synthetic repository and repeats
the overlap pattern with and without the forwarded cancellation. Server stderr is held only in memory and
reduced to a sanitized summary: byte count, sha256, exception class names, traceback locations inside
the pinned package or the Python standard library, and fixed SDK marker strings. Raw stderr, messages,
results and repository content never reach the report.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sou97-git-cancellation-diagnostic/1"
SCENARIOS = ("stop_no_cancel", "stop_cancel", "burst_cancel")
# overlap(): 100-107 enter flight while the server is stopped; 108-115 queue on the host and 115 is cancelled
# there, so it never reaches the server. Cancelling in-flight 100 frees one slot (108 may be dispatched before
# SIGCONT); 109-114 are then dispatched one per completed call.
FIRST, INFLIGHT, LAST = 100, 8, 114
STDERR_CAPTURE_BYTES = 65536
MAX_FRAMES, MAX_EXCEPTIONS = 64, 16
INITIALIZE_SECONDS, TRIAL_SECONDS, SETTLE_SECONDS = 10, 20, 2
MAX_TRIALS, DEFAULT_BUDGET_SECONDS, MAX_BUDGET_SECONDS = 50, 480, 1200
LINUX_SIGNALS = {1: "SIGHUP", 2: "SIGINT", 6: "SIGABRT", 7: "SIGBUS", 9: "SIGKILL", 11: "SIGSEGV", 13: "SIGPIPE",
                 15: "SIGTERM", 31: "SIGSYS"}  # fixed table: the script runs on Linux only
# Fixed SDK constants (mcp 1.29.0 shared/session.py and anyio): their presence is evidence, never data.
MARKERS = {
    "request_already_responded": b"Request already responded to",
    "responder_not_entered": b"RequestResponder must be used as a context manager",
    "no_active_cancel_scope": b"No active cancel scope",
    "cancel_scope_other_task": b"cancel scope in a different task",
    "broken_resource": b"BrokenResourceError",
    "closed_resource": b"ClosedResourceError",
}
FRAME = re.compile(rb'^[\s|+-]*File "([^"\n]{1,1024})", line (\d{1,7}), in ([A-Za-z_<][A-Za-z0-9_<>.]{0,127})\s*$')
EXCEPTION = re.compile(rb"^[\s|+-]*((?:[A-Za-z_][A-Za-z0-9_]{0,63}\.){0,6}"
                       rb"[A-Za-z_][A-Za-z0-9_]{0,63}(?:Error|Exception|ExceptionGroup|Group|Interrupt|Exit|Cancelled))(?::|\s*$)")
PACKAGE_MODULES = ("mcp", "mcp_server_git", "anyio", "git", "gitdb", "pydantic", "pydantic_core", "click",
                   "starlette", "sse_starlette", "httpx", "httpcore")
DIFFERENCES = (
    "unwrapped server: no bwrap, seccomp, Landlock, Git launcher, cgroup budget or process owner",
    "no native relay: no admission latency, host -32800 replies or reclaim timing; 108 is written before "
    "SIGCONT, which the relay does only when 100's reclaim finishes first",
    "repo_path and --repository are the host path of the synthetic repository, not /workspace",
    "the control refills 108-114 one per completion; without the host cancellation 115 would also be dispatched",
)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def location(path: bytes, python_root: bytes | None):
    """Public code location of a traceback frame, or None. Only the pinned package and stdlib qualify."""
    try:
        text = path.decode("ascii")
    except UnicodeDecodeError:
        return None
    if ".." in text.split("/") or not text.endswith(".py"):
        return None
    if python_root is not None and not text.startswith(python_root.decode("ascii", "replace").rstrip("/") + "/"):
        return None
    marker = "/site-packages/"
    if marker in text:
        relative = text.split(marker, 1)[1]
        if relative.split("/", 1)[0] in PACKAGE_MODULES and re.fullmatch(r"[A-Za-z0-9_/]+\.py", relative):
            return "site-packages/" + relative
        return None
    stdlib = re.search(r"/lib/python3\.\d+/((?:asyncio|concurrent|threading|selectors|subprocess|runpy|"
                       r"contextlib|signal|socket|io|typing|functools)[A-Za-z0-9_/]*\.py)$", text)
    return "stdlib/" + stdlib.group(1) if stdlib else None


def sanitize_stderr(captured: bytes, total: int, python_root: bytes | None = None) -> dict:
    """Bounded, content-free summary of server stderr. Never returns any raw line or message text."""
    frames, exceptions = [], []
    summary = {"received_bytes": total, "captured_bytes": len(captured), "truncated": total > len(captured),
               "captured_sha256": hashlib.sha256(captured).hexdigest(), "lines": 0, "traceback_headers": 0,
               "frames": frames, "frames_dropped": 0, "foreign_frames": 0, "exceptions": exceptions,
               "exceptions_dropped": 0, "markers": sorted(name for name, value in MARKERS.items() if value in captured)}
    for line in captured.splitlines():
        summary["lines"] += 1
        if line.lstrip(b" |+-").endswith(b"Traceback (most recent call last):"):  # also Exception Group
            summary["traceback_headers"] += 1
            continue
        frame = FRAME.match(line)
        if frame:
            where = location(frame.group(1), python_root)
            if where is None:
                summary["foreign_frames"] += 1
            elif len(frames) < MAX_FRAMES:
                frames.append({"file": where, "line": int(frame.group(2)), "function": frame.group(3).decode("ascii")})
            else:
                summary["frames_dropped"] += 1
            continue
        exception = EXCEPTION.match(line)
        if exception:
            name = exception.group(1).decode("ascii")
            if len(exceptions) < MAX_EXCEPTIONS:
                exceptions.append(name)
            else:
                summary["exceptions_dropped"] += 1
    return summary


def exit_status(returncode):
    if returncode is None:
        return {"exited": False, "code": None, "signal": None}
    if returncode < 0:
        return {"exited": True, "code": None, "signal": LINUX_SIGNALS.get(-returncode, -returncode)}
    return {"exited": True, "code": returncode, "signal": None}


def classify_responses(rows: list[tuple[float, dict]], fragment: str, expected=None) -> dict:
    """Numeric ids, error codes and a boolean usefulness check only; never result or error text."""
    by_id = {}
    for _, row in rows:
        identifier = row.get("id")
        if type(identifier) is not int:
            continue
        if "error" in row:
            code = row["error"].get("code") if isinstance(row["error"], dict) else None
            kind = f"error:{code}" if type(code) is int else "error:invalid"
        else:
            content = row.get("result", {}).get("content") if isinstance(row.get("result"), dict) else None
            text = "".join(item.get("text", "") for item in content if isinstance(item, dict)) if isinstance(content, list) else ""
            kind = "result_useful" if fragment in text else "result_other"
        by_id.setdefault(identifier, []).append(kind)
    return {"by_id": {str(k): v for k, v in sorted(by_id.items())},
            "duplicate_ids": sorted(k for k, v in by_id.items() if len(v) > 1),
            "missing_ids": sorted(set(expected) - set(by_id)) if expected is not None else None}


def plan(scenario: str) -> dict:
    """Request order of one trial. `initial` is written while stopped (or as one burst); `refill` is written one
    call per completed non-cancelled call, as the native relay refills its eight active slots."""
    inflight = list(range(FIRST, FIRST + INFLIGHT))
    if scenario == "stop_no_cancel":
        return {"stop": True, "initial": inflight, "refill": list(range(FIRST + INFLIGHT, LAST + 1)), "cancelled": None}
    if scenario in ("stop_cancel", "burst_cancel"):
        return {"stop": scenario == "stop_cancel", "initial": inflight + [("cancel", FIRST), FIRST + INFLIGHT],
                "refill": list(range(FIRST + INFLIGHT + 1, LAST + 1)), "cancelled": FIRST}
    raise ValueError("unknown scenario")


def native_cancel(identifier):
    """Exactly the frame real_server.rs forwards to the child: no reason field."""
    return {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": identifier}}


def frames(items, call) -> list[dict]:
    return [native_cancel(item[1]) if isinstance(item, tuple) else call(item) for item in items]


class StderrCapture:
    """Drain server stderr into a bounded in-memory buffer; counts every byte, keeps at most the bound."""
    def __init__(self, stream, limit=STDERR_CAPTURE_BYTES):
        self.stream, self.limit, self.buffer, self.total = stream, limit, bytearray(), 0
        self.thread = threading.Thread(target=self.drain, daemon=True)
        self.thread.start()

    def drain(self):
        while chunk := self.stream.read1(8192):
            self.total += len(chunk)
            room = self.limit - len(self.buffer)
            if room > 0:
                self.buffer += chunk[:room]

    def finish(self, timeout=3):
        self.thread.join(timeout=timeout)
        drained = not self.thread.is_alive()
        if drained:
            self.stream.close()
        return bytes(self.buffer), self.total, drained


def trial(scenario, index, *, sou68, command, python_root, workspace, env):
    """One fresh unwrapped original server; returns a content-free record."""
    steps = plan(scenario)
    call = lambda i: sou68.call(i, "git_show", {"revision": "HEAD"}, workspace)  # overlap()'s call(i)
    expected = [i for i in steps["initial"] + steps["refill"] if not isinstance(i, tuple) and i != steps["cancelled"]]
    class Client(sou68.Client):
        def receive(self, timeout=INITIALIZE_SECONDS):  # bounds initialize(); trial reads use their own deadline
            return super().receive(timeout=min(timeout, INITIALIZE_SECONDS))

    client = Client(command, env, workspace, subprocess.PIPE, f"diagnostic {scenario} {index}")
    stderr = StderrCapture(client.process.stderr)
    record = {"scenario": scenario, "trial": index, "initialized": False}
    rows, eof_at, started = [], None, None
    try:
        client.initialize()
        record["initialized"] = True
        pid = client.process.pid
        if steps["stop"]:
            os.kill(pid, signal.SIGSTOP)
            try:
                client.send(*frames(steps["initial"], call))
            finally:
                os.kill(pid, signal.SIGCONT)
        else:
            client.send(*frames(steps["initial"], call))
        started = time.monotonic()
        refill, answered = list(steps["refill"]), set()
        deadline = started + TRIAL_SECONDS
        while time.monotonic() < deadline:
            try:
                raw = client.lines.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                break
            if raw is None:
                eof_at = time.monotonic()
                break
            try:
                row = json.loads(raw)
            except ValueError:
                record["invalid_stdout_lines"] = record.get("invalid_stdout_lines", 0) + 1
                continue
            if not isinstance(row, dict) or "id" not in row:
                continue
            rows.append((time.monotonic(), row))
            identifier = row.get("id")
            first = identifier not in answered
            answered.add(identifier)
            if first and identifier != steps["cancelled"] and refill:
                try:
                    client.send(call(refill.pop(0)))
                except OSError:
                    record["refill_write_failed"] = True
                    refill = []
            if set(expected) <= answered:
                if steps["cancelled"] is None or steps["cancelled"] in answered:
                    break
                # The cancelled call may get the SDK's own error, a late result or nothing; wait briefly.
                deadline = min(deadline, time.monotonic() + SETTLE_SECONDS)
        record["refill_unsent"] = len(refill)
        record["exited_before_close"] = client.process.poll() is not None
        record["status_before_close"] = exit_status(client.process.poll())
    except Exception as error:  # the type is recorded, never the message
        record["driver_error"] = type(error).__name__
    finally:
        try:
            client.close()
        except Exception as error:
            record["close_error"] = type(error).__name__
    captured, total, closed = stderr.finish()
    record.update(
        status_after_close=exit_status(client.process.returncode), forced_cleanup=client.forced_cleanup,
        process_cleanup_all_stopped=(client.process_witness.final or {}).get("all_stopped") is True,
        responses=classify_responses(rows, "SOU-68 synthetic", expected),
        timing_ms={"first_response": round((rows[0][0] - started) * 1000, 1) if rows and started else None,
                   "last_response": round((rows[-1][0] - started) * 1000, 1) if rows and started else None,
                   "stdout_eof": round((eof_at - started) * 1000, 1) if eof_at and started else None},
        stderr=dict(sanitize_stderr(captured, total, python_root), drained=closed))
    record["server_terminated"] = record.get("exited_before_close") is True or eof_at is not None
    return record


def aggregate(records):
    result = {}
    for scenario in SCENARIOS:
        rows = [r for r in records if r["scenario"] == scenario]
        result[scenario] = {
            "trials": len(rows), "initialized": sum(r["initialized"] for r in rows),
            "server_terminated": sum(r["server_terminated"] for r in rows),
            "nonzero_exit": sum(r["status_after_close"]["code"] not in (0, None) or r["status_after_close"]["signal"] is not None
                                for r in rows if not r["forced_cleanup"]),
            "forced_cleanup": sum(r["forced_cleanup"] for r in rows),
            "stderr_nonempty": sum(r["stderr"]["received_bytes"] > 0 for r in rows),
            "duplicate_response_trials": sum(bool(r["responses"]["duplicate_ids"]) for r in rows),
            "missing_response_trials": sum(bool(r["responses"].get("missing_ids")) for r in rows),
            "exceptions": sorted({name for r in rows for name in r["stderr"]["exceptions"]}),
            "markers": sorted({name for r in rows for name in r["stderr"]["markers"]}),
        }
    return result


def overall_status(records, requested: int) -> str:
    """complete only if every requested round ran and every trial reached its scenario and closed."""
    if not records or any(r.get("driver_error") or not r["initialized"] or r.get("close_error")
                          or not r["process_cleanup_all_stopped"] for r in records):
        return "inconclusive"
    if len(records) < requested * len(SCENARIOS):
        return "partial"
    return "complete"


def step_summary(report) -> str:
    status = f"status: `{report['status']}`"
    if report.get("error"):
        status += f" ({report.get('error_stage')}: {report['error']})"
    lines = ["### SOU-97 Git cancellation diagnostic (DIAGNOSTIC ONLY, never acceptance evidence)", "", status, ""]
    if report.get("summary"):
        lines += ["| scenario | trials | terminated | nonzero exit | stderr | duplicates | missing | exceptions | markers |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for name, row in report["summary"].items():
            lines.append(f"| {name} | {row['trials']} | {row['server_terminated']} | {row['nonzero_exit']} | "
                         f"{row['stderr_nonempty']} | {row['duplicate_response_trials']} | {row['missing_response_trials']} | "
                         f"{', '.join(row['exceptions']) or '-'} | {', '.join(row['markers']) or '-'} |")
    return "\n".join(lines) + "\n"


def run(args):
    sou68 = load("sou97_diag_sou68", "verify-sou68-real-mcp.py")
    base, install = sou68.BASE, sou68.INSTALL
    require = base.require
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 required")
    before = base.source()
    require(before["commit"] == args.expected_commit and not before["dirty"], "clean exact commit required")
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), "new output directory outside source required")
    require(1 <= args.trials <= MAX_TRIALS, f"trials must be 1..{MAX_TRIALS}")
    require(60 <= args.max_seconds <= MAX_BUDGET_SECONDS, f"max-seconds must be 60..{MAX_BUDGET_SECONDS}")
    output.mkdir(mode=0o700, parents=True)
    report = {"format": FORMAT, "diagnostic_only": True, "acceptance_evidence": False,
              "note": "Unwrapped pinned original server only; never SOU-68 or SOU-97 acceptance evidence.",
              "status": "incomplete", "source": before, "driver_sha256": base.sha(Path(__file__)),
              "requirements_lock_sha256": base.sha(install.ASSETS / "requirements.lock"),
              "platform": platform.platform(), "trials_per_scenario": args.trials, "scenarios": list(SCENARIOS),
              "budget_seconds": args.max_seconds, "budget_exhausted": False,
              "differences_from_protected_overlap": list(DIFFERENCES)}
    stage, started = "prepare_repository", time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="sou97-git-diagnostic-") as temporary:
            private = Path(temporary)
            home = private / "home"
            home.mkdir(mode=0o700)
            env = base.environment(home)
            env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
            workspace = private / "workspace"
            sou68.prepare_repo(workspace, args.git, env)
            stage = "install"
            installed = private / "installed"
            install.install(installed, workspace, args.git, args.git_sha256, args.bwrap, args.git_launcher)
            python = installed / "package/python/bin/python3.11"
            command = [str(python), "-I", "-B", "-m", "mcp_server_git", "--repository", str(workspace)]
            env.update(GIT_PYTHON_GIT_EXECUTABLE=str(args.git), GIT_OPTIONAL_LOCKS="0")
            snapshot = base.snapshot(workspace)
            stage, records = "trials", []
            for index in range(args.trials):
                if time.monotonic() - started > args.max_seconds:
                    report["budget_exhausted"] = True
                    break
                for scenario in SCENARIOS:  # interleaved so drift affects every scenario alike
                    records.append(trial(scenario, index, sou68=sou68, command=command,
                                         python_root=os.fsencode(python.parents[1]), workspace=workspace, env=env))
            report["repository_unchanged"] = base.snapshot(workspace) == snapshot
            report.update(trials=records, summary=aggregate(records), status=overall_status(records, args.trials))
    except Exception as error:  # type and stage only: messages can carry paths or command lines
        report.update(status="fail", error=type(error).__name__, error_stage=stage)
    report["elapsed_seconds"] = round(time.monotonic() - started, 1)
    base.write(output / "diagnostic.json", report)
    print(json.dumps({"status": report["status"], "diagnostic_only": True, "error": report.get("error"),
                      "error_stage": report.get("error_stage"), "summary": report.get("summary"),
                      "report": str(output / "diagnostic.json")}))
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if report["status"] != "complete":
            print(f"::warning title=SOU-97 Git diagnostic (not acceptance)::status={report['status']}")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
                stream.write(step_summary(report))
    return 0 if report["status"] == "complete" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    for name in ("git", "bwrap", "git-launcher", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--trials", type=int, default=20, help=f"rounds of all scenarios (1..{MAX_TRIALS})")
    parser.add_argument("--max-seconds", type=int, default=DEFAULT_BUDGET_SECONDS,
                        help=f"wall-clock budget; no new round starts after it (60..{MAX_BUDGET_SECONDS})")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False, "diagnostic_only": True, "scenarios": list(SCENARIOS)}))
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
