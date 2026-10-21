#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""DIAGNOSTIC ONLY: repeat the SOU-68 protected overlap through the real sandbox and native relay.

Never acceptance evidence; nothing here is read by the SOU-68 driver or the SOU-97 gate. Phase 1 runs fresh
protected sessions (the driver's command, environment, pinned original Git server, sandbox, native relay,
policy and in-session prefix) for the default and candidate classifiers, each with the unchanged production
overlap() and with a control that differs only by omitting its two cancellations. Unless phase 1 reproduces
a failure, phase 2 repeats the original failing order exactly: startup_refusals, candidate_replay and
protected() from the driver, each against a fresh daemon.

Native already withholds server stderr; only its byte count is recorded. Collector logs, transcripts,
responses and repository content stay in a private temporary directory; the report keeps allowlisted
collector fields, owner reason codes, fixed outcome codes and cleanup verification only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sou97-git-protected-overlap-diagnostic/1"
CLASSIFIERS = ("default", "candidate")
VARIANTS = ("cancel", "no_cancel")
DEFAULT_SESSIONS, MAX_SESSIONS = 6, 12  # per classifier x variant cell
DEFAULT_REPLAY_ITERATIONS, MAX_REPLAY_ITERATIONS = 2, 4
DEFAULT_BUDGET_SECONDS, MIN_BUDGET_SECONDS, MAX_BUDGET_SECONDS = 900, 300, 1500
SESSION_RESERVE_SECONDS, REPLAY_RESERVE_SECONDS = 60, 240
LOG_BYTES, LOG_ROWS, ROW_BYTES = 4 * 1024 * 1024, 20000, 65536
OVERLAP_IDS = range(100, 116)
OWNER_REASONS = frozenset((
    "mcp_owner_stop_requested", "mcp_owner_sandbox_failed", "mcp_owner_namespace_lost", "mcp_owner_control_failed",
    "mcp_owner_control_invalid", "mcp_owner_control_closed", "mcp_owner_parent_lost", "mcp_owner_startup_failed",
    "mcp_owner_active", "mcp_owner_platform_unsupported"))
CALL_STATES = ("queued", "admitting", "running", "inflight", "finished", "inspecting", "reclaiming", "cancelled", "complete")
# Static require() messages of overlap(), the session prefix and the shared client; never echoed, only mapped.
OUTCOMES = {
    "one owned original Git server PID required": "server_pid_not_unique",
    "eight real calls did not enter flight": "inflight_not_reached",
    "queued cancellation target absent": "queued_target_absent",
    "inflight cancellation target was not dispatched": "inflight_target_not_dispatched",
    "inflight/queued cancellation not correlated": "cancellation_not_correlated",
    "late, cross-call or missing concurrent result": "concurrent_result_mismatch",
    "unsafe original result escaped inspection": "result_injection_escaped",
    "result inspection lacked independent execution witness": "inspection_witness_missing",
    "result refusal broke useful follow-up": "followup_failed",
    "protected useful read failed": "read_failed",
    "original initialization changed": "initialization_mismatch",
    "original discovery changed": "discovery_mismatch",
    "unbounded/incomplete client response": "client_response_invalid",
    "JSON-RPC id/type correlation changed": "response_id_mismatch",
}
DIFFERENCES = (
    "phase 1 sessions repeat protected()'s in-session prefix (poison read, follow-up, six reads) but not its "
    "unwrapped calibration, refusal loop or daemon outage; phase 2 runs the driver's functions unchanged",
    "the no_cancel control is overlap() without its two cancellations; it expects all sixteen replies",
    "the sandbox-positive isolation test is not repeated; the default acceptance step runs it",
    "phase 1 shares one daemon across sessions; phase 2 starts a fresh daemon per iteration, as a driver run does",
    "phase 2's protected() mutates and restores the index itself and asserts its own unchanged window; the report "
    "compares the repository only across phase 1",
)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def outcome_code(error: BaseException) -> str:
    """Fixed code for a failed step; the message itself never leaves this function."""
    if isinstance(error, queue.Empty):
        return "response_timeout"
    message = str(error) if isinstance(error, ValueError) else ""
    if message in OUTCOMES:
        return OUTCOMES[message]
    if message.endswith(" closed before correlated response"):
        return "closed_before_response"
    if message.startswith("original server call refused: "):
        return "server_call_refused"
    return "other:" + type(error).__name__


def overlap_without_cancel(sou68, client, log, report, base=100):
    """Control: sou68.overlap() with only its two cancellations and their reply check removed."""
    transport, require = sou68.BASE, sou68.require
    client.process_witness.sample()
    candidates = []
    for pid, start in client.process_witness.observed:
        try:
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if transport.ProcessWitness.identity(pid) == start and argv[0] == b"/mcp-server/python/bin/python3.11" and b"mcp_server_git" in argv:
                candidates.append((pid, start))
        except OSError:
            pass
    require(len(candidates) == 1, "one owned original Git server PID required")
    pid, start = candidates[0]
    record = {"owned_server_pid": pid, "request_base": base, "cancelled": [], "replies": [], "passed": False}
    report.setdefault("overlap_rounds", []).append(record)
    report["overlap"] = record
    os.kill(pid, signal.SIGSTOP)
    try:
        client.send(*[sou68.call(i) for i in range(base, base + 8)])
        transport.wait_event(log, lambda rows: any(r.get("host_call_id") in range(base, base + 8) and r.get("active") == 8 for r in rows),
                        "eight real calls did not enter flight")
        # A global active-count row can describe admission work. Require the
        # actual target to reach the original-server wire before cancelling it.
        transport.wait_event(log, lambda rows: any(r.get("host_call_id") == base and r.get("state") == "inflight" for r in rows),
                        "inflight cancellation target was not dispatched")
        client.send(*[sou68.call(i) for i in range(base + 8, base + 16)])
        transport.wait_event(log, lambda rows: any(r.get("host_call_id") == base + 15 and r.get("state") == "queued" for r in rows),
                        "queued cancellation target absent")
    finally:
        if transport.ProcessWitness.identity(pid) == start:
            os.kill(pid, signal.SIGCONT)
    for _ in range(16):
        record["replies"].append(client.receive()[0])
    require({r["id"] for r in record["replies"]} == set(range(base, base + 16)) and all("SOU-68 synthetic" in sou68.text(r) for r in record["replies"]),
            "late, cross-call or missing concurrent result")
    record["passed"] = True


def session_prefix(sou68, client, stack, witness):
    """protected()'s in-session calls before overlap(), with the same checks (no originals comparison)."""
    base, require = sou68.BASE, sou68.require
    client.initialize()
    witness.drain()
    poison, _ = client.exchange(sou68.call(8, "git_show", {"revision": stack.poison}))
    require(base.refused(poison) and sou68.INJECTION not in json.dumps(poison), "unsafe original result escaped inspection")
    require(witness.drain() > 0, "result inspection lacked independent execution witness")
    followup, _ = client.exchange(sou68.call(9))
    require("SOU-68 synthetic" in sou68.text(followup), "result refusal broke useful follow-up")
    for identifier, (tool, args, fragment) in enumerate(sou68.READS, 10):
        response, raw = client.exchange(sou68.call(identifier, tool, args))
        require(not base.refused(response) and fragment in sou68.text(response), "protected useful read failed")


def protected_command(stack, classifier):
    """Exactly protected()'s collector command and environment for one classifier."""
    python = stack.install / "package/python/bin/python3.11"
    env = dict(stack.env, GIT_PYTHON_GIT_EXECUTABLE=str(stack.git), GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL="/dev/null", GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    env.update(AGENTFW_MCP_SERVER_PROFILE=str(stack.install / "profile.json"), AGENTFW_CLASSIFIER="rule-baseline",
               AGENTFW_RULE_BASELINE=classifier["path"], AGENTFW_CLASSIFIER_PYTHON=sys.executable)
    command = [str(stack.binary), "mcp", "--native-admission", "--id", "sou68-git", "--", str(python),
               "-I", "-B", "-m", "mcp_server_git", "--repository", "/workspace"]
    return command, env


def parse_collector(path: Path, terminals: dict) -> dict:
    """Allowlisted, bounded fields of one collector log. No message, payload, path or instance id is kept."""
    summary = {"available": False, "input_limited": False, "row_limited": False, "oversized_rows": 0,
               "invalid_rows": 0, "server_starts": 0, "server_ends": [], "owner_ends": [], "stderr_bytes": 0,
               "terminal_codes": [], "unknown_terminal_rows": 0, "calls": {}}
    try:
        with path.open("rb") as stream:
            raw = stream.read(LOG_BYTES + 1)
    except OSError:
        return summary
    summary["available"] = True
    if len(raw) > LOG_BYTES:
        summary["input_limited"] = True
        raw = raw[:LOG_BYTES]
    for index, line in enumerate(raw.splitlines()):
        if index >= LOG_ROWS:
            summary["row_limited"] = True
            break
        if len(line) > ROW_BYTES:
            summary["oversized_rows"] += 1
            continue
        line = line.strip()
        if line.startswith(b"Error:"):
            code = terminals.get(line)
            if code is None:
                summary["unknown_terminal_rows"] += 1
            elif code not in summary["terminal_codes"]:
                summary["terminal_codes"].append(code)
            continue
        try:
            row = json.loads(line)
        except (ValueError, UnicodeDecodeError, RecursionError):
            summary["invalid_rows"] += 1
            continue
        if not isinstance(row, dict):
            continue
        event = row.get("event")
        if event == "mcp_real_server_start":
            summary["server_starts"] += 1
        elif event == "mcp_real_stderr":
            value = row.get("received_bytes")
            if type(value) is int and 0 <= value <= 2 ** 53:
                summary["stderr_bytes"] = max(summary["stderr_bytes"], value)
        elif event == "mcp_real_server_end" and len(summary["server_ends"]) < 8:
            summary["server_ends"].append({key: row[key] for key in (
                "cleanup_verified", "transport_complete", "budget_failure_observed", "owner_failure_observed",
                "owner_cleanup_verified", "budget_cleanup_verified") if type(row.get(key)) is bool})
        elif event == "mcp_real_owner_end" and len(summary["owner_ends"]) < 8:
            owner = row.get("owner") if isinstance(row.get("owner"), dict) else {}
            cleanup = owner.get("cleanup") if isinstance(owner.get("cleanup"), dict) else {}
            reason = owner.get("reason")
            item = {"reason": reason if reason in OWNER_REASONS else "unrecognized",
                    "cleanup_reason": cleanup.get("reason") if cleanup.get("reason") in OWNER_REASONS else
                    ("absent" if "reason" not in cleanup else "unrecognized")}
            for key in ("cleanup_verified", "observed_failure"):
                if type(row.get(key)) is bool:
                    item[key] = row[key]
            if type(owner.get("failed")) is bool:
                item["failed"] = owner["failed"]
            for key in ("process_reaped", "namespace_terminated", "owned_resources_removed", "runtime_failure"):
                if type(cleanup.get(key)) is bool:
                    item[key] = cleanup[key]
            summary["owner_ends"].append(item)
        elif event == "mcp_real_call":
            identifier, state = row.get("host_call_id"), row.get("state")
            if type(identifier) is int and identifier in OVERLAP_IDS and state in CALL_STATES:
                call = summary["calls"].setdefault(str(identifier), {"states": [], "dispatched": False})
                if not call["states"] or call["states"][-1] != state:
                    call["states"] = (call["states"] + [state])[-12:]
                call["dispatched"] = call["dispatched"] or row.get("execution_dispatched") is True
    owners, ends = summary["owner_ends"], summary["server_ends"]
    summary["sandbox_failure"] = any(o["reason"] == "mcp_owner_sandbox_failed" or o["cleanup_reason"] == "mcp_owner_sandbox_failed"
                                     or o.get("runtime_failure") is True for o in owners)
    summary["transport_incomplete"] = any(e.get("transport_complete") is not True for e in ends)
    summary["owner_cleanup_unverified"] = any(o.get("cleanup_verified") is not True or o.get("process_reaped") is not True
                                              or o.get("namespace_terminated") is not True
                                              or o.get("owned_resources_removed") is not True for o in owners)
    summary["server_cleanup_unverified"] = any(e.get("cleanup_verified") is not True for e in ends)
    summary["server_end_missing"] = summary["server_starts"] > len(ends)
    return summary


def cleanup_failures(client_state: dict, collector: dict) -> list[str]:
    """Every cleanup boundary that was not verified; an empty list is the only success."""
    problems = []
    if client_state.get("all_stopped") is not True:
        problems.append("process_tree_survived")
    if client_state.get("forced_cleanup"):
        problems.append("forced_kill")
    if not collector.get("available"):
        problems.append("collector_log_missing")
    for key in ("owner_cleanup_unverified", "server_cleanup_unverified", "server_end_missing"):
        if collector.get(key):
            problems.append(key)
    return problems


def matrix(sessions: int) -> list[tuple[str, str, int]]:
    """Interleaved so drift and daemon age affect every cell alike."""
    return [(classifier, variant, index) for index in range(sessions) for classifier in CLASSIFIERS for variant in VARIANTS]


def session(sou68, stack, classifier, variant, index, root, *, command=None, env=None, witness_cls=None):
    """One fresh protected session: prefix, then overlap() or its control. Returns a content-free record."""
    if command is None:
        command, env = protected_command(stack, classifier)
    directory = root / f"session-{len(list(root.glob('session-*'))):03d}"
    directory.mkdir(mode=0o700)
    log_path = directory / "collector.log"
    record = {"classifier": classifier["mode"], "variant": variant, "index": index, "stage": "start"}
    witness = (witness_cls or sou68.RepositoryWitness)(stack.workspace)
    started = time.monotonic()
    client = None
    try:
        with log_path.open("wb") as log:
            client = sou68.Client(command, env, stack.workspace, log, f"diagnostic {classifier['mode']} {variant} {index}")
            try:
                record["stage"] = "prefix"
                session_prefix(sou68, client, stack, witness)
                record["stage"] = "overlap"
                if variant == "cancel":
                    sou68.overlap(client, log_path, {})  # unchanged production assertions
                else:
                    overlap_without_cancel(sou68, client, log_path, {})
                record["stage"], record["outcome"] = "done", "passed"
            except Exception as error:
                record["outcome"] = outcome_code(error)
            finally:
                try:
                    client.close()
                except Exception as error:
                    record["close_error"] = type(error).__name__
    finally:
        witness.close()
    final = (client.process_witness.final or {}) if client else {}
    client_state = {"exit_code": client.process.returncode if client else None,
                    "forced_cleanup": client.forced_cleanup if client else False,
                    "all_stopped": final.get("all_stopped") is True,
                    "descendants": final.get("descendant_count") if type(final.get("descendant_count")) is int else None}
    collector = parse_collector(log_path, sou68.DIAGNOSTIC_TERMINALS)
    record.update(client=client_state, collector=collector, seconds=round(time.monotonic() - started, 2),
                  cleanup_failures=cleanup_failures(client_state, collector))
    daemon = getattr(stack, "daemon", None)
    record["daemon_alive"] = daemon is not None and daemon.poll() is None
    return record


def replay_logs(directory: Path, terminals: dict) -> dict:
    """Aggregate of the replay sessions' collector logs in one iteration."""
    paths = sorted(directory.glob("sou97-replay-collector-*.log"))[:256]
    parsed = [parse_collector(path, terminals) for path in paths]
    return {"logs": len(parsed), "sandbox_failures": sum(p["sandbox_failure"] for p in parsed),
            "transport_incomplete": sum(p["transport_incomplete"] for p in parsed),
            "stderr_nonzero": sum(p["stderr_bytes"] > 0 for p in parsed),
            "max_stderr_bytes": max((p["stderr_bytes"] for p in parsed), default=0),
            "cleanup_unverified": sum(p["owner_cleanup_unverified"] or p["server_cleanup_unverified"] for p in parsed)}


def start_daemon(sou68, stack, directory: Path):
    base = sou68.BASE
    port = base.DEMO.free_port()
    base.write(stack.home / ".agentfw/config.yaml", {
        "port": port, "enforce": True, "max_record_bytes": 1048576, "policy": str(stack.install / "policy.yaml"),
        "native": {"registry_path": str(stack.install / "registry.json"), "registry_sha256": base.sha(stack.install / "registry.json")}})
    log = (directory / "daemon.log").open("wb")
    daemon = subprocess.Popen([str(stack.binary), "serve"], env=stack.env, stdout=log, stderr=log)
    log.close()
    base.require(base.DEMO.wait_healthy(port, daemon), "owned enforcing daemon failed to start")
    return daemon


def stop_daemon(sou68, daemon) -> bool:
    sou68.BASE.DEMO.stop(daemon)
    return daemon.poll() is not None


def replay_iteration(sou68, stack, candidate, directory: Path, index: int) -> dict:
    """The original failing order, verbatim: startup_refusals, candidate_replay, protected()."""
    directory.mkdir(mode=0o700)
    record = {"index": index, "stage": "daemon", "stages_completed": []}
    started, daemon, receiver = time.monotonic(), None, None
    report = {}
    try:
        daemon = start_daemon(sou68, stack, directory)
        receiver = sou68.BASE.DEMO.Receiver()
        run = SimpleNamespace(**{**vars(stack), "root": directory, "daemon": daemon, "receiver": receiver,
                                 "classifier": candidate})
        for name in ("startup_refusals", "candidate_replay", "protected"):
            record["stage"] = name
            getattr(sou68, name)(run, report)
            record["stages_completed"].append(name)
        record["stage"], record["outcome"] = "done", "passed"
    except Exception as error:
        record["outcome"] = outcome_code(error)
    finally:
        record["daemon_stopped"] = daemon is None or stop_daemon(sou68, daemon)
        egress = len(receiver.bodies) if receiver is not None else 0
        if receiver is not None:
            receiver.close()
    replay = report.get("sou97_replay") if isinstance(report.get("sou97_replay"), dict) else {}
    client = report.get("protected_client") if isinstance(report.get("protected_client"), dict) else {}
    final = client.get("process_cleanup") if isinstance(client.get("process_cleanup"), dict) else {}
    collector = parse_collector(directory / "collector.log", sou68.DIAGNOSTIC_TERMINALS)
    record.update(
        replay={"cases": replay.get("cases") if type(replay.get("cases")) is int else None,
                "sessions": replay.get("sessions") if type(replay.get("sessions")) is int else None,
                "failures": len(replay["failures"]) if isinstance(replay.get("failures"), list) else None,
                "collectors": replay_logs(directory, sou68.DIAGNOSTIC_TERMINALS)},
        protected=sou68.protected_diagnostics(report, directory), collector=collector, egress_bodies=egress,
        seconds=round(time.monotonic() - started, 2))
    protected_started = "protected" in record["stages_completed"] or record["stage"] == "protected"
    client_state = {"all_stopped": final.get("all_stopped") is True, "forced_cleanup": client.get("forced_cleanup") is True}
    record["cleanup_failures"] = (cleanup_failures(client_state, collector) if protected_started else []) + \
        ([] if record["daemon_stopped"] else ["daemon_survived"]) + \
        (["replay_cleanup_unverified"] if record["replay"]["collectors"]["cleanup_unverified"] else [])
    return record


def aggregate(sessions, iterations) -> dict:
    cells = {}
    for classifier in CLASSIFIERS:
        for variant in VARIANTS:
            rows = [r for r in sessions if r["classifier"] == classifier and r["variant"] == variant]
            outcomes = {}
            for row in rows:
                outcomes[row.get("outcome", "none")] = outcomes.get(row.get("outcome", "none"), 0) + 1
            cells[f"{classifier}/{variant}"] = {
                "sessions": len(rows), "passed": outcomes.get("passed", 0), "outcomes": dict(sorted(outcomes.items())),
                "sandbox_failures": sum(r["collector"]["sandbox_failure"] for r in rows),
                "stderr_nonzero": sum(r["collector"]["stderr_bytes"] > 0 for r in rows),
                "transport_incomplete": sum(r["collector"]["transport_incomplete"] for r in rows),
                "cleanup_failures": sum(bool(r["cleanup_failures"]) for r in rows)}
    outcomes = {}
    for row in iterations:
        outcomes[row.get("outcome", "none")] = outcomes.get(row.get("outcome", "none"), 0) + 1
    return {"phase1": cells, "phase2": {
        "iterations": len(iterations), "passed": outcomes.get("passed", 0), "outcomes": dict(sorted(outcomes.items())),
        "protected_sandbox_failures": sum(r["collector"]["sandbox_failure"] for r in iterations),
        "protected_stderr_nonzero": sum(r["collector"]["stderr_bytes"] > 0 for r in iterations),
        "replay_sandbox_failures": sum(r["replay"]["collectors"]["sandbox_failures"] for r in iterations),
        "cleanup_failures": sum(bool(r["cleanup_failures"]) for r in iterations)}}


CRASH_OUTCOMES = frozenset(("closed_before_response", "response_timeout", "concurrent_result_mismatch"))


def reproduced(sessions) -> bool:
    """A crash-like signal, not e.g. a classifier refusing a read."""
    return any(r["collector"]["sandbox_failure"] or r["collector"]["transport_incomplete"]
               or r.get("outcome") in CRASH_OUTCOMES for r in sessions)


def overall_status(report) -> str:
    """complete only when every planned unit ran with every cleanup boundary verified."""
    sessions, iterations = report.get("sessions", []), report.get("iterations", [])
    if any(r["cleanup_failures"] or r.get("close_error") for r in sessions + iterations):
        return "inconclusive"
    if any(not r["daemon_alive"] for r in sessions) or not sessions:
        return "inconclusive"
    if len(sessions) < report["planned_sessions"] or len(iterations) < report["planned_iterations"]:
        return "partial"
    return "complete"


def step_summary(report) -> str:
    status = f"status: `{report['status']}`"
    if report.get("error"):
        status += f" ({report.get('error_stage')}: {report['error']})"
    lines = ["### SOU-97 Git protected overlap diagnostic (DIAGNOSTIC ONLY, never acceptance evidence)", "", status, ""]
    summary = report.get("summary")
    if summary:
        lines += ["| cell | sessions | passed | sandbox failures | stderr > 0 | transport incomplete | cleanup failures | outcomes |",
                  "|---|---|---|---|---|---|---|---|"]
        for name, row in summary["phase1"].items():
            outcomes = ", ".join(f"{k}={v}" for k, v in row["outcomes"].items()) or "-"
            lines.append(f"| {name} | {row['sessions']} | {row['passed']} | {row['sandbox_failures']} | {row['stderr_nonzero']} | "
                         f"{row['transport_incomplete']} | {row['cleanup_failures']} | {outcomes} |")
        phase2 = summary["phase2"]
        outcomes = ", ".join(f"{k}={v}" for k, v in phase2["outcomes"].items()) or "-"
        lines.append(f"| candidate after replay (phase 2: {report.get('phase2_decision')}) | {phase2['iterations']} | "
                     f"{phase2['passed']} | {phase2['protected_sandbox_failures']} | {phase2['protected_stderr_nonzero']} | - | "
                     f"{phase2['cleanup_failures']} | {outcomes} |")
    return "\n".join(lines) + "\n"


def run(args):
    sou68 = load("sou97_protected_diag_sou68", "verify-sou68-real-mcp.py")
    base, install, replay = sou68.BASE, sou68.INSTALL, sou68.REPLAY
    require = base.require
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "Linux x86-64 required")
    before = base.source()
    require(before["commit"] == args.expected_commit and not before["dirty"], "clean exact commit required")
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(ROOT), "new output directory outside source required")
    require(1 <= args.sessions <= MAX_SESSIONS, f"sessions must be 1..{MAX_SESSIONS}")
    require(0 <= args.replay_iterations <= MAX_REPLAY_ITERATIONS, f"replay iterations must be 0..{MAX_REPLAY_ITERATIONS}")
    require(MIN_BUDGET_SECONDS <= args.max_seconds <= MAX_BUDGET_SECONDS,
            f"max-seconds must be {MIN_BUDGET_SECONDS}..{MAX_BUDGET_SECONDS}")
    candidate = replay.classifier_identity(args.classifier_script, args.classifier_sha256)
    default = {"path": str(sou68.DEFAULT_CLASSIFIER), "file": sou68.DEFAULT_CLASSIFIER.name,
               "sha256": base.sha(sou68.DEFAULT_CLASSIFIER), "revision": None, "mode": "default"}
    output.mkdir(mode=0o700, parents=True)
    planned = matrix(args.sessions)
    report = {"format": FORMAT, "diagnostic_only": True, "acceptance_evidence": False,
              "note": "Protected chain repeated for diagnosis only; never SOU-68 or SOU-97 acceptance evidence.",
              "status": "incomplete", "source": before, "driver_sha256": base.sha(ROOT / "scripts/verify-sou68-real-mcp.py"),
              "script_sha256": base.sha(Path(__file__)), "binary_sha256": base.sha(args.agentfw),
              "classifiers": {name: {k: v for k, v in item.items() if k != "path"} for name, item in
                              (("default", default), ("candidate", candidate))},
              "platform": platform.platform(), "budget_seconds": args.max_seconds, "budget_exhausted": False,
              "planned_sessions": len(planned), "replay_arm": args.replay_arm, "planned_iterations": 0,
              "differences_from_failing_run": list(DIFFERENCES), "sessions": [], "iterations": []}
    stage, started = "setup", time.monotonic()
    remaining = lambda: args.max_seconds - (time.monotonic() - started)
    try:
        with tempfile.TemporaryDirectory(prefix="sou97-git-protected-diagnostic-") as temporary:
            private = Path(temporary)
            home = private / "home"
            home.mkdir(mode=0o700)
            env = base.environment(home)
            env.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0")
            workspace = private / "workspace"
            poison = sou68.prepare_repo(workspace, args.git, env)
            stage = "install"
            installed = private / "installed"
            install.install(installed, workspace, args.git, args.git_sha256, args.bwrap, args.git_launcher)
            subprocess.run([str(args.agentfw), "install"], env=env, stdin=subprocess.DEVNULL, capture_output=True,
                           check=True, timeout=30)
            stack = SimpleNamespace(root=private, home=home, binary=args.agentfw, git=args.git, workspace=workspace,
                                    poison=poison, install=installed, env=env, classifier=candidate, daemon=None)
            snapshot = base.snapshot(workspace)
            iterations = args.replay_iterations if args.replay_arm != "never" else 0
            phase1_deadline = args.max_seconds - iterations * REPLAY_RESERVE_SECONDS
            stage = "phase1"
            phase1 = private / "phase1"
            phase1.mkdir(mode=0o700)
            stack.daemon = start_daemon(sou68, stack, phase1)
            try:
                for classifier_name, variant, index in planned:
                    if time.monotonic() - started > phase1_deadline - SESSION_RESERVE_SECONDS:
                        report["budget_exhausted"] = True
                        break
                    classifier = default if classifier_name == "default" else candidate
                    record = session(sou68, stack, classifier, variant, index, phase1)
                    report["sessions"].append(record)
                    if not record["daemon_alive"]:
                        break  # admission is gone; later sessions would not measure the server
            finally:
                report["phase1_daemon_stopped"] = stop_daemon(sou68, stack.daemon)
            report["phase1_repository_unchanged"] = base.snapshot(workspace) == snapshot
            run_phase2 = args.replay_arm == "always" or (args.replay_arm == "auto" and not reproduced(report["sessions"]))
            report["phase2_decision"] = ("never" if args.replay_arm == "never" else
                                         "run" if run_phase2 else "skipped: phase 1 reproduced a failure")
            if run_phase2:
                report["planned_iterations"] = iterations
                stage = "phase2"
                for index in range(iterations):
                    if remaining() < REPLAY_RESERVE_SECONDS:
                        report["budget_exhausted"] = True
                        break
                    report["iterations"].append(replay_iteration(sou68, stack, candidate, private / f"replay-{index}", index))
            report["summary"] = aggregate(report["sessions"], report["iterations"])
            report["status"] = overall_status(report)
            if not report["phase1_daemon_stopped"]:
                report["status"] = "inconclusive"
    except Exception as error:  # type and stage only: messages can carry paths or command lines
        report.update(status="fail", error=type(error).__name__, error_stage=stage)
        report["summary"] = aggregate(report["sessions"], report["iterations"])
    report["elapsed_seconds"] = round(time.monotonic() - started, 1)
    base.write(output / "diagnostic.json", report)
    print(json.dumps({"status": report["status"], "diagnostic_only": True, "error": report.get("error"),
                      "error_stage": report.get("error_stage"), "phase2": report.get("phase2_decision"),
                      "summary": report.get("summary"), "report": str(output / "diagnostic.json")}))
    if os.environ.get("GITHUB_ACTIONS") == "true":
        if report["status"] != "complete":
            print(f"::warning title=SOU-97 Git protected diagnostic (not acceptance)::status={report['status']}")
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
                stream.write(step_summary(report))
    return 0 if report["status"] == "complete" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    for name in ("agentfw", "git", "bwrap", "git-launcher", "output", "classifier-script"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--git-sha256", required=True)
    parser.add_argument("--classifier-sha256", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--sessions", type=int, default=DEFAULT_SESSIONS, help=f"per classifier x variant cell (1..{MAX_SESSIONS})")
    parser.add_argument("--replay-iterations", type=int, default=DEFAULT_REPLAY_ITERATIONS,
                        help=f"candidate-after-replay repetitions (0..{MAX_REPLAY_ITERATIONS})")
    parser.add_argument("--replay-arm", choices=("auto", "always", "never"), default="auto",
                        help="auto: run phase 2 only if phase 1 did not reproduce a failure")
    parser.add_argument("--max-seconds", type=int, default=DEFAULT_BUDGET_SECONDS,
                        help=f"wall-clock budget ({MIN_BUDGET_SECONDS}..{MAX_BUDGET_SECONDS}); no new unit starts after it")
    args = parser.parse_args()
    if not args.run:
        print(json.dumps({"status": "plan", "executed": False, "diagnostic_only": True,
                          "cells": [f"{c}/{v}" for c in CLASSIFIERS for v in VARIANTS],
                          "sessions_per_cell": args.sessions, "replay_arm": args.replay_arm,
                          "replay_iterations": args.replay_iterations}))
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
