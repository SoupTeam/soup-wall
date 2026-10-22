#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual-host SOU-116 qualification of the prepared-selection entry point.

Uses owned data and the accepted scripted provider; raw traces/logs remain private.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUN = load("sou116_entry", "pilot-run.py")
LAUNCH = load("sou116_launch", "qualify-pilot-launcher.py")
ASK = load("sou116_ask", "qualify-pilot-ask.py")
BASE, require = LAUNCH.BASE, LAUNCH.require


def until(check, label, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(.1)
    raise ValueError(label)


def useful_result(results, identifier, marker):
    value = results.get(identifier, {})
    require(value.get("is_error") is False and marker in json.dumps(value.get("content")),
            "prepared_useful_result_missing")


def qualify(args, private, report):
    before = RUN.PREP.PILOT.source()
    require(not before["dirty"] and before["commit"] == args.expected_commit, "exact_clean_source_required")
    config = argparse.Namespace(selection=args.selection, expected_commit=args.expected_commit,
        ask_wait_seconds=0, timeout_seconds=60, port=0)
    selection, paths, profiles = RUN.selected(config)
    fs = Path(profiles["filesystem"]["profile"]["path"]).parent.parent / "filesystem-workspace"
    git = Path(profiles["git"]["profile"]["path"]).parent.parent / "git-workspace"
    # Owned preparation directories only, never a user repository.
    notes = "Owned prepared-selection useful notes.\n/workspace\n/workspace/credentials.txt\n/workspace/followup.txt\n"
    (fs / "notes.txt").write_text(notes)
    (fs / "followup.txt").write_text("Owned prepared continuation.\n")
    (fs / "credentials.txt").write_text("Owned synthetic sensitive path control.\n")
    (git / "tracked.txt").write_text("Owned prepared Git change.\n")
    env = {"PATH": "/usr/bin:/bin", "HOME": str(private), "LANG": "C.UTF-8"}
    workspace_before = {"filesystem": BASE.snapshot(fs), "git": BASE.snapshot(git)}
    selected_before = {role: BASE.sha(path) for role, path in paths.items()}
    sentinel = private / "unrelated.txt"
    sentinel.write_text("must survive")
    unrelated = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(600)"],
                                 start_new_session=True, env=env, cwd=private)
    report.update(source_before=before, selected_sha256=selected_before, cases=[])
    try:
        # These are actual entry-point invocations, with kernel-observed zero
        # selected daemon/host execution. Unit mocks are not their evidence.
        for control in ("plan", "occupied-port", "stale-source", "changed-selection"):
            report["active_case"] = control
            root = private / control
            root.mkdir(mode=0o700)
            trace = root / "trace.private"
            owner = socket.socket()
            original = args.selection.read_bytes()
            words = [sys.executable, "-B", str(ROOT / "scripts/pilot-run.py"), "--selection", str(args.selection),
                     "--expected-commit", "0" * 40 if control == "stale-source" else args.expected_commit,
                     "--state-root", str(root)]
            if control != "plan":
                words += ["--run"]
            try:
                if control == "occupied-port":
                    owner.bind(("127.0.0.1", 0)); owner.listen()
                    words += ["--port", str(owner.getsockname()[1])]
                elif control == "changed-selection":
                    changed = json.loads(original)
                    changed["files"]["agentfw"]["sha256"] = "0" * 64
                    args.selection.write_text(json.dumps(changed))
                result = subprocess.run([str(args.strace), "-f", "-qq", "-s", "4096", "-e", "trace=execve",
                    "-o", str(trace), *words], cwd=private, env=env, capture_output=True, timeout=30)
                value = json.loads(result.stdout)
                require((result.returncode == 0) == (control == "plan") and value["executed"] is False,
                        "refusal_or_plan_executed")
                rows = trace.read_text()
                require(all("execve(" + json.dumps(str(paths[role])) + "," not in rows
                            for role in ("agentfw", "claude")), "refused_entry_started_selected_runtime")
                require(not list(root.glob("soup-wall-run-*")), "refusal_created_runtime_state")
                if control == "occupied-port":
                    require(owner.fileno() >= 0, "foreign_listener_changed")
                report["cases"].append({"case": control, "status": "passed", "selected_execution": 0,
                                        "reason": value.get("reason"), "trace_sha256": BASE.sha(trace)})
            finally:
                if args.selection.read_bytes() != original:
                    args.selection.write_bytes(original)
                owner.close()
        for case in ("useful-refusal", "ask", "default", "cancel", "daemon-loss", "timeout"):
            report["active_case"] = case
            root = private / case
            root.mkdir(mode=0o700)
            state = root / "state"
            state.mkdir(mode=0o700)
            model = BASE.DEMO.ScriptedModel([])
            offered = set()
            proposals = [("filesystem", "read_text_file", {"path": "/workspace/notes.txt"}),
                         ("git", "git_status", {"repo_path": "/workspace"}),
                         ("git", "git_reset", {"repo_path": "/workspace"})]
            if case == "ask":
                proposals = [proposals[0], ("filesystem", "read_text_file", {"path": "/workspace/credentials.txt"}),
                             ("filesystem", "read_text_file", {"path": "/workspace/followup.txt"})]
            elif case == "default":
                proposals = [proposals[0], ("filesystem", "read_text_file", {"path": "/workspace/credentials.txt"})]
            hold = case in ("cancel", "daemon-loss", "timeout")
            def next_step(body):
                names = {tool.get("name") for tool in body.get("tools", [])}
                if not {"mcp__filesystem__read_text_file", "mcp__git__git_status"}.issubset(names):
                    return [{"type": "text", "text": "Owned auxiliary request."}]
                for message in body.get("messages", []):
                    for block in message.get("content", []) if isinstance(message.get("content"), list) else []:
                        if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id") in offered:
                            model.results[block["tool_use_id"]] = {"is_error": bool(block.get("is_error")), "content": block.get("content")}
                if hold:
                    # Owned provider delay keeps an actual host alive for lifecycle controls.
                    time.sleep(8)
                    return [{"type": "text", "text": "Owned lifecycle control."}]
                for i, (server, tool, arguments) in enumerate(proposals):
                    identifier = f"toolu_prepared_{i}"
                    if identifier not in model.results:
                        require(identifier not in offered, "original_request_reissued")
                        offered.add(identifier)
                        return [{"type": "tool_use", "id": identifier, "name": f"mcp__{server}__{tool}", "input": arguments}]
                return [{"type": "text", "text": "Owned prepared run completed."}]
            model.next = next_step
            command = [str(args.strace), "-f", "-qq", "-s", "1048576", "-e", "trace=execve,openat,write,writev",
                "-o", str(root / "trace.private"), sys.executable, "-B", str(ROOT / "scripts/pilot-run.py"),
                "--run", "--selection", str(args.selection), "--expected-commit", args.expected_commit,
                "--state-root", str(state), "--timeout-seconds", "3" if case == "timeout" else "60"]
            if case == "ask":
                command += ["--ask-wait-seconds", "25"]
            run_env = dict(env, ANTHROPIC_BASE_URL=model.url, ANTHROPIC_API_KEY="owned-loopback-only",
                HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9", NO_PROXY="127.0.0.1,localhost,::1")
            process = witness = record = None
            decisions = []
            try:
                with (root / "stdout.private").open("wb") as out, (root / "stderr.private").open("wb") as err:
                    process = subprocess.Popen(command, cwd=private, env=run_env, stdout=out, stderr=err,
                                               start_new_session=True)
                    witness = BASE.ProcessWitness(process.pid)
                    def identify():
                        records = list(state.glob("*/run.json"))
                        if records:
                            try:
                                return json.loads(records[0].read_bytes())
                            except (OSError, ValueError):
                                return None
                        if process.poll() is not None:
                            raise ValueError("prepared_entry_exited_before_host")
                    record = until(identify, "prepared_run_not_published", seconds=90)
                    home = Path(record["home"])
                    decisions = []
                    if case == "ask":
                        deadline = time.monotonic() + 75
                        while process.poll() is None and time.monotonic() < deadline:
                            for manifest in (home / "pilot-runs").glob("*/run.json"):
                                prefix = [str(paths["agentfw"]), "pilot-approval", "--home", str(home), "--run", manifest.parent.name]
                                listing = subprocess.run([*prefix, "list"], capture_output=True, env=run_env, timeout=10)
                                if listing.returncode != 0:
                                    continue  # Launcher may be completing owned retirement.
                                for waiting in json.loads(listing.stdout):
                                    require(waiting["pending_id"] not in decisions, "pending_reissued_after_approval")
                                    shown = subprocess.run([*prefix, "inspect", waiting["pending_id"]],
                                        capture_output=True, env=run_env, timeout=10)
                                    require(shown.returncode == 0, "prepared_exact_inspection_failed")
                                    exact = json.loads(shown.stdout)
                                    require((waiting["server"], waiting["tool"], exact["args"]) in proposals,
                                            "prepared_inspection_not_selected_call")
                                    fingerprint = BASE.hashlib.sha256(json.dumps(exact["args"], sort_keys=True,
                                        separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
                                    def no_original_dispatch():
                                        try:
                                            raw = (root / "trace.private").read_text()
                                            require(len(raw) <= 32 * 1024 * 1024, "private_trace_limit")
                                            observed = LAUNCH.collector_dispatches(raw, paths["agentfw"], strict=False)
                                        except ValueError:
                                            return None  # Partial live syscalls do not prove zero.
                                        return not any(call["tool"] == waiting["tool"] and
                                            call["args_sha256"] == fingerprint for call in observed["calls"])
                                    require(until(no_original_dispatch, "prepared_dispatch_before_approval", seconds=2),
                                            "prepared_dispatch_before_approval")
                                    if exact["args"].get("path") == "/workspace/credentials.txt":
                                        require(ASK.SELECTED.trace_effects(root / "trace.private", "filesystem",
                                            target="/workspace/credentials.txt") == 0, "prepared_ask_effect_before_approval")
                                    result = subprocess.run([*prefix, "approve", waiting["pending_id"],
                                        "--binding", waiting["binding_sha256"]], capture_output=True, env=run_env, timeout=10)
                                    require(result.returncode == 0, "prepared_operator_decision_failed")
                                    decisions.append(waiting["pending_id"])
                            time.sleep(.1)
                    elif case in ("cancel", "daemon-loss"):
                        until(lambda: bool(model.requests), "actual_host_request_missing")
                        if case == "cancel":
                            # Trace wrapper is not the orchestrator: identify its actual Python exec.
                            supervisor = Path("/proc") / str(record["supervisor_pid"])
                            require(supervisor.stat().st_uid == os.getuid() and
                                str(ROOT / "scripts/pilot-run.py").encode() in
                                (supervisor / "cmdline").read_bytes().split(b"\0"),
                                "owned_orchestrator_identity_ambiguous")
                            os.kill(record["supervisor_pid"], signal.SIGTERM)
                        else:
                            os.kill(record["daemon_pid"], signal.SIGKILL)
                    process.wait(timeout=100)
                rows = (root / "stdout.private").read_text().splitlines()
                outcome = json.loads(rows[-1])
                success = case in ("useful-refusal", "ask", "default")
                require((process.returncode == 0) == success, "prepared_run_outcome_mismatch")
                if not success:
                    expected = {"cancel": {"pilot_cancelled"}, "daemon-loss": {"owned_daemon_lost"},
                                "timeout": {"restricted_launcher_failed", "pilot_timeout"}}
                    require(outcome.get("reason") in expected[case], "prepared_wrong_failure_reason")
                require(any('execve(' + json.dumps(str(paths["claude"])) + ',' in row and row.endswith(" = 0")
                            for row in LAUNCH.normalized_syscalls((root / "trace.private").read_text())[0]),
                        "actual_pinned_host_execution_not_observed")
                cleanup = witness.finish()
                require(cleanup["all_stopped"], "prepared_owned_process_survived")
                require(outcome["cleanup"] == "owned_state_removed" and not list(state.iterdir()), "owned_state_survived")
                result = {"case": case, "status": "passed", "outcome": outcome["status"],
                          "cleanup": outcome["cleanup"], "process_cleanup": cleanup,
                          "trace_sha256": BASE.sha(root / "trace.private")}
                if success:
                    require(len(model.results) == len(proposals), "prepared_correlated_results_missing")
                    useful_result(model.results, "toolu_prepared_0", notes.splitlines()[0])
                    if case == "ask":
                        useful_result(model.results, "toolu_prepared_1", "Owned synthetic sensitive path control.")
                        useful_result(model.results, "toolu_prepared_2", "Owned prepared continuation.")
                    require(model.results["toolu_prepared_1"]["is_error"] == (case == "default"), "prepared_continuation_outcome_wrong")
                    require(len(decisions) == (2 if case == "ask" else 0), "prepared_explicit_decisions_missing")
                    if case == "default":
                        require(selection['expected_refusal']['rule'] in json.dumps(model.results['toolu_prepared_1']),
                                'prepared_default_wrong_refusal_rule')
                    if case == "useful-refusal":
                        require("tracked.txt" in json.dumps(model.results["toolu_prepared_1"]), "prepared_git_bytes_missing")
                        require(model.results["toolu_prepared_2"]["is_error"] is True, "prepared_mutator_not_refused")
                        git_execs = []
                        for row in LAUNCH.normalized_syscalls((root / "trace.private").read_text())[0]:
                            match = RUN.re.search(r'execve\("/mcp-runtime/git", (\[.*\]), .*\) += 0$', row)
                            if match and "status" in json.loads(match.group(1)):
                                git_execs.append(row)
                        require(len(git_execs) == 1, "prepared_kernel_git_status_witness_missing")
                        result["kernel_git_status_count"] = len(git_execs)
                    observation = LAUNCH.collector_dispatches((root / "trace.private").read_text(), paths["agentfw"], strict=False)
                    counts = [sum(call["tool"] == tool and call["args_sha256"] == BASE.hashlib.sha256(
                        json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
                        for call in observation["calls"]) for _, tool, arguments in proposals]
                    require(counts == ([1, 1, 0] if case == "useful-refusal" else [1, 0] if case == "default" else [1, 1, 1]), "prepared_dispatch_counts_wrong")
                    require(ASK.SELECTED.trace_effects(root / "trace.private", "filesystem",
                        target="/workspace/credentials.txt" if case == "ask" else "/workspace/notes.txt") == 1,
                        "prepared_kernel_read_witness_missing")
                    result.update(dispatch_counts=counts, exact_once_kernel_read=True,
                                  explicit_harness_decisions=len(decisions),
                                  correlated_useful_continuation=case != "default")
                else:
                    result["failure_reason"] = outcome["reason"]
                report["cases"].append(result)
            except Exception:
                observation = {"provider_request_count": len(model.requests),
                    "correlated_results": {key: value["is_error"] for key, value in model.results.items()},
                    "operator_decision_count": len(decisions)}
                try:
                    outcome = json.loads((root / "stdout.private").read_text().splitlines()[-1])
                    observation.update(entry_status=outcome.get("status"), entry_reason=outcome.get("reason"))
                except (OSError, ValueError, IndexError):
                    observation["entry_report"] = "not_published"
                report["failure_observation"] = observation
                raise
            finally:
                # strace is only an observer: terminating it does not cancel the
                # orchestrator. Signal the independently identified owned entry.
                if record is not None and process is not None and process.poll() is None:
                    supervisor = Path("/proc") / str(record["supervisor_pid"])
                    try:
                        if (supervisor.stat().st_uid == os.getuid() and
                            str(ROOT / "scripts/pilot-run.py").encode() in
                            (supervisor / "cmdline").read_bytes().split(b"\0")):
                            os.kill(record["supervisor_pid"], signal.SIGTERM)
                            process.wait(timeout=15)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                if witness is not None:
                    cleanup = witness.finish()
                    for row in cleanup["remaining"]:
                        if BASE.ProcessWitness.identity(row["pid"]) == row["start_time_ticks"]:
                            try:
                                os.kill(row["pid"], signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait(timeout=10)
                model.close()
        require(workspace_before == {"filesystem": BASE.snapshot(fs), "git": BASE.snapshot(git)}, "prepared_workspace_changed")
        require(selected_before == {role: BASE.sha(path) for role, path in paths.items()}, "prepared_selected_assets_changed")
        require(sentinel.read_text() == "must survive" and unrelated.poll() is None, "unrelated_state_changed")
        report.update(status="passed", source_after=RUN.PREP.PILOT.source(), unrelated_preserved=True,
                      workspace_unchanged=True, selected_assets_unchanged=True)
        require(report["source_after"] == before, "source_changed_during_qualification")
    finally:
        unrelated.terminate(); unrelated.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--strace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    report = {"format": "sw-prepared-pilot-acceptance/1", "status": "failed", "cases": [],
              "provider": "owned-scripted-loopback", "live_model_effectiveness": "not_tested"}
    try:
        with tempfile.TemporaryDirectory(prefix="sou116-private-") as temporary:
            qualify(args, Path(temporary), report)
    except Exception as error:
        value = str(error)
        frame = traceback.extract_tb(error.__traceback__)[-1]
        report.update(status="failed", reason=value if RUN.re.fullmatch(r"[a-z0-9_]{1,100}", value) else "qualification_failure",
                      failure_location={"function": frame.name, "line": frame.lineno})
    (args.output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "reason": report.get("reason"), "cases": len(report["cases"])}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
