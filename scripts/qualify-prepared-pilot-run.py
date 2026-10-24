#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual-host qualification of prepared selection, lifecycle and exact stop.

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
import threading
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
STORE = load("sou132_store", "sou84_owned_acceptance.py")
STOP = load("sou125_prepared_stop", "prepared_stop_witness.py")
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


def validation_timeout(args):
    value = getattr(args, "validation_timeout_seconds", 30)
    require(type(value) is int and 30 <= value <= 180, "validation_deadline_out_of_range")
    return value


def qualify(args, private, report):
    control_seconds = validation_timeout(args)
    before = RUN.PREP.PILOT.source()
    require(not before["dirty"] and before["commit"] == args.expected_commit, "exact_clean_source_required")
    config = argparse.Namespace(selection=args.selection, expected_commit=args.expected_commit,
        ask_wait_seconds=0, timeout_seconds=60, port=0)
    selection, paths, profiles = RUN.selected(config)
    require("prepared_workspaces" not in selection, "generated_qualification_refuses_existing_project")
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
    unrelated = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(1800)"],
                                 start_new_session=True, env=env, cwd=private)
    report.update(source_before=before, selected_sha256=selected_before, cases=[],
                  trace_requested={"mode": "seccomp-bpf", "fallback_possible": True,
                                   "run_syscalls": "execve,openat,write,writev",
                                   "validation_syscalls": "execve"})
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
                result = subprocess.run([str(args.strace), "-f", "--seccomp-bpf", "-qq", "-s", "4096", "-e", "trace=execve",
                    "-o", str(trace), *words], cwd=private, env=env, capture_output=True, timeout=control_seconds)
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
        cases = ("useful-refusal", "ask", "default", "cancel", "daemon-loss", "host-crash", "timeout")
        audit_only = getattr(args, "audit_retention_only", False)
        if audit_only:
            cases = ("audit-rotation", "audit-unavailable", "useful-refusal")
        for case in cases:
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
            elif case == "audit-unavailable":
                proposals = proposals[:2]
            hold = case in ("cancel", "daemon-loss", "host-crash", "timeout")
            lifecycle_ready = threading.Event()
            audit_ready = threading.Event()
            audit_observed = {}
            def next_step(body):
                names = {tool.get("name") for tool in body.get("tools", [])}
                if not {"mcp__filesystem__read_text_file", "mcp__git__git_status"}.issubset(names):
                    return [{"type": "text", "text": "Owned auxiliary request."}]
                for message in body.get("messages", []):
                    for block in message.get("content", []) if isinstance(message.get("content"), list) else []:
                        if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id") in offered:
                            model.results[block["tool_use_id"]] = {"is_error": bool(block.get("is_error")), "content": block.get("content")}
                if case == "audit-unavailable" and "toolu_prepared_0" in model.results:
                    require(audit_ready.wait(15), "prepared_audit_context_missing")
                    if not audit_observed:
                        active = Path(record["home"]).parent / "audit"
                        manifest = RUN.AUDIT.private_json(active / "manifest.json")
                        segment = active / f"segment-{manifest['segments'][-1]['id']:020}.jsonl"
                        # Owned fault injection: exhaust the declared active-segment
                        # bound. This is not a claim of filling the physical disk.
                        with segment.open("ab") as stream:
                            stream.write(b"x" * RUN.AUDIT.LIMITS["segment_size_bytes"])
                        audit_observed["injected_active_segment_limit"] = True
                    if "toolu_prepared_1" in model.results:
                        health = STORE.request(record["port"], "/health")
                        require(health["audit"]["state"] == "unavailable", "prepared_audit_failure_not_latched")
                        audit_observed["sink_unavailable"] = True
                if case == "audit-rotation" and "toolu_prepared_0" in model.results and not audit_observed:
                    require(audit_ready.wait(15), "prepared_audit_context_missing")
                    active = Path(record["home"]).parent
                    current = RUN.native_instance(record["port"], audit_token)["instance_id"]
                    reader_results = []
                    reader_started = threading.Event()
                    def concurrent_reader():
                        receipt = RUN.AUDIT.private_json(active / "audit-run.json")
                        reader_started.set()
                        for ordinal in range(8):
                            try:
                                RUN.AUDIT.export_run(active, root / f"reader-{ordinal}.json", receipt["run_id"])
                                reader_results.append("snapshot")
                            except RUN.AUDIT.REPORT.ReportError as error:
                                reader_results.append("retry" if str(error) in (
                                    "retention changed during export; retry", "retained segment was replaced during export")
                                    else "unexpected_failure")
                            time.sleep(.01)
                    reader = threading.Thread(target=concurrent_reader, daemon=True)
                    reader.start()
                    require(reader_started.wait(5), "prepared_audit_reader_not_started")
                    for index in range(2000):
                        STORE.request(record["port"], "/hook", {"session_id": "owned-audit-rotation",
                            "hook_event_name": "SOU132FutureEvent", "synthetic": "PRIVATE_SOU132_CANARY"}, hook_token)
                        if index in (200, 1000):
                            receipt = RUN.AUDIT.private_json(active / "audit-run.json")
                            result = RUN.AUDIT.export_run(active, root / f"active-export-{index}.json", receipt["run_id"])
                            require(result["completeness"] == "incomplete", "active_audit_export_overclaimed")
                    manifest = RUN.AUDIT.private_json(active / "audit" / "manifest.json")
                    reader.join(timeout=10)
                    require(not reader.is_alive() and len(reader_results) == 8
                            and "unexpected_failure" not in reader_results, "prepared_audit_concurrent_reader_failed")
                    size = STORE.owned_bytes(active / "audit")
                    require(manifest["pruned_through"] > 0 and size <= RUN.AUDIT.LIMITS["total_disk_bytes"]
                            and RUN.native_instance(record["port"], audit_token)["instance_id"] == current,
                            "prepared_audit_rotation_or_instance_failed")
                    audit_observed.update(pruned_through=manifest["pruned_through"], owned_bytes=size,
                                          active_exports=2, concurrent_snapshots=reader_results.count("snapshot"),
                                          concurrent_retries=reader_results.count("retry"), unchanged_native_instance=True)
                if hold:
                    # Owned provider delay keeps an actual host alive for lifecycle controls.
                    lifecycle_ready.set()  # Both original servers are in this host's tool catalog.
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
            command = [str(args.strace), "-f", "--seccomp-bpf", "-qq", "-s", "1048576", "-e", "trace=execve,openat,write,writev",
                "-o", str(root / "trace.private"), sys.executable, "-B", str(ROOT / "scripts/pilot-run.py"),
                "--run", "--selection", str(args.selection), "--expected-commit", args.expected_commit,
                "--state-root", str(state), "--timeout-seconds", "3" if case == "timeout" else "180" if case == "audit-rotation" else "60"]
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
                    if case in ("audit-rotation", "audit-unavailable"):
                        audit_token = (home / "native-token").read_text().strip()
                        hook_token = (home / "token").read_text().strip()
                        audit_ready.set()
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
                    elif case in ("cancel", "daemon-loss", "host-crash"):
                        until(lambda: lifecycle_ready.is_set(), "actual_host_request_missing", seconds=75)
                        if case == "cancel":
                            # Trace wrapper is not the orchestrator: identify its actual Python exec.
                            supervisor = Path("/proc") / str(record["supervisor_pid"])
                            require(supervisor.stat().st_uid == os.getuid() and
                                str(ROOT / "scripts/pilot-run.py").encode() in
                                (supervisor / "cmdline").read_bytes().split(b"\0"),
                                "owned_orchestrator_identity_ambiguous")
                            os.kill(record["supervisor_pid"], signal.SIGTERM)
                        elif case == "daemon-loss":
                            os.kill(record["daemon_pid"], signal.SIGKILL)
                        else:
                            def actual_host():
                                witness.sample()
                                matches = []
                                for (pid, start), _ in list(witness.observed.items()):
                                    if BASE.ProcessWitness.identity(pid) != start:
                                        continue
                                    try:
                                        if Path(f"/proc/{pid}/exe").samefile(paths["claude"]):
                                            matches.append((pid, start))
                                    except OSError:
                                        continue
                                return matches[0] if len(matches) == 1 else None
                            pid, start = until(actual_host, "prepared_owned_host_identity_missing")
                            require(BASE.ProcessWitness.identity(pid) == start, "prepared_owned_host_identity_changed")
                            os.kill(pid, signal.SIGKILL)
                    process.wait(timeout=220 if case == "audit-rotation" else 100)
                rows = (root / "stdout.private").read_text().splitlines()
                outcome = json.loads(rows[-1])
                success = case in ("useful-refusal", "ask", "default", "audit-rotation", "audit-unavailable")
                require((process.returncode == 0) == success, "prepared_run_outcome_mismatch")
                if not success:
                    expected = {"cancel": {"pilot_cancelled"}, "daemon-loss": {"owned_daemon_lost"},
                                "host-crash": {"restricted_launcher_failed"},
                                "timeout": {"restricted_launcher_failed", "pilot_timeout"}}
                    require(outcome.get("reason") in expected[case], "prepared_wrong_failure_reason")
                    require(outcome["status"] == "failed", "prepared_false_terminal_success")
                require(any('execve(' + json.dumps(str(paths["claude"])) + ',' in row and row.endswith(" = 0")
                            for row in LAUNCH.normalized_syscalls((root / "trace.private").read_text())[0]),
                        "actual_pinned_host_execution_not_observed")
                cleanup = witness.finish()
                require(cleanup["all_stopped"], "prepared_owned_process_survived")
                require(outcome["cleanup"] == "owned_processes_stopped_audit_retained"
                        and len(list(state.iterdir())) == 1, "owned_state_survived")
                retained = Path(outcome["audit"]["directory"])
                run_id = RUN.AUDIT.verify_cleanup(retained)
                if case == "audit-unavailable":
                    try:
                        RUN.AUDIT.export_run(retained, root / "audit-summary.json", run_id)
                    except RUN.AUDIT.REPORT.ReportError as error:
                        require(str(error) == "retained segment is unsafe or exceeds limit", "prepared_audit_wrong_export_failure")
                    else:
                        raise ValueError("prepared_audit_unsafe_export_succeeded")
                    require(not (root / "audit-summary.json").exists() and audit_observed.get("sink_unavailable"),
                            "prepared_audit_failure_overclaimed")
                    audit_export = {"status": "refused", "reason": "unsafe_or_over_limit_retained_evidence"}
                else:
                    audit_export = RUN.AUDIT.export_run(retained, root / "audit-summary.json", run_id)
                    audit_summary = json.loads((root / "audit-summary.json").read_bytes())
                    require(audit_summary["source_commit"] == args.expected_commit
                            and audit_summary["policy_sha256"] == selected_before["policy"]
                            and audit_summary["allow_proves_execution"] is False
                            and b"owned-loopback-only" not in (root / "audit-summary.json").read_bytes(),
                            "prepared_audit_identity_or_privacy_failed")
                result = {"case": case, "status": "passed", "outcome": outcome["status"],
                          "cleanup": outcome["cleanup"], "process_cleanup": cleanup,
                          "audit_export": audit_export, "audit_summary_sha256": BASE.sha(root / "audit-summary.json")
                          if (root / "audit-summary.json").exists() else None,
                          "trace_sha256": BASE.sha(root / "trace.private")}
                if case == "audit-rotation":
                    require(audit_observed and "intentional_retention" in audit_export["notices"],
                            "prepared_audit_loss_not_exported")
                    result["audit_rotation"] = audit_observed
                elif case == "audit-unavailable":
                    result["audit_failure"] = audit_observed
                if success:
                    require(len(model.results) == len(proposals), "prepared_correlated_results_missing")
                    useful_result(model.results, "toolu_prepared_0", notes.splitlines()[0])
                    if case == "ask":
                        useful_result(model.results, "toolu_prepared_1", "Owned synthetic sensitive path control.")
                        useful_result(model.results, "toolu_prepared_2", "Owned prepared continuation.")
                    require(model.results["toolu_prepared_1"]["is_error"] == (case in ("default", "audit-unavailable")), "prepared_continuation_outcome_wrong")
                    require(len(decisions) == (2 if case == "ask" else 0), "prepared_explicit_decisions_missing")
                    if case == "default":
                        require(selection['expected_refusal']['rule'] in json.dumps(model.results['toolu_prepared_1']),
                                'prepared_default_wrong_refusal_rule')
                    if case in ("useful-refusal", "audit-rotation"):
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
                    require(counts == ([1, 1, 0] if case in ("useful-refusal", "audit-rotation") else [1, 0] if case in ("default", "audit-unavailable") else [1, 1, 1]), "prepared_dispatch_counts_wrong")
                    require(ASK.SELECTED.trace_effects(root / "trace.private", "filesystem",
                        target="/workspace/credentials.txt" if case == "ask" else "/workspace/notes.txt") == 1,
                        "prepared_kernel_read_witness_missing")
                    result.update(dispatch_counts=counts, exact_once_kernel_read=True,
                                  explicit_harness_decisions=len(decisions),
                                  correlated_useful_continuation=case not in ("default", "audit-unavailable"))
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
        if not audit_only:
            STOP.qualify(args, private, report, RUN, LAUNCH, ASK, paths, env, notes, useful_result, unrelated)
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
    parser.add_argument("--validation-timeout-seconds", type=int, default=30)
    parser.add_argument("--audit-retention-only", action="store_true", help="Focus on SOU-132 rotation/export, failed-sink refusal and fresh useful continuation")
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
    if "source_before" in report:
        try:
            report["source_after"] = RUN.PREP.PILOT.source()
            if report["source_after"] != report["source_before"]:
                report.update(status="failed", reason="source_changed_during_qualification")
        except (OSError, ValueError, subprocess.SubprocessError):
            report.update(status="failed", reason="closing_source_identity_unavailable")
    (args.output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "reason": report.get("reason"), "cases": len(report["cases"])}))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
