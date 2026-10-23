# SPDX-License-Identifier: Apache-2.0
"""Owned native Linux witnesses for the existing prepared-pilot stop command.

This is qualification support, never an alternate process owner or stop path.
The installed entry, original host/servers, authenticated CLI and Linux kernel
provide the evidence. Raw authority, provider contents and traces stay private.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from types import SimpleNamespace


def require(condition, code):
    if not condition:
        raise ValueError(code)


def until(check, code, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.05)
    raise ValueError(code)


def exact_stop_response(value, run_id, status):
    require(value == {"run": run_id, "status": status,
                      "running_effects_rolled_back": False}
            and value["running_effects_rolled_back"] is False, "stop_response_not_exact")


def receipt_state(value, run_bytes, terminal):
    require(isinstance(value, dict) and set(value) == {
        "contract", "run_sha256", "status", "signature"}
        and value["contract"] == "sw-pilot-stop/1"
        and value["run_sha256"] == hashlib.sha256(run_bytes).hexdigest()
        and value["status"] in ({"stopped"} if terminal else {"requested", "revoked"})
        and isinstance(value["signature"], str)
        and re.fullmatch(r"[A-Za-z0-9_-]{43}", value["signature"]),
        "stop_receipt_not_exact_terminal" if terminal else "false_stopped_receipt")
    # Authentication is independently checked by the real CLI, not this parser.
    return {"contract": value["contract"], "run_sha256": value["run_sha256"],
            "status": value["status"]}


def enrolled_owners(run, live, verified):
    """Both exact owners must be observed; an empty array cannot prove cleanup."""
    require(live.get("instance_id") == run["instance_id"]
            and live.get("registry_sha256") == run["registry_sha256"],
            "stop_native_instance_changed")
    rows = live.get("pilot_cleanup")
    require(isinstance(rows, list), "stop_owner_observations_missing")
    selected = []
    for server, digest in run["authorities"].items():
        matches = [row for row in rows if row.get("authority_sha256") == digest]
        require(len(matches) == 1 and matches[0].get("host_session") == run["host_session"]
                and matches[0].get("server_id") == server
                and matches[0].get("verified") is verified, "stop_exact_owner_not_observed")
        selected.append({"server": server, "verified": verified})
    require({row["server"] for row in selected} == {"filesystem", "git"},
            "stop_both_selected_owners_required")
    return selected


def process_role(words, pid, collectors, claude):
    if pid in collectors:
        return "collector"
    # Launcher and bwrap argv contain child executable/helper flags as data.
    # Only the executed image's own argv position identifies a helper or host.
    if len(words) > 1 and words[1] == b"--agentfw-mcp-owner-v1":
        return "owner"
    if len(words) > 1 and words[1] == b"--agentfw-mcp-pid1-v1":
        return "pid1"
    if words and words[0] == str(claude).encode():
        return "host"
    return None


def namespace_pid1_status(status, pid, uid):
    fields = {row.split(":", 1)[0]: row.split(":", 1)[1].split()
              for row in status.splitlines() if ":" in row}
    require(fields.get("Uid") == [str(uid)] * 4 and fields.get("NSpid")
            and len(fields["NSpid"]) >= 2 and fields["NSpid"][0] == str(pid)
            and fields["NSpid"][-1] == "1", "stop_pid1_not_in_owned_namespace")


class Provider:
    """Hold original proposals at barriers, including a post-stop attempt."""
    def __init__(self, model, hold_after):
        self.model, self.hold_after = model, hold_after
        self.ready, self.release = threading.Event(), threading.Event()
        self.after_ready, self.after_release = threading.Event(), threading.Event()
        self.future_offered, self.cancelled = threading.Event(), threading.Event()
        self.offered, self.offered_at = set(), {}
        self.calls = [("filesystem", "read_text_file", {"path": "/workspace/notes.txt"}),
                      ("git", "git_status", {"repo_path": "/workspace"}),
                      ("filesystem", "read_text_file", {"path": "/workspace/followup.txt"})]

    def next(self, body):
        require(len(self.model.requests) <= 40, "stop_provider_request_bound")
        names = {tool.get("name") for tool in body.get("tools", [])}
        if not {"mcp__filesystem__read_text_file", "mcp__git__git_status"}.issubset(names):
            return [{"type": "text", "text": "Owned auxiliary request."}]
        for message in body.get("messages", []):
            blocks = message.get("content", [])
            for block in blocks if isinstance(blocks, list) else []:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    identifier = block.get("tool_use_id")
                    if identifier in self.offered:
                        self.model.results[identifier] = {"is_error": bool(block.get("is_error")),
                                                           "content": block.get("content")}
        self.ready.set()
        require(self.release.wait(120), "stop_provider_start_barrier_timeout")
        if self.cancelled.is_set():
            return [{"type": "text", "text": "Owned provider cancelled."}]
        for index, (server, tool, arguments) in enumerate(self.calls):
            if index == 2:
                if not self.hold_after:
                    return [{"type": "text", "text": "Owned peer useful run completed."}]
                self.after_ready.set()
                require(self.after_release.wait(120), "stop_provider_future_barrier_timeout")
                if self.cancelled.is_set():
                    return [{"type": "text", "text": "Owned provider cancelled."}]
            identifier = "toolu_prepared_stop_" + str(index)
            if identifier not in self.model.results:
                require(identifier not in self.offered, "stop_original_proposal_reissued")
                self.offered.add(identifier)
                self.offered_at[identifier] = time.monotonic_ns()
                if index == 2:
                    self.future_offered.set()
                return [{"type": "tool_use", "id": identifier,
                         "name": f"mcp__{server}__{tool}", "input": arguments}]
        return [{"type": "text", "text": "Owned future proposal completed."}]

    def close(self):
        self.cancelled.set()
        self.release.set()
        self.after_release.set()


class Prepared:
    def __init__(self, context, root, hold_after=True, defer_ready=False):
        self.c, self.root = context, root
        root.mkdir(mode=0o700)
        self.state = root / "state"
        self.state.mkdir(mode=0o700)
        self.trace = root / "trace.private"
        self.model = context.base.DEMO.ScriptedModel([])
        # A deliberately disconnected host is expected in a stop witness.
        self.model.server.handle_error = lambda *_: None
        self.provider = Provider(self.model, hold_after)
        self.model.next = self.provider.next
        self.env = dict(context.env, ANTHROPIC_BASE_URL=self.model.url,
            ANTHROPIC_API_KEY="owned-loopback-only", HTTP_PROXY="http://127.0.0.1:9",
            HTTPS_PROXY="http://127.0.0.1:9", NO_PROXY="127.0.0.1,localhost,::1")
        command = [str(context.args.strace), "-f", "-qq", "-s", "1048576", "-e",
            "trace=execve,openat,write,writev,kill", "-o", str(self.trace), sys.executable, "-B",
            str(context.source / "scripts/pilot-run.py"), "--run", "--selection",
            str(context.args.selection), "--expected-commit", context.args.expected_commit,
            "--state-root", str(self.state), "--timeout-seconds", "90"]
        self.out = (root / "stdout.private").open("wb")
        self.err = (root / "stderr.private").open("wb")
        self.process = subprocess.Popen(command, cwd=root, env=self.env, stdout=self.out,
                                        stderr=self.err, start_new_session=True)
        self.witness = context.base.ProcessWitness(self.process.pid)
        self.record = self.run = self.manifest = None
        self.identities = {}
        if not defer_ready:
            try:
                self.wait_ready()
            except Exception:
                self.close()
                raise

    def wait_ready(self):
        def identify():
            for path in self.state.glob("*/run.json"):
                try:
                    record = json.loads(path.read_bytes())
                    home = Path(record["home"])
                    for manifest in (home / "pilot-runs").glob("*/run.json"):
                        run = json.loads(manifest.read_bytes())
                        require(run["launcher_pid"] == record["launcher_pid"]
                                and run["home"] == str(home)
                                and run["run_id"] == manifest.parent.name,
                                "stop_prepared_run_identity_mismatch")
                        self.record, self.home = record, home
                        self.run, self.manifest = run, manifest
                        return True
                except (OSError, json.JSONDecodeError):
                    continue
            require(self.process.poll() is None, "stop_prepared_entry_exited_before_publication")
        until(identify, "stop_prepared_run_not_published", seconds=90)
        until(lambda: self.provider.ready.is_set(), "stop_actual_host_not_ready", seconds=90)
        self.observe()
        self.capture_identities()
        self.initial_owners = enrolled_owners(self.run, self.native(), False)

    def native(self):
        return self.c.run.native_instance(self.record["port"], (self.home / "native-token").read_text().strip())

    def operator_command(self):
        return [str(self.c.paths["agentfw"]), "pilot-approval", "--home", str(self.home),
                "--run", self.run["run_id"], "stop"]

    def operator(self, success, status="stopped"):
        result = subprocess.run(self.operator_command(), cwd=self.root, env=self.env,
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        require((result.returncode == 0) == success, "stop_operator_outcome_mismatch")
        require(len(result.stdout) <= 4096, "stop_operator_output_bound")
        if success:
            exact_stop_response(json.loads(result.stdout), self.run["run_id"], status)
        else:
            require(not result.stdout.strip(), "stop_failed_operator_claimed_success")
        return result

    def observe(self):
        def complete():
            require(self.trace.stat().st_size <= 32 * 1024 * 1024, "stop_trace_bound")
            raw = self.trace.read_text()
            if not raw.endswith("\n"):
                return None
            try:
                return self.c.launch.collector_dispatches(raw, self.c.paths["agentfw"], strict=False)
            except ValueError:
                return None  # Partial live writes cannot establish zero dispatch.
        return until(complete, "stop_complete_wire_observation_missing", seconds=3)

    def capture_identities(self):
        observed = self.observe()
        collectors = observed["collector_servers"]
        require(len(collectors) == 2 and set(collectors.values()) == {"filesystem", "git"},
                "stop_two_live_collectors_required")
        self.witness.sample()
        syscalls = self.c.launch.normalized_syscalls(self.trace.read_text())[0]
        roles = {"host": [], "owner": [], "pid1": [], "collector": []}
        for (pid, start), _row in list(self.witness.observed.items()):
            if self.c.base.ProcessWitness.identity(pid) != start:
                continue
            directory = Path("/proc") / str(pid)
            try:
                words = (directory / "cmdline").read_bytes().split(b"\0")
            except OSError:
                continue  # A short-lived setup child is not a required live owner.
            role = process_role(words, pid, collectors, self.c.paths["claude"])
            if role is None:
                try:
                    if (directory / "exe").samefile(self.c.paths["claude"]):
                        role = "host"  # A native host may rewrite its process title.
                except OSError:
                    pass
            if role is not None:
                row = {"pid": pid, "start_time_ticks": start, "role": role}
                if role == "pid1":
                    # The existing PID1 deliberately sets dumpable=0 to keep
                    # its lease private. Procfs status and strace still prove
                    # its nested PID1 and pinned namespace image without
                    # opening protected exe/ns links or changing that boundary.
                    namespace_pid1_status((directory / "status").read_text(), pid, os.getuid())
                    require(any(re.match(rf'{pid}\s+execve\("/mcp-runtime/owner",', call)
                                and re.search(r'\)\s+= 0$', call) for call in syscalls),
                            "stop_pid1_kernel_image_not_observed")
                else:
                    require(directory.stat().st_uid == os.getuid(), "stop_foreign_process_observed")
                    image = (directory / "exe").stat()
                    selected = self.c.paths["claude"] if role == "host" else self.c.paths["agentfw"]
                    expected = selected.stat()
                    require((image.st_dev, image.st_ino) == (expected.st_dev, expected.st_ino),
                            "stop_observed_process_image_not_selected")
                if role == "collector":
                    row["server"] = collectors[pid]
                roles[role].append(row)
                self.identities[(pid, start)] = row
        require(len(roles["host"]) == 1 and len(roles["owner"]) == 2
                and len(roles["pid1"]) == 2 and len(roles["collector"]) == 2,
                "stop_host_collectors_and_namespace_helpers_not_observed")
        self.roles = roles

    def signal(self, pid, signum):
        matches = [start for (candidate, start) in list(self.witness.observed) if candidate == pid]
        require(len(matches) == 1 and self.c.base.ProcessWitness.identity(pid) == matches[0],
                "stop_signal_owned_identity_changed")
        os.kill(pid, signum)
        if signum == signal.SIGSTOP:
            until(lambda: self.c.base.ProcessWitness.identity(pid) == matches[0]
                  and Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] in ("T", "t"),
                  "stop_owned_process_not_paused", seconds=2)

    def useful(self):
        self.provider.release.set()
        def ready():
            require(self.process.poll() is None, "stop_entry_exited_before_useful_baseline")
            return self.provider.after_ready.is_set()
        until(ready, "stop_useful_baseline_missing", seconds=60)
        self.check_useful()
        require(len(self.observe()["calls"]) == 2, "stop_baseline_dispatch_count_wrong")

    def check_useful(self):
        self.c.useful(self.model.results, "toolu_prepared_stop_0", self.c.notes.splitlines()[0])
        value = self.model.results.get("toolu_prepared_stop_1", {})
        require(value.get("is_error") is False and "tracked.txt" in json.dumps(value.get("content")),
                "stop_git_useful_result_missing")
        rows = self.c.launch.normalized_syscalls(self.trace.read_text())[0]
        executions = [re.search(r'execve\("/mcp-runtime/git", (\[.*\]), .*\) += 0$', row) for row in rows]
        require(sum(match is not None and "status" in json.loads(match[1]) for match in executions) == 1,
                "stop_useful_kernel_git_status_missing")
        require(self.c.ask.SELECTED.trace_effects(self.trace, "filesystem", target="/workspace/notes.txt") == 1,
                "stop_useful_kernel_read_missing")

    def receipt(self, terminal):
        return receipt_state(json.loads(self.manifest.with_name("stop.json").read_bytes()),
                             self.manifest.read_bytes(), terminal)

    def finish(self, stopped=False, failure=None):
        self.process.wait(timeout=105)
        self.out.flush(); self.err.flush()
        outcome = json.loads((self.root / "stdout.private").read_text().splitlines()[-1])
        if failure is not None:
            require(self.process.returncode != 0 and outcome["status"] == "failed"
                    and outcome.get("reason") in failure, "stop_expected_failure_not_reported")
        else:
            require(self.process.returncode == 0 and outcome["status"] == ("stopped" if stopped else "completed"),
                    "stop_prepared_terminal_outcome_wrong")
        cleanup = self.witness.finish()
        require(cleanup["all_stopped"], "stop_owned_descendant_survived")
        require(all(self.c.base.ProcessWitness.identity(pid) != start for pid, start in self.identities),
                "stop_host_collector_or_helper_survived")
        if stopped:
            require(outcome["cleanup"] == "owned_processes_stopped_state_retained"
                    and outcome["running_effects_rolled_back"] is False
                    and Path(outcome["retained_stop_state"]) == self.home.parent,
                    "stop_exact_recovery_state_not_retained")
            self.receipt(True)
            self.operator(True, "already_stopped")
        elif failure is None:
            require(outcome["cleanup"] == "owned_state_removed" and not list(self.state.iterdir()),
                    "stop_peer_owned_state_survived")
        return {"entry_status": outcome["status"], "entry_reason": outcome.get("reason"),
                "cleanup": outcome["cleanup"], "process_cleanup": cleanup,
                "observed_owned_roles": list(self.identities.values()),
                "trace_sha256": self.c.base.sha(self.trace)}

    def diagnostic(self):
        value = {"provider_request_count": len(self.model.requests),
                 "offered_proposal_count": len(self.provider.offered),
                 "correlated_result_errors": {key: row["is_error"] for key, row in self.model.results.items()},
                 "entry_returncode": self.process.poll(),
                 "observed_owned_roles": list(self.identities.values())}
        try:
            self.out.flush()
            outcome = json.loads((self.root / "stdout.private").read_text().splitlines()[-1])
            value["entry_status"] = outcome.get("status")
            value["entry_reason"] = outcome.get("reason")
        except (OSError, ValueError, IndexError):
            value["entry_report"] = "not_published"
        if self.trace.exists():
            value["trace_sha256"] = self.c.base.sha(self.trace)
        return value

    def close(self):
        self.provider.close()
        if self.record is not None and self.process.poll() is None:
            try:
                self.signal(self.record["supervisor_pid"], signal.SIGTERM)
                self.process.wait(timeout=18)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
        cleanup = self.witness.finish()
        for row in cleanup["remaining"]:
            if self.c.base.ProcessWitness.identity(row["pid"]) == row["start_time_ticks"]:
                try:
                    os.kill(row["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)
        self.out.close(); self.err.close()
        self.model.close()


def record_controls(pilot, unrelated, report):
    original = pilot.manifest.read_bytes()
    sentinel_identity = pilot.c.base.ProcessWitness.identity(unrelated.pid)
    stopped = pilot.manifest.with_name("stop.json")
    cases = []
    for case in ("forged-run", "stale-start", "foreign-live-pid", "foreign-pid-reused-start", "forged-stopped-receipt"):
        changed = json.loads(original)
        try:
            if case == "forged-run":
                changed["host_session"] = "forged-owned-witness-host"
            elif case == "stale-start":
                changed["launcher_start"] += 1
            elif case in ("foreign-live-pid", "foreign-pid-reused-start"):
                changed["launcher_pid"] = unrelated.pid
                changed["launcher_start"] = sentinel_identity + (case == "foreign-pid-reused-start")
            else:
                stopped.write_text(json.dumps({"contract": "sw-pilot-stop/1",
                    "run_sha256": hashlib.sha256(original).hexdigest(), "status": "stopped",
                    "signature": "A" * 43}))
                stopped.chmod(0o600)
            if case != "forged-stopped-receipt":
                pilot.manifest.write_text(json.dumps(changed))
            pilot.operator(False)
            require(pilot.process.poll() is None and unrelated.poll() is None
                    and pilot.c.base.ProcessWitness.identity(unrelated.pid) == sentinel_identity,
                    "stop_refused_record_changed_process")
            require(case == "forged-stopped-receipt" or not stopped.exists(),
                    "stop_refused_record_created_intent")
            cases.append({"case": case, "status": "passed", "operator_refused": True,
                          "pid_reuse_scope": "forged_start_ticks_no_forced_kernel_pid_reuse"
                          if case == "foreign-pid-reused-start" else None})
        finally:
            pilot.manifest.write_bytes(original)
            if stopped.exists():
                stopped.unlink()
    report["record_controls"] = cases


def concurrent(context, private, report, unrelated):
    active = []
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0)); listener.listen()
    listener_identity = listener.getsockname()
    unrelated_identity = context.base.ProcessWitness.identity(unrelated.pid)
    try:
        # Spawn both entries before waiting for either costly native startup.
        # Sequential startup consumed the first host's unchanged 90s budget.
        selected = Prepared(context, private / "selected", defer_ready=True)
        active.append(selected)
        peer = Prepared(context, private / "peer", hold_after=False, defer_ready=True)
        active.append(peer)
        selected.wait_ready()
        require(not selected.observe()["calls"], "stop_dispatch_before_provider_barrier")
        # The peer is already starting, with its provider barrier closed. Run
        # independent selected controls now instead of spending its live budget
        # waiting for the peer's cold setup. Both peers are proven ready before
        # stop; both useful peer dispatches still happen strictly after stop.
        record_controls(selected, unrelated, report)
        selected.useful()
        baseline = selected.observe()["calls"]
        peer.wait_ready()
        require(selected.run["run_id"] != peer.run["run_id"]
                and selected.home != peer.home and selected.record["port"] != peer.record["port"],
                "stop_independent_prepared_runs_required")
        require(not peer.observe()["calls"], "stop_dispatch_before_provider_barrier")
        require(not peer.observe()["calls"] and not peer.provider.offered,
                "stop_peer_original_action_occurred_early")
        selected.operator(True)
        stopped_at = time.monotonic_ns()
        receipt = selected.receipt(True)
        report["selected"] = selected.finish(stopped=True)
        # Attempt an additional original tool proposal only after authenticated
        # completion. The terminated host/collectors cannot dispatch it.
        selected.provider.after_release.set()
        require(selected.provider.future_offered.wait(3), "stop_future_proposal_not_attempted")
        require(selected.provider.offered_at["toolu_prepared_stop_2"] > stopped_at
                and selected.observe()["calls"] == baseline,
                "stop_future_original_dispatch_observed")
        require(peer.process.poll() is None and unrelated.poll() is None
                and context.base.ProcessWitness.identity(unrelated.pid) == unrelated_identity,
                "stop_changed_other_run_or_process")
        enrolled_owners(peer.run, peer.native(), False)
        peer.provider.release.set()
        report["peer"] = peer.finish()
        peer.check_useful()
        require(all(value > stopped_at for value in peer.provider.offered_at.values())
                and len(peer.observe()["calls"]) == 2, "stop_peer_not_useful_after_selected_stop")
        require(context.ask.SELECTED.trace_effects(peer.trace, "filesystem", target="/workspace/notes.txt") == 1,
                "stop_peer_kernel_read_missing")
        require(context.ask.SELECTED.trace_effects(selected.trace, "filesystem", target="/workspace/followup.txt") == 0,
                "stop_future_kernel_read_observed")
        # Connecting and accepting on the same pre-existing socket proves it is
        # still a functioning listener, beyond an unchanged descriptor number.
        with socket.create_connection(listener_identity, timeout=2) as client:
            connection, _ = listener.accept()
            with connection:
                client.sendall(b"owned-unrelated")
                require(connection.recv(32) == b"owned-unrelated", "stop_unrelated_listener_changed")
        require(listener.getsockname() == listener_identity, "stop_unrelated_listener_changed")
        report.update(status="passed", exact_authenticated_receipt=receipt,
            selected_owner_obligations=selected.initial_owners, future_dispatches=0,
            future_kernel_reads=0, peer_original_dispatches_after_stop=2,
            peer_useful_after_stop=True, unrelated_listener_preserved=True,
            unrelated_process_identity_preserved=True,
            running_effects_rolled_back=False)
    except Exception:
        report["failure_observations"] = [pilot.diagnostic() for pilot in active]
        raise
    finally:
        for pilot in reversed(active):
            pilot.close()
        listener.close()


def lifecycle(context, private, report, case):
    pilot = Prepared(context, private)
    operator = None
    paused = []
    try:
        pilot.useful()
        baseline = pilot.observe()["calls"]
        if case == "interrupted-stop":
            # Stop the existing launcher at a known point, interrupt only the
            # CLI after durable revocation, then let its existing cleanup resume.
            launcher = pilot.record["launcher_pid"]
            pilot.signal(launcher, signal.SIGSTOP); paused.append(launcher)
            with (private / "operator.stdout.private").open("wb") as out, (
                    private / "operator.stderr.private").open("wb") as err:
                operator = subprocess.Popen(pilot.operator_command(), cwd=private, env=pilot.env,
                    stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True)
                until(lambda: pilot.manifest.with_name("stop.json").exists()
                      and pilot.receipt(False)["status"] == "revoked", "stop_revocation_not_durable", seconds=5)
                require(operator.poll() is None, "stop_operator_finished_before_interruption")
                operator.kill(); operator.wait(timeout=5)
            require(operator.returncode != 0 and not (private / "operator.stdout.private").read_bytes().strip(),
                    "stop_interrupted_operator_claimed_success")
            pilot.signal(launcher, signal.SIGCONT); paused.remove(launcher)
            report.update(pilot.finish(stopped=True), interrupted_operator=True,
                          exact_authenticated_receipt=pilot.receipt(True))
        elif case == "unconfirmed-namespace-stop":
            collector = next(row["pid"] for row in pilot.roles["collector"] if row["server"] == "filesystem")
            pilot.signal(collector, signal.SIGSTOP); paused.append(collector)
            pilot.operator(False)
            report.update(pilot.finish(failure={"restricted_launcher_failed"}),
                stop_receipt=pilot.receipt(False), namespace_cleanup_unconfirmed=True,
                terminal_success_refused=True)
            pilot.operator(False)
        elif case == "daemon-loss-stop":
            # Freeze both existing owners so neither can retire metadata before
            # the CLI records intent and observes lost daemon authority.
            supervisor = pilot.record["supervisor_pid"]
            launcher = pilot.record["launcher_pid"]
            pilot.signal(supervisor, signal.SIGSTOP); paused.append(supervisor)
            pilot.signal(launcher, signal.SIGSTOP); paused.append(launcher)
            pilot.signal(pilot.record["daemon_pid"], signal.SIGKILL)
            pilot.operator(False)
            pilot.signal(supervisor, signal.SIGCONT); paused.remove(supervisor)
            # Observe the supervisor entering its failure cleanup before the
            # launcher can exit. A delay cannot prove this ordering.
            until(lambda: any(re.fullmatch(rf"{supervisor}\s+kill\(-{launcher}, SIGTERM\)\s+= 0", row)
                for row in context.launch.normalized_syscalls(pilot.trace.read_text())[0]),
                "stop_daemon_loss_supervisor_cleanup_not_observed", seconds=5)
            pilot.signal(launcher, signal.SIGCONT); paused.remove(launcher)
            report.update(pilot.finish(failure={"owned_daemon_lost"}),
                stop_receipt=pilot.receipt(False), terminal_success_refused=True)
            pilot.operator(False)
        else:
            raise ValueError("stop_unknown_lifecycle_case")
        require(pilot.observe()["calls"] == baseline, "stop_failure_dispatched_future_call")
        report.update(status="passed", future_dispatches=0)
    except Exception:
        report["status"] = "failed"
        report["failure_observation"] = pilot.diagnostic()
        raise
    finally:
        for pid in paused:
            try:
                pilot.signal(pid, signal.SIGCONT)
            except (OSError, ValueError):
                pass
        if operator is not None and operator.poll() is None:
            operator.kill(); operator.wait(timeout=5)
        pilot.close()


def qualify(args, private, report, run, launch, ask, paths, env, notes, useful, unrelated):
    require(sys.platform == "linux" and Path("/proc/self/stat").is_file(),
            "stop_native_linux_required")
    context = SimpleNamespace(args=args, source=run.ROOT, run=run, launch=launch,
        ask=ask, base=launch.BASE, paths=paths, env=env, notes=notes, useful=useful)
    root = private / "emergency-stop"
    root.mkdir(mode=0o700)
    section = {"format": "sw-prepared-pilot-stop-witness/1", "status": "failed",
               "provider": "owned-scripted-loopback", "paid_api_calls": 0,
               "source_commit": args.expected_commit, "cases": []}
    report["emergency_stop"] = section
    for case in ("two-prepared-runs", "interrupted-stop", "daemon-loss-stop", "unconfirmed-namespace-stop"):
        report["active_case"] = "stop-" + case
        result = {"case": case, "status": "failed"}
        section["cases"].append(result)
        if case == "two-prepared-runs":
            path = root / case
            path.mkdir(mode=0o700)
            concurrent(context, path, result, unrelated)
        else:
            lifecycle(context, root / case, result, case)
    section["status"] = "passed"
