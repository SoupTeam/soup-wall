#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SOU-112: actual installed two-terminal launcher workflow; no paid provider.

Operator decisions are explicit same-user CLI actions in an owned harness, not
proof of physical human presence. Raw arguments, grants and syscall traces stay
in private temporary storage. Kernel effects and host-correlated results are
independent of approval files and CLI success messages.
"""
from __future__ import annotations
import argparse
import json
import math
import os
import re
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid
import traceback
import threading

import importlib.util

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LAUNCH = load("sou112_original_launcher", "qualify-pilot-launcher.py")
SELECTED = load("sou112_selected_witness", "verify-sou105-selected-approval.py")
BASE, require = LAUNCH.BASE, LAUNCH.require


def diagnostic(text):
    # Export a finite code, never arbitrary host/argument/token output.
    for marker, code in [
        ("owned collector retirement not confirmed within cleanup budget", "collector_retirement_unconfirmed"),
        ("selected namespace cleanup unconfirmed", "owner_cleanup_unconfirmed"),
        ("foreign namespace cleanup identity", "foreign_cleanup_identity"),
        ("daemon did not confirm revocation", "run_revocation_unconfirmed"),
        ("owned host process group termination unconfirmed", "host_group_unconfirmed"),
        ("selected-owner cleanup worker failed", "owner_cleanup_worker_failed"),
        ("collector authority failed", "authority_verification"),
        ("same agentfw executable", "collector_image"),
        ("accepted two-server", "classifier_identity"),
        ("failed pinned", "asset_identity"),
        ("selected executable or library changed", "asset_identity"),
        ("read lease lost", "read_lease_lost"),
        ("changed during hashing", "capture_bytes_changed"),
        ("immutable proof", "immutable_proof"),
        ("changed during verification", "capture_identity_changed"),
        ("identity or metadata changed", "resume_identity_changed"),
        ("policy mismatch", "policy_identity"),
        ("approval/liveness/registry", "daemon_prerequisites"),
        ("native.approval and native.liveness", "daemon_prerequisites"),
        ("owned, private", "private_permissions"),
        ("not owned by a pilot launcher", "launcher_role"),
        ("not sealed", "manifest_seals"),
        ("sealed selection", "manifest_identity"),
        ("executable differs", "launcher_executable"),
        ("wrong or restarted daemon", "daemon_instance"),
        ("daemon refused", "daemon_auth"),
        ("not owned by this live pilot", "run_scope"),
        ("binding differs", "exact_binding"),
        ("before approval", "inspection_required"),
        ("cleanup", "cleanup"),
        ("unexpected argument", "cli_argument_parsing"),
        ("open bounded operator input", "operator_input_missing"),
        ("pilot launcher is no longer live", "launcher_exited"),
        ("No such file or directory", "owned_file_missing"),
        ("timed out", "deadline"),
    ]:
        if marker in text:
            return code
    return "unclassified"


def until(check, label, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(.05)
    raise ValueError(label)


def await_original_expiry(expires_at_ms):
    # Expiry is deliberately induced before a separate useful request can be
    # offered. Do not spend that follow-up's existing wait on the primary TTL.
    require(type(expires_at_ms) is int and expires_at_ms >= 0, "original_expiry_invalid")
    remaining = (expires_at_ms - time.time_ns() // 1_000_000) / 1000
    require(remaining <= 20, "original_expiry_outside_case")
    if remaining > 0:
        time.sleep(remaining)
    require(time.time_ns() // 1_000_000 >= expires_at_ms, "original_expiry_not_reached")


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)


class ProposalGate:
    """Hold owned provider proposals until every independent host is ready."""
    def __init__(self, deferred=False):
        self.ready = threading.Event()
        self.released = threading.Event()
        self.cancelled = threading.Event()
        if not deferred:
            self.released.set()

    def wait(self, timeout=60):
        self.ready.set()
        require(self.released.wait(timeout), "provider_proposal_barrier_timeout")
        return not self.cancelled.is_set()

    def release(self):
        self.released.set()

    def cancel(self):
        self.cancelled.set()
        self.released.set()


def release_ready_pilots(pilots, seconds=60):
    def ready():
        require(all(pilot.process.poll() is None for pilot in pilots), "host_exited_before_proposal_barrier")
        return all(pilot.proposals.ready.is_set() for pilot in pilots)
    until(ready, "independent_hosts_not_ready", seconds=seconds)
    # All checks precede every release. Startup cannot consume an Ask lease,
    # and incomplete observations cannot be mistaken for zero dispatch.
    for pilot in pilots:
        require(not pilot.offered and pilot.operator("list") == [], "proposal_or_pending_before_barrier")
        require(pilot.undispatched(), "original_dispatch_before_barrier")
    released_at = time.time_ns() // 1_000_000
    for pilot in pilots:
        pilot.proposals.release()
    return released_at


class Pilot:
    def __init__(self, setup, root, classifier, kind, enabled=True, deferred=False):
        self.setup, self.root, self.kind = setup, root, kind
        root.mkdir(mode=0o700)
        self.session, self.run_id = str(uuid.uuid4()), None
        self.trace = root / "syscalls.private"
        self.model = BASE.DEMO.ScriptedModel([])
        self.offered, self.result_times, self.result_monotonic = set(), {}, {}
        self.proposal_monotonic = {}
        self.first_pending_ms = None
        self.close_after_primary = False
        self.proposals = ProposalGate(deferred)
        target = ("filesystem", "read_text_file", {"path": "/workspace/credentials.txt"}) if kind == "filesystem" else (
            "git", "git_show", {"repo_path": "/workspace", "revision": setup.head_before})
        self.primary = target
        self.peer = ("filesystem", "read_text_file", {"path": "/workspace/notes.txt"})

        def next_step(body):
            require(len(self.model.requests) <= 32, "owned_provider_request_bound")
            names = {tool.get("name") for tool in body.get("tools", [])}
            if not {"mcp__filesystem__read_text_file", "mcp__git__git_show"}.issubset(names):
                return [{"type": "text", "text": "Owned auxiliary request."}]
            if not self.proposals.wait():
                return [{"type": "text", "text": "Owned provider closed before proposals."}]
            for message in body.get("messages", []):
                blocks = message.get("content", [])
                for block in blocks if isinstance(blocks, list) else []:
                    if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id") in self.offered:
                        logical = block["tool_use_id"].removeprefix("toolu_pilot_ask_")
                        self.result_times.setdefault(logical, time.time_ns() // 1_000_000)
                        self.result_monotonic.setdefault(logical, time.monotonic_ns())
                        self.model.results[logical] = {"is_error": bool(block.get("is_error")), "content": block.get("content")}
            if "primary" not in self.model.results:
                proposals = [("primary", self.primary)]
                if kind == "filesystem":
                    proposals.append(("allow-peer", self.peer))
            elif self.close_after_primary:
                return [{"type": "text", "text": "Owned terminal signal probe completed."}]
            elif "followup" not in self.model.results:
                proposals = [("followup", self.peer)]
            else:
                return [{"type": "text", "text": "Owned operator continuation completed."}]
            result = []
            for identifier, (server, tool, arguments) in proposals:
                wire_id = "toolu_pilot_ask_" + identifier
                require(wire_id not in self.offered,"host_request_would_have_been_reissued")
                self.proposal_monotonic.setdefault(identifier, time.monotonic_ns())
                self.offered.add(wire_id)
                result.append({"type": "tool_use", "id": wire_id, "name": f"mcp__{server}__{tool}", "input": arguments})
            return result

        self.model.next = next_step
        env = dict(setup.env, ANTHROPIC_BASE_URL=self.model.url, ANTHROPIC_API_KEY="owned-loopback-only",
            HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9", NO_PROXY="127.0.0.1,localhost,::1")
        # Keep the identical syscall/effect witness set, but avoid ptrace stops
        # for unrelated stat/readlink calls during large verified-input walks.
        # Both paired sides use this exact harness and request this mode.
        # https://github.com/strace/strace/blob/master/doc/INTERNALS.md
        command = [str(setup.selected["strace"]), "-f", "--seccomp-bpf", "-qq", "-s", "1048576", "-e", "trace=" + LATENCY.TRACE_SYSCALLS,
            "-o", str(self.trace), str(setup.binary), "pilot-launch", "--claude", str(setup.selected["claude"]),
            "--workspace", str(setup.workspace), "--fs-profile", str(setup.profiles["filesystem"]),
            "--git-profile", str(setup.profiles["git"]), "--home", str(setup.home), "--policy", str(setup.policy),
            "--classifier", str(classifier), "--host-session", self.session, "--timeout-seconds", "90", "--json"]
        if enabled:
            command += ["--ask-wait-seconds", "25"]
        self.out = (root / "host.stdout.private").open("wb")
        self.err = (root / "host.stderr.private").open("wb")
        self.process = subprocess.Popen(command, cwd=root, env=env, stdout=self.out, stderr=self.err, start_new_session=True)
        self.witness = BASE.ProcessWitness(self.process.pid)
        if enabled:
            def identify():
                directory = setup.home / "pilot-runs"
                for path in directory.glob("*/run.json"):
                    try:
                        record = json.loads(path.read_text())
                    except (OSError,ValueError):
                        continue  # Bounded publication retry, never authority.
                    if record["host_session"] == self.session:
                        self.run_id, self.metadata, self.launcher_pid = record["run_id"], path, record["launcher_pid"]
                        self.launcher_start = record["launcher_start"]
                        require(all(re.fullmatch(r"[0-9a-f]{64}",v) for v in record["authorities"].values()), "run_metadata_contains_non_digest_authority")
                        require((setup.home / "native-token").read_text().strip() not in path.read_text(), "run_metadata_leaked_native_token")
                        return True
                if self.process.poll() is not None:
                    self.err.flush()
                    raise ValueError("launcher_before_publication_" + diagnostic((root / "host.stderr.private").read_text()[-16000:]))
            try:
                until(identify, "run_metadata_missing", seconds=90)
            except Exception:
                self.close()
                raise

    def operator(self, *words, success=True, without_home=False):
        command = [str(self.setup.binary), "pilot-approval", "--home", str(self.setup.home), "--run", self.run_id, *words]
        env = dict(self.setup.env)
        if without_home:
            env.pop("HOME", None)
        result = subprocess.run(command, cwd=self.root, env=env, capture_output=True, text=True, timeout=10)
        require((result.returncode == 0) == success, "operator_outcome_" + words[0] + "_" + diagnostic(result.stderr))
        return json.loads(result.stdout) if result.returncode == 0 else None

    def waiting(self):
        def check():
            rows = self.operator("list")
            if not rows and "primary" in self.model.results:
                raise ValueError("primary_result_before_pending_" + diagnostic(json.dumps(self.model.results["primary"])))
            require(self.process.poll() is None, "host_exited_before_pending")
            return rows[0] if len(rows) == 1 else None
        pending = until(check, "selected_pending_missing")
        proposal = self.proposal_monotonic.get("primary")
        self.first_pending_ms = None if proposal is None else (time.monotonic_ns() - proposal) / 1_000_000
        return pending

    def effects(self, peer=False):
        return SELECTED.trace_effects(self.trace, "filesystem" if peer else self.kind,
            target="/workspace/notes.txt" if peer else "/workspace/credentials.txt", git_revision=self.setup.head_before)

    def wire_observation(self):
        # A partial live strace write is inconclusive, never a zero witness.
        last_error = "incomplete_trace_line"
        def observe():
            nonlocal last_error
            require(self.trace.stat().st_size <= 32 * 1024 * 1024, "wire_trace_bound")
            text = self.trace.read_text()
            if not text.endswith("\n"):
                return None
            try:
                return LAUNCH.collector_dispatches(text, self.setup.binary, strict=False)
            except ValueError as error:
                code = str(error)
                last_error = code if re.fullmatch(r"[a-z_]{1,80}", code) else "invalid_trace_encoding"
                return None
        try:
            return until(observe, "complete_original_wire_observation_missing", seconds=2)
        except ValueError:
            raise ValueError("original_wire_observation_" + last_error) from None

    def dispatches(self, peer=False):
        observed = self.wire_observation()
        _, tool, arguments = self.peer if peer else self.primary
        fingerprint = BASE.hashlib.sha256(json.dumps(arguments, sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        return sum(call["tool"] == tool and call["args_sha256"] == fingerprint
            for call in observed["calls"])

    def undispatched(self):
        return self.dispatches() == 0 and self.effects() == 0

    def inspect(self, pending):
        shown = self.operator("inspect", pending["pending_id"])
        expected = self.primary[2] if pending["server"] == self.primary[0] and pending["tool"] == self.primary[1] else self.peer[2]
        require(shown["args"] == expected and shown["binding_sha256"] == pending["binding_sha256"], "inspection_not_exact_original_call")

    def pause_collector(self):
        observed = self.wire_observation()
        matches = [pid for pid, server in observed["collector_servers"].items() if server == self.kind]
        require(len(matches) == 1, "one_kernel_observed_selected_collector_required")
        pid = matches[0]
        identity = BASE.ProcessWitness.identity(pid)
        require(identity is not None, "selected_collector_not_live")
        os.kill(pid,signal.SIGSTOP)
        until(lambda: Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()[0] in ("T","t"), "collector_not_stopped",seconds=2)
        require(BASE.ProcessWitness.identity(pid) == identity, "collector_identity_changed")

    def terminate_collector(self):
        observed = self.wire_observation()
        matches = [pid for pid, server in observed["collector_servers"].items() if server == self.kind]
        require(len(matches) == 1, "one_kernel_observed_selected_collector_required")
        pid = matches[0]
        # The trace retains historical PIDs. Bind the pidfd to an identity
        # already sampled while this process was an owned descendant; reading
        # a new identity here could adopt an unrelated reused PID.
        starts = [start for candidate, start in self.witness.observed.copy() if candidate == pid]
        require(len(starts) == 1, "recorded_selected_collector_identity_required")
        identity = starts[0]
        require(BASE.ProcessWitness.identity(pid) == identity, "selected_collector_not_live")
        descriptor = os.pidfd_open(pid)
        try:
            require(BASE.ProcessWitness.identity(pid) == identity, "collector_identity_changed")
            signal.pidfd_send_signal(descriptor, signal.SIGTERM)
        finally:
            os.close(descriptor)
        return pid

    def decide(self, pending, decision):
        self.inspect(pending)
        self.operator(decision, pending["pending_id"], "--binding", pending["binding_sha256"])
        return {"expires_at_ms":pending["expires_at_ms"],
            "decision_submitted_at_ms":time.time_ns() // 1_000_000}

    def finish(self, expected=0):
        self.process.wait(timeout=100)
        self.out.close(); self.err.close()
        require((self.process.returncode == 0) == (expected == 0), "unexpected_launcher_exit_" + diagnostic((self.root / "host.stderr.private").read_text()[-16000:]))
        if expected == 0:
            report = json.loads((self.root / "host.stdout.private").read_text())
            require(report["status"] == "completed" and not Path(report["private_config_dir"]).exists(), "private_host_config_survived")
        if self.run_id:
            require(not self.metadata.parent.exists(), "owned_run_metadata_survived")
        cleanup = self.witness.finish()
        require(cleanup["all_stopped"], "owned_descendant_survived")
        return cleanup

    def failure_observation(self):
        # Finite diagnostics only. Never retain raw errors, arguments or tokens.
        result = {"profile": self.kind, "entry_returncode": self.process.poll(),
                  "offered_count": len(self.offered), "provider_requests": len(self.model.requests),
                  "primary_present": "primary" in self.model.results}
        primary = self.model.results.get("primary")
        if primary is not None:
            result["primary_is_error"] = primary.get("is_error")
            result["primary_diagnostic"] = diagnostic(json.dumps(primary))
        if not getattr(self.err, "closed", False):
            self.err.flush()
        result["stderr_diagnostic"] = diagnostic((self.root / "host.stderr.private").read_bytes()[-16000:].decode('utf-8', errors='replace'))
        if self.trace.exists() and self.trace.stat().st_size <= 32 * 1024 * 1024:
            try:
                lines, _ = LAUNCH.normalized_syscalls(self.trace.read_text(), thread_birth_order=True)
                collectors = LAUNCH.collector_processes(lines, self.setup.binary)
                timings = []
                failures = []
                cleanup = []
                terminal = []
                for pid, server in collectors.items():
                    for line in lines:
                        match = re.fullmatch(rf"{pid}\s+(?:exit_group\((\d+)\).*|\+\+\+ killed by (SIGTERM|SIGKILL|SIGINT|SIGPIPE|SIGSEGV|SIGABRT).*\+\+\+)", line)
                        if match:
                            if match[1] is not None and 0 <= int(match[1]) <= 255:
                                terminal.append(dict(server=server, exit_code=int(match[1])))
                            elif match[2] is not None:
                                terminal.append(dict(server=server, signal=match[2]))
                    for row in LATENCY.collector_stderr_rows(lines, pid):
                        if row.get("event") in ("mcp_real_owner_end", "mcp_real_budget_end", "mcp_real_server_end"):
                            # Finite, selected-collector booleans only. Owner
                            # metadata, credentials and raw trace stay private.
                            fields = {k: row[k] for k in ("cleanup_verified", "observed_failure",
                                "budget_cleanup_verified", "budget_failure_observed",
                                "owner_cleanup_verified", "owner_failure_observed", "transport_complete")
                                if type(row.get(k)) is bool}
                            cleanup.append(dict(server=server, event=row["event"], **fields))
                        code = row.get("failure_code")
                        if (row.get("event") in ("mcp_verified_inputs_capture_failure", "mcp_real_transport_failure")
                                and code in ("identity_lookup_changed", "identity_changed", "size_changed", "bytes_changed",
                                             "lease_lost", "verity_unavailable", "verity_unsupported", "runtime_digest_mismatch",
                                             "package_digest_mismatch", "profile_changed", "input_missing", "input_permission",
                                             "input_io", "capture_failure", "unknown_transport_failure")):
                            failures.append({"server": server, "event": row["event"], "failure_code": code})
                        elapsed, stage = row.get("elapsed_ms"), row.get("stage")
                        if (row.get("event") == "mcp_asset_verification_timing"
                                and stage in ("selected_profile", "runtime_and_libraries", "package_tree")
                                and type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0):
                            timings.append({"server": server, "stage": stage, "elapsed_ms": elapsed})
                result["asset_timings"] = timings[:32]
                result["collector_failures"] = failures[:16]
                result["collector_cleanup"] = cleanup[:16]
                result["collector_terminal"] = terminal[:16]
                result["trace_sha256"] = LAUNCH.sha(self.trace)
            except LATENCY.ObservationError as error:
                result["trace_diagnostic"] = {"reason": "write_unobserved", "kind": error.kind,
                                              "record_sha256": error.record_sha256}
            except (OSError, ValueError, UnicodeError):
                result["trace_diagnostic"] = "incomplete_or_invalid_observation"
        return result

    def close(self):
        self.proposals.cancel()
        if self.process.poll() is None and self.run_id:
            if BASE.ProcessWitness.identity(self.launcher_pid) == self.launcher_start:
                try:
                    os.kill(self.launcher_pid,signal.SIGTERM)
                    self.process.wait(timeout=10)
                except (ProcessLookupError,subprocess.TimeoutExpired):
                    pass
        stop(self.process)
        self.model.close()
        self.out.close(); self.err.close()
        cleanup = self.witness.finish()
        for item in cleanup["remaining"]:
            if BASE.ProcessWitness.identity(item["pid"]) == item["start_time_ticks"]:
                try:
                    os.kill(item["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass


def finish_qualification(report, cases, samples, active, daemon):
    report["cases"] = cases
    try:
        if samples:
            report["latency"] = LATENCY.summarize(cases, samples)
    finally:
        # Metrics never own cleanup. Attempt every owned host and the daemon,
        # even when bookkeeping or an earlier host's cleanup raises.
        cleanup_error = None
        for pilot in active:
            try:
                pilot.close()
            except Exception as error:
                if cleanup_error is None:
                    cleanup_error = error
        try:
            stop(daemon)
        except Exception as error:
            if cleanup_error is None:
                cleanup_error = error
        if cleanup_error is not None:
            raise cleanup_error


def qualify(args, private, report, pilot_class=None):
    pilot_class = Pilot if pilot_class is None else pilot_class
    setup = LAUNCH.prepare_original_launch(args, private, report)
    classifier = private / "classifier.py"
    classifier.write_bytes((ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py").read_bytes())
    report.pop("policy_sha256",None)
    report["classifier_sha256"] = LAUNCH.sha(classifier)
    (setup.workspace / "credentials.txt").write_text("Owned synthetic inventory: 7 red widgets\n")
    (setup.workspace / "notes.txt").write_text("Owned useful continuation: 7 red widgets\n")
    before = BASE.snapshot(setup.workspace)
    status_before = setup.git("status","--porcelain=v1")
    cases, active, daemon = [], [], None

    def start_daemon(kind, ttl):
        nonlocal daemon
        stop(daemon)
        sensitive = ", touches_sensitive_path: true" if kind == "filesystem" else ""
        setup.policy.write_text("agent_policies:\n  - name: owned-read-ask\n    when: { action_class: read_only" + sensitive + " }\n    action: ask\ndefault: allow\n")
        BASE.write(setup.home / "config.yaml", {"port": setup.port, "enforce": True, "policy": str(setup.policy),
            "native": {"registry_path": str(setup.registry), "registry_sha256": LAUNCH.sha(setup.registry),
                "approval": {"ttl_seconds": ttl}, "liveness": {"default_lease_seconds": 4,
                    "max_lease_seconds": 60, "maintenance_interval_ms": 100}}})
        with (private / "daemon.private").open("ab") as log:
            daemon = subprocess.Popen([str(setup.binary), "serve"], cwd=private, env=setup.env, stdout=log, stderr=log)
        require(BASE.DEMO.wait_healthy(setup.port, daemon), "daemon_not_ready")

    try:
        samples = getattr(args, "approval_samples", 0)
        for kind in ("git", "filesystem"):
            selected_cases = (["approve"] * (samples or 1) if samples or getattr(args, "approval_smoke", False) else
                ["expire", "restart", "approve", "reject", "cancel", "approved_cancel", "default"]
                + (["collector_term"] if kind == "git" else []))
            for sample_index, case in enumerate(selected_cases):
                try:
                    start_daemon(kind, 20 if case == "expire" else 30)
                    paired = kind == "filesystem" and case == "approve"
                    pilot = pilot_class(setup, private / (kind + "-" + case + "-" + str(sample_index)), classifier, kind,
                                  enabled=case != "default", deferred=paired)
                    active.append(pilot)
                    pilot.close_after_primary = case == "collector_term"
                    row = {"profile": kind, "case": case, "sample_index": sample_index, "configured": case != "default", "pending":False,
                        "approved":False, "passed": False, "broker_ttl_seconds":20 if case == "expire" else 30, "policy_sha256":LAUNCH.sha(setup.policy),
                        "configuration_sha256":LAUNCH.sha(setup.home / "config.yaml")}
                    cases.append(row)
                    sibling = other = None
                    if kind == "filesystem" and case == "approve":
                        # Start both actual hosts before either pending lease is
                        # consumed by the other host's startup. Deadlines stay fixed.
                        row["stage"] = "start_independent_run"
                        sibling = pilot_class(setup, private / ("independent-run-" + str(sample_index)), classifier, kind, deferred=True)
                        active.append(sibling)
                        row["proposals_released_at_ms"] = release_ready_pilots([pilot, sibling])
                        row["both_hosts_ready_before_proposals"] = True
                    if case != "default":
                        row["stage"] = "wait_primary"
                        waiting = pilot.waiting()
                        row["first_pending_ms"] = pilot.first_pending_ms
                        row.update(pending=True, binding_sha256=waiting["binding_sha256"],
                                   pending_expires_at_ms=waiting["expires_at_ms"],
                                   pending_observed_at_ms=time.time_ns() // 1_000_000)
                        row["stage"] = "before_decision_wire_check"
                        require(pilot.undispatched(), "dispatch_before_operator_decision")
                        if kind == "filesystem" and case == "approve":
                            until(lambda: pilot.dispatches(peer=True) == 1 and pilot.effects(peer=True) == 1, "Allow_peer_blocked_by_pending_Ask", seconds=5)
                            row["allow_peer_while_pending"] = True
                        if case == "approve":
                            rows = pilot.operator("list", without_home=True)
                            require(any(r["pending_id"] == waiting["pending_id"] for r in rows),
                                "explicit_home_depends_on_environment")
                            row["explicit_home_without_environment"] = True
                        if case in ("approve", "reject"):
                            # Exact binding alone is insufficient without inspection.
                            row["stage"] = "inspection_required_control"
                            pilot.operator("approve", waiting["pending_id"], "--binding", waiting["binding_sha256"], success=False)
                            row["stage"] = "inspect_primary"
                            pilot.inspect(waiting)
                            if kind == "filesystem" and case == "approve":
                                row["stage"] = "wait_independent_pending"
                                other = sibling.waiting()
                                pilot.operator("approve", other["pending_id"], "--binding", other["binding_sha256"], success=False)
                                sibling.operator("reject", waiting["pending_id"], "--binding", waiting["binding_sha256"], success=False)
                                require(sibling.undispatched(), "cross_run_decision_dispatched")
                            pilot.operator("approve", waiting["pending_id"], "--binding", "0" * 64, success=False)
                            row["stage"] = "metadata_tamper_control"
                            saved = pilot.metadata.read_bytes()
                            altered = json.loads(saved); altered["host_session"] = "untrusted-label"
                            pilot.metadata.write_text(json.dumps(altered))
                            pilot.operator("list", success=False)
                            pilot.metadata.write_bytes(saved)
                            require(pilot.undispatched(), "target_dispatched_before_exact_decision")
                            row["stage"] = "exact_decision"
                            row["decision_attempt_at_ms"] = time.time_ns() // 1_000_000
                            decision_monotonic = time.monotonic_ns()
                            pilot.operator(case, waiting["pending_id"], "--binding", waiting["binding_sha256"])
                            row["decision_submitted"] = case
                            pilot.operator("approve", waiting["pending_id"], "--binding", waiting["binding_sha256"], success=False)
                        elif case in ("cancel","approved_cancel"):
                            if case == "approved_cancel":
                                pilot.inspect(waiting)
                                pilot.pause_collector()
                                pilot.operator("approve",waiting["pending_id"],"--binding",waiting["binding_sha256"])
                                require((setup.home / "native-grants" / (waiting["pending_id"]+".json")).is_file(), "unused_grant_not_issued")
                                require(pilot.undispatched(), "stopped_collector_dispatched")
                                row.update(approval_issued=True,decision_submitted="approve")
                            else:
                                pilot.inspect(waiting)
                            os.kill(pilot.launcher_pid, signal.SIGTERM)
                        elif case == "collector_term":
                            row["stage"] = "terminate_exact_pending_collector"
                            terminated_collector = pilot.terminate_collector()
                            row["cleanup"] = pilot.finish()
                            primary = pilot.model.results.get("primary")
                            require(primary is not None and primary["is_error"] is True,
                                    "terminated_primary_not_refused")
                            require(pilot.undispatched(), "terminated_collector_dispatched")
                            lines, _ = LAUNCH.normalized_syscalls(pilot.trace.read_text())
                            require(any(re.match(rf"^{terminated_collector}\s+exit_group\(1\)", line)
                                        for line in lines), "collector_term_abrupt_exit_or_missing_ack")
                            row.update(passed=True, dispatched=0, kernel_effects=0, released=False,
                                       collector_sigterm="pidfd_pinned_graceful_cleanup_confirmed")
                            pilot.close(); active.remove(pilot)
                            continue
                        elif case == "restart":
                            pilot.inspect(waiting)
                            start_daemon(kind, 30)
                            pilot.operator("approve", waiting["pending_id"], "--binding", waiting["binding_sha256"], success=False)
                        else:
                            require(case == "expire", "unknown_case")
                        if case in ("cancel", "approved_cancel", "restart"):
                            row["stage"] = "finish_cancel_or_restart"
                            row["cleanup"] = pilot.finish(expected=1)
                            row["stage"] = "after_cancel_or_restart_wire_check"
                            require(pilot.undispatched(), "cancelled_run_dispatched")
                            for extension in ("json","approved","rejected","deciding"):
                                require(not (setup.home / "native-pending" / (waiting["pending_id"]+"."+extension)).exists(), "unused_pending_file_survived")
                            require(not (setup.home / "native-grants" / (waiting["pending_id"]+".json")).exists(), "unused_grant_survived")
                            pilot.operator("approve",waiting["pending_id"],"--binding",waiting["binding_sha256"],success=False)
                            row.update(passed=True, dispatched=0, kernel_effects=0, released=False)
                            pilot.close(); active.remove(pilot)
                            continue
                    # Git's deliberately broad synthetic Ask policy also asks about
                    # the useful follow-up. That separate request needs its own decision.
                    if kind == "git":
                        if case == "expire":
                            row["stage"] = "observe_original_expiry"
                            await_original_expiry(waiting["expires_at_ms"])
                            row["stage"] = "wait_useful_followup_after_original_expiry"
                        def followup_ready():
                            if "primary" not in pilot.model.results:
                                return None
                            rows = pilot.operator("list") if pilot.run_id else []
                            return next((r for r in rows if r["tool"] == "read_text_file"), None)
                        if pilot.run_id:
                            followup = until(followup_ready, "useful_followup_pending_missing")
                            row["followup_decision"] = pilot.decide(followup, "approve")
                    row["cleanup"] = pilot.finish()
                    if sibling:
                        require(sibling.operator("list")[0]["pending_id"] == other["pending_id"], "cleanup_cancelled_other_run")
                        require(sibling.undispatched(), "other_run_dispatched_without_approval")
                        sibling.decide(other,"reject"); sibling.finish()
                        require(sibling.undispatched(), "rejected_other_run_dispatched")
                        sibling.close(); active.remove(sibling)
                        row["cross_run_isolation_and_cleanup"] = True
                    primary = pilot.model.results.get("primary")
                    require(primary is not None and primary["is_error"] == (case != "approve"), "correlated_primary_result_missing")
                    if case == "approve":
                        marker = "7 red widgets" if kind == "filesystem" else "committed baseline"
                        require(marker in json.dumps(primary),"original_approved_result_not_useful")
                        # Conservative operator-attempt-to-correlated-result duration,
                        # including operator verification and decision submission.
                        row["decision_to_result_ms"] = (pilot.result_monotonic["primary"] - decision_monotonic) / 1_000_000
                        # The exact primary collector is selected by successful
                        # execve and server ID; a peer's proof cannot satisfy this.
                        if getattr(args, "require_verified_reuse", False):
                            lines, pending = LAUNCH.normalized_syscalls(pilot.trace.read_text(), thread_birth_order=True)
                            collectors = LAUNCH.collector_processes(lines, setup.binary)
                            selected = [pid for pid, server in collectors.items() if server == kind]
                            require(len(selected) == 1, "one_primary_collector_required")
                            proof = LATENCY.reuse_observation(lines, selected[0], require_completed_call=True)
                            row["verified_inputs_resume"] = proof
                            require(proof["immutable_files"] + proof["leased_files"] > 0, "actual_reuse_missing")
                    primary_text = json.dumps(primary)
                    row["primary_refusal_codes"] = [code for code in ("native_approval_expired", "native_approval_timeout") if code in primary_text]
                    if case == "expire":
                        # The relay min(wait, remaining TTL) may report timeout on
                        # the same boundary the daemon reports expired. Require
                        # both a native deadline refusal and the ORIGINAL expiry.
                        elapsed = pilot.result_times["primary"] - waiting["expires_at_ms"]
                        row["refusal_after_original_expiry_ms"] = elapsed
                        require(row["primary_refusal_codes"] and elapsed >= 0, "expiry_refusal_not_attributed")
                    followup = pilot.model.results.get("followup")
                    followup_text = json.dumps(followup)
                    row["followup"] = {"present": followup is not None,
                        "is_error": None if followup is None else followup["is_error"],
                        "refusal_codes": sorted(set(re.findall(r"native_[a-z_]{1,64}", followup_text)))[:16],
                        "result_received_at_ms":pilot.result_times.get("followup"),
                        "diagnostic_flags": [flag for flag in ("concurrent mcp input", "not classified", "timed out", "closed", "withheld") if flag in followup_text.lower()],
                        "sha256":BASE.hashlib.sha256(followup_text.encode()).hexdigest()}
                    # Default Git Ask is explicitly refused without a wait; its
                    # correlated continuation is another refusal, never a fake Allow.
                    if case != "default" or kind == "filesystem":
                        require(followup and not followup["is_error"] and "7 red widgets" in json.dumps(followup), "useful_continuation_failed")
                    effects, dispatches = pilot.effects(), pilot.dispatches()
                    require(effects == dispatches == (1 if case == "approve" else 0), "original_request_not_exactly_once_or_refused")
                    audit = [json.loads(line) for line in (setup.home / "audit.jsonl").read_text().splitlines() if line]
                    redemptions = [] if case == "default" else [item for item in audit if
                        item.get("host_session") == pilot.session and item.get("event") == "native_call"
                        and ("native_approval_redeemed:" + waiting["pending_id"]) in item.get("reason_codes",[])
                        ]
                    require(len(redemptions) == (1 if case == "approve" else 0), "approval_redemption_observation_mismatch")
                    row.update(passed=True, dispatched=dispatches, kernel_effects=effects, released=not primary["is_error"],
                        approved=bool(redemptions), approved_observation="native signed grant redemption audit",
                        host_result_sha256=BASE.hashlib.sha256(json.dumps(primary,sort_keys=True).encode()).hexdigest(),
                        trace_sha256=LAUNCH.sha(pilot.trace), raw_arguments_exported=False)
                    pilot.close(); active.remove(pilot)
                except Exception as error:
                    if not getattr(args, "complete_inventory", False):
                        raise
                    row = next((r for r in cases if r["profile"] == kind and r["case"] == case
                                and r["sample_index"] == sample_index), None)
                    if row is None:
                        row = {"profile": kind, "case": case, "sample_index": sample_index, "passed": False}
                        cases.append(row)
                    code = str(error)
                    row.update(passed=False, reason=code if re.fullmatch(r"[a-z0-9_]{1,120}", code)
                               else "case_" + type(error).__name__.lower())
                    cleanup = []
                    for owned in list(active):
                        row.setdefault("failure_observations", []).append(owned.failure_observation())
                        owned.close()
                        remaining = [item for item in owned.witness.finish()["remaining"]
                                     if BASE.ProcessWitness.identity(item["pid"]) == item["start_time_ticks"]]
                        cleanup.append({"all_stopped": not remaining, "remaining": remaining})
                        require(not remaining, "owned_cleanup_unconfirmed_stop_inventory")
                        active.remove(owned)
                    row["failure_cleanup"] = cleanup
        require(before == BASE.snapshot(setup.workspace) and status_before == setup.git("status","--porcelain=v1")
            and setup.index_before == LAUNCH.sha(setup.workspace / ".git/index")
            and setup.head_before == setup.git("rev-parse", "HEAD"), "workspace_or_git_state_changed")
        if getattr(args, "require_five_second_pending", False):
            enforce_pending_bound(cases)
        report.update(status="pass" if all(row["passed"] for row in cases) else "failed", cases=cases, workspace_unchanged=True, real_host_executed=True,
            source_after=BASE.source())
        require(report["source"] == report["source_after"], "source_changed")
        require(report["classifier_sha256"] == LAUNCH.sha(classifier), "classifier_changed")
        require(all(LAUNCH.sha(path) == report["selected_sha256"][name] for name,path in setup.selected.items()), "selected_asset_changed")
        require(all(LAUNCH.sha(path / "profile.json") == report["profiles"][kind]["profile_sha256"] for kind,path in setup.profiles.items()), "profile_changed")
        require(not list((setup.home / "pilot-runs").iterdir()), "run_metadata_remains")
    except Exception:
        observations = []
        for pilot in active:
            try:
                observations.append(pilot.failure_observation())
            except (OSError, ValueError):
                observations.append({"profile": pilot.kind, "diagnostic": "unavailable"})
        report["failure_observations"] = observations
        raise
    finally:
        finish_qualification(report, cases, getattr(args, "approval_samples", 0), active, daemon)


LATENCY = load("pilot_ask_latency", "pilot_ask_latency.py")


def approval_samples(value):
    number = int(value)
    if number != 0 and not 20 <= number <= 100:
        raise argparse.ArgumentTypeError("approval samples must be 0 or 20..100 per profile")
    return number


def enforce_pending_bound(cases):
    """Conservative proposal-to-observed-pending witness; never changes a wait/TTL."""
    for row in cases:
        if row["case"] == "default":
            continue
        elapsed = row.get("first_pending_ms")
        met = type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 5000
        row["first_pending_bound_ms"] = 5000
        row["first_pending_bound_met"] = met
        row["runtime_controls_passed"] = row["passed"]
        if not met:
            row.update(passed=False, reason="first_pending_deadline_missed" if elapsed is not None
                       else "first_pending_observation_missing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("agentfw", "git-launcher", "claude", "node", "npm", "bwrap", "git", "strace", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--complete-inventory", action="store_true",
                        help="Continue independent cases only after confirmed owned cleanup; retain every failure")
    parser.add_argument("--require-five-second-pending", action="store_true",
                        help="Measure the original 5000 ms first-pending bound without changing waits or TTLs")
    parser.add_argument("--offline-inputs", type=Path,
                        help="Prepared npm cache, pinned Python archive and hash-locked wheelhouse")
    parser.add_argument("--require-verified-reuse", action="store_true",
                        help="Require an actual selected-collector kernel reuse event for each approval")
    samples_group = parser.add_mutually_exclusive_group()
    samples_group.add_argument("--approval-smoke", action="store_true",
                              help="One correctness probe per profile; never performance acceptance")
    samples_group.add_argument("--approval-samples", type=approval_samples, default=0,
                        help="Separate performance run: 20..100 fresh approvals per profile; no call resubmission")
    args = parser.parse_args()
    if args.complete_inventory and (args.approval_smoke or args.approval_samples):
        parser.error("--complete-inventory requires the original full inventory")
    args.output.mkdir(parents=True,exist_ok=True)
    report = {"contract_version":"sw-pilot-ask-acceptance/1", "status":"incomplete", "real_host_executed":False,
        "scripted_owned_provider":True, "paid_api_calls":0, "physical_human_presence_proven":False,
        "trace_requested":LATENCY.trace_request()}
    if args.approval_smoke:
        report["qualification_scope"] = "two_profile_correctness_probe_not_performance"
    try:
        with tempfile.TemporaryDirectory(prefix="sou112-private-") as directory:
            qualify(args,Path(directory),report)
        if args.approval_samples and report.get("latency", {}).get("status") != "target_met":
            report["status"] = "performance_blocker"
    except Exception as error:
        report.update(status="failed", error_type=type(error).__name__,
            error_location=[{"function": frame.name, "line": frame.lineno}
                for frame in traceback.extract_tb(error.__traceback__)[-6:]])
        if isinstance(error,ValueError):
            report["error"] = str(error)
    BASE.write(args.output / "qualification.json",report)
    print(json.dumps({key:report.get(key) for key in ("status","error","error_type")}))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
