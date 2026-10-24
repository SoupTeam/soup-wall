#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Launch the accepted prepared Linux pilot. Default: validate a read-only plan.

No builds, downloads, global settings, existing daemon reuse or policy changes.
Only --run creates an owned private daemon and invokes the restricted launcher.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREP = load("pilot_run_preparation", "prepare-installed-pilot.py")
GROUPS = load("pilot_run_groups", "prepare-native-pilot-prerequisites.py")
AUDIT = load("pilot_run_audit", "pilot_audit.py")
MAX_OUTPUT = 4 * 1024 * 1024
OWNER_PID = os.getpid()
PUBLIC_FAILURE_CODES = frozenset({
    'linux_budget_input_invalid',
    'linux_budget_preflight_refused',
    'linux_budget_observation_unverified',
    'native_linux_x86_64_required',
    'non_root_operator_required',
    'native_ubuntu_required_wsl_is_separate',
    'ubuntu_24_04_required',
    'selection_version',
    'selection_roles_mismatch',
    'forbidden_action_expectation_required',
    'absolute_selected_path_required',
    'selected_artifact_unavailable',
    'selected_executable_unavailable',
    'selected_artifact_changed',
    'private_directory_required',
    'private_owned_0700_directory_required',
    'duplicate_json_input_key',
    'nonfinite_json_input',
    'input_size_limit',
    'input_digest_mismatch',
    'regular_input_required',
    'absolute_selection_and_full_commit_required',
    'accepted_two_server_classifier_required',
    'authenticated_readiness_failed',
    'candidate_source_mismatch',
    'canonical_selection_required',
    'canonical_state_root_required',
    'daemon_process_identity_mismatch',
    'daemon_registry_or_features_mismatch',
    'loopback_port_out_of_range',
    'native_instance_invalid',
    'native_readiness_invalid',
    'occupied_port_refused',
    'owned_daemon_lost',
    'owned_daemon_not_ready',
    'owned_process_cleanup_failed',
    'owned_stop_unconfirmed',
    'parent_death_signal_unavailable',
    'pilot_cancelled',
    'pilot_cancelled_before_host',
    'pilot_deadline_out_of_range',
    'pilot_timeout',
    'preparation_marker_mismatch',
    'prepared_assets_inside_checkout',
    'prepared_generation_required',
    'prepared_selection_required',
    'private_output_limit',
    'registry_collision',
    'restricted_launcher_failed',
    'selected_executable_changed',
    'selection_changed_before_host',
    'selection_changed_before_launch',
    'state_inside_checkout',
    'state_inside_workspace',
    'unsafe_state_parent',
    'canonical_existing_workspace_required',
    'existing_workspace_missing_or_moved',
    'owned_workspace_without_shared_write_required',
    'home_directory_workspace_refused',
    'workspace_binding_invalid',
    'selected_workspace_changed',
    'preparation_overlaps_workspace',
    'private_assets_inside_workspace',
    'profile_workspace_identity_mismatch',
    'unsupported_existing_git_layout_use_supported_standalone_repository',
})


class Failure(Exception):
    pass


def storage_failure(error):
    """Finite diagnostics only; never expose paths or exception messages."""
    codes = {errno.ENOSPC: "storage_full", errno.EROFS: "storage_read_only",
             errno.EACCES: "storage_permission_denied", errno.EPERM: "storage_permission_denied",
             errno.EIO: "storage_io_failed", getattr(errno, "EDQUOT", -1): "storage_quota_exceeded"}
    if isinstance(error, OSError):
        return codes.get(error.errno)
    return None


def require(ok, code):
    if not ok:
        raise Failure(code)


def selected(args):
    """Read accepted receipts and identities without executing selected programs."""
    require(args.selection.is_absolute() and re.fullmatch(r"[0-9a-f]{40}", args.expected_commit),
            "absolute_selection_and_full_commit_required")
    path = args.selection
    require(path.resolve(strict=True) == path, "canonical_selection_required")
    PREP.private_dir(path.parent)
    require(path.name == "selection.json" and not path.is_symlink(), "prepared_selection_required")
    generation = path.parent
    PREP.private_dir(generation.parent)
    PREP.private_dir(generation.parent.parent)
    selection_path, profiles = PREP.verify_generation(generation, args.expected_commit, probe_native=False)
    selection = PREP.PILOT.strict_json(selection_path.read_bytes())
    # A completed generation, not an interrupted or caller-assembled one.
    require(re.fullmatch(r"[0-9a-f]{32}", generation.name), "prepared_generation_required")
    marker_path = generation.parent.parent / "current.json"
    marker = PREP.PILOT.strict_json(PREP.bounded_file(marker_path, PREP.MAX_JSON).read_bytes())
    require(marker == {"format": "sw-pilot-preparation/1", "generation": generation.name,
                       "selection_sha256": PREP.FS.sha(selection_path), "status": "prepared-not-active"},
            "preparation_marker_mismatch")
    _, paths = PREP.PILOT.validate_selection(selection, args.expected_commit)
    require(paths["git_classifier"].read_bytes() ==
            (ROOT / "rule_baseline/git_readonly_v1/rule_baseline.py").read_bytes(),
            "accepted_two_server_classifier_required")
    require(0 <= args.ask_wait_seconds <= 25 and 1 <= args.timeout_seconds <= 3600,
            "pilot_deadline_out_of_range")
    require(0 <= args.port <= 65535, "loopback_port_out_of_range")
    require(not generation.is_relative_to(ROOT), "prepared_assets_inside_checkout")
    return selection, paths, profiles


def environment(paths, private):
    # Do not inherit project-controlled PATH/PYTHONPATH/AGENTFW/loader settings.
    env = {"PATH": str(paths["node"].parent) + ":/usr/bin:/bin", "LANG": "C.UTF-8",
           "HOME": str(private), "TMPDIR": str(private), "AGENTFW_HOME": str(private / ".agentfw"),
           "AGENTFW_CLASSIFIER_PYTHON": str(paths["python"]),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"}
    # Operator-selected provider transport only. Never copied into retained state/report.
    for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
                "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env



def budget_input(path):
    """Read an explicit bounded owned file; the existing Rust parser owns schema validation."""
    require(path.is_absolute() and path.resolve(strict=True) == path, "linux_budget_input_invalid")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o022 and info.st_size <= 16384, "linux_budget_input_invalid")
        raw = stream.read(16385)
    require(len(raw) <= 16384, "linux_budget_input_invalid")
    return raw


def budget_cli(paths, private, env, option, path, probe=False):
    # A utility never needs provider access, even before the role split in SOU-143.
    utility = {key: value for key, value in env.items() if key not in (
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "SSL_CERT_FILE")}
    command = [str(paths["agentfw"]), "pilot-budget", option, str(path)]
    if probe:
        command.append("--probe")
    result = subprocess.run(command, cwd=private, env=utility, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=5)
    require(result.returncode == 0 and len(result.stdout) <= 65536,
            "linux_budget_preflight_refused" if probe else "linux_budget_observation_unverified")
    value = PREP.PILOT.strict_json(result.stdout)
    require(value.get("format") == "sw-prepared-pilot-budget/1"
            and re.fullmatch(r"[0-9a-f]{64}", value.get("budget_sha256", ""))
            and value.get("scope") == "per-original-server-process-tree",
            "linux_budget_observation_unverified")
    return value

def json_file(path, value):
    PREP.write_json(path, value)


def parent_death():
    # The owned supervisor handles TERM normally; abrupt parent loss cannot
    # strand its daemon/launcher. Set before exec and close the fork/death race.
    require(ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGTERM, 0, 0, 0) == 0,
            "parent_death_signal_unavailable")
    if os.getppid() != OWNER_PID:
        os._exit(125)


def native_instance(port, token):
    request = urllib.request.Request(f"http://127.0.0.1:{port}/native/v1/instance",
                                     headers={"Authorization": "Bearer " + token})
    # No redirects, no ambient proxy, bounded response. Credentials stay loopback.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args):
            return None
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(request, timeout=1) as response:
        raw = response.read(2 * 1024 * 1024 + 1)
        require(response.status == 200 and len(raw) <= 2 * 1024 * 1024, "native_readiness_invalid")
        return PREP.PILOT.strict_json(raw)


def readiness(paths, home, env, process, port, token, registry_sha, ask):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not GROUPS.leader_finished(process):
        try:
            live = native_instance(port, token)
            require(live["registry_sha256"] == registry_sha
                    and live["liveness_enabled"] is True and live["approval_enabled"] == bool(ask),
                    "daemon_registry_or_features_mismatch")
            # Existing status CLI verifies nonce, current config digest and exact binary.
            status = subprocess.run([str(paths["agentfw"]), "protection-status", "--home", str(home),
                "--query-only", "--require-enforce", "--expect-binary-sha256", PREP.FS.sha(paths["agentfw"]),
                "--expect-registry-sha256", registry_sha], cwd=home.parent, env=env,
                stdin=subprocess.DEVNULL, capture_output=True, timeout=4)
            require(status.returncode == 0 and len(status.stdout) <= 65536, "authenticated_readiness_failed")
            value = PREP.PILOT.strict_json(status.stdout)["snapshot"]
            require(value["runtime"]["pid"] == process.pid, "daemon_process_identity_mismatch")
            require(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", live["instance_id"]), "native_instance_invalid")
            return {"native_instance": live["instance_id"], "runtime_instance": value["runtime"]["instance"],
                    "policy_sha256": value["policy"]["sha256"], "registry_sha256": registry_sha,
                    "binary_sha256": value["runtime"]["binary_sha256"]}
        except (OSError, ValueError, KeyError, Failure, subprocess.TimeoutExpired):
            time.sleep(.1)
    raise Failure("owned_daemon_not_ready")


def confirmed_stop(home, launcher_pid, binary, env, cwd):
    """Confirm an exact durable receipt through the existing authenticated CLI.

    A JSON status, an intent file, SIGTERM or a successful launcher exit alone
    is not evidence. The CLI verifies the HMAC bound to these exact run bytes
    and the expected private daemon home, without contacting a new daemon.
    """
    candidates = list((home / "pilot-runs").glob("*/stop.json"))
    require(len(candidates) == 1, "owned_stop_unconfirmed")
    record = candidates[0].parent / "run.json"
    value = PREP.PILOT.strict_json(record.read_bytes())
    require(value.get("contract") == "sw-pilot-run/1"
            and value.get("run_id") == record.parent.name
            and re.fullmatch(r"[0-9a-f]{32}", record.parent.name)
            and value.get("home") == str(home)
            and value.get("launcher_pid") == launcher_pid,
            "owned_stop_unconfirmed")
    result = subprocess.run([str(binary), "pilot-approval", "--home", str(home),
        "--run", record.parent.name, "stop"], cwd=cwd, env=env,
        stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
    require(result.returncode == 0 and len(result.stdout) <= 4096,
            "owned_stop_unconfirmed")
    response = PREP.PILOT.strict_json(result.stdout)
    require(response == {"run": record.parent.name, "status": "already_stopped",
                         "running_effects_rolled_back": False}, "owned_stop_unconfirmed")


def run(args, report):
    PREP.supported_platform()
    selection, paths, profiles = selected(args)
    if "prepared_workspaces" in selection:
        PREP.validate_existing_workspaces(paths, PREP.workspace_paths(selection, args.selection.parent))
    require(args.state_root is None or (args.state_root.is_absolute()
            and args.state_root.resolve(strict=True) == args.state_root), "canonical_state_root_required")
    state_root = args.state_root or Path(tempfile.gettempdir()).resolve()
    info = state_root.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
            and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), "unsafe_state_parent")
    require(not state_root.is_relative_to(ROOT), "state_inside_checkout")
    for profile in profiles.values():
        workspace = Path(json.loads(Path(profile["profile"]["path"]).read_bytes())["workspace"])
        require(not state_root.is_relative_to(workspace), "state_inside_workspace")
    # Refuse any occupied port. Existing operator services are never adopted or stopped.
    with socket.socket() as reservation:
        try:
            reservation.bind(("127.0.0.1", args.port))
        except OSError:
            raise Failure("occupied_port_refused") from None
        port = reservation.getsockname()[1]
    private = None
    audit_selected = False
    daemon = launcher = None
    streams = []
    cancelled = False
    report.update(stage="private_setup", host_started=False)
    def cancel(_signum, _frame):
        nonlocal cancelled
        cancelled = True
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        for sig in previous:
            signal.signal(sig, cancel)
        require(not cancelled, "pilot_cancelled")
        private = Path(tempfile.mkdtemp(prefix="soup-wall-run-", dir=state_root))
        private.chmod(0o700)
        report.update(run_directory=str(private), port=port, executed=False)
        home = private / ".agentfw"
        home.mkdir(mode=0o700)
        env = environment(paths, private)
        budget_snapshot = None
        if getattr(args, "linux_budget", None) is not None:
            raw = budget_input(args.linux_budget)
            budget_snapshot = private / "selected-linux-budget.json"
            with budget_snapshot.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw)
            observation = budget_cli(paths, private, env, "--config", budget_snapshot, probe=True)
            require(observation.get("status") == "available-not-active"
                    and observation.get("protected_children_started") is False,
                    "linux_budget_observation_unverified")
            report["resource_budget"] = observation
        tools = []
        for kind in ("filesystem", "git"):
            tools.extend(PREP.PILOT.strict_json((Path(profiles[kind]["profile"]["path"]).parent /
                                               "registry.json").read_bytes())["tools"])
        require(len({tool["name"] for tool in tools}) == len(tools), "registry_collision")
        registry = home / "registry.json"
        json_file(registry, {"contract_version": "sw-native/1", "registry_id": "prepared-pilot-v1", "tools": tools})
        registry_sha = PREP.FS.sha(registry)
        native = {"registry_path": str(registry), "registry_sha256": registry_sha,
                  "liveness": {"default_lease_seconds": 4, "max_lease_seconds": 4,
                               "maintenance_interval_ms": 250}}
        if args.ask_wait_seconds:
            native["approval"] = {"ttl_seconds": 120}
        retention, audit_receipt = AUDIT.selection(private, args.expected_commit,
            PREP.FS.sha(args.selection), PREP.FS.sha(paths["policy"]), registry_sha,
            PREP.FS.sha(paths["agentfw"]))
        json_file(private / "audit-run.json", audit_receipt)
        audit_selected = True
        report["audit"] = {"run_id": audit_receipt["run_id"], "retention": AUDIT.LIMITS,
                           "retention_sha256": audit_receipt["retention_sha256"]}
        json_file(home / "config.yaml", {"bind": "127.0.0.1", "port": port, "enforce": True,
                  "policy": str(paths["policy"]), "native": native, "audit_retention": retention})
        token = secrets.token_urlsafe(32)
        for filename, value in (("native-token", token), ("token", secrets.token_urlsafe(32))):
            with (home / filename).open("x") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
        # Last pre-effect verification, including source, selected bytes and package trees.
        require(selected(args)[0] == selection, "selection_changed_before_launch")
        require(not cancelled, "pilot_cancelled")
        daemon_log = (private / "daemon.private.log").open("xb")
        os.fchmod(daemon_log.fileno(), 0o600)
        streams.append(daemon_log)
        report["stage"] = "daemon_start"
        daemon = subprocess.Popen([str(paths["agentfw"]), "serve"], cwd=private, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            start_new_session=True, preexec_fn=parent_death)
        report["executed"] = True
        with selectors.DefaultSelector() as selector:
            selector.register(daemon.stdout, selectors.EVENT_READ, (daemon_log, False))
            report["identity"] = readiness(paths, home, env, daemon, port, token, registry_sha,
                                           args.ask_wait_seconds)
            require(not cancelled and not GROUPS.leader_finished(daemon), "pilot_cancelled_before_host")
            require(selected(args)[0] == selection, "selection_changed_before_host")
            roots = PREP.workspace_paths(selection, args.selection.parent)
            workspace, git_workspace = roots["filesystem"], roots["git"]
            command = [str(paths["agentfw"]), "pilot-launch", "--claude", str(paths["claude"]),
                "--agent-bin", str(paths["agentfw"]), "--home", str(home), "--workspace", str(workspace),
                "--git-workspace", str(git_workspace), "--fs-profile", profiles["filesystem"]["profile"]["path"],
                "--git-profile", profiles["git"]["profile"]["path"], "--policy", str(paths["policy"]),
                "--classifier", str(paths["git_classifier"]), "--timeout-seconds", str(args.timeout_seconds),
                "--ask-wait-seconds", str(args.ask_wait_seconds), "--prompt", args.prompt, "--json"]
            if budget_snapshot is not None:
                command.extend(["--linux-budget", str(budget_snapshot),
                                "--linux-budget-sha256", report["resource_budget"]["budget_sha256"]])
            log = (private / "host.private.log").open("xb")
            os.fchmod(log.fileno(), 0o600)
            streams.append(log)
            require(not cancelled and not GROUPS.leader_finished(daemon), "pilot_cancelled_before_host")
            report["stage"] = "host_start"
            launcher = subprocess.Popen(command, cwd=private, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=parent_death)
            report["host_started"] = True
            selector.register(launcher.stdout, selectors.EVENT_READ, (log, True))
            report["launcher_pid"] = launcher.pid
            report["stage"] = "run_publication"
            # Non-secret rendezvous for the existing second-terminal operator CLI.
            json_file(private / "run.json", {"format": "sw-prepared-pilot-run/1", "home": str(home),
                      "supervisor_pid": os.getpid(), "launcher_pid": launcher.pid, "daemon_pid": daemon.pid, "port": port})
            print(json.dumps({"status": "running", "run_directory": str(private), "home": str(home)},
                             ensure_ascii=True), file=sys.stderr, flush=True)
            report["stage"] = "active_run"
            deadline, count = time.monotonic() + args.timeout_seconds + 15, 0
            while not GROUPS.leader_finished(launcher):
                require(not cancelled, "pilot_cancelled")
                require(time.monotonic() < deadline, "pilot_timeout")
                require(not GROUPS.leader_finished(daemon), "owned_daemon_lost")
                for key, _ in selector.select(timeout=.1):
                    raw = os.read(key.fd, 65536)
                    if not raw:
                        selector.unregister(key.fileobj)
                        continue
                    count += len(raw)
                    require(count <= MAX_OUTPUT, "private_output_limit")
                    key.data[0].write(raw)
            # Let the existing launcher finish its own process-group/Ask cleanup first.
            result = os.waitid(os.P_PID, launcher.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            require(result is not None and result.si_code == os.CLD_EXITED and result.si_status == 0,
                    "restricted_launcher_failed")
        stops = list((home / "pilot-runs").glob("*/stop.json"))
        if stops:
            confirmed_stop(home, launcher.pid, paths["agentfw"], env, private)
            report.update(status="stopped", launcher_exit=0, running_effects_rolled_back=False)
        else:
            report.update(status="completed", launcher_exit=0)
    except OSError as error:
        code = storage_failure(error)
        if code:
            report["storage_failure"] = code
        raise
    finally:
        errors = []
        for name, process in (("launcher", launcher), ("daemon", daemon)):
            if process is not None:
                try:
                    # TERM allows the accepted launcher to reap the separate host group.
                    if name == "launcher" and not GROUPS.leader_finished(process):
                        os.killpg(process.pid, signal.SIGTERM)
                        until = time.monotonic() + 10
                        while not GROUPS.leader_finished(process) and time.monotonic() < until:
                            time.sleep(.05)
                    GROUPS.stop_group(process)
                except (OSError, subprocess.TimeoutExpired, GROUPS.Failure):
                    errors.append(name)
                finally:
                    process.stdout.close()
        for stream in streams:
            try:
                stream.close()
            except OSError as error:
                errors.append("private_log")
                if storage_failure(error):
                    report["cleanup_storage_failure"] = storage_failure(error)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        # Stop processes before snapshot/export. Retention housekeeping never
        # resets a live session or its sticky risk, receipts or policy state.
        if private is not None and getattr(args, "linux_budget", None) is not None:
            try:
                bindings = list((private / ".agentfw" / "pilot-budgets").glob("*/linux-budget-binding.json"))
                require(len(bindings) <= 1, "linux_budget_observation_unverified")
                if bindings:
                    report["resource_budget"] = budget_cli(paths, private, env, "--binding", bindings[0])
                    budget_status = report["resource_budget"]["status"]
                    if budget_status in ("unresolved", "refused", "active-at-attachment"):
                        report.update(status="failed", reason="linux_budget_observation_unverified")
            except (OSError, ValueError, Failure, subprocess.TimeoutExpired):
                report["resource_budget"] = {"status": "unresolved", "requested": True}
                errors.append("resource_budget")
        if not errors and private is not None:
            try:
                # An authenticated stop may have completed, or may still need
                # operator recovery. Preserve its private receipt and identity;
                # deletion here would make a repeated stop indistinguishable
                # from an unknown/forged run. No process is preserved.
                stops = list((private / ".agentfw" / "pilot-runs").glob("*/stop.json"))
                if stops:
                    report["retained_stop_state"] = str(private)
                elif audit_selected:
                    # Keep only selected bounded evidence. Tokens, raw host and
                    # daemon logs, provider state and runtime settings are removed.
                    for child in private.iterdir():
                        if child.name not in ("audit", "audit-run.json"):
                            if child.is_dir() and not child.is_symlink():
                                shutil.rmtree(child)
                            else:
                                child.unlink()
                else:
                    shutil.rmtree(private)
                if audit_selected:
                    json_file(private / "audit-finished.json", {"format": AUDIT.FORMAT,
                        "run_id": report["audit"]["run_id"], "owned_processes_stopped": True})
                    report["audit"].update(directory=str(private), snapshot=AUDIT.state(private))
            except OSError as error:
                errors.append("private_state")
                if storage_failure(error):
                    report["cleanup_storage_failure"] = storage_failure(error)
        report["cleanup"] = ("failed" if errors else "owned_processes_stopped_state_retained"
                             if report.get("retained_stop_state") else "owned_processes_stopped_audit_retained"
                             if audit_selected else "owned_state_removed")
        if errors:
            report["cleanup_failures"] = errors
        require(not errors, "owned_process_cleanup_failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--state-root", type=Path)
    parser.add_argument("--linux-budget", type=Path,
                        help="Explicit owned Linux budget JSON; absent means unbudgeted")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--ask-wait-seconds", type=int, default=0)
    parser.add_argument("--prompt", default="Read useful notes with filesystem and inspect Git status using the selected MCP tools.")
    args = parser.parse_args()
    report = {"format": "sw-prepared-pilot-run/1", "status": "plan", "executed": False}
    try:
        report["resource_budget"] = {"status": "unbudgeted", "requested": False}
        if args.linux_budget is not None:
            raw = budget_input(args.linux_budget)
            report["resource_budget"] = {"status": "selected-not-validated", "requested": True,
                                         "input_sha256": hashlib.sha256(raw).hexdigest()}
        selection, _, profiles = selected(args)
        report.update(selection_sha256=PREP.FS.sha(args.selection), source=selection["source"], profiles=profiles,
                      workspaces=selection.get("prepared_workspaces", {"mode": "generated-demo"}),
                      audit_retention=AUDIT.LIMITS)
        if args.run:
            run(args, report)
    except Exception as error:
        # Never echo subprocess output, raw paths, arguments, credentials or arbitrary exception strings.
        code = str(error)
        if args.linux_budget is not None and code in {"native_linux_x86_64_required",
                "native_ubuntu_required_wsl_is_separate", "ubuntu_24_04_required"}:
            report["resource_budget"]["status"] = "unsupported"
        report.update(status="failed", reason=code if code in PUBLIC_FAILURE_CODES
                      else "pilot_input_or_runtime_failure")
        failure = storage_failure(error) or report.get("storage_failure") or report.get("cleanup_storage_failure")
        if failure:
            report.update(storage_failure=failure,
                          recovery="Restore space and access to the owned state directory, then rerun with fresh authority.",
                          effects="Host effects may have occurred; cleanup does not roll them back."
                          if report.get("host_started") else "Protected host was not started.")
    print(json.dumps(report, sort_keys=True, ensure_ascii=True))
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
