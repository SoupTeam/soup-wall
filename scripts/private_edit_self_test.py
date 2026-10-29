#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Installed, opt-in private-output self-test over the accepted edit-session API.

The verified component starts this helper with its recorded interpreter. Preview
only reads accepted receipts. Execution creates synthetic data in one fresh
private directory; it never prepares a selection, installs a component or edits
an operator project. The scripted provider is owned numeric loopback only.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import select
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sw-private-edit-self-test/1"
CASES = ("create-read", "replace-read", "ask-reject-replay", "aggregate-quota",
         "exact-run-stop", "stopped-authority", "daemon-loss", "fresh-run-recovery")
OLD = b"Owned original: seven blue containers.\n"
NEW = b"Owned replacement: twelve red samples.\n"
CLAUDE = "fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7"
MAX_STREAM = 1024 * 1024
MAX_RETAINED = 32 * 1024 * 1024
MAX_ENTRIES = 512
EXIT = {"passed": 0, "preview": 0, "failed": 3, "incomplete": 4, "unsupported": 5}


class ObservationIncomplete(Exception):
    """A bounded witness could not establish the outcome; no effect inferred."""


def require(condition, code):
    if not condition:
        raise ValueError(code)


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bounded(path, limit=65536):
    """No links, devices or unbounded private-file reads."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_size <= limit,
                "bounded_regular_file_required")
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "private_file_limit")
    return raw


def strict(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate_json_key")
            value[key] = item
        return value
    def nonfinite(_):
        raise ValueError("nonfinite_json")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def snapshot(path):
    try:
        meta = path.lstat()
    except FileNotFoundError:
        return {"exists": False}
    require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_size <= 4096,
            "witness_target_not_owned_regular")
    return {"exists": True, "device": meta.st_dev, "inode": meta.st_ino,
            "mode": meta.st_mode, "size": meta.st_size, "sha256": sha(bounded(path, 4096))}


def tree_witness(root, *, contents=True, transient=False):
    """Finite, non-following witness. Names and contents never enter the report."""
    require(not transient or contents is False, "transient_content_witness_refused")
    rows, total, visited = [], 0, 0
    if not root.exists():
        return sha(b"absent")
    pending = [root]
    while pending:
        path = pending.pop()
        visited += 1
        require(visited <= MAX_ENTRIES, "witness_entry_limit")
        try:
            meta = path.lstat()
            row = [str(path.relative_to(root)), meta.st_dev, meta.st_ino, meta.st_mode,
                   meta.st_nlink, meta.st_size, meta.st_mtime_ns]
            if stat.S_ISDIR(meta.st_mode):
                # Apply the bound to all hints, including ones that disappear.
                with os.scandir(path) as entries:
                    for entry in entries:
                        require(visited + len(pending) < MAX_ENTRIES, "witness_entry_limit")
                        pending.append(Path(entry.path))
            elif stat.S_ISREG(meta.st_mode):
                total += meta.st_size
                require(total <= MAX_RETAINED, "witness_byte_limit")
                if contents:
                    row.append(sha(bounded(path, MAX_STREAM * 2)))
            elif stat.S_ISLNK(meta.st_mode):
                target = os.fsencode(os.readlink(path))
                require(len(target) <= 4096, "witness_link_limit")
                row.append(sha(target))
            else:
                raise ValueError("witness_special_file_refused")
        except FileNotFoundError:
            # An atomic publication or host temporary file can vanish while
            # monitoring retained bytes. This is not a preservation witness.
            if transient and path != root:
                continue
            raise
        rows.append(row)
    rows.sort(key=lambda row: row[0])
    return sha(json.dumps(rows, separators=(",", ":")).encode())


def platform_profile():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        return {"id": "unsupported", "supported": False}
    kernel = bounded(Path("/proc/sys/kernel/osrelease"), 4096).decode().lower()
    return {"id": "wsl2-linux-x86_64" if "microsoft" in kernel else "native-linux-x86_64",
            "supported": True}


def inventory():
    return [{"id": name, "attempted": False, "status": "incomplete"} for name in CASES]


def counts(rows):
    return {"expected": len(CASES), "attempted": sum(r.get("attempted") is True for r in rows),
            **{name: sum(r.get("status") == name for r in rows)
               for name in ("passed", "failed", "incomplete", "unsupported")}}


def passed(report):
    rows = report.get("cases", [])
    by_id = {row.get("id"): row for row in rows}
    required_facts = {
        "create-read": ("exact_readback",), "replace-read": ("exact_readback",),
        "ask-reject-replay": ("rejection_observed", "replay_refused"),
        "aggregate-quota": ("second_target_absent", "quota_not_refunded", "mutation_ceiling_enforced", "byte_ceiling_enforced"),
        "exact-run-stop": ("independent_run_preserved",),
        "stopped-authority": ("stale_approval_refused",),
        "daemon-loss": ("read_only_diagnosis",),
        "fresh-run-recovery": ("old_epoch_refused", "old_run_preserved", "fresh_ask_required"),
    }
    return (report.get("format") == FORMAT and report.get("status") == "passed"
            and report.get("executed") is True and report.get("paid_inference") is False
            and report.get("expected") == list(CASES)
            and [r.get("id") for r in rows] == list(CASES)
            and all(r.get("attempted") is True and r.get("status") == "passed" for r in rows)
            and all(by_id.get(name, {}).get(fact) is True
                    for name, facts in required_facts.items() for fact in facts)
            and all(by_id.get("daemon-loss", {}).get(field) == value for field, value in (
                ("effects", "indeterminate"), ("host_delivery", "unknown"), ("model_consumption", "unknown")))
            and by_id.get("fresh-run-recovery", {}).get("automatic_retry") is False
            and report.get("cleanup", {}).get("all_owned_processes_stopped") is True
            and (report.get("cleanup", {}).get("workspace_removed") is True
                 or (report.get("cleanup", {}).get("workspace_retained") is True
                     and report.get("cleanup", {}).get("keep_workspace_requested") is True))
            and report.get("preservation", {}).get("installed_state_unchanged") is True
            and report.get("preservation", {}).get("original_projects_unchanged") is True
            and report.get("preservation", {}).get("unrelated_sentinel_unchanged") is True)


def reason(error):
    if (type(error) is ValueError or isinstance(error, ObservationIncomplete)) and re.fullmatch(r"[a-z][a-z0-9_]{0,100}", str(error)):
        return str(error)
    if isinstance(error, TimeoutError):
        return "self_test_deadline"
    return "self_test_observation_incomplete"


def failure_observation(error):
    """Only source locations and finite types; never exception text or paths."""
    kinds = (FileNotFoundError, PermissionError, ProcessLookupError, ChildProcessError,
             TimeoutError, OSError, ObservationIncomplete, ValueError, KeyboardInterrupt)
    value = {"kind": next((kind.__name__ for kind in kinds if isinstance(error, kind)), "unexpected")}
    if isinstance(error, OSError) and type(error.errno) is int:
        value["errno"] = error.errno
    trace = error.__traceback__
    while trace is not None:
        code = trace.tb_frame.f_code
        if code.co_filename == __file__ and code.co_name != "require":
            value["helper_line"] = trace.tb_lineno
            value["helper_function"] = code.co_name if re.fullmatch(r"[a-z_][a-z0-9_]{0,79}", code.co_name) else "helper"
        trace = trace.tb_next
    return value


def preflight(args):
    """Read installed identity first: source-checkout Git fallback is forbidden."""
    source_module = load("self_test_source_identity", "pilot_source_identity.py")
    source = source_module.installed(ROOT)
    require(source is not None, "verified_installed_component_required")
    require(args.home.is_absolute() and args.home.resolve(strict=True) == args.home,
            "canonical_home_required")
    pointer = strict(bounded(args.home / "pilot-front-door/current.json"))
    component = pointer.get("component", "")
    require(re.fullmatch(r"[0-9a-f]{64}", component) is not None
            and ROOT == args.home / "pilot-front-door/components" / component / "tree",
            "current_component_identity_mismatch")
    pilot = load("self_test_selected_pilot", "pilot-run.py")
    selected_args = SimpleNamespace(selection=args.selection, expected_commit=source["commit"],
                                    ask_wait_seconds=0, timeout_seconds=args.timeout_seconds, port=0)
    selection, paths, _ = pilot.selected(selected_args)
    require(args.agent.is_absolute() and args.agent.resolve(strict=True) == args.agent
            and args.agent == paths["agentfw"], "selected_agent_identity_mismatch")
    require(digest_file(paths["claude"]) == CLAUDE, "genuine_pinned_claude_required")
    roots = pilot.PREP.workspace_paths(selection, args.selection.parent)
    identities = {"source_commit": source["commit"], "source_tree": source["tree"],
                  "component_sha256": component, "selection_sha256": sha(bounded(args.selection)),
                  "helper_python_sha256": pointer["python"]["sha256"],
                  "installed_sha256": {role: item["sha256"] for role, item in selection["files"].items()}}
    require(re.fullmatch(r"[0-9a-f]{64}", identities["helper_python_sha256"]) is not None,
            "helper_python_identity_invalid")
    return pilot, paths, roots, identities


class Capture:
    """Drain a child continuously while keeping a strict memory bound."""
    def __init__(self, stream):
        self.data, self.total, self.error = bytearray(), 0, False
        def read():
            try:
                while raw := os.read(stream.fileno(), 65536):
                    self.total += len(raw)
                    self.data.extend(raw[:max(0, MAX_STREAM - len(self.data))])
            except OSError:
                self.error = True
        self.thread = threading.Thread(target=read, daemon=True)
        self.thread.start()

    def raw(self):
        require(self.total <= MAX_STREAM and not self.error, "child_output_limit")
        return bytes(self.data)

    def finish(self):
        self.thread.join(timeout=2)
        require(not self.thread.is_alive(), "child_output_drain_incomplete")
        return self.raw()


class BoundedRequests(list):
    def __init__(self):
        super().__init__()
        self.bytes = 0

    def append(self, raw):
        require(type(raw) is bytes and len(self) < 32 and self.bytes + len(raw) <= MAX_STREAM,
                "provider_request_limit")
        self.bytes += len(raw)
        super().append(raw)


def owned_process_witness(base, parent):
    """Observe validated ancestry and retain kernel handles for exact cleanup.

    A children-list PID is only a hint. Pin it with pidfd_open and recheck both
    its birth/PPid and its parent's birth before recording it. Cleanup signals
    the pinned kernel object, never a numeric descendant PID.
    """
    class Witness(base.ProcessWitness):
        def __init__(self, pid):
            if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
                raise OSError(errno.ENOSYS, "pidfd_support_required")
            self.owner_start = self.identity(pid)
            self.observation_error = None
            self.handles, self.handles_closed = {}, False
            self.unproven = {}
            self.exited_hints = self.recycled_hints = self.reparented_owned = 0
            require(self.owner_start is not None, "owned_process_identity_missing")
            super().__init__(pid)

        @staticmethod
        def info(pid):
            try:
                with Path(f"/proc/{pid}/stat").open("rb") as stream:
                    raw = stream.read(8193)
                if len(raw) > 8192 or b") " not in raw:
                    return None
                fields = raw.rsplit(b") ", 1)[1].split()
                return int(fields[19]), int(fields[1])
            except (OSError, ValueError, IndexError):
                return None

        @classmethod
        def identity(cls, pid):
            value = cls.info(pid)
            return value[0] if value is not None else None

        @staticmethod
        def exited(descriptor):
            return bool(select.select([descriptor], [], [], 0)[0])

        def parent_exited(self, pid, start):
            descriptor = self.handles.get((pid, start))
            return descriptor is not None and self.exited(descriptor)

        def retain_unproven(self, key, descriptor):
            # Unproven child hints are observation-only. They never enter the
            # owned set or the signal path. An exited hint is harmless; a live
            # unresolved hint prevents complete cleanup evidence.
            if self.exited(descriptor):
                self.exited_hints += 1
                return False
            if key in self.unproven:
                return False
            self.unproven[key] = descriptor
            return True

        def pin(self, pid, parent_pid, parent_start):
            before = self.info(pid)
            if before is None:
                return None
            key = pid, before[0]
            # Its existing pidfd and birth already established ownership. A
            # child remains owned when its original parent exits and it is
            # reparented; repeating an ancestry test would reject normal exit.
            if key in self.handles:
                return key
            ancestry_valid = before[1] == parent_pid and (
                parent_start is None or self.identity(parent_pid) == parent_start)
            require(len(self.handles) + len(self.unproven) < 128, "process_witness_limit")
            descriptor = os.pidfd_open(pid, 0)
            retained = False
            try:
                after = self.info(pid)
                if after is None:
                    if self.exited(descriptor):
                        self.exited_hints += 1
                    else:
                        retained = self.retain_unproven(key, descriptor)
                    return None
                if after[0] != before[0]:
                    # Birth changed: the first hinted process has exited. The
                    # newly pinned process is not adopted or signalled.
                    self.recycled_hints += 1
                    return None
                parent_stable = parent_start is None or self.identity(parent_pid) == parent_start
                parent_finished = parent_start is not None and self.parent_exited(parent_pid, parent_start)
                if not ancestry_valid or not ((after[1] == parent_pid and parent_stable) or parent_finished):
                    retained = self.retain_unproven(key, descriptor)
                    return None
                if after[1] != parent_pid:
                    self.reparented_owned += 1
                self.handles[key] = descriptor
                self.observed[key] = {"pid": pid, "start_time_ticks": before[0],
                    "parent_process": pid == self.parent, "pidfd_pinned": True,
                    "parent_pid": parent_pid, "parent_start_time_ticks": parent_start}
                retained = True
                return key
            finally:
                if not retained:
                    os.close(descriptor)

        def sample(self):
            if self.handles_closed or self.identity(self.parent) != self.owner_start:
                return
            pending, visited = [(self.parent, os.getpid(), None)], set()
            try:
                while pending:
                    pid, parent_pid, parent_start = pending.pop()
                    if pid in visited:
                        continue
                    visited.add(pid)
                    require(len(visited) <= 128, "process_witness_limit")
                    try:
                        key = self.pin(pid, parent_pid, parent_start)
                    except ProcessLookupError:
                        continue
                    if key is None:
                        continue
                    try:
                        with Path(f"/proc/{pid}/task/{pid}/children").open("rb") as stream:
                            raw = stream.read(16385)
                        require(len(raw) <= 16384, "process_witness_limit")
                        children = [int(value) for value in raw.split()]
                        require(len(children) <= 128, "process_witness_limit")
                        # The children file may belong to a recycled parent by
                        # now. An exited pinned parent is a normal race; hints
                        # still need their own stable birth and ancestry proof.
                        if self.identity(pid) != key[1]:
                            if not self.parent_exited(pid, key[1]):
                                self.observation_error = "process_observation_incomplete"
                            else:
                                pending.extend((child, pid, key[1]) for child in children)
                            continue
                        pending.extend((child, pid, key[1]) for child in children)
                    except FileNotFoundError:
                        pass
            except (OSError, ValueError):
                self.observation_error = "process_observation_incomplete"

        def stop_sampling(self):
            self.stopped.set()
            self.thread.join(timeout=2)

        def signal_owned(self, selected_signal=None):
            if self.handles_closed:
                return
            selected_signal = signal.SIGKILL if selected_signal is None else selected_signal
            for descriptor in list(self.handles.values()):
                try:
                    signal.pidfd_send_signal(descriptor, selected_signal, None, 0)
                except ProcessLookupError:
                    pass
                except OSError:
                    self.observation_error = "process_cleanup_signal_incomplete"

        def close_handles(self):
            if not self.handles_closed:
                for descriptor in [*self.handles.values(), *self.unproven.values()]:
                    os.close(descriptor)
                self.handles.clear()
                self.unproven.clear()
                self.handles_closed = True

        def finish(self):
            if self.final is not None and (self.final["all_stopped"] or self.handles_closed):
                return self.final
            self.stop_sampling()
            deadline = time.monotonic() + 5
            while True:
                alive = [self.observed[key] for key, descriptor in self.handles.items()
                         if not self.exited(descriptor)]
                unresolved = [{"pid": key[0], "start_time_ticks": key[1]} for key, descriptor in self.unproven.items()
                              if not self.exited(descriptor)]
                if (not alive and not unresolved) or time.monotonic() >= deadline:
                    break
                time.sleep(.02)
            rows = list(self.observed.values())
            self.final = {"observed": rows, "descendant_count": sum(not r["parent_process"] for r in rows),
                "all_stopped": not alive and not unresolved and not self.thread.is_alive() and self.observation_error is None,
                "remaining": alive, "unproven_hints_remaining": unresolved, "pidfd_cleanup": True,
                "discarded_exited_hints": self.exited_hints, "discarded_recycled_hints": self.recycled_hints,
                "reparented_owned_count": self.reparented_owned}
            if self.observation_error is not None:
                self.final["observation_error"] = self.observation_error
            if not alive and not unresolved:
                self.close_handles()
            return self.final
    return Witness(parent)


class Suite:
    def __init__(self, args, paths, roots, report):
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise OSError(errno.ENOSYS, "pidfd_support_required")
        descriptor = os.pidfd_open(os.getpid(), 0)
        os.close(descriptor)
        self.args, self.paths, self.roots, self.report = args, paths, roots, report
        self.deadline = time.monotonic() + args.timeout_seconds
        self.work = args.output / "owned"
        self.work.mkdir(mode=0o700)
        self.state = self.work / "runs"
        self.state.mkdir(mode=0o700)
        self.env = {"PATH": "/usr/bin:/bin", "HOME": str(self.work), "TMPDIR": str(self.work),
                    "LANG": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                    "AGENTFW_WORKSPACE": str(self.work)}
        self.active = []
        self.host = load("self_test_scripted_provider", "mcp-admission-demo.py")
        self.base = load("self_test_process_witness", "verify-sou62-real-mcp.py")
        self.sentinel = self.work / "unrelated.txt"
        self.write(self.sentinel, b"Owned unrelated sentinel.\n")
        self.sentinel_before = snapshot(self.sentinel)

    def remaining(self, maximum=15):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError()
        return min(remaining, maximum)

    @staticmethod
    def write(path, raw):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)

    def check(self):
        self.remaining()
        require(snapshot(self.sentinel) == self.sentinel_before, "unrelated_sentinel_changed")
        tree_witness(self.work, contents=False, transient=True)

    def cli(self, *words, timeout=12):
        process = subprocess.Popen([str(self.args.agent), "edit-session", *map(str, words)],
            cwd=self.work, env=self.env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        out, err = Capture(process.stdout), Capture(process.stderr)
        try:
            process.wait(timeout=self.remaining(timeout))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=3)
        stdout, stderr = out.finish(), err.finish()
        self.report["last_command"] = {"exit_code": process.returncode,
            "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
            "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)}
        try:
            value = strict(stdout)
        except ValueError:
            value = None
        return process.returncode, value

    def ask(self, run, action="list", pending=None):
        words = ["ask", "--run", run, action]
        if pending is not None:
            if action == "approve":
                words += ["--binding", pending["binding_sha256"]]
            words += ["--", pending["pending_id"]]
        return self.cli(*words)

    def prepare(self, name, replace=False, two=False, limits=None):
        root, plan = self.work / name, self.work / (name + "-plan")
        root.mkdir(mode=0o700)
        self.write(root / "source.txt", OLD)
        if replace:
            self.write(root / "result.txt", OLD)
        limits = limits or (1, len(NEW) * (2 if two else 1))
        words = ["prepare", "--home", self.args.home, "--root", root,
                 "--claude", self.paths["claude"], "--private-sole-writer", "--out", plan,
                 "--read", "source.txt", "--read", "result.txt",
                 "--replace" if replace else "--create", "result.txt",
                 "--max-mutations", limits[0], "--max-write-bytes", limits[1], "--apply"]
        if two:
            words += ["--create", "second.txt", "--read", "second.txt"]
        code, value = self.cli(*words)
        require(code == 0 and isinstance(value, dict), "self_test_prepare_failed")
        quota = value["profile"]["mutation_quota"]
        require(quota["max_mutations"] == limits[0] and quota["max_write_bytes"] == limits[1],
                "selected_quota_changed")
        return root, plan, value

    def until(self, predicate, failure, seconds=5):
        deadline = time.monotonic() + self.remaining(seconds)
        while time.monotonic() < deadline:
            self.check()
            value = predicate()
            if value:
                return value
            time.sleep(.025)
        raise ValueError(failure)


class Run:
    def __init__(self, suite, name, *, replace=False, two=False, pause_after=None, limits=None):
        self.suite, self.name = suite, name
        self.process = self.witness = self.model = self.stdout = self.stderr = None
        self.closed, self.release, self.paused = threading.Event(), threading.Event(), threading.Event()
        self.offered, self.observed, self.decisions = set(), {}, []
        self.run = self.home = None
        self.finished = None
        suite.active.append(self)
        self.root, self.plan, self.prepared = suite.prepare(name, replace, two, limits)
        self.target = self.root / "result.txt"
        self.before = snapshot(self.target)
        self.plan_before = sha(bounded(self.plan / "profile.json"))
        targets = self.prepared["profile"]["targets"]
        def read(leaf):
            index = next(i for i, t in enumerate(targets) if t["name"] == leaf)
            return f"read_output_{index}", {"path": leaf}
        def write(leaf):
            index = next(i for i, t in enumerate(targets) if t["name"] == leaf)
            baseline = targets[index]["replacement"]
            arguments = {"path": leaf, "content": NEW.decode()}
            if baseline is not None:
                arguments.update(old_identity=baseline["identity"], old_sha256=baseline["sha256"])
            return ("replace" if baseline else "create") + f"_output_{index}", arguments
        self.proposals = [read("source.txt"), write("result.txt"), read("result.txt")]
        if two:
            self.proposals += [write("second.txt"), read("second.txt")]
        self.model = suite.host.ScriptedModel([])
        self.model.requests = BoundedRequests()
        # The generic demo server prints tracebacks containing source paths on
        # handler errors. The self-test reports only finite typed observations.
        self.model.server.handle_error = lambda *_args: None
        def step(body):
            names = {t.get("name") for t in body.get("tools", [])}
            if not any(n and n.startswith("mcp__private-output__") for n in names):
                return [{"type": "text", "text": "Owned auxiliary request."}]
            for message in body.get("messages", []):
                blocks = message.get("content", [])
                for block in blocks if isinstance(blocks, list) else []:
                    if isinstance(block, dict) and block.get("type") == "tool_result" and block.get("tool_use_id") in self.offered:
                        self.observed[block["tool_use_id"]] = {"is_error": bool(block.get("is_error")), "content": block.get("content")}
            for index, (tool, arguments) in enumerate(self.proposals):
                identity = "toolu_self_test_" + str(index)
                if identity not in self.observed:
                    if pause_after is not None and index > pause_after:
                        self.paused.set()
                        if not self.release.wait(suite.remaining(20)) or self.closed.is_set():
                            return [{"type": "text", "text": "Owned request stopped."}]
                    require(identity not in self.offered, "host_reissued_request")
                    self.offered.add(identity)
                    return [{"type": "tool_use", "id": identity, "name": "mcp__private-output__" + tool, "input": arguments}]
            return [{"type": "text", "text": "Owned self-test sequence completed."}]
        self.model.next = step
        prompt = suite.work / (name + "-prompt.txt")
        suite.write(prompt, b"Use only the selected private output tools for the owned test sequence.")
        env = dict(suite.env, ANTHROPIC_API_KEY=secrets.token_hex(32), ANTHROPIC_BASE_URL=self.model.url,
                   HTTP_PROXY="http://127.0.0.1:9", HTTPS_PROXY="http://127.0.0.1:9",
                   NO_PROXY="localhost,127.0.0.1,::1")
        self.process = subprocess.Popen([str(suite.args.agent), "edit-session", "run", "--plan", str(self.plan),
            "--sha256", self.prepared["profile_sha256"], "--state", str(suite.state), "--prompt-file", str(prompt),
            "--timeout-seconds", str(max(1, int(suite.remaining(40))))], cwd=suite.work, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        self.stdout, self.stderr = Capture(self.process.stdout), Capture(self.process.stderr)
        self.witness = owned_process_witness(suite.base, self.process.pid)
        suite.until(self.record, "running_record_missing", 10)
        control = strict(bounded(self.run / "control.json"))
        require(control["launcher_pid"] == self.process.pid
                and control["launcher_start"] == suite.base.ProcessWitness.identity(self.process.pid)
                and control["profile_sha256"] == self.prepared["profile_sha256"], "owned_launcher_identity_mismatch")
        self.control = control

    def record(self):
        rows = self.stdout.raw().splitlines()
        if not rows:
            return None
        value = strict(rows[0])
        candidate = Path(value["run"])
        require(candidate.parent == self.suite.state and candidate.name.startswith("edit-")
                and candidate.resolve(strict=True) == candidate, "owned_run_identity_mismatch")
        self.run = candidate
        record = strict(bounded(candidate / "run.json"))
        self.home = Path(record["home"])
        require(self.home.parent == candidate and self.home.resolve(strict=True) == self.home,
                "owned_run_home_mismatch")
        return candidate

    def pending(self):
        code, value = self.suite.ask(self.run)
        return value[0] if code == 0 and isinstance(value, list) and value else None

    def decide(self, pending, approve=True):
        code, _ = self.suite.ask(self.run, "approve" if approve else "reject", pending)
        if code == 0:
            self.decisions.append(dict(pending))
        return code

    def finish(self, *, approve=True, expected_exit=0):
        if self.finished is not None:
            return self.finished
        seen = {item["pending_id"] for item in self.decisions}
        # WNOWAIT keeps the leader owned and unreaped while process identities
        # are being sampled, closing the root-PID reuse window.
        while os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            self.suite.check()
            self.stdout.raw(); self.stderr.raw()
            pending = self.pending()
            if pending and pending["pending_id"] not in seen:
                require(self.decide(pending, approve) == 0, "pending_decision_failed")
                seen.add(pending["pending_id"])
            time.sleep(.025)
        self.witness.stop_sampling()
        self.process.wait(timeout=2)
        stdout, stderr = self.stdout.finish(), self.stderr.finish()
        cleanup = self.witness.finish()
        if not cleanup["all_stopped"] or cleanup["descendant_count"] < 2:
            raise ObservationIncomplete("owned_process_cleanup_incomplete")
        require(expected_exit is None or self.process.returncode == expected_exit, "unexpected_host_exit")
        require(sha(bounded(self.plan / "profile.json")) == self.plan_before, "immutable_plan_changed")
        require(not any(p.name.startswith(".soup-") for p in self.root.iterdir()), "staging_state_remains")
        terminal = strict(bounded(self.run / "terminal.json")) if (self.run / "terminal.json").exists() else None
        raw_audit = bounded(self.home / "audit.jsonl", MAX_STREAM * 2)
        audit = [strict(line) for line in raw_audit.splitlines() if line]
        writes = [r for r in audit if r.get("event") == "native_call" and r.get("released") is True
                  and str(r.get("tool", "")).startswith(("create_output_", "replace_output_"))]
        publications = [r for r in audit if r.get("event") == "native_publish" and r.get("released") is True]
        bindings = {item["binding_sha256"] for item in self.decisions}
        require(all(r.get("binding_sha256") in bindings for r in [*writes, *publications]),
                "write_without_exact_approval")
        require(b"edit_adapter_mutation_dispatch" not in stderr, "unexpected_adapter_mutation")
        quota = terminal.get("mutation_quota") if terminal else None
        if quota is not None:
            fields = ("admitted_mutation_attempts", "charged_write_bytes", "known_committed_mutations", "known_committed_write_bytes")
            require(all(type(quota.get(key)) is int and quota[key] >= 0 for key in fields), "quota_usage_invalid")
            quota = {key: quota[key] for key in fields}
            limits = self.prepared["profile"]["mutation_quota"]
            require(quota["admitted_mutation_attempts"] <= limits["max_mutations"]
                    and quota["charged_write_bytes"] <= limits["max_write_bytes"]
                    and quota["known_committed_mutations"] <= quota["admitted_mutation_attempts"]
                    and quota["known_committed_write_bytes"] <= quota["charged_write_bytes"], "quota_ceiling_violated")
            previous = (0, 0)
            for line in stderr.splitlines():
                try:
                    event = strict(line)
                except ValueError:
                    continue
                if isinstance(event, dict) and event.get("event") == "edit_mutation_quota":
                    usage = event["usage"]
                    current = (usage["admitted_mutation_attempts"], usage["charged_write_bytes"])
                    require(all(type(n) is int for n in current) and current[0] >= previous[0]
                            and current[1] >= previous[1], "active_quota_refunded")
                    previous = current
        self.finished = {"exit_code": self.process.returncode, "native_write_authorizations": len(writes),
            "publication_gates": len(publications), "approved_or_rejected": len(self.decisions),
            "observed_results": len(self.observed), "audit_sha256": sha(raw_audit),
            "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr),
            "provider_requests": len(self.model.requests), "provider_bytes": self.model.requests.bytes,
            "processes": cleanup, "target_before": self.before, "target_after": snapshot(self.target),
            "quota": quota}
        return self.finished

    def stop(self):
        code, value = self.suite.cli("stop", "--run", self.run, "--output", "json-v1", timeout=16)
        require(code == 0 and isinstance(value, dict)
                and value.get("status") in ("stopped", "already_stopped")
                and value.get("revocation_confirmed") is True and value.get("cleanup_confirmed") is True
                and value.get("effects_may_remain_committed") is True
                and value.get("running_effects_rolled_back") is False
                and value.get("automatic_retry") is False, "exact_stop_unconfirmed")
        return {key: value[key] for key in ("status", "revocation_confirmed", "cleanup_confirmed",
                                            "effects_may_remain_committed", "automatic_retry")}

    def close(self):
        self.closed.set(); self.release.set()
        if self.witness is not None:
            self.witness.stop_sampling()
            # Only the originally pinned root can contribute a final sample.
            self.witness.sample()
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGCONT)
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
        # Kernel handles stay bound even if a numeric descendant PID is reused.
        if self.witness is not None:
            self.witness.signal_owned()
        for capture in (self.stdout, self.stderr):
            if capture is not None:
                capture.thread.join(timeout=2)
        if self.model is not None:
            self.model.close()
        return self.witness.finish() if self.witness is not None else {"all_stopped": True, "observed": []}


def useful(run, facts, *, expected_authorizations=1):
    observed = [run.observed.get("toolu_self_test_" + str(i)) for i in range(3)]
    evidence = {"target_bytes_match": bounded(run.target, 4096) == NEW,
                "initial_results_present": all(isinstance(item, dict) for item in observed),
                "initial_results_succeeded": all(isinstance(item, dict) and not item.get("is_error") for item in observed),
                "initial_read_exact": exact_result((observed[0] or {}).get("content"), OLD),
                "final_read_exact": exact_result((observed[2] or {}).get("content"), NEW),
                "expected_write_authorizations": facts["native_write_authorizations"] == expected_authorizations}
    # Preserve independent runtime observations even when their grading fails.
    active = next(row for row in run.suite.report["cases"] if row["id"] == run.suite.report["active_case"])
    active.setdefault("runtime_attempts", []).append({"witness": facts, "readback": evidence})
    for field, complete in evidence.items():
        require(complete, "useful_" + field + "_missing")


def result_text(content):
    """Normalize only accepted text envelopes, never a substring match."""
    if isinstance(content, list):
        if not content or not all(isinstance(block, dict) and block.get("type") == "text"
                                  and isinstance(block.get("text"), str) for block in content):
            return None
        content = "".join(block["text"] for block in content)
    if not isinstance(content, str):
        return None
    return re.sub(r"\n\n?<system-reminder>\n<total_tokens>[0-9]+ tokens left</total_tokens>\n</system-reminder>$", "", content)


def exact_result(content, expected):
    content = result_text(content)
    if content is None:
        return False
    if content == expected.decode():
        return True
    try:
        value = strict(content)
    except ValueError:
        return False
    return isinstance(value, dict) and value == {"content": expected.decode()}


def quota_refusal(result, code):
    if result.get("is_error") is not True:
        return False
    try:
        value = strict(result_text(result.get("content")) or "")
    except ValueError:
        return False
    return (isinstance(value, dict) and value.get("error_code") == code
            and value.get("automatic_retry") is False
            and value.get("active_run_reset_available") is False)


def execute(suite, report):
    rows = {row["id"]: row for row in report["cases"]}
    def begin(name):
        row = rows[name]; row["attempted"] = True
        report["active_case"] = name
        return row
    def done(row, **facts):
        suite.check()
        row.update(facts, status="passed")
    previous_approval = None
    for name, replacing in (("create-read", False), ("replace-read", True)):
        row = begin(name)
        run = Run(suite, name, replace=replacing)
        facts = run.finish()
        useful(run, facts)
        require(not replacing or facts["publication_gates"] == 1, "replace_publication_missing")
        if previous_approval:
            require(suite.ask(previous_approval[0], "approve", previous_approval[1])[0] != 0,
                    "approved_authority_replayed")
        previous_approval = run.run, run.decisions[0]
        done(row, witness=facts, exact_readback=True)

    row = begin("ask-reject-replay")
    run = Run(suite, "reject", replace=True, pause_after=1)
    pending = suite.until(run.pending, "pending_ask_missing")
    require(run.decide(pending, False) == 0, "rejection_failed")
    suite.until(run.paused.is_set, "rejected_result_missing")
    require(run.observed["toolu_self_test_1"]["is_error"]
            and snapshot(run.target) == run.before, "rejected_write_had_effect")
    require(run.decide(pending) != 0, "rejected_authority_replayed")
    run.release.set()
    facts = run.finish()
    require(facts["native_write_authorizations"] == 0 and snapshot(run.target) == run.before,
            "rejection_not_preserved")
    done(row, witness=facts, rejection_observed=True, replay_refused=True)

    row = begin("aggregate-quota")
    run = Run(suite, "quota", two=True)
    facts = run.finish()
    useful(run, facts, expected_authorizations=2)
    usage = facts["quota"] or {}
    require(not (run.root / "second.txt").exists()
            and run.observed["toolu_self_test_3"]["is_error"]
            and usage.get("admitted_mutation_attempts") == 1
            and usage.get("charged_write_bytes") == len(NEW)
            and usage.get("known_committed_mutations") == 1
            and usage.get("known_committed_write_bytes") == len(NEW)
            and len(run.decisions) == 2
            and quota_refusal(run.observed["toolu_self_test_3"], "edit_quota_mutation_limit"),
            "aggregate_quota_not_enforced")
    byte_run = Run(suite, "byte-quota", two=True, limits=(2, len(NEW) + 1))
    byte_facts = byte_run.finish()
    useful(byte_run, byte_facts, expected_authorizations=2)
    byte_usage = byte_facts["quota"] or {}
    require(not (byte_run.root / "second.txt").exists()
            and byte_run.observed["toolu_self_test_3"]["is_error"]
            and byte_usage.get("admitted_mutation_attempts") == 1
            and byte_usage.get("charged_write_bytes") == len(NEW)
            and byte_usage.get("known_committed_mutations") == 1
            and byte_usage.get("known_committed_write_bytes") == len(NEW)
            and len(byte_run.decisions) == 2
            and quota_refusal(byte_run.observed["toolu_self_test_3"], "edit_quota_write_byte_limit"),
            "aggregate_byte_quota_not_enforced")
    done(row, witness=facts, byte_witness=byte_facts, second_target_absent=True, quota_not_refunded=True,
         mutation_ceiling_enforced=True, byte_ceiling_enforced=True,
         native_authorizations_precede_quota=True, fresh_ask_for_each_mutation=True)

    row = begin("exact-run-stop")
    selected = Run(suite, "selected-stop", replace=True)
    pending = suite.until(selected.pending, "stop_pending_missing")
    peer = Run(suite, "independent-peer")
    peer_pending = suite.until(peer.pending, "peer_pending_missing")
    stop = selected.stop()
    require(peer.process.poll() is None and snapshot(selected.target) == selected.before,
            "stop_changed_peer_or_target")
    selected_facts = selected.finish(expected_exit=0)
    require(peer.decide(peer_pending) == 0, "peer_approval_failed")
    peer_facts = peer.finish()
    useful(peer, peer_facts)
    require(selected_facts["native_write_authorizations"] == 0, "stopped_pending_write_dispatched")
    done(row, selected=selected_facts, peer=peer_facts, stop=stop, independent_run_preserved=True)
    row = begin("stopped-authority")
    require(selected.decide(pending) != 0, "stopped_approval_replayed")
    repeated = selected.stop()
    require(repeated["status"] == "already_stopped" and snapshot(selected.target) == selected.before,
            "repeat_stop_changed_effect")
    done(row, stale_approval_refused=True, repeat_stop=repeated)

    row = begin("daemon-loss")
    lost = Run(suite, "daemon-loss", replace=True)
    lost_pending = suite.until(lost.pending, "loss_pending_missing")
    old_token = bounded(lost.home / "native-token").decode()
    diagnostic = strict(bounded(lost.run / "diagnostic-context.json"))
    owner = diagnostic["owner"]
    # This accepted runner hosts its enforcing axum daemon in the owning
    # launcher process. Bind the injected loss to the daemon's recorded birth,
    # never to an arbitrary process named by an operator file.
    require(owner["pid"] == lost.process.pid
            and owner["start_ticks"] == suite.base.ProcessWitness.identity(lost.process.pid)
            and owner["uid"] == os.geteuid(), "owned_daemon_birth_mismatch")
    lost.process.kill()
    lost_facts = lost.finish(expected_exit=None)
    require(lost_facts["exit_code"] != 0 and snapshot(lost.target) == lost.before
            and lost_facts["native_write_authorizations"] == 0
            and lost.decide(lost_pending) != 0, "daemon_loss_did_not_fail_closed")
    before = tree_witness(lost.run)
    code, diagnosis = suite.cli("status", "--run", lost.run, "--json")
    require(code == 0 and isinstance(diagnosis, dict)
            and diagnosis.get("effects") == "indeterminate"
            and diagnosis.get("host_delivery") == "unknown"
            and diagnosis.get("model_consumption") == "unknown"
            and tree_witness(lost.run) == before, "interrupted_outcome_overclaimed")
    done(row, witness=lost_facts, effects="indeterminate", host_delivery="unknown",
         model_consumption="unknown", read_only_diagnosis=True,
         interruption_scope="combined-owner-and-in-process-daemon-loss",
         daemon_owner={"pid": owner["pid"], "start_ticks": owner["start_ticks"]},
         daemon_owner_birth_verified=True)

    row = begin("fresh-run-recovery")
    fresh = Run(suite, "fresh-recovery")
    fresh_pending = suite.until(fresh.pending, "fresh_pending_missing")
    require(fresh_pending["pending_id"] != lost_pending["pending_id"]
            and fresh.control["instance_id"] != lost.control["instance_id"], "fresh_authority_not_new")
    config = bounded(fresh.home / "config.yaml").decode()
    port = int(re.search(r"^port: ([0-9]+)$", config, re.M)[1])
    request = urllib.request.Request(f"http://127.0.0.1:{port}/native/edit-session/v1",
        data=b"retired authority must not reach the new epoch",
        headers={"Authorization": "Bearer " + old_token}, method="POST")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_):
            return None
    refused = False
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(request, timeout=2):
            pass
    except urllib.error.HTTPError as error:
        refused = error.code == 401
    require(refused and lost.decide(lost_pending) != 0, "old_epoch_authority_accepted")
    require(fresh.decide(fresh_pending) == 0, "fresh_approval_failed")
    facts = fresh.finish()
    useful(fresh, facts)
    require(tree_witness(lost.run) == before and snapshot(lost.target) == lost.before,
            "recovery_resumed_old_run")
    done(row, witness=facts, old_epoch_refused=True, old_run_preserved=True,
         automatic_retry=False, fresh_ask_required=True, old_quota_not_refilled=True)
    report.pop("active_case", None)


def output_directory(args, roots):
    output = args.output
    require(output is not None and output.is_absolute() and not output.exists()
            and output.parent.resolve(strict=True) / output.name == output,
            "fresh_absolute_output_required")
    for root in [ROOT, args.home, args.selection.parent.parent.parent, *roots.values()]:
        require(not output.is_relative_to(root) and not root.is_relative_to(output),
                "output_overlaps_protected_state")
    parent = output.parent.stat()
    require(parent.st_uid == os.geteuid() and not parent.st_mode & 0o022,
            "private_output_parent_required")
    output.mkdir(mode=0o700)


def remove_owned(path):
    require(path.name == "owned" and path.resolve(strict=True) == path, "cleanup_root_identity_changed")
    pending, count = [path], 0
    while pending:
        current = pending.pop()
        count += 1
        require(count <= MAX_ENTRIES and current.is_relative_to(path), "cleanup_entry_limit")
        mode = current.lstat().st_mode
        require(stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode),
                "cleanup_special_file_refused")
        if stat.S_ISDIR(mode):
            current.chmod(0o700)
            with os.scandir(current) as entries:
                for entry in entries:
                    require(count + len(pending) < MAX_ENTRIES, "cleanup_entry_limit")
                    pending.append(Path(entry.path))
        elif stat.S_ISREG(mode):
            current.chmod(0o600)
    def repair(function, name, _error):
        candidate = Path(name)
        require(candidate.is_relative_to(path) and not candidate.is_symlink(), "cleanup_path_escape")
        candidate.chmod(0o700 if candidate.is_dir() else 0o600)
        function(name)
    shutil.rmtree(path, onerror=repair)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--agent", type=Path, required=True)
    parser.add_argument("--run", action="store_true", help="Consent to bounded execution in a fresh owned workspace.")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--keep-workspace", action="store_true")
    args = parser.parse_args(argv)
    if not 10 <= args.timeout_seconds <= 600:
        parser.error("--timeout-seconds must be between 10 and 600")
    if args.run and args.output is None:
        parser.error("--run requires --output")
    report = {"format": FORMAT, "status": "incomplete", "executed": False, "paid_inference": False,
        "expected": list(CASES), "cases": inventory(),
        "scope": "selected-genuine-Claude-owned-scripted-provider-native-private-output",
        "original_filesystem_git": "selected-runtime-pins-validated; private-output edits use the accepted native edit API",
        "effects_of_interrupted_runs": "indeterminate; no automatic retry or mutation replay",
        "cleanup": {"all_owned_processes_stopped": True, "workspace_removed": False,
                    "workspace_retained": False, "keep_workspace_requested": args.keep_workspace}}
    suite, output_created = None, False
    protected_before = None
    try:
        profile = platform_profile()
        report["platform"] = profile
        if not profile["supported"]:
            report.update(status="unsupported", reason="linux_x86_64_required")
            for row in report["cases"]:
                row["status"] = "unsupported"
        else:
            require(os.geteuid() != 0, "non_root_operator_required")
            pilot, paths, roots, identities = preflight(args)
            report["identities"] = identities
            if not args.run:
                report.update(status="preview", reason="explicit_run_consent_required")
            else:
                output_directory(args, roots)
                output_created = True
                # Snapshot complete selected project bytes only within explicit finite bounds.
                # Larger projects produce INCOMPLETE rather than an unverified preservation claim.
                protected_before = {"projects": {kind: tree_witness(root) for kind, root in roots.items()},
                    "current": sha(bounded(args.home / "pilot-front-door/current.json")),
                    "home": tree_witness(args.home, contents=False),
                    "selection": sha(bounded(args.selection))}
                suite = Suite(args, paths, roots, report)
                report["executed"] = True
                execute(suite, report)
                report["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        code = reason(error)
        report["failure_observation"] = failure_observation(error)
        report.update(status="incomplete" if isinstance(error, (OSError, TimeoutError, KeyboardInterrupt, ObservationIncomplete)) else "failed",
                      reason=code)
        active = report.get("active_case")
        for row in report["cases"]:
            if row["id"] == active:
                row.update(status=report["status"], reason=code)
    finally:
        if suite is not None:
            cleanups = []
            for run in suite.active:
                try:
                    cleanups.append(run.close())
                except Exception:
                    cleanups.append({"all_stopped": False})
            report["cleanup"]["all_owned_processes_stopped"] = all(r.get("all_stopped") is True for r in cleanups)
            report["cleanup"]["process_groups"] = cleanups
            try:
                after = {"projects": {kind: tree_witness(root) for kind, root in suite.roots.items()},
                    "current": sha(bounded(args.home / "pilot-front-door/current.json")),
                    "home": tree_witness(args.home, contents=False),
                    "selection": sha(bounded(args.selection))}
                report["preservation"] = {"original_projects_unchanged": after["projects"] == protected_before["projects"],
                    "installed_state_unchanged": all(after[k] == protected_before[k] for k in ("current", "home", "selection")),
                    "unrelated_sentinel_unchanged": snapshot(suite.sentinel) == suite.sentinel_before}
            except Exception:
                report["preservation"] = {"original_projects_unchanged": False, "installed_state_unchanged": False}
            if report["cleanup"]["all_owned_processes_stopped"] and not args.keep_workspace:
                try:
                    remove_owned(suite.work)
                    report["cleanup"]["workspace_removed"] = True
                except Exception:
                    report["cleanup"]["workspace_retained"] = True
            else:
                report["cleanup"]["workspace_retained"] = True
            if report["status"] == "passed" and not passed(report):
                report.update(status="incomplete", reason="cleanup_or_preservation_incomplete")
        report["inventory"] = counts(report["cases"])
        report.pop("active_case", None)
        if output_created:
            raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
            require(len(raw) <= 256 * 1024, "report_byte_limit")
            Suite.write(args.output / "report.json", raw)
    print(json.dumps({key: report[key] for key in ("format", "status", "executed", "inventory")}
                     | {"reason": report.get("reason"), "platform": report.get("platform"),
                        "identities": report.get("identities"), "cleanup": report["cleanup"]}, sort_keys=True))
    return EXIT[report["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
