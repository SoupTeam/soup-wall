"""Read-only, bounded observations of every leaf in one prepared pilot root.

Pass the accepted SOU-79 module as ``resource``; this module loads no source and
starts no work at import. Leaf names/inodes in snapshots are private correlation
fields. The driver must match them to bound receipts, then omit them publicly.
``finish`` never kills processes, removes cgroups, or repairs delegation.
"""

from __future__ import annotations

import copy
import errno
import os
from pathlib import Path
import re
import stat
import threading
import time


FORMAT = "sou142-prepared-budget-observer/1"
LEAF = re.compile(r"agentfw-mcp-[0-9a-f]{32}\Z")
MAX_BYTES = 65_536
MAX_MEMBERS = 4_096
MAX_U64 = (1 << 64) - 1
ROLES = frozenset(("filesystem", "git"))
TEARDOWN = frozenset((errno.ENOENT, errno.ENODEV))


class ObservationError(ValueError):
    """A finite observer reason, without paths or exception payloads."""


def _require(condition, reason):
    if not condition:
        raise ObservationError(reason)


def _number(value):
    _require(type(value) is int and 0 <= value <= MAX_U64, "counter_invalid")
    return value


class BudgetObserver:
    """Pin a fresh root and observe at most ``max_leaves`` historical leaves.

    ``classify_member(pid)`` is optional and must perform its own live process
    identity checks. It may return None, filesystem/git, or an exact dict with
    ``server`` and boolean ``original_runtime_seen``. Raw process identities
    never enter the returned rows. A missing or ambiguous supplied classifier
    cannot become successful attribution.
    """

    def __init__(self, root, resource, max_leaves=64, classify_member=None):
        _require(type(max_leaves) is int and 1 <= max_leaves <= 64, "leaf_limit_invalid")
        _require(classify_member is None or callable(classify_member), "classifier_invalid")
        self.root, self.resource = Path(root), resource
        self.max_leaves, self.classify_member = max_leaves, classify_member
        self._lock, self._stop = threading.RLock(), threading.Event()
        self._rows, self._errors, self._final = {}, [], None
        self._root_fd = None
        self._started, self._closed = time.monotonic(), False
        try:
            _require(self.root.is_absolute() and self.root.resolve(strict=True) == self.root,
                     "root_invalid")
            self._root_fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(self._root_fd)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                     and not info.st_mode & 0o077, "root_invalid")
            self._root_identity = (info.st_dev, info.st_ino)
            self._check_root()
            _require(not self._directories(), "root_not_empty")
            _require(not self._read(self._root_fd, "cgroup.procs").strip(), "root_not_empty")
        except (OSError, RuntimeError, ValueError):
            if self._root_fd is not None:
                os.close(self._root_fd)
                self._root_fd = None
            raise ObservationError("observer_root_invalid_or_occupied") from None
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    @staticmethod
    def _read(directory, name):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                             os.O_NONBLOCK, dir_fd=directory)
        try:
            chunks, length = [], 0
            while length <= MAX_BYTES:
                raw = os.read(descriptor, min(4_096, MAX_BYTES + 1 - length))
                if not raw:
                    break
                chunks.append(raw)
                length += len(raw)
            _require(length <= MAX_BYTES, "control_overflow")
            return b"".join(chunks).decode("ascii")
        finally:
            os.close(descriptor)

    def _check_root(self):
        current = self.root.stat(follow_symlinks=False)
        held = os.fstat(self._root_fd)
        _require(stat.S_ISDIR(current.st_mode)
                 and (current.st_dev, current.st_ino) == self._root_identity
                 and (held.st_dev, held.st_ino) == self._root_identity
                 and current.st_uid == os.geteuid() and not current.st_mode & 0o077
                 and self.root.resolve(strict=True) == self.root, "root_replaced")

    def _directories(self):
        result = []
        # FD-relative inventory cannot follow an operator's substituted root.
        with os.scandir(self._root_fd) as entries:
            for entry in entries:
                _require(not entry.is_symlink(), "unexpected_symlink")
                if entry.is_dir(follow_symlinks=False):
                    _require(len(result) < self.max_leaves, "leaf_limit_exceeded")
                    _require(LEAF.fullmatch(entry.name) is not None, "unexpected_directory")
                    result.append(entry.name)
        return result

    def _discover(self):
        for name in self._directories():
            if name in self._rows:
                continue
            _require(len(self._rows) < self.max_leaves, "leaf_limit_exceeded")
            try:
                descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                                     os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._root_fd)
            except FileNotFoundError:
                self._error("leaf_vanished_before_pin")
                continue
            try:
                info = os.fstat(descriptor)
                _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                         and not info.st_mode & 0o077, "leaf_invalid")
                identity = (info.st_dev, info.st_ino)
                _require(not any((row["device"], row["inode"]) == identity
                                 for row in self._rows.values()), "leaf_renamed")
                _require(self.resource.leaf_state(self.root / name, identity) == "live",
                         "leaf_replaced")
                self._rows[name] = {
                    "leaf": name, "device": info.st_dev, "inode": info.st_ino,
                    "first": None, "last": None, "samples": 0, "startup_samples": 0,
                    "memory_peak_bytes": 0, "tasks_peak": 0,
                    "counter_max": {"oom": 0, "oom_kill": 0, "pids_max": 0, "throttled": 0},
                    "member_count_peak": 0, "servers": [], "original_runtime_seen": False,
                    "removed": False, "errors": [], "shutdown_read": None,
                    "_fd": descriptor, "_seen": time.monotonic(), "_removed_at": None,
                    "_shutdown": None,
                }
            except Exception:
                os.close(descriptor)
                raise

    def _error(self, reason, row=None):
        target = self._errors if row is None else row["errors"]
        if reason not in target:
            # Reasons originate only in the finite branches below.
            target.append(reason)

    @staticmethod
    def _keyed(raw, allowed):
        result = {}
        for line in raw.splitlines():
            fields = line.split()
            _require(len(fields) == 2 and fields[0] not in result, "counter_invalid")
            value = _number(int(fields[1]))
            if fields[0] in allowed:
                result[fields[0]] = value
        return result

    def _counters(self, row):
        descriptor = row["_fd"]
        values = {name: _number(int(self._read(descriptor, name).strip()))
                  for name in ("memory.current", "memory.peak", "pids.current")}
        values["memory.events"] = self._keyed(self._read(descriptor, "memory.events"),
                                              ("low", "high", "max", "oom", "oom_kill", "oom_group_kill"))
        values["pids.events"] = self._keyed(self._read(descriptor, "pids.events"), ("max",))
        values["cpu.stat"] = self._keyed(self._read(descriptor, "cpu.stat"),
                                         ("usage_usec", "user_usec", "system_usec", "nr_periods",
                                          "nr_throttled", "throttled_usec", "nr_bursts", "burst_usec"))
        values["cgroup.events"] = self._keyed(self._read(descriptor, "cgroup.events"),
                                              ("populated", "frozen"))
        raw_members = self._read(descriptor, "cgroup.procs").split()
        _require(len(raw_members) <= MAX_MEMBERS, "member_limit_exceeded")
        members = [int(value) for value in raw_members]
        _require(all(0 < value <= (1 << 31) - 1 for value in members), "members_invalid")
        values["member_count"] = len(set(members))
        for name in ("pids.peak",):
            try:
                values[name] = _number(int(self._read(descriptor, name).strip()))
            except FileNotFoundError:
                pass
        return values, members

    @staticmethod
    def _project(values):
        projected = {}
        scalar = ("memory.max", "memory.swap.max", "memory.oom.group", "pids.max",
                  "memory.current", "memory.peak", "pids.current", "pids.peak", "cpu.max.burst")
        for key in scalar:
            if key in values:
                projected[key] = _number(values[key])
        if "cpu.max" in values:
            cpu = values["cpu.max"]
            _require(isinstance(cpu, list) and len(cpu) == 2, "counter_invalid")
            projected["cpu.max"] = [_number(value) for value in cpu]
        allowed = {"memory.events": ("low", "high", "max", "oom", "oom_kill", "oom_group_kill"),
                   "pids.events": ("max",), "cpu.stat": ("usage_usec", "user_usec", "system_usec",
                   "nr_periods", "nr_throttled", "throttled_usec", "nr_bursts", "burst_usec"),
                   "cgroup.events": ("populated", "frozen")}
        for section, names in allowed.items():
            if section in values:
                _require(isinstance(values[section], dict), "counter_invalid")
                projected[section] = {name: _number(values[section][name])
                                      for name in names if name in values[section]}
        members = values.get("member_count")
        if members is None:
            members = len(set(values.get("cgroup.procs", ())))
        projected["member_count"] = _number(members)
        return projected

    def _retain_counters(self, row, values):
        row["memory_peak_bytes"] = max(row["memory_peak_bytes"], values["memory.current"],
                                        values["memory.peak"])
        row["tasks_peak"] = max(row["tasks_peak"], values["pids.current"], values.get("pids.peak", 0))
        row["member_count_peak"] = max(row["member_count_peak"], values["member_count"])
        for key, section, field in (("oom", "memory.events", "oom"),
                                   ("oom_kill", "memory.events", "oom_kill"),
                                   ("pids_max", "pids.events", "max"),
                                   ("throttled", "cpu.stat", "nr_throttled")):
            _require(field in values[section], "counter_missing")
            row["counter_max"][key] = max(row["counter_max"][key], values[section][field])

    def _classify(self, row, members):
        if self.classify_member is None or (row["servers"] and row["original_runtime_seen"]):
            return
        servers = set(row["servers"])
        for member in set(members):
            try:
                value = self.classify_member(member)
                if value is None:
                    continue
                runtime = False
                if isinstance(value, dict):
                    _require(set(value) == {"server", "original_runtime_seen"}
                             and type(value["original_runtime_seen"]) is bool, "classifier_invalid")
                    runtime, value = value["original_runtime_seen"], value["server"]
                _require(value in ROLES, "classifier_invalid")
                servers.add(value)
                row["original_runtime_seen"] |= runtime
            except Exception:
                self._error("member_classification_failed", row)
        row["servers"] = sorted(servers)
        if len(servers) > 1:
            self._error("member_classification_ambiguous", row)

    def _gone(self, row):
        identity = (row["device"], row["inode"])
        state = self.resource.leaf_state(self.root / row["leaf"], identity)
        held = os.fstat(row["_fd"])
        _require((held.st_dev, held.st_ino) == identity, "leaf_replaced")
        if state != "gone":
            return False
        try:
            descriptor = os.open("cgroup.events", os.O_RDONLY | os.O_NOFOLLOW |
                                 os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=row["_fd"])
        except OSError as error:
            if error.errno in TEARDOWN:
                return True
            raise
        os.close(descriptor)
        return False

    def _settle(self, row, code=None):
        now = time.monotonic()
        if row["_shutdown"] is None:
            _require(code in TEARDOWN, "teardown_invalid")
            row["_shutdown"] = self.resource.ShutdownRead(code, now)
        pending = row["_shutdown"]
        state = pending.advance(self._gone(row), time.monotonic())
        row["shutdown_read"] = pending.metadata()
        if state == "resolved":
            row["removed"], row["_removed_at"] = True, time.monotonic()
        elif state == "failed":
            self._error("teardown_unverified", row)

    def _sample(self, row):
        if row["removed"]:
            _require(self._gone(row), "leaf_reappeared")
            return
        if row["_shutdown"] is not None:
            self._settle(row)
            return
        if self.resource.leaf_state(self.root / row["leaf"],
                                    (row["device"], row["inode"])) == "gone":
            self._settle(row, errno.ENOENT)
            return
        try:
            values, members = self._counters(row)
            self._retain_counters(row, values)
            self._classify(row, members)
            startup = self._project(values)
            row["startup_samples"] += 1
            row["last_counters"] = startup
            try:
                full = self.resource.kernel_values(Path(f"/proc/self/fd/{row['_fd']}"))
            except ValueError:
                limits = [self._read(row["_fd"], name).strip()
                          for name in ("memory.max", "pids.max", "cpu.max")]
                _require(not members and row["samples"] == 0
                         and any(value.split()[0] == "max" for value in limits if value),
                         "kernel_values_invalid")
                return
            full = self._project(full)
            row["first"] = row["first"] if row["first"] is not None else full
            row["last"], row["samples"] = full, row["samples"] + 1
        except OSError as error:
            if error.errno in TEARDOWN:
                self._settle(row, error.errno)
            else:
                self._error("control_read_failed", row)

    def _poll(self):
        self._check_root()
        self._discover()
        for row in self._rows.values():
            try:
                self._sample(row)
            except (OSError, ValueError, TypeError, KeyError, IndexError):
                self._error("leaf_observation_failed", row)

    def _run(self):
        while not self._stop.is_set():
            with self._lock:
                try:
                    self._poll()
                except (OSError, RuntimeError, ValueError, TypeError, KeyError):
                    self._error("root_inventory_observation_failed")
            self._stop.wait(0.002)

    def _project_row(self, row, final=False):
        value = {key: copy.deepcopy(item) for key, item in row.items() if not key.startswith("_")}
        incomplete = []
        if final and self.classify_member is not None and len(row["servers"]) != 1:
            incomplete.append("classification_missing")
        if final and self.classify_member is not None and not row["original_runtime_seen"]:
            incomplete.append("original_runtime_not_observed")
        if final and not row["removed"]:
            incomplete.append("owned_leaf_removal_unverified")
        value["incomplete_reasons"] = incomplete
        value["observer_errors"] = list(self._errors)
        value["leaf_duration_millis"] = int(((row["_removed_at"] or time.monotonic())
                                             - row["_seen"]) * 1_000)
        value["status"] = ("failed" if value["errors"] or self._errors else
                           "incomplete" if incomplete else "removed" if value["removed"] else "observing")
        return value

    def snapshot(self):
        """Return a private, detached copy; it contains no process metadata."""
        with self._lock:
            rows = self._final if self._final is not None else [
                self._project_row(row) for row in self._rows.values()]
            return {"format": FORMAT, "status": "failed" if self._errors or any(
                row["status"] == "failed" for row in rows) else "incomplete" if any(
                row["status"] == "incomplete" for row in rows) else "closed" if self._closed else "observing",
                "root_identity": {"device": self._root_identity[0], "inode": self._root_identity[1]},
                "errors": list(self._errors), "rows": copy.deepcopy(rows)}

    def finish(self):
        """Stop sampling and close pins. No fallback cleanup can count as success."""
        self._stop.set()
        self._thread.join(timeout=3)
        with self._lock:
            if self._final is not None:
                return copy.deepcopy(self._final)
            if self._thread.is_alive():
                self._error("observer_thread_unstopped")
            else:
                try:
                    self._poll()
                except (OSError, RuntimeError, ValueError, TypeError, KeyError):
                    self._error("root_inventory_observation_failed")
                # Every existing quarantine began with its own accepted 250 ms
                # deadline. Never restart it or accept samples after uncertainty.
                while any(row["_shutdown"] is not None and
                          row["_shutdown"].status == "pending" for row in self._rows.values()):
                    try:
                        self._check_root()
                    except (OSError, RuntimeError, ValueError):
                        self._error("root_inventory_observation_failed")
                    for row in self._rows.values():
                        if row["_shutdown"] is not None and row["_shutdown"].status == "pending":
                            try:
                                self._settle(row)
                            except (OSError, ValueError, TypeError, KeyError):
                                row["_shutdown"].reject(time.monotonic())
                                row["shutdown_read"] = row["_shutdown"].metadata()
                                self._error("teardown_unverified", row)
                    time.sleep(0.002)
                for row in self._rows.values():
                    os.close(row["_fd"])
                os.close(self._root_fd)
                self._root_fd = None
            self._closed = not self._thread.is_alive()
            self._final = [self._project_row(row, final=True) for row in self._rows.values()]
            return copy.deepcopy(self._final)
