"""Read-only capacity observations for the three Linux preparation commands."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import ctypes
from dataclasses import dataclass
import errno
import os
from pathlib import Path
import platform
import json
import re
import stat

FORMAT = "sw-pilot-capacity/1"
GIB = 1024 ** 3
MIB = 1024 ** 2
MAX_BYTES = 2 ** 63 - 1
_active = ContextVar("pilot_capacity_guard", default=None)


@dataclass(frozen=True)
class Demand:
    role: str
    path: Path
    declared_bytes: int | None


def record(status, reason, **fields):
    return {"format": FORMAT, "status": status, "reason": reason,
            "admitted": status == "sufficient", "space_reserved": False, **fields}


class Refusal(Exception):
    def __init__(self, report):
        self.report = report
        super().__init__(report["reason"])


def amount(value, *, unknown=False):
    if unknown and value is None:
        return
    if type(value) is not int or not 0 <= value <= MAX_BYTES:
        raise Refusal(record("refused", "invalid_allowance"))


def summarize(demands, observations, reserve_bytes):
    amount(reserve_bytes)
    if not 1 <= len(demands) <= 16 or len(demands) != len(observations):
        raise Refusal(record("refused", "invalid_allowance"))
    groups = {}
    unknown = None
    for demand, observation in zip(demands, observations):
        amount(demand.declared_bytes, unknown=True)
        if demand.declared_bytes is None:
            unknown = "unknown_allowance"
        available = observation.get("available_bytes")
        if type(available) is not int or not 0 <= available <= MAX_BYTES:
            unknown = "unknown_capacity"
            available = None
        if observation.get("quota") != "disabled":
            unknown = "unknown_quota"
        if type(observation.get("available_inodes")) is not int:
            unknown = "unknown_capacity"
        key = observation.get("filesystem_id")
        if key is None:
            unknown = "unknown_capacity"
            key = "unknown:" + demand.role
        group = groups.setdefault(str(key), {"filesystem_id": str(key), "roles": [],
            "declared_bytes": 0, "reserve_bytes": reserve_bytes,
            "available_bytes": available, "quota": observation.get("quota", "unknown"),
            "filesystem_type": observation.get("filesystem_type", "unknown")})
        group["roles"].append(demand.role)
        if observation.get("quota") != "disabled":
            group["quota"] = observation.get("quota", "unknown")
        if group["available_bytes"] is None or available is None:
            group["available_bytes"] = None
        else:
            group["available_bytes"] = min(group["available_bytes"], available)
        group["declared_bytes"] += demand.declared_bytes or 0
        amount(group["declared_bytes"] + reserve_bytes)
        group["required_bytes"] = group["declared_bytes"] + reserve_bytes
        if observation.get("read_only"):
            return record("refused", "read_only_filesystem")
        if observation.get("available_inodes") == 0:
            return record("insufficient", "no_free_inodes")
    filesystems = list(groups.values())
    if any(g["available_bytes"] is not None and g["available_bytes"] < g["required_bytes"]
           for g in filesystems):
        return record("insufficient", "low_space", filesystems=filesystems)
    if unknown:
        return record("unknown", unknown, filesystems=filesystems)
    return record("sufficient", "declared_budget_available", filesystems=filesystems)


def open_destination(path):
    text = str(path)
    if (not path.is_absolute() or len(text.encode()) > 4096 or len(path.parts) > 64
            or ".." in path.parts or any(ord(c) < 32 for c in text)):
        raise Refusal(record("refused", "unsafe_destination"))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    identities = []
    try:
        prefix = Path("/")
        for part in (None, *path.parts[1:]):
            if part is not None:
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                    | os.O_CLOEXEC, dir_fd=fd)
                except FileNotFoundError:
                    break
                os.close(fd)
                fd = child
                prefix /= part
            info = os.fstat(fd)
            shared_temp = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if (info.st_uid not in (0, os.geteuid())
                    or (info.st_mode & 0o022 and not shared_temp)):
                raise Refusal(record("refused", "unsafe_destination"))
            identities.append((str(prefix), info.st_dev, info.st_ino))
        return fd, identities
    except BaseException:
        os.close(fd)
        raise


def filesystem_type(fd):
    with open(f"/proc/self/fdinfo/{fd}", "rb") as stream:
        info = stream.read(8193)
    if len(info) > 8192:
        return "unknown"
    mount = next((line.split()[1] for line in info.splitlines() if line.startswith(b"mnt_id:")), None)
    with open("/proc/self/mountinfo", "rb") as stream:
        content = stream.read(2 * MIB + 1)
    if len(content) > 2 * MIB:
        return "unknown"
    for line in content.splitlines():
        before, delimiter, after = line.partition(b" - ")
        fields = before.split()
        if delimiter and fields and fields[0] == mount:
            return after.split()[0].decode("ascii", errors="replace")
    return "unknown"


def quota_state(fd, kind):
    if platform.machine() != "x86_64" or kind not in ("ext4", "tmpfs"):
        return "unknown"
    libc = ctypes.CDLL(None, use_errno=True)
    for quota_type in (0, 1, 2):
        buffer = ctypes.create_string_buffer(24)
        ctypes.set_errno(0)
        result = libc.syscall(ctypes.c_long(443), ctypes.c_int(fd),
            ctypes.c_uint((0x800005 << 8) | quota_type), ctypes.c_int(0),
            ctypes.cast(buffer, ctypes.c_void_p))
        if result == 0:
            return "enabled"
        if ctypes.get_errno() != errno.ESRCH:
            return "unknown"
    return "disabled"


def observe(fd):
    info = os.fstat(fd)
    space = os.fstatvfs(fd)
    kind = filesystem_type(fd)
    return {"filesystem_id": str(info.st_dev), "filesystem_type": kind,
            "available_bytes": space.f_bavail * space.f_frsize,
            "available_inodes": space.f_favail, "read_only": bool(space.f_flag & os.ST_RDONLY),
            "quota": quota_state(fd, kind)}


def inspect(demands, reserve_bytes, previous=None):
    amount(reserve_bytes)
    if not 1 <= len(demands) <= 16:
        raise Refusal(record("refused", "invalid_allowance"))
    for demand in demands:
        amount(demand.declared_bytes, unknown=True)
        if (not isinstance(demand.role, str) or len(demand.role) > 64
                or len(str(demand.path).encode()) > 4096):
            raise Refusal(record("refused", "unsafe_destination"))
    if platform.system() != "Linux":
        return record("unknown", "unsupported_platform"), []
    identities, observations = [], []
    try:
        for index, demand in enumerate(demands):
            fd, current = open_destination(demand.path)
            try:
                if previous is not None:
                    old = previous[index]
                    if current[:len(old)] != old or current[-1][1] != old[-1][1]:
                        raise Refusal(record("refused", "destination_changed"))
                if not os.access(".", os.W_OK | os.X_OK, dir_fd=fd, effective_ids=True):
                    raise Refusal(record("refused", "destination_not_writable"))
                identities.append(current)
                observations.append(observe(fd))
            finally:
                os.close(fd)
        return summarize(demands, observations, reserve_bytes), identities
    except Refusal as error:
        return error.report, identities
    except OSError as error:
        unsafe = error.errno in (errno.ELOOP, errno.ENOTDIR)
        return record("refused" if unsafe else "unknown",
                      "unsafe_destination" if unsafe else "inaccessible_filesystem"), identities


def plan(demands, reserve_bytes):
    report, _ = inspect(demands, reserve_bytes)
    return report


class Guard:
    def __init__(self, demands, reserve_bytes):
        self.demands = list(demands)
        self.reserve_bytes = reserve_bytes

    def __enter__(self):
        report, self.identities = inspect(self.demands, self.reserve_bytes)
        if not report["admitted"]:
            raise Refusal({**report, "phase": "before_preparation", "work": "not_started"})
        self.bound = []
        return self

    def bind(self, path):
        self.recheck("before_generation_binding")
        report, identities = inspect([Demand("generation_work", path, 0)], self.reserve_bytes)
        if not report["admitted"]:
            raise Refusal({**report, "phase": "generation_binding", "work": "may_have_started"})
        if (path.parent != self.demands[0].path or identities[0][-1][0] != str(path)
                or identities[0][-1][1] != self.identities[0][-1][1]):
            raise Refusal(record("refused", "destination_changed", phase="generation_binding",
                                 work="may_have_started"))
        self.bound.append((path, identities[0]))

    def recheck(self, phase):
        remaining = [Demand(item.role, item.path, 0) for item in self.demands]
        report, identities = inspect(remaining, self.reserve_bytes, self.identities)
        if not report["admitted"]:
            raise Refusal({**report, "phase": phase, "work": "may_have_started"})
        self.identities = identities
        try:
            for path, previous in self.bound:
                fd, current = open_destination(path)
                try:
                    if current != previous:
                        raise Refusal(record("refused", "destination_changed"))
                finally:
                    os.close(fd)
        except (OSError, Refusal):
            raise Refusal(record("refused", "destination_changed", phase=phase,
                                 work="may_have_started")) from None

    def __exit__(self, *exc):
        return False


def bind(path):
    guard = _active.get()
    if guard is not None:
        guard.bind(path)


def recheck(phase):
    guard = _active.get()
    if guard is not None:
        guard.recheck(phase)


def add_arguments(parser):
    parser.add_argument("--capacity-plan", action="store_true", help="observe capacity without running tools or creating output")
    parser.add_argument("--guard-capacity", action="store_true", help="refuse preparation unless the declared budget is available")
    for name, default in (("build", None), ("cache", None), ("temp", None), ("reserve", GIB)):
        parser.add_argument(f"--capacity-{name}-bytes", type=int, default=default)


def selected_inventory(output):
    if platform.system() != "Linux":
        return {"state": "not_observed", "verified": False}
    try:
        fd, identities = open_destination(output)
        try:
            if identities[-1][0] != str(output):
                return {"state": "absent", "verified": False}
            marker = os.open("current.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = os.fstat(marker)
                if (not stat.S_ISREG(info.st_mode) or info.st_size > 65536 or info.st_nlink != 1
                        or info.st_uid != os.geteuid()):
                    return {"state": "untrusted", "verified": False}
                value = json.loads(os.read(marker, 65537))
                generation = value.get("generation") if isinstance(value, dict) else None
                if not isinstance(generation, str) or re.fullmatch("[0-9a-f]{32}", generation) is None:
                    return {"state": "invalid", "verified": False}
                return {"state": "selected_marker_observed", "generation": generation,
                        "marker_bytes": info.st_size, "verified": False,
                        "retained_generation_bytes": None}
            finally:
                os.close(marker)
        finally:
            os.close(fd)
    except FileNotFoundError:
        return {"state": "absent", "verified": False}
    except (OSError, ValueError, RecursionError, Refusal):
        return {"state": "unreadable_or_untrusted", "verified": False}


def archive_inventory(args):
    result = []
    for name in ("git_archive", "bwrap_archive", "node_archive", "python_archive"):
        path = getattr(args, name, None)
        if path is None:
            continue
        item = {"role": name, "bytes": None, "pin_verified": False}
        if platform.system() == "Linux":
            try:
                parent, identities = open_destination(path.parent)
                try:
                    if identities[-1][0] == str(path.parent):
                        info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                        if stat.S_ISREG(info.st_mode):
                            item.update(bytes=info.st_size, filesystem_id=str(info.st_dev))
                finally:
                    os.close(parent)
            except (OSError, Refusal):
                pass
        result.append(item)
    return result


def requirements(stage, args):
    if args.output is None:
        raise Refusal(record("refused", "output_required"))
    for name in ("build", "cache", "temp", "reserve"):
        amount(getattr(args, f"capacity_{name}_bytes"), unknown=name != "reserve")
    if len(str(args.output).encode()) > 4096:
        raise Refusal(record("refused", "unsafe_destination"))
    build = args.capacity_build_bytes
    if stage == "source" and build is None:
        build = 8 * GIB
    archive_cap = {"native": 80 * MIB, "source": 0, "assets": 256 * MIB}[stage]
    extraction_cap = {"native": GIB, "source": 0, "assets": 2 * GIB}[stage]
    final_copy_cap = 512 * MIB if stage == "source" else 0
    total = None if build is None else build + archive_cap + extraction_cap + final_copy_cap
    demands = [Demand("generation", args.output / "generations", total)]
    if stage == "assets":
        cache = args.npm_cache or args.output / "generations"
        demands.append(Demand("npm_cache", cache, args.capacity_cache_bytes))
        demands.append(Demand("npm_temp", Path("/tmp"), args.capacity_temp_bytes))
        pip_temp = os.environ.get("TMPDIR")
        if pip_temp:
            demands.append(Demand("pip_temp", Path(pip_temp), args.capacity_temp_bytes))
    inventory = {"stage": stage, "known_pinned_archive_bytes": None,
        "archive_upper_bound_bytes": archive_cap, "extraction_upper_bound_bytes": extraction_cap,
        "final_copy_upper_bound_bytes": final_copy_cap,
        "cargo_cache_included_in_build_allowance": stage == "source",
        "build_allowance_bytes": build, "build_allowance_kind": "existing_limit" if stage == "source"
            and args.capacity_build_bytes is None else "caller_declared",
        "reuse_credit_bytes": 0, "reuse_verification": "existing_preparer_only",
        "selected_generation": selected_inventory(args.output),
        "supplied_archives": archive_inventory(args),
        "cache_inventory": "not_walked", "wheelhouse": "read_only_input" if stage == "assets" else None,
        "demands": [{"role": item.role, "path": str(item.path),
                     "declared_bytes": item.declared_bytes} for item in demands]}
    return demands, inventory


def cli_plan(stage, args):
    try:
        demands, inventory = requirements(stage, args)
        return {**plan(demands, args.capacity_reserve_bytes), "inventory": inventory}
    except Refusal as error:
        return error.report


@contextmanager
def checked(stage, args):
    if not args.guard_capacity:
        yield
        return
    demands, _ = requirements(stage, args)
    with Guard(demands, args.capacity_reserve_bytes) as guard:
        token = _active.set(guard)
        try:
            yield
        finally:
            _active.reset(token)
