#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Local, source-aware PR feedback. Never posts or satisfies a GitHub check.

Plan reads committed Git objects only. Run checks an isolated exact-head worktree,
keeps the contributor's existing dirty files untouched, and refuses source drift.
Neither mode is trusted candidate admission or native qualification.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import threading
import tempfile
import time
import tomllib
import types

sys.dont_write_bytecode = True  # Plan mode must not create import cache files.

FORMAT = "sw-local-pr-verification/1"
MAX_GIT_OUTPUT = 2 * 1024 * 1024
MAX_DIRTY_BYTES = 16 * 1024 * 1024
MAX_DIRTY_FILES = 256
MAX_LOG = 64 * 1024
MAX_EXCERPT = 2048
MAX_PATHS = 4096
MAX_PYTHON_FILE = 2 * 1024 * 1024
RUST_PIN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
GIT_EXECUTABLE = shutil.which("git")
CHECK_COST = {
    "patch_whitespace": 3, "docs_unit": 15, "docs_links": 15,
    "python_syntax": 5, "ci_contracts": 40, "rust_fmt": 20,
    "rust_clippy": 120, "rust_test_compile": 120,
}
CHECK_ORDER = tuple(CHECK_COST)


class Refusal(Exception):
    """Finite local refusal; never interpolate subprocess output into it."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def git(root, *args, timeout=10):
    if not GIT_EXECUTABLE:
        raise Refusal("git_unavailable")
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    try:
        process = subprocess.Popen([GIT_EXECUTABLE, "-C", str(root), *args],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   stdin=subprocess.DEVNULL, env=env,
                                   start_new_session=os.name != "nt",
                                   creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
    except OSError:
        raise Refusal("git_unavailable") from None
    output = bytearray()
    overflow = threading.Event()

    def collect():
        try:
            while chunk := process.stdout.read(65536):
                room = MAX_GIT_OUTPUT - len(output)
                output.extend(chunk[:room])
                if len(chunk) > room:
                    overflow.set()
                    break
        finally:
            process.stdout.close()

    reader = threading.Thread(target=collect, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout
    try:
        while process.poll() is None and not overflow.is_set() and time.monotonic() < deadline:
            time.sleep(.02)
    except KeyboardInterrupt:
        _kill_tree(process)
        raise
    if process.poll() is None:
        _kill_tree(process)
    reader.join(timeout=1)
    if reader.is_alive():
        _kill_tree(process)
        reader.join(timeout=1)
        raise Refusal("git_descendant_output_open")
    if overflow.is_set():
        raise Refusal("git_output_limit")
    if time.monotonic() >= deadline and process.returncode != 0:
        raise Refusal("git_timeout")
    if process.returncode:
        raise Refusal("git_source_invalid")
    return bytes(output)


def resolve(root, ref):
    if not ref or len(ref) > 256 or "\x00" in ref:
        raise Refusal("ref_invalid")
    value = git(root, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", value):
        raise Refusal("ref_invalid")
    return value


def digest_file(path, limit=None):
    value = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            size += len(block)
            if limit is not None and size > limit:
                raise Refusal("source_snapshot_limit")
            value.update(block)
    return value.hexdigest(), size


def source_snapshot(root, base_ref, head_ref):
    """Include committed ref movement and bounded pre-existing dirty contents."""
    snapshot = hashlib.sha256()
    snapshot.update(resolve(root, base_ref).encode())
    snapshot.update(resolve(root, head_ref).encode())
    snapshot.update(git(root, "rev-parse", "HEAD"))
    status = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    snapshot.update(status)
    paths = [part.decode("utf-8", "surrogateescape") for part in
             git(root, "ls-files", "-m", "-o", "--exclude-standard", "-z").split(b"\0") if part]
    if len(paths) > MAX_DIRTY_FILES:
        raise Refusal("source_snapshot_limit")
    total = 0
    for name in sorted(set(paths)):
        path = root / name
        try:
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raw = os.readlink(path).encode("utf-8", "surrogateescape")
                total += len(raw)
                snapshot.update(hashlib.sha256(raw).digest())
            elif stat.S_ISREG(info.st_mode):
                identity, size = digest_file(path, MAX_DIRTY_BYTES - total)
                total += size
                snapshot.update(identity.encode())
            else:
                raise Refusal("source_snapshot_unsupported")
        except FileNotFoundError:
            snapshot.update(b"deleted")
        except OSError:
            raise Refusal("source_snapshot_changed") from None
        snapshot.update(name.encode("utf-8", "surrogateescape"))
    snapshot.update(git(root, "diff", "--cached", "--binary", "--no-ext-diff"))
    return snapshot.hexdigest(), bool(status)


def toolchain(root, head):
    def blob(name):
        try:
            return git(root, "show", f"{head}:{name}")
        except Refusal:
            raise Refusal("source_contract_missing") from None
    raw = blob("rust-toolchain.toml")
    try:
        pin = tomllib.loads(raw.decode("utf-8"))["toolchain"]["channel"]
    except (UnicodeError, ValueError, KeyError, TypeError):
        raise Refusal("toolchain_invalid") from None
    if type(pin) is not str or not RUST_PIN.fullmatch(pin):
        raise Refusal("toolchain_not_exact")
    return {"rust_channel": pin, "rust_toolchain_sha256": hashlib.sha256(raw).hexdigest(),
            "cargo_lock_sha256": hashlib.sha256(blob("Cargo.lock")).hexdigest()}


def base_impact(root, base, paths):
    """Use the explicit base's accepted selector, never dirty or head code."""
    names = ("sou91_ruleset_patch", "ci_activation", "ci_impact")
    previous = {name: sys.modules.get(name) for name in names}
    identities = {}
    try:
        for name in names:
            try:
                raw = git(root, "show", f"{base}:scripts/{name}.py")
            except Refusal:
                raise Refusal("selector_base_missing") from None
            identities[name] = hashlib.sha256(raw).hexdigest()
            module = types.ModuleType(name)
            module.__file__ = f"{base}:scripts/{name}.py"
            sys.modules[name] = module
            try:
                exec(compile(raw, module.__file__, "exec"), module.__dict__)
            except Exception:
                raise Refusal("selector_base_invalid") from None
        result = sys.modules["ci_impact"].plan(paths)
        if result.get("schema") != "sou91-ci-plan/1":
            raise Refusal("selector_base_invalid")
        return result, identities
    finally:
        for name, old in previous.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


def inspect(root, base_ref, head_ref):
    root = Path(root).resolve()
    if not (root / ".git").exists():
        raise Refusal("repository_required")
    base, head = resolve(root, base_ref), resolve(root, head_ref)
    try:
        git(root, "merge-base", "--is-ancestor", base, head)
    except Refusal:
        raise Refusal("base_not_ancestor") from None
    raw = git(root, "diff", "--name-only", "--no-renames", "-z", base, head)
    paths = [entry.decode("utf-8", "surrogateescape") for entry in raw.split(b"\0") if entry]
    if len(paths) > MAX_PATHS:
        raise Refusal("path_limit")
    impact, selector_contract = base_impact(root, base, paths)
    full = impact["mode"] == "full"
    rust = full or any(path.endswith(".rs") or path in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")
                       for path in paths)
    tree = git(root, "ls-tree", "-r", "-z", head)
    head_files = {entry.split(b"\t", 1)[1].decode("utf-8", "surrogateescape")
                  for entry in tree.split(b"\0") if b"\t" in entry}
    python = [path for path in paths if path.endswith(".py") and path in head_files]
    ci_contracts = full or any(path.startswith("scripts/ci_") or path.startswith(".github/") for path in paths)
    selected = {"patch_whitespace": True, "docs_unit": True, "docs_links": True,
                "python_syntax": bool(python), "ci_contracts": ci_contracts,
                "rust_fmt": rust, "rust_clippy": rust, "rust_test_compile": rust}
    remote = [{"workflow": name, "jobs": jobs, "status": "not-run"}
              for name, jobs in impact["workflows"].items() if jobs]
    return {"format": FORMAT, "authority": "local-feedback-only", "base": base, "head": head,
            "base_ref": base_ref, "head_ref": head_ref, "paths": paths,
            "impact_mode": impact["mode"], "impact_schema": impact["schema"],
            "executables": {"git": GIT_EXECUTABLE, "python": sys.executable},
            "python_version": ".".join(map(str, sys.version_info[:3])),
            "source_contract": toolchain(root, head),
            "selector_base_sha256": selector_contract,
            "local_checks": [{"name": name, "selected": selected[name],
                              "estimated_cost_seconds": CHECK_COST[name],
                              "platform": ("Windows job or Linux subreaper/pidfd" if name not in
                                           ("rust_clippy", "rust_test_compile") else
                                           "Windows job or Linux subreaper/pidfd; pinned Rust and offline dependency cache")}
                             for name in CHECK_ORDER],
            "remote_required": {"status": "not-run", "workflows": remote,
                                "codeql": impact["codeql"],
                                "native_provider_idp": "not-run; requires selected remote environment"},
            "python_paths": python, "full_qualification": False,
            "github_status_posted": False, "trusted_admission": False}


def rust_tools(pin):
    rustup = shutil.which("rustup")
    if not rustup:
        return {}
    env = dict(os.environ, RUSTUP_AUTO_INSTALL="0", RUSTUP_TOOLCHAIN=pin)
    paths = {}
    for tool in ("rustc", "cargo", "rustfmt", "clippy-driver"):
        try:
            result = subprocess.run([rustup, "which", tool, "--toolchain", pin],
                                    capture_output=True, timeout=5, env=env, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode or len(result.stdout) > 4096:
            continue
        path = Path(result.stdout.decode("utf-8", "replace").strip())
        if not path.is_file():
            continue
        paths[tool] = str(path)
    if "rustc" not in paths:
        return {}
    try:
        version = subprocess.run([paths["rustc"], "--version"], capture_output=True,
                                 timeout=5, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if version.returncode or not version.stdout.startswith(("rustc " + pin + " ").encode()):
        return {}
    paths["rustc_version"] = version.stdout.decode("utf-8", "replace").strip()[:128]
    return paths


def commands(check, plan, scratch, tools):
    python = sys.executable
    if check == "patch_whitespace":
        return [GIT_EXECUTABLE, "diff", "--check", plan["base"], plan["head"]]
    if check == "docs_unit":
        return [python, "-B", "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_check_docs.py", "-q"]
    if check == "docs_links":
        return [python, "-B", "scripts/check_docs.py"]
    if check == "python_syntax":
        code = "import ast,sys; [ast.parse(open(p,encoding='utf-8').read(),filename=p) for p in sys.argv[1:]]"
        return [python, "-B", "-c", code, *plan["python_paths"]]
    if check == "ci_contracts":
        return [python, "-B", "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_ci_*.py", "-q"]
    cargo = tools["cargo"]
    if check == "rust_fmt":
        return [cargo, "fmt", "--all", "--", "--check"]
    if check == "rust_clippy":
        return [cargo, "clippy", "--locked", "--offline", "--workspace", "--all-targets", "-j", "2", "--", "-D", "warnings"]
    if check == "rust_test_compile":
        return [cargo, "test", "--locked", "--offline", "--workspace", "--no-run", "-j", "2"]
    raise Refusal("check_unknown")


def _kill_tree(process):
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            if process.poll() is None:
                process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _owned_group_present(process):
    """The fresh POSIX session remains addressable while any member remains."""
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    return True


class _WindowsJob:
    """Gate a checker until it is inside an owned Windows job object."""

    def __init__(self):
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        self.kernel.CreateJobObjectW.restype = ctypes.c_void_p
        self.kernel.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self.kernel.AssignProcessToJobObject.restype = ctypes.c_int
        self.kernel.QueryInformationJobObject.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                                         ctypes.c_void_p, ctypes.c_uint32,
                                                         ctypes.c_void_p]
        self.kernel.QueryInformationJobObject.restype = ctypes.c_int
        self.kernel.TerminateJobObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.kernel.TerminateJobObject.restype = ctypes.c_int
        self.kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel.CloseHandle.restype = ctypes.c_int
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError("job object unavailable")

    def assign(self, process):
        if not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise OSError("job assignment unavailable")

    def active(self):
        class Accounting(ctypes.Structure):
            _fields_ = [("times", ctypes.c_longlong * 4),
                        ("total_page_faults", ctypes.c_uint32),
                        ("total_processes", ctypes.c_uint32),
                        ("active_processes", ctypes.c_uint32),
                        ("terminated_processes", ctypes.c_uint32)]
        info = Accounting()
        if not self.kernel.QueryInformationJobObject(self.handle, 1, ctypes.byref(info),
                                                     ctypes.sizeof(info), None):
            raise OSError("job accounting unavailable")
        return info.active_processes

    def terminate(self):
        if not self.kernel.TerminateJobObject(self.handle, 1):
            raise OSError("job termination unavailable")

    def close(self):
        self.kernel.CloseHandle(self.handle)


def _finish_owned_group(process, job=None):
    """Stop descendants even when the checker leader has already exited zero."""
    if os.name == "nt":
        try:
            had_members = job.active() > 0
            if had_members:
                job.terminate()
            process.wait(timeout=3)
            until = time.monotonic() + 1
            while job.active() and time.monotonic() < until:
                time.sleep(.02)
            return had_members, job.active() == 0
        except (OSError, subprocess.TimeoutExpired):
            _kill_tree(process)
            return False, False
    had_members = _owned_group_present(process)
    _kill_tree(process)
    until = time.monotonic() + 1
    while _owned_group_present(process) and time.monotonic() < until:
        time.sleep(.02)
    return had_members, not _owned_group_present(process)


def _supervise_linux(deadline, argv):
    """Isolate one checker under a child subreaper; stderr is private protocol."""
    def report(code, descendants, cleaned, reason, executed):
        sys.stderr.write(json.dumps({"exit_code": code, "descendants": descendants,
                                     "cleaned": cleaned, "reason": reason,
                                     "executed": executed}) + "\n")
        sys.stderr.flush()
        return 0 if cleaned else 2

    if (sys.platform != "linux" or not argv or not hasattr(os, "pidfd_open")
            or not hasattr(signal, "pidfd_send_signal")):
        return report(None, False, True, "containment_unavailable", False)
    children_file = Path(f"/proc/self/task/{os.getpid()}/children")
    try:
        children_file.read_bytes()
        descriptor = os.pidfd_open(os.getpid(), 0)
        os.close(descriptor)
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                              ctypes.c_ulong, ctypes.c_ulong]
        libc.prctl.restype = ctypes.c_int
        subreaper_ready = libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
    except (OSError, AttributeError):
        subreaper_ready = False
    if not subreaper_ready:
        return report(None, False, True, "containment_unavailable", False)
    try:
        checker = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                   stdout=None, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    except OSError:
        return report(None, False, True, "executable_unavailable", False)

    def children():
        raw = children_file.read_bytes()
        if len(raw) > 16384:
            raise OSError("child census limit")
        values = [int(value) for value in raw.split()]
        if len(values) > 1024:
            raise OSError("child census limit")
        return values

    reason = None
    while checker.poll() is None:
        if time.monotonic() >= deadline:
            reason = "deadline"
            break
        if select.select([sys.stdin.buffer], [], [], .05)[0] and not os.read(0, 1):
            reason = "cancelled"
            break

    descendants = False
    cleaned = False
    until = time.monotonic() + 2
    try:
        while time.monotonic() < until:
            owned = children()
            descendants |= any(pid != checker.pid for pid in owned)
            if not owned:
                cleaned = True
                break
            for pid in owned:
                try:
                    descriptor = os.pidfd_open(pid, 0)
                except ProcessLookupError:
                    continue
                try:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
                except ProcessLookupError:
                    pass
                finally:
                    os.close(descriptor)
            try:
                checker.wait(timeout=.02)
            except subprocess.TimeoutExpired:
                pass
            if checker.returncode is not None:
                while True:
                    try:
                        reaped, _ = os.waitpid(-1, os.WNOHANG)
                    except ChildProcessError:
                        break
                    if not reaped:
                        break
            time.sleep(.01)
        if not cleaned:
            cleaned = not children()
    except (OSError, ValueError):
        reason = "descendant_cleanup_unverified"
    return report(checker.returncode, descendants, cleaned, reason, True)


def run_one(argv, cwd, env, deadline):
    started = time.monotonic()
    job = None
    supervised = sys.platform == "linux"
    executed = False
    try:
        if os.name == "nt":
            # The wrapper waits for the gate before starting the real checker.
            # This removes the launch/assignment race and keeps all descendants
            # in the job even if the real checker exits before its child.
            wrapper = ("import subprocess,sys; sys.stdin.buffer.read(1); "
                       "p=subprocess.Popen(sys.argv[1:], stdin=subprocess.DEVNULL); "
                       "sys.exit(p.wait())")
            process = subprocess.Popen([sys.executable, "-B", "-c", wrapper, *argv],
                                       cwd=cwd, env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            try:
                job = _WindowsJob()
                job.assign(process)
                process.stdin.write(b"1")
                process.stdin.close()
            except OSError:
                _kill_tree(process)
                if job:
                    job.close()
                return "unavailable", "owned_job_unavailable", None, 0, "", 0, False
            executed = True
        elif supervised:
            process = subprocess.Popen([sys.executable, "-B", str(Path(__file__).resolve()),
                                        "_supervise", str(deadline), *argv],
                                       cwd=cwd, env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
        else:
            return "unavailable", "descendant_containment_unavailable", None, 0, "", 0, False
    except OSError:
        return "unavailable", "executable_unavailable", None, 0, "", 0, False
    output = bytearray()
    overflow = threading.Event()

    def collect():
        try:
            while chunk := process.stdout.read(4096):
                room = MAX_LOG - len(output)
                output.extend(chunk[:room])
                if len(chunk) > room:
                    overflow.set()
                    break
        finally:
            process.stdout.close()

    reader = threading.Thread(target=collect, daemon=True)
    reader.start()
    reason = None
    try:
        while process.poll() is None:
            if overflow.is_set():
                reason = "output_limit"
                break
            if time.monotonic() >= deadline:
                reason = "deadline"
                break
            time.sleep(.05)
    except KeyboardInterrupt:
        reason = "cancelled"
    if supervised and reason:
        process.stdin.close()  # EOF requests bounded descendant cleanup.
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            reason = "descendant_cleanup_unverified"
    # The Linux helper adopts children across setsid; the outer session and
    # Windows job still need independent completion checks.
    descendants, cleaned = _finish_owned_group(process, job)
    if job:
        job.close()
    exit_code = process.returncode
    if supervised:
        try:
            raw = process.stderr.read(4097)
            if len(raw) > 4096:
                raise ValueError("supervisor report limit")
            witness = json.loads(raw)
            if (type(witness) is not dict or type(witness.get("cleaned")) is not bool
                    or type(witness.get("descendants")) is not bool
                    or type(witness.get("executed")) is not bool
                    or (witness.get("exit_code") is not None
                        and type(witness["exit_code"]) is not int)):
                raise ValueError("supervisor report invalid")
            exit_code = witness["exit_code"]
            executed = witness["executed"]
            descendants |= witness["descendants"]
            cleaned &= witness["cleaned"]
            reason = reason or witness.get("reason")
        except (ValueError, OSError):
            cleaned = False
        finally:
            process.stdin.close()
            process.stderr.close()
    if not cleaned:
        reason = "descendant_cleanup_unverified"
    elif descendants and not reason:
        reason = "descendant_after_exit"
    reader.join(timeout=1)
    if reader.is_alive():
        _kill_tree(process)
        reader.join(timeout=1)
        reason = reason or "descendant_output_open"
    if overflow.is_set():
        reason = "output_limit"
    excerpt = bytes(output[-MAX_EXCERPT:]).decode("utf-8", "replace")
    duration = round(time.monotonic() - started, 3)
    if reason in ("containment_unavailable", "executable_unavailable") and exit_code is None and cleaned:
        return "unavailable", reason, None, len(output), excerpt, duration, False
    if reason:
        return "incomplete", reason, exit_code, len(output), excerpt, duration, executed
    return ("passed" if exit_code == 0 else "failed",
            "exit_zero" if exit_code == 0 else "exit_nonzero",
            exit_code, len(output), excerpt, duration, executed)


def availability(name, status, reason, excerpt):
    """An offline Cargo cache miss was executed but cannot qualify source."""
    if (name in ("rust_clippy", "rust_test_compile") and status == "failed"
            and "attempting to make an HTTP request, but --offline was specified" in excerpt):
        return "unavailable", "offline_dependency_unavailable"
    return status, reason


def _scratch_head_safe(root, head):
    raw = git(root, "ls-tree", "-r", "-z", head)
    if len(raw.split(b"\0")) > 20000:
        raise Refusal("tree_limit")
    for entry in raw.split(b"\0"):
        if entry and not entry.startswith((b"100644 ", b"100755 ")):
            raise Refusal("tree_entry_unsupported")


def run(root, base_ref, head_ref, *, step_seconds=120, total_seconds=600):
    if not 1 <= step_seconds <= 300 or not 1 <= total_seconds <= 900:
        raise Refusal("deadline_invalid")
    root = Path(root).resolve()
    planned = inspect(root, base_ref, head_ref)
    before, dirty = source_snapshot(root, base_ref, head_ref)
    if resolve(root, base_ref) != planned["base"] or resolve(root, head_ref) != planned["head"]:
        raise Refusal("source_changed_before_check")
    _scratch_head_safe(root, planned["head"])
    rust = rust_tools(planned["source_contract"]["rust_channel"])
    started = time.monotonic()
    results = []
    scratch = Path(tempfile.mkdtemp(prefix="sou206-local-"))
    os.chmod(scratch, 0o700)
    checkout = scratch / "source"
    attached = False
    cancelled = False
    refusal = None
    cleanup_failed = False
    try:
        git(root, "worktree", "add", "--detach", str(checkout), planned["head"], timeout=30)
        attached = True
        if git(checkout, "rev-parse", "HEAD").decode().strip() != planned["head"]:
            raise Refusal("scratch_source_changed")
        scratch_before = git(checkout, "status", "--porcelain=v1", "-z", "--untracked-files=all")
        environment = {"PATH": os.environ.get("PATH", ""),
                       "RUSTUP_TOOLCHAIN": planned["source_contract"]["rust_channel"],
                       "RUSTUP_AUTO_INSTALL": "0", "CARGO_NET_OFFLINE": "true",
                       "CARGO_TARGET_DIR": str(scratch / "target"), "CARGO_BUILD_JOBS": "2",
                       "PIP_NO_INDEX": "1", "PYTHONDONTWRITEBYTECODE": "1", "CI": "1"}
        for key in ("HOME", "USERPROFILE", "RUSTUP_HOME", "CARGO_HOME"):
            if os.environ.get(key):
                environment[key] = os.environ[key]
        finish_by = started + total_seconds
        for index, item in enumerate(planned["local_checks"]):
            name = item["name"]
            if not item["selected"]:
                results.append({"name": name, "status": "skipped", "executed": False,
                                "reason": "not_selected", "duration_seconds": 0})
                continue
            if cancelled or time.monotonic() >= finish_by:
                results.append({"name": name, "status": "not-run", "executed": False,
                                "reason": "prior_incomplete_or_deadline", "duration_seconds": 0})
                continue
            required_rust = {"rust_fmt": ("cargo", "rustfmt"),
                             "rust_clippy": ("cargo", "clippy-driver"),
                             "rust_test_compile": ("cargo",)}.get(name, ())
            if required_rust and any(tool not in rust for tool in required_rust):
                results.append({"name": name, "status": "unavailable", "executed": False,
                                "reason": "pinned_toolchain_missing", "duration_seconds": 0})
                continue
            argv = commands(name, planned, checkout, rust)
            required = {"docs_unit": "scripts/tests/test_check_docs.py",
                        "docs_links": "scripts/check_docs.py",
                        "ci_contracts": "scripts/tests/test_ci_impact.py"}.get(name)
            if required and not (checkout / required).is_file():
                results.append({"name": name, "status": "unavailable", "executed": False,
                                "reason": "checker_missing", "duration_seconds": 0})
                continue
            if name == "python_syntax" and any(
                    not (checkout / path).is_file() or (checkout / path).stat().st_size > MAX_PYTHON_FILE
                    for path in planned["python_paths"]):
                results.append({"name": name, "status": "unavailable", "executed": False,
                                "reason": "python_input_limit", "duration_seconds": 0})
                continue
            status, reason, code, size, excerpt, duration, executed = run_one(
                argv, checkout, environment, min(time.monotonic() + step_seconds, finish_by))
            status, reason = availability(name, status, reason, excerpt)
            results.append({"name": name, "status": status, "executed": executed,
                            "reason": reason, "command": argv, "exit_code": code,
                            "output_bytes_retained": size, "output_excerpt": excerpt,
                            "duration_seconds": duration})
            if reason == "descendant_cleanup_unverified":
                raise Refusal(reason)
            if status == "incomplete":
                cancelled = True
        scratch_after = git(checkout, "status", "--porcelain=v1", "-z", "--untracked-files=all")
        if scratch_after != scratch_before or git(checkout, "diff", "--binary", "--no-ext-diff"):
            raise Refusal("scratch_source_changed")
        after, _ = source_snapshot(root, base_ref, head_ref)
        if before != after:
            raise Refusal("source_changed_during_check")
    except Refusal as error:
        refusal = error.code
    except KeyboardInterrupt:
        refusal = "cancelled"
    finally:
        unverified_descendant = any(item.get("reason") == "descendant_cleanup_unverified"
                                    for item in results)
        if unverified_descendant:
            # A still-running checker may hold this checkout. Keep its private
            # scratch intact for explicit local recovery instead of deleting
            # files beneath an unverified process.
            cleanup_failed = True
        else:
            if attached:
                try:
                    git(root, "worktree", "remove", "--force", str(checkout), timeout=20)
                except Refusal:
                    cleanup_failed = True
            # The directory was made by this invocation and is required to remain
            # under the system temporary root before recursive cleanup.
            if scratch.parent.resolve() == Path(tempfile.gettempdir()).resolve() and not scratch.is_symlink():
                try:
                    shutil.rmtree(scratch)
                except OSError:
                    cleanup_failed = True
            else:
                cleanup_failed = True
    if cleanup_failed:
        refusal = ("descendant_cleanup_unverified" if unverified_descendant else
                   "cleanup_incomplete")
    for item in planned["local_checks"][len(results):]:
        results.append({"name": item["name"], "status": "not-run", "executed": False,
                        "reason": "source_refused", "duration_seconds": 0})
    counts = {status: sum(item["status"] == status for item in results)
              for status in ("passed", "failed", "skipped", "unavailable", "not-run", "incomplete")}
    planned.update({"mode": "run", "dirty_worktree_excluded": dirty,
                    "resolved_rust_tools": rust,
                    "status": "refused" if refusal else "complete", "reason": refusal,
                    "source_snapshot_sha256": before, "checks": results,
                    "counts": {"selected": sum(item["selected"] for item in planned["local_checks"]),
                               "executed": sum(item.get("executed", False) for item in results), **counts},
                    "duration_seconds": round(time.monotonic() - started, 3),
                    "retained_scratch": str(scratch) if unverified_descendant else None,
                    "local_checks_passed": refusal is None and
                    counts["failed"] == counts["unavailable"] == counts["not-run"] == counts["incomplete"] == 0,
                    "full_qualification": False, "github_status_posted": False,
                    "trusted_admission": False})
    return planned


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run"))
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--base", required=True, help="explicit base commit or ref")
    parser.add_argument("--head", required=True, help="explicit committed head or ref")
    parser.add_argument("--step-seconds", type=int, default=120)
    parser.add_argument("--total-seconds", type=int, default=600)
    parser.add_argument("--report-json", type=Path, help="exclusive private local report; no overwrite")
    args = parser.parse_args()
    try:
        if args.report_json and args.mode == "plan":
            raise Refusal("plan_is_read_only")
        if args.report_json and (args.report_json.exists() or args.report_json.is_symlink()):
            raise Refusal("report_exists")
        if args.report_json and args.report_json.resolve().is_relative_to(args.repo.resolve()):
            raise Refusal("report_inside_source")
        result = (inspect(args.repo, args.base, args.head) if args.mode == "plan" else
                  run(args.repo, args.base, args.head,
                      step_seconds=args.step_seconds, total_seconds=args.total_seconds))
        result["mode"] = args.mode
        raw = (json.dumps(result, sort_keys=True, ensure_ascii=True) + "\n").encode()
        if args.report_json:
            fd = os.open(args.report_json, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
        sys.stdout.buffer.write(raw)
        return 0 if args.mode == "plan" or result["local_checks_passed"] else 2
    except Refusal as error:
        sys.stdout.write(json.dumps({"format": FORMAT, "authority": "local-feedback-only",
                                     "status": "refused", "reason": error.code,
                                     "full_qualification": False, "github_status_posted": False,
                                     "trusted_admission": False}, sort_keys=True) + "\n")
        return 2


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == "_supervise":
        raise SystemExit(_supervise_linux(float(sys.argv[2]), sys.argv[3:]))
    raise SystemExit(main())
