#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the two pinned native pilot prerequisites in a private Linux prefix.

The default is an inventory. Only --prepare downloads (when explicitly allowed),
extracts, builds, and atomically selects a verified generation. This never
grants bubblewrap namespace permission or starts the protected pilot.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
import pilot_capacity as capacity
from pilot_provider import utility_environment
SOURCES = {
    "git": ("2.51.2", "git-2.51.2",
            "https://www.kernel.org/pub/software/scm/git/git-2.51.2.tar.xz",
            "233d7143a2d58e60755eee9b76f559ec73ea2b3c297f5b503162ace95966b4e3", 64 * 1024 * 1024),
    "bwrap": ("0.13.1", "bubblewrap-0.13.1",
              "https://github.com/containers/bubblewrap/releases/download/v0.13.1/bubblewrap-0.13.1.tar.xz",
              "0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d", 16 * 1024 * 1024),
}
GIT_FLAGS = ("-j2", "NO_CURL=YesPlease", "NO_EXPAT=YesPlease", "NO_TCLTK=YesPlease",
             "NO_GETTEXT=YesPlease", "NO_OPENSSL=YesPlease", "git")
BWRAP_FLAGS = ("-Dtests=false", "-Dman=disabled", "-Dselinux=disabled",
               "-Dbash_completion=disabled", "-Dzsh_completion=disabled")
TOOLS = ("cc", "make", "meson", "ninja", "pkg-config", "ar", "ranlib", "ldd", "readelf")
MAX_RECEIPT = 65536
MAX_LOG = 1024 * 1024
MAX_ENTRIES = 12000
MAX_EXPANDED = 512 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024


class Failure(Exception):
    def __init__(self, reason, stage="inventory", exit_code=None):
        super().__init__(reason)
        self.reason, self.stage, self.exit_code = reason, stage, exit_code


def require(ok, reason, stage="inventory"):
    if not ok:
        raise Failure(reason, stage)


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def strict_json(path):
    path = Path(path)
    require(path.stat().st_size <= MAX_RECEIPT, "receipt_size_limit", "reuse")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_receipt_key", "reuse")
            result[key] = value
        return result
    return json.loads(path.read_bytes(), object_pairs_hook=pairs)


def write_json(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    require(len(data) <= MAX_RECEIPT, "receipt_size_limit", "publish")
    with Path(path).open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def regular(path, *, executable=False):
    info = Path(path).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(),
            "owned_regular_file_required", "verify")
    require(not info.st_mode & (stat.S_ISUID | stat.S_ISGID), "privileged_file_refused", "verify")
    if executable:
        require(os.access(path, os.X_OK), "executable_required", "verify")
    return info


def private(path, *, create=False):
    path = Path(path)
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "private_owned_0700_directory_required")
    return path


def output_root(path):
    require(path is not None and path.is_absolute(), "absolute_output_required")
    parent = path.parent.resolve(strict=True)
    require(parent == path.parent and path.name not in ("", ".", ".."), "unsafe_output_parent")
    info = parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and (info.st_uid in (0, os.getuid()))
            and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX), "unsafe_output_parent")
    require(not path.is_relative_to(ROOT), "output_inside_checkout")
    require(not path.is_symlink(), "symlink_output_refused")
    return private(path, create=not path.exists())


def platform_missing():
    missing = []
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        missing.append("native Ubuntu 24.04 x86_64 required")
    elif "microsoft" in Path("/proc/sys/kernel/osrelease").read_text().lower():
        missing.append("native Ubuntu required; WSL has a separate qualification")
    elif not re.search(r'^VERSION_ID="?24\.04"?$', Path("/etc/os-release").read_text(), re.MULTILINE):
        missing.append("Ubuntu 24.04 required")
    if os.name == "posix" and os.geteuid() == 0:
        missing.append("run as a non-root operator")
    return missing


def tool_inventory(args):
    found, missing = {}, []
    for name in TOOLS:
        selected = shutil.which(name)
        if selected is None:
            missing.append({"dependency": name, "install": "build-essential meson ninja-build pkg-config binutils"})
            continue
        path = Path(selected).resolve(strict=True)
        if not path.is_file() or not os.access(path, os.X_OK):
            missing.append({"dependency": name, "install": "provide an executable tool"})
            continue
        found[name] = str(path)
    if "pkg-config" in found:
        for library, package in (("libcap", "libcap-dev"), ("zlib", "zlib1g-dev")):
            env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
            if library == "libcap" and args.pkg_config_libdir:
                env["PKG_CONFIG_LIBDIR"] = optional_directory(args.pkg_config_libdir)
                if args.pkg_config_sysroot:
                    env["PKG_CONFIG_SYSROOT_DIR"] = optional_directory(args.pkg_config_sysroot)
            result = subprocess.run([found["pkg-config"], "--exists", library], env=env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if result.returncode:
                missing.append({"dependency": library, "install": package})
    return found, missing


def source_identity(expected):
    require(re.fullmatch(r"[0-9a-f]{40}", expected or ""), "full_expected_commit_required")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, timeout=10, env=utility_environment()).decode().strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, timeout=10, env=utility_environment())
    require(head == expected and not dirty, "candidate_source_mismatch")
    identity = json.loads((ROOT / "profiles/mcp/git-readonly-v1/upstream-identity.json").read_text())
    require(identity["git_source_url"] == SOURCES["git"][2]
            and identity["git_source_sha256"] == SOURCES["git"][3]
            and identity["git_version"] == SOURCES["git"][0], "accepted_git_pin_changed")
    return head


def optional_directory(path):
    if path is None:
        return None
    require(path.is_absolute() and path.is_dir() and not path.is_symlink(), "absolute_dependency_directory_required")
    info = path.stat()
    require(info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022,
            "unsafe_dependency_directory")
    return str(path.resolve(strict=True))


def environment(tools, home, args):
    paths = [str(Path(path).parent) for path in tools.values()]
    paths.extend(("/usr/bin", "/bin"))
    result = {"PATH": os.pathsep.join(dict.fromkeys(paths)), "HOME": str(home),
              "TMPDIR": str(home / "tmp"), "LANG": "C", "LC_ALL": "C",
              "CC": tools["cc"], "AR": tools["ar"], "RANLIB": tools["ranlib"],
              "PKG_CONFIG": tools["pkg-config"], "SOURCE_DATE_EPOCH": "0"}
    if value := optional_directory(args.pkg_config_libdir):
        result["PKG_CONFIG_LIBDIR"] = value
    if value := optional_directory(args.pkg_config_sysroot):
        result["PKG_CONFIG_SYSROOT_DIR"] = value
    if value := optional_directory(args.meson_pythonpath):
        result["PYTHONPATH"] = value
    return result


def bounded_archive(path, kind):
    info = Path(path).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= SOURCES[kind][4],
            f"{kind}_archive_size_or_type", "inputs")
    require(digest(path) == SOURCES[kind][3], f"{kind}_archive_digest_mismatch", "inputs")
    return Path(path).resolve(strict=True)


def download(kind, destination):
    capacity.recheck("before_download")
    url = SOURCES[kind][2]
    require(url.startswith("https://"), "unpinned_download_refused", "download")
    limit = SOURCES[kind][4]
    request = urllib.request.Request(url, headers={"User-Agent": "soup-wall-sou115/1"})
    deadline = time.monotonic() + 120
    try:
        with urllib.request.urlopen(request, timeout=25) as response, destination.open("xb") as target:
            os.fchmod(target.fileno(), 0o600)
            require(response.geturl().startswith("https://"), "insecure_download_redirect", "download")
            count = 0
            while block := response.read(65536):
                require(time.monotonic() <= deadline, f"{kind}_download_timeout", "download")
                count += len(block)
                require(count <= limit, f"{kind}_download_size_limit", "download")
                target.write(block)
    except (OSError, TimeoutError, urllib.error.URLError) as error:
        raise Failure(f"{kind}_download_failed; use the pinned local archive", "download") from error
    bounded_archive(destination, kind)
    return destination


def extract(archive, destination, kind):
    """Preflight the complete layout before writing any archive member."""
    capacity.recheck("before_extraction")
    prefix = SOURCES[kind][1]
    with tarfile.open(archive, "r:xz") as bundle:
        members = bundle.getmembers()
        require(len(members) <= MAX_ENTRIES and sum(item.size for item in members) <= MAX_EXPANDED,
                "archive_expansion_limit", "extract")
        seen, links = set(), []
        for member in members:
            parts = PurePosixPath(member.name).parts
            require(parts and parts[0] == prefix and ".." not in parts and not member.name.startswith("/"),
                    "archive_path_escape", "extract")
            relative = Path(*parts[1:])
            require(relative not in seen and member.size <= MAX_FILE, "archive_duplicate_or_large_entry", "extract")
            seen.add(relative)
            if relative == Path("."):
                require(member.isdir(), "archive_root_invalid", "extract")
                continue
            require(member.isdir() or member.isfile() or member.issym(), "archive_special_file", "extract")
            if member.issym():
                require(not PurePosixPath(member.linkname).is_absolute(), "archive_link_escape", "extract")
                links.append((relative, member.linkname))
        link_paths = {name for name, _ in links}
        for relative in seen:
            require(not any(parent in link_paths for parent in relative.parents), "archive_link_parent", "extract")
        for member in members:
            relative = Path(*PurePosixPath(member.name).parts[1:])
            if relative == Path(".") or member.issym():
                continue
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if member.isdir():
                target.mkdir(exist_ok=True, mode=0o700)
            else:
                with bundle.extractfile(member) as source, target.open("xb") as output:
                    require(source is not None, "archive_entry_missing", "extract")
                    remaining = member.size
                    while remaining:
                        block = source.read(min(65536, remaining))
                        require(block, "archive_entry_truncated", "extract")
                        output.write(block)
                        remaining -= len(block)
                target.chmod(0o700 if member.mode & 0o111 else 0o600)
        for relative, linkname in links:
            target = destination / relative
            resolved = (target.parent / linkname).resolve(strict=False)
            require(resolved.is_relative_to(destination.resolve(strict=True)) and resolved.is_file()
                    and not resolved.is_symlink(), "archive_link_escape", "extract")
            target.symlink_to(linkname)


def group_has_running_member(pgid):
    """Inspect the owned Linux process group, excluding already-dead zombies."""
    with os.scandir("/proc") as entries:
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            try:
                fields = (Path(entry.path) / "stat").read_text().rsplit(") ", 1)[1].split()
            except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
                continue
            if len(fields) >= 3 and fields[0] not in ("Z", "X") and int(fields[2]) == pgid:
                return True
    return False


def leader_finished(process):
    # WNOWAIT leaves the group leader unreaped. Its PID therefore cannot be
    # reused while stop_group is still allowed to signal that process group.
    return process.returncode is not None or os.waitid(
        os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def stop_group(process):
    if process.returncode is not None:
        return
    pgid = process.pid  # start_new_session=True made the child its own leader.
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 2
    while group_has_running_member(pgid) and time.monotonic() < deadline:
        time.sleep(0.05)
    if group_has_running_member(pgid):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 2
        while group_has_running_member(pgid) and time.monotonic() < deadline:
            time.sleep(0.05)
    require(not group_has_running_member(pgid), "owned_build_group_not_stopped", "cleanup")
    process.wait(timeout=2)


def build(command, *, cwd, env, log, seconds, stage):
    """Drain bounded output and stop the entire owned process group on every exit."""
    capacity.recheck("before_build")
    cancelled = False

    def mark_cancelled(_signum, _frame):
        nonlocal cancelled
        cancelled = True

    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
    try:
        for signum in previous:
            signal.signal(signum, mark_cancelled)
        with log.open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
            process = None
            selector = None
            try:
                process = subprocess.Popen(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                selector = selectors.DefaultSelector()
                selector.register(process.stdout, selectors.EVENT_READ)
                deadline, count, over_limit = time.monotonic() + seconds, 0, False
                while selector.get_map() or not leader_finished(process):
                    if cancelled:
                        raise Failure(f"{stage}_cancelled", stage)
                    if time.monotonic() > deadline:
                        raise Failure(f"{stage}_timeout; inspect private log", stage)
                    if not selector.get_map():
                        time.sleep(0.2)
                    for key, _ in selector.select(timeout=0.2) if selector.get_map() else ():
                        block = os.read(key.fd, 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        count += len(block)
                        output.write(block[:max(0, MAX_LOG - output.tell())])
                        if count > MAX_LOG:
                            over_limit = True
                            raise Failure(f"{stage}_log_limit; inspect private log", stage)
                stop_group(process)
                code = process.returncode
                if cancelled:
                    raise Failure(f"{stage}_cancelled", stage)
                require(not over_limit, f"{stage}_log_limit", stage)
                if code:
                    raise Failure(f"{stage}_exit_{code}; inspect private log", stage, code)
            finally:
                if selector is not None:
                    selector.close()
                if process is not None:
                    try:
                        stop_group(process)
                    finally:
                        process.stdout.close()
                        output.flush()
                        os.fsync(output.fileno())
                else:
                    output.flush()
                    os.fsync(output.fileno())
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def captured(command, *, seconds=10, stage="verify"):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=seconds, check=False, env=utility_environment())
    require(len(result.stdout) <= 65536 and result.returncode == 0, "native_validation_failed", stage)
    return result.stdout.decode("utf-8", "replace")


def native_libraries(binary, tools):
    header = captured([tools["readelf"], "-h", str(binary)])
    require("ELF64" in header and "X86-64" in header, "native_x86_64_elf_required", "verify")
    output = captured([tools["ldd"], str(binary)])
    require("not found" not in output, "native_library_missing", "verify")
    found = {}
    for line in output.splitlines():
        match = re.search(r"(?:=>\s+)?(/[^\s(]+)\s+\(", line)
        if match:
            path = Path(match.group(1)).resolve(strict=True)
            require(path.is_file(), "native_library_missing", "verify")
            found[str(path)] = digest(path)
    return found


def verify_binary(kind, binary, tools):
    regular(binary, executable=True)
    version = captured([str(binary), "--version"])
    require(SOURCES[kind][0] in version.splitlines()[0], f"{kind}_version_mismatch", "verify")
    if kind == "bwrap":
        require("--ro-bind-fd" in captured([str(binary), "--help"]),
                "bubblewrap_ro_bind_fd_required", "verify")
    libraries = native_libraries(binary, tools)
    return {"path": str(binary.resolve(strict=True)), "sha256": digest(binary),
            "version": version.splitlines()[0], "libraries": libraries}


def tree_digest(generation, *, completed=False):
    """Bind all source/build bytes while excluding the receipt that contains this hash."""
    overall = hashlib.sha256()
    for base, dirs, files in os.walk(generation, followlinks=False):
        dirs.sort()
        for name in sorted(dirs + files):
            path = Path(base) / name
            relative = path.relative_to(generation).as_posix()
            if relative == "receipt.json":
                continue
            info = path.lstat()
            require(info.st_uid == os.getuid() and not info.st_mode & (stat.S_ISUID | stat.S_ISGID),
                    "generation_entry_ownership_changed", "reuse")
            # POSIX symlink mode is normally 0777 and chmod would affect its
            # target. The frozen parent directory protects the link entry;
            # each regular target is checked separately below.
            if completed and not path.is_symlink():
                require(not info.st_mode & 0o222, "completed_generation_writable", "reuse")
            if path.is_symlink():
                target = path.resolve(strict=True)
                require(target.is_relative_to(generation.resolve(strict=True)) and target.is_file(),
                        "generation_link_escape", "reuse")
                marker = "link:" + os.readlink(path)
            elif path.is_dir():
                marker = "directory"
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                        "generation_special_entry", "reuse")
                marker = "file:" + digest(path)
            overall.update(relative.encode() + b"\0" + marker.encode() + b"\0")
    return overall.hexdigest()


def verify_generation(generation, expected, tools, *, completed=False):
    info = generation.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and (not completed or stat.S_IMODE(info.st_mode) == 0o500),
            "generation_directory_changed", "reuse")
    receipt_path = generation / "receipt.json"
    regular(receipt_path)
    if completed:
        require(not receipt_path.stat().st_mode & 0o222, "completed_receipt_writable", "reuse")
    receipt = strict_json(receipt_path)
    require(receipt.get("format") == "sw-native-pilot-prerequisites/1"
            and receipt.get("source_commit") == expected
            and receipt.get("flags") == {"git": list(GIT_FLAGS), "bwrap": list(BWRAP_FLAGS)},
            "receipt_identity_changed", "reuse")
    require(receipt.get("generation_tree_sha256") == tree_digest(generation, completed=completed),
            "generation_tree_changed", "reuse")
    for kind in SOURCES:
        require(receipt["archives"][kind] == {"url": SOURCES[kind][2], "sha256": SOURCES[kind][3]},
                "archive_identity_changed", "reuse")
    for name, entry in receipt["tools"].items():
        require(name in TOOLS and entry["path"] == tools[name]
                and digest(entry["path"]) == entry["sha256"],
                "tool_identity_changed", "reuse")
    for kind in SOURCES:
        binary = generation / ("git-src/git" if kind == "git" else "bwrap-build/bwrap")
        require(receipt["binaries"][kind] == verify_binary(kind, binary, tools),
                "completed_binary_or_library_changed", "reuse")
    return receipt


def freeze(generation):
    for base, directories, files in os.walk(generation, followlinks=False):
        for filename in files:
            path = Path(base) / filename
            if path.is_symlink():
                continue
            path.chmod(0o500 if path.stat().st_mode & 0o111 else 0o400)
        for dirname in directories:
            path = Path(base) / dirname
            if not path.is_symlink():
                path.chmod(0o500)
    generation.chmod(0o500)


def failure_record(output, error):
    record = {"status": "failed", "stage": error.stage, "reason": error.reason[:160],
              "exit_code": error.exit_code, "active_protection": False}
    if output is not None and output.exists() and not output.is_symlink():
        info = output.lstat()
        if stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() \
                and stat.S_IMODE(info.st_mode) == 0o700 and not output.is_relative_to(ROOT) \
                and not (output / "first-failure.json").exists():
            write_json(output / "first-failure.json", record)
    return record


def prepare(args):
    missing = platform_missing()
    tools, dependencies = tool_inventory(args)
    missing.extend(f'{item["dependency"]}: install {item["install"]}' for item in dependencies)
    for kind in SOURCES:
        archive = getattr(args, kind + "_archive")
        if archive is None and not args.allow_download:
            missing.append(f"--{kind}-archive ABSOLUTE_PINNED_ARCHIVE or --allow-download")
        elif archive is not None and (not archive.is_absolute() or not archive.is_file()):
            missing.append(f"--{kind}-archive must be an existing absolute file")
    if args.output is None:
        missing.append("--output ABSOLUTE_PRIVATE_DIRECTORY")
    if not args.expected_commit:
        missing.append("--expected-commit FULL_REVIEWED_COMMIT")
    pins = {kind: {"version": row[0], "url": row[2], "sha256": row[3]}
            for kind, row in SOURCES.items()}
    if not args.prepare:
        return {"status": "plan", "executed": False, "missing": missing,
                "pins": pins, "required_packages": ["build-essential", "meson", "ninja-build",
                    "pkg-config", "binutils", "libcap-dev", "zlib1g-dev"],
                "next": "supply missing inputs, then --prepare; sandbox and pilot qualification are separate"}
    require(not missing, "missing_prerequisites: " + "; ".join(missing)[:140])
    source = source_identity(args.expected_commit)
    output = output_root(args.output)
    generations = private(output / "generations", create=not (output / "generations").exists())
    marker = output / "current.json"
    if marker.exists() and not args.rebuild:
        regular(marker)
        selected = strict_json(marker)
        require(selected.get("format") == "sw-native-pilot-current/1"
                and re.fullmatch(r"[0-9a-f]{32}", selected.get("generation", "")),
                "current_marker_invalid", "reuse")
        generation = generations / selected["generation"]
        receipt = verify_generation(generation, source, tools, completed=True)
        require(digest(generation / "receipt.json") == selected["receipt_sha256"],
                "current_marker_changed", "reuse")
        return {"status": "reused", "git": receipt["binaries"]["git"]["path"],
                "bwrap": receipt["binaries"]["bwrap"]["path"],
                "receipt": str(generation / "receipt.json"), "active_protection": False}
    generation = private(generations / uuid.uuid4().hex, create=True)
    capacity.bind(generation)
    (generation / "tmp").mkdir(mode=0o700)
    env = environment(tools, generation, args)
    archives = {}
    for kind in SOURCES:
        supplied = getattr(args, kind + "_archive")
        archives[kind] = bounded_archive(supplied, kind) if supplied else download(
            kind, generation / (kind + ".tar.xz"))
    for kind in SOURCES:
        destination = generation / (kind + "-src")
        destination.mkdir(mode=0o700)
        extract(archives[kind], destination, kind)
    git = generation / "git-src/git"
    bwrap = generation / "bwrap-build/bwrap"
    build([tools["make"], *GIT_FLAGS], cwd=generation / "git-src", env=env,
          log=generation / "git-build.log", seconds=600, stage="git_build")
    build([tools["meson"], "setup", str(generation / "bwrap-build"),
           str(generation / "bwrap-src"), *BWRAP_FLAGS], cwd=generation, env=env,
          log=generation / "bwrap-setup.log", seconds=120, stage="bwrap_setup")
    build([tools["meson"], "compile", "-C", str(generation / "bwrap-build")],
          cwd=generation, env=env, log=generation / "bwrap-build.log", seconds=300, stage="bwrap_build")
    binaries = {kind: verify_binary(kind, path, tools) for kind, path in (("git", git), ("bwrap", bwrap))}
    receipt = {"format": "sw-native-pilot-prerequisites/1", "source_commit": source,
               "archives": {kind: {"url": SOURCES[kind][2], "sha256": SOURCES[kind][3]}
                            for kind in SOURCES},
               "tools": {name: {"path": path, "sha256": digest(path)} for name, path in tools.items()},
               "flags": {"git": list(GIT_FLAGS), "bwrap": list(BWRAP_FLAGS)},
               "binaries": binaries, "generation_tree_sha256": tree_digest(generation),
               "status": "built-not-qualified"}
    write_json(generation / "receipt.json", receipt)
    verify_generation(generation, source, tools)
    freeze(generation)
    current = {"format": "sw-native-pilot-current/1", "generation": generation.name,
               "receipt_sha256": digest(generation / "receipt.json")}
    capacity.recheck("before_selection")
    temporary = output / (".current-" + uuid.uuid4().hex)
    write_json(temporary, current)
    os.replace(temporary, marker)
    fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"status": "prepared-not-qualified", "git": str(git), "bwrap": str(bwrap),
            "receipt": str(generation / "receipt.json"), "active_protection": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    capacity.add_arguments(parser)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--rebuild", action="store_true")
    parser.add_argument("--allow-download", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--git-archive", type=Path)
    parser.add_argument("--bwrap-archive", type=Path)
    parser.add_argument("--pkg-config-libdir", type=Path)
    parser.add_argument("--pkg-config-sysroot", type=Path)
    parser.add_argument("--meson-pythonpath", type=Path)
    args = parser.parse_args()
    if args.capacity_plan:
        if args.prepare or args.guard_capacity:
            parser.error("--capacity-plan is read-only; use it without --prepare or --guard-capacity")
        print(json.dumps(capacity.cli_plan("native", args), sort_keys=True))
        return 0
    if args.guard_capacity and not args.prepare:
        parser.error("--guard-capacity requires --prepare")
    try:
        with capacity.checked("native", args):
            print(json.dumps(prepare(args)))
        return 0 if not args.prepare or not platform_missing() else 2
    except capacity.Refusal as error:
        print(json.dumps(error.report, sort_keys=True))
        return 2
    except (Failure, OSError, ValueError, KeyError, TypeError, tarfile.TarError,
            subprocess.SubprocessError, urllib.error.URLError) as error:
        failure = error if isinstance(error, Failure) else Failure(type(error).__name__ + "_failed", "prepare")
        output = args.output if args.prepare else None
        print(json.dumps(failure_record(output, failure)))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
