#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the three reviewed Agent inputs for the native Linux pilot.

The default is a read-only inventory. --build creates or verifies a private,
external generation; neither action starts the pilot or grants protection.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import tomllib
import traceback
from urllib.parse import unquote, urlparse
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
import pilot_capacity as capacity
from pilot_provider import utility_environment
import pilot_preparation_lock as coordination
PIN = "1.94.1"  # The checked-in native Ubuntu CI toolchain; never `stable`.
FORMAT = "sw-native-pilot-agent-source-build/1"
CURRENT_FORMAT = "sw-native-pilot-agent-source-current/1"
MAX_FINAL_BYTES = 512 * 1024 * 1024
MAX_TARGET_BYTES = 8 * 1024 * 1024 * 1024
MAX_TARGET_ENTRIES = 200000
BUILD_SECONDS = 1200
BUILD_COMMANDS = (
    ("bins", ("build", "--locked", "-p", "agentfw", "--bins", "--message-format=json")),
    ("tests", ("test", "--locked", "-p", "agentfw", "--lib", "--no-run", "--message-format=json")),
)
ROLES = ("agentfw", "git_launcher", "sandbox_tests")

spec = importlib.util.spec_from_file_location(
    "pilot_native_prerequisites", ROOT / "scripts/prepare-native-pilot-prerequisites.py")
assert spec and spec.loader
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class Failure(Exception):
    def __init__(self, reason, stage="inventory"):
        super().__init__(reason)
        self.reason, self.stage = reason, stage
        self.exit_code = None


def require(ok, reason, stage="inventory"):
    if not ok:
        raise Failure(reason, stage)


def git(root, *args):
    result = subprocess.run(["git", *args], cwd=root, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=15, check=False, env=utility_environment())
    require(result.returncode == 0 and len(result.stdout) <= 4 * 1024 * 1024,
            "source_git_query_failed", "source")
    return result.stdout


def source_identity(root, expected_commit):
    """Bind both the Git tree and the bytes of every tracked checkout file."""
    require(re.fullmatch(r"[0-9a-f]{40}", expected_commit or ""),
            "full_expected_commit_required", "source")
    head = git(root, "rev-parse", "HEAD").decode().strip()
    tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    require(head == expected_commit, "candidate_source_mismatch", "source")
    require(not git(root, "status", "--porcelain", "--untracked-files=all"),
            "candidate_source_dirty", "source")
    names = [os.fsdecode(name) for name in git(root, "ls-files", "-z").split(b"\0") if name]
    require("Cargo.lock" in names and "rust-toolchain.toml" in names,
            "tracked_build_identity_missing", "source")
    try:
        files = {name: native.digest(root / name) for name in names}
    except OSError as error:
        raise Failure("tracked_source_unreadable", "source") from error
    # Match the canonical file digest used by the accepted SOU-111 verifier.
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode()
    return {"commit": head, "tree": tree, "dirty": False,
            "files_sha256": hashlib.sha256(canonical).hexdigest(),
            "cargo_lock_sha256": files["Cargo.lock"],
            "rust_toolchain_sha256": files["rust-toolchain.toml"]}


def selected_tools():
    """Inspect an already-installed exact toolchain without rustup installation."""
    found, missing = {"python": str(Path(sys.executable).resolve(strict=True))}, []
    for name in ("git", "rustup", "cc", "c++", "ld", "ar", "ranlib",
                 "make", "cmake", "pkg-config", "readelf"):
        selected = shutil.which(name)
        if selected is None:
            missing.append(f"{name}: provide an existing native build tool")
        else:
            found[name] = str(Path(selected).resolve(strict=True))
    if "rustup" in found:
        for name in ("cargo", "rustc"):
            try:
                result = subprocess.run([found["rustup"], "which", "--toolchain", PIN, name],
                                        env={**utility_environment(build=True), "RUSTUP_AUTO_INSTALL": "0"},
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        timeout=10, check=False)
                if result.returncode:
                    raise ValueError("toolchain_absent")
                path = Path(result.stdout.decode().strip()).resolve(strict=True)
                if not path.is_file() or not os.access(path, os.X_OK):
                    raise ValueError("toolchain_unusable")
                found[name] = str(path)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                missing.append(f"{name}: install reviewed Rust toolchain {PIN} in advance")
    if "rustc" in found and "cargo" in found:
        for name, prefix in (("rustc", f"rustc {PIN} "), ("cargo", f"cargo {PIN} ")):
            try:
                result = subprocess.run([found[name], "--version"], stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, timeout=10, check=False,
                                        env={**utility_environment(build=True), "RUSTUP_TOOLCHAIN": PIN,
                                             "RUSTUP_AUTO_INSTALL": "0"})
                if result.returncode or not result.stdout.decode().startswith(prefix):
                    missing.append(f"{name}: exact version {PIN} required")
            except (OSError, subprocess.TimeoutExpired, UnicodeError):
                missing.append(f"{name}: exact version {PIN} could not be verified")
        try:
            result = subprocess.run([found["rustc"], "-vV"], env=utility_environment(build=True), stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=10, check=False)
            if result.returncode or b"host: x86_64-unknown-linux-gnu" not in result.stdout:
                missing.append("rustc: x86_64-unknown-linux-gnu host required")
        except (OSError, subprocess.TimeoutExpired):
            missing.append("rustc: host target could not be verified")
    for name, path in found.items():
        try:
            info = Path(path).stat()
            if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
                missing.append(f"{name}: regular executable required")
        except OSError:
            missing.append(f"{name}: existing executable required")
    return found, missing


def inventory(root, output, expected_commit):
    tools, missing = selected_tools()
    missing.extend(native.platform_missing())
    if platform.system() == "Linux":
        try:
            release = Path("/etc/os-release").read_text()
            if not re.search(r'^ID="?ubuntu"?$', release, re.MULTILINE):
                missing.append("native Ubuntu distribution identity required")
        except OSError:
            missing.append("Ubuntu distribution identity unavailable")
    if output is None or not output.is_absolute():
        missing.append("--output: absolute external private directory required")
    elif output == root or output.is_relative_to(root):
        missing.append("--output: directory outside the checkout required")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit or ""):
        missing.append("--expected-commit: full reviewed SHA required")
    if not (root / "Cargo.lock").is_file():
        missing.append("Cargo.lock: tracked lockfile required")
    if re.fullmatch(r"[0-9a-f]{40}", expected_commit or ""):
        try:
            source_identity(root, expected_commit)
        except (Failure, OSError, subprocess.SubprocessError) as error:
            missing.append("source: " + (error.reason if isinstance(error, Failure)
                                         else "source_query_failed"))
    return {"status": "plan", "executed": False, "missing": missing,
            "toolchain": PIN, "tools": tools, "output": str(output) if output else None,
            "commands": [["cargo", *flags] for _, flags in BUILD_COMMANDS],
            "next": "resolve missing inputs, then rerun with --build; qualification is separate"}


def tool_identity(tools):
    return {name: {"path": path, "sha256": native.digest(path)}
            for name, path in sorted(tools.items())}


def build_options(tools):
    paths = {name: entry["path"] for name, entry in tools.items()}
    return {"RUSTUP_TOOLCHAIN": PIN, "RUSTUP_AUTO_INSTALL": "0",
            "CARGO_BUILD_JOBS": "2", "SOURCE_DATE_EPOCH": "0",
            "RUSTC": paths["rustc"],
            "CC": paths["cc"], "CXX": paths["c++"], "AR": paths["ar"],
            "RANLIB": paths["ranlib"], "CMAKE": paths["cmake"]}


def bounded_tree_size(generation):
    total = 0
    for base, _, files in os.walk(generation, followlinks=False):
        for name in files:
            path = Path(base) / name
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == os.getuid(), "generation_entry_invalid", "verify")
            total += info.st_size
            require(total <= MAX_FINAL_BYTES, "generation_size_limit", "verify")


def target_within_limit(target):
    target = Path(target)
    if not stat.S_ISDIR(target.lstat().st_mode):
        return False

    def walk_error(error):
        # Cargo may remove a child directory after its parent was enumerated.
        # A missing root or any unreadable inventory must still fail closed.
        if isinstance(error, FileNotFoundError) and error.filename:
            vanished = Path(error.filename)
            if vanished != target and vanished.is_relative_to(target):
                return
        raise error

    total, entries = 0, 0
    for base, dirs, files in os.walk(target, followlinks=False, onerror=walk_error):
        entries += len(dirs) + len(files)
        if entries > MAX_TARGET_ENTRIES:
            return False
        for name in files:
            try:
                info = (Path(base) / name).lstat()
            except FileNotFoundError:
                continue  # Cargo deleted this temporary file since enumeration.
            total += info.st_size
            if total > MAX_TARGET_BYTES:
                return False
    return True


def bounded_cargo(command, *, root, env, target, log, stage):
    """Use SOU-115's owned-group reaper, with an aggregate target quota."""
    capacity.recheck("before_cargo")
    cancelled = False

    def cancel(_signum, _frame):
        nonlocal cancelled
        cancelled = True

    previous = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)}
    process = None
    selector = None
    try:
        for signum in previous:
            signal.signal(signum, cancel)
        with log.open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
            try:
                process = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                selector = selectors.DefaultSelector()
                selector.register(process.stdout, selectors.EVENT_READ)
                deadline, next_size_check = time.monotonic() + BUILD_SECONDS, 0.0
                count = 0
                while selector.get_map() or not native.leader_finished(process):
                    now = time.monotonic()
                    require(not cancelled, f"{stage}_cancelled", stage)
                    require(now <= deadline, f"{stage}_timeout", stage)
                    if now >= next_size_check:
                        require(target_within_limit(target), f"{stage}_target_limit", stage)
                        next_size_check = now + 2
                    if not selector.get_map():
                        time.sleep(0.2)
                    for key, _ in selector.select(timeout=0.2) if selector.get_map() else ():
                        block = os.read(key.fd, 65536)
                        if not block:
                            selector.unregister(key.fileobj)
                            continue
                        count += len(block)
                        output.write(block[:max(0, native.MAX_LOG - output.tell())])
                        require(count <= native.MAX_LOG, f"{stage}_log_limit", stage)
                native.stop_group(process)
                require(not cancelled, f"{stage}_cancelled", stage)
                require(process.returncode == 0, f"{stage}_exit_{process.returncode}", stage)
                require(target_within_limit(target), f"{stage}_target_limit", stage)
            finally:
                if selector is not None:
                    selector.close()
                if process is not None:
                    try:
                        native.stop_group(process)
                    finally:
                        process.stdout.close()
                output.flush()
                os.fsync(output.fileno())
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def checked_binary(path, generation):
    require(path.is_absolute() and path.is_relative_to(generation),
            "binary_outside_generation", "verify")
    info = native.regular(path, executable=True)
    require(info.st_size <= MAX_FINAL_BYTES, "binary_size_limit", "verify")
    with path.open("rb") as stream:
        header = stream.read(20)
        require(header.startswith(b"\x7fELF\x02\x01") and header[18:20] == b"\x3e\x00",
                "native_x86_64_elf_required", "verify")
    return {"path": str(path), "sha256": native.digest(path), "size": info.st_size}


def cargo_artifact_source(path):
    """Cargo may hardlink a build artifact; the selected copy must not be."""
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and not info.st_mode & (stat.S_ISUID | stat.S_ISGID)
            and os.access(path, os.X_OK), "cargo_artifact_not_owned_executable", "artifact")
    require(0 < info.st_size <= MAX_FINAL_BYTES, "cargo_artifact_size_limit", "artifact")
    return info


def verify_receipt(generation, expected_source, expected_tools, *, completed=True):
    receipt_path = generation / "receipt.json"
    native.regular(receipt_path)
    receipt = native.strict_json(receipt_path)
    require(receipt.get("format") == FORMAT and receipt.get("source") == expected_source
            and receipt.get("tools") == expected_tools
            and receipt.get("commands") == [["cargo", *flags] for _, flags in BUILD_COMMANDS]
            and receipt.get("toolchain") == PIN
            and receipt.get("environment") == build_options(expected_tools),
            "receipt_identity_changed", "reuse")
    require(generation.lstat().st_uid == os.getuid()
            and stat.S_IMODE(generation.lstat().st_mode) == (0o500 if completed else 0o700),
            "generation_directory_changed", "reuse")
    for role in ROLES:
        require(receipt["binaries"][role] == checked_binary(generation / "bin" / role, generation),
                "binary_digest_or_mode_changed", "reuse")
    bounded_tree_size(generation)
    require(receipt["generation_tree_sha256"] == native.tree_digest(generation, completed=completed),
            "generation_tree_changed", "reuse")
    return receipt


def expected_package(root):
    manifest = root / "crates/agentfw/Cargo.toml"
    package = tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]
    require(package["name"] == "agentfw"
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", package["version"]),
            "agent_package_identity_changed", "artifact")
    return manifest.parent.resolve(strict=True), package["version"]


def package_matches(package_id, root, version):
    if not isinstance(package_id, str) or not package_id.startswith("path+file://"):
        return False
    location, marker, suffix = package_id.partition("#")
    if not marker or suffix not in (version, f"agentfw@{version}"):
        return False
    return Path(unquote(urlparse(location.removeprefix("path+")).path)).resolve() == root


def artifacts(log, requested, package_root, package_version):
    hits = {}
    for line in log.read_bytes().splitlines():
        try:
            row = json.loads(line)
        except (UnicodeError, ValueError):
            continue
        if row.get("reason") != "compiler-artifact" or not package_matches(
                row.get("package_id"), package_root, package_version):
            continue
        target = row.get("target", {})
        name, kinds = target.get("name"), target.get("kind", [])
        role = "agentfw" if name == "agentfw" and "bin" in kinds else (
            "git_launcher" if name == "agentfw-git-sandbox" and "bin" in kinds else (
            "sandbox_tests" if name == "agentfw" and "lib" in kinds and row.get("profile", {}).get("test") else None))
        if role not in requested or not row.get("executable"):
            continue
        require(role not in hits, "duplicate_cargo_artifact", "artifact")
        hits[role] = Path(row["executable"])
    require(set(hits) == set(requested), "required_cargo_artifact_missing", "artifact")
    return hits


def build_generation(root, generation, tools):
    (generation / "tmp").mkdir(mode=0o700)
    (generation / "bin").mkdir(mode=0o700)
    cargo_home = generation / "cargo-home"
    cargo_home.mkdir(mode=0o700)
    target = generation / "target"
    target.mkdir(mode=0o700)
    options = build_options(tool_identity(tools))
    env = {"PATH": os.pathsep.join(dict.fromkeys([*(str(Path(p).parent) for p in tools.values()),
                                                    "/usr/bin", "/bin"])),
           "HOME": str(generation), "TMPDIR": str(generation / "tmp"),
           "CARGO_HOME": str(cargo_home),
           "CARGO_TARGET_DIR": str(target),
           "LANG": "C", "LC_ALL": "C", **options}
    start = time.monotonic()
    found = {}
    package_root, package_version = expected_package(root)
    for stage, flags in BUILD_COMMANDS:
        log = generation / f"cargo-{stage}.log"
        bounded_cargo([tools["cargo"], *flags], root=root, env=env, target=generation,
                      log=log, stage=f"agent_{stage}")
        found.update(artifacts(log, ("agentfw", "git_launcher") if stage == "bins" else
                               ("sandbox_tests",), package_root, package_version))
    copied = 0
    capacity.recheck("before_artifact_copy")
    for role in ROLES:
        source = found[role].resolve(strict=True)
        require(source.is_relative_to(target.resolve(strict=True)),
                "cargo_artifact_outside_target", "artifact")
        size = cargo_artifact_source(source).st_size
        require(0 < size <= MAX_FINAL_BYTES - copied, "binary_size_limit", "artifact")
        copied += size
        destination = generation / "bin" / role
        with source.open("rb") as read, destination.open("xb") as write:
            os.fchmod(write.fileno(), 0o700)
            remaining = size
            while remaining:
                block = read.read(min(1024 * 1024, remaining))
                require(block, "cargo_artifact_truncated", "artifact")
                write.write(block)
                remaining -= len(block)
            require(not read.read(1), "cargo_artifact_grew", "artifact")
            write.flush()
            os.fsync(write.fileno())
        checked_binary(destination, generation)
    # Cargo intermediates and the isolated registry cache are never selected
    # inputs. Retain only bounded logs and finished binaries.
    for work in (target, cargo_home):
        require(work.resolve(strict=True).is_relative_to(generation.resolve(strict=True)),
                "unsafe_build_cleanup", "cleanup")
        shutil.rmtree(work)
    bounded_tree_size(generation)
    return round(time.monotonic() - start, 3)


def selected(output, source, tools):
    marker = output / "current.json"
    native.regular(marker)
    current = native.strict_json(marker)
    require(current.get("format") == CURRENT_FORMAT
            and re.fullmatch(r"[0-9a-f]{32}", current.get("generation", "")),
            "current_marker_invalid", "reuse")
    generation = output / "generations" / current["generation"]
    receipt = verify_receipt(generation, source, tools)
    require(native.digest(generation / "receipt.json") == current.get("receipt_sha256"),
            "current_marker_changed", "reuse")
    return receipt, generation


def result(status, generation, seconds):
    return {"status": status, "agentfw": str(generation / "bin/agentfw"),
            "git_launcher": str(generation / "bin/git_launcher"),
            "sandbox_tests": str(generation / "bin/sandbox_tests"),
            "receipt": str(generation / "receipt.json"), "build_seconds": seconds,
            "active_protection": False}


def run_build(root, output, expected_commit, *, rebuild=False, wait_seconds=0):
    wait_seconds = coordination.bounded_wait(wait_seconds)
    source = source_identity(root, expected_commit)
    plan = inventory(root, output, expected_commit)
    require(not plan["missing"], "missing_inputs: " + "; ".join(plan["missing"])[:300])
    tools = tool_identity(plan["tools"])
    output = native.output_root(output)
    with coordination.hold(output, wait_seconds=wait_seconds) as claim:
        # A waiter never acts on the pre-lock snapshot. The receipt and marker
        # are rechecked under the lifetime lock before any reuse or build.
        current_plan = inventory(root, output, expected_commit)
        require(not current_plan["missing"] and
                source_identity(root, expected_commit) == source and
                tool_identity(current_plan["tools"]) == tools,
                "input_changed_while_waiting", "coordination")
        capacity.recheck("after_coordination")
        generations = output / "generations"
        generations.mkdir(mode=0o700, exist_ok=True)
        native.private(generations)
        require(not (output / "current.json").is_symlink(), "current_marker_symlink", "reuse")
        if (output / "current.json").exists():
            native.regular(output / "current.json")
            current = native.strict_json(output / "current.json")
            require(current.get("format") == CURRENT_FORMAT and
                    re.fullmatch(r"[0-9a-f]{32}", current.get("generation", "")) and
                    re.fullmatch(r"[0-9a-f]{64}", current.get("receipt_sha256", "")),
                    "current_marker_invalid", "reuse")
            if not rebuild:
                _, previous_generation = selected(output, source, tools)
                answer = result("reused", previous_generation, 0)
                answer.update(waited_seconds=claim.waited_seconds,
                              contended=claim.contended)
                return answer
        # A dead owner cannot hold the descriptor lock. Its incomplete private
        # generations stay as failure evidence, while a fresh owner may build.
        incomplete = sum(1 for _ in itertools.islice(generations.iterdir(), 17)) if not (
            output / "current.json").exists() else 0
        require(incomplete <= 16, "retained_incomplete_generation_limit", "coordination")
        generation = native.private(generations / uuid.uuid4().hex, create=True)
        capacity.bind(generation)
        seconds = build_generation(root, generation, current_plan["tools"])
        require(source_identity(root, expected_commit) == source,
                "candidate_source_changed_during_build", "source")
        require(tool_identity(current_plan["tools"]) == tools,
                "compiler_input_changed_during_build", "verify")
        binaries = {role: checked_binary(generation / "bin" / role, generation) for role in ROLES}
        receipt = {"format": FORMAT, "status": "built-not-qualified", "source": source,
                   "tools": tools, "toolchain": PIN,
                   "commands": [["cargo", *flags] for _, flags in BUILD_COMMANDS],
                   "environment": build_options(tools),
                   "binaries": binaries, "build_seconds": seconds,
                   "generation_tree_sha256": native.tree_digest(generation)}
        native.write_json(generation / "receipt.json", receipt)
        verify_receipt(generation, source, tools, completed=False)
        native.freeze(generation)
        verify_receipt(generation, source, tools, completed=True)
        marker = {"format": CURRENT_FORMAT, "generation": generation.name,
                  "receipt_sha256": native.digest(generation / "receipt.json")}
        capacity.recheck("before_selection")
        temporary = output / (".current-" + uuid.uuid4().hex)
        native.write_json(temporary, marker)
        claim.verify()
        os.replace(temporary.name, "current.json", src_dir_fd=claim.directory_fd,
                   dst_dir_fd=claim.directory_fd)
        claim.verify()
        os.fsync(claim.directory_fd)
        answer = result("built-not-qualified", generation, seconds)
        answer.update(waited_seconds=claim.waited_seconds,
                      contended=claim.contended)
        if incomplete:
            answer["retained_interrupted_generations"] = incomplete
        return answer


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    capacity.add_arguments(parser)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--rebuild", action="store_true")
    parser.add_argument("--wait-seconds", type=float, default=0,
                        help="explicit bounded wait for an owned same-root build (max 2700)")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-commit")
    args = parser.parse_args(argv)
    if args.capacity_plan:
        if args.build or args.guard_capacity:
            parser.error("--capacity-plan is read-only; use it without --build or --guard-capacity")
        print(json.dumps(capacity.cli_plan("source", args), sort_keys=True))
        return 0
    if args.guard_capacity and not args.build:
        parser.error("--guard-capacity requires --build")
    try:
        require(not args.rebuild or args.build, "rebuild_requires_build")
        coordination.bounded_wait(args.wait_seconds)
        require(args.build or args.wait_seconds == 0, "wait_requires_build")
        with capacity.checked("source", args):
            value = (run_build(ROOT, args.output, args.expected_commit,
                               rebuild=args.rebuild, wait_seconds=args.wait_seconds)
                     if args.build else inventory(ROOT, args.output, args.expected_commit))
            print(json.dumps(value, sort_keys=True))
        return 0
    except capacity.Refusal as error:
        print(json.dumps(error.report, sort_keys=True))
        return 2
    except coordination.Busy as error:
        print(json.dumps({"status": "busy", "reason": error.reason,
                          "waited_seconds": error.waited_seconds,
                          "active_protection": False}, sort_keys=True))
        return 3
    except (Failure, native.Failure, coordination.Unsafe, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError) as error:
        failure = (error if isinstance(error, (Failure, native.Failure)) else
                   Failure(str(error) if isinstance(error, coordination.Unsafe) else
                           type(error).__name__ + "_failed", "coordination" if isinstance(
                               error, coordination.Unsafe) else "build"))
        record = {"status": "failed", "stage": failure.stage,
                  "reason": failure.reason[:300], "active_protection": False}
        if not isinstance(error, (Failure, native.Failure)):
            frames = [frame for frame in traceback.extract_tb(error.__traceback__)
                      if frame.filename == __file__]
            if frames:
                record["failure_location"] = {"function": frames[-1].name,
                                              "line": frames[-1].lineno}
        if args.build:
            try:
                native.failure_record(args.output, failure)
            except (native.Failure, OSError):
                pass  # Never replace the original bounded failure reason.
        print(json.dumps(record, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
