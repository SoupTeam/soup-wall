#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Simulated compilation with real subprocesses, receipts and publication.

Only compiler and host probes are replaced. The production coordination,
generation validation and marker publication code executes in each process.
"""
import importlib.util
import os
from pathlib import Path
import sys
import time
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[2]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kind, output_text, witness_text, gate_text, identity, operation, wait_text, failure = sys.argv[1:9]
output, witness = Path(output_text), Path(witness_text)
gate = None if gate_text == "-" else Path(gate_text)
commit = identity * 40
if len(sys.argv) == 11:
    start_gate, ready = Path(sys.argv[9]), Path(sys.argv[10])
    descriptor = os.open(ready, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(descriptor, b"ready\n")
    finally:
        os.close(descriptor)
    deadline = time.monotonic() + 10
    while not start_gate.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not start_gate.exists():
        raise SystemExit("simulated_start_gate_timeout")


def started():
    descriptor = os.open(witness, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        os.write(descriptor, (kind + ":" + identity + "\n").encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if gate is not None:
        deadline = time.monotonic() + 20
        while not gate.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        if not gate.exists():
            raise RuntimeError("simulated_build_gate_timeout")


def resumed_bwrap_started():
    """Independent witness for a resumed owner holding the real root lock."""
    record = witness.with_name(witness.name + "-resumed-bwrap")
    descriptor = os.open(record, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        os.write(descriptor, b"bwrap\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    if gate is not None:
        deadline = time.monotonic() + 20
        while not gate.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        if not gate.exists():
            raise RuntimeError("simulated_resume_gate_timeout")


def observe_real_contention():
    """Tell the parent only after the kernel refused the waiter's first lock."""
    selected = os.environ.get("SIMULATED_CONTENDED_WITNESS")
    if not selected:
        return
    import pilot_preparation_lock as coordination
    original = coordination.fcntl.flock

    def witnessed(fd, operation):
        try:
            return original(fd, operation)
        except BlockingIOError:
            descriptor = os.open(selected, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC,
                                 0o600)
            try:
                os.write(descriptor, b"contended\n")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            raise

    coordination.fcntl.flock = witnessed


if kind == "source":
    build = load("pilot_source_worker", "build-native-pilot-inputs.py")
    observe_real_contention()
    source = {"commit": commit, "tree": "b" * 40, "dirty": False,
              "files_sha256": identity * 64, "cargo_lock_sha256": "d" * 64,
              "rust_toolchain_sha256": "e" * 64}
    tools = {name: str(Path(sys.executable).resolve())
             for name in ("cargo", "rustc", "cc", "c++", "ar", "ranlib", "cmake")}

    def compile_one(_root, generation, _tools):
        started()
        if failure == "fail":
            raise build.Failure("simulated_compile_failure", "compile")
        binaries = generation / "bin"
        binaries.mkdir(mode=0o700)
        for role in build.ROLES:
            file = binaries / role
            file.write_bytes(b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\x00" + role.encode())
            file.chmod(0o700)
        return 0.25

    arguments = ["--build", "--output", str(output), "--expected-commit", commit,
                 "--wait-seconds", wait_text]
    if operation == "rebuild":
        arguments.append("--rebuild")
    with patch.object(build, "source_identity", return_value=source), \
         patch.object(build, "inventory", return_value={"missing": [], "tools": tools}), \
         patch.object(build, "build_generation", side_effect=compile_one):
        raise SystemExit(build.main(arguments))

if kind == "native":
    prep = load("pilot_native_worker", "prepare-native-pilot-prerequisites.py")
    observe_real_contention()
    tools = {name: str(Path(sys.executable).resolve()) for name in prep.TOOLS}

    def compile_one(_command, *, cwd, env, log, seconds, stage):
        log.write_text(stage + "\n")
        if stage == "git_build":
            started()
            if failure == "fail":
                raise prep.Failure("simulated_compile_failure", "git_build")
            file = cwd / "git"
        elif stage == "bwrap_build":
            if failure == "fail-bwrap":
                raise prep.Failure("simulated_bwrap_failure", "bwrap_build")
            if operation in ("resume", "rebuild-resume"):
                resumed_bwrap_started()
            file = cwd / "bwrap-build/bwrap"
            file.parent.mkdir(exist_ok=True)
        else:
            return
        file.write_bytes(b"simulated " + stage.encode())
        file.chmod(0o700)

    def captured(command, **_kwargs):
        if command[1] == "--help":
            return "--ro-bind-fd"
        return "git version 2.51.2" if command[0].endswith("/git") else "bubblewrap 0.13.1"

    archive_parent = output.parent
    arguments = [str(SCRIPTS / "prepare-native-pilot-prerequisites.py"), "--prepare",
                 "--output", str(output), "--expected-commit", commit,
                 "--git-archive", str(archive_parent / "git.tar.xz"),
                 "--bwrap-archive", str(archive_parent / "bwrap.tar.xz"),
                 "--wait-seconds", wait_text]
    if operation == "rebuild":
        arguments.append("--rebuild")
    elif operation == "resume":
        arguments.append("--resume")
    elif operation == "rebuild-resume":
        arguments.extend(("--rebuild", "--resume"))
    with patch.object(prep, "platform_missing", return_value=[]), \
         patch.object(prep, "tool_inventory", return_value=(tools, [])), \
         patch.object(prep, "source_identity", return_value=commit), \
         patch.object(prep, "bounded_archive", side_effect=lambda path, _kind: path), \
         patch.object(prep, "extract"), \
         patch.object(prep, "build", side_effect=compile_one), \
         patch.object(prep, "captured", side_effect=captured), \
         patch.object(prep, "native_libraries", return_value={}), \
         patch.object(sys, "argv", arguments):
        raise SystemExit(prep.main())

raise SystemExit("unknown_simulated_builder")
