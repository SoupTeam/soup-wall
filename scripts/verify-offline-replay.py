#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build an exact clean source and run owned offline replay qualification.

Default is a read-only plan. --run creates one fresh private output directory,
uses offline Cargo, and executes only this source's public synthetic tests.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sou152-offline-qualification/1"


class Refusal(Exception):
    pass


def require(ok, code):
    if not ok:
        raise Refusal(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bounded_run(argv, cwd, env, timeout, cap=16 * 1024 * 1024):
    """Bound both streams and wall time; terminate only this owned process group."""
    child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             start_new_session=True)
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()

    def collect(stream, target):
        while chunk := stream.read(65536):
            if len(target) + len(chunk) <= cap:
                target.extend(chunk)
            else:
                overflow.set()
        stream.close()

    threads = [threading.Thread(target=collect, args=(stream, target), daemon=True)
               for stream, target in zip((child.stdout, child.stderr), buffers)]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    failure = None
    while child.poll() is None:
        if overflow.is_set() or time.monotonic() > deadline:
            failure = "process_output_bound" if overflow.is_set() else "process_timeout"
            os.killpg(child.pid, signal.SIGKILL)
            break
        time.sleep(0.02)
    child.wait()
    for thread in threads:
        thread.join(timeout=2)
    if any(thread.is_alive() for thread in threads):
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for thread in threads:
            thread.join(timeout=2)
        raise Refusal("process_descendant_stream_open")
    require(failure is None and not overflow.is_set(), failure or "process_output_bound")
    return child.returncode, bytes(buffers[0]), bytes(buffers[1])


def source_identity(root, expected):
    require(re.fullmatch(r"[0-9a-f]{40}", expected) is not None, "expected_commit_full_sha_required")
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}

    def git(*args):
        code, out, _ = bounded_run(["git", "-C", str(root), *args], root, env, 15)
        require(code == 0, "source_git_read_failed")
        return out.decode("ascii").strip()

    require(git("rev-parse", "HEAD") == expected, "source_commit_mismatch")
    require(not git("status", "--porcelain=v1", "--untracked-files=all"), "source_must_be_clean")
    return {"commit": expected, "tree": git("rev-parse", "HEAD^{tree}"), "clean": True}


def fresh_output(path, source):
    """No overwrite, source writes, '..', or symlink ancestors."""
    require(path.is_absolute() and ".." not in path.parts, "output_absolute_without_parent_required")
    require(len(os.fsencode(path)) <= 4096 and len(path.parts) <= 64, "output_path_bound")
    require(not path.is_relative_to(source) and not source.is_relative_to(path), "output_must_be_outside_source")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in path.parts[1:-1]:
            next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        os.mkdir(path.name, 0o700, dir_fd=fd)
        result = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            info = os.fstat(result)
            require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "output_private_directory_required")
        finally:
            os.close(result)
    except OSError as error:
        raise Refusal("output_fresh_private_path_required") from error
    finally:
        os.close(fd)
    return path


def file_identity(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= cap, "artifact_regular_file_bound")
        data = stream.read(cap + 1)
        after = os.fstat(stream.fileno())
    require(len(data) <= cap and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, len(data), after.st_mtime_ns), "artifact_changed")
    return {"sha256": sha(data), "bytes": len(data)}


def export_report(output, report):
    data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    require(len(data) <= 128 * 1024, "qualification_report_bound")
    fd = os.open(output / "report.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def qualify(args):
    require(os.name == "posix", "qualification_unix_required")
    before = source_identity(ROOT, args.expected_commit)
    if not args.run:
        return {"format": FORMAT, "status": "plan", "source": before,
                "actions": ["fresh_private_output", "offline_exact_source_build", "three_owned_cli_tests"],
                "no_execution": True}
    output = fresh_output(Path(args.output), ROOT)
    report = {"format": FORMAT, "status": "failed", "source": before,
              "protection_claim": False, "scope": "legacy-agent-event-inspection/1"}
    try:
        require(Path(args.cargo).is_absolute(), "explicit_absolute_cargo_required")
        cargo = Path(args.cargo)
        report["cargo"] = file_identity(cargo, 128 * 1024 * 1024)
        with tempfile.TemporaryDirectory(prefix="owned-build-", dir=output) as build:
            build = Path(build)
            target = build / "target"
            # Cargo may read the operator's dependency cache, but --offline and
            # --locked prohibit dependency downloads/resolution updates. The
            # replay child receives only its disposable home in the Rust tests.
            env = {**os.environ, "CARGO_TARGET_DIR": str(target), "TMPDIR": str(build),
                   "CARGO_TERM_COLOR": "never", "CARGO_INCREMENTAL": "0"}
            for name in ("RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "SOU152_AGENTFW_BINARY", "SOU152_PARITY_REPORT", "SOU152_OWNED_FIFO_PROBE"):
                env.pop(name, None)
            env["PATH"] = str(cargo.parent) + os.pathsep + env.get("PATH", "")
            code, out, err = bounded_run([str(cargo), "test", "--locked", "--offline", "-p", "agentfw",
                                         "--test", "offline_replay_cli", "--no-run", "--message-format=json"],
                                        ROOT, env, 1200)
            report["build"] = {"exit_code": code, "stdout_sha256": sha(out), "stderr_sha256": sha(err)}
            require(code == 0, "offline_build_failed")
            binaries = {}
            for line in out.splitlines():
                row = json.loads(line)
                if row.get("reason") == "compiler-artifact" and row.get("executable"):
                    name = row["target"]["name"]
                    if name in ("agentfw", "offline_replay_cli"):
                        candidate = Path(row["executable"])
                        require(candidate.is_relative_to(target), "build_artifact_outside_owned_target")
                        binaries[name] = candidate
            require(set(binaries) == {"agentfw", "offline_replay_cli"}, "required_build_artifacts_missing")
            report["binaries"] = {name: file_identity(path, 256 * 1024 * 1024) for name, path in binaries.items()}
            report["fixtures"] = {path.name: file_identity(path, 1024 * 1024)
                                  for path in sorted((ROOT / "crates/agentfw/tests/fixtures/offline-replay").iterdir())}
            report["shipped_policy"] = file_identity(ROOT / "crates/agent/policies/agent-default.yaml", 65536)
            report["driver"] = file_identity(Path(__file__), 65536)
            parity = output / "parity.json"
            env["SOU152_AGENTFW_BINARY"] = str(binaries["agentfw"])
            env["SOU152_PARITY_REPORT"] = str(parity)
            code, out, err = bounded_run([str(binaries["offline_replay_cli"]), "--nocapture"], ROOT, env, 60, 1024 * 1024)
            report["tests"] = {"exit_code": code, "stdout_sha256": sha(out), "stderr_sha256": sha(err)}
            require(code == 0 and b"3 passed; 0 failed; 0 ignored" in out, "owned_cli_tests_failed_or_skipped")
            report["parity_report"] = file_identity(parity, 65536)
            evidence = json.loads(parity.read_bytes())
            require(evidence["format"] == "sou152-offline-parity/1", "parity_report_format")
            effects = evidence["effects"]
            for key in ("command_calibrated", "network_receiver_calibrated", "state_canaries_readable_control",
                        "target_fifo_calibrated", "command_marker_absent", "state_and_inputs_unchanged", "no_home_discovery"):
                require(effects.get(key) is True, "required_positive_witness_missing")
            require(effects.get("network_connections") == 0 and effects.get("target_fifo_opens") == 0,
                    "unexpected_tool_effect")
            require(len(evidence["cases"]) == 3 and all(case.get("production_parity") is True
                    and case.get("trace_state_parity") is True for case in evidence["cases"]), "production_parity_missing")
            report["host_sandbox"] = effects["host_sandbox"]
            if effects["host_sandbox"]["status"] == "passed":
                require(set(effects["host_sandbox"].get("calibrated_denials", [])) ==
                        {"target_read", "state_read", "file_write", "process_fork", "network"}
                        and effects["host_sandbox"].get("target_read_denied") is True
                        and effects["host_sandbox"].get("target_denial_exit_code") == 73
                        and effects["host_sandbox"].get("allowed_fifo_under_same_sandbox") is True,
                        "host_sandbox_target_calibration_missing")
            report["limitations"] = ["Owned synthetic fixtures do not establish detection or protection rates.",
                "FIFO observation samples opens; it does not independently prove absence of every short-lived file read.",
                "Source/build identities assume the explicitly selected local Cargo/Rust toolchain and dependency cache."]
            if effects["host_sandbox"]["status"] != "passed":
                report["limitations"].append("Host sandbox unavailable; no syscall-level state/target-read exclusion claim.")
            report["source_after"] = source_identity(ROOT, args.expected_commit)
            require(report["source_after"] == before, "source_changed")
            report["status"] = "passed" if effects["host_sandbox"]["status"] == "passed" else "passed_with_limits"
    except (Refusal, OSError, ValueError, KeyError) as error:
        report["failure_code"] = str(error) if isinstance(error, Refusal) else "qualification_environment_or_report_failed"
    export_report(output, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--cargo", default="")
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    try:
        report = qualify(args)
        print(json.dumps({key: report[key] for key in ("format", "status", "source")}, sort_keys=True))
        return 1 if report["status"] == "failed" else 0
    except (Refusal, OSError, ValueError):
        print("Offline qualification refused: source, output or environment precondition failed", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
