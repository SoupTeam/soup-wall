#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Qualify the installed private-edit self-test from a clean developer checkout.

This driver prepares only its own component home, then invokes the installed
front door outside the checkout. It never prepares or changes the supplied
selection. No consent means no installation, writes, provider or child process.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sw-private-edit-self-test-qualification/1"
SELF_TEST = "sw-private-edit-self-test/1"
CASES = ("create-read", "replace-read", "ask-reject-replay", "aggregate-quota",
         "exact-run-stop", "stopped-authority", "daemon-loss", "fresh-run-recovery")
CHECKS = ("installed-identity", "inert-preview", "tampered-selection",
          "genuine-installed-run", "changed-helper-refusal")
STREAM_LIMIT = 512 * 1024


def require(condition, code):
    if not condition:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("nonfinite_json")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def bounded_file(path, limit=STREAM_LIMIT):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        meta = os.fstat(stream.fileno())
        require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and meta.st_size <= limit,
                "bounded_regular_file_required")
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "file_byte_limit")
    return raw


def write_new(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)


def positive_report(value, expected):
    """Missing observations, cleanup or one changed identity cannot pass."""
    if not isinstance(value, dict):
        return False
    rows = value.get("cases", [])
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        return False
    cleanup = value.get("cleanup", {})
    preservation = value.get("preservation", {})
    identities = value.get("identities", {})
    inventory = value.get("inventory", {})
    profile = value.get("platform", {})
    if not all(isinstance(item, dict) for item in (cleanup, preservation, identities, inventory, profile)):
        return False
    installed = identities.get("installed_sha256", {})
    if not isinstance(installed, dict):
        return False
    return (value.get("format") == SELF_TEST and value.get("status") == "passed"
            and value.get("executed") is True and value.get("paid_inference") is False
            and value.get("expected") == list(CASES)
            and [row.get("id") for row in rows] == list(CASES)
            and all(row.get("attempted") is True and row.get("status") == "passed" for row in rows)
            and cleanup.get("all_owned_processes_stopped") is True
            and cleanup.get("workspace_removed") is True
            and cleanup.get("workspace_retained") is False
            and preservation.get("installed_state_unchanged") is True
            and preservation.get("original_projects_unchanged") is True
            and preservation.get("unrelated_sentinel_unchanged") is True
            and identities.get("source_commit") == expected["source_commit"]
            and identities.get("source_tree") == expected["source_tree"]
            and identities.get("component_sha256") == expected["component_sha256"]
            and identities.get("selection_sha256") == expected["selection_sha256"]
            and installed.get("agentfw") == expected["agentfw_sha256"]
            and inventory == {"expected": len(CASES), "attempted": len(CASES), "passed": len(CASES),
                              "failed": 0, "incomplete": 0, "unsupported": 0}
            and profile.get("id") == "native-linux-x86_64")


def passed(value):
    rows = value.get("checks", [])
    return (value.get("format") == FORMAT and value.get("status") == "passed"
            and [row.get("id") for row in rows] == list(CHECKS)
            and all(row.get("attempted") is True and row.get("status") == "passed" for row in rows)
            and value.get("selected_inputs_unchanged") is True)


class Capture:
    def __init__(self, stream):
        self.total, self.raw, self.failed = 0, bytearray(), False

        def drain():
            try:
                while block := os.read(stream.fileno(), 65536):
                    self.total += len(block)
                    self.raw.extend(block[:max(0, STREAM_LIMIT - len(self.raw))])
            except OSError:
                self.failed = True
            finally:
                stream.close()

        self.thread = threading.Thread(target=drain, daemon=True)
        self.thread.start()

    def finish(self):
        self.thread.join(timeout=3)
        require(not self.thread.is_alive() and not self.failed and self.total <= STREAM_LIMIT,
                "qualification_stream_limit")
        return bytes(self.raw)


class Driver:
    def __init__(self, args, report):
        self.args, self.report = args, report
        self.deadline = time.monotonic() + 700
        self.home = args.output / "component-home"
        self.home.mkdir(mode=0o700)
        self.cwd = args.output / "outside-checkout"
        self.cwd.mkdir(mode=0o700)
        self.env = {"PATH": "/usr/bin:/bin", "HOME": str(self.cwd), "LANG": "C.UTF-8",
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        self.active = None

    def call(self, words, timeout=30, *, cwd=None):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, "qualification_deadline")
        process = subprocess.Popen(list(map(str, words)), env=self.env, cwd=cwd or self.cwd,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        out, err = Capture(process.stdout), Capture(process.stderr)
        try:
            deadline = time.monotonic() + min(timeout, remaining)
            while process.poll() is None:
                require(out.total <= STREAM_LIMIT and err.total <= STREAM_LIMIT, "qualification_stream_limit")
                require(time.monotonic() < deadline, "qualification_child_deadline")
                time.sleep(.025)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        stdout, stderr = out.finish(), err.finish()
        observation = {"exit_code": process.returncode, "stdout_bytes": len(stdout),
                       "stderr_bytes": len(stderr), "stdout_sha256": sha(stdout),
                       "stderr_sha256": sha(stderr), "raw_retained": False}
        value = None
        if stdout.strip():
            try:
                value = strict(stdout)
            except ValueError:
                pass
        if self.active is not None:
            self.active.setdefault("commands", []).append(observation)
        return process.returncode, value

    def command(self, selection=None, output=None, run=False):
        words = [self.args.agentfw, "self-test", "private-edit", "--home", self.home,
                 "--selection", selection or self.args.selection]
        if output is not None:
            words += ["--output", output]
        if run:
            words += ["--run", "--timeout-seconds", "550"]
        return words

    def begin(self, name):
        self.active = next(row for row in self.report["checks"] if row["id"] == name)
        self.active["attempted"] = True
        return self.active


def qualify(args, report):
    require(platform.system() == "Linux" and platform.machine() == "x86_64"
            and os.geteuid() != 0, "native_linux_operator_required")
    require("microsoft" not in Path("/proc/sys/kernel/osrelease").read_text().lower(),
            "native_linux_required_wsl_is_separate")
    for path in (args.agentfw, args.selection, args.python):
        require(path is not None and path.is_absolute() and path.resolve(strict=True) == path,
                "absolute_canonical_inputs_required")
    require(args.output is not None and args.output.is_absolute() and not args.output.exists()
            and args.output.parent.resolve(strict=True) / args.output.name == args.output,
            "fresh_absolute_output_required")
    require(not args.output.is_relative_to(ROOT) and not ROOT.is_relative_to(args.output),
            "outside_checkout_required")
    for path in (args.agentfw, args.selection, args.python):
        require(not path.is_relative_to(args.output), "output_overlaps_inputs")
    parent = args.output.parent.stat()
    require(parent.st_uid == os.geteuid() and not parent.st_mode & 0o022,
            "private_output_parent_required")
    args.output.mkdir(mode=0o700)
    report["output_created"] = True
    before = {"agentfw": digest_file(args.agentfw), "python": digest_file(args.python),
              "selection": sha(bounded_file(args.selection, 65536))}
    driver = Driver(args, report)

    try:
        row = driver.begin("installed-identity")
        archive = args.output / "component.tar"
        code, built = driver.call([args.python, "-I", "-B", ROOT / "scripts/build-pilot-front-door.py",
                                   "--out", archive], timeout=60, cwd=ROOT)
        require(code == 0 and isinstance(built, dict), "component_build_failed")
        require(digest_file(archive) == built.get("archive_sha256"), "component_archive_identity")
        with tarfile.open(archive, "r:") as bundle:
            member = bundle.getmember("manifest.json")
            require(member.isreg() and member.size <= 65536, "component_manifest_bound")
            manifest_bytes = bundle.extractfile(member).read(65537)
        manifest = strict(manifest_bytes)
        require(sha(manifest_bytes) == built.get("component"), "component_manifest_identity")
        code, installed = driver.call([args.agentfw, "pilot-component", "--home", driver.home,
            "install", archive, "--sha256", built["archive_sha256"], "--python", args.python], timeout=60)
        require(code == 0 and isinstance(installed, dict) and installed.get("component") == built["component"],
                "component_install_failed")
        expected = {"source_commit": manifest["source"]["commit"], "source_tree": manifest["source"]["tree"],
                    "component_sha256": built["component"], "agentfw_sha256": before["agentfw"],
                    "selection_sha256": before["selection"]}
        report["identities"] = expected
        row.update(status="passed", component_verified=True)

        row = driver.begin("inert-preview")
        preview = args.output / "preview-must-not-exist"
        pointer = driver.home / "pilot-front-door/current.json"
        pointer_before = sha(bounded_file(pointer))
        code, value = driver.call(driver.command(output=preview), timeout=60)
        require(code == 0 and isinstance(value, dict) and value.get("format") == SELF_TEST
                and value.get("status") == "preview" and value.get("executed") is False
                and value.get("inventory", {}).get("attempted") == 0 and not preview.exists()
                and sha(bounded_file(pointer)) == pointer_before, "preview_was_not_inert")
        row.update(status="passed", no_output_created=True, no_execution=True, current_pointer_unchanged=True)

        row = driver.begin("tampered-selection")
        negative = args.output / "negative-selection"
        negative.mkdir(mode=0o700)
        damaged = negative / "selection.json"
        selected = strict(bounded_file(args.selection, 65536))
        selected["files"]["agentfw"]["sha256"] = "0" * 64
        write_new(damaged, (json.dumps(selected, sort_keys=True) + "\n").encode())
        refused_output = args.output / "refused-must-not-exist"
        code, value = driver.call(driver.command(selection=damaged, output=refused_output, run=True), timeout=60)
        require(code != 0 and isinstance(value, dict) and value.get("format") == SELF_TEST
                and value.get("executed") is False and value.get("inventory", {}).get("attempted") == 0
                and not refused_output.exists() and sha(bounded_file(pointer)) == pointer_before,
                "damaged_selection_started_or_changed_state")
        row.update(status="passed", no_execution=True, no_output_created=True,
                   current_pointer_unchanged=True)

        row = driver.begin("genuine-installed-run")
        execution = args.output / "run"
        code, value = driver.call(driver.command(output=execution, run=True), timeout=580)
        child_path = execution / "report.json"
        require(child_path.is_file(), "installed_self_test_report_missing")
        raw = bounded_file(child_path)
        child = strict(raw)
        row.update(report_sha256=sha(raw), report_bytes=len(raw))
        if isinstance(child, dict) and isinstance(child.get("inventory"), dict):
            row["inventory"] = {key: count for key, count in child["inventory"].items()
                                if key in ("expected", "attempted", "passed", "failed", "incomplete", "unsupported")
                                and type(count) is int and 0 <= count <= len(CASES)}
        require(code == 0 and positive_report(child, expected), "installed_self_test_did_not_pass")
        row.update(status="passed", outside_checkout=True, exact_installed_identity=True,
                   independent_native_runtime=True)

        row = driver.begin("changed-helper-refusal")
        helper = driver.home / "pilot-front-door/components" / built["component"] / "tree/scripts/private_edit_self_test.py"
        original = bounded_file(helper)
        canary = driver.cwd / "unverified-helper-ran"
        hostile = ("from pathlib import Path\nPath(" + repr(str(canary)) + ").write_text('unverified helper executed')\n").encode()
        try:
            helper.chmod(0o600)
            helper.write_bytes(hostile)
            helper.chmod(0o400)
            after_tamper = args.output / "tampered-helper-must-not-exist"
            code, value = driver.call(driver.command(output=after_tamper, run=True), timeout=30)
            require(code != 0 and isinstance(value, dict) and value.get("format") == SELF_TEST
                    and value.get("status") == "incomplete" and value.get("executed") is False
                    and value.get("reason") == "installed_component_unavailable"
                    and not canary.exists() and not after_tamper.exists(),
                    "changed_helper_executed_or_fell_back")
        finally:
            helper.chmod(0o600)
            helper.write_bytes(original)
            helper.chmod(0o400)
        require(sha(bounded_file(helper)) == sha(original), "owned_helper_restore_failed")
        row.update(status="passed", canary_absent=True, no_fallback=True,
                   no_output_created=True, helper_restored=True)
        report["status"] = "passed"
    finally:
        after = {"agentfw": digest_file(args.agentfw), "python": digest_file(args.python),
                 "selection": sha(bounded_file(args.selection, 65536))}
        report["selected_inputs_unchanged"] = before == after
        if not report["selected_inputs_unchanged"]:
            report["status"] = "failed"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--agentfw", type=Path)
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--python", type=Path, default=Path("/usr/bin/python3.12"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({"format": FORMAT, "executed": False, "checks": list(CHECKS)}))
        return 0
    report = {"format": FORMAT, "status": "incomplete", "executed": True, "paid_inference": False,
              "checks": [{"id": name, "attempted": False, "status": "incomplete"} for name in CHECKS]}
    try:
        qualify(args, report)
        require(passed(report), "incomplete_qualification")
    except (Exception, KeyboardInterrupt) as error:
        safe = str(error) if type(error) is ValueError and re.fullmatch(r"[a-z][a-z0-9_]{0,100}", str(error)) else "qualification_incomplete"
        report.update(status="failed", reason=safe)
        active = next((row for row in report["checks"] if row["attempted"] and row["status"] == "incomplete"), None)
        if active is not None:
            active.update(status="failed", reason=safe)
    report["inventory"] = {"expected": len(CHECKS), "attempted": sum(row["attempted"] for row in report["checks"]),
        **{state: sum(row["status"] == state for row in report["checks"]) for state in ("passed", "failed", "incomplete")}}
    if report.pop("output_created", False):
        raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
        require(len(raw) <= STREAM_LIMIT, "qualification_report_limit")
        write_new(args.output / "qualification.json", raw)
    print(json.dumps({key: report[key] for key in ("format", "status", "inventory")}))
    return 0 if passed(report) else 1


if __name__ == "__main__":
    raise SystemExit(main())
