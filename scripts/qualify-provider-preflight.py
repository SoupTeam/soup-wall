#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact-source installed provider-check qualification on native Ubuntu 24.04.

The checkout supplies only test code and a component built from this exact
source. Every checked command runs via an installed agentfw from /tmp, with a
private home and loopback fixtures outside the source tree. No model call.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "sw-sou193-installed-preflight-evidence/1"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def source(expected):
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, timeout=10).decode().strip()
    changed = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"],
                                      cwd=ROOT, timeout=10)
    if revision != expected or changed:
        raise ValueError("source_not_exact_clean")
    return revision


def private_file(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentfw", type=Path, required=True)
    parser.add_argument("--component", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (platform.system() != "Linux" or platform.machine() != "x86_64"
            or platform.freedesktop_os_release().get("VERSION_ID") != "24.04"
            or os.geteuid() == 0):
        parser.error("native_ubuntu_2404_nonroot_required")
    for path in (args.agentfw, args.component, args.python, args.output):
        if not path.is_absolute() or path.is_relative_to(ROOT):
            parser.error("absolute_external_path_required")
    for path in (args.agentfw, args.component, args.python):
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
            parser.error("input_not_private_or_system_owned")
    revision = source(args.expected_commit)
    args.output.mkdir(mode=0o700)
    if stat.S_IMODE(args.output.stat().st_mode) != 0o700 or args.output.stat().st_uid != os.getuid():
        parser.error("output_not_owned_private")
    spec = importlib.util.spec_from_file_location("sou193_native_tests",
                                                  ROOT / "scripts/tests/test_pilot_provider_preflight.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    saved = {key: os.environ.get(key) for key in ("SOU193_INSTALLED_AGENTFW", "SOU193_INSTALLED_COMPONENT",
                                                  "SOU193_INSTALLED_PYTHON")}
    os.environ.update(SOU193_INSTALLED_AGENTFW=str(args.agentfw),
                      SOU193_INSTALLED_COMPONENT=str(args.component),
                      SOU193_INSTALLED_PYTHON=str(args.python))
    try:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.Preflight)
        sink = io.StringIO()
        result = unittest.TextTestRunner(stream=sink, verbosity=0).run(suite)
    finally:
        for key, old in saved.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old
    failed = [test.id().rsplit(".", 1)[-1] for test, _ in result.failures + result.errors]
    evidence = {"format": FORMAT, "source_commit": revision,
                "agentfw_sha256": digest(args.agentfw), "component_sha256": digest(args.component),
                "python_sha256": digest(args.python), "python_version": platform.python_version(),
                "tests": result.testsRun, "failed_cases": sorted(failed),
                "passed": result.wasSuccessful() and result.testsRun == 11
                          and not module.APPLICATION_PAYLOADS,
                "scripted_provider_only": True,
                "observed_application_payloads": len(module.APPLICATION_PAYLOADS),
                "active_protection": False}
    private_file(args.output / "report.json", (json.dumps(evidence, sort_keys=True) + "\n").encode())
    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
