# SPDX-License-Identifier: Apache-2.0
"""Same-source pilot inputs in the existing public Linux archive; never publish.

The source builder's v1 receipts remain supported. This v2 release-lane receipt
records two production binaries; no libtest executable is a release input.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile

from pilot_candidate import *  # shared staging/runtime/publication contract


def load(root, name, filename):
    spec = importlib.util.spec_from_file_location(name, root / "scripts" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stage(root, directory, binaries, commit):
    # Reuse accepted SOU-119 exact source capture and SOU-154 deterministic
    # component construction, preserving v1 source-builder receipt validation.
    builder = load(root, "candidate_native_builder", "build-native-pilot-inputs.py")
    source = builder.source_identity(root, commit)
    component = load(root, "candidate_front_door", "build-pilot-front-door.py")
    archive, manifest, identity = component.build()
    require(identity == {key: source[key] for key in identity}, "candidate_component_source_mismatch")
    require(all(not (directory / name).exists() for name in FILES), "candidate_stage_already_exists")
    launcher = binaries / LAUNCHER
    file_record(launcher)
    shutil.copyfile(launcher, directory / LAUNCHER)
    os.chmod(directory / LAUNCHER, 0o755)
    require(file_record(directory / "agentfw")["sha256"] == file_record(binaries / "agentfw")["sha256"],
            "candidate_agent_stage_mismatch")
    tools = {}
    for name in ("rustc", "cargo"):
        path = Path(shutil.which(name) or "")
        require(path.is_absolute(), "candidate_compiler_unavailable")
        path = path.resolve(strict=True)
        version = subprocess.check_output([str(path), "--version"], timeout=10).decode().strip()
        require(version.startswith(name + " " + PIN + " "), "candidate_compiler_version_mismatch")
        tools[name] = {"version": version, "sha256": file_record(path)["sha256"]}
    for name, raw in ((SOURCE, canonical(source)), (COMPONENT, archive)):
        (directory / name).write_bytes(raw)
        os.chmod(directory / name, 0o644)
    receipt = {"format": FORMAT, "status": "built-not-qualified", "lane": "release", "target": TARGET,
               "toolchain": PIN, "tools": tools, "commands": [COMMAND], "source": source,
               "source_sha256": sha(canonical(source)),
               "binaries": {role: {"path": name, **file_record(directory / name)}
                            for role, name in BINARY_NAMES.items()},
               "component": {"path": COMPONENT, **file_record(directory / COMPONENT)},
               "component_manifest_sha256": sha(manifest)}
    (directory / RECEIPT).write_bytes(canonical(receipt))
    os.chmod(directory / RECEIPT, 0o644)
    return validate_directory(directory, commit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("stage", "check"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--binaries", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "stage":
            require(args.binaries is not None, "candidate_binaries_required")
            result = stage(Path(__file__).resolve().parents[1], args.directory, args.binaries, args.expected_commit)
        else:
            result = validate_directory(args.directory, args.expected_commit)
        print(json.dumps({"status": "verified-inputs-not-qualified", **result}, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError):
        print(json.dumps({"status": "failed", "reason": "candidate_inputs_refused", "active_protection": False}))
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
