#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inventory qualification build declarations without treating them as attestation.

Literal Cargo commands and delegated source-build entry points are separate.
Compilation counts require Cargo artifact records; mixed test/runtime step time
is never relabelled as compiler time. The selected reuse contract stays narrow.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from ci_components import blocks
from ci_impact import WORKFLOW_JOBS

FORMAT = "sw-ci-build-inventory/1"
TUPLE = "ubuntu2404-x86_64-rust1.99.1-agent-default-debug-v1"
CONSUMERS = ("linux-create-file", "linux-installed-edit")
OVERRIDES = ("RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
             "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CC", "CXX", "CARGO_PROFILE_")
DELEGATES = ("build-native-pilot-inputs.py", "native-verified-execution-build.py", "ci_qualification_build.py")


def lines_with_continuations(body):
    pending, start = "", 0
    for number, line in enumerate(body.splitlines(), 1):
        if not pending:
            start = number
        pending += line.strip().rstrip("\\").rstrip() + " "
        if line.rstrip().endswith("\\"):
            continue
        yield start, pending.strip()
        pending = ""
    if pending:
        yield start, pending.strip()


def cargo_commands(body):
    result = []
    for number, line in lines_with_continuations(body):
        match = re.search(r"(?:^|[\s&])cargo\s+(build|test|check|clippy|fmt|fetch)\b(.*)", line)
        if not match and "ci_qualification_build.py cargo " in line:
            match = re.search(r" -- (build|test|clippy)\b(.*)", line)
        if not match:
            continue
        # Keep original shell syntax as evidence; do not execute or guess it.
        command = "cargo " + match[1] + match[2]
        try:
            words = shlex.split(command)
        except ValueError:
            words = []
        def option(name):
            if name in words:
                index = words.index(name)
                return words[index + 1] if index + 1 < len(words) else "unresolved"
            return next((word.split("=", 1)[1] for word in words if word.startswith(name + "=")), None)
        result.append({"job_line": number, "command": command, "operation": match[1],
                       "package": option("-p") or option("--package"),
                       "target": option("--target") or "implicit-host",
                       "profile": option("--profile") or ("release" if "--release" in words else "dev/test"),
                       "features": option("--features"), "all_features": "--all-features" in words,
                       "no_default_features": "--no-default-features" in words,
                       "offline": "--offline" in words, "locked": "--locked" in words,
                       "count_kind": "Cargo invocation declaration, not observed rustc compilation"})
    return result


def job_inventory(workflow, job, body):
    runner = re.search(r"(?m)^    runs-on:\s*(.+)$", body)
    tools = re.findall(r"rust-toolchain@([^\s]+)", body)
    env_pins = re.findall(r"(?m)^\s+RUSTUP_TOOLCHAIN:\s*['\"]?([^'\"\s]+)", body)
    delegated = [name for name in DELEGATES if name in body]
    return {"workflow": workflow, "job": job,
            "runner": runner[1] if runner else "unresolved",
            "toolchain_actions": sorted(set(tools)), "environment_toolchains": sorted(set(env_pins)),
            "cargo": cargo_commands(body), "delegated_build_entries": delegated,
            "build_environment_declarations": [line.strip() for line in body.splitlines()
                                                if any(name in line for name in OVERRIDES)],
            "runtime_path_constraints": [line.strip() for line in body.splitlines()
                                         if any(marker in line for marker in (
                                             "CARGO_TARGET_DIR", "--ro-bind", "--unshare-net", "SOU161_SCRATCH",
                                             "$PWD/target/", '"$CARGO_TARGET_DIR/') )],
            "compatibility": "selected-declaration-candidate" if (
                workflow == "mcp-create-file.yml" and job in CONSUMERS) else "not-selected"}


def compatible_declaration(value):
    """Only a candidate: producer/consumer independently verify real image/ABI."""
    if value["workflow"] != "mcp-create-file.yml" or value["job"] not in CONSUMERS:
        return False
    if value["runner"] != "ubuntu-24.04" or set(value["toolchain_actions"]) != {"1.99.1"}:
        return False
    if any(pin != "1.99.1" for pin in value["environment_toolchains"]):
        return False
    if any(marker in line for line in value["build_environment_declarations"]
           for marker in ("RUSTFLAGS", "RUSTC_WRAPPER", "CARGO_PROFILE_")):
        return False
    return all(not command["all_features"] and not command["no_default_features"]
               and command["features"] is None and command["target"] == "implicit-host"
               and command["profile"] == "dev/test"
               and (command["operation"] in {"fetch", "fmt"} or
                    (command["package"] == "agentfw" and command["locked"]))
               for command in value["cargo"])


def inventory(root=ROOT):
    jobs, files = [], {}
    for workflow in WORKFLOW_JOBS:
        path = root / ".github/workflows" / workflow
        raw = path.read_bytes()
        files[str(path.relative_to(root))] = hashlib.sha256(raw).hexdigest()
        # Include explicit manual development jobs, but never double-count the
        # generated shared copy of these original declarations.
        for job, body in blocks(raw.decode("utf-8-sig")).items():
            if cargo_commands(body) or any(name in body for name in DELEGATES):
                jobs.append(job_inventory(workflow, job, body))
    return {"format": FORMAT, "workflow_files_sha256": files, "jobs": jobs,
            "denominators": {"registered_source_workflows": len(WORKFLOW_JOBS),
                             "jobs_with_literal_or_delegated_builds": len(jobs),
                             "literal_cargo_invocation_declarations": sum(len(job["cargo"]) for job in jobs)},
            "selected_tuple": TUPLE,
            "selected_candidates": [value for value in jobs if compatible_declaration(value)],
            "limits": ["Matrix declarations are not expanded or counted as observed runner jobs",
                       "No actual compilation count is inferred from a Cargo command",
                       "Hosted image version, compiler hashes, ABI and fixture paths require runtime verification",
                       "No execution-time saving or billing claim follows from this inventory"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    value = inventory()
    for name, revision in (("commit", "HEAD"), ("tree", "HEAD^{tree}")):
        value.setdefault("source", {})[name] = subprocess.check_output(
            ["git", "rev-parse", revision], cwd=ROOT, text=True, timeout=15).strip()
    raw = json.dumps(value, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(raw)
    else:
        print(raw, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
